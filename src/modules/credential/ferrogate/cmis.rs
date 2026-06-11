//! CMIS gRPC client (Phase 4): fetches the composite-key JWKS from FerroGate's
//! Central Machine Identity Service via the `ferrogate.v1.MachineIdentity/JWKS`
//! RPC.
//!
//! Transport is selected by [`FerroGateConfig::cmis_tls_enable`]:
//! - **TLS (default):** a hybrid post-quantum TLS 1.3 channel using
//!   `ferro-crypto`'s `X25519MLKEM768` provider, with the server certificate
//!   pinned by SHA-384 SPKI (no CA chain — CMIS uses a composite self-signed
//!   cert). Pins come from `cmis_spki_pins`.
//! - **Plaintext:** cleartext gRPC (h2c) — for a dev/loopback CMIS only.
//!
//! The gRPC stubs in [`proto`] are pre-generated from
//! `machine_identity.proto` and vendored (`cmis_proto.rs`) so building
//! BastionVault does not require `protoc`.

#![cfg(not(feature = "sync_handler"))]

use std::{sync::Arc, time::Duration};

use tonic::transport::{Channel, Endpoint};

use super::FerroGateConfig;

/// Pre-generated tonic stubs for the `ferrogate.v1` package.
#[allow(clippy::all, clippy::pedantic, unreachable_pub, missing_docs, rust_2018_idioms)]
pub mod proto {
    include!("cmis_proto.rs");
}

use proto::machine_identity_client::MachineIdentityClient;
use proto::JwksRequest;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// `tonic::transport::Error` renders as a bare `"transport error"`; the useful
/// detail (TLS handshake alert, SPKI pin mismatch, connection refused, …) lives
/// in its `source()` chain. Walk it so connect failures are diagnosable — e.g.
/// a rotated CMIS cert shows the pin-verification failure instead of a useless
/// generic string.
fn explain<E: std::error::Error>(err: &E) -> String {
    let mut out = err.to_string();
    let mut src = err.source();
    while let Some(e) = src {
        let detail = e.to_string();
        if !detail.is_empty() && !out.ends_with(&detail) {
            out.push_str(": ");
            out.push_str(&detail);
        }
        src = e.source();
    }
    out
}

/// Fetch the raw `jwks_json` string from CMIS. Returns a human-readable error
/// (safe to surface) on any transport/RPC failure.
///
/// With [`FerroGateConfig::cmis_same_host`] set, host-local aliases are tried
/// before the configured endpoint (see [`candidate_endpoints`]); the first
/// endpoint that connects serves the RPC.
pub async fn fetch_jwks_json(config: &FerroGateConfig) -> Result<String, String> {
    if config.cmis_endpoint.trim().is_empty() {
        return Err("cmis_grpc source selected but cmis_endpoint is empty".to_string());
    }

    let mut errors = Vec::new();
    for endpoint in candidate_endpoints(config) {
        let attempt = if config.cmis_tls_enable {
            connect_tls(config, &endpoint).await
        } else {
            connect_plaintext(&endpoint).await
        };
        match attempt {
            Ok(channel) => {
                let mut client = MachineIdentityClient::new(channel);
                let resp = client
                    .jwks(JwksRequest {})
                    .await
                    .map_err(|e| format!("CMIS JWKS RPC failed: {}", e.message()))?;
                return Ok(resp.into_inner().jwks_json);
            }
            Err(e) => errors.push(e),
        }
    }
    Err(errors.join("; "))
}

/// Endpoints to dial, in order. Without `cmis_same_host` this is just the
/// configured endpoint. With it, CMIS is declared to run on the same machine
/// as this server, where the configured endpoint — typically the host's
/// public name, the right answer for *external* clients (MIAs) — may not be
/// reachable from the server's own vantage point: inside a rootless-podman
/// (pasta) container the host's own address hairpins into the container's
/// empty namespace and is refused. Host-local aliases are tried first with
/// the configured port, then the configured endpoint as a fallback. The SPKI
/// pin authenticates the peer whichever name connects, so trying aliases
/// does not weaken verification.
fn candidate_endpoints(config: &FerroGateConfig) -> Vec<String> {
    let configured = config.cmis_endpoint.trim().to_string();
    if !config.cmis_same_host {
        return vec![configured];
    }
    let port = configured.rsplit(':').next().and_then(|p| p.parse::<u16>().ok());
    let mut out = Vec::new();
    if let Some(port) = port {
        // Podman/Docker's alias for "the machine this container runs on".
        out.push(format!("host.containers.internal:{port}"));
        // Bare-metal / host-network deployments.
        out.push(format!("127.0.0.1:{port}"));
    }
    if !out.contains(&configured) {
        out.push(configured);
    }
    out
}

/// Cleartext gRPC channel (dev/loopback only).
async fn connect_plaintext(endpoint: &str) -> Result<Channel, String> {
    Endpoint::from_shared(format!("http://{endpoint}"))
        .map_err(|e| format!("invalid cmis_endpoint: {e}"))?
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .connect()
        .await
        .map_err(|e| format!("connect to CMIS at {endpoint} (plaintext) failed: {}", explain(&e)))
}

/// Hybrid post-quantum TLS gRPC channel with SHA-384 SPKI pinning.
async fn connect_tls(config: &FerroGateConfig, endpoint: &str) -> Result<Channel, String> {
    use ferro_crypto::pin::{SpkiPin, SpkiPinVerifier};
    use ferro_crypto::tls::{ferrogate_provider, ProviderMode};

    if config.cmis_spki_pins.is_empty() {
        return Err("cmis_tls_enable is set but cmis_spki_pins is empty (cannot verify the CMIS \
                    certificate without a pin)"
            .to_string());
    }
    let pins = config
        .cmis_spki_pins
        .iter()
        .map(|p| SpkiPin::from_hex(p.trim()).map_err(|e| format!("invalid cmis_spki_pin '{p}': {e}")))
        .collect::<Result<Vec<_>, _>>()?;

    // Hybrid-preferred keeps a plain-X25519 fallback for bring-up interop; the
    // peer is still authenticated by the SPKI pin regardless of the group.
    let provider = Arc::new(ferrogate_provider(ProviderMode::HybridPreferredWithX25519Fallback));
    let verifier = SpkiPinVerifier::new(pins, provider.clone());

    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("build rustls config: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let mut http = hyper_util::client::legacy::connect::HttpConnector::new();
    http.enforce_http(false);
    http.set_connect_timeout(Some(CONNECT_TIMEOUT));

    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .enable_http2()
        .wrap_connector(http);

    Endpoint::from_shared(format!("https://{endpoint}"))
        .map_err(|e| format!("invalid cmis_endpoint: {e}"))?
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .connect_with_connector(connector)
        .await
        .map_err(|e| format!("connect to CMIS at {endpoint} (PQ-TLS) failed: {}", explain(&e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(endpoint: &str, same_host: bool) -> FerroGateConfig {
        FerroGateConfig {
            cmis_endpoint: endpoint.to_string(),
            cmis_same_host: same_host,
            ..FerroGateConfig::default()
        }
    }

    #[test]
    fn same_host_off_uses_only_the_configured_endpoint() {
        assert_eq!(candidate_endpoints(&cfg("cmis.example.com:8443", false)), vec![
            "cmis.example.com:8443"
        ]);
    }

    #[test]
    fn same_host_tries_local_aliases_first_then_configured() {
        assert_eq!(candidate_endpoints(&cfg("segdc1vds0005.fgv.br:8443", true)), vec![
            "host.containers.internal:8443",
            "127.0.0.1:8443",
            "segdc1vds0005.fgv.br:8443",
        ]);
    }

    #[test]
    fn same_host_does_not_duplicate_a_loopback_endpoint() {
        assert_eq!(candidate_endpoints(&cfg("127.0.0.1:9000", true)), vec![
            "host.containers.internal:9000",
            "127.0.0.1:9000",
        ]);
    }

    #[test]
    fn same_host_without_a_port_falls_back_to_the_configured_endpoint() {
        assert_eq!(candidate_endpoints(&cfg("cmis.example.com", true)), vec!["cmis.example.com"]);
    }
}
