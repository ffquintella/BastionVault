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

/// Fetch the raw `jwks_json` string from CMIS. Returns a human-readable error
/// (safe to surface) on any transport/RPC failure.
pub async fn fetch_jwks_json(config: &FerroGateConfig) -> Result<String, String> {
    if config.cmis_endpoint.trim().is_empty() {
        return Err("cmis_grpc source selected but cmis_endpoint is empty".to_string());
    }

    let channel = if config.cmis_tls_enable {
        connect_tls(config).await?
    } else {
        connect_plaintext(&config.cmis_endpoint).await?
    };

    let mut client = MachineIdentityClient::new(channel);
    let resp = client
        .jwks(JwksRequest {})
        .await
        .map_err(|e| format!("CMIS JWKS RPC failed: {}", e.message()))?;
    Ok(resp.into_inner().jwks_json)
}

/// Cleartext gRPC channel (dev/loopback only).
async fn connect_plaintext(endpoint: &str) -> Result<Channel, String> {
    Endpoint::from_shared(format!("http://{endpoint}"))
        .map_err(|e| format!("invalid cmis_endpoint: {e}"))?
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .connect()
        .await
        .map_err(|e| format!("connect to CMIS (plaintext) failed: {e}"))
}

/// Hybrid post-quantum TLS gRPC channel with SHA-384 SPKI pinning.
async fn connect_tls(config: &FerroGateConfig) -> Result<Channel, String> {
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

    Endpoint::from_shared(format!("https://{}", config.cmis_endpoint))
        .map_err(|e| format!("invalid cmis_endpoint: {e}"))?
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .connect_with_connector(connector)
        .await
        .map_err(|e| format!("connect to CMIS (PQ-TLS) failed: {e}"))
}
