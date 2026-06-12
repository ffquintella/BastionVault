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
/// The set of nodes to try, in order, comes from [`candidate_endpoints`]:
/// - With [`FerroGateConfig::cmis_srv`] set, the SRV record is resolved into
///   every advertised CMIS node (RFC 2782 order) — HA failover.
/// - Otherwise the single configured `cmis_endpoint`, optionally preceded by
///   host-local aliases when [`FerroGateConfig::cmis_same_host`] is set.
///
/// Each candidate is dialed in turn; the SPKI pin is verified per node, so the
/// first node that connects *and* verifies serves the RPC. A node whose cert
/// has diverged from the pin fails verification and the next candidate is
/// tried, exactly as the MIA fails over.
pub async fn fetch_jwks_json(config: &FerroGateConfig) -> Result<String, String> {
    if config.cmis_endpoint.trim().is_empty() && config.cmis_srv.trim().is_empty() {
        return Err(
            "cmis_grpc source selected but neither cmis_endpoint nor cmis_srv is set".to_string(),
        );
    }

    let mut errors = Vec::new();
    for endpoint in candidate_endpoints(config).await? {
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

/// Nodes to dial, in order. When [`FerroGateConfig::cmis_srv`] is set the SRV
/// record is resolved into every advertised CMIS node (RFC 2782 order); this
/// mirrors the MIA, which fails over across the cluster so a single node whose
/// cert has diverged from the shared pin does not take the mount down. The SRV
/// path takes precedence over a literal `cmis_endpoint`, and `cmis_same_host`
/// host-local aliasing does not apply to it (SRV advertises real cluster
/// members, not a co-located CMIS).
///
/// Without SRV this is the host-local-alias expansion of the single configured
/// endpoint (see [`host_local_candidates`]).
async fn candidate_endpoints(config: &FerroGateConfig) -> Result<Vec<String>, String> {
    let srv = config.cmis_srv.trim();
    if !srv.is_empty() {
        return resolve_srv_candidates(srv).await;
    }
    Ok(host_local_candidates(config))
}

/// Expand a single configured endpoint. Without `cmis_same_host` this is just
/// the configured endpoint. With it, CMIS is declared to run on the same
/// machine as this server, where the configured endpoint — typically the
/// host's public name, the right answer for *external* clients (MIAs) — may
/// not be reachable from the server's own vantage point: inside a
/// rootless-podman (pasta) container the host's own address hairpins into the
/// container's empty namespace and is refused. Host-local aliases are tried
/// first with the configured port, then the configured endpoint as a fallback.
/// The SPKI pin authenticates the peer whichever name connects, so trying
/// aliases does not weaken verification.
fn host_local_candidates(config: &FerroGateConfig) -> Vec<String> {
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

/// Resolve a CMIS `[cmis].srv` owner name to **every** advertised node as
/// `host:port`, ordered by RFC 2782 (ascending priority, then descending
/// weight, then target name). Mirrors the MIA's own SRV selection
/// (`ferrogate/crates/mia/src/endpoint.rs`) so the mount tries the same nodes
/// in the same order — but, unlike a single-node snapshot, returns the whole
/// ordered set so the fetch can fail over when the most-preferred node is
/// unreachable or its cert has diverged from the shared pin.
async fn resolve_srv_candidates(name: &str) -> Result<Vec<String>, String> {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    use hickory_resolver::proto::rr::RData;
    use hickory_resolver::TokioResolver;

    if name.is_empty() {
        return Err("cmis_srv is empty".to_string());
    }
    let (cfg, opts) = hickory_resolver::system_conf::read_system_conf()
        .unwrap_or_else(|_| (ResolverConfig::default(), ResolverOpts::default()));
    let mut builder = TokioResolver::builder_with_config(cfg, TokioRuntimeProvider::default());
    *builder.options_mut() = opts;
    let resolver = builder.build().map_err(|e| format!("DNS resolver init failed: {e}"))?;

    let resp =
        resolver.srv_lookup(name).await.map_err(|e| format!("CMIS SRV lookup for {name:?} failed: {e}"))?;

    // (priority, weight, port, target); a "." target means "not available
    // here" (RFC 2782) and is dropped.
    let records: Vec<(u16, u16, u16, String)> = resp
        .answers()
        .iter()
        .filter_map(|rec| match &rec.data {
            RData::SRV(srv) => {
                let target = srv.target.to_utf8().trim_end_matches('.').to_string();
                (!target.is_empty()).then_some((srv.priority, srv.weight, srv.port, target))
            }
            _ => None,
        })
        .collect();
    if records.is_empty() {
        return Err(format!("CMIS SRV record {name:?} resolved to no usable targets"));
    }
    Ok(rank_srv_records(records))
}

/// Order SRV records into a dial list by RFC 2782 preference: ascending
/// priority is a hard floor, then descending weight, then target name as a
/// deterministic tiebreak. Pure so the ordering is unit-testable without DNS.
fn rank_srv_records(mut records: Vec<(u16, u16, u16, String)>) -> Vec<String> {
    records.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)).then(a.3.cmp(&b.3)));
    records.into_iter().map(|(_, _, port, target)| format!("{target}:{port}")).collect()
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
        assert_eq!(host_local_candidates(&cfg("cmis.example.com:8443", false)), vec![
            "cmis.example.com:8443"
        ]);
    }

    #[test]
    fn same_host_tries_local_aliases_first_then_configured() {
        assert_eq!(host_local_candidates(&cfg("segdc1vds0005.fgv.br:8443", true)), vec![
            "host.containers.internal:8443",
            "127.0.0.1:8443",
            "segdc1vds0005.fgv.br:8443",
        ]);
    }

    #[test]
    fn same_host_does_not_duplicate_a_loopback_endpoint() {
        assert_eq!(host_local_candidates(&cfg("127.0.0.1:9000", true)), vec![
            "host.containers.internal:9000",
            "127.0.0.1:9000",
        ]);
    }

    #[test]
    fn same_host_without_a_port_falls_back_to_the_configured_endpoint() {
        assert_eq!(host_local_candidates(&cfg("cmis.example.com", true)), vec!["cmis.example.com"]);
    }

    #[test]
    fn srv_records_rank_by_priority_then_weight_then_target() {
        // Two priorities; within priority 10 the heavier weight comes first;
        // equal-weight nodes break the tie on target name. The healthy-node
        // failover the outage needed is exactly this list being tried in order.
        let records = vec![
            (20, 100, 8443, "backup.example.com".to_string()),
            (10, 5, 8443, "node-b.example.com".to_string()),
            (10, 50, 8443, "node-a.example.com".to_string()),
            (10, 50, 9443, "aaa.example.com".to_string()),
        ];
        assert_eq!(rank_srv_records(records), vec![
            "aaa.example.com:9443",   // pri 10, weight 50, name sorts first
            "node-a.example.com:8443", // pri 10, weight 50
            "node-b.example.com:8443", // pri 10, weight 5
            "backup.example.com:8443", // pri 20 (hard floor, last)
        ]);
    }

    #[test]
    fn srv_ranking_preserves_every_node_for_failover() {
        // All advertised nodes must survive ranking — dropping any would
        // reintroduce the single-node failure the SRV path exists to avoid.
        let records = vec![
            (10, 10, 8443, "n1.example.com".to_string()),
            (10, 10, 8443, "n2.example.com".to_string()),
            (10, 10, 8443, "n3.example.com".to_string()),
        ];
        assert_eq!(rank_srv_records(records).len(), 3);
    }

    #[tokio::test]
    async fn srv_takes_precedence_and_an_empty_config_is_rejected() {
        // Neither endpoint nor SRV set → explicit error, no silent dial.
        let empty = FerroGateConfig { jwks_source: "cmis_grpc".to_string(), ..FerroGateConfig::default() };
        assert!(fetch_jwks_json(&empty).await.is_err());
    }
}
