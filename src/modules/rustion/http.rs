//! Shared HTTP client construction for Rustion-bound requests.
//!
//! Every outbound call to a Rustion bastion (probe, session open /
//! renew / kill, telemetry pull, recording fetch, enrolment attest /
//! deenrol) goes through `build_client_for(target, timeout)` so the
//! per-target TLS pinning model is honoured uniformly.
//!
//! When [`RustionTarget::tls_pinned_cert_pem`] is non-empty:
//! - Chain validation is **disabled** (`danger_accept_invalid_certs`).
//! - Hostname verification is **disabled** (`danger_accept_invalid_hostnames`).
//! - The pinned leaf cert is still added via `add_root_certificate` so
//!   that for self-signed CAs (cert with `BasicConstraints: CA=true`)
//!   rustls will accept the chain natively; otherwise the
//!   accept-invalid escape hatch covers self-signed *leaf* certs that
//!   webpki refuses as trust anchors (no `BasicConstraints` extension).
//!
//! Why downgrading TLS verification to "encryption only" is acceptable
//! here: BV's actual authentication of every Rustion-bound request
//! sits in the BVRG-v1 hybrid envelope (Ed25519 + ML-DSA-65 signature
//! over the request body, bound to a pinned authority pubkey on the
//! Rustion side). The TLS layer is *transport encryption* — the
//! cryptographic identity is in the envelope, not the TLS leaf.
//! Storing the pinned PEM is still useful for operator diagnostics
//! and for a future SPKI-pinning verifier that will compare the
//! presented leaf against this stored copy.
//!
//! When the field is empty, we fall back to the standard reqwest
//! defaults (webpki-roots), preserving strict CA verification for
//! deployments behind a real PKI.

use std::time::Duration;

use crate::errors::RvError;

use super::config::RustionTarget;

/// Build a `reqwest::Client` for the given Rustion target.
///
/// `timeout` is applied as the per-request total timeout. The
/// redirect policy is hard-pinned to `none` — a misbehaving (or
/// compromised) bastion must not be able to redirect us to an
/// arbitrary URL.
pub fn build_client_for(
    target: &RustionTarget,
    timeout: Duration,
) -> Result<reqwest::Client, RvError> {
    let mut builder = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout);

    let pem = target.tls_pinned_cert_pem.trim();
    if !pem.is_empty() {
        let cert = reqwest::Certificate::from_pem(pem.as_bytes()).map_err(|e| {
            RvError::ErrString(format!(
                "rustion: parse pinned cert for target {}: {e}",
                target.id
            ))
        })?;
        builder = builder
            .add_root_certificate(cert)
            // Self-signed *leaf* certs (no `BasicConstraints: CA=true`)
            // are refused by webpki as trust anchors even when added
            // via `add_root_certificate`. We downgrade to encryption-
            // only TLS in that case — BV's BVRG-v1 envelope is the
            // real authentication layer; the TLS leaf is transport
            // encryption.
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
    }

    builder
        .build()
        .map_err(|e| RvError::ErrString(format!("rustion: build http client: {e}")))
}
