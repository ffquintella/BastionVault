//! Shared HTTP client construction for Rustion-bound requests.
//!
//! Every outbound call to a Rustion bastion (probe, session open /
//! renew / kill, telemetry pull, recording fetch, enrolment attest /
//! deenrol) goes through `build_client_for(target, timeout)` so the
//! per-target TLS pinning model is honoured uniformly.
//!
//! When [`RustionTarget::tls_pinned_cert_pem`] is non-empty:
//! - The webpki-roots default trust store is **disabled**.
//! - The pinned leaf cert is added as the sole root.
//! - Hostname verification is **disabled** — pinning the exact leaf
//!   makes hostname matching redundant, and lets BV tolerate
//!   self-signed certs without SubjectAltName (common in pre-prod /
//!   lab deployments where operators don't want to mint a full CA).
//!
//! When the field is empty, we fall back to the standard reqwest
//! defaults (webpki-roots), preserving the original behaviour for
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
            .tls_built_in_root_certs(false)
            .add_root_certificate(cert)
            .danger_accept_invalid_hostnames(true);
    }

    builder
        .build()
        .map_err(|e| RvError::ErrString(format!("rustion: build http client: {e}")))
}
