//! Phase 9.2 — BV-side enrolment lifecycle: `attest`, `deenrol`.
//!
//! `attest` lands on every enrolled bastion once a week (the BV core
//! boot spawns a tokio interval). Rustion bumps the authority record's
//! `attestation_renew_at` on acceptance. The same envelope can be
//! triggered manually via `rustion_authority_attest` from the GUI.
//!
//! `deenrol` lands once, just before BV deletes the local target
//! record. Rustion tombstones the authority and refuses any further
//! envelope from the same pubkey. Belt-and-braces in case the
//! operator does a hard delete on the BV side: the on-bastion CLI
//! still has `rustion authority deenrol --name` for the symmetric
//! revocation.

#![deny(unsafe_code)]

use std::time::Duration;

use bv_crypto::BvrgMasterSigningKey;
use serde::Deserialize;

use crate::errors::RvError;

use super::config::RustionTarget;
use super::envelope::{self, OperatorContext};
use super::store::RustionStore;

#[derive(Debug, thiserror::Error)]
pub enum EnrolmentError {
    #[error("master signing key unavailable: {0}")]
    Master(String),
    #[error("target {0} not found in registry")]
    TargetNotFound(String),
    #[error("envelope build failed: {0}")]
    Envelope(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("upstream rejected: status={status} body={body}")]
    Http { status: u16, body: String },
}

impl From<EnrolmentError> for RvError {
    fn from(e: EnrolmentError) -> Self {
        RvError::ErrString(format!("rustion enrolment: {e}"))
    }
}

/// Result of an `attest` round-trip with a single bastion. The
/// `attested_at` / `expires_at` strings are RFC 3339 timestamps as
/// Rustion echoes them back; the caller may store the `expires_at`
/// to drive the next weekly tick deadline.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AttestResult {
    pub bastion_id: String,
    pub correlation_id: String,
    pub attested_at: String,
    pub expires_at: String,
}

/// Send an `attest` envelope to a single bastion. Used both by the
/// weekly timer (iterating every healthy target) and by the manual
/// `rustion_authority_attest` Tauri command (single bastion, immediate).
#[maybe_async::maybe_async]
pub async fn attest_bastion(
    store: &RustionStore,
    master: &BvrgMasterSigningKey,
    operator: &OperatorContext,
    bastion_id: &str,
) -> Result<AttestResult, EnrolmentError> {
    let target = store
        .get_target(bastion_id)
        .await
        .map_err(|e| EnrolmentError::Master(format!("{e}")))?
        .ok_or_else(|| EnrolmentError::TargetNotFound(bastion_id.into()))?;

    let built = envelope::build_attest(master, &target, operator)
        .map_err(|e| EnrolmentError::Envelope(format!("{e}")))?;

    let client = build_http_client().map_err(EnrolmentError::Transport)?;
    let url = format!(
        "https://{}/v1/authorities/attest",
        target.endpoint.trim_end_matches('/')
    );
    let resp = client
        .post(&url)
        .header("X-Rustion-Authority", "bastion-vault")
        .header("Content-Type", "application/octet-stream")
        .body(built.bytes)
        .send()
        .await
        .map_err(|e| EnrolmentError::Transport(format!("{e}")))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(EnrolmentError::Http {
            status: status.as_u16(),
            body,
        });
    }

    #[derive(Deserialize)]
    struct Body {
        attested_at: String,
        expires_at: String,
    }
    let body: Body = resp
        .json()
        .await
        .map_err(|e| EnrolmentError::Envelope(format!("body parse: {e}")))?;
    Ok(AttestResult {
        bastion_id: bastion_id.to_string(),
        correlation_id: built.correlation_id,
        attested_at: body.attested_at,
        expires_at: body.expires_at,
    })
}

/// Per-bastion result of the periodic re-attestation sweep.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AttestAllResult {
    pub attempted: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub results: Vec<AttestOutcome>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "status")]
pub enum AttestOutcome {
    #[serde(rename = "ok")]
    Ok(AttestResult),
    #[serde(rename = "err")]
    Err {
        bastion_id: String,
        error: String,
    },
}

/// Walk every enrolled bastion and send `attest`. Failures don't
/// short-circuit — the sweep continues so a single offline bastion
/// doesn't drop everyone else's attestation window. Caller emits
/// audit events from the returned vector.
#[maybe_async::maybe_async]
pub async fn attest_all(
    store: &RustionStore,
    master: &BvrgMasterSigningKey,
    operator: &OperatorContext,
) -> Result<AttestAllResult, EnrolmentError> {
    let targets = store
        .list_targets()
        .await
        .map_err(|e| EnrolmentError::Master(format!("{e}")))?;
    let mut out = AttestAllResult {
        attempted: 0,
        succeeded: 0,
        failed: 0,
        results: Vec::with_capacity(targets.len()),
    };
    for t in targets {
        out.attempted += 1;
        match attest_bastion(store, master, operator, &t.id).await {
            Ok(r) => {
                out.succeeded += 1;
                out.results.push(AttestOutcome::Ok(r));
            }
            Err(e) => {
                out.failed += 1;
                out.results.push(AttestOutcome::Err {
                    bastion_id: t.id,
                    error: e.to_string(),
                });
            }
        }
    }
    Ok(out)
}

/// Send a `deenrol` envelope to a single bastion. Returns the
/// correlation id so the BV audit chain can pair the local
/// `target.deenrolled` row with the matching `authority.deenrolled`
/// Rustion-side entry (once the witness puller picks it up).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DeenrolResult {
    pub bastion_id: String,
    pub correlation_id: String,
}

#[maybe_async::maybe_async]
pub async fn deenrol_bastion(
    target: &RustionTarget,
    master: &BvrgMasterSigningKey,
    operator: &OperatorContext,
    reason: &str,
) -> Result<DeenrolResult, EnrolmentError> {
    let built = envelope::build_deenrol(master, target, operator, reason)
        .map_err(|e| EnrolmentError::Envelope(format!("{e}")))?;

    let client = build_http_client().map_err(EnrolmentError::Transport)?;
    let url = format!(
        "https://{}/v1/authorities/deenrol",
        target.endpoint.trim_end_matches('/')
    );
    let resp = client
        .post(&url)
        .header("X-Rustion-Authority", "bastion-vault")
        .header("Content-Type", "application/octet-stream")
        .body(built.bytes)
        .send()
        .await
        .map_err(|e| EnrolmentError::Transport(format!("{e}")))?;

    let status = resp.status();
    // We accept 200/204; we also tolerate 404 / 410 (Rustion already
    // forgot us — fine, we're trying to delete) so the BV-side
    // deletion proceeds idempotently.
    if !status.is_success()
        && status != reqwest::StatusCode::NOT_FOUND
        && status != reqwest::StatusCode::GONE
    {
        let body = resp.text().await.unwrap_or_default();
        return Err(EnrolmentError::Http {
            status: status.as_u16(),
            body,
        });
    }
    Ok(DeenrolResult {
        bastion_id: target.id.clone(),
        correlation_id: built.correlation_id,
    })
}

fn build_http_client() -> Result<reqwest::Client, String> {
    reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("{e}"))
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attest_outcome_serializes_with_status_tag() {
        let ok = AttestOutcome::Ok(AttestResult {
            bastion_id: "rt_1".into(),
            correlation_id: "c1".into(),
            attested_at: "2026-05-20T12:00:00Z".into(),
            expires_at: "2026-05-27T12:00:00Z".into(),
        });
        let j = serde_json::to_string(&ok).unwrap();
        assert!(j.contains("\"status\":\"ok\""));
        assert!(j.contains("\"bastion_id\":\"rt_1\""));

        let err = AttestOutcome::Err {
            bastion_id: "rt_2".into(),
            error: "transport: connection refused".into(),
        };
        let j = serde_json::to_string(&err).unwrap();
        assert!(j.contains("\"status\":\"err\""));
        assert!(j.contains("connection refused"));
    }
}
