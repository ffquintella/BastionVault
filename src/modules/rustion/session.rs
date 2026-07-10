//! Session-open orchestration on the BV side.
//!
//! `POST rustion/session/open` calls into this module. The handler:
//!   1. Resolves the connection profile's pinned bastion list (or
//!      empty = global pool).
//!   2. Runs the dispatcher to get an ordered candidate list.
//!   3. For each candidate, builds a BVRG-v1 `open` envelope via the
//!      master signing-key stub (Phase 9 replaces with PKI cert) and
//!      POSTs it at the target's `/v1/sessions` endpoint.
//!   4. On 4xx → halt + surface the error. On transport / 5xx →
//!      advance to the next candidate.
//!   5. On 201 → return `{session_id, host, port, ticket, expires_at,
//!      protocol, recording_id, bastion_id}` to the caller.
//!
//! Phase 3 ships the orchestration; the GUI-side wiring (Tauri command
//! + Connection-tab editor) and the resource-side connection-profile
//!   shape land in follow-up commits.

#![deny(unsafe_code)]

use std::time::Duration;

use bv_crypto::BvrgMasterSigningKey;
use serde::{Deserialize, Serialize};

use crate::errors::RvError;

use super::config::RustionTarget;
use super::dispatcher::{self, DispatchPlan, OpenAttemptOutcome};
use super::envelope::{self, BuiltEnvelope, CredentialMaterial, OperatorContext};
use super::store::RustionStore;
use super::RustionTargetHealth;

/// Caller payload for `POST rustion/session/open`. The connection
/// profile lives on the resource record; for Phase 3 the handler
/// accepts the resolved bits directly so the dispatcher can run
/// without a full profile-resolver pass. Phase 3.1's resource-side
/// integration assembles the request from a `ConnectionProfile`.
#[derive(Debug, Clone, Deserialize)]
pub struct SessionOpenRequest {
    /// Connection-profile target: the operator's eventual SSH/RDP
    /// destination. Echoed into the envelope's `target` block so
    /// Rustion knows where to dial after consuming the ticket.
    pub target_host: String,
    pub target_port: u16,
    /// `"ssh" | "rdp"`.
    pub target_protocol: String,
    #[serde(default)]
    pub target_hostkey_pin: Option<String>,

    /// Resolved credential material from the resource's credential
    /// source (Secret / LDAP / SSH-engine / PKI). The session-open
    /// handler doesn't run the resolver — Phase 3.1's resource-side
    /// path does, and hands the result here.
    pub credential_kind: String,
    pub credential_username: String,
    #[serde(with = "serde_bytes_compat")]
    pub credential_material: Vec<u8>,
    /// For `ssh-cert`: the signed OpenSSH certificate text, sealed into
    /// the envelope's `credential.extra["cert"]`. `material` carries the
    /// ephemeral private key. Empty for every other kind.
    #[serde(default)]
    pub credential_cert: Option<String>,
    /// For `rdp-cert` (smart-card RDP through the bastion): the DER
    /// private key matching the certificate in `credential_material`.
    /// Sealed into the envelope's `credential.extra["key"]`. Empty for
    /// every other kind.
    #[serde(default, with = "serde_bytes_compat")]
    pub credential_key: Vec<u8>,
    /// For `rdp-cert`: the smart-card PIN, sealed into
    /// `credential.extra["pin"]`. Empty for every other kind.
    #[serde(default)]
    pub credential_pin: String,
    /// For `rdp-cert`: optional AD domain / realm, sealed into
    /// `credential.extra["domain"]`. Empty when the cert's UPN is
    /// authoritative.
    #[serde(default)]
    pub credential_domain: String,

    /// Session policy from the profile. Rustion clamps `ttl_secs` to
    /// the authority record's `max_session_secs` regardless.
    pub ttl_secs: u32,
    pub max_renewals: u8,
    /// `"always" | "off" | "input-redacted"`.
    pub recording: String,

    /// Connection-profile bastion preference. `None` or empty list =
    /// global random pool. A non-empty list pins the order.
    #[serde(default)]
    pub bastions: Option<Vec<String>>,

    /// When the `bastions` list was resolved from a named bastion group,
    /// the group name — purely for audit attribution (`bastion_selection
    /// = "group"`). `None` means the list came from a profile/tier
    /// literal or the random pool.
    #[serde(default)]
    pub bastion_group: Option<String>,

    /// Shuffle the (health-filtered) bastion list before walking it.
    /// Set when the resolved group's `selection` is `random`. Ignored
    /// unless `bastions` is a non-empty list.
    #[serde(default)]
    pub bastion_shuffle: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionOpenResponse {
    pub session_id: String,
    pub host: String,
    pub port: u16,
    pub ticket: String,
    pub expires_at: String,
    pub protocol: String,
    pub recording_id: String,
    /// Which Rustion target the session landed on. Audit handlers
    /// stamp this on the `session.open` event.
    pub bastion_id: String,
    pub bastion_name: String,
    /// `pinned | ordered-fallback | random-pool` per the spec.
    pub bastion_selection: &'static str,
    /// IDs the dispatcher tried (in order) before this one
    /// accepted. Empty on a first-candidate success.
    pub bastion_candidates_tried: Vec<String>,
    /// The correlation id BV picked when building the `open` envelope.
    /// The GUI needs this verbatim to issue subsequent `renew` / `kill`
    /// requests — Rustion verifies that the renew/kill envelope's
    /// correlation_id matches the one stamped on the session at open
    /// time. Phase 5.
    pub correlation_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionOpenError {
    #[error("no candidate Rustion targets available — every target is unhealthy, disabled, or unregistered")]
    NoCandidates,
    #[error("every candidate refused the session — see `attempts` for per-target errors")]
    AllRejected { attempts: Vec<AttemptOutcome> },
    #[error("master signing key not initialised: {0}")]
    Master(String),
    #[error("envelope build failed: {0}")]
    Envelope(String),
    #[error("inner store error: {0}")]
    Store(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct AttemptOutcome {
    pub bastion_id: String,
    pub bastion_name: String,
    pub outcome: String,
}

/// Run the dispatcher + envelope build + POST loop and return the
/// session-ticket bundle on success. The caller supplies the
/// operator context (resolved from the calling token's metadata)
/// and the request payload (resolved from the connection profile +
/// credential source).
#[maybe_async::maybe_async]
pub async fn open_session(
    store: &RustionStore,
    master: &BvrgMasterSigningKey,
    operator: &OperatorContext,
    request: &SessionOpenRequest,
) -> Result<SessionOpenResponse, SessionOpenError> {
    // 1. Pull the registry + health snapshot the dispatcher needs.
    let ids = store.list_target_ids().await.map_err(|e| SessionOpenError::Store(format!("{e}")))?;
    let mut targets: Vec<RustionTarget> = Vec::with_capacity(ids.len());
    for id in &ids {
        if let Some(t) = store.get_target(id).await.map_err(|e| SessionOpenError::Store(format!("{e}")))? {
            targets.push(t);
        }
    }
    let mut health_cache: Vec<(String, RustionTargetHealth)> = Vec::new();
    for t in &targets {
        if let Some(h) = store.get_health(&t.id).await.map_err(|e| SessionOpenError::Store(format!("{e}")))? {
            health_cache.push((t.id.clone(), h));
        }
    }
    let health = |id: &str| -> Option<RustionTargetHealth> {
        health_cache.iter().find(|(k, _)| k == id).map(|(_, v)| v.clone())
    };

    let pinned_ref: Option<&[String]> = request.bastions.as_deref();
    let plan: DispatchPlan = dispatcher::plan(pinned_ref, &targets, &health, &mut rand::rng());

    if plan.candidates.is_empty() {
        return Err(SessionOpenError::NoCandidates);
    }

    // 2. Walk candidates. On 4xx → halt, on transport/5xx → advance.
    // Client is built per-target inside the loop — each Rustion can
    // carry its own pinned TLS leaf cert.
    let mut attempts: Vec<AttemptOutcome> = Vec::new();
    let mut tried_ids: Vec<String> = Vec::new();

    for target in &plan.candidates {
        tried_ids.push(target.id.clone());
        let client = super::http::build_client_for(target, Duration::from_secs(10))
            .map_err(|e| SessionOpenError::Master(format!("http client: {e}")))?;
        let built = match build_open_envelope(master, target, operator, request) {
            Ok(b) => b,
            Err(e) => {
                attempts.push(AttemptOutcome {
                    bastion_id: target.id.clone(),
                    bastion_name: target.name.clone(),
                    outcome: format!("envelope_build: {e}"),
                });
                return Err(SessionOpenError::Envelope(format!("target `{}`: {e}", target.name)));
            }
        };

        let outcome = post_envelope(&client, target, &built).await;
        match outcome {
            OpenAttemptOutcome::Success => {
                // The post_envelope wrapper returns the parsed
                // response body alongside Success; we reach into the
                // dedicated `post_envelope_with_body` call below for
                // the bundle. Marker case unreachable.
                unreachable!("OpenAttemptOutcome::Success returned without body — bug");
            }
            OpenAttemptOutcome::Transport(err_str) => {
                attempts.push(AttemptOutcome {
                    bastion_id: target.id.clone(),
                    bastion_name: target.name.clone(),
                    outcome: format!("transport: {err_str}"),
                });
                continue;
            }
            OpenAttemptOutcome::Http(status, body) => {
                attempts.push(AttemptOutcome {
                    bastion_id: target.id.clone(),
                    bastion_name: target.name.clone(),
                    outcome: format!("http {status}: {body}"),
                });
                if !dispatcher::should_advance(&OpenAttemptOutcome::Http(status, body.clone())) {
                    // Halt on 4xx — surface the per-target error.
                    return Err(SessionOpenError::AllRejected { attempts });
                }
                continue;
            }
        }
    }

    // Walked the whole list without success.
    Err(SessionOpenError::AllRejected { attempts })
}

/// Build the `open` envelope plus inline the post in one go so the
/// success path can return the parsed body. Keeping it inline avoids
/// the orphan `OpenAttemptOutcome::Success` case that has no body
/// channel today.
#[maybe_async::maybe_async]
pub async fn open_session_v2(
    store: &RustionStore,
    master: &BvrgMasterSigningKey,
    operator: &OperatorContext,
    request: &SessionOpenRequest,
) -> Result<SessionOpenResponse, SessionOpenError> {
    let ids = store.list_target_ids().await.map_err(|e| SessionOpenError::Store(format!("{e}")))?;
    let mut targets: Vec<RustionTarget> = Vec::with_capacity(ids.len());
    for id in &ids {
        if let Some(t) = store.get_target(id).await.map_err(|e| SessionOpenError::Store(format!("{e}")))? {
            targets.push(t);
        }
    }
    let mut health_cache: Vec<(String, RustionTargetHealth)> = Vec::new();
    for t in &targets {
        if let Some(h) = store.get_health(&t.id).await.map_err(|e| SessionOpenError::Store(format!("{e}")))? {
            health_cache.push((t.id.clone(), h));
        }
    }
    let health = |id: &str| -> Option<RustionTargetHealth> {
        health_cache.iter().find(|(k, _)| k == id).map(|(_, v)| v.clone())
    };

    // Scope the (`!Send`) ThreadRng to the synchronous planning step so
    // it is dropped before the `.await` loop below — otherwise the
    // session-open future stops being `Send`.
    let plan: DispatchPlan = {
        let mut rng = rand::rng();
        match (request.bastions.as_deref(), request.bastion_group.as_deref()) {
            // List resolved from a named group → dispatch as Group,
            // honouring the group's ordered/random selection.
            (Some(members), Some(_group)) if !members.is_empty() => {
                dispatcher::plan_group(members, request.bastion_shuffle, &targets, &health, &mut rng)
            }
            // Profile/tier literal list, or empty → existing pinned/random-pool logic.
            (pinned, _) => dispatcher::plan(pinned, &targets, &health, &mut rng),
        }
    };
    if plan.candidates.is_empty() {
        return Err(SessionOpenError::NoCandidates);
    }

    // Per-target client construction; honours `tls_pinned_cert_pem`.
    let mut attempts: Vec<AttemptOutcome> = Vec::new();
    let mut tried_ids: Vec<String> = Vec::new();
    let bastion_selection = plan.mode.as_str();

    for target in &plan.candidates {
        tried_ids.push(target.id.clone());
        let client = super::http::build_client_for(target, Duration::from_secs(10))
            .map_err(|e| SessionOpenError::Master(format!("http client: {e}")))?;
        let built = match build_open_envelope(master, target, operator, request) {
            Ok(b) => b,
            Err(e) => {
                return Err(SessionOpenError::Envelope(format!("target `{}`: {e}", target.name)));
            }
        };

        let url = format!("https://{}/v1/sessions", target.endpoint.trim_end_matches('/'));
        let send = client
            .post(&url)
            .header("X-Rustion-Authority", "bastion-vault")
            .header("Content-Type", "application/octet-stream")
            .body(built.bytes.clone())
            .send()
            .await;

        let resp = match send {
            Ok(r) => r,
            Err(e) => {
                attempts.push(AttemptOutcome {
                    bastion_id: target.id.clone(),
                    bastion_name: target.name.clone(),
                    outcome: format!("transport: {e}"),
                });
                continue;
            }
        };
        let status = resp.status();
        if status.is_success() {
            let body: RustionSessionBody = match resp.json().await {
                Ok(b) => b,
                Err(e) => {
                    attempts.push(AttemptOutcome {
                        bastion_id: target.id.clone(),
                        bastion_name: target.name.clone(),
                        outcome: format!("body parse: {e}"),
                    });
                    continue;
                }
            };

            return Ok(SessionOpenResponse {
                session_id: body.session_id,
                host: body.host,
                port: body.port,
                ticket: body.ticket,
                expires_at: body.expires_at,
                protocol: body.protocol,
                recording_id: body.recording_id,
                bastion_id: target.id.clone(),
                bastion_name: target.name.clone(),
                bastion_selection,
                bastion_candidates_tried: tried_ids.iter().take(tried_ids.len() - 1).cloned().collect(),
                correlation_id: built.correlation_id.clone(),
            });
        }

        // Non-2xx → record + decide whether to advance.
        let status_code = status.as_u16();
        let body_text = resp.text().await.unwrap_or_else(|_| String::new());
        attempts.push(AttemptOutcome {
            bastion_id: target.id.clone(),
            bastion_name: target.name.clone(),
            outcome: format!("http {status_code}: {body_text}"),
        });
        if !dispatcher::should_advance(&OpenAttemptOutcome::Http(status_code, body_text)) {
            return Err(SessionOpenError::AllRejected { attempts });
        }
    }

    Err(SessionOpenError::AllRejected { attempts })
}

#[derive(Debug, Deserialize)]
struct RustionSessionBody {
    session_id: String,
    host: String,
    port: u16,
    ticket: String,
    expires_at: String,
    protocol: String,
    recording_id: String,
}

fn build_open_envelope(
    master: &BvrgMasterSigningKey,
    target: &RustionTarget,
    operator: &OperatorContext,
    request: &SessionOpenRequest,
) -> Result<BuiltEnvelope, RvError> {
    envelope::build_open(
        master,
        target,
        operator,
        &request.target_host,
        request.target_port,
        &request.target_protocol,
        request.target_hostkey_pin.clone(),
        CredentialMaterial {
            kind: request.credential_kind.clone(),
            username: request.credential_username.clone(),
            material: request.credential_material.clone(),
            cert: request.credential_cert.clone(),
            rdp_cert: if request.credential_kind == "rdp-cert" {
                Some(envelope::RdpCertMaterial {
                    private_key_der: request.credential_key.clone(),
                    pin: request.credential_pin.clone(),
                    domain: request.credential_domain.clone(),
                })
            } else {
                None
            },
        },
        request.ttl_secs,
        request.max_renewals,
        &request.recording,
    )
    .map_err(|e| RvError::ErrString(format!("{e}")))
}

#[maybe_async::maybe_async]
async fn post_envelope(client: &reqwest::Client, target: &RustionTarget, built: &BuiltEnvelope) -> OpenAttemptOutcome {
    let url = format!("https://{}/v1/sessions", target.endpoint.trim_end_matches('/'));
    let result = client
        .post(&url)
        .header("X-Rustion-Authority", "bastion-vault")
        .header("Content-Type", "application/octet-stream")
        .body(built.bytes.clone())
        .send()
        .await;

    match result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if status < 300 {
                OpenAttemptOutcome::Success
            } else {
                OpenAttemptOutcome::Http(status, body)
            }
        }
        Err(e) => OpenAttemptOutcome::Transport(format!("{e}")),
    }
}

// ─── Phase 5: renew + kill ───────────────────────────────────────────

/// Caller payload for `POST rustion/session/renew`.
#[derive(Debug, Clone, Deserialize)]
pub struct SessionRenewRequest {
    pub bastion_id: String,
    pub session_id: String,
    pub correlation_id: String,
    pub extend_secs: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionRenewResponse {
    pub session_id: String,
    pub expires_at: String,
    pub renewals_used: u8,
    pub max_renewals: u8,
    pub bastion_id: String,
}

/// Caller payload for `DELETE rustion/session/kill`.
#[derive(Debug, Clone, Deserialize)]
pub struct SessionKillRequest {
    pub bastion_id: String,
    pub session_id: String,
    pub correlation_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionKillResponse {
    pub session_id: String,
    pub terminated_at: String,
    pub bastion_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionRenewError {
    #[error("bastion `{0}` not found in target registry")]
    BastionNotFound(String),
    #[error("master signing-key: {0}")]
    Master(String),
    #[error("envelope build: {0}")]
    Envelope(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("rustion returned HTTP {status}: {body}")]
    Http { status: u16, body: String },
}

/// Build a `renew` envelope and POST it at the bastion that opened the
/// session. Phase 5.
#[maybe_async::maybe_async]
pub async fn renew_session(
    store: &RustionStore,
    master: &BvrgMasterSigningKey,
    operator: &OperatorContext,
    request: &SessionRenewRequest,
) -> Result<SessionRenewResponse, SessionRenewError> {
    let target = store
        .get_target(&request.bastion_id)
        .await
        .map_err(|e| SessionRenewError::Master(format!("{e}")))?
        .ok_or_else(|| SessionRenewError::BastionNotFound(request.bastion_id.clone()))?;

    let built = envelope::build_renew(master, &target, operator, &request.correlation_id, request.extend_secs)
        .map_err(|e| SessionRenewError::Envelope(format!("{e}")))?;

    let client = super::http::build_client_for(&target, Duration::from_secs(10))
        .map_err(|e| SessionRenewError::Transport(format!("{e}")))?;
    let url = format!("https://{}/v1/sessions/{}/renew", target.endpoint.trim_end_matches('/'), request.session_id);
    let resp = client
        .post(&url)
        .header("X-Rustion-Authority", "bastion-vault")
        .header("Content-Type", "application/octet-stream")
        .body(built.bytes)
        .send()
        .await
        .map_err(|e| SessionRenewError::Transport(format!("{e}")))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(SessionRenewError::Http { status: status.as_u16(), body });
    }

    #[derive(Deserialize)]
    struct Body {
        session_id: String,
        expires_at: String,
        renewals_used: u8,
        max_renewals: u8,
    }
    let body: Body = resp.json().await.map_err(|e| SessionRenewError::Envelope(format!("body parse: {e}")))?;

    Ok(SessionRenewResponse {
        session_id: body.session_id,
        expires_at: body.expires_at,
        renewals_used: body.renewals_used,
        max_renewals: body.max_renewals,
        bastion_id: request.bastion_id.clone(),
    })
}

/// Build a `kill` envelope and DELETE it at the bastion that opened
/// the session. Phase 5.
#[maybe_async::maybe_async]
pub async fn kill_session(
    store: &RustionStore,
    master: &BvrgMasterSigningKey,
    operator: &OperatorContext,
    request: &SessionKillRequest,
) -> Result<SessionKillResponse, SessionRenewError> {
    let target = store
        .get_target(&request.bastion_id)
        .await
        .map_err(|e| SessionRenewError::Master(format!("{e}")))?
        .ok_or_else(|| SessionRenewError::BastionNotFound(request.bastion_id.clone()))?;

    let built = envelope::build_kill(master, &target, operator, &request.correlation_id)
        .map_err(|e| SessionRenewError::Envelope(format!("{e}")))?;

    let client = super::http::build_client_for(&target, Duration::from_secs(10))
        .map_err(|e| SessionRenewError::Transport(format!("{e}")))?;
    let url = format!("https://{}/v1/sessions/{}", target.endpoint.trim_end_matches('/'), request.session_id);
    let resp = client
        .delete(&url)
        .header("X-Rustion-Authority", "bastion-vault")
        .header("Content-Type", "application/octet-stream")
        .body(built.bytes)
        .send()
        .await
        .map_err(|e| SessionRenewError::Transport(format!("{e}")))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(SessionRenewError::Http { status: status.as_u16(), body });
    }

    #[derive(Deserialize)]
    struct Body {
        session_id: String,
        terminated_at: String,
    }
    let body: Body = resp.json().await.map_err(|e| SessionRenewError::Envelope(format!("body parse: {e}")))?;
    Ok(SessionKillResponse {
        session_id: body.session_id,
        terminated_at: body.terminated_at,
        bastion_id: request.bastion_id.clone(),
    })
}

// HTTP client construction moved to `super::http::build_client_for`,
// which honours per-target TLS pinning. The previous helper was
// removed when the pinning model landed.

// Small `Vec<u8>` ↔ CBOR byte-string serde adapter so the request
// payload's `credential_material` survives a JSON / CBOR / serde
// roundtrip. The same wrapper shape as bv_crypto's bvrg payload.
mod serde_bytes_compat {
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(dead_code)]
    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        // Accept either a JSON array of u8s or a base64 string for
        // the JSON-over-HTTP case the GUI uses.
        use serde::de::Error;
        let value = serde_json::Value::deserialize(d)?;
        match value {
            serde_json::Value::Array(arr) => arr
                .into_iter()
                .map(|v| {
                    v.as_u64()
                        .and_then(|n| u8::try_from(n).ok())
                        .ok_or_else(|| Error::custom("array element must be u8"))
                })
                .collect(),
            serde_json::Value::String(s) => {
                use base64::{engine::general_purpose::STANDARD, Engine as _};
                STANDARD.decode(s.as_bytes()).map_err(|e| Error::custom(format!("base64 decode: {e}")))
            }
            _ => Err(Error::custom("credential_material must be a base64 string or u8 array")),
        }
    }
}
