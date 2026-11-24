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

    /// `Some(command)` for the exec form (`features/rustion-agent-exec.md`):
    /// the envelope seals `kind = "exec"` and this command, only bastions
    /// that advertise `ssh_exec` and carry an SSH listener pin are tried,
    /// and the open is refused unless the bastion echoes `kind: "exec"`.
    #[serde(default)]
    pub exec_command: Option<String>,
}

/// Where the vault dials to redeem an exec ticket: the bastion's SSH
/// listener and the host-key pin discovered from it (`GET /v1/listeners`,
/// stored on the target record), the same pair the desktop app's
/// interactive path dials with.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExecDial {
    pub host: String,
    pub port: u16,
    /// `SHA256:<base64>` of the listener's host key. Never empty: a bastion
    /// without one is not tried for exec.
    pub host_key_pin: String,
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
    /// `Some("exec")` for an exec open, checked against the bastion's own
    /// echo; `None` for an interactive one.
    pub kind: Option<String>,
    /// For an exec open: where to dial and which host key to require.
    pub exec_dial: Option<ExecDial>,
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
    /// Exec form: no candidate could take an exec — none advertises
    /// `ssh_exec` on `GET /v1/authorities/self`, has an SSH listener pin, or
    /// answered the capability read. Nothing was posted.
    #[error("no candidate bastion can run an agent command — see `attempts`")]
    ExecUnavailable { attempts: Vec<AttemptOutcome> },
    /// Exec form: the bastion opened the session but did not echo
    /// `kind: "exec"` (a Rustion that ignores the field opens an
    /// *interactive* session). The session was ended with a `kill`
    /// envelope; its ticket is never handed out.
    #[error(
        "bastion `{bastion_name}` answered the exec open without `kind: \"exec\"`; session {session_id} was {}",
        if *killed { "ended" } else { "left to expire (the kill was refused)" }
    )]
    ExecKindNotEchoed { bastion_name: String, session_id: String, killed: bool },
    /// The envelope would exceed the bastion's cap, or the exec form breaks
    /// one of its open rules; nothing was posted.
    #[error("{0}")]
    Refused(envelope::OpenEnvelopeError),
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
    authority: &str,
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
            Err(e @ envelope::OpenEnvelopeError::Bvrg(_)) => {
                attempts.push(AttemptOutcome {
                    bastion_id: target.id.clone(),
                    bastion_name: target.name.clone(),
                    outcome: format!("envelope_build: {e}"),
                });
                return Err(SessionOpenError::Envelope(format!("target `{}`: {e}", target.name)));
            }
            Err(e) => return Err(SessionOpenError::Refused(e)),
        };

        let outcome = post_envelope(&client, target, authority, &built).await;
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
    authority: &str,
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

    open_on_candidates(&plan.candidates, plan.mode.as_str(), master, authority, operator, request).await
}

/// Walk the dispatcher's candidates: build the envelope, POST it, return
/// the first bundle a bastion grants. Transport and 5xx advance, 4xx halts.
/// The exec form (`features/rustion-agent-exec.md`) adds three fail-closed
/// checks: the capability and the listener pin before posting, the open
/// rules and size cap before the first POST, and the `kind: "exec"` echo on
/// the `201`.
#[maybe_async::maybe_async]
pub(crate) async fn open_on_candidates(
    candidates: &[RustionTarget],
    bastion_selection: &'static str,
    master: &BvrgMasterSigningKey,
    authority: &str,
    operator: &OperatorContext,
    request: &SessionOpenRequest,
) -> Result<SessionOpenResponse, SessionOpenError> {
    // Per-target client construction; honours `tls_pinned_cert_pem`.
    let mut attempts: Vec<AttemptOutcome> = Vec::new();
    let mut tried_ids: Vec<String> = Vec::new();
    let exec = request.exec_command.as_deref();
    let mut posted = false;

    for target in candidates {
        tried_ids.push(target.id.clone());
        let attempt = |outcome: String| AttemptOutcome {
            bastion_id: target.id.clone(),
            bastion_name: target.name.clone(),
            outcome,
        };
        let client = super::http::build_client_for(target, Duration::from_secs(10))
            .map_err(|e| SessionOpenError::Master(format!("http client: {e}")))?;
        // Exec: only a bastion with an SSH listener pin that advertises
        // `ssh_exec` is posted to. Absence of the capability means "not
        // supported" (never inferred from the absence of an error); when
        // every candidate is skipped the open is `ExecUnavailable`.
        if exec.is_some() {
            if target.ssh_host_key_fingerprint.trim().is_empty() {
                attempts.push(attempt(
                    "exec_listener_unpinned: the bastion advertises no SSH listener host-key pin \
                     (refresh its listeners); an exec is never dialed unpinned"
                        .into(),
                ));
                continue;
            }
            match fetch_exec_capability(&client, target, authority).await {
                Ok(true) => {}
                Ok(false) => {
                    attempts.push(attempt(
                        "exec_unsupported: the bastion does not advertise `ssh_exec` on /v1/authorities/self \
                         (Rustion 0.20.0 or later with [server] ssh_exec_enabled is required)"
                            .into(),
                    ));
                    continue;
                }
                Err(e) => {
                    attempts.push(attempt(format!("exec_capability_unreadable: {e}")));
                    continue;
                }
            }
        }
        let built = match build_open_envelope(master, target, operator, request) {
            Ok(b) => b,
            Err(e @ envelope::OpenEnvelopeError::Bvrg(_)) => {
                return Err(SessionOpenError::Envelope(format!("target `{}`: {e}", target.name)));
            }
            // Size and exec-form refusals do not depend on the candidate.
            Err(e) => return Err(SessionOpenError::Refused(e)),
        };

        posted = true;
        let url = format!("https://{}/v1/sessions", target.endpoint.trim_end_matches('/'));
        let send = client
            .post(&url)
            .header("X-Rustion-Authority", authority)
            .header("Content-Type", "application/octet-stream")
            .body(built.bytes.clone())
            .send()
            .await;

        let resp = match send {
            Ok(r) => r,
            Err(e) => {
                attempts.push(attempt(format!("transport: {e}")));
                continue;
            }
        };
        let status = resp.status();
        if status.is_success() {
            let body: RustionSessionBody = match resp.json().await {
                Ok(b) => b,
                Err(e) => {
                    attempts.push(attempt(format!("body parse: {e}")));
                    continue;
                }
            };
            let exec_dial = match exec {
                None => None,
                Some(_) if body.kind.as_deref() == Some("exec") => Some(ExecDial {
                    host: String::new(),
                    port: 0,
                    host_key_pin: target.ssh_host_key_fingerprint.trim().to_string(),
                }),
                Some(_) => {
                    // An older bastion ignored `kind` and minted an
                    // interactive ticket: end the session, never return the
                    // ticket, and try no other candidate.
                    let killed = kill_session_on(
                        target,
                        master,
                        authority,
                        operator,
                        &body.session_id,
                        &built.correlation_id,
                    )
                    .await
                    .map_err(|e| {
                        log::warn!(
                            target: "security",
                            "rustion: exec open on `{}` was not echoed as exec and the kill of session {} failed: {e}",
                            target.name,
                            body.session_id
                        )
                    })
                    .is_ok();
                    return Err(SessionOpenError::ExecKindNotEchoed {
                        bastion_name: target.name.clone(),
                        session_id: body.session_id,
                        killed,
                    });
                }
            };
            let exec_dial = exec_dial.map(|d| {
                let (host, port) = exec_dial_coords(target, &body.host, body.port);
                ExecDial { host, port, ..d }
            });

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
                kind: body.kind,
                exec_dial,
            });
        }

        // Non-2xx → record + decide whether to advance.
        let status_code = status.as_u16();
        let body_text = resp.text().await.unwrap_or_else(|_| String::new());
        attempts.push(attempt(format!("http {status_code}: {body_text}")));
        if !dispatcher::should_advance(&OpenAttemptOutcome::Http(status_code, body_text)) {
            return Err(SessionOpenError::AllRejected { attempts });
        }
    }

    if exec.is_some() && !posted {
        return Err(SessionOpenError::ExecUnavailable { attempts });
    }
    Err(SessionOpenError::AllRejected { attempts })
}

/// Whether an `/v1/authorities/self` body advertises agent exec. Only an
/// explicit `"ssh_exec"` in `capabilities` counts: an older Rustion has no
/// `capabilities` field, and one with exec switched off lists `[]`.
pub fn advertises_ssh_exec(body: &serde_json::Value) -> bool {
    body.get("capabilities")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|caps| caps.iter().any(|c| c.as_str() == Some("ssh_exec")))
}

/// Read the bastion's capability advertisement, fresh for every exec open
/// (one extra round trip, and no cached capability to go stale).
#[maybe_async::maybe_async]
async fn fetch_exec_capability(
    client: &reqwest::Client,
    target: &RustionTarget,
    authority: &str,
) -> Result<bool, String> {
    let url = format!("https://{}/v1/authorities/self", target.endpoint.trim_end_matches('/'));
    let resp = client.get(&url).header("X-Rustion-Authority", authority).send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("http {}", status.as_u16()));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| format!("body parse: {e}"))?;
    Ok(advertises_ssh_exec(&body))
}

/// Where to dial a bastion's SSH listener, in the order the desktop app's
/// interactive path resolves it (`resolve_bastion_dial_coords` in the Tauri
/// host): the listener coordinates discovered at enrolment, else the host
/// the open answered with when it is a real address, else the host part of
/// the control-plane endpoint with the answered port.
pub fn exec_dial_coords(target: &RustionTarget, returned_host: &str, returned_port: u16) -> (String, u16) {
    fn is_unspecified(h: &str) -> bool {
        let t = h.trim();
        t.is_empty() || t == "0.0.0.0" || t == "::" || t == "[::]" || t == "*"
    }
    if !is_unspecified(&target.ssh_listener_host) && target.ssh_listener_port != 0 {
        return (target.ssh_listener_host.trim().to_string(), target.ssh_listener_port);
    }
    if !is_unspecified(returned_host) {
        return (returned_host.trim().to_string(), returned_port);
    }
    let endpoint = target.endpoint.trim();
    let host_only = if let Some(rest) = endpoint.strip_prefix('[') {
        rest.split_once(']').map(|(h, _)| h.to_string()).unwrap_or_else(|| endpoint.to_string())
    } else if let Some((h, _)) = endpoint.rsplit_once(':') {
        h.to_string()
    } else {
        endpoint.to_string()
    };
    (host_only, returned_port)
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
    /// `"exec"` from a bastion that honoured the exec form; absent from an
    /// interactive open and from any bastion older than 0.20.0.
    #[serde(default)]
    kind: Option<String>,
}

fn build_open_envelope(
    master: &BvrgMasterSigningKey,
    target: &RustionTarget,
    operator: &OperatorContext,
    request: &SessionOpenRequest,
) -> Result<BuiltEnvelope, envelope::OpenEnvelopeError> {
    let kind = match request.exec_command.as_deref() {
        Some(command) => envelope::OpenKind::Exec { command },
        None => envelope::OpenKind::Interactive,
    };
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
        kind,
    )
}

#[maybe_async::maybe_async]
async fn post_envelope(
    client: &reqwest::Client,
    target: &RustionTarget,
    authority: &str,
    built: &BuiltEnvelope,
) -> OpenAttemptOutcome {
    let url = format!("https://{}/v1/sessions", target.endpoint.trim_end_matches('/'));
    let result = client
        .post(&url)
        .header("X-Rustion-Authority", authority)
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
    authority: &str,
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
        .header("X-Rustion-Authority", authority)
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
    authority: &str,
    operator: &OperatorContext,
    request: &SessionKillRequest,
) -> Result<SessionKillResponse, SessionRenewError> {
    let target = store
        .get_target(&request.bastion_id)
        .await
        .map_err(|e| SessionRenewError::Master(format!("{e}")))?
        .ok_or_else(|| SessionRenewError::BastionNotFound(request.bastion_id.clone()))?;
    kill_session_on(&target, master, authority, operator, &request.session_id, &request.correlation_id).await
}

/// Build a `kill` envelope and DELETE it at `target`, the bastion that
/// opened the session.
#[maybe_async::maybe_async]
pub(crate) async fn kill_session_on(
    target: &RustionTarget,
    master: &BvrgMasterSigningKey,
    authority: &str,
    operator: &OperatorContext,
    session_id: &str,
    correlation_id: &str,
) -> Result<SessionKillResponse, SessionRenewError> {
    let built = envelope::build_kill(master, target, operator, correlation_id)
        .map_err(|e| SessionRenewError::Envelope(format!("{e}")))?;

    let client = super::http::build_client_for(target, Duration::from_secs(10))
        .map_err(|e| SessionRenewError::Transport(format!("{e}")))?;
    let url = format!("https://{}/v1/sessions/{}", target.endpoint.trim_end_matches('/'), session_id);
    let resp = client
        .delete(&url)
        .header("X-Rustion-Authority", authority)
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
        bastion_id: target.id.clone(),
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

#[cfg(test)]
mod exec_tests {
    //! The exec form of the open loop (T483) against an in-process HTTPS
    //! stand-in for a bastion's control plane, which records every request.

    use std::sync::{Arc, Mutex};

    use bv_crypto::{KemProvider, MlKem768Provider};
    use serde_json::{json, Value};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_rustls::{
        rustls::{
            self,
            pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        },
        TlsAcceptor,
    };

    use super::*;

    const PIN: &str = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";

    /// How the stand-in answers.
    #[derive(Clone)]
    struct Script {
        /// The `/v1/authorities/self` body.
        authority: Value,
        /// `POST /v1/sessions`: status and body.
        open: (u16, Value),
    }

    struct MockBastion {
        port: u16,
        cert_pem: String,
        requests: Arc<Mutex<Vec<String>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for MockBastion {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl MockBastion {
        async fn start(script: Script) -> Self {
            let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
            let cert_pem = certified.cert.pem();
            let config =
                rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(
                        vec![CertificateDer::from(certified.cert.der().to_vec())],
                        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der())),
                    )
                    .unwrap();
            let acceptor = TlsAcceptor::from(Arc::new(config));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let recorded = requests.clone();
            let task = tokio::spawn(async move {
                loop {
                    let Ok((tcp, _)) = listener.accept().await else { return };
                    let (acceptor, recorded, script) = (acceptor.clone(), recorded.clone(), script.clone());
                    tokio::spawn(async move {
                        let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                        let Some((method, path)) = read_request(&mut tls).await else { return };
                        recorded.lock().unwrap().push(format!("{method} {path}"));
                        let (status, body) = match (method.as_str(), path.as_str()) {
                            ("GET", "/v1/authorities/self") => (200, script.authority.clone()),
                            ("POST", "/v1/sessions") => script.open.clone(),
                            ("DELETE", p) if p.starts_with("/v1/sessions/") => (
                                200,
                                json!({ "session_id": p.trim_start_matches("/v1/sessions/"), "terminated_at": "now" }),
                            ),
                            _ => (404, json!({ "error": "not_found" })),
                        };
                        let body = body.to_string();
                        let head = format!(
                            "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                             connection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = tls.write_all(head.as_bytes()).await;
                        let _ = tls.write_all(body.as_bytes()).await;
                        let _ = tls.shutdown().await;
                    });
                }
            });
            Self { port, cert_pem, requests, task }
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }
    }

    /// Read one HTTP/1.1 request: its method and path, the body drained.
    async fn read_request<S: AsyncReadExt + Unpin>(stream: &mut S) -> Option<(String, String)> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let head_end = loop {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        let length = head
            .lines()
            .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_string()))
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        while buf.len() < head_end + length {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let mut first = head.lines().next()?.split_whitespace();
        Some((first.next()?.to_string(), first.next()?.to_string()))
    }

    fn target(mock: &MockBastion, kem_pub: &[u8], listener_pin: &str) -> RustionTarget {
        target_at(mock.port, &mock.cert_pem, kem_pub, listener_pin)
    }

    fn target_at(port: u16, cert_pem: &str, kem_pub: &[u8], listener_pin: &str) -> RustionTarget {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        RustionTarget {
            id: "rt_exec".into(),
            name: "bastion-1".into(),
            endpoint: format!("127.0.0.1:{port}"),
            public_key: crate::config::HybridPubKey {
                ed25519: STANDARD.encode([7u8; 32]),
                mldsa65: STANDARD.encode([7u8; 16]),
            },
            kem_public_key: STANDARD.encode(kem_pub),
            fingerprint: String::new(),
            description: String::new(),
            tags: vec![],
            enabled: true,
            default_recording_dir: String::new(),
            tls_pinned_cert_pem: cert_pem.to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            ssh_listener_host: "bastion-1.internal".into(),
            ssh_listener_port: 2222,
            rdp_listener_host: String::new(),
            rdp_listener_port: 0,
            listeners_synced_at: String::new(),
            ssh_host_key_fingerprint: listener_pin.into(),
            rdp_tls_pin_sha256: String::new(),
        }
    }

    fn operator() -> OperatorContext {
        OperatorContext {
            vault_user_id: String::new(),
            vault_user_name: "felipe".into(),
            vault_session_id: String::new(),
            src_ip: String::new(),
            deployment_id: "uuid-deploy".into(),
        }
    }

    fn request(exec: Option<&str>, material: &[u8]) -> SessionOpenRequest {
        SessionOpenRequest {
            target_host: "10.0.0.7".into(),
            target_port: 22,
            target_protocol: "ssh".into(),
            target_hostkey_pin: Some(PIN.into()),
            credential_kind: "ssh-password".into(),
            credential_username: "ops".into(),
            credential_material: material.to_vec(),
            credential_cert: None,
            credential_key: Vec::new(),
            credential_pin: String::new(),
            credential_domain: String::new(),
            ttl_secs: 40,
            max_renewals: 0,
            recording: "always".into(),
            bastions: None,
            bastion_group: None,
            bastion_shuffle: false,
            exec_command: exec.map(str::to_string),
        }
    }

    fn opened(kind: Option<&str>) -> (u16, Value) {
        let mut body = json!({
            "session_id": "s-1", "host": "0.0.0.0", "port": 2222, "ticket": "tkt-secret",
            "expires_at": "2026-11-24T12:00:30Z", "protocol": "ssh", "recording_id": "rec_1",
        });
        if let Some(kind) = kind {
            body["kind"] = json!(kind);
        }
        (201, body)
    }

    fn exec_bastion(kind: Option<&str>) -> Script {
        Script { authority: json!({ "name": "bv", "capabilities": ["ssh_exec"] }), open: opened(kind) }
    }

    async fn run(
        mock: &MockBastion,
        pin: &str,
        req: &SessionOpenRequest,
    ) -> Result<SessionOpenResponse, SessionOpenError> {
        let master = BvrgMasterSigningKey::generate().unwrap();
        let kp = MlKem768Provider.generate_keypair().unwrap();
        let candidates = vec![target(mock, kp.public_key(), pin)];
        open_on_candidates(&candidates, "random-pool", &master, "bv", &operator(), req).await
    }

    /// An exec opens on a bastion that advertises `ssh_exec` and echoes the
    /// kind, and comes back with where to dial and which key to require.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_exec_open_needs_the_capability_and_returns_the_dial() {
        let mock = MockBastion::start(exec_bastion(Some("exec"))).await;
        let opened = run(&mock, PIN, &request(Some("uptime"), b"pw")).await.unwrap();
        assert_eq!(opened.kind.as_deref(), Some("exec"));
        assert_eq!(opened.ticket, "tkt-secret");
        assert_eq!(
            opened.exec_dial,
            Some(ExecDial { host: "bastion-1.internal".into(), port: 2222, host_key_pin: PIN.into() })
        );
        assert_eq!(mock.requests(), vec!["GET /v1/authorities/self", "POST /v1/sessions"]);
    }

    /// Decision 5: an older bastion (no `capabilities` field) or one with
    /// exec switched off (`[]`) is never posted to; the refusal is named.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_bastion_without_ssh_exec_is_never_posted_to() {
        for authority in [json!({ "name": "bv", "version": "0.19.4" }), json!({ "name": "bv", "capabilities": [] })] {
            let mock = MockBastion::start(Script { authority, open: opened(None) }).await;
            match run(&mock, PIN, &request(Some("uptime"), b"pw")).await {
                Err(SessionOpenError::ExecUnavailable { attempts }) => {
                    assert!(attempts[0].outcome.starts_with("exec_unsupported:"), "{:?}", attempts)
                }
                other => panic!("expected ExecUnavailable, got {:?}", other.map(|r| r.session_id)),
            }
            assert_eq!(mock.requests(), vec!["GET /v1/authorities/self"], "nothing was posted");
        }
    }

    /// Second line of defence: a `201` without `kind: "exec"` is an
    /// interactive ticket. The session is ended (DELETE) and the open fails;
    /// the ticket never leaves this function.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_open_not_echoed_as_exec_is_killed() {
        for kind in [None, Some("interactive")] {
            let mock = MockBastion::start(exec_bastion(kind)).await;
            match run(&mock, PIN, &request(Some("uptime"), b"pw")).await {
                Err(e @ SessionOpenError::ExecKindNotEchoed { killed: true, .. }) => {
                    assert!(!e.to_string().contains("tkt-secret"), "{e}")
                }
                other => panic!("expected ExecKindNotEchoed, got {:?}", other.map(|r| r.session_id)),
            }
            assert_eq!(
                mock.requests(),
                vec!["GET /v1/authorities/self", "POST /v1/sessions", "DELETE /v1/sessions/s-1"]
            );
        }
    }

    /// A bastion without an SSH listener pin is not tried at all: an exec is
    /// never dialed unpinned.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unpinned_listener_is_not_tried() {
        let mock = MockBastion::start(exec_bastion(Some("exec"))).await;
        match run(&mock, "", &request(Some("uptime"), b"pw")).await {
            Err(SessionOpenError::ExecUnavailable { attempts }) => {
                assert!(attempts[0].outcome.starts_with("exec_listener_unpinned:"), "{attempts:?}")
            }
            other => panic!("expected ExecUnavailable, got {:?}", other.map(|r| r.session_id)),
        }
        assert!(mock.requests().is_empty());
    }

    /// An envelope past the 16 KiB cap is refused as `envelope_too_large`
    /// before any POST.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_oversized_exec_is_refused_before_posting() {
        let mock = MockBastion::start(exec_bastion(Some("exec"))).await;
        let req = request(Some(&"y".repeat(envelope::MAX_EXEC_COMMAND_BYTES)), &[b'k'; 5 * 1024]);
        match run(&mock, PIN, &req).await {
            Err(SessionOpenError::Refused(e)) => assert!(e.to_string().starts_with("envelope_too_large: "), "{e}"),
            other => panic!("expected envelope_too_large, got {:?}", other.map(|r| r.session_id)),
        }
        assert!(!mock.requests().iter().any(|r| r.starts_with("POST")), "{:?}", mock.requests());
    }

    /// A bastion that refuses the exec open (`409 exec_disabled`) halts the
    /// walk like any 4xx; an interactive open is unchanged (no capability
    /// read, no kind required).
    #[tokio::test(flavor = "multi_thread")]
    async fn refusals_halt_and_interactive_opens_are_unchanged() {
        let script = Script {
            authority: json!({ "capabilities": ["ssh_exec"] }),
            open: (409, json!({ "error": "exec_disabled", "detail": "exec switched off" })),
        };
        let mock = MockBastion::start(script).await;
        match run(&mock, PIN, &request(Some("uptime"), b"pw")).await {
            Err(SessionOpenError::AllRejected { attempts }) => {
                assert!(attempts[0].outcome.contains("exec_disabled"), "{attempts:?}")
            }
            other => panic!("expected AllRejected, got {:?}", other.map(|r| r.session_id)),
        }

        let mock = MockBastion::start(exec_bastion(None)).await;
        let opened = run(&mock, "", &request(None, b"pw")).await.unwrap();
        assert_eq!((opened.kind, opened.exec_dial), (None, None));
        assert_eq!(mock.requests(), vec!["POST /v1/sessions"]);
    }

    #[test]
    fn the_capability_must_be_listed_explicitly() {
        assert!(advertises_ssh_exec(&json!({ "capabilities": ["x", "ssh_exec"] })));
        for body in [json!({}), json!({ "capabilities": [] }), json!({ "capabilities": "ssh_exec" }), json!(null)] {
            assert!(!advertises_ssh_exec(&body), "{body}");
        }
    }

    #[test]
    fn dial_coordinates_follow_the_interactive_path_order() {
        let mut t = target_at(9443, "", &[0u8; 4], PIN);
        t.endpoint = "rustion.example:9443".into();
        assert_eq!(exec_dial_coords(&t, "10.1.1.1", 22), ("bastion-1.internal".into(), 2222));
        t.ssh_listener_host = "0.0.0.0".into();
        assert_eq!(exec_dial_coords(&t, "10.1.1.1", 2200), ("10.1.1.1".into(), 2200));
        assert_eq!(exec_dial_coords(&t, "::", 2200), ("rustion.example".into(), 2200));
        t.endpoint = "[fd00::5]:9443".into();
        assert_eq!(exec_dial_coords(&t, "", 2200), ("fd00::5".into(), 2200));
    }
}
