//! Steps 4-9 of the authorization chain, the credential, and the session
//! task of `resources/v2/connect/agent/ssh/exec`. See the module doc of
//! [`super`] for the chain; this file runs it after the switches.
//!
//! The order is deliberate: everything that can refuse runs before any
//! credential is resolved or minted, and the destination is resolved and
//! checked before that too, so a refused call never touches a secret.

use std::{collections::BTreeMap, sync::Arc};

use base64::Engine as _;
use bv_kernel_api::{
    engines::profile_gate_flag,
    mcp_events::{self, AbortCause, AgentAborted, AgentRefused, SshExecEvent},
    mcp_sessions::BrokeredSessionEnv,
    mcp_transcripts::{
        McpSessionTranscript, SshTranscript, TranscriptBody, TranscriptStore, TranscriptStream, TranscriptSummary,
        MAX_TRANSCRIPT_STREAM_BYTES,
    },
    ssh_credentials::{self, BrokeredCertRequest, SecretResolution, SshCertificateFacts},
    VaultCtx,
};
use bv_mcp::untrusted::{decode_output, shape_stream, CredentialScrubber, DecodedOutput};
use bv_utils::destination_policy::{CheckedTarget, DESTINATION_REFUSED_CODE};
use rand::RngExt;
use serde_json::{Map, Value};
use tokio::{sync::watch, time::Instant};

use super::{
    exec::{self, ExecError, ExecReport, ExecSpec, SshLogin, TranscriptCapture, STDERR, STDOUT},
    CallError, Gated, SessionRefusal, CERT_VALIDITY_SECS, CONNECT_BUDGET, DRAIN_LIMIT_BYTES, SSH_EXEC_TOOL,
};
use crate::{
    agent_access,
    agent_limits::{binding_limit_key, SessionPermit},
    agent_session::{
        aborted_refusal, cause_str, check_transport, destination_policy, now_ms, redeem_agent_ticket, refused,
        resource_type, str_field, watch_revocation, without_code, ScrubberAdapter,
    },
    connect_mfa::{caller_namespace, find_profile},
    errors::RvError,
    logical::{McpBinding, McpBindingKind, Request},
    type_config, ResourceBackendInner,
};

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Clock skew allowed between the SSH engine's `valid_before` and this
/// check, both on this host's clock.
const CERT_SKEW_SECS: u64 = 5;

/// How the session will log in, decided from the stored profile before any
/// secret is touched.
enum LoginPlan {
    Secret { secret_id: String, profile_username: Option<String> },
    Certificate { ssh_mount: String, ssh_role: String, username: String },
}

impl LoginPlan {
    fn from_profile(profile: &Value) -> Result<Self, SessionRefusal> {
        let unsupported = |m: String| SessionRefusal::new("mcp_session_login_class_unsupported", 403, m);
        let cs = profile.get("credential_source").cloned().unwrap_or(Value::Null);
        let username = str_field(profile, "username").map(str::to_string);
        match str_field(&cs, "kind").unwrap_or_default() {
            "secret" => {
                let secret_id = str_field(&cs, "secret_id")
                    .ok_or_else(|| unsupported("the profile's credential_source.secret_id is empty".into()))?;
                Ok(Self::Secret { secret_id: secret_id.to_string(), profile_username: username })
            }
            "ssh-engine" if str_field(&cs, "mode").unwrap_or("ca") == "ca" => {
                let ssh_mount = str_field(&cs, "ssh_mount")
                    .map(|m| m.trim_end_matches('/').to_string())
                    .filter(|m| !m.is_empty())
                    .ok_or_else(|| unsupported("the profile's credential_source.ssh_mount is empty".into()))?;
                let ssh_role = str_field(&cs, "ssh_role")
                    .ok_or_else(|| unsupported("the profile's credential_source.ssh_role is empty".into()))?
                    .to_string();
                let username = username.ok_or_else(|| {
                    unsupported("an ssh-engine profile used for agent sessions must name its login (`username`)".into())
                })?;
                Ok(Self::Certificate { ssh_mount, ssh_role, username })
            }
            other => Err(unsupported(format!(
                "a {other:?} credential source cannot be used for an agent session; only an SSH-engine certificate \
                 (CA mode) or a stored `secret` can"
            ))),
        }
    }
}

/// The profile's pin as a SHA-256 digest. The static check already refused
/// a missing or malformed one; this refuses again rather than trusting it.
fn pinned_digest(profile: &Value) -> Result<[u8; 32], SessionRefusal> {
    let unpinned = || {
        SessionRefusal::new(
            "mcp_session_host_key_unpinned",
            403,
            "an SSH profile used for agent sessions must carry a valid `host_key_pin` (SHA256:<base64>)",
        )
    };
    let pin = str_field(profile, "host_key_pin").ok_or_else(unpinned)?;
    let b64 = pin.strip_prefix("SHA256:").ok_or_else(unpinned)?;
    let digest = base64::engine::general_purpose::STANDARD_NO_PAD.decode(b64).map_err(|_| unpinned())?;
    digest.try_into().map_err(|_| unpinned())
}

/// The host and port to dial: the profile's `target_host` override, else
/// the resource's `ip_address`, else its `hostname` — the order the desktop
/// app uses. From the stored records only, never from the call.
fn session_target(profile: &Value, meta: &Map<String, Value>) -> Result<(String, u16), SessionRefusal> {
    let refuse = |m: String| SessionRefusal::new(DESTINATION_REFUSED_CODE, 403, m);
    let meta_value = Value::Object(meta.clone());
    let host = str_field(profile, "target_host")
        .or_else(|| str_field(&meta_value, "ip_address"))
        .or_else(|| str_field(&meta_value, "hostname"))
        .ok_or_else(|| refuse("the resource has no hostname or ip_address and the profile no target_host".into()))?
        .to_string();
    let well_formed = host.len() <= 253
        && !host.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '@' | '?' | '#' | '\\'));
    if !well_formed {
        return Err(refuse("the resource's target host is not a host name or address".into()));
    }
    let port = match profile.get("target_port") {
        None | Some(Value::Null) => 22,
        Some(v) => v
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .filter(|n| *n != 0)
            .ok_or_else(|| refuse("the profile's target_port is not 1-65535".into()))?,
    };
    Ok((host, port))
}

/// Step 9: resolve the host once, check every address, and hand back the
/// only thing the executor may dial.
async fn check_destination(gated: &Gated, host: String, port: u16) -> Result<CheckedTarget, CallError> {
    let policy = destination_policy(gated.env.as_ref(), &gated.runtime)?;
    crate::agent_session::check_destination(&gated.env, &policy, host, port).await.map_err(CallError::Refused)
}

/// What a signed certificate must say before it is used (§5.2): the
/// confirmed command as `force-command`, the configured `source-address`,
/// no extension at all, a validity of at most a minute, and the login.
fn verify_certificate(
    facts: &SshCertificateFacts,
    command: &str,
    source_address: &str,
    username: &str,
    role: &str,
    now: u64,
) -> Result<(), SessionRefusal> {
    let refuse = |m: String| SessionRefusal::new("mcp_session_login_class_unsupported", 422, m);
    if facts.critical_options.get("force-command").map(String::as_str) != Some(command) {
        return Err(refuse(format!(
            "SSH role `{role}` must list `force-command` in allowed_critical_options: an agent's certificate must \
             bind the confirmed command"
        )));
    }
    if !source_address.is_empty()
        && facts.critical_options.get("source-address").map(String::as_str) != Some(source_address)
    {
        return Err(refuse(format!(
            "SSH role `{role}` must list `source-address` in allowed_critical_options while \
             mcp.brokered_sessions.ssh.cert_source_addresses is set"
        )));
    }
    if !facts.extensions.is_empty() {
        let names: Vec<&str> = facts.extensions.keys().map(String::as_str).collect();
        return Err(refuse(format!(
            "SSH role `{role}` adds extensions ({}) to every certificate; a role used for agent sessions must add \
             none, so the target refuses a PTY and every forwarding",
            names.join(", ")
        )));
    }
    if facts.valid_before > now + CERT_VALIDITY_SECS + CERT_SKEW_SECS {
        return Err(refuse(format!(
            "SSH role `{role}` signed a certificate valid past {CERT_VALIDITY_SECS} s; lower its max_ttl"
        )));
    }
    if !facts.valid_principals.iter().any(|p| p == username) {
        return Err(refuse(format!("SSH role `{role}` did not sign the certificate for login `{username}`")));
    }
    Ok(())
}

/// Resolve or mint the credential, under the server's authority, now that
/// every refusal has run. Returns the login, the scrubber for its secret and
/// the certificate serial.
async fn resolve_login(
    ctx: &dyn VaultCtx,
    ns_prefix: &str,
    resource: &str,
    plan: LoginPlan,
    gated: &Gated,
    actor: &str,
) -> Result<(SshLogin, CredentialScrubber, Option<String>), CallError> {
    let failed = |m: String| refused("mcp_session_failed", 422, m);
    match plan {
        LoginPlan::Secret { secret_id, profile_username } => {
            let resolved = ssh_credentials::resolve_secret_credential(
                ctx,
                ns_prefix,
                resource,
                &secret_id,
                &SecretResolution { audit_label: "mcp-agent-ssh-resolve", actor },
            )
            .await
            .map_err(|e| failed(format!("the profile's stored credential could not be resolved: {e}")))?;
            let username =
                resolved.username.clone().or(profile_username).filter(|u| !u.is_empty()).ok_or_else(|| {
                    refused(
                        "mcp_session_login_class_unsupported",
                        403,
                        "neither the stored secret nor the profile names the login (`username`)",
                    )
                })?;
            let mut scrubber = CredentialScrubber::none();
            if let Some(pem) = resolved.private_key.as_ref() {
                scrubber.add_private_key_pem(pem);
                if let Some(passphrase) = resolved.passphrase.as_ref() {
                    scrubber.add_secret(passphrase);
                }
                let key = russh::keys::decode_secret_key(pem, resolved.passphrase.as_ref().map(|p| p.as_str()))
                    .map_err(|_| failed("the stored private key does not parse, or its passphrase is wrong".into()))?;
                return Ok((SshLogin::StoredKey { username, key: Arc::new(key) }, scrubber, None));
            }
            let Some(password) = resolved.password else {
                return Err(failed("the stored secret carries no password and no private key".into()));
            };
            scrubber.add_password(&username, &password);
            Ok((SshLogin::Password { username, password }, scrubber, None))
        }
        LoginPlan::Certificate { ssh_mount, ssh_role, username } => {
            let source_address = gated.settings.ssh_cert_source_addresses.join(",");
            let mut critical_options = BTreeMap::new();
            critical_options.insert("force-command".to_string(), gated.command.clone());
            if !source_address.is_empty() {
                critical_options.insert("source-address".to_string(), source_address.clone());
            }
            let request = BrokeredCertRequest {
                principal: Some(&username),
                critical_options,
                ttl_secs: Some(CERT_VALIDITY_SECS),
            };
            let minted = ssh_credentials::mint_brokered_ssh_cert(ctx, ns_prefix, &ssh_mount, &ssh_role, &request)
                .await
                .map_err(|e| {
                    failed(format!("SSH role `{ssh_role}` on `{ssh_mount}` did not sign the session certificate: {e}"))
                })?;
            let facts =
                ssh_credentials::inspect_ssh_certificate(&minted.certificate).map_err(|e| failed(e.to_string()))?;
            verify_certificate(&facts, &gated.command, &source_address, &username, &ssh_role, now_secs())?;
            let key = russh::keys::decode_secret_key(&minted.private_key_openssh, None)
                .map_err(|_| failed("the ephemeral session key does not parse".into()))?;
            let cert = russh::keys::Certificate::from_openssh(minted.certificate.trim())
                .map_err(|_| failed("the signed session certificate does not parse".into()))?;
            let serial = Some(format!("{:016x}", facts.serial));
            Ok((
                SshLogin::Certificate { username, key: Arc::new(key), cert: Box::new(cert) },
                CredentialScrubber::none(),
                serial,
            ))
        }
    }
}

/// Steps 4-9, the credential, and the session.
pub(crate) async fn prepare_and_run(
    backend: &ResourceBackendInner,
    req: &mut Request,
    gated: Gated,
) -> Result<Map<String, Value>, CallError> {
    // 4. The connect gate on `resources/secrets/<name>/`, then the record.
    let (resource, profile_id, meta) = backend.connect_target_record(req).await.map_err(|error| {
        let reason =
            if matches!(error, RvError::ErrPermissionDenied) { "permission_denied" } else { "connect_target_refused" };
        CallError::Vault { reason, error }
    })?;
    let not_enabled = |status: u16, m: String| refused("mcp_session_profile_not_agent_enabled", status, m);
    let meta = meta.ok_or_else(|| not_enabled(404, format!("resource `{resource}` not found")))?;
    let profile = find_profile(&meta, &profile_id)
        .ok_or_else(|| not_enabled(404, format!("profile `{profile_id}` not found on resource `{resource}`")))?;
    if str_field(&profile, "protocol") != Some("ssh") {
        return Err(not_enabled(403, format!("profile `{profile_id}` is not an SSH profile")));
    }

    // 5. The type and profile opt-ins, and the profile's static requirements.
    let type_id = resource_type(&meta);
    let types = type_config::effective_type_config(backend.core.as_ref(), req).await.map_err(|e| match e {
        type_config::TypeConfigError::Storage(error) => CallError::Vault { reason: "type_config_unreadable", error },
        type_config::TypeConfigError::Malformed(source) => refused(
            "agent_policy_invalid",
            422,
            format!("the {} resource type configuration is not a JSON object", source.as_str()),
        ),
    })?;
    agent_access::check_agent_enabled(types.type_def(type_id), &profile)
        .map_err(|r| refused(r.code(), r.status(), r.to_string()))?;

    // 6. MFA: the operator's ticket for this exact call, redeemed once.
    let mfa_method = if profile_gate_flag(&profile) {
        Some(redeem_agent_ticket(backend, req, &gated.binding, &resource, &profile_id, SSH_EXEC_TOOL).await?)
    } else {
        None
    };

    // 7. No bastion route is bypassed.
    check_transport(backend, req, &resource, &meta, &profile).await?;

    let plan = LoginPlan::from_profile(&profile)?;
    let host_key_sha256 = pinned_digest(&profile)?;
    let (host, port) = session_target(&profile, &meta)?;

    // 8. Rate and concurrency. The permit travels with the session task.
    let permit = backend
        .agent_limiter(gated.env.as_ref())
        .try_acquire(&binding_limit_key(&gated.binding))
        .map_err(|r| refused(r.code(), 429, without_code(&r.to_string(), r.code())))?;

    // 9. The destination: resolved once, every address checked.
    let target = check_destination(&gated, host, port).await?;

    // Only now, the credential.
    let ns = caller_namespace(&backend.core, req)
        .await
        .map_err(|error| CallError::Vault { reason: "namespace_unresolvable", error })?;
    let ns_prefix = if ns.is_empty() { String::new() } else { format!("{ns}/") };
    let actor = gated.binding.operator.as_ref().map(|o| o.username.clone()).unwrap_or_default();
    let (login, scrubber, cert_serial) =
        resolve_login(backend.core.as_ref(), &ns_prefix, &resource, plan, &gated, &actor).await?;

    let mut who = req.clone();
    who.body = None;
    who.data = None;
    let session_id = format!("as_{:016x}", rand::rng().random::<u64>());
    let target_label = target.primary().to_string();
    let login_kind = login.kind();
    let spec = ExecSpec {
        target,
        host_key_sha256,
        login,
        command: gated.command.clone(),
        connect_budget: CONNECT_BUDGET,
        deadline: Instant::now() + std::time::Duration::from_secs(gated.timeout_secs),
        output_limit: usize::try_from(gated.settings.max_output_bytes).unwrap_or(usize::MAX),
        drain_limit: DRAIN_LIMIT_BYTES,
        transcript_stream_limit: MAX_TRANSCRIPT_STREAM_BYTES,
    };
    let task = SessionTask {
        ctx: backend.core.clone(),
        env: gated.env.clone(),
        token: req.client_token.clone(),
        who,
        binding: gated.binding,
        operator_confirmation: req.mcp_audit.as_ref().and_then(|a| a.operator_confirmation.clone()),
        mfa_method,
        resource,
        profile_id,
        command: gated.command,
        target_label,
        login_kind,
        cert_serial,
        scrubber,
        session_id,
        started_at_ms: now_ms(),
        _permit: permit,
    };
    // The session runs in its own task: when the MCP endpoint's timeout
    // drops this request, the task still closes the connection and records
    // its transcript and events.
    match tokio::spawn(task.run(spec)).await {
        Ok(outcome) => outcome.map_err(CallError::Ended),
        Err(e) => Err(CallError::Ended(SessionRefusal::new(
            "mcp_session_failed",
            500,
            format!("the session task ended abnormally: {e}"),
        ))),
    }
}

/// Everything a session needs once it is authorized, owned, so the task
/// outlives the request.
struct SessionTask {
    ctx: Arc<dyn VaultCtx>,
    env: Arc<dyn BrokeredSessionEnv>,
    /// The MCP token, re-validated every [`REVALIDATE_EVERY`].
    token: String,
    /// The request, without its body: who and from where, for the events.
    who: Request,
    binding: McpBinding,
    operator_confirmation: Option<String>,
    /// The factor the operator proved for a gated profile.
    mfa_method: Option<String>,
    resource: String,
    profile_id: String,
    command: String,
    target_label: String,
    login_kind: &'static str,
    cert_serial: Option<String>,
    scrubber: CredentialScrubber,
    session_id: String,
    started_at_ms: u64,
    /// Held for the life of the session; dropping it frees the slot.
    _permit: SessionPermit,
}

/// One stream for the transcript: what was kept for it (up to 1 MiB, not
/// scrubbed here — the writer scrubs every field itself), and where the
/// model's copy stopped.
fn transcript_stream(
    capture: &TranscriptCapture,
    seen: u64,
    model_kept: usize,
    model_truncated: bool,
) -> TranscriptStream {
    let (text, binary, cut) = match decode_output(&capture.bytes, capture.truncated) {
        DecodedOutput::Binary => (String::new(), true, false),
        DecodedOutput::Text(mut text) => {
            // Lossy decoding can grow the text; the store refuses a stream
            // over its limit, so cut it on a character boundary.
            let mut cut = false;
            if text.len() > MAX_TRANSCRIPT_STREAM_BYTES {
                let mut end = MAX_TRANSCRIPT_STREAM_BYTES;
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                text.truncate(end);
                cut = true;
            }
            (text, false, cut)
        }
    };
    TranscriptStream {
        text,
        seen_bytes: seen,
        stored_truncated: capture.truncated || cut,
        model_truncated_at: model_truncated.then_some(model_kept as u64),
        binary,
    }
}

impl SessionTask {
    fn pairing_id(&self) -> Option<String> {
        match &self.binding.kind {
            McpBindingKind::Pairing(id) => Some(id.clone()),
            McpBindingKind::App(_) => None,
        }
    }

    async fn run(self, spec: ExecSpec) -> Result<Map<String, Value>, SessionRefusal> {
        let started = Instant::now();
        let (abort_tx, abort_rx) = watch::channel(None);
        let watcher = tokio::spawn(watch_revocation(self.ctx.clone(), self.env.clone(), self.token.clone(), abort_tx));
        let outcome = exec::run(spec, abort_rx).await;
        watcher.abort();
        let duration_ms = started.elapsed().as_millis() as u64;
        match outcome {
            Ok(report) => self.finish(report, duration_ms).await,
            Err(ExecError::HostKeyMismatch { observed }) => {
                log::warn!(
                    target: "security",
                    "connect.agent.ssh host key mismatch: resource={} profile={} target={} observed={observed}",
                    self.resource,
                    self.profile_id,
                    self.target_label
                );
                self.emit_refused("mcp_session_host_key_mismatch").await;
                Err(SessionRefusal::new(
                    "mcp_session_host_key_mismatch",
                    403,
                    format!("the target presented host key {observed}, not the pinned one; nothing was authenticated"),
                ))
            }
            Err(ExecError::Aborted(cause)) => {
                self.emit_aborted(cause).await;
                Err(aborted_refusal(cause))
            }
            Err(ExecError::ConnectTimeout) => {
                self.emit_aborted(AbortCause::Timeout).await;
                Err(SessionRefusal::new("mcp_session_timeout", 504, ExecError::ConnectTimeout.to_string()))
            }
            Err(other) => {
                self.emit_aborted(AbortCause::ExecutorError).await;
                Err(SessionRefusal::new("mcp_session_failed", 502, other.to_string()))
            }
        }
    }

    async fn emit_refused(&self, reason: &str) {
        let event = AgentRefused {
            reason: reason.to_string(),
            tool: SSH_EXEC_TOOL.to_string(),
            protocol: "ssh".to_string(),
            resource: Some(self.resource.clone()),
            profile_id: Some(mcp_events::bounded_arg(&self.profile_id)),
            operator: self.binding.operator.clone(),
            pairing_id: self.pairing_id(),
            client_name: self.binding.client_name.clone(),
        };
        if let Err(e) = mcp_events::emit(self.ctx.as_ref(), &event, Some(&self.who)).await {
            log::warn!(target: "security", "connect.agent.refused could not be written to the audit log: {e}");
        }
    }

    async fn emit_aborted(&self, cause: AbortCause) {
        let event = AgentAborted {
            session_id: self.session_id.clone(),
            cause,
            protocol: "ssh".to_string(),
            resource: self.resource.clone(),
            profile_id: self.profile_id.clone(),
            operator: self.binding.operator.clone(),
            pairing_id: self.pairing_id(),
        };
        if let Err(e) = mcp_events::emit(self.ctx.as_ref(), &event, Some(&self.who)).await {
            log::warn!(target: "security", "connect.agent.aborted could not be written to the audit log: {e}");
        }
    }

    /// The session ran: shape the output, record the transcript, emit the
    /// events, and answer.
    async fn finish(self, report: ExecReport, duration_ms: u64) -> Result<Map<String, Value>, SessionRefusal> {
        let finished_at_ms = now_ms();
        let out_capture = report.model.stream(STDOUT);
        let err_capture = report.model.stream(STDERR);
        let out = shape_stream(out_capture, &self.scrubber);
        let err = shape_stream(err_capture, &self.scrubber);
        let binary = out.binary || err.binary;
        let truncated = out.truncated || err.truncated;

        let transcript = McpSessionTranscript {
            summary: TranscriptSummary {
                session_id: self.session_id.clone(),
                tool: SSH_EXEC_TOOL.to_string(),
                resource: self.resource.clone(),
                profile_id: self.profile_id.clone(),
                operator: self.binding.operator.clone(),
                pairing_id: self.pairing_id().unwrap_or_default(),
                client_name: self.binding.client_name.clone(),
                binding_reveal_allowed: self.binding.reveal_allowed,
                operator_confirmation: self.operator_confirmation.clone(),
                mfa_method: self.mfa_method.clone(),
                started_at_ms: self.started_at_ms,
                finished_at_ms,
                credential_echo_redacted: out.credential_redacted || err.credential_redacted,
            },
            body: TranscriptBody::Ssh(SshTranscript {
                command: self.command.clone(),
                target: self.target_label.clone(),
                host_key_fingerprint: report.host_key_fingerprint.clone(),
                login: self.login_kind.to_string(),
                cert_serial: self.cert_serial.clone(),
                exit_status: report.exit_status,
                exit_signal: report.exit_signal.clone(),
                timed_out: report.timed_out,
                aborted: report.aborted.map(|c| cause_str(c).to_string()),
                stdout: transcript_stream(
                    &report.transcript[STDOUT],
                    out_capture.seen(),
                    out_capture.kept().len(),
                    out.truncated,
                ),
                stderr: transcript_stream(
                    &report.transcript[STDERR],
                    err_capture.seen(),
                    err_capture.kept().len(),
                    err.truncated,
                ),
            }),
        };
        let adapter = ScrubberAdapter(&self.scrubber);
        let transcript_id = match TranscriptStore::from_ctx(self.ctx.as_ref()) {
            Ok(store) => match store.record(transcript, &adapter).await {
                Ok(id) => Some(id),
                Err(e) => {
                    log::error!(target: "security", "MCP session {} transcript was not recorded: {e}", self.session_id);
                    None
                }
            },
            Err(e) => {
                log::error!(target: "security", "MCP session {} transcript store unavailable: {e}", self.session_id);
                None
            }
        };
        // Whether the writer found the credential too (it scrubs again).
        let credential_echo_redacted = out.credential_redacted || err.credential_redacted;

        let event = SshExecEvent {
            session_id: self.session_id.clone(),
            operator: self.binding.operator.clone(),
            pairing_id: self.pairing_id(),
            client_name: self.binding.client_name.clone(),
            binding_reveal_allowed: self.binding.reveal_allowed,
            resource: self.resource.clone(),
            profile_id: self.profile_id.clone(),
            target: self.target_label.clone(),
            host_key_fingerprint: report.host_key_fingerprint.clone(),
            login: self.login_kind.to_string(),
            cert_serial: self.cert_serial.clone(),
            mfa_method: self.mfa_method.clone(),
            command_hmac: mcp_events::audit_hmac(self.ctx.as_ref(), self.command.as_bytes()),
            command_bytes: self.command.len() as u64,
            exit_status: report.exit_status,
            exit_signal: report.exit_signal.clone(),
            timed_out: report.timed_out,
            stdout_bytes: out.bytes,
            stderr_bytes: err.bytes,
            truncated,
            credential_echo_redacted,
            duration_ms,
            transcript_id,
            operator_confirmation: self.operator_confirmation.clone(),
        };
        if let Err(e) = mcp_events::emit(self.ctx.as_ref(), &event, Some(&self.who)).await {
            log::warn!(target: "security", "connect.agent.ssh.exec could not be written to the audit log: {e}");
        }
        if report.timed_out {
            self.emit_aborted(AbortCause::Timeout).await;
        }
        if let Some(cause) = report.aborted {
            self.emit_aborted(cause).await;
            return Err(aborted_refusal(cause));
        }

        let mut data = Map::new();
        data.insert("session_id".into(), Value::String(self.session_id.clone()));
        data.insert("exit_status".into(), report.exit_status.map(Value::from).unwrap_or(Value::Null));
        data.insert("exit_signal".into(), report.exit_signal.clone().map(Value::String).unwrap_or(Value::Null));
        data.insert("timed_out".into(), Value::Bool(report.timed_out));
        for (name, stream) in [("stdout", &out), ("stderr", &err)] {
            if !binary {
                data.insert(name.into(), Value::String(stream.for_model.clone().unwrap_or_default()));
            }
            data.insert(format!("{name}_bytes"), Value::from(stream.bytes));
            data.insert(format!("{name}_truncated"), Value::Bool(stream.truncated));
        }
        data.insert("binary_output".into(), Value::Bool(binary));
        data.insert("credential_echo_redacted".into(), Value::Bool(credential_echo_redacted));
        data.insert("duration_ms".into(), Value::from(duration_ms));
        data.insert("host_key_fingerprint".into(), Value::String(report.host_key_fingerprint.clone()));
        data.insert("login".into(), Value::String(self.login_kind.to_string()));
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PIN: &str = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";

    #[test]
    fn the_target_comes_from_the_records_in_the_desktop_order() {
        let meta = json!({ "hostname": "web-01.internal", "ip_address": "10.0.0.9" });
        let meta = meta.as_object().unwrap();
        assert_eq!(session_target(&json!({}), meta).unwrap(), ("10.0.0.9".to_string(), 22));
        assert_eq!(
            session_target(&json!({ "target_host": "10.0.0.7", "target_port": 2222 }), meta).unwrap(),
            ("10.0.0.7".to_string(), 2222)
        );
        let only_name = json!({ "hostname": "web-01.internal" });
        assert_eq!(session_target(&json!({}), only_name.as_object().unwrap()).unwrap().0, "web-01.internal");
        for bad in [json!({ "target_port": 0 }), json!({ "target_port": 70000 }), json!({ "target_port": "22" })] {
            assert_eq!(session_target(&bad, meta).unwrap_err().code, DESTINATION_REFUSED_CODE, "{bad}");
        }
        for host in ["a b", "user@host", "host/path", ""] {
            let p = json!({ "target_host": host });
            let m = Map::new();
            assert!(session_target(&p, &m).is_err(), "{host:?}");
        }
    }

    #[test]
    fn the_pin_must_decode_to_a_sha256_digest() {
        assert_eq!(pinned_digest(&json!({ "host_key_pin": PIN })).unwrap().len(), 32);
        for bad in [
            json!({}),
            json!({ "host_key_pin": "" }),
            json!({ "host_key_pin": "MD5:aa" }),
            json!({ "host_key_pin": "SHA256:AAAA" }),
        ] {
            assert_eq!(pinned_digest(&bad).unwrap_err().code, "mcp_session_host_key_unpinned", "{bad}");
        }
    }

    #[test]
    fn login_plans_follow_the_credential_source() {
        let secret = json!({ "credential_source": { "kind": "secret", "secret_id": "root-pw" }, "username": "ops" });
        assert!(matches!(LoginPlan::from_profile(&secret), Ok(LoginPlan::Secret { .. })));
        let cert = json!({ "username": "ops", "credential_source": { "kind": "ssh-engine", "mode": "ca", "ssh_mount": "ssh/", "ssh_role": "agent" } });
        match LoginPlan::from_profile(&cert) {
            Ok(LoginPlan::Certificate { ssh_mount, ssh_role, username }) => {
                assert_eq!((ssh_mount.as_str(), ssh_role.as_str(), username.as_str()), ("ssh", "agent", "ops"));
            }
            _ => panic!("expected a certificate plan"),
        }
        let no_user = json!({ "credential_source": { "kind": "ssh-engine", "mode": "ca", "ssh_mount": "ssh", "ssh_role": "agent" } });
        assert_eq!(LoginPlan::from_profile(&no_user).err().unwrap().code, "mcp_session_login_class_unsupported");
        for kind in ["ldap", "default-account", "provider", "pki", "fido2"] {
            let p = json!({ "credential_source": { "kind": kind } });
            assert_eq!(
                LoginPlan::from_profile(&p).err().unwrap().code,
                "mcp_session_login_class_unsupported",
                "{kind}"
            );
        }
        let otp = json!({ "credential_source": { "kind": "ssh-engine", "mode": "otp" } });
        assert!(LoginPlan::from_profile(&otp).is_err());
    }

    fn facts(command: &str) -> SshCertificateFacts {
        let mut critical_options = BTreeMap::new();
        critical_options.insert("force-command".to_string(), command.to_string());
        SshCertificateFacts {
            serial: 1,
            key_id: "agent".into(),
            valid_principals: vec!["ops".into()],
            valid_after: 1_000,
            valid_before: 1_060,
            critical_options,
            extensions: BTreeMap::new(),
        }
    }

    #[test]
    fn a_certificate_must_bind_the_command_and_carry_no_extension() {
        assert_eq!(verify_certificate(&facts("uptime"), "uptime", "", "ops", "agent", 1_000), Ok(()));
        let refused = |f: &SshCertificateFacts, source: &str, now: u64| {
            verify_certificate(f, "uptime", source, "ops", "agent", now).unwrap_err()
        };
        // The role dropped force-command (not in allowed_critical_options).
        let mut f = facts("uptime");
        f.critical_options.clear();
        let err = refused(&f, "", 1_000);
        assert_eq!(err.code, "mcp_session_login_class_unsupported");
        assert!(err.message.contains("`agent`") && err.message.contains("force-command"), "{}", err.message);
        // A different command bound.
        assert!(verify_certificate(&facts("id"), "uptime", "", "ops", "agent", 1_000).is_err());
        // Default extensions such as permit-pty.
        let mut f = facts("uptime");
        f.extensions.insert("permit-pty".into(), String::new());
        assert!(refused(&f, "", 1_000).message.contains("permit-pty"));
        // source-address required when configured.
        assert!(refused(&facts("uptime"), "203.0.113.7", 1_000).message.contains("source-address"));
        let mut f = facts("uptime");
        f.critical_options.insert("source-address".into(), "203.0.113.7".into());
        assert_eq!(verify_certificate(&f, "uptime", "203.0.113.7", "ops", "agent", 1_000), Ok(()));
        // Validity over a minute.
        let mut f = facts("uptime");
        f.valid_before = 1_000 + 3600;
        assert!(refused(&f, "", 1_000).message.contains("60 s"));
        // Another login.
        assert!(verify_certificate(&facts("uptime"), "uptime", "", "root", "agent", 1_000).is_err());
    }

    #[test]
    fn transcript_streams_keep_their_start_and_where_the_model_stopped() {
        let capture = TranscriptCapture { bytes: b"hello world\n".to_vec(), truncated: false };
        let t = transcript_stream(&capture, 12, 5, true);
        assert_eq!((t.text.as_str(), t.seen_bytes, t.model_truncated_at), ("hello world\n", 12, Some(5)));
        assert!(!t.stored_truncated && !t.binary);
        let binary = TranscriptCapture { bytes: vec![0; 64], truncated: false };
        let t = transcript_stream(&binary, 64, 64, false);
        assert!(t.binary && t.text.is_empty() && t.model_truncated_at.is_none());
    }
}
