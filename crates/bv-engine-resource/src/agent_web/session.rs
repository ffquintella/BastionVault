//! Steps 4-9 of the authorization chain, the credential, and the session
//! task of `resources/v2/connect/agent/web/fetch`. See the module doc of
//! [`super`] for the chain.
//!
//! As for SSH: everything that can refuse runs before the credential is
//! read, and the start origin is resolved and checked before that, so a
//! refused call never touches a secret.

use std::sync::Arc;

use bv_kernel_api::{
    engines::profile_gate_flag,
    mcp_events::{self, AbortCause, AgentAborted, AgentRefused, WebFetchEvent},
    mcp_sessions::BrokeredSessionEnv,
    mcp_transcripts::{
        McpSessionTranscript, TranscriptBody, TranscriptStore, TranscriptStream, TranscriptSummary, WebTranscript,
        MAX_TRANSCRIPT_STREAM_BYTES,
    },
    VaultCtx,
};
use bv_mcp::{
    sanitize::sanitize_for_model,
    untrusted::{decode_output, CredentialScrubber, DecodedOutput},
};
use rand::RngExt;
use serde_json::{Map, Value};
use tokio::{sync::watch, time::Instant};

use super::{
    fetch::{self, BasicCredential, FetchSpec, FetchStop, FetchTrace, Fetched},
    html::html_to_text,
    profile::{basic_credential, AgentWebProfile, WebLogin},
    tls::{platform_roots, AgentCertVerifier},
    WebGated, CONNECT_BUDGET, MAX_RAW_BODY_BYTES, WEB_FETCH_TOOL,
};
use crate::{
    agent_access,
    agent_limits::{binding_limit_key, SessionPermit},
    agent_session::{
        aborted_refusal, agent_namespace, cause_str, check_destination, check_transport, destination_policy, now_ms,
        pairing_id, redeem_agent_ticket, refused, resource_type, str_field, watch_revocation, without_code, CallError,
        ScrubberAdapter, SessionRefusal,
    },
    connect_mfa::find_profile,
    errors::RvError,
    logical::{McpBinding, Request},
    type_config, ResourceBackendInner,
};

/// What follows the page text when it was cut for the model: the result's
/// `truncated` says so too, for a client that reads fields.
pub const TRUNCATION_MARKER: &str = "\n[… truncated by the vault]";

/// How a response body is shown (§6.3 "Response handling").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyKind {
    Html,
    Text,
    Other,
}

/// From the `Content-Type` essence: HTML is reduced to text; JSON, XML and
/// every `text/*` are text; anything else — or no type at all — is not
/// shown.
fn body_kind(content_type: Option<&str>) -> BodyKind {
    let Some(ct) = content_type else { return BodyKind::Other };
    let essence = ct.split(';').next().unwrap_or_default().trim().to_ascii_lowercase();
    match essence.as_str() {
        "text/html" | "application/xhtml+xml" => BodyKind::Html,
        "application/json" | "application/xml" | "application/javascript" | "application/x-ndjson" => BodyKind::Text,
        e if e.starts_with("text/") || e.ends_with("+json") || e.ends_with("+xml") => BodyKind::Text,
        _ => BodyKind::Other,
    }
}

/// A body as text: `None` when it is not shown (binary by type, or by its
/// bytes). The second value says whether the reduction itself cut it.
fn body_text(kind: BodyKind, body: &[u8], raw_truncated: bool) -> Option<(String, bool)> {
    if kind == BodyKind::Other {
        return None;
    }
    let DecodedOutput::Text(text) = decode_output(body, raw_truncated) else { return None };
    Some(match kind {
        BodyKind::Html => html_to_text(&text, MAX_TRANSCRIPT_STREAM_BYTES),
        _ => (text, false),
    })
}

/// `text` cut to `limit` bytes on a character boundary. Returns whether it
/// was cut.
fn cut(text: &mut String, limit: usize) -> bool {
    if text.len() <= limit {
        return false;
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    true
}

/// Steps 4-9, the credential, and the fetch.
pub(crate) async fn prepare_and_run(
    backend: &ResourceBackendInner,
    req: &mut Request,
    gated: WebGated,
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
    if str_field(&profile, "protocol") != Some("web") {
        return Err(not_enabled(403, format!("profile `{profile_id}` is not a web profile")));
    }

    // 5. The type and profile opt-ins, the static requirements (`form` and
    //    `sso` are refused here), then what the fetch reads.
    let types = type_config::effective_type_config(backend.core.as_ref(), req).await.map_err(|e| match e {
        type_config::TypeConfigError::Storage(error) => CallError::Vault { reason: "type_config_unreadable", error },
        type_config::TypeConfigError::Malformed(source) => refused(
            "agent_policy_invalid",
            422,
            format!("the {} resource type configuration is not a JSON object", source.as_str()),
        ),
    })?;
    agent_access::check_agent_enabled(types.type_def(resource_type(&meta)), &profile)
        .map_err(|r| refused(r.code(), r.status(), r.to_string()))?;
    let web = AgentWebProfile::parse(&profile)?;

    // 6. MFA: the operator's ticket for this exact call, redeemed once.
    let mfa_method = if profile_gate_flag(&profile) {
        Some(redeem_agent_ticket(backend, req, &gated.binding, &resource, &profile_id, WEB_FETCH_TOOL).await?)
    } else {
        None
    };

    // 7. No bastion route is bypassed.
    check_transport(backend, req, &resource, &meta, &profile).await?;

    // The URL is fixed now, before anything is dialed: the confirmed bytes
    // or a refusal.
    fetch::first_url(&web.start, &gated.path)?;

    // 8. Rate and concurrency. The permit travels with the session task.
    let permit = backend
        .agent_limiter(gated.env.as_ref())
        .try_acquire(&binding_limit_key(&gated.binding))
        .map_err(|r| refused(r.code(), 429, without_code(&r.to_string(), r.code())))?;

    // 9. The start origin: resolved once, every address checked. Redirect
    //    hops are checked the same way, by the executor, as they come.
    let policy = destination_policy(gated.env.as_ref(), &gated.runtime)?;
    let first_target = check_destination(&gated.env, &policy, web.start.dial_host(), web.start.port).await?;

    // Only now, the credential.
    let mut scrubber = CredentialScrubber::none();
    let credential = match &web.login {
        WebLogin::Open => None,
        WebLogin::HttpAuth { secret_id, fields } => {
            let mut data = backend.read_resource_secret(req, &resource, secret_id).await.map_err(|r| {
                refused(
                    "mcp_session_failed",
                    422,
                    format!("the profile's stored credential could not be read: {}", r.into_rv()),
                )
            })?;
            let pair = basic_credential(&data, fields, secret_id);
            crate::connect_web::zeroize_map(&mut data);
            let (username, password) = pair?;
            let actor = gated.binding.operator.as_ref().map(|o| o.username.as_str()).unwrap_or_default();
            log::info!(target: "security", "mcp-agent-web-resolve: user={actor} resource={resource} key={secret_id}");
            scrubber.add_password(&username, &password);
            Some(BasicCredential { username, password })
        }
    };

    let mut who = req.clone();
    who.body = None;
    who.data = None;
    let session_id = format!("aw_{:016x}", rand::rng().random::<u64>());
    let verifier = AgentCertVerifier::new(platform_roots(), web.pins.clone());
    let spec = FetchSpec {
        method: gated.method.clone(),
        path: gated.path.clone(),
        start: web.start.clone(),
        allowed: web.allowed.clone(),
        first_target,
        policy,
        env: gated.env.clone(),
        verifier,
        credential,
        deadline: Instant::now() + std::time::Duration::from_secs(gated.timeout_secs),
        connect_budget: CONNECT_BUDGET,
        raw_limit: MAX_RAW_BODY_BYTES,
    };
    let task = WebSessionTask {
        ctx: backend.core.clone(),
        env: gated.env.clone(),
        token: req.client_token.clone(),
        who,
        binding: gated.binding,
        operator_confirmation: req.mcp_audit.as_ref().and_then(|a| a.operator_confirmation.clone()),
        mfa_method,
        resource,
        profile_id,
        method: gated.method,
        path: gated.path,
        origin: web.start.key.clone(),
        login: web.login.kind(),
        max_output_bytes: usize::try_from(gated.settings.max_output_bytes).unwrap_or(usize::MAX),
        scrubber,
        session_id,
        started_at_ms: now_ms(),
        namespace: agent_namespace(req),
        _permit: permit,
    };
    // The fetch runs in its own task: when the MCP endpoint's timeout drops
    // this request, the task still closes its connection and records its
    // transcript and events.
    match tokio::spawn(task.run(spec)).await {
        Ok(outcome) => outcome.map_err(CallError::Ended),
        Err(e) => Err(CallError::Ended(SessionRefusal::new(
            "mcp_session_failed",
            500,
            format!("the session task ended abnormally: {e}"),
        ))),
    }
}

/// Everything a fetch needs once it is authorized, owned, so the task
/// outlives the request.
struct WebSessionTask {
    ctx: Arc<dyn VaultCtx>,
    env: Arc<dyn BrokeredSessionEnv>,
    /// The MCP token, re-validated every second.
    token: String,
    /// The request, without its body: who and from where, for the events.
    who: Request,
    binding: McpBinding,
    operator_confirmation: Option<String>,
    mfa_method: Option<String>,
    resource: String,
    profile_id: String,
    method: String,
    path: String,
    origin: String,
    login: &'static str,
    max_output_bytes: usize,
    scrubber: CredentialScrubber,
    session_id: String,
    started_at_ms: u64,
    /// The namespace the fetch ran in (the MCP token's binding).
    namespace: String,
    /// Held for the life of the session; dropping it frees the slot.
    _permit: SessionPermit,
}

/// The page text, shaped: what the model gets, what the transcript keeps.
struct ShapedBody {
    /// Sanitized, cut at `max_output_bytes`, with the marker when cut.
    for_model: Option<String>,
    /// Credential-scrubbed, not sanitized, up to 1 MiB.
    for_transcript: TranscriptStream,
    truncated: bool,
    binary: bool,
    redacted: bool,
}

impl WebSessionTask {
    fn pairing_id(&self) -> Option<String> {
        pairing_id(Some(&self.binding))
    }

    async fn run(mut self, spec: FetchSpec) -> Result<Map<String, Value>, SessionRefusal> {
        let started = Instant::now();
        let (abort_tx, abort_rx) = watch::channel(None);
        let watcher = tokio::spawn(watch_revocation(self.ctx.clone(), self.env.clone(), self.token.clone(), abort_tx));
        let (mut trace, outcome) = fetch::run(spec, abort_rx).await;
        watcher.abort();
        let duration_ms = started.elapsed().as_millis() as u64;
        // Every cookie value the target set during the call is scrubbed
        // from what is returned and recorded, like the credential.
        for value in std::mem::take(&mut trace.jar).into_seen_values() {
            self.scrubber.add_secret(&value);
        }
        match outcome {
            Ok(fetched) => self.finish(trace, fetched, duration_ms).await,
            Err(stop) => {
                let (aborted, timed_out, stopped) = match &stop {
                    FetchStop::Aborted(cause) => (Some(*cause), false, None),
                    FetchStop::TimedOut => (Some(AbortCause::Timeout), true, None),
                    FetchStop::Failed(_) => (Some(AbortCause::ExecutorError), false, None),
                    FetchStop::Refused(r) => (None, false, Some(r.code.to_string())),
                };
                // A fetch that sent nothing has nothing to transcribe. The
                // events of a stopped fetch carry no transcript id; the
                // transcript's session id is the correlation.
                if !trace.hops.is_empty() {
                    let body = WebTranscript {
                        aborted: aborted.map(|c| cause_str(c).to_string()),
                        timed_out,
                        stopped,
                        ..self.transcript_base(&trace)
                    };
                    self.record(body, false).await;
                }
                match stop {
                    FetchStop::Refused(refusal) => {
                        self.emit_refused(refusal.code).await;
                        Err(refusal)
                    }
                    FetchStop::Aborted(cause) => {
                        self.emit_aborted(cause).await;
                        Err(aborted_refusal(cause))
                    }
                    FetchStop::TimedOut => {
                        self.emit_aborted(AbortCause::Timeout).await;
                        Err(SessionRefusal::new(
                            "mcp_session_timeout",
                            504,
                            "the fetch did not finish within the call's timeout; it was stopped",
                        ))
                    }
                    FetchStop::Failed(message) => {
                        self.emit_aborted(AbortCause::ExecutorError).await;
                        Err(SessionRefusal::new("mcp_session_failed", 502, message))
                    }
                }
            }
        }
    }

    /// The transcript fields every outcome shares.
    fn transcript_base(&self, trace: &FetchTrace) -> WebTranscript {
        WebTranscript {
            method: self.method.clone(),
            path: self.path.clone(),
            origin: self.origin.clone(),
            target: trace.first_target.map(|a| a.to_string()).unwrap_or_default(),
            login: self.login.to_string(),
            tls: trace.tls.and_then(|v| v.trust_label()).map(str::to_string),
            hops: trace.hops.clone(),
            ..Default::default()
        }
    }

    /// Record the transcript; its id, or `None` when recording failed (the
    /// failure is in the log).
    async fn record(&self, body: WebTranscript, redacted: bool) -> Option<String> {
        let transcript = McpSessionTranscript {
            summary: TranscriptSummary {
                session_id: self.session_id.clone(),
                tool: WEB_FETCH_TOOL.to_string(),
                resource: self.resource.clone(),
                profile_id: self.profile_id.clone(),
                operator: self.binding.operator.clone(),
                pairing_id: self.pairing_id().unwrap_or_default(),
                client_name: self.binding.client_name.clone(),
                namespace: self.namespace.clone(),
                binding_reveal_allowed: self.binding.reveal_allowed,
                operator_confirmation: self.operator_confirmation.clone(),
                mfa_method: self.mfa_method.clone(),
                started_at_ms: self.started_at_ms,
                finished_at_ms: now_ms(),
                credential_echo_redacted: redacted,
            },
            body: TranscriptBody::Web(body),
        };
        let adapter = ScrubberAdapter(&self.scrubber);
        match TranscriptStore::from_ctx(self.ctx.as_ref()) {
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
        }
    }

    async fn emit_refused(&self, reason: &str) {
        let event = AgentRefused {
            reason: reason.to_string(),
            tool: WEB_FETCH_TOOL.to_string(),
            protocol: "web".to_string(),
            resource: Some(self.resource.clone()),
            profile_id: Some(mcp_events::bounded_arg(&self.profile_id)),
            operator: self.binding.operator.clone(),
            pairing_id: self.pairing_id(),
            client_name: self.binding.client_name.clone(),
            namespace: self.namespace.clone(),
        };
        if let Err(e) = mcp_events::emit(self.ctx.as_ref(), &event, Some(&self.who)).await {
            log::warn!(target: "security", "connect.agent.refused could not be written to the audit log: {e}");
        }
    }

    async fn emit_aborted(&self, cause: AbortCause) {
        let event = AgentAborted {
            session_id: self.session_id.clone(),
            cause,
            protocol: "web".to_string(),
            resource: self.resource.clone(),
            profile_id: self.profile_id.clone(),
            operator: self.binding.operator.clone(),
            pairing_id: self.pairing_id(),
            namespace: self.namespace.clone(),
        };
        if let Err(e) = mcp_events::emit(self.ctx.as_ref(), &event, Some(&self.who)).await {
            log::warn!(target: "security", "connect.agent.aborted could not be written to the audit log: {e}");
        }
    }

    /// Steps 2-4 of §8 for the page: decode, reduce, scrub, cap, sanitize.
    fn shape(&self, fetched: &Fetched) -> ShapedBody {
        let kind = body_kind(fetched.content_type.as_deref());
        let empty = TranscriptStream { seen_bytes: fetched.body.len() as u64, ..Default::default() };
        if fetched.body.is_empty() {
            return ShapedBody {
                for_model: Some(String::new()),
                for_transcript: empty,
                truncated: false,
                binary: false,
                redacted: false,
            };
        }
        let Some((text, reduction_cut)) = body_text(kind, &fetched.body, fetched.body_truncated) else {
            return ShapedBody {
                for_model: None,
                for_transcript: TranscriptStream { binary: true, ..empty },
                truncated: fetched.body_truncated,
                binary: true,
                redacted: false,
            };
        };
        let (mut scrubbed, redacted) = self.scrubber.scrub(&text);
        // The transcript keeps up to 1 MiB of the extracted text.
        let mut stored = scrubbed.clone();
        let stored_cut = cut(&mut stored, MAX_TRANSCRIPT_STREAM_BYTES);
        let model_cut = cut(&mut scrubbed, self.max_output_bytes);
        let model_kept = scrubbed.len();
        let mut for_model = sanitize_for_model(&scrubbed);
        let truncated = model_cut || reduction_cut || fetched.body_truncated;
        if truncated {
            for_model.push_str(TRUNCATION_MARKER);
        }
        ShapedBody {
            for_model: Some(for_model),
            for_transcript: TranscriptStream {
                text: stored,
                seen_bytes: fetched.body.len() as u64,
                stored_truncated: stored_cut || reduction_cut || fetched.body_truncated,
                model_truncated_at: model_cut.then_some(model_kept as u64),
                binary: false,
            },
            truncated,
            binary: false,
            redacted,
        }
    }

    /// The fetch answered: shape the page, record the transcript, emit the
    /// event, and answer.
    async fn finish(
        self,
        trace: FetchTrace,
        fetched: Fetched,
        duration_ms: u64,
    ) -> Result<Map<String, Value>, SessionRefusal> {
        let shaped = self.shape(&fetched);
        let (final_path, path_redacted) = self.scrubber.scrub(&fetched.final_path);
        let redacted = shaped.redacted || path_redacted;
        let body = WebTranscript {
            status: Some(fetched.status),
            content_type: fetched.content_type.clone(),
            body_bytes: fetched.body.len() as u64,
            body_truncated: fetched.body_truncated,
            text: shaped.for_transcript.clone(),
            ..self.transcript_base(&trace)
        };
        let transcript_id = self.record(body, redacted).await;

        let event = WebFetchEvent {
            session_id: self.session_id.clone(),
            operator: self.binding.operator.clone(),
            pairing_id: self.pairing_id(),
            client_name: self.binding.client_name.clone(),
            namespace: self.namespace.clone(),
            binding_reveal_allowed: self.binding.reveal_allowed,
            resource: self.resource.clone(),
            profile_id: self.profile_id.clone(),
            method: self.method.clone(),
            path_hmac: mcp_events::audit_hmac(self.ctx.as_ref(), self.path.as_bytes()),
            path_bytes: self.path.len() as u64,
            origin: self.origin.clone(),
            target: trace.first_target.map(|a| a.to_string()).unwrap_or_default(),
            login: self.login.to_string(),
            tls: trace.tls.and_then(|v| v.trust_label()).map(str::to_string),
            mfa_method: self.mfa_method.clone(),
            status: Some(fetched.status),
            redirects: fetched.redirects,
            credential_sent: trace.credential_sent,
            body_bytes: fetched.body.len() as u64,
            truncated: shaped.truncated,
            binary_output: shaped.binary,
            credential_echo_redacted: redacted,
            duration_ms,
            transcript_id,
            operator_confirmation: self.operator_confirmation.clone(),
        };
        if let Err(e) = mcp_events::emit(self.ctx.as_ref(), &event, Some(&self.who)).await {
            log::warn!(target: "security", "connect.agent.web.fetch could not be written to the audit log: {e}");
        }

        let mut data = Map::new();
        data.insert("session_id".into(), Value::String(self.session_id.clone()));
        data.insert("method".into(), Value::String(self.method.clone()));
        data.insert("status".into(), Value::from(fetched.status));
        data.insert(
            "content_type".into(),
            fetched.content_type.as_deref().map(|c| Value::String(sanitize_for_model(c))).unwrap_or(Value::Null),
        );
        data.insert("final_origin".into(), Value::String(fetched.final_origin.clone()));
        data.insert("final_path".into(), Value::String(sanitize_for_model(&final_path)));
        data.insert("redirected".into(), Value::Bool(fetched.redirects > 0));
        if let Some(text) = shaped.for_model {
            data.insert("body_text".into(), Value::String(text));
        }
        data.insert("body_bytes".into(), Value::from(fetched.body.len() as u64));
        data.insert("truncated".into(), Value::Bool(shaped.truncated));
        data.insert("binary_output".into(), Value::Bool(shaped.binary));
        data.insert("credential_echo_redacted".into(), Value::Bool(redacted));
        data.insert("duration_ms".into(), Value::from(duration_ms));
        data.insert("login".into(), Value::String(self.login.to_string()));
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bodies_are_shown_by_their_content_type() {
        assert_eq!(body_kind(Some("text/html; charset=utf-8")), BodyKind::Html);
        assert_eq!(body_kind(Some("application/XHTML+xml")), BodyKind::Html);
        for t in ["application/json", "text/plain", "text/csv", "application/problem+json", "image/svg+xml"] {
            assert_eq!(body_kind(Some(t)), BodyKind::Text, "{t}");
        }
        for t in ["application/pdf", "image/png", "application/octet-stream", "application/zip"] {
            assert_eq!(body_kind(Some(t)), BodyKind::Other, "{t}");
        }
        assert_eq!(body_kind(None), BodyKind::Other, "no type is not guessed at");
    }

    #[test]
    fn binary_bodies_are_not_shown_even_when_typed_as_text() {
        assert_eq!(body_text(BodyKind::Other, b"hello", false), None);
        assert_eq!(body_text(BodyKind::Text, &[0u8; 64], false), None, "mostly NUL is binary");
        assert_eq!(body_text(BodyKind::Text, b"{\"ok\":true}", false), Some(("{\"ok\":true}".into(), false)));
        assert_eq!(body_text(BodyKind::Html, b"<p>hi<script>x</script></p>", false), Some(("hi".into(), false)));
    }

    #[test]
    fn text_is_cut_on_a_character_boundary() {
        let mut t = "ação".to_string();
        assert!(cut(&mut t, 2));
        assert_eq!(t, "a");
        let mut t = "abc".to_string();
        assert!(!cut(&mut t, 3));
    }
}
