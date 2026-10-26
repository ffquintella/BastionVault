//! What every MCP brokered-session route shares
//! (`features/mcp-brokered-sessions.md` §3, §10-11): the refusal type, the
//! dispatch/binding and switch checks, the operator's MFA ticket, the
//! bastion and destination checks, and revocation. `agent_ssh` (Phase 1)
//! and `agent_web` (Phase 2) both run their calls through these, so a check
//! is written once and holds for every protocol.
//!
//! The half that only a compiled executor needs (the ticket, the transport
//! and destination checks, revocation) is behind the executor features, as
//! the executors themselves are.

use serde_json::Value;

use crate::{
    bv_error_response_status,
    errors::RvError,
    kernel_api::{
        mcp_events::{self, AgentRefused},
        mcp_sessions::{BrokeredSessionEnv, BrokeredSessionRuntime, BrokeredSessionSettings},
    },
    logical::{McpBinding, McpBindingKind, Request},
};

/// How often a running session re-validates its token and the runtime
/// switch. Every second, so a revocation ends the session within the two
/// seconds §5.3 allows, including the time to close.
pub const REVALIDATE_EVERY: std::time::Duration = std::time::Duration::from_secs(1);

/// A refusal or a failure with its stable code (`bv_mcp::error::SESSION_ERROR_CODES`).
/// The message names the resource or the rule, never output, credential
/// material or a ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRefusal {
    pub code: &'static str,
    pub status: u16,
    pub message: String,
}

impl SessionRefusal {
    pub fn new(code: &'static str, status: u16, message: impl Into<String>) -> Self {
        Self { code, status, message: message.into() }
    }

    /// The error the route answers with: the code first, so the dispatcher
    /// can carry it to the client as `data.code`.
    pub fn into_error(self) -> RvError {
        bv_error_response_status!(self.status, &format!("{}: {}", self.code, self.message))
    }
}

/// How a call ended, when it did not return output. `Vault` and `Ended`
/// come from an executor's half, so a build without one never makes them.
#[derive(Debug)]
#[cfg_attr(
    not(all(any(feature = "mcp_sessions_ssh", feature = "mcp_sessions_web"), not(feature = "sync_handler"))),
    allow(dead_code)
)]
pub(crate) enum CallError {
    /// Refused before anything was dialed: the handler emits
    /// `connect.agent.refused` with `reason`.
    Refused(SessionRefusal),
    /// Refused by a vault check that has its own error (the `connect` gate's
    /// permission denial, a missing resource); `reason` names it in the event.
    Vault { reason: &'static str, error: RvError },
    /// The session ran (or tried to): its own task has emitted its events and
    /// recorded its transcript.
    Ended(SessionRefusal),
}

impl From<SessionRefusal> for CallError {
    fn from(r: SessionRefusal) -> Self {
        Self::Refused(r)
    }
}

/// The call as the dispatcher sent it, for refusal events.
pub(crate) struct AgentCall {
    pub resource: String,
    pub profile_id: String,
    pub binding: Option<McpBinding>,
}

impl AgentCall {
    pub fn from_request(req: &Request) -> Self {
        let arg = |key: &str| req.get_data(key).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
        Self {
            resource: arg("resource"),
            profile_id: arg("profile_id"),
            binding: req.auth.as_ref().and_then(|a| a.mcp_binding.clone()),
        }
    }

    pub fn pairing_id(&self) -> Option<String> {
        pairing_id(self.binding.as_ref())
    }
}

/// The pairing id of a binding; `None` for an app or no binding.
pub(crate) fn pairing_id(binding: Option<&McpBinding>) -> Option<String> {
    match binding.map(|b| &b.kind) {
        Some(McpBindingKind::Pairing(id)) => Some(id.clone()),
        _ => None,
    }
}

/// Which route a refusal is for, in its event.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SessionTool {
    /// The MCP tool, e.g. `bv_resource_ssh_exec`.
    pub tool: &'static str,
    /// `ssh`, `web` or `rdp`: the `mcp.brokered_sessions.protocols` entry.
    pub protocol: &'static str,
}

/// The namespace an agent call is attributed to in its events: the MCP
/// token's stored binding, where the dispatcher routes every call
/// (`features/mcp-namespace-selection.md`). Attribution only, so a binding
/// that does not normalize is recorded as stored rather than as root.
pub(crate) fn agent_namespace(req: &Request) -> String {
    let Some(auth) = req.auth.as_ref() else {
        return String::new();
    };
    crate::kernel_api::namespace::bound_namespace(&auth.metadata)
        .unwrap_or_else(|_| crate::kernel_api::namespace::binding_from_metadata(&auth.metadata).0)
}

/// `connect.agent.refused`, best effort: the call is refused whatever
/// happens to the event, and a broker failure is logged.
#[maybe_async::maybe_async]
pub(crate) async fn emit_refused(
    ctx: &dyn crate::kernel_api::VaultCtx,
    req: &Request,
    call: &AgentCall,
    tool: SessionTool,
    reason: &str,
) {
    let event = AgentRefused {
        reason: reason.to_string(),
        tool: tool.tool.to_string(),
        protocol: tool.protocol.to_string(),
        resource: Some(mcp_events::bounded_arg(&call.resource)).filter(|s| !s.is_empty()),
        profile_id: Some(mcp_events::bounded_arg(&call.profile_id)).filter(|s| !s.is_empty()),
        operator: call.binding.as_ref().and_then(|b| b.operator.clone()),
        pairing_id: call.pairing_id(),
        client_name: call.binding.as_ref().map(|b| b.client_name.clone()).unwrap_or_default(),
        namespace: agent_namespace(req),
    };
    if let Err(e) = mcp_events::emit(ctx, &event, Some(req)).await {
        log::warn!(target: "security", "connect.agent.refused could not be written to the audit log: {e}");
    }
}

/// Steps 1-2: the route answers only the MCP dispatcher, for a binding that
/// may open sessions, on a call the operator confirmed. Returns the binding.
pub(crate) fn check_dispatch_and_binding(req: &Request) -> Result<McpBinding, SessionRefusal> {
    let binding = req.auth.as_ref().and_then(|a| a.mcp_binding.clone());
    let Some(binding) = binding.filter(|_| req.mcp_dispatch) else {
        return Err(SessionRefusal::new(
            "mcp_connect_not_allowed",
            403,
            "this route answers only calls the MCP dispatcher routes for an MCP-bound token; it is not a \
             general remote-session API",
        ));
    };
    // Defence in depth: the dispatcher checked all three already.
    if !binding.connect_allowed || !binding.confirm_connect {
        return Err(SessionRefusal::new(
            "mcp_connect_not_allowed",
            403,
            "this pairing does not allow brokered sessions (connect_allowed)",
        ));
    }
    if !matches!(binding.kind, McpBindingKind::Pairing(_)) {
        return Err(SessionRefusal::new(
            "mcp_connect_requires_local_operator",
            403,
            "brokered sessions need a local pairing with an operator to confirm each call; network-mode apps \
             never open them",
        ));
    }
    // The gatekeeper's confirmation record (§9). The vault cannot see the
    // confirmation happen; it requires the gatekeeper's assertion and
    // audits it as asserted. Without one the call is refused: confirmation
    // is mandatory for every session call, permanently.
    let confirmed =
        req.mcp_audit.as_ref().is_some_and(|a| a.confirmed_by_operator && a.operator_confirmation.is_some());
    if !confirmed {
        return Err(SessionRefusal::new(
            "mcp_confirmation_required",
            403,
            "every brokered-session call must be confirmed by the operator through the local gatekeeper, and \
             this call carries no confirmation",
        ));
    }
    Ok(binding)
}

/// Step 3: every switch on for `protocol`, and its executor compiled in
/// (`feature` names the cargo feature). Returns the settings and the
/// runtime read.
#[maybe_async::maybe_async]
pub(crate) async fn check_switches(
    env: Option<std::sync::Arc<dyn BrokeredSessionEnv>>,
    protocol: &str,
    executor_compiled: bool,
    feature: &str,
) -> Result<(std::sync::Arc<dyn BrokeredSessionEnv>, BrokeredSessionSettings, BrokeredSessionRuntime), SessionRefusal> {
    let disabled = |m: &str| SessionRefusal::new("mcp_brokered_sessions_disabled", 403, m);
    let env = env.ok_or_else(|| disabled("brokered sessions are not available on this server"))?;
    let settings = env.settings();
    if !settings.enabled {
        return Err(disabled("brokered sessions are off in the server configuration (mcp.brokered_sessions.enabled)"));
    }
    if !settings.allows_protocol(protocol) {
        return Err(SessionRefusal::new(
            "mcp_session_protocol_disabled",
            403,
            format!("`{protocol}` is not among the server configuration's mcp.brokered_sessions.protocols"),
        ));
    }
    let runtime = env
        .runtime()
        .await
        .map_err(|e| disabled(&format!("the runtime brokered-session switch could not be read ({e}); refusing")))?;
    if !runtime.enabled {
        return Err(disabled(
            "brokered sessions are switched off at runtime (sys/mcp/config brokered_sessions_enabled)",
        ));
    }
    if !executor_compiled {
        return Err(SessionRefusal::new(
            "mcp_session_protocol_disabled",
            403,
            format!("this build has no `{protocol}` session executor (cargo feature {feature})"),
        ));
    }
    Ok((env, settings, runtime))
}

/// The optional `timeout_secs`, within the configured call timeout.
pub(crate) fn check_timeout(req: &Request, settings: &BrokeredSessionSettings) -> Result<u64, SessionRefusal> {
    match req.get_data("timeout_secs").ok() {
        None | Some(Value::Null) => Ok(settings.call_timeout_secs),
        Some(v) => match v.as_u64() {
            Some(n) if n >= 1 && n <= settings.call_timeout_secs => Ok(n),
            _ => Err(SessionRefusal::new(
                "mcp_invalid_argument",
                400,
                format!("`timeout_secs` must be 1-{} on this server", settings.call_timeout_secs),
            )),
        },
    }
}

#[cfg(all(any(feature = "mcp_sessions_ssh", feature = "mcp_sessions_web"), not(feature = "sync_handler")))]
pub(crate) use executor::*;

/// The executors' shared half.
#[cfg(all(any(feature = "mcp_sessions_ssh", feature = "mcp_sessions_web"), not(feature = "sync_handler")))]
mod executor {
    use std::{
        num::NonZeroU32,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use bv_kernel_api::{
        mcp_events::AbortCause, mcp_sessions::BrokeredSessionEnv, mcp_transcripts::TranscriptScrubber, VaultCtx,
    };
    use bv_mcp::untrusted::CredentialScrubber;
    use bv_utils::destination_policy::{
        parse_target_cidrs, CheckedTarget, DestinationPolicy, DESTINATION_REFUSED_CODE,
    };
    use serde_json::{Map, Value};
    use tokio::{sync::watch, time::MissedTickBehavior};

    use super::{CallError, SessionRefusal, REVALIDATE_EVERY};
    use crate::{
        agent_limits::{SessionLimiter, SessionLimits},
        connect_mfa::{caller_namespace, ConnectMfaTicketStore, McpCallBinding, TicketBinding},
        kernel_api::mcp_sessions::BrokeredSessionRuntime,
        logical::{McpBinding, McpBindingKind, Request},
        ResourceBackendInner,
    };

    /// A non-empty, trimmed string field of a stored record.
    pub fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
        v.get(key).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty())
    }

    /// The stored resource's type id, for the type opt-in.
    pub fn resource_type(meta: &Map<String, Value>) -> &str {
        meta.get("type").and_then(Value::as_str).unwrap_or_default()
    }

    pub fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
    }

    /// A limiter's or a policy's own message already leads with the code.
    pub fn without_code(message: &str, code: &str) -> String {
        message.strip_prefix(code).and_then(|m| m.strip_prefix(": ")).unwrap_or(message).to_string()
    }

    pub fn refused(code: &'static str, status: u16, message: impl Into<String>) -> CallError {
        CallError::Refused(SessionRefusal::new(code, status, message))
    }

    impl ResourceBackendInner {
        /// This node's session limiter, built from the server config on first
        /// use (the config is static for the life of the process). One
        /// limiter for every protocol: the per-binding and per-node limits
        /// count sessions, whatever they speak.
        pub(crate) fn agent_limiter(&self, env: &dyn BrokeredSessionEnv) -> &SessionLimiter {
            self.agent_limiter.get_or_init(|| {
                let settings = env.settings();
                let defaults = SessionLimits::default();
                SessionLimiter::new(SessionLimits {
                    rate_per_binding_per_min: NonZeroU32::new(settings.rate_per_binding_per_min)
                        .unwrap_or(defaults.rate_per_binding_per_min),
                    max_concurrent: NonZeroU32::new(settings.max_concurrent).unwrap_or(defaults.max_concurrent),
                })
            })
        }
    }

    /// Whether the binding's operator is a userpass principal: the only kind
    /// with a second factor on file to step up with (§3.1 "Userpass-only").
    pub fn userpass_operator(binding: &McpBinding) -> Option<&crate::logical::McpOperatorRef> {
        binding.operator.as_ref().filter(|o| !o.username.is_empty() && o.mount_path.starts_with("userpass"))
    }

    /// Step 6 for an MFA-gated profile (`features/mcp-brokered-sessions.md`
    /// §3.1 step 5): redeem the operator's ticket the gatekeeper relayed,
    /// single use and delete-before-validate, against the ticket this exact
    /// call must carry --
    ///
    /// * mount, principal and namespace from `McpBinding.operator` (the MCP
    ///   token's own metadata is empty), and the namespace must also be the
    ///   one this call runs in, so a ticket for a same-named resource in
    ///   another tenant cannot be spent here;
    /// * resource and profile from the call;
    /// * `mcp_call` = the binding's pairing id, `tool` and the hash of the
    ///   call's arguments the endpoint recorded -- so another command, path,
    ///   tool, resource, profile, pairing or operator burns the ticket and is
    ///   refused.
    ///
    /// Runs before any credential is resolved. Returns the factor proved.
    pub async fn redeem_agent_ticket(
        backend: &ResourceBackendInner,
        req: &Request,
        binding: &McpBinding,
        resource: &str,
        profile_id: &str,
        tool: &str,
    ) -> Result<String, CallError> {
        let Some(operator) = userpass_operator(binding) else {
            return Err(refused(
                "mcp_session_mfa_unavailable",
                403,
                "this connection profile requires MFA, and only a userpass operator holds the enrolled factors to \
                 complete it; the operator who paired this assistant is not a userpass user",
            ));
        };
        let ticket = req
            .get_data("connect_ticket")
            .ok()
            .and_then(|v| v.as_str().map(str::trim).filter(|t| !t.is_empty()).map(str::to_string))
            .ok_or_else(|| {
                refused(
                    "mcp_session_mfa_required",
                    403,
                    "this connection profile requires MFA, which the operator completes in the gatekeeper's \
                     confirmation for this one call; this call carries no operator ticket",
                )
            })?;
        let pairing_id = match &binding.kind {
            McpBindingKind::Pairing(id) => id.clone(),
            McpBindingKind::App(_) => {
                return Err(refused(
                    "mcp_connect_requires_local_operator",
                    403,
                    "network-mode apps never open sessions",
                ))
            }
        };
        let call = req.mcp_audit.as_ref().filter(|a| a.tool == tool && !a.args_hash.is_empty()).ok_or_else(|| {
            refused(
                "mcp_session_mfa_ticket_refused",
                403,
                "this call carries no record of its arguments to bind the operator's ticket to",
            )
        })?;
        let namespace = caller_namespace(&backend.core, req)
            .await
            .map_err(|error| CallError::Vault { reason: "namespace_unresolvable", error })?;
        if namespace != operator.namespace {
            return Err(refused(
                "mcp_session_mfa_unavailable",
                403,
                "the operator signed in to another namespace than the one this call runs in, so their MFA ticket \
                 cannot be bound to this resource",
            ));
        }
        let expect = TicketBinding {
            mount: operator.mount_path.clone(),
            principal: operator.username.to_lowercase(),
            namespace,
            resource: resource.to_string(),
            profile_id: profile_id.to_string(),
            mcp_call: Some(McpCallBinding {
                pairing_id: pairing_id.clone(),
                tool: tool.to_string(),
                args_hash: call.args_hash.clone(),
            }),
        };
        let store = ConnectMfaTicketStore::new(backend.core.as_ref())
            .map_err(|error| CallError::Vault { reason: "mfa_ticket_store_unavailable", error })?;
        let record = store.consume(&ticket, &expect).await.map_err(|e| match e {
            crate::connect_mfa::TicketError::Storage(error) => {
                CallError::Vault { reason: "mfa_ticket_store_unavailable", error }
            }
            other => refused("mcp_session_mfa_ticket_refused", 403, other.to_string()),
        })?;
        log::info!(
            "connect.mfa.authorized resource={resource} profile={profile_id} principal={} method={} mcp_call=true \
             pairing_id={pairing_id} tool={tool}",
            record.principal,
            record.method
        );
        Ok(record.method)
    }

    /// Step 7: a session must not bypass a bastion. A `rustion` profile, a
    /// `rustion-required` transport policy, and `rustion-preferred` with a
    /// bastion available all route through Rustion, which cannot run an
    /// agent's session, so they are refused rather than dialed direct. An
    /// unresolvable policy is refused too: guessing "direct" is how a lock
    /// gets bypassed.
    pub async fn check_transport(
        backend: &ResourceBackendInner,
        req: &Request,
        resource: &str,
        meta: &Map<String, Value>,
        profile: &Value,
    ) -> Result<(), CallError> {
        let bastion = |m: String| refused("mcp_session_requires_bastion", 403, m);
        if str_field(profile, "kind") == Some("rustion") {
            return Err(bastion(
                "this profile routes through a Rustion bastion, which cannot run an agent's session".into(),
            ));
        }
        let path = "rustion/policy/effective";
        let router = backend.core.router();
        if router
            .matching_mount(path)
            .map_err(|e| bastion(format!("the transport policy could not be resolved: {e}")))?
            != "rustion/"
        {
            // No Rustion engine mounted: direct is the only transport there is.
            return Ok(());
        }
        let groups = match backend.core.resource_groups() {
            Some(index) => index
                .groups_for_resource(resource)
                .await
                .map_err(|e| bastion(format!("the resource's asset groups could not be read: {e}")))?,
            None => Vec::new(),
        };
        let mut body = Map::new();
        body.insert("resource_id".into(), Value::String(resource.to_string()));
        if let Some(t) = meta.get("type").and_then(Value::as_str).filter(|t| !t.is_empty()) {
            body.insert("resource_type".into(), Value::String(t.to_string()));
        }
        if !groups.is_empty() {
            body.insert("asset_group_ids".into(), Value::Array(groups.into_iter().map(Value::String).collect()));
        }
        let mut sub = Request::new_write_request(path, Some(body));
        sub.operation = crate::logical::Operation::Write;
        sub.auth = req.auth.clone();
        sub.namespace_path = req.namespace_path.clone();
        let data = router
            .handle_request(&mut sub)
            .await
            .map_err(|e| {
                bastion(format!(
                    "the Rustion transport policy could not be resolved ({e}); refusing rather than guessing"
                ))
            })?
            .and_then(|r| r.data)
            .unwrap_or_default();
        let transport = data.get("transport").and_then(Value::as_str).unwrap_or_default();
        let has_bastion = data.get("bastions").and_then(Value::as_array).is_some_and(|b| !b.is_empty());
        match transport {
            "rustion-required" => Err(bastion(
                "the resource's transport policy is rustion-required; agent sessions are never dialed direct".into(),
            )),
            "rustion-preferred" if has_bastion => Err(bastion(
                "the resource's transport policy prefers a Rustion bastion and one is configured; agent sessions \
                 are not downgraded to direct"
                    .into(),
            )),
            _ => Ok(()),
        }
    }

    /// The destination policy in force for this call: the runtime (or
    /// server, or default) allow-list, the always-denied classes and the
    /// vault's own addresses, as the environment builds it.
    pub fn destination_policy(
        env: &dyn BrokeredSessionEnv,
        runtime: &BrokeredSessionRuntime,
    ) -> Result<DestinationPolicy, CallError> {
        let parsed = parse_target_cidrs(&runtime.allowed_target_cidrs).map_err(|e| {
            refused(DESTINATION_REFUSED_CODE, 403, format!("the destination allow-list in force does not parse ({e})"))
        })?;
        Ok(env.destination_policy(parsed.cidrs))
    }

    /// Step 9 (and every web redirect hop): resolve `host` once through the
    /// environment's resolver, check every address, and hand back the only
    /// thing an executor may dial.
    pub async fn check_destination(
        env: &Arc<dyn BrokeredSessionEnv>,
        policy: &DestinationPolicy,
        host: String,
        port: u16,
    ) -> Result<CheckedTarget, SessionRefusal> {
        let policy = policy.clone();
        let resolver = env.resolver();
        // The platform resolver blocks.
        let checked = tokio::task::spawn_blocking(move || policy.resolve_and_check(resolver.as_ref(), &host, port))
            .await
            .map_err(|e| {
                SessionRefusal::new(DESTINATION_REFUSED_CODE, 500, format!("the destination check did not finish: {e}"))
            })?;
        checked.map_err(|r| SessionRefusal::new(r.code(), 403, without_code(&r.to_string(), r.code())))
    }

    /// The transcript writer's view of a session's credential scrubber.
    pub struct ScrubberAdapter<'a>(pub &'a CredentialScrubber);

    impl TranscriptScrubber for ScrubberAdapter<'_> {
        fn scrub(&self, text: &str) -> (String, bool) {
            self.0.scrub(text)
        }
    }

    /// Watch the session's token and the runtime switch until one says stop.
    pub async fn watch_revocation(
        ctx: Arc<dyn VaultCtx>,
        env: Arc<dyn BrokeredSessionEnv>,
        token: String,
        tx: watch::Sender<Option<AbortCause>>,
    ) {
        let mut tick = tokio::time::interval(REVALIDATE_EVERY);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tick.tick().await;
            if let Some(cause) = revalidate(ctx.as_ref(), env.as_ref(), &token).await {
                let _ = tx.send(Some(cause));
                return;
            }
        }
    }

    /// `None` while the session may go on. A check that cannot be made ends
    /// the session too: fail closed.
    async fn revalidate(ctx: &dyn VaultCtx, env: &dyn BrokeredSessionEnv, token: &str) -> Option<AbortCause> {
        let Some(tokens) = ctx.tokens() else { return Some(AbortCause::ExecutorError) };
        match tokens.lookup(token).await {
            Ok(Some(_)) => {}
            Ok(None) => return Some(AbortCause::TokenRevoked),
            Err(_) => return Some(AbortCause::ExecutorError),
        }
        match env.runtime().await {
            Ok(r) if r.enabled => None,
            Ok(_) => Some(AbortCause::KillSwitch),
            Err(_) => Some(AbortCause::ExecutorError),
        }
    }

    pub fn cause_str(cause: AbortCause) -> &'static str {
        match cause {
            AbortCause::TokenRevoked => "token_revoked",
            AbortCause::KillSwitch => "kill_switch",
            AbortCause::Timeout => "timeout",
            AbortCause::ExecutorError => "executor_error",
        }
    }

    /// What a session cut short by revocation or the kill switch answers.
    pub fn aborted_refusal(cause: AbortCause) -> SessionRefusal {
        let why = match cause {
            AbortCause::TokenRevoked => "the pairing or its token was revoked",
            AbortCause::KillSwitch => "brokered sessions were switched off",
            AbortCause::Timeout => "the call timed out",
            AbortCause::ExecutorError => "the session could not be re-validated",
        };
        SessionRefusal::new("mcp_session_aborted", 409, format!("{why}; the session was ended"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn only_a_userpass_operator_can_step_up_for_an_agent() {
            let mut binding = McpBinding {
                kind: McpBindingKind::Pairing("p".into()),
                catalogue_hash: String::new(),
                tool_allowlist: vec![],
                path_scope: vec![],
                reveal_allowed: false,
                destructive_allowed: false,
                client_name: String::new(),
                client_version: String::new(),
                waived_until: None,
                connect_allowed: true,
                confirm_connect: true,
                operator: Some(crate::logical::McpOperatorRef {
                    username: "felipe".into(),
                    mount_path: "userpass/".into(),
                    ..Default::default()
                }),
            };
            assert!(userpass_operator(&binding).is_some());
            binding.operator.as_mut().unwrap().mount_path = "oidc/".into();
            assert!(userpass_operator(&binding).is_none());
            binding.operator.as_mut().unwrap().mount_path = "userpass/".into();
            binding.operator.as_mut().unwrap().username = String::new();
            assert!(userpass_operator(&binding).is_none());
            binding.operator = None;
            assert!(userpass_operator(&binding).is_none());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logical::{Auth, McpAuditContext};

    fn binding(kind: McpBindingKind, connect: bool, confirm: bool) -> McpBinding {
        McpBinding {
            kind,
            catalogue_hash: String::new(),
            tool_allowlist: vec!["bv_resource_ssh_exec".into()],
            path_scope: vec!["resources/secrets/web-01/".into()],
            reveal_allowed: false,
            destructive_allowed: false,
            client_name: "claude-code".into(),
            client_version: "2".into(),
            waived_until: None,
            connect_allowed: connect,
            confirm_connect: confirm,
            operator: None,
        }
    }

    fn request(binding: Option<McpBinding>, dispatched: bool, confirmed: bool) -> Request {
        let mut req = Request::new("v2/connect/agent/ssh/exec");
        req.mcp_dispatch = dispatched;
        req.auth = Some(Auth { mcp_binding: binding, ..Default::default() });
        req.mcp_audit = Some(McpAuditContext {
            confirmed_by_operator: confirmed,
            operator_confirmation: confirmed.then(|| "asserted-by-local-host".to_string()),
            ..Default::default()
        });
        req
    }

    fn code(r: Result<McpBinding, SessionRefusal>) -> &'static str {
        r.map(|_| "ok").unwrap_or_else(|e| e.code)
    }

    #[test]
    fn only_a_confirmed_dispatched_pairing_with_connect_passes() {
        let pairing = || binding(McpBindingKind::Pairing("p".into()), true, true);
        assert_eq!(code(check_dispatch_and_binding(&request(Some(pairing()), true, true))), "ok");
        // Not routed by the dispatcher: not a REST session API.
        assert_eq!(code(check_dispatch_and_binding(&request(Some(pairing()), false, true))), "mcp_connect_not_allowed");
        assert_eq!(code(check_dispatch_and_binding(&request(None, true, true))), "mcp_connect_not_allowed");
        // The binding must allow sessions, with confirmation.
        let no_connect = binding(McpBindingKind::Pairing("p".into()), false, true);
        assert_eq!(code(check_dispatch_and_binding(&request(Some(no_connect), true, true))), "mcp_connect_not_allowed");
        let no_confirm = binding(McpBindingKind::Pairing("p".into()), true, false);
        assert_eq!(code(check_dispatch_and_binding(&request(Some(no_confirm), true, true))), "mcp_connect_not_allowed");
        // Network-mode apps never.
        let app = binding(McpBindingKind::App("ci".into()), true, true);
        assert_eq!(
            code(check_dispatch_and_binding(&request(Some(app), true, true))),
            "mcp_connect_requires_local_operator"
        );
        // No confirmation marker: fail closed.
        assert_eq!(
            code(check_dispatch_and_binding(&request(Some(pairing()), true, false))),
            "mcp_confirmation_required"
        );
        let mut half = request(Some(pairing()), true, true);
        half.mcp_audit.as_mut().unwrap().operator_confirmation = None;
        assert_eq!(code(check_dispatch_and_binding(&half)), "mcp_confirmation_required");
    }

    #[test]
    fn a_refusal_leads_its_error_with_the_code() {
        let err = SessionRefusal::new("mcp_session_busy", 429, "this pairing already has a session open").into_error();
        let text = err.to_string();
        assert!(text.contains("mcp_session_busy: this pairing already has a session open"), "{text}");
        let mapped = bv_mcp::error::session_error_from_backend(&text).unwrap();
        assert_eq!(mapped.code(), "mcp_session_busy");
    }
}
