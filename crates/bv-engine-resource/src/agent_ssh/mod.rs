//! `resources/v2/connect/agent/ssh/exec`: the handler behind the MCP tool
//! `bv_resource_ssh_exec` (`features/mcp-brokered-sessions.md` §3, §5, §10-11).
//!
//! One call is one session: authorized, opened, used, closed, audited and
//! transcribed, from the vault process. The credential is resolved or minted
//! here and never leaves; the agent gets bounded, sanitized output.
//!
//! **The authorization chain** (§3 step 5), each refusal a stable code and a
//! `connect.agent.refused` event:
//!
//! 1. the request was routed by the MCP dispatcher, with an MCP binding;
//! 2. the binding allows sessions (`connect_allowed`, `confirm_connect`) and
//!    is a local pairing; the gatekeeper asserted the operator's confirmation;
//! 3. the switches: the server config's `mcp.brokered_sessions` (on, `ssh`
//!    listed), the runtime `sys/mcp/config` switch, and an executor compiled
//!    in (`mcp_sessions_ssh`);
//! 4. the `connect` gate on `resources/secrets/<name>/` — policy grants only,
//!    since an MCP token has no entity;
//! 5. the type's `agent_sessions_max` and the profile's `agent_access`, with
//!    the profile's static requirements (a supported credential source, a
//!    host-key pin);
//! 6. MFA: a gated profile is refused until the gatekeeper can run the
//!    operator's step-up (`mcp_session_mfa_required`, or
//!    `mcp_session_mfa_unavailable` for a non-userpass operator);
//! 7. no bastion route is bypassed: a `rustion` profile, a
//!    `rustion-required` policy, or `rustion-preferred` with a bastion;
//! 8. the rate and concurrency limits;
//! 9. the destination policy on every resolved address.
//!
//! Only then is the credential resolved (or the certificate minted), and the
//! session runs in its own task ([`session`]), so a request the MCP endpoint
//! times out still closes its connection and records its transcript.

use std::time::Duration;

use serde_json::{Map, Value};

use crate::{
    bv_error_response_status,
    errors::RvError,
    kernel_api::{
        mcp_events::{self, AgentRefused},
        mcp_sessions::{BrokeredSessionEnv, BrokeredSessionRuntime, BrokeredSessionSettings},
    },
    logical::{Backend, McpBinding, McpBindingKind, Request, Response},
};

#[cfg(all(feature = "mcp_sessions_ssh", not(feature = "sync_handler")))]
pub mod exec;
#[cfg(all(feature = "mcp_sessions_ssh", not(feature = "sync_handler")))]
mod session;
#[cfg(all(feature = "mcp_sessions_ssh", not(feature = "sync_handler"), any(test, feature = "test-support")))]
pub mod test_server;

/// The MCP tool this route serves.
pub const SSH_EXEC_TOOL: &str = "bv_resource_ssh_exec";

/// Budget for TCP connect, SSH handshake and authentication, inside the call
/// timeout (§5.3).
pub const CONNECT_BUDGET: Duration = Duration::from_secs(10);

/// Bytes read and discarded past the output cap before the channel is closed
/// (§5.3).
pub const DRAIN_LIMIT_BYTES: usize = 1 << 20;

/// How often a running session re-validates its token and the runtime
/// switch. Every second, so a revocation ends the session within the two
/// seconds §5.3 allows, including the time to send `KILL` and close.
pub const REVALIDATE_EVERY: Duration = Duration::from_secs(1);

/// Longest validity a brokered certificate may carry (§5.2).
pub const CERT_VALIDITY_SECS: u64 = 60;

/// Whether this build carries the SSH executor.
pub const SSH_EXECUTOR_COMPILED: bool = cfg!(all(feature = "mcp_sessions_ssh", not(feature = "sync_handler")));

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
/// come from the executor's half, so a build without it never makes them.
#[derive(Debug)]
#[cfg_attr(not(all(feature = "mcp_sessions_ssh", not(feature = "sync_handler"))), allow(dead_code))]
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
    fn from_request(req: &Request) -> Self {
        let arg = |key: &str| req.get_data(key).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
        Self {
            resource: arg("resource"),
            profile_id: arg("profile_id"),
            binding: req.auth.as_ref().and_then(|a| a.mcp_binding.clone()),
        }
    }

    pub fn pairing_id(&self) -> Option<String> {
        match self.binding.as_ref().map(|b| &b.kind) {
            Some(McpBindingKind::Pairing(id)) => Some(id.clone()),
            _ => None,
        }
    }
}

/// `connect.agent.refused`, best effort: the call is refused whatever
/// happens to the event, and a broker failure is logged.
#[maybe_async::maybe_async]
pub(crate) async fn emit_refused(ctx: &dyn crate::kernel_api::VaultCtx, req: &Request, call: &AgentCall, reason: &str) {
    let event = AgentRefused {
        reason: reason.to_string(),
        tool: SSH_EXEC_TOOL.to_string(),
        protocol: "ssh".to_string(),
        resource: Some(mcp_events::bounded_arg(&call.resource)).filter(|s| !s.is_empty()),
        profile_id: Some(mcp_events::bounded_arg(&call.profile_id)).filter(|s| !s.is_empty()),
        operator: call.binding.as_ref().and_then(|b| b.operator.clone()),
        pairing_id: call.pairing_id(),
        client_name: call.binding.as_ref().map(|b| b.client_name.clone()).unwrap_or_default(),
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
             general remote-exec API",
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

/// The confirmed command, re-validated exactly as the dispatcher validated
/// it (§5.1): the handler does not trust that it was.
pub(crate) fn check_command(req: &Request) -> Result<String, SessionRefusal> {
    let invalid = |m: String| SessionRefusal::new("mcp_invalid_argument", 400, m);
    let command = req
        .get_data("command")
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .ok_or_else(|| invalid("`command` is required".into()))?;
    if command.is_empty() || command.len() > bv_mcp::dispatcher::MAX_SESSION_COMMAND_BYTES {
        return Err(invalid(format!(
            "`command` is {} bytes; it must be 1-{}",
            command.len(),
            bv_mcp::dispatcher::MAX_SESSION_COMMAND_BYTES
        )));
    }
    if let Some(c) = bv_mcp::sanitize::forbidden_command_char(&command) {
        return Err(invalid(format!(
            "`command` contains U+{:04X}; a session command is refused rather than cleaned",
            c as u32
        )));
    }
    Ok(command)
}

/// Step 3: every switch on. Returns the settings and the runtime read.
#[maybe_async::maybe_async]
pub(crate) async fn check_switches(
    env: Option<std::sync::Arc<dyn BrokeredSessionEnv>>,
) -> Result<(std::sync::Arc<dyn BrokeredSessionEnv>, BrokeredSessionSettings, BrokeredSessionRuntime), SessionRefusal> {
    let disabled = |m: &str| SessionRefusal::new("mcp_brokered_sessions_disabled", 403, m);
    let env = env.ok_or_else(|| disabled("brokered sessions are not available on this server"))?;
    let settings = env.settings();
    if !settings.enabled {
        return Err(disabled("brokered sessions are off in the server configuration (mcp.brokered_sessions.enabled)"));
    }
    if !settings.allows_protocol("ssh") {
        return Err(SessionRefusal::new(
            "mcp_session_protocol_disabled",
            403,
            "SSH is not among the server configuration's mcp.brokered_sessions.protocols",
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
    if !SSH_EXECUTOR_COMPILED {
        return Err(SessionRefusal::new(
            "mcp_session_protocol_disabled",
            403,
            "this build has no SSH session executor (cargo feature mcp_sessions_ssh)",
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

#[maybe_async::maybe_async]
impl super::ResourceBackendInner {
    /// `POST resources/v2/connect/agent/ssh/exec`.
    pub async fn handle_agent_ssh_exec(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let call = AgentCall::from_request(req);
        match self.agent_ssh_exec(req).await {
            Ok(data) => Ok(Some(Response::data_response(Some(data)))),
            Err(CallError::Refused(refusal)) => {
                emit_refused(self.core.as_ref(), req, &call, refusal.code).await;
                Err(refusal.into_error())
            }
            Err(CallError::Vault { reason, error }) => {
                emit_refused(self.core.as_ref(), req, &call, reason).await;
                Err(error)
            }
            Err(CallError::Ended(refusal)) => Err(refusal.into_error()),
        }
    }

    async fn agent_ssh_exec(&self, req: &mut Request) -> Result<Map<String, Value>, CallError> {
        let binding = check_dispatch_and_binding(req)?;
        let command = check_command(req)?;
        let (env, settings, runtime) = check_switches(self.core.kernel().brokered_sessions()).await?;
        let timeout_secs = check_timeout(req, &settings)?;
        let gated = Gated { binding, command, env, settings, runtime, timeout_secs };
        self.run_gated(req, gated).await
    }

    /// Steps 4-9 and the session itself ([`session`]).
    #[cfg(all(feature = "mcp_sessions_ssh", not(feature = "sync_handler")))]
    async fn run_gated(&self, req: &mut Request, gated: Gated) -> Result<Map<String, Value>, CallError> {
        session::prepare_and_run(self, req, gated).await
    }

    /// A build without the executor: `check_switches` has already refused,
    /// so this is never reached; it refuses the same way regardless.
    #[cfg(not(all(feature = "mcp_sessions_ssh", not(feature = "sync_handler"))))]
    async fn run_gated(&self, _req: &mut Request, _gated: Gated) -> Result<Map<String, Value>, CallError> {
        Err(CallError::Refused(SessionRefusal::new(
            "mcp_session_protocol_disabled",
            403,
            "this build has no SSH session executor (cargo feature mcp_sessions_ssh)",
        )))
    }
}

/// What steps 1-3 established.
#[cfg_attr(not(all(feature = "mcp_sessions_ssh", not(feature = "sync_handler"))), allow(dead_code))]
pub(crate) struct Gated {
    pub binding: McpBinding,
    pub command: String,
    pub env: std::sync::Arc<dyn BrokeredSessionEnv>,
    pub settings: BrokeredSessionSettings,
    pub runtime: BrokeredSessionRuntime,
    pub timeout_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logical::{Auth, McpAuditContext};

    fn binding(kind: McpBindingKind, connect: bool, confirm: bool) -> McpBinding {
        McpBinding {
            kind,
            catalogue_hash: String::new(),
            tool_allowlist: vec![SSH_EXEC_TOOL.into()],
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
        // Not routed by the dispatcher: not a REST exec API.
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
