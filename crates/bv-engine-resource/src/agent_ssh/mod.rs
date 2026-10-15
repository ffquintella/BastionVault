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
//! 6. MFA: a gated profile needs the operator's ticket for this exact call,
//!    relayed by the gatekeeper and redeemed once (`mcp_session_mfa_required`
//!    without one, `mcp_session_mfa_ticket_refused` for one bound to anything
//!    else, `mcp_session_mfa_unavailable` for a non-userpass operator);
//! 7. no bastion route is bypassed: a `rustion` profile, a
//!    `rustion-required` policy, or `rustion-preferred` with a bastion;
//! 8. the rate and concurrency limits;
//! 9. the destination policy on every resolved address.
//!
//! Only then is the credential resolved (or the certificate minted), and the
//! session runs in its own task ([`session`]), so a request the MCP endpoint
//! times out still closes its connection and records its transcript.
//!
//! The protocol-neutral checks (steps 1-4, 6-9) are `agent_session`'s,
//! shared with the web route (`agent_web`).

use std::time::Duration;

use serde_json::{Map, Value};

// The refusal type is public here, where it has always been; the rest of
// the shared session code is crate-internal.
pub use crate::agent_session::SessionRefusal;
pub(crate) use crate::agent_session::{
    check_dispatch_and_binding, check_timeout, emit_refused, AgentCall, CallError, SessionTool,
};
use crate::{
    errors::RvError,
    kernel_api::mcp_sessions::{BrokeredSessionEnv, BrokeredSessionRuntime, BrokeredSessionSettings},
    logical::{Backend, McpBinding, Request, Response},
};

#[cfg(all(feature = "mcp_sessions_ssh", not(feature = "sync_handler")))]
pub mod exec;
#[cfg(all(feature = "mcp_sessions_ssh", not(feature = "sync_handler")))]
mod session;
#[cfg(all(feature = "mcp_sessions_ssh", not(feature = "sync_handler"), any(test, feature = "test-support")))]
pub mod test_server;

/// The MCP tool this route serves.
pub const SSH_EXEC_TOOL: &str = "bv_resource_ssh_exec";

/// The tool and protocol this route's refusal events name.
pub(crate) const SSH_TOOL: SessionTool = SessionTool { tool: SSH_EXEC_TOOL, protocol: "ssh" };

/// Budget for TCP connect, SSH handshake and authentication, inside the call
/// timeout (§5.3).
pub const CONNECT_BUDGET: Duration = Duration::from_secs(10);

/// Bytes read and discarded past the output cap before the channel is closed
/// (§5.3).
pub const DRAIN_LIMIT_BYTES: usize = 1 << 20;

/// How often a running session re-validates its token and the runtime
/// switch (shared by every protocol).
pub use crate::agent_session::REVALIDATE_EVERY;

/// Longest validity a brokered certificate may carry (§5.2).
pub const CERT_VALIDITY_SECS: u64 = 60;

/// Whether this build carries the SSH executor.
pub const SSH_EXECUTOR_COMPILED: bool = cfg!(all(feature = "mcp_sessions_ssh", not(feature = "sync_handler")));

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
                emit_refused(self.core.as_ref(), req, &call, SSH_TOOL, refusal.code).await;
                Err(refusal.into_error())
            }
            Err(CallError::Vault { reason, error }) => {
                emit_refused(self.core.as_ref(), req, &call, SSH_TOOL, reason).await;
                Err(error)
            }
            Err(CallError::Ended(refusal)) => Err(refusal.into_error()),
        }
    }

    async fn agent_ssh_exec(&self, req: &mut Request) -> Result<Map<String, Value>, CallError> {
        let binding = check_dispatch_and_binding(req)?;
        let command = check_command(req)?;
        let (env, settings, runtime) = crate::agent_session::check_switches(
            self.core.kernel().brokered_sessions(),
            "ssh",
            SSH_EXECUTOR_COMPILED,
            "mcp_sessions_ssh",
        )
        .await?;
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
