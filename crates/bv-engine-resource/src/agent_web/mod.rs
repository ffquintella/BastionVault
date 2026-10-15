//! `resources/v2/connect/agent/web/fetch`: the handler behind the MCP tool
//! `bv_resource_web_fetch` (`features/mcp-brokered-sessions.md` §3, §6,
//! §10-11).
//!
//! One call is one fetch: authorized, dialed, answered, closed, audited and
//! transcribed, from the vault process. The vault logs in (when the profile
//! is `http-auth`) and returns page text; it never hands back a session — no
//! cookie, no `Set-Cookie`, no `Authorization`, no `Location`, no session
//! URL. The credential is resolved here and used here only, and only in
//! answer to the target's own challenge.
//!
//! **The authorization chain** is the SSH route's (`agent_ssh`, through
//! `agent_session`), with the web specifics:
//!
//! 1. routed by the MCP dispatcher, for a confirmed pairing with
//!    `connect_allowed`;
//! 2. the method (`GET`/`HEAD`) and the path, re-checked with the
//!    dispatcher's own rules (§6.3 "Path rules");
//! 3. the switches, `web` listed, and the executor compiled in
//!    (`mcp_sessions_web`);
//! 4. the `connect` gate on `resources/secrets/<name>/`;
//! 5. the type's and the profile's opt-ins, and the profile's static
//!    requirements: `open` or `http-auth` (`form` and `sso` are refused with
//!    `mcp_web_login_mode_unsupported`), https only, a stored `secret` for
//!    `http-auth`;
//! 6. the operator's MFA ticket for this exact call, when the profile is
//!    gated;
//! 7. no bastion route bypassed (`rustion` profile, `rustion-isolated`
//!    transport, a Rustion policy);
//! 8. rate and concurrency;
//! 9. the destination policy on the start origin — and again on every
//!    redirect hop, inside the executor.

use std::time::Duration;

use serde_json::{Map, Value};

use crate::{
    agent_session::{
        check_dispatch_and_binding, check_switches, check_timeout, emit_refused, AgentCall, CallError, SessionRefusal,
        SessionTool,
    },
    errors::RvError,
    kernel_api::mcp_sessions::{BrokeredSessionEnv, BrokeredSessionRuntime, BrokeredSessionSettings},
    logical::{Backend, McpBinding, Request, Response},
};

#[cfg(all(feature = "mcp_sessions_web", not(feature = "sync_handler")))]
mod cookies;
#[cfg(all(feature = "mcp_sessions_web", not(feature = "sync_handler")))]
mod fetch;
#[cfg(all(feature = "mcp_sessions_web", not(feature = "sync_handler")))]
mod html;
#[cfg(all(feature = "mcp_sessions_web", not(feature = "sync_handler")))]
mod profile;
#[cfg(all(feature = "mcp_sessions_web", not(feature = "sync_handler")))]
mod session;
#[cfg(all(feature = "mcp_sessions_web", not(feature = "sync_handler"), any(test, feature = "test-support")))]
pub mod test_server;
#[cfg(all(feature = "mcp_sessions_web", not(feature = "sync_handler")))]
mod tls;

/// The MCP tool this route serves.
pub const WEB_FETCH_TOOL: &str = "bv_resource_web_fetch";

/// The tool and protocol this route's refusal events name.
pub(crate) const WEB_TOOL: SessionTool = SessionTool { tool: WEB_FETCH_TOOL, protocol: "web" };

/// Budget for resolving, connecting and the TLS handshake of one request,
/// inside the call timeout.
pub const CONNECT_BUDGET: Duration = Duration::from_secs(10);

/// Raw response body read, at most (§11 "Limits": 2 MiB, also the ceiling).
/// Past it the connection is dropped and the result says `truncated`.
pub const MAX_RAW_BODY_BYTES: usize = 2 << 20;

/// Redirects followed, at most (§6.3), each only to an origin the profile
/// allows and each re-checked against the destination policy.
pub const MAX_REDIRECTS: usize = 5;

/// Whether this build carries the web executor.
pub const WEB_EXECUTOR_COMPILED: bool = cfg!(all(feature = "mcp_sessions_web", not(feature = "sync_handler")));

/// The confirmed method and path, re-validated exactly as the dispatcher
/// validated them (§6.3): the handler does not trust that it was. Returns
/// `(method, path)`.
pub(crate) fn check_request_line(req: &Request) -> Result<(String, String), SessionRefusal> {
    let field = |key: &str| req.get_data(key).ok().and_then(|v| v.as_str().map(str::to_string));
    validate_request_line(field("method").as_deref(), field("path").as_deref())
}

fn validate_request_line(method: Option<&str>, path: Option<&str>) -> Result<(String, String), SessionRefusal> {
    let invalid = |m: String| SessionRefusal::new("mcp_invalid_argument", 400, m);
    let method = method.ok_or_else(|| invalid("`method` is required".into()))?;
    bv_mcp::dispatcher::check_web_method(method).map_err(invalid)?;
    let path = path.ok_or_else(|| invalid("`path` is required".into()))?;
    bv_mcp::dispatcher::check_web_path(path).map_err(invalid)?;
    Ok((method.to_string(), path.to_string()))
}

#[maybe_async::maybe_async]
impl super::ResourceBackendInner {
    /// `POST resources/v2/connect/agent/web/fetch`.
    pub async fn handle_agent_web_fetch(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let call = AgentCall::from_request(req);
        match self.agent_web_fetch(req).await {
            Ok(data) => Ok(Some(Response::data_response(Some(data)))),
            Err(CallError::Refused(refusal)) => {
                emit_refused(self.core.as_ref(), req, &call, WEB_TOOL, refusal.code).await;
                Err(refusal.into_error())
            }
            Err(CallError::Vault { reason, error }) => {
                emit_refused(self.core.as_ref(), req, &call, WEB_TOOL, reason).await;
                Err(error)
            }
            Err(CallError::Ended(refusal)) => Err(refusal.into_error()),
        }
    }

    async fn agent_web_fetch(&self, req: &mut Request) -> Result<Map<String, Value>, CallError> {
        let binding = check_dispatch_and_binding(req)?;
        let (method, path) = check_request_line(req)?;
        let (env, settings, runtime) =
            check_switches(self.core.kernel().brokered_sessions(), "web", WEB_EXECUTOR_COMPILED, "mcp_sessions_web")
                .await?;
        let timeout_secs = check_timeout(req, &settings)?;
        let gated = WebGated { binding, method, path, env, settings, runtime, timeout_secs };
        self.run_web_gated(req, gated).await
    }

    /// Steps 4-9 and the fetch itself ([`session`]).
    #[cfg(all(feature = "mcp_sessions_web", not(feature = "sync_handler")))]
    async fn run_web_gated(&self, req: &mut Request, gated: WebGated) -> Result<Map<String, Value>, CallError> {
        session::prepare_and_run(self, req, gated).await
    }

    /// A build without the executor: `check_switches` has already refused,
    /// so this is never reached; it refuses the same way regardless.
    #[cfg(not(all(feature = "mcp_sessions_web", not(feature = "sync_handler"))))]
    async fn run_web_gated(&self, _req: &mut Request, _gated: WebGated) -> Result<Map<String, Value>, CallError> {
        Err(CallError::Refused(SessionRefusal::new(
            "mcp_session_protocol_disabled",
            403,
            "this build has no web session executor (cargo feature mcp_sessions_web)",
        )))
    }
}

/// What steps 1-3 established.
#[cfg_attr(not(all(feature = "mcp_sessions_web", not(feature = "sync_handler"))), allow(dead_code))]
pub(crate) struct WebGated {
    pub binding: McpBinding,
    /// `GET` or `HEAD`.
    pub method: String,
    /// The confirmed origin-relative path, with its query.
    pub path: String,
    pub env: std::sync::Arc<dyn BrokeredSessionEnv>,
    pub settings: BrokeredSessionSettings,
    pub runtime: BrokeredSessionRuntime,
    pub timeout_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The handler refuses what the dispatcher refuses, by the same code:
    /// a request that did not come through the dispatcher's validation is
    /// still held to it.
    #[test]
    fn the_request_line_is_rechecked_with_the_dispatchers_rules() {
        assert_eq!(validate_request_line(Some("GET"), Some("/api?x=1")).unwrap(), ("GET".into(), "/api?x=1".into()));
        assert_eq!(validate_request_line(Some("HEAD"), Some("/")).unwrap().0, "HEAD");
        for (m, p) in [
            (Some("POST"), Some("/")),
            (None, Some("/")),
            (Some("GET"), None),
            (Some("GET"), Some("https://evil/")),
            (Some("GET"), Some("//evil/")),
            (Some("GET"), Some("/a/%2e%2e/b")),
            (Some("GET"), Some("/a#frag")),
        ] {
            assert_eq!(validate_request_line(m, p).unwrap_err().code, "mcp_invalid_argument", "{m:?} {p:?}");
        }
    }
}
