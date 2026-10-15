//! The MCP endpoint's JSON-RPC handling, in process (`features/mcp-access.md`
//! §5). What `POST /v2/mcp` does once its transport gates have passed --
//! parse the request, check the protocol revision, authenticate the bearer
//! as an MCP-bound token, then answer `server/discover`, `tools/list` or a
//! `tools/call` through `bv-mcp`'s dispatcher -- with no HTTP in it.
//!
//! Two callers, one implementation: `bv-server`'s `/v2/mcp` route, after its
//! TLS, size, origin and bearer-extraction gates; and the desktop app's local
//! MCP server when its vault is embedded, where there is no HTTP listener to
//! forward to. Keeping it here means an embedded vault answers an assistant
//! exactly as a remote one does, gate for gate.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bv_client::{Backend, ClientError, JsonResponse, Operation as ClientOp};
use bv_mcp::{
    catalogue,
    dispatcher::{self, DispatchContext, PrincipalInfo},
    jsonrpc::{JsonRpcError, JsonRpcRequest, JsonRpcResponse, RequestMeta, MCP_PROTOCOL_VERSION},
    request_state::SingleUseGuard,
};
use serde_json::{json, Map, Value};

use crate::{
    core::Core,
    errors::RvError,
    kernel_api::mcp_events::{self, AgentRefused},
    logical::{is_open_world_mcp_tool, Auth, McpAuditContext, McpBinding, McpBindingKind, Operation, Request},
    modules::auth::AuthModule,
};

/// Everything a call needs besides the request itself.
pub struct McpEndpoint<'a> {
    pub core: &'a Arc<Core>,
    /// The caller's address, for CIDR-bound tokens. Empty when there is no
    /// network peer (in process), which refuses a CIDR-bound token rather
    /// than inventing an address for it.
    pub client_ip: &'a str,
    pub tool_timeout: Duration,
    /// `major.minor` reported by `server/discover`.
    pub server_version: &'a str,
    /// Keys the `requestState` HMAC. Process-local in both callers.
    pub request_state_key: &'a [u8],
    pub single_use_guard: &'a SingleUseGuard,
}

/// What the transport answers with.
#[derive(Debug)]
pub enum McpEndpointOutcome {
    /// A JSON-RPC answer (success or a JSON-RPC error), sent as-is.
    Answer(JsonRpcResponse),
    /// The body is not a JSON-RPC request (HTTP 400).
    BadRequest(String),
    /// The bearer is not a live MCP-bound token (HTTP 401).
    Unauthorized(&'static str),
}

/// Answers one JSON-RPC request carried by `body`, authenticated by
/// `token`. An `Err` is an internal failure (no auth module, a token-store
/// error), which a caller surfaces as it surfaces any other vault error.
pub async fn handle_jsonrpc(ep: &McpEndpoint<'_>, token: &str, body: &[u8]) -> Result<McpEndpointOutcome, RvError> {
    let rpc: JsonRpcRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return Ok(McpEndpointOutcome::BadRequest(format!("invalid JSON-RPC body: {e}"))),
    };

    let meta: RequestMeta =
        rpc.params.get("_meta").and_then(|m| serde_json::from_value(m.clone()).ok()).unwrap_or_default();
    if let Some(v) = &meta.protocol_version {
        if v != MCP_PROTOCOL_VERSION {
            return Ok(McpEndpointOutcome::Answer(JsonRpcResponse::failure(
                rpc.id,
                JsonRpcError::new(bv_mcp::error::JSONRPC_UNSUPPORTED_PROTOCOL_VERSION, "unsupported protocol version"),
            )));
        }
    }

    let Some(auth) = check_mcp_token(ep.core, token, ep.client_ip).await? else {
        return Ok(McpEndpointOutcome::Unauthorized("invalid token"));
    };
    let Some(binding) = auth.mcp_binding.clone() else {
        return Ok(McpEndpointOutcome::Unauthorized("token is not MCP-bound"));
    };

    let response = match rpc.method.as_str() {
        "server/discover" => JsonRpcResponse::success(
            rpc.id,
            json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "serverInfo": { "name": "bastionvault", "version": ep.server_version },
            }),
        ),
        "tools/list" => {
            let mut list = catalogue::tools_list_json();
            list["ttlMs"] = json!(300_000);
            list["cacheScope"] = json!("private");
            JsonRpcResponse::success(rpc.id, list)
        }
        "tools/call" => handle_tools_call(ep, rpc.id.clone(), rpc.params, token, &auth, &binding, &meta).await,
        other => JsonRpcResponse::failure(rpc.id, JsonRpcError::new(-32601, format!("method not found: {other}"))),
    };
    Ok(McpEndpointOutcome::Answer(response))
}

async fn handle_tools_call(
    ep: &McpEndpoint<'_>,
    id: Value,
    params: Value,
    token: &str,
    auth: &Auth,
    binding: &McpBinding,
    meta: &RequestMeta,
) -> JsonRpcResponse {
    let tool = params.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
    let args = params.get("arguments").and_then(Value::as_object).cloned().unwrap_or_default();
    let confirmed_state = params.get("_meta").and_then(|m| m.get("requestState")).and_then(Value::as_str);

    let mcp_audit = mcp_audit_context(ep, &tool, &args, binding, params.get("_meta"));
    // The dispatcher consumes the arguments; a session tool's refusal event
    // names the resource and profile they gave.
    let session_args = is_open_world_mcp_tool(&tool).then(|| args.clone());
    let backend = InProcessMcpBackend { core: ep.core.clone(), mcp_audit };
    let principal = PrincipalInfo {
        accessor: mcp_accessor(token),
        display_name: meta.client_info.as_ref().map(|c| c.name.clone()).unwrap_or_default(),
        // The token entry's own policies, which are what the ACL evaluates
        // every routed call against.
        policies: auth.policies.clone(),
    };
    let ctx = DispatchContext {
        binding,
        backend: &backend,
        token,
        principal: &principal,
        confirm_reveal: false,
        confirm_destructive: false,
        request_state_key: ep.request_state_key,
        single_use_guard: ep.single_use_guard,
    };

    let timeout = if session_args.is_some() { session_call_timeout(ep.core) } else { ep.tool_timeout };
    let outcome = match tokio::time::timeout(timeout, dispatcher::call(&tool, args, confirmed_state, &ctx)).await {
        Ok(outcome) => outcome,
        Err(_) => {
            let message = if session_args.is_some() {
                "the session call exceeded mcp.brokered_sessions.call_timeout_secs"
            } else {
                "the tool call exceeded mcp.tool_timeout_secs"
            };
            return JsonRpcResponse::failure(id, JsonRpcError::with_data_code(-32603, message, "mcp_tool_timeout"));
        }
    };
    match outcome {
        Ok(result) => JsonRpcResponse::success(id, serde_json::to_value(result).unwrap_or(Value::Null)),
        Err(err) => {
            if let Some(args) = session_args.as_ref().filter(|_| refused_before_routing(&err)) {
                audit_session_refusal(ep.core, token, auth, binding, &tool, args, err.code()).await;
            }
            JsonRpcResponse::failure(id, JsonRpcError::with_data_code(err.jsonrpc_code(), err.to_string(), err.code()))
        }
    }
}

/// The `request.mcp` audit block for one `tools/call`
/// (`features/mcp-access.md` §10; the slice `features/mcp-brokered-sessions.md`
/// §10 assigns to Phase 1). Set on every request the call routes, so the
/// standard audit entry says which binding, client and tool it was for.
///
/// `decision` is `allowed`: the block only reaches the audit log on a routed
/// request, which the dispatcher's gates have passed. `transport` is what the
/// vault can see — `http` from `bv-server`'s route, `in-process` from an
/// embedded vault (the transport with no network peer, `client_ip` empty);
/// how the local gatekeeper was reached is not visible here.
fn mcp_audit_context(
    ep: &McpEndpoint<'_>,
    tool: &str,
    args: &Map<String, Value>,
    binding: &McpBinding,
    meta: Option<&Value>,
) -> McpAuditContext {
    static CATALOGUE_HASH: OnceLock<String> = OnceLock::new();
    let (kind, name) = match &binding.kind {
        McpBindingKind::App(name) => ("app", name.clone()),
        McpBindingKind::Pairing(id) => ("pairing", id.clone()),
    };
    let meta_tool = catalogue::find(tool);
    let reveal_requested =
        meta_tool.is_some_and(|m| m.is_reveal) && args.get("reveal").and_then(Value::as_bool).unwrap_or(false);
    let confirmation = bv_mcp::jsonrpc::operator_confirmation(meta);
    McpAuditContext {
        kind: kind.to_string(),
        name,
        client_name: binding.client_name.clone(),
        client_version: binding.client_version.clone(),
        transport: if ep.client_ip.is_empty() { "in-process" } else { "http" }.to_string(),
        tool: tool.to_string(),
        catalogue_hash: CATALOGUE_HASH.get_or_init(catalogue::catalogue_hash).clone(),
        args_hash: dispatcher::args_hash(args),
        reveal_requested,
        reveal_granted: reveal_requested && binding.reveal_allowed,
        destructive: meta_tool.is_some_and(|m| m.destructive),
        confirmed_by_operator: confirmation.is_some(),
        operator_confirmation: confirmation.map(|_| "asserted-by-local-host".to_string()),
        decision: "allowed".to_string(),
        waived: binding.waived_until.is_some(),
        ..Default::default()
    }
}

/// Margin past a session's own call timeout before the endpoint gives up on
/// it. The session handler bounds the session itself (connect included) and
/// then records its transcript and events; this lets it answer `timed_out`
/// rather than be cut off (`features/mcp-brokered-sessions.md` §11). A
/// session the endpoint does drop still finishes in its own task.
const SESSION_RESPONSE_MARGIN_SECS: u64 = 10;

/// A session tool's endpoint timeout: `mcp.brokered_sessions.call_timeout_secs`
/// (as the registered session environment reports it) plus the margin, in
/// place of `mcp.tool_timeout_secs`.
fn session_call_timeout(core: &Arc<Core>) -> Duration {
    let call_timeout = core
        .kernel_services
        .brokered_sessions()
        .map(|env| env.settings().call_timeout_secs)
        .unwrap_or(core.mcp_brokered_sessions.call_timeout_secs);
    Duration::from_secs(call_timeout.saturating_add(SESSION_RESPONSE_MARGIN_SECS))
}

/// Whether the dispatcher refused the call itself, before anything was
/// routed. A refusal from the session handler underneath arrives as a
/// backend or session error and is audited there, with its own code.
fn refused_before_routing(err: &bv_mcp::McpError) -> bool {
    !matches!(
        err,
        bv_mcp::McpError::Backend(_) | bv_mcp::McpError::ResultTooLarge { .. } | bv_mcp::McpError::Session { .. }
    )
}

/// `connect.agent.refused` for a session tool the dispatcher refused
/// (`features/mcp-brokered-sessions.md` §10): no connect grant, an app
/// binding, a path out of scope, an invalid argument. The resource and
/// profile are the call's own arguments, bounded; the event is best effort,
/// since the call is refused whatever happens to it.
async fn audit_session_refusal(
    core: &Arc<Core>,
    token: &str,
    auth: &Auth,
    binding: &McpBinding,
    tool: &str,
    args: &Map<String, Value>,
    code: &str,
) {
    let protocol = match tool {
        "bv_resource_ssh_exec" => "ssh",
        "bv_resource_web_fetch" => "web",
        "bv_resource_rdp_act" => "rdp",
        _ => "unknown",
    };
    let arg = |key: &str| args.get(key).and_then(Value::as_str).map(mcp_events::bounded_arg);
    let event = AgentRefused {
        reason: code.to_string(),
        tool: tool.to_string(),
        protocol: protocol.to_string(),
        resource: arg("resource"),
        profile_id: arg("profile"),
        operator: binding.operator.clone(),
        pairing_id: match &binding.kind {
            McpBindingKind::Pairing(id) => Some(id.clone()),
            McpBindingKind::App(_) => None,
        },
        client_name: binding.client_name.clone(),
    };
    let mut who = Request::new("mcp/dispatch");
    who.client_token = token.to_string();
    who.auth = Some(auth.clone());
    if let Err(e) = mcp_events::emit(core.as_ref(), &event, Some(&who)).await {
        log::warn!(target: "security", "connect.agent.refused could not be written to the audit log: {e}");
    }
}

async fn check_mcp_token(core: &Arc<Core>, token: &str, client_ip: &str) -> Result<Option<Auth>, RvError> {
    let auth_module = core.module_manager().get_module::<AuthModule>("auth").ok_or(RvError::ErrPermissionDenied)?;
    let token_store = auth_module.token_store.load_full().ok_or(RvError::ErrPermissionDenied)?;
    token_store.check_token("mcp/dispatch", token, client_ip, true).await
}

/// The MCP-local, hash-derived accessor -- see `bv-kernel`'s `mcp.rs`
/// module doc for why this is not a general `TokenStore` accessor.
fn mcp_accessor(token: &str) -> String {
    bv_mcp::pairing::hash_token(token)
}

/// Adapts `Core::handle_request` to `bv_client::Backend`, in-process, no
/// HTTP hop.
struct InProcessMcpBackend {
    core: Arc<Core>,
    /// Stamped on every request this call routes (`Request::mcp_audit`).
    mcp_audit: McpAuditContext,
}

#[async_trait::async_trait]
impl Backend for InProcessMcpBackend {
    async fn handle(
        &self,
        operation: ClientOp,
        path: &str,
        body: Option<Map<String, Value>>,
        token: &str,
    ) -> Result<Option<JsonResponse>, ClientError> {
        let mut req = Request::new(path);
        req.operation = match operation {
            ClientOp::Read => Operation::Read,
            ClientOp::Write => Operation::Write,
            ClientOp::Delete => Operation::Delete,
            ClientOp::List => Operation::List,
        };
        req.client_token = token.to_string();
        req.body = body;
        // The token this call carries is MCP-bound; `pre_route`'s
        // `check_token` must be told so via `Request::mcp_dispatch`, or its
        // MCP-origin gate refuses the very token this whole path exists to
        // dispatch. See that field's doc.
        req.mcp_dispatch = true;
        req.mcp_audit = Some(self.mcp_audit.clone());
        let resp = self.core.handle_request(&mut req).await.map_err(|e| ClientError::backend(e.to_string()))?;
        Ok(resp.map(|r| JsonResponse { data: r.data, ..Default::default() }))
    }
}
