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

use std::sync::Arc;
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
    logical::{Auth, McpBinding, Operation, Request},
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
        "tools/call" => handle_tools_call(ep, rpc.id.clone(), rpc.params, token, &binding, &meta).await,
        other => JsonRpcResponse::failure(rpc.id, JsonRpcError::new(-32601, format!("method not found: {other}"))),
    };
    Ok(McpEndpointOutcome::Answer(response))
}

async fn handle_tools_call(
    ep: &McpEndpoint<'_>,
    id: Value,
    params: Value,
    token: &str,
    binding: &McpBinding,
    meta: &RequestMeta,
) -> JsonRpcResponse {
    let tool = params.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
    let args = params.get("arguments").and_then(Value::as_object).cloned().unwrap_or_default();
    let confirmed_state = params.get("_meta").and_then(|m| m.get("requestState")).and_then(Value::as_str);

    let backend = InProcessMcpBackend { core: ep.core.clone() };
    let principal = PrincipalInfo {
        accessor: mcp_accessor(token),
        display_name: meta.client_info.as_ref().map(|c| c.name.clone()).unwrap_or_default(),
        policies: Vec::new(),
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

    let outcome =
        match tokio::time::timeout(ep.tool_timeout, dispatcher::call(&tool, args, confirmed_state, &ctx)).await {
            Ok(outcome) => outcome,
            Err(_) => {
                return JsonRpcResponse::failure(
                    id,
                    JsonRpcError::with_data_code(
                        -32603,
                        "the tool call exceeded mcp.tool_timeout_secs",
                        "mcp_tool_timeout",
                    ),
                )
            }
        };
    match outcome {
        Ok(result) => JsonRpcResponse::success(id, serde_json::to_value(result).unwrap_or(Value::Null)),
        Err(err) => {
            JsonRpcResponse::failure(id, JsonRpcError::with_data_code(err.jsonrpc_code(), err.to_string(), err.code()))
        }
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
        let resp = self.core.handle_request(&mut req).await.map_err(|e| ClientError::backend(e.to_string()))?;
        Ok(resp.map(|r| JsonResponse { data: r.data, ..Default::default() }))
    }
}
