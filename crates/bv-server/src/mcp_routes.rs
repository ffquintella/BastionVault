//! MCP Access (`features/mcp-access.md`, Phase 3): the `/v2/mcp` transport.
//! `POST /v2/mcp/token` is routed to the ordinary logical path
//! `sys/mcp/token` (see `bv-kernel`'s `mcp.rs`), reusing
//! [`crate::handle_request`]. `POST /v2/mcp` speaks JSON-RPC and dispatches
//! through `bv-mcp`'s `Dispatcher`, fed a `bv_client::Backend` that calls
//! `Core::handle_request` directly (same shape as the GUI's
//! `EmbeddedBackend`, not reachable from this crate).
// source: features/mcp-access.md §5-6. Disclosed simplifications: the
// negotiated TLS key-exchange group is not carried from the TLS layer, so
// `require_hybrid_kex` cannot be verified and the route FAILS CLOSED when it
// is set (see `hybrid_kex_gate`) rather than ignoring it; the `requestState`
// HMAC key and single-use guard are process-local, not barrier-derived --
// still single-use and still expires, just not HA-shared.

use std::sync::{Arc, OnceLock};

use actix_web::{web, HttpRequest, HttpResponse};
use bv_client::{Backend, ClientError, JsonResponse, Operation as ClientOp};
use bv_mcp::{
    catalogue,
    dispatcher::{self, DispatchContext, PrincipalInfo},
    jsonrpc::{JsonRpcError, JsonRpcRequest, JsonRpcResponse, RequestMeta, MCP_PROTOCOL_VERSION},
    request_state::SingleUseGuard,
};
use serde_json::{json, Map, Value};

use crate::{
    config::McpConfig,
    core::Core,
    errors::RvError,
    get_token_from_req,
    logical::{Auth, McpBinding, Operation, Request},
    modules::auth::AuthModule,
    response_error, Connection, HttpError,
};

pub fn init_mcp_service(cfg: &mut web::ServiceConfig) {
    // Registered ahead of the `/v2/{path:.*}` logical catch-all (see
    // `init_service`) so these exact paths win.
    cfg.service(
        web::resource("/v2/mcp/token")
            .app_data(web::PayloadConfig::default().limit(default_max_request_bytes()))
            .route(web::post().to(mcp_token_exchange))
            .default_service(web::route().to(method_not_allowed)),
    );
    cfg.service(
        web::resource("/v2/mcp")
            .app_data(web::PayloadConfig::default().limit(default_max_request_bytes()))
            .route(web::post().to(mcp_dispatch))
            .default_service(web::route().to(method_not_allowed)),
    );
    cfg.service(
        web::resource("/.well-known/oauth-protected-resource/v2/mcp")
            .route(web::get().to(protected_resource_metadata)),
    );
}

async fn method_not_allowed() -> HttpResponse {
    response_error(actix_web::http::StatusCode::METHOD_NOT_ALLOWED, "")
}

fn default_max_request_bytes() -> usize {
    256 * 1024
}

const DEFAULT_TOOL_TIMEOUT_SECS: u64 = 30;

/// Spec §5 step 1: MCP carries login tokens and secret material, so it is
/// served over TLS, or over plaintext only on a loopback-only listener the
/// operator explicitly opted in for. Judged on the *listener* (`secure()`
/// and its bound address), never on `Forwarded`/`X-Forwarded-Proto`, which a
/// plaintext client could simply assert.
fn transport_gate(req: &HttpRequest, cfg: &McpConfig) -> Option<HttpResponse> {
    let app = req.app_config();
    if app.secure() || (cfg.allow_plaintext_loopback && app.local_addr().ip().is_loopback()) {
        return None;
    }
    Some(response_error(
        actix_web::http::StatusCode::SERVICE_UNAVAILABLE,
        "mcp_requires_tls: MCP is served over TLS only (or plaintext on a loopback-only listener with mcp.allow_plaintext_loopback = true)",
    ))
}

/// Spec §5 step 2. Enforcing `require_hybrid_kex` needs the negotiated
/// key-exchange group, which this build does not yet carry out of the TLS
/// layer. An operator who asked for the guarantee must not be silently served
/// without it, so the route refuses instead.
fn hybrid_kex_gate(cfg: &McpConfig) -> Option<HttpResponse> {
    cfg.require_hybrid_kex.then(|| {
        response_error(
            actix_web::http::StatusCode::SERVICE_UNAVAILABLE,
            "mcp_hybrid_kex_unverifiable: mcp.require_hybrid_kex is set but this build cannot verify the negotiated key exchange, so /v2/mcp is not served",
        )
    })
}

fn max_request_bytes(cfg: &McpConfig) -> usize {
    match cfg.max_request_bytes {
        0 => default_max_request_bytes(),
        n => n.min(default_max_request_bytes()),
    }
}

fn tool_timeout(cfg: &McpConfig) -> std::time::Duration {
    std::time::Duration::from_secs(match cfg.tool_timeout_secs {
        0 => DEFAULT_TOOL_TIMEOUT_SECS,
        n => n,
    })
}

async fn protected_resource_metadata(mcp_config: web::Data<McpConfig>) -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "resource": mcp_config.canonical_url,
        "authorization_servers": mcp_config.authorization_servers,
        "bearer_methods_supported": ["header"],
        "scopes_supported": Vec::<String>::new(),
    }))
}

/// `POST /v2/mcp/token` -- the exchange. See the module doc: an ordinary
/// logical write, so this handler is transport glue only.
async fn mcp_token_exchange(
    req: HttpRequest,
    body: web::Bytes,
    core: web::Data<Arc<Core>>,
    mcp_config: web::Data<McpConfig>,
) -> Result<HttpResponse, HttpError> {
    if !mcp_config.enabled {
        return Ok(response_error(actix_web::http::StatusCode::SERVICE_UNAVAILABLE, "MCP Access is not enabled"));
    }
    if let Some(refusal) = transport_gate(&req, &mcp_config) {
        return Ok(refusal);
    }
    let token = get_token_from_req(&req)?;
    let mut logical_req = Request::new("sys/mcp/token");
    logical_req.operation = Operation::Write;
    logical_req.client_token = token;
    if let Some(conn) = req.conn_data::<Connection>() {
        let req_conn = crate::logical::Connection { peer_addr: conn.peer.to_string(), ..Default::default() };
        logical_req.connection = Some(req_conn);
    }
    if !body.is_empty() {
        logical_req.body = Some(
            serde_json::from_slice::<Value>(&body)
                .map_err(|e| RvError::ErrResponse(format!("invalid JSON body: {e}")))?
                .as_object()
                .cloned()
                .ok_or_else(|| RvError::ErrResponse("body must be a JSON object".to_string()))?,
        );
    }
    crate::handle_request(core, &mut logical_req).await
}

/// The `requestState` HMAC key. Process-local -- see the module doc.
fn request_state_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let seed = uuid::Uuid::new_v4();
        *blake3::hash(seed.as_bytes()).as_bytes()
    })
}

fn single_use_guard() -> &'static SingleUseGuard {
    static GUARD: OnceLock<SingleUseGuard> = OnceLock::new();
    GUARD.get_or_init(SingleUseGuard::new)
}

/// The MCP-local, hash-derived accessor -- see `bv-kernel`'s `mcp.rs`
/// module doc for why this is not a general `TokenStore` accessor.
fn mcp_accessor(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

/// Adapts `Core::handle_request` to `bv_client::Backend`, in-process, no
/// HTTP hop -- modeled on `gui/src-tauri/src/backend.rs`'s
/// `EmbeddedBackend`, which is GUI-only and not reachable from here.
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
        let resp =
            self.core.handle_request(&mut req).await.map_err(|e| ClientError::backend(e.to_string()))?;
        Ok(resp.map(|r| JsonResponse { data: r.data, ..Default::default() }))
    }
}

/// `POST /v2/mcp` -- spec §5. Steps 1-3 (TLS/DoS gates) are the existing
/// listener config and `dos_middleware` (this route is not exempted from
/// it); this handler covers step 4 onward.
async fn mcp_dispatch(
    req: HttpRequest,
    body: web::Bytes,
    core: web::Data<Arc<Core>>,
    mcp_config: web::Data<McpConfig>,
) -> Result<HttpResponse, HttpError> {
    if !mcp_config.enabled {
        return Ok(response_error(actix_web::http::StatusCode::SERVICE_UNAVAILABLE, "MCP Access is not enabled"));
    }
    if let Some(refusal) = transport_gate(&req, &mcp_config) {
        return Ok(refusal);
    }
    if let Some(refusal) = hybrid_kex_gate(&mcp_config) {
        return Ok(refusal);
    }
    if body.len() > max_request_bytes(&mcp_config) {
        return Ok(response_error(actix_web::http::StatusCode::PAYLOAD_TOO_LARGE, "request body exceeds mcp.max_request_bytes"));
    }

    // Origin: absent, or must be in the allow-list (exact match).
    if let Some(origin) = req.headers().get(actix_web::http::header::ORIGIN).and_then(|v| v.to_str().ok()) {
        if !mcp_config.allowed_origins.iter().any(|o| o == origin) {
            return Ok(response_error(actix_web::http::StatusCode::FORBIDDEN, "origin not allowed"));
        }
    }

    // Bearer from the Authorization header only; the query string is
    // never inspected for a token, which is structural, not a filter.
    let Ok(token) = get_token_from_req(&req) else {
        return Ok(response_error(actix_web::http::StatusCode::UNAUTHORIZED, "missing bearer token"));
    };

    let rpc: JsonRpcRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return Ok(response_error(
                actix_web::http::StatusCode::BAD_REQUEST,
                &format!("invalid JSON-RPC body: {e}"),
            ))
        }
    };

    let meta: RequestMeta = rpc
        .params
        .get("_meta")
        .and_then(|m| serde_json::from_value(m.clone()).ok())
        .unwrap_or_default();
    if let Some(v) = &meta.protocol_version {
        if v != MCP_PROTOCOL_VERSION {
            return Ok(jsonrpc_error(
                rpc.id.clone(),
                bv_mcp::error::JSONRPC_UNSUPPORTED_PROTOCOL_VERSION,
                "unsupported protocol version",
            ));
        }
    }

    let client_ip = req.conn_data::<Connection>().map(|c| c.peer.to_string()).unwrap_or_default();
    let Some(auth) = check_mcp_token(&core, &token, &client_ip).await? else {
        return Ok(response_error(actix_web::http::StatusCode::UNAUTHORIZED, "invalid token"));
    };
    let Some(binding) = auth.mcp_binding.clone() else {
        return Ok(response_error(actix_web::http::StatusCode::UNAUTHORIZED, "token is not MCP-bound"));
    };

    let response = match rpc.method.as_str() {
        "server/discover" => JsonRpcResponse::success(
            rpc.id,
            json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "serverInfo": { "name": "bastionvault", "version": server_major_minor() },
            }),
        ),
        "tools/list" => {
            let mut list = catalogue::tools_list_json();
            list["ttlMs"] = json!(300_000);
            list["cacheScope"] = json!("private");
            JsonRpcResponse::success(rpc.id, list)
        }
        "tools/call" => {
            handle_tools_call(rpc.id.clone(), rpc.params, &core, &token, &binding, &meta, tool_timeout(&mcp_config))
                .await
        }
        other => JsonRpcResponse::failure(rpc.id, JsonRpcError::new(-32601, format!("method not found: {other}"))),
    };
    Ok(HttpResponse::Ok().json(response))
}

fn jsonrpc_error(id: Value, code: i64, message: &str) -> HttpResponse {
    HttpResponse::Ok().json(JsonRpcResponse::failure(id, JsonRpcError::new(code, message)))
}

fn server_major_minor() -> String {
    let full = env!("CARGO_PKG_VERSION");
    full.splitn(3, '.').take(2).collect::<Vec<_>>().join(".")
}

async fn handle_tools_call(
    id: Value,
    params: Value,
    core: &Arc<Core>,
    token: &str,
    binding: &McpBinding,
    meta: &RequestMeta,
    timeout: std::time::Duration,
) -> JsonRpcResponse {
    let tool = params.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
    let args = params.get("arguments").and_then(Value::as_object).cloned().unwrap_or_default();
    let confirmed_state = params.get("_meta").and_then(|m| m.get("requestState")).and_then(Value::as_str);

    let backend = InProcessMcpBackend { core: core.clone() };
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
        request_state_key: request_state_key(),
        single_use_guard: single_use_guard(),
    };

    let outcome = match tokio::time::timeout(timeout, dispatcher::call(&tool, args, confirmed_state, &ctx)).await {
        Ok(outcome) => outcome,
        Err(_) => {
            return JsonRpcResponse::failure(
                id,
                JsonRpcError::with_data_code(-32603, "the tool call exceeded mcp.tool_timeout_secs", "mcp_tool_timeout"),
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

async fn check_mcp_token(core: &Arc<Core>, token: &str, client_ip: &str) -> Result<Option<Auth>, HttpError> {
    let auth_module = core.module_manager().get_module::<AuthModule>("auth").ok_or(RvError::ErrPermissionDenied)?;
    let token_store = auth_module.token_store.load_full().ok_or(RvError::ErrPermissionDenied)?;
    Ok(token_store.check_token("mcp/dispatch", token, client_ip, true).await?)
}

#[cfg(test)]
mod tests {
    use actix_web::test::TestRequest;

    use super::*;

    fn plaintext_request() -> HttpRequest {
        // `TestRequest` builds a plaintext listener bound to 127.0.0.1.
        TestRequest::default().to_http_request()
    }

    #[test]
    fn plaintext_is_refused_unless_loopback_and_explicitly_allowed() {
        let req = plaintext_request();
        assert!(!req.app_config().secure(), "the fixture must be a plaintext listener");

        let refusal = transport_gate(&req, &McpConfig::default()).expect("plaintext is refused by default");
        assert_eq!(refusal.status(), actix_web::http::StatusCode::SERVICE_UNAVAILABLE);

        let allowed = McpConfig { allow_plaintext_loopback: true, ..Default::default() };
        assert!(transport_gate(&req, &allowed).is_none(), "explicit opt-in on a loopback listener is honoured");
    }

    #[test]
    fn a_forwarded_proto_header_cannot_talk_the_gate_into_serving_plaintext() {
        let req = TestRequest::default().insert_header(("X-Forwarded-Proto", "https")).to_http_request();
        assert!(transport_gate(&req, &McpConfig::default()).is_some());
    }

    #[test]
    fn require_hybrid_kex_fails_closed_until_the_group_can_be_verified() {
        assert!(hybrid_kex_gate(&McpConfig::default()).is_none());
        let refusal = hybrid_kex_gate(&McpConfig { require_hybrid_kex: true, ..Default::default() })
            .expect("a requirement that cannot be checked must not be silently dropped");
        assert_eq!(refusal.status(), actix_web::http::StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn body_cap_defaults_and_is_clamped_to_the_hard_ceiling() {
        let cap = |n| max_request_bytes(&McpConfig { max_request_bytes: n, ..Default::default() });
        assert_eq!(cap(0), default_max_request_bytes());
        assert_eq!(cap(1024), 1024);
        assert_eq!(cap(default_max_request_bytes() * 100), default_max_request_bytes());
    }

    #[test]
    fn tool_timeout_defaults_and_honours_config() {
        let t = |n| tool_timeout(&McpConfig { tool_timeout_secs: n, ..Default::default() });
        assert_eq!(t(0), std::time::Duration::from_secs(DEFAULT_TOOL_TIMEOUT_SECS));
        assert_eq!(t(5), std::time::Duration::from_secs(5));
    }
}
