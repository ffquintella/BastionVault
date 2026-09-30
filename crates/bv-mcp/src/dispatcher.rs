//! `tools/call` → gates → `bv_client::Backend` → result shaping. Spec §6.

use bv_client::{Backend, ClientError, Operation};
use bv_logical::McpBinding;
use serde_json::{Map, Value};

use crate::{
    catalogue::{self, ToolMeta},
    error::McpError,
    jsonrpc::CallToolResult,
    request_state::{self, RequestStatePayload, SingleUseGuard},
    sanitize::sanitize_for_model,
};

/// Non-secret facts about the calling principal, needed only to answer
/// `bv_whoami` without a routed request (spec §7: "answered from the token
/// entry, not by routing to `auth/token/lookup-self`").
pub struct PrincipalInfo {
    pub accessor: String,
    pub display_name: String,
    pub policies: Vec<String>,
}

/// Everything a single `tools/call` dispatch needs that isn't the tool name
/// and arguments.
pub struct DispatchContext<'a> {
    pub binding: &'a McpBinding,
    pub backend: &'a dyn Backend,
    pub token: &'a str,
    pub principal: &'a PrincipalInfo,
    /// Local-pairing-only per-call confirmation switches (Phase 4/5). An
    /// app-mode caller (Phase 1-3) passes `false` for both — "None at call
    /// time" per spec §3's principal table.
    pub confirm_reveal: bool,
    pub confirm_destructive: bool,
    pub request_state_key: &'a [u8],
    pub single_use_guard: &'a SingleUseGuard,
}

struct ToolRequest {
    operation: Operation,
    path: String,
    body: Option<Map<String, Value>>,
}

pub async fn call(
    tool: &str,
    args: Map<String, Value>,
    confirmed_state: Option<&str>,
    ctx: &DispatchContext<'_>,
) -> Result<CallToolResult, McpError> {
    let meta = catalogue::find(tool).ok_or_else(|| McpError::UnknownTool(tool.to_string()))?;
    check_tool_allowed(tool, ctx.binding)?;

    if tool == "bv_whoami" {
        return Ok(whoami_result(ctx.principal));
    }

    let req = build_tool_request(tool, &args)?;
    check_path_scope(&req.path, ctx.binding)?;

    // Destructiveness is a property of the tool itself (write/delete/issue),
    // not an opt-in request argument the way `reveal` is — a destructive
    // tool is refused outright unless the binding allows it.
    if meta.destructive {
        check_destructive_gate(meta.destructive, ctx.binding)?;
    }

    let reveal_requested = args.get("reveal").and_then(Value::as_bool).unwrap_or(false);
    if meta.is_reveal && reveal_requested {
        check_reveal_gate(meta.is_reveal, reveal_requested, ctx.binding)?;
    }

    // A tool can need both confirmations at once (`bv_pki_issue` is both
    // destructive and a reveal) — combine into a single MRTR round trip
    // rather than asking twice.
    let needs_reveal_confirm = meta.is_reveal && reveal_requested && ctx.confirm_reveal;
    let needs_destructive_confirm = meta.destructive && ctx.confirm_destructive;
    if needs_reveal_confirm || needs_destructive_confirm {
        let decision = match (needs_reveal_confirm, needs_destructive_confirm) {
            (true, true) => "reveal+destructive",
            (true, false) => "reveal",
            (false, true) => "destructive",
            (false, false) => unreachable!("guarded by the enclosing if"),
        };
        if let Some(result) = require_confirmation(tool, &args, decision, confirmed_state, ctx)? {
            return Ok(result);
        }
    }

    let response =
        ctx.backend.handle(req.operation, &req.path, req.body, ctx.token).await.map_err(map_backend_error)?;

    Ok(shape_result(meta, reveal_requested, response))
}

/// Runs the MRTR confirmation half of a gated call. `Ok(Some(result))`
/// means "return this `input_required` result to the caller now"; `Ok(None)`
/// means the confirmation was already presented and verified — proceed with
/// dispatch.
fn require_confirmation(
    tool: &str,
    args: &Map<String, Value>,
    decision: &str,
    confirmed_state: Option<&str>,
    ctx: &DispatchContext<'_>,
) -> Result<Option<CallToolResult>, McpError> {
    let args_hash = hash_args(args);
    match confirmed_state {
        None => {
            let payload = RequestStatePayload {
                token_accessor: ctx.principal.accessor.clone(),
                tool: tool.to_string(),
                args_hash,
                decision: decision.to_string(),
                exp: now_secs() + request_state::MAX_TTL_SECS,
            };
            let state = request_state::mint(&payload, ctx.request_state_key);
            Ok(Some(CallToolResult::input_required(format!("confirmation required for `{tool}`"), state)))
        }
        Some(state) => {
            let payload = request_state::verify(state, ctx.request_state_key)?;
            let matches = payload.token_accessor == ctx.principal.accessor
                && payload.tool == tool
                && payload.args_hash == args_hash
                && payload.decision == decision;
            if !matches || !ctx.single_use_guard.consume(&payload) {
                return Err(McpError::ConfirmationInvalid);
            }
            Ok(None)
        }
    }
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn hash_args(args: &Map<String, Value>) -> String {
    let bytes = serde_json::to_vec(args).unwrap_or_default();
    blake3::hash(&bytes).to_hex().to_string()
}

fn map_backend_error(err: ClientError) -> McpError {
    McpError::Backend(err.to_string())
}

fn whoami_result(principal: &PrincipalInfo) -> CallToolResult {
    let data = serde_json::json!({
        "accessor": principal.accessor,
        "display_name": sanitize_for_model(&principal.display_name),
        "policies": principal.policies,
    });
    let mut result = CallToolResult::text(format!("accessor: {}", principal.accessor));
    result.structured_content = Some(data);
    result
}

/// Redact a `tools/call` response's `data` before returning it: sanitize
/// every string leaf, and — unless `reveal` was both requested and
/// granted — replace the tool's declared secret-bearing fields with the
/// `<redacted>` sentinel (spec §6 "Result shaping").
fn shape_result(meta: &ToolMeta, reveal_requested: bool, response: Option<bv_client::JsonResponse>) -> CallToolResult {
    let mut data = response.and_then(|r| r.data).unwrap_or_default();
    if meta.is_reveal && !reveal_requested {
        redact_reveal_fields(&mut data);
    }
    sanitize_map(&mut data);
    let summary = format!("{} ok", meta.name);
    let mut result = CallToolResult::text(summary);
    result.structured_content = Some(Value::Object(data));
    result
}

/// The declared secret-bearing field names for the catalogue's reveal
/// tools. A field not in this list is assumed non-secret and passes
/// through unredacted even when `reveal` was not requested.
fn redact_reveal_fields(data: &mut Map<String, Value>) {
    for key in ["data", "plaintext", "code", "private_key"] {
        if data.contains_key(key) {
            data.insert(key.to_string(), Value::String("<redacted>".to_string()));
        }
    }
}

fn sanitize_map(map: &mut Map<String, Value>) {
    for (_, v) in map.iter_mut() {
        sanitize_value(v);
    }
}

fn sanitize_value(value: &mut Value) {
    match value {
        Value::String(s) => *s = sanitize_for_model(s),
        Value::Array(arr) => arr.iter_mut().for_each(sanitize_value),
        Value::Object(obj) => obj.iter_mut().for_each(|(_, v)| sanitize_value(v)),
        _ => {}
    }
}

fn check_tool_allowed(tool: &str, binding: &McpBinding) -> Result<(), McpError> {
    if binding.tool_allowlist.iter().any(|t| t == tool) {
        Ok(())
    } else {
        Err(McpError::ToolNotAllowed(tool.to_string()))
    }
}

/// Exact match or single trailing-`*` prefix on the pattern — spec §6
/// decision: intentionally minimal, defence in depth only. Real ACL under
/// `Core::handle_request` remains authoritative.
fn check_path_scope(path: &str, binding: &McpBinding) -> Result<(), McpError> {
    let in_scope = binding.path_scope.iter().any(|pattern| {
        if let Some(prefix) = pattern.strip_suffix('*') {
            path.starts_with(prefix)
        } else {
            path == pattern
        }
    });
    if in_scope {
        Ok(())
    } else {
        Err(McpError::PathOutOfScope(path.to_string()))
    }
}

fn check_reveal_gate(is_reveal_tool: bool, reveal_requested: bool, binding: &McpBinding) -> Result<(), McpError> {
    if is_reveal_tool && reveal_requested && !binding.reveal_allowed {
        return Err(McpError::RevealDenied);
    }
    Ok(())
}

pub(crate) fn check_destructive_gate(is_destructive_tool: bool, binding: &McpBinding) -> Result<(), McpError> {
    if is_destructive_tool && !binding.destructive_allowed {
        return Err(McpError::DestructiveDenied);
    }
    Ok(())
}

/// Normalize a caller-supplied path *component* before it is folded into a
/// request path: no `..`, no leading `/`, and it may not itself smuggle a
/// `sys/`/`auth/` prefix — those stay unreachable from any tool by
/// construction (spec §6).
fn normalize_component(raw: &str) -> Result<String, McpError> {
    if raw.contains("..") {
        return Err(McpError::InvalidArgument("path components may not contain `..`".into()));
    }
    let trimmed = raw.trim_start_matches('/');
    if trimmed.starts_with("sys/") || trimmed == "sys" || trimmed.starts_with("auth/") || trimmed == "auth" {
        return Err(McpError::PathOutOfScope(trimmed.to_string()));
    }
    if trimmed.is_empty() {
        return Err(McpError::InvalidArgument("path component must not be empty".into()));
    }
    Ok(trimmed.to_string())
}

fn arg_str<'a>(args: &'a Map<String, Value>, key: &str) -> Result<&'a str, McpError> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| McpError::InvalidArgument(format!("missing or non-string `{key}`")))
}

fn build_tool_request(tool: &str, args: &Map<String, Value>) -> Result<ToolRequest, McpError> {
    match tool {
        "bv_capabilities" => {
            let path = normalize_component(arg_str(args, "path")?)?;
            let mut body = Map::new();
            body.insert("path".into(), Value::String(path));
            Ok(ToolRequest { operation: Operation::Read, path: "sys/capabilities-self".to_string(), body: Some(body) })
        }
        "bv_kv_list" => {
            let mount = normalize_component(arg_str(args, "mount")?)?;
            let path = normalize_component(arg_str(args, "path")?)?;
            Ok(ToolRequest { operation: Operation::List, path: format!("{mount}/metadata/{path}"), body: None })
        }
        "bv_kv_read_metadata" => {
            let mount = normalize_component(arg_str(args, "mount")?)?;
            let path = normalize_component(arg_str(args, "path")?)?;
            Ok(ToolRequest { operation: Operation::Read, path: format!("{mount}/metadata/{path}"), body: None })
        }
        "bv_kv_read" => {
            let mount = normalize_component(arg_str(args, "mount")?)?;
            let path = normalize_component(arg_str(args, "path")?)?;
            Ok(ToolRequest { operation: Operation::Read, path: format!("{mount}/data/{path}"), body: None })
        }
        "bv_resource_list" => {
            let path = normalize_component(arg_str(args, "path")?)?;
            Ok(ToolRequest { operation: Operation::List, path: format!("resource/{path}"), body: None })
        }
        "bv_resource_describe" => {
            let path = normalize_component(arg_str(args, "path")?)?;
            Ok(ToolRequest { operation: Operation::Read, path: format!("resource/{path}"), body: None })
        }
        "bv_transit_encrypt" => {
            let key = normalize_component(arg_str(args, "key")?)?;
            let mut body = Map::new();
            body.insert("plaintext".into(), Value::String(arg_str(args, "plaintext")?.to_string()));
            if let Some(ctx) = args.get("context").and_then(Value::as_str) {
                body.insert("context".into(), Value::String(ctx.to_string()));
            }
            Ok(ToolRequest { operation: Operation::Write, path: format!("transit/encrypt/{key}"), body: Some(body) })
        }
        "bv_transit_decrypt" => {
            let key = normalize_component(arg_str(args, "key")?)?;
            let mut body = Map::new();
            body.insert("ciphertext".into(), Value::String(arg_str(args, "ciphertext")?.to_string()));
            Ok(ToolRequest { operation: Operation::Write, path: format!("transit/decrypt/{key}"), body: Some(body) })
        }
        "bv_transit_sign" => {
            let key = normalize_component(arg_str(args, "key")?)?;
            let mut body = Map::new();
            body.insert("input".into(), Value::String(arg_str(args, "input")?.to_string()));
            Ok(ToolRequest { operation: Operation::Write, path: format!("transit/sign/{key}"), body: Some(body) })
        }
        "bv_transit_verify" => {
            let key = normalize_component(arg_str(args, "key")?)?;
            let mut body = Map::new();
            body.insert("input".into(), Value::String(arg_str(args, "input")?.to_string()));
            body.insert("signature".into(), Value::String(arg_str(args, "signature")?.to_string()));
            Ok(ToolRequest { operation: Operation::Write, path: format!("transit/verify/{key}"), body: Some(body) })
        }
        "bv_totp_code" => {
            let name = normalize_component(arg_str(args, "name")?)?;
            Ok(ToolRequest { operation: Operation::Read, path: format!("totp/code/{name}"), body: None })
        }
        "bv_pki_list_certs" => {
            Ok(ToolRequest { operation: Operation::List, path: "pki/certs".to_string(), body: None })
        }
        "bv_pki_read_cert" => {
            let serial = normalize_component(arg_str(args, "serial")?)?;
            Ok(ToolRequest { operation: Operation::Read, path: format!("pki/cert/{serial}"), body: None })
        }
        "bv_kv_write" => {
            let mount = normalize_component(arg_str(args, "mount")?)?;
            let path = normalize_component(arg_str(args, "path")?)?;
            let data = args
                .get("data")
                .and_then(Value::as_object)
                .cloned()
                .ok_or_else(|| McpError::InvalidArgument("missing or non-object `data`".into()))?;
            let mut body = Map::new();
            body.insert("data".into(), Value::Object(data));
            Ok(ToolRequest { operation: Operation::Write, path: format!("{mount}/data/{path}"), body: Some(body) })
        }
        "bv_kv_delete" => {
            let mount = normalize_component(arg_str(args, "mount")?)?;
            let path = normalize_component(arg_str(args, "path")?)?;
            // Soft-delete only — the current version's data endpoint, never
            // `metadata` (which would also erase version history).
            Ok(ToolRequest { operation: Operation::Delete, path: format!("{mount}/data/{path}"), body: None })
        }
        "bv_pki_issue" => {
            let role = normalize_component(arg_str(args, "role")?)?;
            let common_name = arg_str(args, "common_name")?;
            let mut body = Map::new();
            body.insert("common_name".into(), Value::String(common_name.to_string()));
            if let Some(ttl) = args.get("ttl").and_then(Value::as_str) {
                body.insert("ttl".into(), Value::String(ttl.to_string()));
            }
            if let Some(alt_names) = args.get("alt_names").and_then(Value::as_str) {
                body.insert("alt_names".into(), Value::String(alt_names.to_string()));
            }
            Ok(ToolRequest { operation: Operation::Write, path: format!("pki/issue/{role}"), body: Some(body) })
        }
        "bv_ssh_sign" => {
            let role = normalize_component(arg_str(args, "role")?)?;
            let public_key = arg_str(args, "public_key")?;
            let mut body = Map::new();
            body.insert("public_key".into(), Value::String(public_key.to_string()));
            if let Some(principals) = args.get("valid_principals").and_then(Value::as_str) {
                body.insert("valid_principals".into(), Value::String(principals.to_string()));
            }
            Ok(ToolRequest { operation: Operation::Write, path: format!("ssh/sign/{role}"), body: Some(body) })
        }
        other => Err(McpError::UnknownTool(other.to_string())),
    }
}
