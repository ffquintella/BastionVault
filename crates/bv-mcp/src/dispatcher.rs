//! `tools/call` → gates → `bv_client::Backend` → result shaping. Spec §6.

use bv_client::{Backend, ClientError, Operation};
use bv_logical::{McpBinding, McpBindingKind};
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
    /// The path the grant's `path_scope` must cover when it is not `path`
    /// itself. Only `bv_capabilities` sets it: its endpoint is always
    /// `sys/capabilities-self`, and scoping that would make the tool usable
    /// only by a grant naming a `sys/` path -- and then for every path.
    scope_subject: Option<String>,
}

impl ToolRequest {
    fn scope_subject(&self) -> &str {
        self.scope_subject.as_deref().unwrap_or(&self.path)
    }
}

pub async fn call(
    tool: &str,
    args: Map<String, Value>,
    confirmed_state: Option<&str>,
    ctx: &DispatchContext<'_>,
) -> Result<CallToolResult, McpError> {
    let meta = catalogue::find(tool).ok_or_else(|| McpError::UnknownTool(tool.to_string()))?;
    dispatch(meta, args, confirmed_state, ctx).await
}

/// [`call`] once the tool's catalogue entry is known. Separate so the gate
/// order can be tested against an entry that is not (yet) in the catalogue,
/// such as an open-world tool before its phase ships.
pub(crate) async fn dispatch(
    meta: &ToolMeta,
    args: Map<String, Value>,
    confirmed_state: Option<&str>,
    ctx: &DispatchContext<'_>,
) -> Result<CallToolResult, McpError> {
    let tool = meta.name;
    check_tool_allowed(tool, ctx.binding)?;
    // Before any argument is looked at: a binding that may not open
    // sessions learns nothing more from a session tool than that.
    if meta.open_world {
        check_open_world_gate(ctx.binding)?;
    }

    if tool == "bv_whoami" {
        return Ok(whoami_result(ctx.principal));
    }

    let req = build_tool_request(tool, &args)?;
    check_path_scope(req.scope_subject(), ctx.binding)?;

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
    let args_hash = args_hash(args);
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

/// BLAKE3 over the `serde_json` bytes of a call's `arguments`, hex-encoded.
///
/// Public because two parties must compute it identically: the dispatcher
/// binds an MRTR `requestState` to it, and the local gatekeeper binds an
/// operator's connect MFA ticket to it (`features/mcp-brokered-sessions.md`
/// §3.1). Key order is stable because no crate in this workspace enables
/// `serde_json`'s `preserve_order` (see the note on `catalogue_hash`). A map
/// that cannot serialize hashes the empty input rather than panicking; such a
/// map cannot have come from a parsed JSON-RPC request.
pub fn args_hash(args: &Map<String, Value>) -> String {
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

/// The connect gate for open-world (session) tools,
/// `features/mcp-brokered-sessions.md` §3 step 2, in the spec's order:
///
/// 1. `connect_allowed`, and with it `confirm_connect` — a binding claiming
///    the first without the second is not one the exchange mints, so it is
///    refused as not allowed rather than trusted;
/// 2. the binding is a local pairing. An app binding is refused whatever it
///    claims: network-mode apps never open sessions, permanently.
///
/// The session handler re-checks all three as defence in depth.
pub(crate) fn check_open_world_gate(binding: &McpBinding) -> Result<(), McpError> {
    if !binding.connect_allowed || !binding.confirm_connect {
        return Err(McpError::ConnectNotAllowed);
    }
    if !matches!(binding.kind, McpBindingKind::Pairing(_)) {
        return Err(McpError::ConnectRequiresLocalOperator);
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

/// KV v2 lists only a directory: `metadata/` for the mount's top level,
/// `metadata/<prefix>/` below it. `metadata/<name>` without the slash is the
/// single-key route, which has no list operation. `path` is optional, and
/// absent, empty or `/` lists the top level.
fn kv_list_path(mount: &str, args: &Map<String, Value>) -> Result<String, McpError> {
    let raw = match args.get("path") {
        None | Some(Value::Null) => "",
        Some(Value::String(s)) => s.as_str(),
        Some(_) => return Err(McpError::InvalidArgument("non-string `path`".into())),
    };
    let prefix = raw.trim_matches('/');
    if prefix.is_empty() {
        return Ok(format!("{mount}/metadata/"));
    }
    let prefix = normalize_component(prefix)?;
    Ok(format!("{mount}/metadata/{prefix}/"))
}

/// A resource name is one path segment: the engine's record route is
/// `resources/<name>` with no deeper level.
fn resource_name(args: &Map<String, Value>) -> Result<String, McpError> {
    let name = normalize_component(arg_str(args, "name")?)?;
    if name.contains('/') {
        return Err(McpError::InvalidArgument("a resource name may not contain `/`".into()));
    }
    Ok(name)
}

fn arg_str<'a>(args: &'a Map<String, Value>, key: &str) -> Result<&'a str, McpError> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| McpError::InvalidArgument(format!("missing or non-string `{key}`")))
}

fn build_tool_request(tool: &str, args: &Map<String, Value>) -> Result<ToolRequest, McpError> {
    match tool {
        "bv_capabilities" => {
            // `sys/capabilities-self` is a write that takes a `paths` array;
            // a read is refused by the ACL and has no route besides.
            let path = normalize_component(arg_str(args, "path")?)?;
            let mut body = Map::new();
            body.insert("paths".into(), Value::Array(vec![Value::String(path.clone())]));
            Ok(ToolRequest {
                operation: Operation::Write,
                path: "sys/capabilities-self".to_string(),
                body: Some(body),
                scope_subject: Some(path),
            })
        }
        "bv_kv_list" => {
            let mount = normalize_component(arg_str(args, "mount")?)?;
            Ok(ToolRequest {
                operation: Operation::List,
                path: kv_list_path(&mount, args)?,
                body: None,
                scope_subject: None,
            })
        }
        "bv_kv_read_metadata" => {
            let mount = normalize_component(arg_str(args, "mount")?)?;
            let path = normalize_component(arg_str(args, "path")?)?;
            Ok(ToolRequest {
                operation: Operation::Read,
                path: format!("{mount}/metadata/{path}"),
                body: None,
                scope_subject: None,
            })
        }
        "bv_kv_read" => {
            let mount = normalize_component(arg_str(args, "mount")?)?;
            let path = normalize_component(arg_str(args, "path")?)?;
            Ok(ToolRequest {
                operation: Operation::Read,
                path: format!("{mount}/data/{path}"),
                body: None,
                scope_subject: None,
            })
        }
        // The resource engine is mounted at `resources/` and keeps its
        // records, flat, under `resources/resources/<name>`.
        "bv_resource_list" => Ok(ToolRequest {
            operation: Operation::List,
            path: "resources/resources/".to_string(),
            body: None,
            scope_subject: None,
        }),
        "bv_resource_describe" => {
            let name = resource_name(args)?;
            Ok(ToolRequest {
                operation: Operation::Read,
                path: format!("resources/resources/{name}"),
                body: None,
                scope_subject: None,
            })
        }
        "bv_transit_encrypt" => {
            let key = normalize_component(arg_str(args, "key")?)?;
            let mut body = Map::new();
            body.insert("plaintext".into(), Value::String(arg_str(args, "plaintext")?.to_string()));
            if let Some(ctx) = args.get("context").and_then(Value::as_str) {
                body.insert("context".into(), Value::String(ctx.to_string()));
            }
            Ok(ToolRequest {
                operation: Operation::Write,
                path: format!("transit/encrypt/{key}"),
                body: Some(body),
                scope_subject: None,
            })
        }
        "bv_transit_decrypt" => {
            let key = normalize_component(arg_str(args, "key")?)?;
            let mut body = Map::new();
            body.insert("ciphertext".into(), Value::String(arg_str(args, "ciphertext")?.to_string()));
            Ok(ToolRequest {
                operation: Operation::Write,
                path: format!("transit/decrypt/{key}"),
                body: Some(body),
                scope_subject: None,
            })
        }
        "bv_transit_sign" => {
            let key = normalize_component(arg_str(args, "key")?)?;
            let mut body = Map::new();
            body.insert("input".into(), Value::String(arg_str(args, "input")?.to_string()));
            Ok(ToolRequest {
                operation: Operation::Write,
                path: format!("transit/sign/{key}"),
                body: Some(body),
                scope_subject: None,
            })
        }
        "bv_transit_verify" => {
            let key = normalize_component(arg_str(args, "key")?)?;
            let mut body = Map::new();
            body.insert("input".into(), Value::String(arg_str(args, "input")?.to_string()));
            body.insert("signature".into(), Value::String(arg_str(args, "signature")?.to_string()));
            Ok(ToolRequest {
                operation: Operation::Write,
                path: format!("transit/verify/{key}"),
                body: Some(body),
                scope_subject: None,
            })
        }
        "bv_totp_code" => {
            let name = normalize_component(arg_str(args, "name")?)?;
            Ok(ToolRequest {
                operation: Operation::Read,
                path: format!("totp/code/{name}"),
                body: None,
                scope_subject: None,
            })
        }
        "bv_pki_list_certs" => Ok(ToolRequest {
            operation: Operation::List,
            path: "pki/certs".to_string(),
            body: None,
            scope_subject: None,
        }),
        "bv_pki_read_cert" => {
            let serial = normalize_component(arg_str(args, "serial")?)?;
            Ok(ToolRequest {
                operation: Operation::Read,
                path: format!("pki/cert/{serial}"),
                body: None,
                scope_subject: None,
            })
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
            Ok(ToolRequest {
                operation: Operation::Write,
                path: format!("{mount}/data/{path}"),
                body: Some(body),
                scope_subject: None,
            })
        }
        "bv_kv_delete" => {
            let mount = normalize_component(arg_str(args, "mount")?)?;
            let path = normalize_component(arg_str(args, "path")?)?;
            // Soft-delete only — the current version's data endpoint, never
            // `metadata` (which would also erase version history).
            Ok(ToolRequest {
                operation: Operation::Delete,
                path: format!("{mount}/data/{path}"),
                body: None,
                scope_subject: None,
            })
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
            Ok(ToolRequest {
                operation: Operation::Write,
                path: format!("pki/issue/{role}"),
                body: Some(body),
                scope_subject: None,
            })
        }
        "bv_ssh_sign" => {
            let role = normalize_component(arg_str(args, "role")?)?;
            let public_key = arg_str(args, "public_key")?;
            let mut body = Map::new();
            body.insert("public_key".into(), Value::String(public_key.to_string()));
            if let Some(principals) = args.get("valid_principals").and_then(Value::as_str) {
                body.insert("valid_principals".into(), Value::String(principals.to_string()));
            }
            Ok(ToolRequest {
                operation: Operation::Write,
                path: format!("ssh/sign/{role}"),
                body: Some(body),
                scope_subject: None,
            })
        }
        other => Err(McpError::UnknownTool(other.to_string())),
    }
}
