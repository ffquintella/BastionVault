//! `tools/call` → gates → `bv_client::Backend` → result shaping. Spec §6.

use bv_client::{Backend, ClientError, Operation};
use bv_logical::{McpBinding, McpBindingKind};
use serde_json::{Map, Value};

use crate::{
    catalogue::{self, ToolMeta},
    error::{session_error_from_backend, McpError},
    jsonrpc::CallToolResult,
    request_state::{self, RequestStatePayload, SingleUseGuard},
    sanitize::{forbidden_command_char, sanitize_for_model},
    untrusted::{self, SessionProtocol, UntrustedSource},
};

/// The route `bv_resource_ssh_exec` dispatches to
/// (`features/mcp-brokered-sessions.md` §13). The handler accepts only
/// requests this dispatcher routes (`Request::mcp_dispatch`).
pub const SSH_EXEC_PATH: &str = "resources/v2/connect/agent/ssh/exec";

/// The route `bv_resource_web_fetch` dispatches to (§13), answering only
/// requests this dispatcher routes, like [`SSH_EXEC_PATH`].
pub const WEB_FETCH_PATH: &str = "resources/v2/connect/agent/web/fetch";

/// Longest session command, in bytes (§11 "Limits": default and ceiling).
pub const MAX_SESSION_COMMAND_BYTES: usize = 4096;

/// Longest web fetch path, query included, in bytes (§6.3 "Path rules").
pub const MAX_WEB_PATH_BYTES: usize = 2048;

/// The methods `bv_resource_web_fetch` may send (§6.3). Read-only by HTTP
/// semantics; there is no body to send.
pub const WEB_FETCH_METHODS: &[&str] = &["GET", "HEAD"];

/// Largest `timeout_secs` a session call may ask for: the server's ceiling
/// for `call_timeout_secs`. The handler further refuses anything above the
/// configured value.
pub const MAX_SESSION_TIMEOUT_SECS: u64 = 120;

/// Longest resource name or profile id a session tool accepts.
pub const MAX_SESSION_NAME_BYTES: usize = 128;

/// The final cap on a shaped `bv_resource_ssh_exec` result (§8 step 6). The
/// handler returns at most `max_output_bytes` of output (ceiling 256 KiB),
/// carried twice — in `structuredContent` and in the text — and at most
/// doubled by JSON escaping once the sanitizer has removed every control but
/// `\n` and `\t`; 64 KiB covers the rest. A result over it means a cap did
/// not hold, and is refused rather than cut.
pub const SSH_EXEC_RESULT_CEILING_BYTES: usize = 4 * 262_144 + 65_536;

/// The final cap on a shaped `bv_resource_web_fetch` result, by the same
/// reckoning as [`SSH_EXEC_RESULT_CEILING_BYTES`]: at most
/// `max_output_bytes` of page text (ceiling 256 KiB) plus the truncation
/// marker, carried twice and at most doubled by escaping, and the small
/// fixed fields.
pub const WEB_FETCH_RESULT_CEILING_BYTES: usize = 4 * 262_144 + 65_536;

/// Non-secret facts about the calling principal, needed only to answer
/// `bv_whoami` without a routed request (spec §7: "answered from the token
/// entry, not by routing to `auth/token/lookup-self`").
pub struct PrincipalInfo {
    pub accessor: String,
    pub display_name: String,
    pub policies: Vec<String>,
    /// The namespace the token is bound to and every call is routed in,
    /// canonical (`""` = root). From the token's stored binding, never from
    /// the client. Reported by `bv_whoami` and `bv_resource_list`.
    pub namespace: String,
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
    /// The operator's connect MFA ticket the local gatekeeper relayed in
    /// `_meta` (`features/mcp-brokered-sessions.md` §3.1 step 5). Put in the
    /// routed body's `connect_ticket` for a session tool only, where the
    /// handler redeems it against this exact call; ignored for every other
    /// tool. Never taken from `arguments`.
    pub connect_ticket: Option<&'a str>,
}

/// A session tool call as the operator confirms it
/// (`features/mcp-brokered-sessions.md` §9): validated exactly as
/// [`call`] validates it, so the local gatekeeper refuses a malformed call
/// before it prompts anyone, and shows the operator the very values the
/// vault will route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCall {
    pub tool: &'static str,
    /// `ssh`, `web` or `rdp`.
    pub protocol: &'static str,
    /// The resource as it will be routed (one normalized segment).
    pub resource: String,
    pub profile: String,
    /// SSH: the command, byte for byte what runs. Empty for other protocols.
    pub command: String,
    /// Web: the HTTP method, `GET` or `HEAD` (the default `GET` filled in).
    /// Empty for other protocols.
    pub method: String,
    /// Web: the origin-relative path with its query, byte for byte what is
    /// requested. Empty for other protocols.
    pub path: String,
    pub timeout_secs: Option<u64>,
    /// [`args_hash`] of the call's `arguments`: what an operator MFA ticket
    /// for this call is bound to.
    pub args_hash: String,
    /// The path the binding's `path_scope` must cover.
    pub scope_subject: String,
}

/// Validates a session tool call without routing it. `Err` is the refusal
/// the dispatcher would answer with; an unknown or non-session tool is
/// [`McpError::UnknownTool`].
pub fn session_call(tool: &str, args: &Map<String, Value>) -> Result<SessionCall, McpError> {
    let meta = catalogue::find(tool).filter(|m| m.open_world).ok_or_else(|| McpError::UnknownTool(tool.to_string()))?;
    let req = build_tool_request(meta.name, args)?;
    let scope_subject = req.scope_subject().to_string();
    let body = req.body.unwrap_or_default();
    let text = |key: &str| body.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
    match meta.name {
        "bv_resource_ssh_exec" => Ok(SessionCall {
            tool: meta.name,
            protocol: "ssh",
            resource: text("resource"),
            profile: text("profile_id"),
            command: text("command"),
            method: String::new(),
            path: String::new(),
            timeout_secs: body.get("timeout_secs").and_then(Value::as_u64),
            args_hash: args_hash(args),
            scope_subject,
        }),
        "bv_resource_web_fetch" => Ok(SessionCall {
            tool: meta.name,
            protocol: "web",
            resource: text("resource"),
            profile: text("profile_id"),
            command: String::new(),
            method: text("method"),
            path: text("path"),
            timeout_secs: body.get("timeout_secs").and_then(Value::as_u64),
            args_hash: args_hash(args),
            scope_subject,
        }),
        other => Err(McpError::UnknownTool(other.to_string())),
    }
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
    // tool is refused outright unless the binding allows it. A session tool
    // is the exception: its grant is `connect_allowed` (checked above) and
    // its confirmation is the operator's, on every call; its
    // `destructiveHint` is advice to the client, not a second grant.
    if meta.destructive && !meta.open_world {
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
    let needs_destructive_confirm = meta.destructive && !meta.open_world && ctx.confirm_destructive;
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

    let mut body = req.body;
    if meta.open_world {
        if let Some(ticket) = ctx.connect_ticket {
            body.get_or_insert_with(Map::new).insert("connect_ticket".into(), Value::String(ticket.to_string()));
        }
    }
    let response =
        ctx.backend.handle(req.operation, &req.path, body, ctx.token).await.map_err(|e| map_backend_error(meta, e))?;

    if meta.open_world {
        return shape_session_result(meta, &args, response);
    }
    let mut result = shape_result(meta, reveal_requested, response);
    if tool == "bv_resource_list" {
        // Which namespace's resources these are: the token's own, never one
        // the client named.
        if let Some(Value::Object(data)) = result.structured_content.as_mut() {
            data.insert("namespace".into(), Value::String(sanitize_for_model(&ctx.principal.namespace)));
        }
    }
    Ok(result)
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
/// §3.1), possibly in another process built with other features.
///
/// So the bytes are canonical: every object's keys in byte order, at every
/// depth, whatever the build's `serde_json` map type. Without
/// `preserve_order` (the case in this workspace's vault builds) that is the
/// order `serde_json` already writes, so this hash is unchanged from the one
/// earlier releases computed; with it (a host whose dependency graph turns
/// it on) the client's key order would otherwise leak into the hash and an
/// operator's ticket would never match. A map that cannot serialize hashes
/// the empty input rather than panicking; such a map cannot have come from a
/// parsed JSON-RPC request.
pub fn args_hash(args: &Map<String, Value>) -> String {
    let canonical = canonical_json(&Value::Object(args.clone()));
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    blake3::hash(&bytes).to_hex().to_string()
}

/// `value` with every object rebuilt in sorted key order, which a map that
/// keeps insertion order then also serializes in.
fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), canonical_json(&map[key]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical_json).collect()),
        other => other.clone(),
    }
}

/// A routed call's failure. A session handler leads its refusals with a
/// stable code ([`crate::error::SESSION_ERROR_CODES`]), which is carried
/// through as `data.code`; anything else is a plain backend error.
fn map_backend_error(meta: &ToolMeta, err: ClientError) -> McpError {
    let message = err.to_string();
    if meta.open_world {
        if let Some(session) = session_error_from_backend(&message) {
            return session;
        }
    }
    McpError::Backend(message)
}

/// Steps 5 and 6 of §8 for a session result: the handler has already capped,
/// decoded, credential-scrubbed and sanitized the output (it holds the
/// credential; this side never does). Here it is wrapped in the untrusted
/// envelope — the constant preamble, `structuredContent.untrusted` — and the
/// whole result is checked against its ceiling.
fn shape_session_result(
    meta: &ToolMeta,
    args: &Map<String, Value>,
    response: Option<bv_client::JsonResponse>,
) -> Result<CallToolResult, McpError> {
    let data = response.and_then(|r| r.data).unwrap_or_default();
    let (protocol, ceiling, body) = match meta.name {
        "bv_resource_ssh_exec" => (SessionProtocol::Ssh, SSH_EXEC_RESULT_CEILING_BYTES, render_ssh_text(&data)),
        "bv_resource_web_fetch" => (SessionProtocol::Web, WEB_FETCH_RESULT_CEILING_BYTES, render_web_text(&data)),
        other => return Err(McpError::UnknownTool(other.to_string())),
    };
    let source = UntrustedSource {
        protocol,
        resource: args.get("resource").and_then(Value::as_str).unwrap_or_default(),
        profile: args.get("profile").and_then(Value::as_str).unwrap_or_default(),
    };
    let result = untrusted::envelope(&source, &body, data);
    untrusted::check_result_size(&result, ceiling)?;
    Ok(result)
}

/// The text a client without `structuredContent` support shows: the exit
/// status and both streams, with their byte counts. Follows the constant
/// preamble; the envelope sanitizes it again.
fn render_ssh_text(data: &Map<String, Value>) -> String {
    let mut out = String::new();
    let timed_out = data.get("timed_out").and_then(Value::as_bool).unwrap_or(false);
    match (data.get("exit_status").and_then(Value::as_u64), data.get("exit_signal").and_then(Value::as_str)) {
        _ if timed_out => out.push_str("timed out; the command was sent KILL"),
        (Some(status), _) => out.push_str(&format!("exit status: {status}")),
        (None, Some(signal)) => out.push_str(&format!("killed by signal: {signal}")),
        (None, None) => out.push_str("exit status: unknown"),
    }
    let binary = data.get("binary_output").and_then(Value::as_bool).unwrap_or(false);
    for stream in ["stdout", "stderr"] {
        let bytes = data.get(&format!("{stream}_bytes")).and_then(Value::as_u64).unwrap_or(0);
        let truncated = data.get(&format!("{stream}_truncated")).and_then(Value::as_bool).unwrap_or(false);
        let cut = if truncated { ", truncated" } else { "" };
        if binary {
            out.push_str(&format!("\n\n{stream}: binary output ({bytes} bytes{cut}), not shown"));
            continue;
        }
        let text = data.get(stream).and_then(Value::as_str).unwrap_or_default();
        if bytes == 0 && text.is_empty() {
            out.push_str(&format!("\n\n{stream}: (empty)"));
        } else {
            out.push_str(&format!("\n\n--- {stream} ({bytes} bytes{cut}) ---\n{text}"));
        }
    }
    out
}

/// The text a client without `structuredContent` support shows for a web
/// fetch: the status line, where the answer came from, and the page text
/// with its byte count. Follows the constant preamble; the envelope
/// sanitizes it again. Never a header other than the content type.
fn render_web_text(data: &Map<String, Value>) -> String {
    let status = data.get("status").and_then(Value::as_u64).map(|s| s.to_string()).unwrap_or_else(|| "?".into());
    let content_type = data.get("content_type").and_then(Value::as_str).unwrap_or("no content type");
    let mut out = format!("HTTP {status} ({content_type})");
    if data.get("redirected").and_then(Value::as_bool).unwrap_or(false) {
        let origin = data.get("final_origin").and_then(Value::as_str).unwrap_or_default();
        let path = data.get("final_path").and_then(Value::as_str).unwrap_or_default();
        out.push_str(&format!("\nafter redirects, from {origin}{path}"));
    }
    let bytes = data.get("body_bytes").and_then(Value::as_u64).unwrap_or(0);
    let cut = if data.get("truncated").and_then(Value::as_bool).unwrap_or(false) { ", truncated" } else { "" };
    if data.get("binary_output").and_then(Value::as_bool).unwrap_or(false) {
        out.push_str(&format!("\n\nbody: binary ({bytes} bytes{cut}), not shown"));
        return out;
    }
    let text = data.get("body_text").and_then(Value::as_str).unwrap_or_default();
    if text.is_empty() {
        out.push_str(&format!("\n\nbody: (empty, {bytes} bytes)"));
    } else {
        out.push_str(&format!("\n\n--- body ({bytes} bytes{cut}) ---\n{text}"));
    }
    out
}

fn whoami_result(principal: &PrincipalInfo) -> CallToolResult {
    let data = serde_json::json!({
        "accessor": principal.accessor,
        "display_name": sanitize_for_model(&principal.display_name),
        "policies": principal.policies,
        "namespace": sanitize_for_model(&principal.namespace),
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
    if path_scope_covers(&binding.path_scope, path) {
        Ok(())
    } else {
        Err(McpError::PathOutOfScope(path.to_string()))
    }
}

/// Whether a grant's `path_scope` covers `path`, by the dispatcher's own
/// rule. Public so the local gatekeeper can tell, before it prompts, that
/// the vault will refuse a call as out of scope.
pub fn path_scope_covers(path_scope: &[String], path: &str) -> bool {
    path_scope.iter().any(|pattern| {
        if let Some(prefix) = pattern.strip_suffix('*') {
            path.starts_with(prefix)
        } else {
            path == pattern
        }
    })
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

/// Session tools take exactly their declared arguments: what the operator
/// confirms is the whole call, so nothing may ride along unshown.
fn check_known_args(args: &Map<String, Value>, known: &[&str]) -> Result<(), McpError> {
    match args.keys().find(|k| !known.contains(&k.as_str())) {
        Some(extra) => Err(McpError::InvalidArgument(format!("unknown argument `{}`", sanitize_for_model(extra)))),
        None => Ok(()),
    }
}

/// A name a session tool folds into a path or a record lookup: a resource
/// or a profile id. One segment, bounded, and nothing a reader of the
/// confirmation could not see.
fn session_name<'a>(args: &'a Map<String, Value>, key: &str) -> Result<&'a str, McpError> {
    let raw = arg_str(args, key)?;
    if raw.is_empty() || raw.len() > MAX_SESSION_NAME_BYTES {
        return Err(McpError::InvalidArgument(format!("`{key}` must be 1-{MAX_SESSION_NAME_BYTES} bytes")));
    }
    if raw.trim() != raw || raw.contains('/') || raw.contains("..") {
        return Err(McpError::InvalidArgument(format!(
            "`{key}` must be one path segment, with no `/`, `..` or surrounding whitespace"
        )));
    }
    if let Some(c) = forbidden_command_char(raw) {
        return Err(McpError::InvalidArgument(format!("`{key}` contains U+{:04X}, which is not allowed", c as u32)));
    }
    Ok(raw)
}

/// `bv_resource_ssh_exec`'s `command` (§5.1): UTF-8 (a JSON string already
/// is), 1-4096 bytes, and no character [`forbidden_command_char`] names.
/// Refused, never cleaned: the operator confirms exactly what runs. The
/// handler repeats this check.
fn session_command(args: &Map<String, Value>) -> Result<&str, McpError> {
    let command = arg_str(args, "command")?;
    if command.is_empty() || command.len() > MAX_SESSION_COMMAND_BYTES {
        return Err(McpError::InvalidArgument(format!(
            "`command` is {} bytes; it must be 1-{MAX_SESSION_COMMAND_BYTES}",
            command.len()
        )));
    }
    if let Some(c) = forbidden_command_char(command) {
        return Err(McpError::InvalidArgument(format!(
            "`command` contains U+{:04X}, a control, bidi, zero-width, tag or other invisible character; \
             a session command is refused rather than cleaned, so the operator confirms exactly what runs",
            c as u32
        )));
    }
    Ok(command)
}

/// `bv_resource_web_fetch`'s `method`: exactly `GET` or `HEAD` (§6.3).
/// Public so the session handler re-checks with this very rule.
pub fn check_web_method(method: &str) -> Result<(), String> {
    if WEB_FETCH_METHODS.contains(&method) {
        Ok(())
    } else {
        Err(format!("`method` must be one of {WEB_FETCH_METHODS:?}"))
    }
}

/// Characters a web fetch path may carry, besides alphanumerics and a valid
/// `%XX` escape: RFC 3986's unreserved, sub-delims, and the gen-delims a path
/// or query may hold (`:`, `@`, `/`, `?`). A `#` (a fragment), square
/// brackets (authority only), space, quotes, angle brackets, backslash,
/// caret, backtick, braces, pipe and every non-ASCII or control byte are
/// refused.
fn web_path_char_ok(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?".contains(&c)
}

/// One round of percent-decoding, bytewise; an invalid escape is left as is
/// (the character check has already refused one).
fn percent_decode_once(raw: &[u8]) -> Vec<u8> {
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' && i + 2 < raw.len() {
            if let (Some(h), Some(l)) = (hex(raw[i + 1]), hex(raw[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(raw[i]);
        i += 1;
    }
    out
}

/// `bv_resource_web_fetch`'s `path` (§6.3 "Path rules"): origin-relative,
/// starting with `/` but not `//`; at most [`MAX_WEB_PATH_BYTES`]; no
/// fragment; only RFC 3986 characters, with every `%` starting a valid
/// escape; and no `..` segment in the path part after percent-decoding --
/// decoded repeatedly (a double-encoded `%252e%252e` included), split on
/// both `/` and `\` as some servers do, and with a `;` path parameter cut off
/// (`..;` is `..` to a servlet container). Refused, never cleaned: the operator
/// confirms exactly what is requested. Public so the session handler
/// re-checks with this very rule.
pub fn check_web_path(path: &str) -> Result<(), String> {
    if path.is_empty() || path.len() > MAX_WEB_PATH_BYTES {
        return Err(format!("`path` is {} bytes; it must be 1-{MAX_WEB_PATH_BYTES}", path.len()));
    }
    if !path.starts_with('/') || path.starts_with("//") {
        return Err("`path` must be origin-relative: start with `/`, not `//`, and carry no scheme or host".into());
    }
    let bytes = path.as_bytes();
    if let Some(at) = bytes.iter().position(|b| *b == b'#') {
        return Err(format!("`path` has a fragment at byte {at}; fragments are never sent"));
    }
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'%' {
            let valid = bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit);
            if !valid {
                return Err(format!("`path` has a `%` at byte {i} that does not start a %XX escape"));
            }
            i += 3;
            continue;
        }
        if !web_path_char_ok(c) {
            return Err(format!("`path` has a byte outside RFC 3986 at offset {i} (0x{c:02X}); percent-encode it"));
        }
        i += 1;
    }
    let path_part = path.split('?').next().unwrap_or_default();
    let mut decoded = path_part.as_bytes().to_vec();
    for _ in 0..3 {
        let next = percent_decode_once(&decoded);
        if next == decoded {
            break;
        }
        decoded = next;
    }
    let dot_dot = |segment: &[u8]| segment.split(|b| *b == b';').next() == Some(b"..".as_slice());
    if decoded.split(|b| *b == b'/' || *b == b'\\').any(dot_dot) {
        return Err("`path` has a `..` segment (after percent-decoding); it is refused, not normalized".into());
    }
    // What an HTTP client's URL parser would rewrite is refused too, so the
    // bytes the operator confirms are the bytes sent: a `.` segment (also
    // `%2e`) is dropped by it, and a `'` in the query is escaped to `%27`.
    if path_part.split('/').any(|segment| segment == "." || segment.eq_ignore_ascii_case("%2e")) {
        return Err("`path` has a `.` segment, which would be normalized away; send the path without it".into());
    }
    if path.split_once('?').is_some_and(|(_, query)| query.contains('\'')) {
        return Err("`path` has a `'` in its query; percent-encode it as %27".into());
    }
    Ok(())
}

/// The optional `timeout_secs`: an integer in 1..=[`MAX_SESSION_TIMEOUT_SECS`].
fn session_timeout(args: &Map<String, Value>) -> Result<Option<u64>, McpError> {
    match args.get("timeout_secs") {
        None | Some(Value::Null) => Ok(None),
        Some(v) => match v.as_u64() {
            Some(n) if (1..=MAX_SESSION_TIMEOUT_SECS).contains(&n) => Ok(Some(n)),
            _ => Err(McpError::InvalidArgument(format!(
                "`timeout_secs` must be an integer in 1..={MAX_SESSION_TIMEOUT_SECS}"
            ))),
        },
    }
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
        // The one tool that reads under `sys/`, which `normalize_component`
        // refuses for every client-supplied component: the prefix is fixed
        // here and only a single-segment name is taken from the client. The
        // namespace is the token's own (`InProcessMcpBackend`), never an
        // argument, and the vault's ACL decides on the caller's token, so a
        // user who may not read the policy gets a refusal whatever the
        // pairing says.
        "bv_policy_read" => {
            check_known_args(args, &["name"])?;
            let name = session_name(args, "name")?;
            Ok(ToolRequest {
                operation: Operation::Read,
                path: format!("sys/policies/acl/{name}"),
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
        "bv_resource_ssh_exec" => {
            check_known_args(args, &["resource", "profile", "command", "timeout_secs"])?;
            let resource = normalize_component(session_name(args, "resource")?)?;
            let profile = session_name(args, "profile")?;
            let command = session_command(args)?;
            let mut body = Map::new();
            body.insert("resource".into(), Value::String(resource.clone()));
            body.insert("profile_id".into(), Value::String(profile.to_string()));
            body.insert("command".into(), Value::String(command.to_string()));
            if let Some(timeout) = session_timeout(args)? {
                body.insert("timeout_secs".into(), Value::from(timeout));
            }
            // The scope subject is the path the `connect` capability is
            // checked on (§1): a scope for describing a resource
            // (`resources/resources/<name>`) must not become one for
            // connecting to it.
            Ok(ToolRequest {
                operation: Operation::Write,
                path: SSH_EXEC_PATH.to_string(),
                body: Some(body),
                scope_subject: Some(format!("resources/secrets/{resource}/")),
            })
        }
        "bv_resource_web_fetch" => {
            check_known_args(args, &["resource", "profile", "method", "path", "timeout_secs"])?;
            let resource = normalize_component(session_name(args, "resource")?)?;
            let profile = session_name(args, "profile")?;
            let method = match args.get("method") {
                None | Some(Value::Null) => "GET",
                Some(Value::String(m)) => m.as_str(),
                Some(_) => return Err(McpError::InvalidArgument("non-string `method`".into())),
            };
            check_web_method(method).map_err(McpError::InvalidArgument)?;
            let path = arg_str(args, "path")?;
            check_web_path(path).map_err(McpError::InvalidArgument)?;
            let mut body = Map::new();
            body.insert("resource".into(), Value::String(resource.clone()));
            body.insert("profile_id".into(), Value::String(profile.to_string()));
            body.insert("method".into(), Value::String(method.to_string()));
            body.insert("path".into(), Value::String(path.to_string()));
            if let Some(timeout) = session_timeout(args)? {
                body.insert("timeout_secs".into(), Value::from(timeout));
            }
            // As for SSH: the connect path, not the describe path, is the
            // scope subject.
            Ok(ToolRequest {
                operation: Operation::Write,
                path: WEB_FETCH_PATH.to_string(),
                body: Some(body),
                scope_subject: Some(format!("resources/secrets/{resource}/")),
            })
        }
        other => Err(McpError::UnknownTool(other.to_string())),
    }
}
