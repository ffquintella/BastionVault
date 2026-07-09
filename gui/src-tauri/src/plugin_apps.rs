//! Plugin App Extensions (Extensibility v2) — Tauri-backend app-module
//! runtime. Phases 2 (dynamic menus) & 3 (plugin windows).
//!
//! Unlike the *stateless* form-hook sandbox in `plugin_hooks.rs` (fresh
//! `Store` per call, empty linker), an **app module** is a long-lived,
//! stateful WASM instance: one per `(plugin, active version)` per
//! signed-in session, created lazily when a surface bundle carrying an
//! `app-module` asset arrives, and torn down on sign-out / vault-switch
//! / surface update. Its linear memory persists across entry-point calls
//! so a plugin can hold state (e.g. a cached "pending approvals" count)
//! between `bvx_init`, `bvx_menu_click`, `bvx_window_event`, `bvx_tick`.
//!
//! Security invariants (carried from the server runtime `runtime.rs`):
//! * The `bvx.*` import set is the entire capability surface. Every
//!   import is registered unconditionally and gated **inside** the
//!   closure against the capability flags copied from the manifest — a
//!   module that imports a symbol the host doesn't register fails to
//!   instantiate (defence-in-depth).
//! * Same sandbox limits as the form hook: 256 MiB memory, 100 M fuel
//!   *refueled per entry-point call*, 4 MiB payload cap.
//! * Menus/windows are validated host-side on every call (route prefix,
//!   section whitelist, 16-menu cap, window `max_open` clamp).
//!
//! Phases 4/5 (`bvx.api_request`, `bvx.net_http`) are intentionally NOT
//! registered here yet — a module importing them fails to instantiate,
//! which is the desired clean-refusal until those phases land.

use std::collections::BTreeMap;
use std::sync::Arc;

use bv_client::{Backend, Operation};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wasmtime::{
    AsContext, AsContextMut, Caller, Engine, Instance, Linker, Module, Store, StoreLimits,
    StoreLimitsBuilder,
};

/// Per-entry-point-call instruction ceiling (refueled each call).
pub const FUEL_PER_CALL: u64 = 100_000_000;
/// Per-instance memory ceiling.
pub const MEMORY_BYTES: usize = 256 * 1024 * 1024;
/// Cap on JSON exchanged across the host boundary in one call.
pub const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
/// Hard cap on dynamic menu entries a single plugin may hold.
pub const MAX_DYNAMIC_MENUS: usize = 16;
/// Floor on `bvx_tick` cadence.
pub const MIN_TICK_INTERVAL_MS: i64 = 30_000;

/// Response-body cap for `bvx.net_http` (Phase 5).
pub const MAX_NET_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Ceiling on the per-plugin network call ring buffer (Phase 5).
pub const NET_RING_CAP: usize = 100;
/// Hard timeout ceiling for `bvx.net_http` (Phase 5).
pub const NET_TIMEOUT_MAX_MS: u64 = 60_000;
/// Redirect-hop cap for `bvx.net_http` (Phase 5) — every hop re-validated.
pub const NET_MAX_REDIRECTS: usize = 3;

// Return codes shared with the guest ABI (mirror the server `bv` codes).
const RC_OK: i32 = 0;
const RC_FORBIDDEN: i32 = -2;
const RC_BUFFER_TOO_SMALL: i32 = -3;
const RC_INTERNAL: i32 = -4;
const RC_NET_NOT_GRANTED: i32 = -6;
const RC_NET_HOST_DENIED: i32 = -7;
const RC_WINDOW_LIMIT: i32 = -8;

#[derive(Debug, Error)]
pub enum AppModuleError {
    #[error("compile: {0}")]
    Compile(String),
    #[error("instantiate: {0}")]
    Instantiate(String),
    #[error("missing `memory` export")]
    MissingMemory,
    #[error("missing required `bv_alloc` export")]
    MissingAlloc,
    #[error("invocation: {0}")]
    Invocation(String),
    #[error("input too large ({0} bytes; max is 4 MiB)")]
    InputTooLarge(usize),
    #[error("link: {0}")]
    Link(String),
}

/// The subset of `capabilities.app` the runtime gates against, shipped
/// in the active-surfaces bundle (`bv_plugin_surface::AppModuleRef`).
#[derive(Debug, Clone, Default)]
pub struct AppCapsGate {
    pub dynamic_menus: bool,
    pub windows_max_open: u32,
    /// Mount-scoped prefixes `bvx.api_request` may target (Phase 4).
    pub api_paths: Vec<String>,
}

/// Everything needed to instantiate one app-module instance: identity,
/// capability gates, and the live session context the `bvx.api_request`
/// / `bvx.net_http` imports ride (Phases 4/5).
pub struct AppModuleConfig {
    pub plugin: String,
    pub version: String,
    pub sha256: String,
    /// The plugin's mount, substituted for `{mount}` in api_paths + calls.
    pub mount: String,
    pub caps: AppCapsGate,
    /// Live dispatch handle for `bvx.api_request` (embedded or remote).
    pub backend: Option<Arc<dyn Backend>>,
    /// Session token the api bridge rides — server ACLs stay authoritative.
    pub token: String,
    pub namespace: Option<String>,
    /// Granted outbound hosts (from the bundle grant). Empty = not
    /// granted → `bvx.net_http` returns `NET_NOT_GRANTED`.
    pub net_hosts: Vec<String>,
    /// Manifest `https_only` flag (defaults true) — governs the http
    /// exception in `net_gate`.
    pub net_https_only: bool,
}

/// One recorded `bvx.net_http` call for the per-plugin ring buffer
/// surfaced on the Plugins admin page.
#[derive(Debug, Clone, Serialize)]
pub struct NetCall {
    pub at_unix_ms: i64,
    pub method: String,
    pub host: String,
    /// HTTP status on success; `None` when the call was refused/failed
    /// before a response (see `outcome`).
    pub status: Option<u16>,
    pub bytes: usize,
    /// `"ok"` or a short refusal reason (`not_granted`, `host_denied`, …).
    pub outcome: String,
}

/// A menu the plugin created/updated at runtime. Serialised to the
/// webview verbatim; renders identically to a static `SurfaceMenu`
/// (`min_policy` hint included) plus the optional `badge`.
#[derive(Debug, Clone, Serialize)]
pub struct DynamicMenu {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub icon: String,
    pub section: String,
    pub route: String,
    #[serde(default)]
    pub min_policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub badge: Option<String>,
    /// Owning plugin — lets the frontend route menu-click callbacks and
    /// scope teardown.
    pub plugin: String,
}

/// Raw shape accepted by `bvx.menu_upsert` (the `SurfaceMenu` JSON plus
/// `badge`). Validated host-side before it becomes a [`DynamicMenu`].
#[derive(Debug, Deserialize)]
struct MenuUpsertInput {
    id: String,
    label: String,
    #[serde(default)]
    icon: String,
    section: String,
    route: String,
    #[serde(default)]
    min_policy: String,
    #[serde(default)]
    badge: Option<String>,
}

/// A window operation recorded during an entry-point call, applied by
/// the Tauri glue after the call returns (the WASM closure has no
/// `AppHandle`, so it records intent and the host executes it).
#[derive(Debug, Clone)]
pub enum WindowOp {
    Open {
        handle: u32,
        route: String,
        title: String,
        width: Option<f64>,
        height: Option<f64>,
    },
    Close {
        handle: u32,
    },
    Emit {
        handle: u32,
        payload: String,
    },
}

#[derive(Debug, Deserialize)]
struct WindowOpenInput {
    route: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    width: Option<f64>,
    #[serde(default)]
    height: Option<f64>,
}

/// Wasmtime `Store` state for one app-module instance.
struct AppCtx {
    plugin: String,
    /// `/plugin/<plugin>/` — the only route prefix menus and windows
    /// may target.
    menu_prefix: String,
    /// Plugin mount, substituted for `{mount}` in `bvx.api_request`.
    mount: String,
    // capability gates copied from the manifest at build time
    dynamic_menus: bool,
    windows_max_open: u32,
    /// Vault-API bridge scope (Phase 4). Empty = `bvx.api_request` denied.
    api_paths: Vec<String>,
    // live session context the async host imports ride (Phases 4/5)
    backend: Option<Arc<dyn Backend>>,
    token: String,
    namespace: Option<String>,
    // network capability (Phase 5)
    net_hosts: Vec<String>,
    net_https_only: bool,
    net_ring: Vec<NetCall>,
    // accumulated state
    menus: BTreeMap<String, DynamicMenu>,
    open_windows: Vec<u32>,
    next_window_handle: u32,
    window_ops: Vec<WindowOp>,
    response_window: Option<(u32, u32)>,
    limits: StoreLimits,
}

impl AppCtx {
    /// Record a network call in the bounded ring buffer.
    fn push_net_call(&mut self, call: NetCall) {
        if self.net_ring.len() >= NET_RING_CAP {
            self.net_ring.remove(0);
        }
        self.net_ring.push(call);
    }
}

fn valid_section(s: &str) -> bool {
    matches!(s, "secrets" | "sharing" | "admin" | "settings")
}

/// Validate a menu-upsert against the same rules as registration-time
/// surface validation: scoped route, known section, non-empty id/label.
fn validate_menu(input: MenuUpsertInput, menu_prefix: &str, plugin: &str) -> Option<DynamicMenu> {
    if input.id.trim().is_empty() || input.label.trim().is_empty() {
        return None;
    }
    if !valid_section(&input.section) {
        return None;
    }
    if !input.route.starts_with(menu_prefix) || input.route.contains("..") {
        return None;
    }
    Some(DynamicMenu {
        id: input.id,
        label: input.label,
        icon: input.icon,
        section: input.section,
        route: input.route,
        min_policy: input.min_policy,
        badge: input.badge,
        plugin: plugin.to_string(),
    })
}

// ── guest-memory helpers (closure side) ──────────────────────────────

fn read_bytes(caller: &mut Caller<'_, AppCtx>, ptr: i32, len: i32) -> Option<Vec<u8>> {
    if ptr < 0 || len < 0 || len as usize > MAX_PAYLOAD_BYTES {
        return None;
    }
    let memory = caller.get_export("memory").and_then(|e| e.into_memory())?;
    let mut buf = vec![0u8; len as usize];
    memory.read(caller.as_context(), ptr as usize, &mut buf).ok()?;
    Some(buf)
}

/// Write `src` into the guest's `(out_ptr, out_max)` window. Returns the
/// byte length on success, `RC_BUFFER_TOO_SMALL` if it doesn't fit (the
/// guest re-calls with a larger buffer), or `RC_INTERNAL` on a memory
/// fault — the single choke point for the buffer-retry protocol, mirror
/// of the server runtime's `write_to_buffer`.
fn write_to_buffer(caller: &mut Caller<'_, AppCtx>, src: &[u8], out_ptr: i32, out_max: i32) -> i32 {
    if out_ptr < 0 || out_max < 0 {
        return RC_INTERNAL;
    }
    if src.len() as i64 > out_max as i64 {
        return RC_BUFFER_TOO_SMALL;
    }
    let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) else {
        return RC_INTERNAL;
    };
    match memory.write(caller.as_context_mut(), out_ptr as usize, src) {
        Ok(()) => src.len() as i32,
        Err(_) => RC_INTERNAL,
    }
}

/// Process-global fuel-metering **async** engine for app modules. Async
/// support (fiber stacks) is what lets `bvx.api_request` / `bvx.net_http`
/// await inside a host import; mirrors `src/plugins/module_cache.rs`.
fn engine() -> &'static Engine {
    use std::sync::OnceLock;
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        // wasmtime ≥ 33 is always async-capable; setting the stack size
        // is what the async store needs (mirrors the server runtime).
        config.async_stack_size(1024 * 1024);
        config.max_wasm_stack(1024 * 1024);
        config.cranelift_nan_canonicalization(true);
        Engine::new(&config).expect("wasmtime engine")
    })
}

/// Register every `bvx.*` import unconditionally; gate inside each
/// closure against the `AppCtx` capability flags.
fn register_bvx_imports(linker: &mut Linker<AppCtx>) -> Result<(), AppModuleError> {
    let map_err = |e: wasmtime::Error| AppModuleError::Link(e.to_string());

    // bvx.log(level, ptr, len) — always available; silent on bad input.
    linker
        .func_wrap(
            "bvx",
            "log",
            |mut caller: Caller<'_, AppCtx>, level: i32, ptr: i32, len: i32| {
                let Some(bytes) = read_bytes(&mut caller, ptr, len) else {
                    return;
                };
                let line = String::from_utf8_lossy(&bytes).into_owned();
                let plugin = caller.data().plugin.clone();
                match level {
                    1 => log::trace!(target: "plugin_app", "[{plugin}] {line}"),
                    2 => log::debug!(target: "plugin_app", "[{plugin}] {line}"),
                    3 => log::info!(target: "plugin_app", "[{plugin}] {line}"),
                    4 => log::warn!(target: "plugin_app", "[{plugin}] {line}"),
                    _ => log::error!(target: "plugin_app", "[{plugin}] {line}"),
                }
            },
        )
        .map_err(map_err)?;

    // bvx.now_unix_ms() -> i64 — always available (wall clock is not a
    // secret; matches the server `bv.now_unix_ms`).
    linker
        .func_wrap("bvx", "now_unix_ms", |_caller: Caller<'_, AppCtx>| -> i64 {
            now_unix_ms()
        })
        .map_err(map_err)?;

    // bvx.set_result(ptr, len) — record the response window for the
    // current entry point (read back host-side after the call).
    linker
        .func_wrap(
            "bvx",
            "set_result",
            |mut caller: Caller<'_, AppCtx>, ptr: i32, len: i32| {
                if ptr < 0 || len < 0 {
                    return;
                }
                caller.data_mut().response_window = Some((ptr as u32, len as u32));
            },
        )
        .map_err(map_err)?;

    // bvx.menu_upsert(json_ptr, json_len) -> i32 — gated by dynamic_menus.
    linker
        .func_wrap(
            "bvx",
            "menu_upsert",
            |mut caller: Caller<'_, AppCtx>, ptr: i32, len: i32| -> i32 {
                if !caller.data().dynamic_menus {
                    return RC_FORBIDDEN;
                }
                let Some(bytes) = read_bytes(&mut caller, ptr, len) else {
                    return RC_INTERNAL;
                };
                let Ok(input) = serde_json::from_slice::<MenuUpsertInput>(&bytes) else {
                    return RC_INTERNAL;
                };
                let prefix = caller.data().menu_prefix.clone();
                let plugin = caller.data().plugin.clone();
                let Some(menu) = validate_menu(input, &prefix, &plugin) else {
                    return RC_INTERNAL;
                };
                let ctx = caller.data_mut();
                if !ctx.menus.contains_key(&menu.id) && ctx.menus.len() >= MAX_DYNAMIC_MENUS {
                    log::warn!(target: "plugin_app",
                        "[{plugin}] menu_upsert refused: {MAX_DYNAMIC_MENUS}-entry cap reached");
                    return RC_INTERNAL;
                }
                ctx.menus.insert(menu.id.clone(), menu);
                RC_OK
            },
        )
        .map_err(map_err)?;

    // bvx.menu_remove(id_ptr, id_len) -> i32.
    linker
        .func_wrap(
            "bvx",
            "menu_remove",
            |mut caller: Caller<'_, AppCtx>, ptr: i32, len: i32| -> i32 {
                if !caller.data().dynamic_menus {
                    return RC_FORBIDDEN;
                }
                let Some(bytes) = read_bytes(&mut caller, ptr, len) else {
                    return RC_INTERNAL;
                };
                let Ok(id) = String::from_utf8(bytes) else {
                    return RC_INTERNAL;
                };
                caller.data_mut().menus.remove(&id);
                RC_OK
            },
        )
        .map_err(map_err)?;

    // bvx.window_open(json_ptr, json_len) -> i32 (>= 0 handle) — gated
    // by windows_max_open > 0; clamped to the cap.
    linker
        .func_wrap(
            "bvx",
            "window_open",
            |mut caller: Caller<'_, AppCtx>, ptr: i32, len: i32| -> i32 {
                let max = caller.data().windows_max_open;
                if max == 0 {
                    return RC_FORBIDDEN;
                }
                let Some(bytes) = read_bytes(&mut caller, ptr, len) else {
                    return RC_INTERNAL;
                };
                let Ok(input) = serde_json::from_slice::<WindowOpenInput>(&bytes) else {
                    return RC_INTERNAL;
                };
                let prefix = caller.data().menu_prefix.clone();
                if !input.route.starts_with(&prefix) || input.route.contains("..") {
                    return RC_INTERNAL;
                }
                let ctx = caller.data_mut();
                if ctx.open_windows.len() as u32 >= max {
                    return RC_WINDOW_LIMIT;
                }
                let handle = ctx.next_window_handle;
                ctx.next_window_handle += 1;
                ctx.open_windows.push(handle);
                ctx.window_ops.push(WindowOp::Open {
                    handle,
                    route: input.route,
                    title: input.title,
                    width: input.width,
                    height: input.height,
                });
                handle as i32
            },
        )
        .map_err(map_err)?;

    // bvx.window_close(handle) -> i32.
    linker
        .func_wrap(
            "bvx",
            "window_close",
            |mut caller: Caller<'_, AppCtx>, handle: i32| -> i32 {
                if caller.data().windows_max_open == 0 || handle < 0 {
                    return RC_FORBIDDEN;
                }
                let h = handle as u32;
                let ctx = caller.data_mut();
                ctx.open_windows.retain(|x| *x != h);
                ctx.window_ops.push(WindowOp::Close { handle: h });
                RC_OK
            },
        )
        .map_err(map_err)?;

    // bvx.window_emit(handle, json_ptr, json_len) -> i32.
    linker
        .func_wrap(
            "bvx",
            "window_emit",
            |mut caller: Caller<'_, AppCtx>, handle: i32, ptr: i32, len: i32| -> i32 {
                if caller.data().windows_max_open == 0 || handle < 0 {
                    return RC_FORBIDDEN;
                }
                let Some(bytes) = read_bytes(&mut caller, ptr, len) else {
                    return RC_INTERNAL;
                };
                let Ok(payload) = String::from_utf8(bytes) else {
                    return RC_INTERNAL;
                };
                caller.data_mut().window_ops.push(WindowOp::Emit {
                    handle: handle as u32,
                    payload,
                });
                RC_OK
            },
        )
        .map_err(map_err)?;

    // bvx.api_request(req_ptr, req_len, out_ptr, out_max) -> i32 — async;
    // the vault-API bridge (Phase 4). Rides the user's session token; the
    // server ACL pipeline stays the sole authority.
    linker
        .func_wrap_async(
            "bvx",
            "api_request",
            |mut caller: Caller<'_, AppCtx>, args: (i32, i32, i32, i32)| {
                let (req_ptr, req_len, out_ptr, out_max) = args;
                Box::new(async move {
                    api_request_impl(&mut caller, req_ptr, req_len, out_ptr, out_max).await
                })
            },
        )
        .map_err(map_err)?;

    // bvx.net_http(req_ptr, req_len, out_ptr, out_max) -> i32 — async;
    // admin-granted outbound HTTPS (Phase 5), gated by `net_gate`.
    linker
        .func_wrap_async(
            "bvx",
            "net_http",
            |mut caller: Caller<'_, AppCtx>, args: (i32, i32, i32, i32)| {
                let (req_ptr, req_len, out_ptr, out_max) = args;
                Box::new(async move {
                    net_http_impl(&mut caller, req_ptr, req_len, out_ptr, out_max).await
                })
            },
        )
        .map_err(map_err)?;

    Ok(())
}

// ── bvx.api_request (Phase 4) ────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ApiRequestInput {
    op: String,
    path: String,
    #[serde(default)]
    data: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Substitute `{mount}` and enforce the request path stays inside the
/// plugin's mount **and** matches a declared `api_paths` prefix. Returns
/// the resolved path or `Err(())` (→ forbidden) without touching the
/// backend. Shares the `{mount}`/`..`/escape rules with
/// `plugin_surface_dispatch`.
fn resolve_api_path(path: &str, mount: &str, api_paths: &[String]) -> Result<String, ()> {
    let m = mount.trim_end_matches('/');
    let resolved = path.replace("{mount}", m);
    if resolved.contains('{') || resolved.contains("..") {
        return Err(());
    }
    if !resolved.starts_with(m) {
        return Err(());
    }
    let allowed = api_paths.iter().any(|p| {
        let pp = p.replace("{mount}", m);
        let pp = pp.trim_end_matches('/');
        resolved == pp || resolved.starts_with(&format!("{pp}/"))
    });
    if !allowed {
        return Err(());
    }
    Ok(resolved)
}

async fn api_request_impl(
    caller: &mut Caller<'_, AppCtx>,
    req_ptr: i32,
    req_len: i32,
    out_ptr: i32,
    out_max: i32,
) -> i32 {
    // Gate: no declared api_paths → the bridge is disabled.
    if caller.data().api_paths.is_empty() {
        return RC_FORBIDDEN;
    }
    let Some(bytes) = read_bytes(caller, req_ptr, req_len) else {
        return RC_INTERNAL;
    };
    let Ok(req) = serde_json::from_slice::<ApiRequestInput>(&bytes) else {
        return RC_INTERNAL;
    };
    let op = match req.op.as_str() {
        "read" => Operation::Read,
        "write" => Operation::Write,
        "delete" => Operation::Delete,
        "list" => Operation::List,
        _ => return RC_INTERNAL,
    };
    let mount = caller.data().mount.clone();
    let api_paths = caller.data().api_paths.clone();
    let resolved = match resolve_api_path(&req.path, &mount, &api_paths) {
        Ok(p) => p,
        Err(()) => {
            log::warn!(target: "plugin_app",
                "[{}] api_request denied: path `{}` outside api_paths",
                caller.data().plugin, req.path);
            return RC_FORBIDDEN;
        }
    };
    let Some(backend) = caller.data().backend.clone() else {
        return RC_INTERNAL;
    };
    let token = caller.data().token.clone();
    let namespace = caller.data().namespace.clone();
    let resp = backend
        .handle_with_namespace(op, &resolved, req.data, &token, namespace.as_deref())
        .await;
    let out = match resp {
        Ok(Some(r)) => serde_json::json!({ "data": r.data }),
        Ok(None) => serde_json::json!({ "data": null }),
        // Error envelope — a backend/ACL failure is data, not a host error.
        Err(e) => serde_json::json!({ "error": e.to_string() }),
    };
    let out_bytes = serde_json::to_vec(&out).unwrap_or_default();
    write_to_buffer(caller, &out_bytes, out_ptr, out_max)
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ── bvx.net_http (Phase 5) ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct NetRequestInput {
    #[serde(default = "default_method")]
    method: String,
    url: String,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    body_b64: Option<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

fn default_method() -> String {
    "GET".to_string()
}

/// Outcome of a `net_http` attempt: the terminal `(status, body, host)`
/// on success, or `(guest_code, short_reason, host)` on refusal/failure.
type NetResult = Result<(u16, Vec<u8>, String), (i32, &'static str, String)>;

async fn net_http_impl(
    caller: &mut Caller<'_, AppCtx>,
    req_ptr: i32,
    req_len: i32,
    out_ptr: i32,
    out_max: i32,
) -> i32 {
    let granted = caller.data().net_hosts.clone();
    let https_only = caller.data().net_https_only;
    let at = now_unix_ms();

    // First gate: no grant at all.
    if granted.is_empty() {
        caller.data_mut().push_net_call(NetCall {
            at_unix_ms: at,
            method: String::new(),
            host: String::new(),
            status: None,
            bytes: 0,
            outcome: "not_granted".into(),
        });
        return RC_NET_NOT_GRANTED;
    }

    let Some(bytes) = read_bytes(caller, req_ptr, req_len) else {
        return RC_INTERNAL;
    };
    let Ok(req) = serde_json::from_slice::<NetRequestInput>(&bytes) else {
        return RC_INTERNAL;
    };
    let method = req.method.clone();

    match net_fetch(&req, &granted, https_only).await {
        Ok((status, body, host)) => {
            let n = body.len();
            caller.data_mut().push_net_call(NetCall {
                at_unix_ms: at,
                method,
                host,
                status: Some(status),
                bytes: n,
                outcome: "ok".into(),
            });
            use base64::Engine;
            let out = serde_json::json!({
                "status": status,
                "bytes": n,
                "body_b64": base64::engine::general_purpose::STANDARD.encode(&body),
            });
            let out_bytes = serde_json::to_vec(&out).unwrap_or_default();
            write_to_buffer(caller, &out_bytes, out_ptr, out_max)
        }
        Err((code, reason, host)) => {
            caller.data_mut().push_net_call(NetCall {
                at_unix_ms: at,
                method,
                host,
                status: None,
                bytes: 0,
                outcome: reason.into(),
            });
            code
        }
    }
}

/// Resolve a host:port to its IP set (blocking getaddrinfo on the tokio
/// blocking pool). Returns `Err(())` on resolution failure.
async fn resolve_ips(host: &str, port: u16) -> Result<Vec<std::net::IpAddr>, ()> {
    let hostport = format!("{host}:{port}");
    tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        hostport
            .to_socket_addrs()
            .map(|it| it.map(|s| s.ip()).collect::<Vec<_>>())
            .map_err(|_| ())
    })
    .await
    .map_err(|_| ())?
}

/// Perform the request with manual, re-validated redirects. Every hop
/// (including the first) is checked by `net_gate` for scheme/host/port
/// and SSRF-safe resolved IPs; redirects are capped at
/// [`NET_MAX_REDIRECTS`]; the response body is streamed with a hard
/// [`MAX_NET_RESPONSE_BYTES`] cap; the timeout is clamped to
/// [`NET_TIMEOUT_MAX_MS`]; no cookie jar, no ambient proxy creds.
async fn net_fetch(req: &NetRequestInput, granted: &[String], https_only: bool) -> NetResult {
    use futures_util::StreamExt;

    let denied = |reason: &'static str, host: String| (RC_NET_HOST_DENIED, reason, host);

    let mut url =
        reqwest::Url::parse(&req.url).map_err(|_| denied("bad_url", String::new()))?;
    let method = reqwest::Method::from_bytes(req.method.to_uppercase().as_bytes())
        .map_err(|_| (RC_INTERNAL, "bad_method", String::new()))?;
    let timeout = std::time::Duration::from_millis(
        req.timeout_ms.unwrap_or(30_000).min(NET_TIMEOUT_MAX_MS),
    );
    let body = match &req.body_b64 {
        Some(b) => {
            use base64::Engine;
            Some(
                base64::engine::general_purpose::STANDARD
                    .decode(b)
                    .map_err(|_| (RC_INTERNAL, "bad_body_b64", String::new()))?,
            )
        }
        None => None,
    };

    // No redirect-following (we re-validate manually), no cookie store
    // (reqwest default), explicit timeout.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()
        .map_err(|_| (RC_INTERNAL, "client", String::new()))?;

    let mut hops = 0usize;
    loop {
        let host = url.host_str().unwrap_or_default().to_string();
        // 1–3: scheme / host allowlist / port.
        let target =
            crate::net_gate::validate_url(url.scheme(), url.host_str(), url.port(), granted, https_only)
                .map_err(|e| match e {
                    crate::net_gate::NetError::NotGranted => {
                        (RC_NET_NOT_GRANTED, "not_granted", host.clone())
                    }
                    crate::net_gate::NetError::HostDenied => (RC_NET_HOST_DENIED, "host_denied", host.clone()),
                })?;
        // 4: SSRF — resolved IPs must be public unless explicitly granted.
        let port = url.port_or_known_default().unwrap_or(443);
        let ips = resolve_ips(&target.host, port)
            .await
            .map_err(|_| denied("dns", host.clone()))?;
        crate::net_gate::check_resolved_ips(&target, &ips).map_err(|_| denied("ssrf", host.clone()))?;

        let mut rb = client.request(method.clone(), url.clone());
        for (k, v) in &req.headers {
            rb = rb.header(k, v);
        }
        if let Some(b) = &body {
            rb = rb.body(b.clone());
        }
        let resp = rb.send().await.map_err(|_| denied("send", host.clone()))?;
        let status = resp.status();

        if status.is_redirection() {
            if hops >= NET_MAX_REDIRECTS {
                return Err(denied("too_many_redirects", host));
            }
            let loc = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|h| h.to_str().ok())
                .ok_or_else(|| denied("redirect_no_location", host.clone()))?;
            let next = url.join(loc).map_err(|_| denied("bad_redirect", host.clone()))?;
            url = next;
            hops += 1;
            continue; // re-validate the new hop from the top
        }

        // Terminal response — stream the body with a hard cap.
        let code = status.as_u16();
        let mut stream = resp.bytes_stream();
        let mut buf: Vec<u8> = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| denied("body", host.clone()))?;
            if buf.len() + chunk.len() > MAX_NET_RESPONSE_BYTES {
                return Err(denied("body_too_large", host));
            }
            buf.extend_from_slice(&chunk);
        }
        return Ok((code, buf, host));
    }
}

/// A live app-module instance: persistent `Store` + `Instance`. Not
/// `Sync` (Wasmtime), but `Send`, so it lives behind the `AppState`
/// async mutex.
pub struct AppModuleInstance {
    pub plugin: String,
    pub version: String,
    pub sha256: String,
    store: Store<AppCtx>,
    instance: Instance,
    /// Last `bvx_tick` wall-clock ms; enforces the 30 s floor.
    last_tick_ms: i64,
    /// Last non-zero return / error, surfaced to the operator UX.
    pub last_error: Option<String>,
}

impl AppModuleInstance {
    /// Compile + instantiate a module and wire its `bvx.*` imports.
    /// Does not call `bvx_init` — the caller does that after storing
    /// the instance so an init that pushes menus is observed.
    pub async fn create(
        config: AppModuleConfig,
        wasm_bytes: &[u8],
    ) -> Result<Self, AppModuleError> {
        let module = Module::from_binary(engine(), wasm_bytes)
            .map_err(|e| AppModuleError::Compile(e.to_string()))?;

        let limits = StoreLimitsBuilder::new().memory_size(MEMORY_BYTES).build();
        let ctx = AppCtx {
            plugin: config.plugin.clone(),
            menu_prefix: format!("/plugin/{}/", config.plugin),
            mount: config.mount.clone(),
            dynamic_menus: config.caps.dynamic_menus,
            windows_max_open: config.caps.windows_max_open,
            api_paths: config.caps.api_paths.clone(),
            backend: config.backend.clone(),
            token: config.token.clone(),
            namespace: config.namespace.clone(),
            net_hosts: config.net_hosts.clone(),
            net_https_only: config.net_https_only,
            net_ring: Vec::new(),
            menus: BTreeMap::new(),
            open_windows: Vec::new(),
            next_window_handle: 1,
            window_ops: Vec::new(),
            response_window: None,
            limits,
        };
        let mut store: Store<AppCtx> = Store::new(engine(), ctx);
        store.limiter(|c| &mut c.limits);
        store
            .set_fuel(FUEL_PER_CALL)
            .map_err(|e| AppModuleError::Instantiate(e.to_string()))?;

        let mut linker: Linker<AppCtx> = Linker::new(engine());
        register_bvx_imports(&mut linker)?;

        let instance = linker
            .instantiate_async(&mut store, &module)
            .await
            .map_err(|e| AppModuleError::Instantiate(e.to_string()))?;

        // Required exports.
        instance
            .get_memory(&mut store, "memory")
            .ok_or(AppModuleError::MissingMemory)?;
        instance
            .get_typed_func::<i32, i32>(&mut store, "bv_alloc")
            .map_err(|_| AppModuleError::MissingAlloc)?;

        Ok(Self {
            plugin: config.plugin,
            version: config.version,
            sha256: config.sha256,
            store,
            instance,
            last_tick_ms: 0,
            last_error: None,
        })
    }

    /// Snapshot of the plugin's current dynamic menus.
    pub fn menus(&self) -> Vec<DynamicMenu> {
        self.store.data().menus.values().cloned().collect()
    }

    /// Snapshot of the network call ring buffer (operator UX).
    pub fn net_calls(&self) -> Vec<NetCall> {
        self.store.data().net_ring.clone()
    }

    /// Drain the window ops recorded during the most recent call.
    pub fn drain_window_ops(&mut self) -> Vec<WindowOp> {
        std::mem::take(&mut self.store.data_mut().window_ops)
    }

    /// Remove a handle from the open set (called when the webview
    /// closes a plugin window).
    pub fn mark_window_closed(&mut self, handle: u32) {
        self.store.data_mut().open_windows.retain(|h| *h != handle);
    }

    /// Currently-open window handles — used to close the plugin's
    /// windows on instance teardown.
    pub fn open_window_handles(&self) -> Vec<u32> {
        self.store.data().open_windows.clone()
    }

    pub async fn call_init(&mut self, ctx_json: &[u8]) -> Result<Option<i32>, AppModuleError> {
        self.invoke_ptr_len("bvx_init", ctx_json).await
    }

    pub async fn call_menu_click(&mut self, ev_json: &[u8]) -> Result<Option<i32>, AppModuleError> {
        self.invoke_ptr_len("bvx_menu_click", ev_json).await
    }

    pub async fn call_window_event(
        &mut self,
        ev_json: &[u8],
    ) -> Result<Option<i32>, AppModuleError> {
        self.invoke_ptr_len("bvx_window_event", ev_json).await
    }

    /// Call `bvx_tick(now_ms)` if the 30 s floor has elapsed. Returns
    /// `Ok(None)` when the export is absent or the floor hasn't passed.
    pub async fn maybe_tick(&mut self, now_ms: i64) -> Result<Option<i32>, AppModuleError> {
        if now_ms - self.last_tick_ms < MIN_TICK_INTERVAL_MS {
            return Ok(None);
        }
        let Ok(func) = self
            .instance
            .get_typed_func::<i64, i32>(&mut self.store, "bvx_tick")
        else {
            return Ok(None);
        };
        self.last_tick_ms = now_ms;
        self.reset_for_call()?;
        let status = func
            .call_async(&mut self.store, now_ms)
            .await
            .map_err(|e| AppModuleError::Invocation(e.to_string()))?;
        Ok(Some(status))
    }

    fn reset_for_call(&mut self) -> Result<(), AppModuleError> {
        self.store
            .set_fuel(FUEL_PER_CALL)
            .map_err(|e| AppModuleError::Instantiate(e.to_string()))?;
        let d = self.store.data_mut();
        d.response_window = None;
        d.window_ops.clear();
        Ok(())
    }

    /// Invoke an optional `(ptr,len) -> i32` entry point. Returns
    /// `Ok(None)` when the export is absent (all entry points except
    /// `memory`/`bv_alloc` are optional).
    async fn invoke_ptr_len(
        &mut self,
        export: &str,
        json: &[u8],
    ) -> Result<Option<i32>, AppModuleError> {
        if json.len() > MAX_PAYLOAD_BYTES {
            return Err(AppModuleError::InputTooLarge(json.len()));
        }
        let Ok(func) = self
            .instance
            .get_typed_func::<(i32, i32), i32>(&mut self.store, export)
        else {
            return Ok(None);
        };
        self.reset_for_call()?;
        let alloc = self
            .instance
            .get_typed_func::<i32, i32>(&mut self.store, "bv_alloc")
            .map_err(|_| AppModuleError::MissingAlloc)?;
        let len = json.len() as i32;
        let ptr = alloc
            .call_async(&mut self.store, len)
            .await
            .map_err(|e| AppModuleError::Invocation(e.to_string()))?;
        let memory = self
            .instance
            .get_memory(&mut self.store, "memory")
            .ok_or(AppModuleError::MissingMemory)?;
        memory
            .write(&mut self.store, ptr as usize, json)
            .map_err(|e| AppModuleError::Invocation(e.to_string()))?;
        let status = func
            .call_async(&mut self.store, (ptr, len))
            .await
            .map_err(|e| AppModuleError::Invocation(e.to_string()))?;
        Ok(Some(status))
    }
}

// ── Tauri glue: instance-map management, windows, events, commands ───
//
// The core above is Tauri-free and unit-tested. Everything below wires
// it into `AppState`, the webview event bus, and secondary windows.

use std::collections::HashMap;

use bv_client::SurfaceCache;
use bv_plugin_surface::ActiveSurfaceBundle;
use tauri::{AppHandle, Emitter, Manager, Runtime, State, WebviewUrl, WebviewWindowBuilder};

use crate::error::CmdResult;
use crate::state::AppState;

/// Union of every live instance's dynamic menus.
fn collect_menus(map: &HashMap<String, AppModuleInstance>) -> Vec<DynamicMenu> {
    let mut out = Vec::new();
    for inst in map.values() {
        out.extend(inst.menus());
    }
    out
}

/// Push the current dynamic-menu set to the webview. The frontend
/// replaces its dynamic slice wholesale, so an empty slice clears it.
fn emit_menus<R: Runtime>(app: &AppHandle<R>, menus: &[DynamicMenu]) {
    let _ = app.emit("plugin-menus-updated", menus);
}

/// Apply the window ops a plugin recorded during an entry-point call.
/// Runs after the instance lock is released (window construction is
/// synchronous but shouldn't hold the map lock).
fn apply_window_ops<R: Runtime>(app: &AppHandle<R>, plugin: &str, ops: Vec<WindowOp>) {
    for op in ops {
        match op {
            WindowOp::Open {
                handle,
                route,
                title,
                width,
                height,
            } => {
                let label = format!("plugin-{plugin}-{handle}");
                // Host-drawn title, always prefixed with the plugin name
                // so a plugin window can't spoof host chrome.
                let shown = if title.trim().is_empty() { &route } else { &title };
                let title_full = format!("{plugin} — {shown}");
                // Route already validated to start with `/plugin/<name>/`.
                // The `pluginWindow` query param drives the bare (chrome-
                // less) render + `subscribe` event routing on the frontend.
                let url = format!("index.html#{route}?pluginWindow={handle}");
                let built = WebviewWindowBuilder::new(app, &label, WebviewUrl::App(url.into()))
                    .title(title_full)
                    .inner_size(width.unwrap_or(720.0), height.unwrap_or(520.0))
                    .resizable(true)
                    .build();
                match built {
                    Ok(win) => {
                        let app2 = app.clone();
                        let plugin2 = plugin.to_string();
                        win.on_window_event(move |ev| {
                            if let tauri::WindowEvent::CloseRequested { .. } = ev {
                                let app3 = app2.clone();
                                let plugin3 = plugin2.clone();
                                tauri::async_runtime::spawn(async move {
                                    handle_window_closed(&app3, &plugin3, handle).await;
                                });
                            }
                        });
                    }
                    Err(e) => log::warn!(target: "plugin_app",
                        "[{plugin}] window build failed: {e}"),
                }
            }
            WindowOp::Close { handle } => {
                let label = format!("plugin-{plugin}-{handle}");
                if let Some(w) = app.get_webview_window(&label) {
                    let _ = w.close();
                }
            }
            WindowOp::Emit { handle, payload } => {
                // Per-handle event name scopes the payload to the window
                // that subscribed (mirrors the SSH/RDP session pattern).
                let _ = app.emit(&format!("plugin-window-data-{handle}"), payload);
            }
        }
    }
}

/// Re-instantiate the app-module set to match a freshly-fetched surface
/// bundle: (re)build changed/new modules, tear down modules whose plugin
/// dropped out, then emit the merged dynamic-menu set. Called from the
/// surface refresh + watch commands.
pub async fn sync_from_bundle<R: Runtime>(
    app: &AppHandle<R>,
    state: &AppState,
    bundle: &ActiveSurfaceBundle,
    backend: Arc<dyn Backend>,
    cache: &SurfaceCache,
    token: &str,
) {
    use std::collections::HashSet;

    // Entries that ship an app module.
    let desired: Vec<&bv_plugin_surface::ActiveSurfaceEntry> = bundle
        .entries
        .iter()
        .filter(|e| e.app_module.is_some())
        .collect();
    let desired_names: HashSet<&str> = desired.iter().map(|e| e.plugin.as_str()).collect();

    // Session context every app module's api/net imports ride.
    let namespace = state.active_namespace.lock().await.clone();

    // Snapshot current instances (brief lock) to decide what to rebuild.
    let current: Vec<(String, String)> = {
        let g = state.app_modules.lock().await;
        g.iter().map(|(k, v)| (k.clone(), v.sha256.clone())).collect()
    };
    let current_sha: HashMap<&str, &str> =
        current.iter().map(|(p, s)| (p.as_str(), s.as_str())).collect();

    // Fetch bytes for new/changed modules (async; done outside the lock).
    struct Rebuild {
        config: AppModuleConfig,
        bytes: Vec<u8>,
    }
    let mut rebuilds: Vec<Rebuild> = Vec::new();
    for e in &desired {
        let am = e.app_module.as_ref().expect("filtered to Some");
        let unchanged = current_sha.get(e.plugin.as_str()) == Some(&am.sha256.as_str());
        if unchanged {
            continue;
        }
        match bv_client::ensure_asset(&*backend, cache, &e.plugin, &e.version, &am.sha256, token)
            .await
        {
            Ok(Some(bytes)) => rebuilds.push(Rebuild {
                config: AppModuleConfig {
                    plugin: e.plugin.clone(),
                    version: e.version.clone(),
                    sha256: am.sha256.clone(),
                    mount: e.mount.clone(),
                    caps: AppCapsGate {
                        dynamic_menus: am.dynamic_menus,
                        windows_max_open: am.windows_max_open,
                        api_paths: am.api_paths.clone(),
                    },
                    backend: Some(backend.clone()),
                    token: token.to_string(),
                    namespace: namespace.clone(),
                    // Granted hosts arrive live in the bundle grant; empty
                    // (or absent) means the plugin is ungranted.
                    net_hosts: e
                        .grant
                        .as_ref()
                        .map(|g| g.net_hosts.clone())
                        .unwrap_or_default(),
                    net_https_only: am.net_https_only,
                },
                bytes,
            }),
            Ok(None) => log::warn!(target: "plugin_app",
                "[{}] app-module asset {} unavailable on server", e.plugin, am.sha256),
            Err(err) => log::warn!(target: "plugin_app",
                "[{}] app-module asset fetch failed: {err}", e.plugin),
        }
    }

    // Apply under the lock: remove stale + replaced, build + init new.
    let mut windows_to_close: Vec<String> = Vec::new();
    let mut init_ops: Vec<(String, Vec<WindowOp>)> = Vec::new();
    let menus;
    {
        let mut g = state.app_modules.lock().await;
        // Tear down instances whose plugin is no longer present.
        let stale: Vec<String> = g
            .keys()
            .filter(|k| !desired_names.contains(k.as_str()))
            .cloned()
            .collect();
        for p in stale {
            if let Some(inst) = g.remove(&p) {
                for h in inst.open_window_handles() {
                    windows_to_close.push(format!("plugin-{p}-{h}"));
                }
            }
        }
        for rb in rebuilds {
            let plugin = rb.config.plugin.clone();
            let version = rb.config.version.clone();
            let mount = rb.config.mount.clone();
            // Replacing an existing version: close its windows first.
            if let Some(old) = g.remove(&plugin) {
                for h in old.open_window_handles() {
                    windows_to_close.push(format!("plugin-{plugin}-{h}"));
                }
            }
            match AppModuleInstance::create(rb.config, &rb.bytes).await {
                Ok(mut inst) => {
                    let ctx = serde_json::json!({
                        "plugin": plugin,
                        "version": version,
                        "mount": mount,
                        "policies": [],
                        "locale": "en",
                    })
                    .to_string();
                    if let Err(e) = inst.call_init(ctx.as_bytes()).await {
                        log::warn!(target: "plugin_app", "[{plugin}] bvx_init failed: {e}");
                        inst.last_error = Some(e.to_string());
                    }
                    let ops = inst.drain_window_ops();
                    if !ops.is_empty() {
                        init_ops.push((plugin.clone(), ops));
                    }
                    g.insert(plugin.clone(), inst);
                }
                Err(e) => log::warn!(target: "plugin_app",
                    "[{plugin}] app module failed to instantiate: {e}"),
            }
        }
        menus = collect_menus(&g);
    }

    for label in windows_to_close {
        if let Some(w) = app.get_webview_window(&label) {
            let _ = w.close();
        }
    }
    for (plugin, ops) in init_ops {
        apply_window_ops(app, &plugin, ops);
    }
    emit_menus(app, &menus);
}

/// Tear down every app-module instance (sign-out / vault-switch / seal),
/// closing their windows and clearing the webview's dynamic menus.
pub async fn teardown_all<R: Runtime>(app: &AppHandle<R>, state: &AppState) {
    let mut labels = Vec::new();
    {
        let mut g = state.app_modules.lock().await;
        for (p, inst) in g.drain() {
            for h in inst.open_window_handles() {
                labels.push(format!("plugin-{p}-{h}"));
            }
        }
    }
    for l in labels {
        if let Some(w) = app.get_webview_window(&l) {
            let _ = w.close();
        }
    }
    emit_menus(app, &[]);
}

/// Deliver a window's `closed` event back into the owning instance,
/// then apply any windows/menus it produced in response.
pub async fn handle_window_closed<R: Runtime>(app: &AppHandle<R>, plugin: &str, handle: u32) {
    // Resolve state from the owned handle so the spawned close-event
    // future captures only `'static` data (Send).
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let state = state.inner();
    let mut g = state.app_modules.lock().await;
    let ops = match g.get_mut(plugin) {
        Some(inst) => {
            inst.mark_window_closed(handle);
            let ev = serde_json::json!({ "handle": handle, "kind": "closed" }).to_string();
            let _ = inst.call_window_event(ev.as_bytes()).await;
            inst.drain_window_ops()
        }
        None => return,
    };
    let menus = collect_menus(&g);
    drop(g);
    apply_window_ops(app, plugin, ops);
    emit_menus(app, &menus);
}

/// Fire `bvx_tick` on every instance whose 30 s floor has elapsed, then
/// re-emit menus (a tick may update a badge). Called opportunistically
/// from the surface long-poll loop.
pub async fn tick_all<R: Runtime>(app: &AppHandle<R>, state: &AppState) {
    let now = now_unix_ms();
    let mut pending: Vec<(String, Vec<WindowOp>)> = Vec::new();
    let menus;
    {
        let mut g = state.app_modules.lock().await;
        let plugins: Vec<String> = g.keys().cloned().collect();
        for p in plugins {
            if let Some(inst) = g.get_mut(&p) {
                match inst.maybe_tick(now).await {
                    Ok(Some(_)) => {
                        let ops = inst.drain_window_ops();
                        if !ops.is_empty() {
                            pending.push((p.clone(), ops));
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        log::warn!(target: "plugin_app", "[{p}] bvx_tick failed: {e}");
                        inst.last_error = Some(e.to_string());
                    }
                }
            }
        }
        menus = collect_menus(&g);
    }
    for (plugin, ops) in pending {
        apply_window_ops(app, &plugin, ops);
    }
    emit_menus(app, &menus);
}

/// Operator UX: per-plugin app-module state for the Plugins admin page
/// (running / errored / menu count).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AppModuleStatus {
    pub plugin: String,
    pub version: String,
    pub menu_count: usize,
    /// `Some(message)` when the last entry-point call trapped/failed.
    pub errored: Option<String>,
}

#[tauri::command]
pub async fn plugin_app_status(state: State<'_, AppState>) -> CmdResult<Vec<AppModuleStatus>> {
    let g = state.app_modules.lock().await;
    Ok(g.values()
        .map(|i| AppModuleStatus {
            plugin: i.plugin.clone(),
            version: i.version.clone(),
            menu_count: i.menus().len(),
            errored: i.last_error.clone(),
        })
        .collect())
}

/// Phase 5: the per-plugin `bvx.net_http` call ring buffer (last 100),
/// so an admin can see exactly what a granted plugin does with the grant.
#[tauri::command]
pub async fn plugin_app_net_calls(
    state: State<'_, AppState>,
    plugin: String,
) -> CmdResult<Vec<NetCall>> {
    let g = state.app_modules.lock().await;
    Ok(g.get(&plugin).map(|i| i.net_calls()).unwrap_or_default())
}

/// Frontend calls this when a user clicks a plugin's *dynamic* menu, so
/// the plugin can react (`bvx_menu_click`) — e.g. open a window.
#[tauri::command]
pub async fn plugin_app_menu_click<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    plugin: String,
    menu_id: String,
) -> CmdResult<()> {
    let mut g = state.app_modules.lock().await;
    let ops = match g.get_mut(&plugin) {
        Some(inst) => {
            let ev = serde_json::json!({ "id": menu_id }).to_string();
            if let Err(e) = inst.call_menu_click(ev.as_bytes()).await {
                log::warn!(target: "plugin_app", "[{plugin}] bvx_menu_click failed: {e}");
                inst.last_error = Some(e.to_string());
            }
            inst.drain_window_ops()
        }
        None => return Ok(()),
    };
    let menus = collect_menus(&g);
    drop(g);
    apply_window_ops(&app, &plugin, ops);
    emit_menus(&app, &menus);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(bytes))
    }

    fn caps(dynamic_menus: bool, windows_max_open: u32) -> AppCapsGate {
        AppCapsGate {
            dynamic_menus,
            windows_max_open,
            api_paths: vec![],
        }
    }

    /// Build a config for a `totp`-plugin instance with the given caps
    /// (no backend, no net grant) — enough for the menu/window tests.
    fn cfg(caps: AppCapsGate, sha256: String) -> AppModuleConfig {
        AppModuleConfig {
            plugin: "totp".into(),
            version: "1.0.0".into(),
            sha256,
            mount: "secret/totp".into(),
            caps,
            backend: None,
            token: String::new(),
            namespace: None,
            net_hosts: vec![],
            net_https_only: true,
        }
    }

    async fn instance(caps: AppCapsGate, bytes: &[u8]) -> AppModuleInstance {
        AppModuleInstance::create(cfg(caps, sha(bytes)), bytes).await.unwrap()
    }

    /// A module whose `bvx_init` upserts one menu (with a badge) via
    /// `bvx.menu_upsert`, embedding the JSON in a data segment.
    fn menu_module_wat(menu_json: &str) -> Vec<u8> {
        let bytes = menu_json.as_bytes();
        // Place JSON at offset 4096; bv_alloc hands out from 8192.
        let wat = format!(
            r#"
            (module
              (import "bvx" "menu_upsert" (func $upsert (param i32 i32) (result i32)))
              (import "bvx" "now_unix_ms" (func $now (result i64)))
              (import "bvx" "log" (func $log (param i32 i32 i32)))
              (import "bvx" "set_result" (func $set (param i32 i32)))
              (memory (export "memory") 2)
              (data (i32.const 4096) "{escaped}")
              (func (export "bv_alloc") (param i32) (result i32) i32.const 8192)
              (func (export "bvx_init") (param i32 i32) (result i32)
                (call $upsert (i32.const 4096) (i32.const {len}))))
        "#,
            escaped = menu_json.replace('"', "\\22"),
            len = bytes.len(),
        );
        wat::parse_str(&wat).expect("valid wat")
    }

    #[tokio::test]
    async fn init_upserts_a_dynamic_menu() {
        let json = r#"{"id":"totp.expiring","label":"Expiring soon","section":"secrets","route":"/plugin/totp/expiring","badge":"3"}"#;
        let bytes = menu_module_wat(json);
        let mut inst = instance(caps(true, 0), &bytes).await;
        let status = inst.call_init(b"{}").await.unwrap();
        assert_eq!(status, Some(RC_OK));
        let menus = inst.menus();
        assert_eq!(menus.len(), 1);
        assert_eq!(menus[0].id, "totp.expiring");
        assert_eq!(menus[0].badge.as_deref(), Some("3"));
        assert_eq!(menus[0].plugin, "totp");
    }

    #[tokio::test]
    async fn menu_upsert_forbidden_without_capability() {
        // dynamic_menus = false → bvx.menu_upsert returns -2, no menu.
        let json = r#"{"id":"x","label":"X","section":"secrets","route":"/plugin/totp/x"}"#;
        let bytes = menu_module_wat(json);
        let mut inst = instance(caps(false, 0), &bytes).await;
        let status = inst.call_init(b"{}").await.unwrap();
        assert_eq!(status, Some(RC_FORBIDDEN));
        assert!(inst.menus().is_empty());
    }

    #[tokio::test]
    async fn menu_with_route_outside_plugin_is_rejected() {
        // route points at another plugin → validate_menu rejects → -4.
        let json = r#"{"id":"x","label":"X","section":"secrets","route":"/plugin/other/x"}"#;
        let bytes = menu_module_wat(json);
        let mut inst = instance(caps(true, 0), &bytes).await;
        let status = inst.call_init(b"{}").await.unwrap();
        assert_eq!(status, Some(RC_INTERNAL));
        assert!(inst.menus().is_empty());
    }

    #[tokio::test]
    async fn missing_optional_export_is_none() {
        // Module with no bvx_menu_click export → call returns Ok(None).
        let json = r#"{"id":"x","label":"X","section":"secrets","route":"/plugin/totp/x"}"#;
        let bytes = menu_module_wat(json);
        let mut inst = instance(caps(true, 0), &bytes).await;
        assert_eq!(inst.call_menu_click(b"{}").await.unwrap(), None);
    }

    #[tokio::test]
    async fn unknown_undeclared_import_fails_instantiation() {
        // Importing a symbol the host doesn't register must fail.
        let wat = r#"
            (module
              (import "bvx" "does_not_exist" (func (param i32 i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "bv_alloc") (param i32) (result i32) i32.const 0)
              (func (export "bvx_init") (param i32 i32) (result i32) i32.const 0))
        "#;
        let bytes = wat::parse_str(wat).unwrap();
        let result = AppModuleInstance::create(cfg(caps(true, 0), sha(&bytes)), &bytes).await;
        assert!(matches!(result, Err(AppModuleError::Instantiate(_))));
    }

    #[tokio::test]
    async fn window_open_records_op_and_clamps() {
        // A module whose init opens two windows; max_open = 1 → 2nd -8.
        let wat = r#"
            (module
              (import "bvx" "window_open" (func $open (param i32 i32) (result i32)))
              (memory (export "memory") 1)
              (data (i32.const 0) "{\22route\22:\22/plugin/totp/review\22}")
              (func (export "bv_alloc") (param i32) (result i32) i32.const 2048)
              (func (export "bvx_init") (param i32 i32) (result i32)
                (drop (call $open (i32.const 0) (i32.const 31)))
                (call $open (i32.const 0) (i32.const 31))))
        "#;
        let bytes = wat::parse_str(wat).unwrap();
        let mut inst = instance(caps(false, 1), &bytes).await;
        // 2nd open hits the cap → returns WINDOW_LIMIT.
        let status = inst.call_init(b"{}").await.unwrap();
        assert_eq!(status, Some(RC_WINDOW_LIMIT));
        let ops = inst.drain_window_ops();
        assert_eq!(ops.len(), 1, "only the first open should be recorded");
        assert!(matches!(&ops[0], WindowOp::Open { route, .. } if route == "/plugin/totp/review"));
    }

    #[tokio::test]
    async fn window_open_forbidden_without_capability() {
        let wat = r#"
            (module
              (import "bvx" "window_open" (func $open (param i32 i32) (result i32)))
              (memory (export "memory") 1)
              (data (i32.const 0) "{\22route\22:\22/plugin/totp/review\22}")
              (func (export "bv_alloc") (param i32) (result i32) i32.const 2048)
              (func (export "bvx_init") (param i32 i32) (result i32)
                (call $open (i32.const 0) (i32.const 31))))
        "#;
        let bytes = wat::parse_str(wat).unwrap();
        let mut inst = instance(caps(true, 0), &bytes).await;
        assert_eq!(inst.call_init(b"{}").await.unwrap(), Some(RC_FORBIDDEN));
        assert!(inst.drain_window_ops().is_empty());
    }

    // ── Phase 4: bvx.api_request path authorization ──

    #[test]
    fn resolve_api_path_allows_mount_scoped() {
        let api = vec!["{mount}/".to_string()];
        assert_eq!(
            resolve_api_path("{mount}/approvals/42", "secret/totp", &api),
            Ok("secret/totp/approvals/42".to_string())
        );
    }

    #[test]
    fn resolve_api_path_refuses_other_mount_and_sys() {
        let api = vec!["{mount}/".to_string()];
        // Another mount / sys / traversal / unresolved placeholder.
        assert!(resolve_api_path("secret/other/x", "secret/totp", &api).is_err());
        assert!(resolve_api_path("sys/plugins", "secret/totp", &api).is_err());
        assert!(resolve_api_path("{mount}/../other", "secret/totp", &api).is_err());
        assert!(resolve_api_path("{mount}/a/{name}", "secret/totp", &api).is_err());
    }

    #[test]
    fn resolve_api_path_honours_narrow_prefix() {
        // A plugin that only declared `{mount}/public/` can't reach
        // `{mount}/private/`.
        let api = vec!["{mount}/public/".to_string()];
        assert!(resolve_api_path("{mount}/public/x", "secret/totp", &api).is_ok());
        assert!(resolve_api_path("{mount}/private/x", "secret/totp", &api).is_err());
    }

    #[tokio::test]
    async fn api_request_forbidden_without_api_paths() {
        // No declared api_paths → the bridge is disabled → -2, and the
        // backend is never touched (backend is None here).
        let wat = r#"
            (module
              (import "bvx" "api_request" (func $api (param i32 i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "bv_alloc") (param i32) (result i32) i32.const 4096)
              (func (export "bvx_init") (param i32 i32) (result i32)
                (call $api (i32.const 0) (i32.const 0) (i32.const 4096) (i32.const 1024))))
        "#;
        let bytes = wat::parse_str(wat).unwrap();
        // caps with empty api_paths (the default from `caps`).
        let mut inst = instance(caps(false, 0), &bytes).await;
        assert_eq!(inst.call_init(b"{}").await.unwrap(), Some(RC_FORBIDDEN));
    }

    // ── Phase 5: bvx.net_http grant gate ──

    #[tokio::test]
    async fn net_http_not_granted_without_grant() {
        // net_hosts empty (no admin grant) → -6, recorded in the ring.
        let wat = r#"
            (module
              (import "bvx" "net_http" (func $net (param i32 i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "bv_alloc") (param i32) (result i32) i32.const 4096)
              (func (export "bvx_init") (param i32 i32) (result i32)
                (call $net (i32.const 0) (i32.const 0) (i32.const 4096) (i32.const 1024))))
        "#;
        let bytes = wat::parse_str(wat).unwrap();
        let mut inst = instance(caps(false, 0), &bytes).await;
        assert_eq!(inst.call_init(b"{}").await.unwrap(), Some(RC_NET_NOT_GRANTED));
        let calls = inst.net_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].outcome, "not_granted");
    }
}
