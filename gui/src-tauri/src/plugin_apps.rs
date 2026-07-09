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

use serde::{Deserialize, Serialize};
use thiserror::Error;
use wasmtime::{
    AsContext, Caller, Engine, Instance, Linker, Module, Store, StoreLimits, StoreLimitsBuilder,
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

// Return codes shared with the guest ABI (mirror the server `bv` codes;
// -6/-7 reserved for net, added in Phase 5).
const RC_OK: i32 = 0;
const RC_FORBIDDEN: i32 = -2;
const RC_INTERNAL: i32 = -4;
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
    /// Consumed by the `bvx.api_request` gate in Phase 4 (the vault-API
    /// bridge); carried now so the instance already knows its scope.
    #[allow(dead_code)]
    pub api_paths: Vec<String>,
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
    // capability gates copied from the manifest at build time
    dynamic_menus: bool,
    windows_max_open: u32,
    // accumulated state
    menus: BTreeMap<String, DynamicMenu>,
    open_windows: Vec<u32>,
    next_window_handle: u32,
    window_ops: Vec<WindowOp>,
    response_window: Option<(u32, u32)>,
    limits: StoreLimits,
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

/// Process-global fuel-metering engine for app modules.
fn engine() -> &'static Engine {
    use std::sync::OnceLock;
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
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

    Ok(())
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
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
    pub fn create(
        plugin: &str,
        version: &str,
        sha256: &str,
        caps: &AppCapsGate,
        wasm_bytes: &[u8],
    ) -> Result<Self, AppModuleError> {
        let module = Module::from_binary(engine(), wasm_bytes)
            .map_err(|e| AppModuleError::Compile(e.to_string()))?;

        let limits = StoreLimitsBuilder::new().memory_size(MEMORY_BYTES).build();
        let ctx = AppCtx {
            plugin: plugin.to_string(),
            menu_prefix: format!("/plugin/{plugin}/"),
            dynamic_menus: caps.dynamic_menus,
            windows_max_open: caps.windows_max_open,
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
            .instantiate(&mut store, &module)
            .map_err(|e| AppModuleError::Instantiate(e.to_string()))?;

        // Required exports.
        instance
            .get_memory(&mut store, "memory")
            .ok_or(AppModuleError::MissingMemory)?;
        instance
            .get_typed_func::<i32, i32>(&mut store, "bv_alloc")
            .map_err(|_| AppModuleError::MissingAlloc)?;

        Ok(Self {
            plugin: plugin.to_string(),
            version: version.to_string(),
            sha256: sha256.to_string(),
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

    pub fn call_init(&mut self, ctx_json: &[u8]) -> Result<Option<i32>, AppModuleError> {
        self.invoke_ptr_len("bvx_init", ctx_json)
    }

    pub fn call_menu_click(&mut self, ev_json: &[u8]) -> Result<Option<i32>, AppModuleError> {
        self.invoke_ptr_len("bvx_menu_click", ev_json)
    }

    pub fn call_window_event(&mut self, ev_json: &[u8]) -> Result<Option<i32>, AppModuleError> {
        self.invoke_ptr_len("bvx_window_event", ev_json)
    }

    /// Call `bvx_tick(now_ms)` if the 30 s floor has elapsed. Returns
    /// `Ok(None)` when the export is absent or the floor hasn't passed.
    pub fn maybe_tick(&mut self, now_ms: i64) -> Result<Option<i32>, AppModuleError> {
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
            .call(&mut self.store, now_ms)
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
    fn invoke_ptr_len(
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
            .call(&mut self.store, len)
            .map_err(|e| AppModuleError::Invocation(e.to_string()))?;
        let memory = self
            .instance
            .get_memory(&mut self.store, "memory")
            .ok_or(AppModuleError::MissingMemory)?;
        memory
            .write(&mut self.store, ptr as usize, json)
            .map_err(|e| AppModuleError::Invocation(e.to_string()))?;
        let status = func
            .call(&mut self.store, (ptr, len))
            .map_err(|e| AppModuleError::Invocation(e.to_string()))?;
        Ok(Some(status))
    }
}

// ── Tauri glue: instance-map management, windows, events, commands ───
//
// The core above is Tauri-free and unit-tested. Everything below wires
// it into `AppState`, the webview event bus, and secondary windows.

use std::collections::HashMap;

use bv_client::{Backend, SurfaceCache};
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
    backend: &dyn Backend,
    cache: &SurfaceCache,
    token: &str,
) {
    use std::collections::HashSet;

    // Desired app modules from the bundle: (plugin, version, mount, ref).
    let desired: Vec<(&str, &str, &str, &bv_plugin_surface::AppModuleRef)> = bundle
        .entries
        .iter()
        .filter_map(|e| {
            e.app_module
                .as_ref()
                .map(|am| (e.plugin.as_str(), e.version.as_str(), e.mount.as_str(), am))
        })
        .collect();
    let desired_names: HashSet<&str> = desired.iter().map(|(p, _, _, _)| *p).collect();

    // Snapshot current instances (brief lock) to decide what to rebuild.
    let current: Vec<(String, String)> = {
        let g = state.app_modules.lock().await;
        g.iter().map(|(k, v)| (k.clone(), v.sha256.clone())).collect()
    };
    let current_sha: HashMap<&str, &str> =
        current.iter().map(|(p, s)| (p.as_str(), s.as_str())).collect();

    // Fetch bytes for new/changed modules (async; done outside the lock).
    struct Rebuild {
        plugin: String,
        version: String,
        mount: String,
        sha256: String,
        caps: AppCapsGate,
        bytes: Vec<u8>,
    }
    let mut rebuilds: Vec<Rebuild> = Vec::new();
    for (plugin, version, mount, am) in &desired {
        let unchanged = current_sha.get(plugin) == Some(&am.sha256.as_str());
        if unchanged {
            continue;
        }
        match bv_client::ensure_asset(backend, cache, plugin, version, &am.sha256, token).await {
            Ok(Some(bytes)) => rebuilds.push(Rebuild {
                plugin: plugin.to_string(),
                version: version.to_string(),
                mount: mount.to_string(),
                sha256: am.sha256.clone(),
                caps: AppCapsGate {
                    dynamic_menus: am.dynamic_menus,
                    windows_max_open: am.windows_max_open,
                    api_paths: am.api_paths.clone(),
                },
                bytes,
            }),
            Ok(None) => log::warn!(target: "plugin_app",
                "[{plugin}] app-module asset {} unavailable on server", am.sha256),
            Err(e) => log::warn!(target: "plugin_app",
                "[{plugin}] app-module asset fetch failed: {e}"),
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
            // Replacing an existing version: close its windows first.
            if let Some(old) = g.remove(&rb.plugin) {
                for h in old.open_window_handles() {
                    windows_to_close.push(format!("plugin-{}-{h}", rb.plugin));
                }
            }
            match AppModuleInstance::create(
                &rb.plugin,
                &rb.version,
                &rb.sha256,
                &rb.caps,
                &rb.bytes,
            ) {
                Ok(mut inst) => {
                    let ctx = serde_json::json!({
                        "plugin": rb.plugin,
                        "version": rb.version,
                        "mount": rb.mount,
                        "policies": [],
                        "locale": "en",
                    })
                    .to_string();
                    if let Err(e) = inst.call_init(ctx.as_bytes()) {
                        log::warn!(target: "plugin_app",
                            "[{}] bvx_init failed: {e}", rb.plugin);
                        inst.last_error = Some(e.to_string());
                    }
                    let ops = inst.drain_window_ops();
                    if !ops.is_empty() {
                        init_ops.push((rb.plugin.clone(), ops));
                    }
                    g.insert(rb.plugin.clone(), inst);
                }
                Err(e) => log::warn!(target: "plugin_app",
                    "[{}] app module failed to instantiate: {e}", rb.plugin),
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
            let _ = inst.call_window_event(ev.as_bytes());
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
                match inst.maybe_tick(now) {
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
            if let Err(e) = inst.call_menu_click(ev.as_bytes()) {
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

    #[test]
    fn init_upserts_a_dynamic_menu() {
        let json = r#"{"id":"totp.expiring","label":"Expiring soon","section":"secrets","route":"/plugin/totp/expiring","badge":"3"}"#;
        let bytes = menu_module_wat(json);
        let mut inst =
            AppModuleInstance::create("totp", "1.0.0", &sha(&bytes), &caps(true, 0), &bytes)
                .unwrap();
        let status = inst.call_init(b"{}").unwrap();
        assert_eq!(status, Some(RC_OK));
        let menus = inst.menus();
        assert_eq!(menus.len(), 1);
        assert_eq!(menus[0].id, "totp.expiring");
        assert_eq!(menus[0].badge.as_deref(), Some("3"));
        assert_eq!(menus[0].plugin, "totp");
    }

    #[test]
    fn menu_upsert_forbidden_without_capability() {
        // dynamic_menus = false → bvx.menu_upsert returns -2, no menu.
        let json = r#"{"id":"x","label":"X","section":"secrets","route":"/plugin/totp/x"}"#;
        let bytes = menu_module_wat(json);
        let mut inst =
            AppModuleInstance::create("totp", "1.0.0", &sha(&bytes), &caps(false, 0), &bytes)
                .unwrap();
        let status = inst.call_init(b"{}").unwrap();
        assert_eq!(status, Some(RC_FORBIDDEN));
        assert!(inst.menus().is_empty());
    }

    #[test]
    fn menu_with_route_outside_plugin_is_rejected() {
        // route points at another plugin → validate_menu rejects → -4.
        let json = r#"{"id":"x","label":"X","section":"secrets","route":"/plugin/other/x"}"#;
        let bytes = menu_module_wat(json);
        let mut inst =
            AppModuleInstance::create("totp", "1.0.0", &sha(&bytes), &caps(true, 0), &bytes)
                .unwrap();
        let status = inst.call_init(b"{}").unwrap();
        assert_eq!(status, Some(RC_INTERNAL));
        assert!(inst.menus().is_empty());
    }

    #[test]
    fn missing_optional_export_is_none() {
        // Module with no bvx_menu_click export → call returns Ok(None).
        let json = r#"{"id":"x","label":"X","section":"secrets","route":"/plugin/totp/x"}"#;
        let bytes = menu_module_wat(json);
        let mut inst =
            AppModuleInstance::create("totp", "1.0.0", &sha(&bytes), &caps(true, 0), &bytes)
                .unwrap();
        assert_eq!(inst.call_menu_click(b"{}").unwrap(), None);
    }

    #[test]
    fn undeclared_bvx_import_fails_instantiation() {
        // Importing a bvx symbol the host doesn't register must fail —
        // the Phase-2 acceptance invariant.
        let wat = r#"
            (module
              (import "bvx" "api_request" (func (param i32 i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "bv_alloc") (param i32) (result i32) i32.const 0)
              (func (export "bvx_init") (param i32 i32) (result i32) i32.const 0))
        "#;
        let bytes = wat::parse_str(wat).unwrap();
        // `AppModuleInstance` isn't `Debug` (holds a Wasmtime `Store`),
        // so match on the result rather than `unwrap_err`.
        let result =
            AppModuleInstance::create("totp", "1.0.0", &sha(&bytes), &caps(true, 0), &bytes);
        assert!(matches!(result, Err(AppModuleError::Instantiate(_))));
    }

    #[test]
    fn window_open_records_op_and_clamps() {
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
        let mut inst =
            AppModuleInstance::create("totp", "1.0.0", &sha(&bytes), &caps(false, 1), &bytes)
                .unwrap();
        // 2nd open hits the cap → returns WINDOW_LIMIT.
        let status = inst.call_init(b"{}").unwrap();
        assert_eq!(status, Some(RC_WINDOW_LIMIT));
        let ops = inst.drain_window_ops();
        assert_eq!(ops.len(), 1, "only the first open should be recorded");
        assert!(matches!(&ops[0], WindowOp::Open { route, .. } if route == "/plugin/totp/review"));
    }

    #[test]
    fn window_open_forbidden_without_capability() {
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
        let mut inst =
            AppModuleInstance::create("totp", "1.0.0", &sha(&bytes), &caps(true, 0), &bytes)
                .unwrap();
        assert_eq!(inst.call_init(b"{}").unwrap(), Some(RC_FORBIDDEN));
        assert!(inst.drain_window_ops().is_empty());
    }
}
