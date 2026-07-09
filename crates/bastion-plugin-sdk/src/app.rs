//! Extensibility v2 (Phase 6) — app-module authoring.
//!
//! An *app module* is a stateful WASM module that runs in the Tauri
//! backend (never the webview) and drives the plugin's GUI footprint
//! programmatically through the capability-gated `bvx.*` host imports:
//! dynamic menus, plugin windows, the vault-API bridge, and (with an
//! admin grant) network. This module provides:
//!
//! * [`AppHost`] — typed, buffer-retry wrappers over every `bvx.*`
//!   import, mirroring [`crate::Host`]'s ergonomics.
//! * [`AppModule`] — the trait a plugin implements (all entry points
//!   default to a no-op so a plugin only overrides what it uses).
//! * [`app_module!`] — emits the `bvx_init` / `bvx_menu_click` /
//!   `bvx_window_event` / `bvx_tick` exports plus `bv_alloc`.
//!
//! On non-wasm targets (and under `host_test`) the imports fall back to
//! in-memory stubs so authors can `cargo test` their handlers, and the
//! macro is a no-op so the module compiles as a normal library.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::HostError;

// Return codes specific to the app surface (in addition to the shared
// -1/-2/-3/-4 that `HostError` already maps).
/// The plugin has no live admin network grant.
pub const NET_NOT_GRANTED: i32 = -6;
/// The requested host/scheme/port failed the network gate.
pub const NET_HOST_DENIED: i32 = -7;
/// The plugin is at its concurrent-window cap.
pub const WINDOW_LIMIT: i32 = -8;

/// A menu the plugin creates/updates at runtime via [`AppHost::menu_upsert`].
/// Same shape as a static surface menu plus an optional `badge`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Menu {
    pub id: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub icon: String,
    /// One of `secrets` / `sharing` / `admin` / `settings`.
    pub section: String,
    /// Must start with `/plugin/<this-plugin>/`.
    pub route: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub min_policy: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub badge: Option<String>,
}

/// Spec for [`AppHost::window_open`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowSpec {
    /// Must start with `/plugin/<this-plugin>/`.
    pub route: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<f64>,
}

/// Vault operation for [`AppHost::api_request`].
#[derive(Debug, Clone, Copy)]
pub enum ApiOp {
    Read,
    Write,
    Delete,
    List,
}

impl ApiOp {
    fn as_str(self) -> &'static str {
        match self {
            ApiOp::Read => "read",
            ApiOp::Write => "write",
            ApiOp::Delete => "delete",
            ApiOp::List => "list",
        }
    }
}

/// An outbound request for [`AppHost::http`].
#[derive(Debug, Clone, Serialize)]
pub struct HttpRequest {
    #[serde(default)]
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: alloc::collections::BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// Response from [`AppHost::http`].
#[derive(Debug, Clone, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub bytes: usize,
    /// Base64-encoded response body.
    #[serde(default)]
    pub body_b64: String,
}

/// The `bvx_init` context the host passes on first instantiation.
#[derive(Debug, Clone, Deserialize)]
pub struct AppContext {
    #[serde(default)]
    pub plugin: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub mount: String,
    #[serde(default)]
    pub policies: Vec<String>,
    #[serde(default)]
    pub locale: String,
}

/// A dynamic-menu click event (`bvx_menu_click`).
#[derive(Debug, Clone, Deserialize)]
pub struct MenuClick {
    pub id: String,
}

/// A plugin-window lifecycle event (`bvx_window_event`).
#[derive(Debug, Clone, Deserialize)]
pub struct WindowEvent {
    pub handle: u32,
    /// e.g. `"closed"`.
    pub kind: String,
}

/// Network-specific error for [`AppHost::http`], extending [`HostError`]
/// with the two grant-related refusals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetError {
    /// No admin network grant (the manifest flag alone grants nothing).
    NotGranted,
    /// The host/scheme/port/SSRF gate refused the request.
    HostDenied,
    /// Host-side error (bad request, buffer, internal).
    Host(HostError),
}

/// Capability-gated handle to the `bvx.*` host services. Passed to every
/// [`AppModule`] entry point.
pub struct AppHost {
    _private: (),
}

impl Default for AppHost {
    fn default() -> Self {
        Self::new()
    }
}

impl AppHost {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn log(&self, level: crate::LogLevel, msg: &str) {
        app_bindings::log(level as i32, msg.as_bytes());
    }

    pub fn now_unix_ms(&self) -> i64 {
        app_bindings::now_unix_ms()
    }

    /// Advertise a result payload for the current entry-point call.
    pub fn set_result(&self, bytes: &[u8]) {
        app_bindings::set_result(bytes);
    }

    /// Create or update a dynamic menu. Requires `dynamic_menus`.
    pub fn menu_upsert(&self, menu: &Menu) -> Result<(), HostError> {
        let json = serde_json::to_vec(menu).map_err(|_| HostError::Internal)?;
        rc_to_unit(app_bindings::menu_upsert(&json))
    }

    /// Remove a dynamic menu by id.
    pub fn menu_remove(&self, id: &str) -> Result<(), HostError> {
        rc_to_unit(app_bindings::menu_remove(id.as_bytes()))
    }

    /// Open a plugin window rendering `spec.route`. Returns the window
    /// handle. Requires `windows.max_open > 0`.
    pub fn window_open(&self, spec: &WindowSpec) -> Result<u32, HostError> {
        let json = serde_json::to_vec(spec).map_err(|_| HostError::Internal)?;
        let rc = app_bindings::window_open(&json);
        if rc >= 0 {
            Ok(rc as u32)
        } else {
            Err(HostError::from(rc))
        }
    }

    pub fn window_close(&self, handle: u32) -> Result<(), HostError> {
        rc_to_unit(app_bindings::window_close(handle as i32))
    }

    /// Push `payload` to a window's `subscribe`-enabled components.
    pub fn window_emit(&self, handle: u32, payload: &[u8]) -> Result<(), HostError> {
        rc_to_unit(app_bindings::window_emit(handle as i32, payload))
    }

    /// Call the vault API through the user's session. `path` may use
    /// `{mount}`; it must stay under the plugin's declared `api_paths`.
    /// Returns the raw response JSON bytes (the `{"data":…}` or
    /// `{"error":…}` envelope). Requires a non-empty `api_paths`.
    pub fn api_request(
        &self,
        op: ApiOp,
        path: &str,
        data: Option<&[u8]>,
    ) -> Result<Vec<u8>, HostError> {
        // Build the request JSON by hand to avoid forcing a serde_json
        // Value dependency on `data`'s shape.
        let mut req = Vec::new();
        req.extend_from_slice(b"{\"op\":\"");
        req.extend_from_slice(op.as_str().as_bytes());
        req.extend_from_slice(b"\",\"path\":");
        req.extend_from_slice(&json_string(path));
        if let Some(d) = data {
            req.extend_from_slice(b",\"data\":");
            req.extend_from_slice(d);
        }
        req.push(b'}');
        buffer_retry(|buf| app_bindings::api_request(&req, buf))
    }

    /// Make an outbound HTTPS request (subject to the admin grant + the
    /// host network gate). Requires the manifest to request `net` **and**
    /// an admin grant.
    pub fn http(&self, req: &HttpRequest) -> Result<HttpResponse, NetError> {
        let json = serde_json::to_vec(req).map_err(|_| NetError::Host(HostError::Internal))?;
        let out = buffer_retry_net(|buf| app_bindings::net_http(&json, buf))?;
        serde_json::from_slice(&out).map_err(|_| NetError::Host(HostError::Internal))
    }
}

fn rc_to_unit(rc: i32) -> Result<(), HostError> {
    if rc == 0 {
        Ok(())
    } else {
        Err(HostError::from(rc))
    }
}

/// Minimal JSON string encoder for the `path` field (escapes the subset
/// that can appear in a vault path). Avoids depending on serde_json for
/// a bare string in `no_std`.
fn json_string(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() + 2);
    out.push(b'"');
    for b in s.bytes() {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            _ => out.push(b),
        }
    }
    out.push(b'"');
    out
}

/// Growing-buffer retry for out-buffer imports returning `-3` when the
/// caller's buffer is too small (mirrors [`crate::Host::storage_get`]).
fn buffer_retry(mut call: impl FnMut(&mut [u8]) -> i32) -> Result<Vec<u8>, HostError> {
    let mut cap = 4096usize;
    loop {
        let mut buf = alloc::vec![0u8; cap];
        let rc = call(&mut buf);
        if rc >= 0 {
            buf.truncate(rc as usize);
            return Ok(buf);
        }
        if rc == -3 && cap < 8 * 1024 * 1024 {
            cap *= 2;
            continue;
        }
        return Err(HostError::from(rc));
    }
}

fn buffer_retry_net(mut call: impl FnMut(&mut [u8]) -> i32) -> Result<Vec<u8>, NetError> {
    let mut cap = 8192usize;
    loop {
        let mut buf = alloc::vec![0u8; cap];
        let rc = call(&mut buf);
        if rc >= 0 {
            buf.truncate(rc as usize);
            return Ok(buf);
        }
        match rc {
            -3 if cap < 8 * 1024 * 1024 => {
                cap *= 2;
                continue;
            }
            NET_NOT_GRANTED => return Err(NetError::NotGranted),
            NET_HOST_DENIED => return Err(NetError::HostDenied),
            other => return Err(NetError::Host(HostError::from(other))),
        }
    }
}

/// The trait an app module implements. Every entry point defaults to a
/// no-op returning `0` (success), so a plugin overrides only what it
/// needs. Non-zero returns are logged host-side and surface as an
/// operator toast; they never crash the GUI.
pub trait AppModule {
    /// Called once per instance. Typical place to seed dynamic menus.
    fn init(_ctx: &AppContext, _host: &AppHost) -> i32 {
        0
    }
    /// A user clicked one of the plugin's dynamic menus.
    fn menu_click(_ev: &MenuClick, _host: &AppHost) -> i32 {
        0
    }
    /// A plugin window emitted a lifecycle event (e.g. `closed`).
    fn window_event(_ev: &WindowEvent, _host: &AppHost) -> i32 {
        0
    }
    /// Periodic callback (min 30 s cadence, host-enforced).
    fn tick(_now_ms: i64, _host: &AppHost) -> i32 {
        0
    }
}

#[doc(hidden)]
pub mod app_abi {
    //! Glue the [`app_module!`] macro routes the `bvx_*` exports into.
    use super::{AppContext, AppHost, AppModule, MenuClick, WindowEvent};

    unsafe fn input<'a>(ptr: i32, len: i32) -> &'a [u8] {
        if ptr <= 0 || len <= 0 {
            &[]
        } else {
            core::slice::from_raw_parts(ptr as usize as *const u8, len as usize)
        }
    }

    /// # Safety
    /// `ptr`/`len` describe host-written bytes valid for the call.
    pub unsafe fn init<M: AppModule>(ptr: i32, len: i32) -> i32 {
        let ctx: AppContext = serde_json::from_slice(input(ptr, len)).unwrap_or(AppContext {
            plugin: alloc::string::String::new(),
            version: alloc::string::String::new(),
            mount: alloc::string::String::new(),
            policies: alloc::vec::Vec::new(),
            locale: alloc::string::String::new(),
        });
        M::init(&ctx, &AppHost::new())
    }

    /// # Safety
    /// See [`init`].
    pub unsafe fn menu_click<M: AppModule>(ptr: i32, len: i32) -> i32 {
        match serde_json::from_slice::<MenuClick>(input(ptr, len)) {
            Ok(ev) => M::menu_click(&ev, &AppHost::new()),
            Err(_) => -4,
        }
    }

    /// # Safety
    /// See [`init`].
    pub unsafe fn window_event<M: AppModule>(ptr: i32, len: i32) -> i32 {
        match serde_json::from_slice::<WindowEvent>(input(ptr, len)) {
            Ok(ev) => M::window_event(&ev, &AppHost::new()),
            Err(_) => -4,
        }
    }

    pub fn tick<M: AppModule>(now_ms: i64) -> i32 {
        M::tick(now_ms, &AppHost::new())
    }
}

/// Wire an [`AppModule`] impl up to the `bvx_*` WASM ABI.
///
/// Emits `bv_alloc` + `bvx_init` / `bvx_menu_click` / `bvx_window_event`
/// / `bvx_tick`. No-op on non-wasm targets (and under `host_test`) so the
/// module compiles as a plain library and its handlers stay unit-testable.
///
/// ```ignore
/// use bastion_plugin_sdk::app::{app_module, AppContext, AppHost, AppModule, Menu};
///
/// struct Approvals;
/// impl AppModule for Approvals {
///     fn init(ctx: &AppContext, host: &AppHost) -> i32 {
///         let _ = host.menu_upsert(&Menu {
///             id: "approvals.pending".into(),
///             label: "Pending approvals".into(),
///             icon: String::new(),
///             section: "secrets".into(),
///             route: format!("/plugin/{}/pending", ctx.plugin),
///             min_policy: String::new(),
///             badge: Some("3".into()),
///         });
///         0
///     }
/// }
/// app_module!(Approvals);
/// ```
#[macro_export]
macro_rules! app_module {
    ($m:ty) => {
        #[cfg(all(target_arch = "wasm32", not(feature = "host_test")))]
        #[no_mangle]
        pub extern "C" fn bv_alloc(len: i32) -> i32 {
            $crate::abi::alloc(len)
        }

        #[cfg(all(target_arch = "wasm32", not(feature = "host_test")))]
        #[no_mangle]
        pub extern "C" fn bvx_init(ptr: i32, len: i32) -> i32 {
            // SAFETY: host contract — bytes [ptr, ptr+len) are valid.
            unsafe { $crate::app::app_abi::init::<$m>(ptr, len) }
        }

        #[cfg(all(target_arch = "wasm32", not(feature = "host_test")))]
        #[no_mangle]
        pub extern "C" fn bvx_menu_click(ptr: i32, len: i32) -> i32 {
            unsafe { $crate::app::app_abi::menu_click::<$m>(ptr, len) }
        }

        #[cfg(all(target_arch = "wasm32", not(feature = "host_test")))]
        #[no_mangle]
        pub extern "C" fn bvx_window_event(ptr: i32, len: i32) -> i32 {
            unsafe { $crate::app::app_abi::window_event::<$m>(ptr, len) }
        }

        #[cfg(all(target_arch = "wasm32", not(feature = "host_test")))]
        #[no_mangle]
        pub extern "C" fn bvx_tick(now_ms: i64) -> i32 {
            $crate::app::app_abi::tick::<$m>(now_ms)
        }
    };
}

// ── Bindings ─────────────────────────────────────────────────────────

#[cfg(all(target_arch = "wasm32", not(feature = "host_test")))]
mod app_bindings {
    mod raw {
        #[link(wasm_import_module = "bvx")]
        extern "C" {
            pub fn log(level: i32, ptr: i32, len: i32);
            pub fn now_unix_ms() -> i64;
            pub fn set_result(ptr: i32, len: i32);
            pub fn menu_upsert(ptr: i32, len: i32) -> i32;
            pub fn menu_remove(ptr: i32, len: i32) -> i32;
            pub fn window_open(ptr: i32, len: i32) -> i32;
            pub fn window_close(handle: i32) -> i32;
            pub fn window_emit(handle: i32, ptr: i32, len: i32) -> i32;
            pub fn api_request(req_ptr: i32, req_len: i32, out_ptr: i32, out_max: i32) -> i32;
            pub fn net_http(req_ptr: i32, req_len: i32, out_ptr: i32, out_max: i32) -> i32;
        }
    }

    pub fn log(level: i32, msg: &[u8]) {
        unsafe { raw::log(level, msg.as_ptr() as i32, msg.len() as i32) }
    }
    pub fn now_unix_ms() -> i64 {
        unsafe { raw::now_unix_ms() }
    }
    pub fn set_result(bytes: &[u8]) {
        unsafe { raw::set_result(bytes.as_ptr() as i32, bytes.len() as i32) }
    }
    pub fn menu_upsert(json: &[u8]) -> i32 {
        unsafe { raw::menu_upsert(json.as_ptr() as i32, json.len() as i32) }
    }
    pub fn menu_remove(id: &[u8]) -> i32 {
        unsafe { raw::menu_remove(id.as_ptr() as i32, id.len() as i32) }
    }
    pub fn window_open(json: &[u8]) -> i32 {
        unsafe { raw::window_open(json.as_ptr() as i32, json.len() as i32) }
    }
    pub fn window_close(handle: i32) -> i32 {
        unsafe { raw::window_close(handle) }
    }
    pub fn window_emit(handle: i32, payload: &[u8]) -> i32 {
        unsafe { raw::window_emit(handle, payload.as_ptr() as i32, payload.len() as i32) }
    }
    pub fn api_request(req: &[u8], out: &mut [u8]) -> i32 {
        unsafe {
            raw::api_request(
                req.as_ptr() as i32,
                req.len() as i32,
                out.as_mut_ptr() as i32,
                out.len() as i32,
            )
        }
    }
    pub fn net_http(req: &[u8], out: &mut [u8]) -> i32 {
        unsafe {
            raw::net_http(
                req.as_ptr() as i32,
                req.len() as i32,
                out.as_mut_ptr() as i32,
                out.len() as i32,
            )
        }
    }
}

#[cfg(any(not(target_arch = "wasm32"), feature = "host_test"))]
mod app_bindings {
    //! In-memory stubs so authors can `cargo test` app-module handlers.
    //! Menus/windows are captured; API + network responses are scripted
    //! via [`super::test_support`].
    use alloc::collections::BTreeMap;
    use alloc::string::String;
    use alloc::vec::Vec;
    use std::sync::Mutex;

    pub(super) static STATE: Mutex<AppState> = Mutex::new(AppState::new_const());

    pub struct AppState {
        pub menus: Option<BTreeMap<String, Vec<u8>>>,
        pub removed: Option<Vec<String>>,
        pub windows: Option<Vec<Vec<u8>>>,
        pub emits: Option<Vec<(i32, Vec<u8>)>>,
        pub next_handle: i32,
        pub max_windows: i32,
        pub api_script: Option<Vec<Vec<u8>>>,
        pub net_script: Option<Vec<Result<Vec<u8>, i32>>>,
        pub log_lines: Option<Vec<(i32, Vec<u8>)>>,
        pub now_ms: Option<i64>,
    }

    impl AppState {
        pub(super) const fn new_const() -> Self {
            Self {
                menus: None,
                removed: None,
                windows: None,
                emits: None,
                next_handle: 1,
                max_windows: 4,
                api_script: None,
                net_script: None,
                log_lines: None,
                now_ms: None,
            }
        }
    }

    fn write_out(src: &[u8], out: &mut [u8]) -> i32 {
        if src.len() > out.len() {
            return -3;
        }
        out[..src.len()].copy_from_slice(src);
        src.len() as i32
    }

    pub fn log(level: i32, msg: &[u8]) {
        let mut s = STATE.lock().unwrap();
        s.log_lines.get_or_insert_with(Vec::new).push((level, msg.to_vec()));
    }
    pub fn now_unix_ms() -> i64 {
        let s = STATE.lock().unwrap();
        s.now_ms.unwrap_or(0)
    }
    pub fn set_result(_bytes: &[u8]) {}
    pub fn menu_upsert(json: &[u8]) -> i32 {
        // Parse just the id so the capture map is keyed like the host.
        let id = serde_json::from_slice::<serde_json::Value>(json)
            .ok()
            .and_then(|v| v.get("id").and_then(|i| i.as_str()).map(String::from));
        match id {
            Some(id) => {
                let mut s = STATE.lock().unwrap();
                s.menus.get_or_insert_with(BTreeMap::new).insert(id, json.to_vec());
                0
            }
            None => -4,
        }
    }
    pub fn menu_remove(id: &[u8]) -> i32 {
        let id = String::from_utf8_lossy(id).into_owned();
        let mut s = STATE.lock().unwrap();
        s.menus.get_or_insert_with(BTreeMap::new).remove(&id);
        s.removed.get_or_insert_with(Vec::new).push(id);
        0
    }
    pub fn window_open(json: &[u8]) -> i32 {
        let mut s = STATE.lock().unwrap();
        let open = s.windows.get_or_insert_with(Vec::new).len() as i32;
        if open >= s.max_windows {
            return super::WINDOW_LIMIT;
        }
        s.windows.get_or_insert_with(Vec::new).push(json.to_vec());
        let h = s.next_handle;
        s.next_handle += 1;
        h
    }
    pub fn window_close(_handle: i32) -> i32 {
        0
    }
    pub fn window_emit(handle: i32, payload: &[u8]) -> i32 {
        let mut s = STATE.lock().unwrap();
        s.emits.get_or_insert_with(Vec::new).push((handle, payload.to_vec()));
        0
    }
    pub fn api_request(_req: &[u8], out: &mut [u8]) -> i32 {
        let mut s = STATE.lock().unwrap();
        match s.api_script.as_mut().and_then(|q| if q.is_empty() { None } else { Some(q.remove(0)) }) {
            Some(resp) => write_out(&resp, out),
            None => -2, // forbidden when nothing scripted (no api_paths)
        }
    }
    pub fn net_http(_req: &[u8], out: &mut [u8]) -> i32 {
        let mut s = STATE.lock().unwrap();
        match s.net_script.as_mut().and_then(|q| if q.is_empty() { None } else { Some(q.remove(0)) }) {
            Some(Ok(resp)) => write_out(&resp, out),
            Some(Err(code)) => code,
            None => super::NET_NOT_GRANTED,
        }
    }
}

/// Test helpers for app-module authors (available under `host_test`).
#[cfg(feature = "host_test")]
pub mod test_support {
    use super::app_bindings::STATE;
    use alloc::string::String;
    use alloc::vec::Vec;

    pub fn reset() {
        let mut s = STATE.lock().unwrap();
        *s = super::app_bindings::AppState::new_const();
    }

    /// Set the concurrent-window cap the stub enforces (default 4).
    pub fn set_max_windows(n: i32) {
        STATE.lock().unwrap().max_windows = n;
    }

    /// Pin `AppHost::now_unix_ms`.
    pub fn set_now_ms(v: i64) {
        STATE.lock().unwrap().now_ms = Some(v);
    }

    /// Queue a scripted `api_request` response (returned in FIFO order).
    pub fn script_api(response_json: &[u8]) {
        STATE
            .lock()
            .unwrap()
            .api_script
            .get_or_insert_with(Vec::new)
            .push(response_json.to_vec());
    }

    /// Queue a scripted `http` success response.
    pub fn script_net_ok(response_json: &[u8]) {
        STATE
            .lock()
            .unwrap()
            .net_script
            .get_or_insert_with(Vec::new)
            .push(Ok(response_json.to_vec()));
    }

    /// Queue a scripted `http` refusal code (e.g. `NET_HOST_DENIED`).
    pub fn script_net_err(code: i32) {
        STATE
            .lock()
            .unwrap()
            .net_script
            .get_or_insert_with(Vec::new)
            .push(Err(code));
    }

    /// The dynamic menus the module upserted, keyed by id (raw JSON).
    pub fn menus() -> Vec<(String, Vec<u8>)> {
        let s = STATE.lock().unwrap();
        s.menus
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect()
    }

    /// The window-open specs the module recorded (raw JSON).
    pub fn windows() -> Vec<Vec<u8>> {
        STATE.lock().unwrap().windows.clone().unwrap_or_default()
    }

    /// The `window_emit` payloads `(handle, bytes)`.
    pub fn emits() -> Vec<(i32, Vec<u8>)> {
        STATE.lock().unwrap().emits.clone().unwrap_or_default()
    }
}

#[cfg(all(test, feature = "host_test"))]
mod tests {
    use super::*;

    struct Demo;
    impl AppModule for Demo {
        fn init(ctx: &AppContext, host: &AppHost) -> i32 {
            let _ = host.menu_upsert(&Menu {
                id: "demo.main".into(),
                label: "Demo".into(),
                icon: String::new(),
                section: "secrets".into(),
                route: alloc::format!("/plugin/{}/main", ctx.plugin),
                min_policy: String::new(),
                badge: Some("2".into()),
            });
            0
        }
        fn menu_click(_ev: &MenuClick, host: &AppHost) -> i32 {
            let _ = host.window_open(&WindowSpec {
                route: "/plugin/demo/review".into(),
                title: "Review".into(),
                width: None,
                height: None,
            });
            0
        }
    }

    #[test]
    #[serial_test::serial]
    fn init_upserts_menu_and_click_opens_window() {
        test_support::reset();
        let ctx = AppContext {
            plugin: "demo".into(),
            version: "1.0.0".into(),
            mount: "secret/demo".into(),
            policies: alloc::vec![],
            locale: "en".into(),
        };
        assert_eq!(Demo::init(&ctx, &AppHost::new()), 0);
        let menus = test_support::menus();
        assert_eq!(menus.len(), 1);
        assert_eq!(menus[0].0, "demo.main");

        assert_eq!(Demo::menu_click(&MenuClick { id: "demo.main".into() }, &AppHost::new()), 0);
        assert_eq!(test_support::windows().len(), 1);
    }

    #[test]
    #[serial_test::serial]
    fn api_request_reads_scripted_response() {
        test_support::reset();
        test_support::script_api(br#"{"data":{"count":3}}"#);
        let host = AppHost::new();
        let out = host.api_request(ApiOp::Read, "{mount}/pending", None).unwrap();
        assert_eq!(&out, br#"{"data":{"count":3}}"#);
    }

    #[test]
    #[serial_test::serial]
    fn api_request_forbidden_when_unscripted() {
        test_support::reset();
        let host = AppHost::new();
        assert_eq!(host.api_request(ApiOp::List, "{mount}/", None).unwrap_err(), HostError::Forbidden);
    }

    #[test]
    #[serial_test::serial]
    fn http_maps_grant_and_denial_codes() {
        test_support::reset();
        // Not granted by default.
        let host = AppHost::new();
        assert_eq!(host.http(&HttpRequest {
            method: "GET".into(),
            url: "https://hooks.example.com/x".into(),
            headers: Default::default(),
            body_b64: None,
            timeout_ms: None,
        }).unwrap_err(), NetError::NotGranted);

        // Scripted success.
        test_support::script_net_ok(br#"{"status":200,"bytes":2,"body_b64":"aGk="}"#);
        let resp = host.http(&HttpRequest {
            method: "GET".into(),
            url: "https://hooks.example.com/x".into(),
            headers: Default::default(),
            body_b64: None,
            timeout_ms: None,
        }).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.bytes, 2);

        // Scripted denial.
        test_support::script_net_err(NET_HOST_DENIED);
        assert_eq!(host.http(&HttpRequest {
            method: "GET".into(),
            url: "https://blocked.example.com/x".into(),
            headers: Default::default(),
            body_b64: None,
            timeout_ms: None,
        }).unwrap_err(), NetError::HostDenied);
    }
}
