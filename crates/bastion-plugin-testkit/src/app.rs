//! App-module (`bvx.*`) test driver — Extensibility v2 (Phase 6).
//!
//! The [`crate::TestHost`] drives *server* plugins through the `bv_run`
//! ABI. This module is its counterpart for **app modules**: it
//! instantiates an app-module `.wasm` (stateful — one linear memory
//! across calls) against an in-memory `bvx.*` mock host and lets a test
//! drive the entry points (`bvx_init` / `bvx_menu_click` /
//! `bvx_window_event` / `bvx_tick`) while capturing the menus/windows the
//! module produced and scripting its `api_request` / `net_http` replies.
//!
//! The mock enforces the same gates the real Tauri-backend runtime does
//! (`gui/src-tauri/src/plugin_apps.rs`): `dynamic_menus` for `menu_*`,
//! `windows.max_open` for `window_*` (with the `WINDOW_LIMIT` clamp),
//! a non-empty `api_paths` for `api_request`, and a non-empty grant for
//! `net_http` (`NET_NOT_GRANTED` otherwise). [`bvx_conformance_wat`] +
//! [`BVX_IMPORTS`] mirror the surface so the host repo's parity test can
//! run the same module through the *real* linker and fail CI on drift.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use wasmtime::{
    AsContext, AsContextMut, Caller, Config, Engine, Instance, Linker, Module, Store, StoreLimits,
    StoreLimitsBuilder, TypedFunc,
};

use crate::{TestkitError, DEFAULT_FUEL, DEFAULT_MEMORY_BYTES};

const RC_OK: i32 = 0;
const RC_FORBIDDEN: i32 = -2;
const RC_BUFFER_TOO_SMALL: i32 = -3;
const RC_INTERNAL: i32 = -4;
const NET_NOT_GRANTED: i32 = -6;
const NET_HOST_DENIED: i32 = -7;
const WINDOW_LIMIT: i32 = -8;

/// The full `bvx.*` import surface. `(module, name, signature)`. The
/// host repo's parity test instantiates [`bvx_conformance_wat`] against
/// the real `plugin_apps` linker so any addition/removal here that the
/// runtime doesn't mirror fails CI.
pub const BVX_IMPORTS: &[(&str, &str, &str)] = &[
    ("bvx", "log", "(param i32 i32 i32)"),
    ("bvx", "now_unix_ms", "(result i64)"),
    ("bvx", "set_result", "(param i32 i32)"),
    ("bvx", "menu_upsert", "(param i32 i32) (result i32)"),
    ("bvx", "menu_remove", "(param i32 i32) (result i32)"),
    ("bvx", "window_open", "(param i32 i32) (result i32)"),
    ("bvx", "window_close", "(param i32) (result i32)"),
    ("bvx", "window_emit", "(param i32 i32 i32) (result i32)"),
    ("bvx", "api_request", "(param i32 i32 i32 i32) (result i32)"),
    ("bvx", "net_http", "(param i32 i32 i32 i32) (result i32)"),
];

/// A WAT module importing every [`BVX_IMPORTS`] entry, exporting the
/// required `memory` + `bv_alloc`, and a `bvx_init` that returns 0. Used
/// by the parity test to prove the real linker satisfies exactly this
/// surface.
pub fn bvx_conformance_wat() -> String {
    let imports: String = BVX_IMPORTS
        .iter()
        .map(|(m, n, sig)| format!("  (import \"{m}\" \"{n}\" (func {sig}))\n"))
        .collect();
    format!(
        "(module\n{imports}  (memory (export \"memory\") 1)\n  (func (export \"bv_alloc\") (param i32) (result i32) i32.const 1024)\n  (func (export \"bvx_init\") (param i32 i32) (result i32) i32.const 0))\n"
    )
}

/// Captured app-module side effects + scripted host replies.
#[derive(Default)]
struct AppMockState {
    menus: BTreeMap<String, serde_json::Value>,
    removed: Vec<String>,
    windows: Vec<serde_json::Value>,
    emits: Vec<(u32, Vec<u8>)>,
    open_windows: u32,
    next_handle: u32,
    logs: Vec<crate::LogLine>,
    now_ms: i64,
    /// FIFO of raw JSON bodies returned by `api_request`.
    api_script: VecDeque<Vec<u8>>,
    /// FIFO of `net_http` outcomes: `Ok(body)` or `Err(code)`.
    net_script: VecDeque<Result<Vec<u8>, i32>>,
}

struct AppCtx {
    menu_prefix: String,
    dynamic_menus: bool,
    max_windows: u32,
    api_declared: bool,
    net_granted: bool,
    response_window: Option<(u32, u32)>,
    limits: StoreLimits,
    shared: Arc<Mutex<AppMockState>>,
}

fn read_bytes(caller: &mut Caller<'_, AppCtx>, ptr: i32, len: i32) -> Option<Vec<u8>> {
    if ptr < 0 || len < 0 {
        return None;
    }
    let mem = caller.get_export("memory").and_then(|e| e.into_memory())?;
    let mut buf = vec![0u8; len as usize];
    mem.read(caller.as_context(), ptr as usize, &mut buf).ok()?;
    Some(buf)
}

fn write_out(caller: &mut Caller<'_, AppCtx>, src: &[u8], out_ptr: i32, out_max: i32) -> i32 {
    if out_ptr < 0 || out_max < 0 {
        return RC_INTERNAL;
    }
    if src.len() as i64 > out_max as i64 {
        return RC_BUFFER_TOO_SMALL;
    }
    let Some(mem) = caller.get_export("memory").and_then(|e| e.into_memory()) else {
        return RC_INTERNAL;
    };
    match mem.write(caller.as_context_mut(), out_ptr as usize, src) {
        Ok(()) => src.len() as i32,
        Err(_) => RC_INTERNAL,
    }
}

fn valid_section(s: &str) -> bool {
    matches!(s, "secrets" | "sharing" | "admin" | "settings")
}

fn register_bvx_imports(linker: &mut Linker<AppCtx>) -> Result<(), TestkitError> {
    let e = |err: wasmtime::Error| TestkitError::Instantiate(err.to_string());

    linker
        .func_wrap("bvx", "log", |mut caller: Caller<'_, AppCtx>, level: i32, ptr: i32, len: i32| {
            if let Some(b) = read_bytes(&mut caller, ptr, len) {
                let line = String::from_utf8_lossy(&b).into_owned();
                caller.data().shared.lock().unwrap().logs.push(crate::LogLine { level, line });
            }
        })
        .map_err(e)?;
    linker
        .func_wrap("bvx", "now_unix_ms", |caller: Caller<'_, AppCtx>| -> i64 {
            caller.data().shared.lock().unwrap().now_ms
        })
        .map_err(e)?;
    linker
        .func_wrap("bvx", "set_result", |mut caller: Caller<'_, AppCtx>, ptr: i32, len: i32| {
            if ptr >= 0 && len >= 0 {
                caller.data_mut().response_window = Some((ptr as u32, len as u32));
            }
        })
        .map_err(e)?;
    linker
        .func_wrap("bvx", "menu_upsert", |mut caller: Caller<'_, AppCtx>, ptr: i32, len: i32| -> i32 {
            if !caller.data().dynamic_menus {
                return RC_FORBIDDEN;
            }
            let Some(b) = read_bytes(&mut caller, ptr, len) else { return RC_INTERNAL };
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(&b) else { return RC_INTERNAL };
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or_default().to_string();
            let section = v.get("section").and_then(|x| x.as_str()).unwrap_or_default();
            let route = v.get("route").and_then(|x| x.as_str()).unwrap_or_default();
            let prefix = caller.data().menu_prefix.clone();
            if id.is_empty() || !valid_section(section) || !route.starts_with(&prefix) {
                return RC_INTERNAL;
            }
            let mut st = caller.data().shared.lock().unwrap();
            if !st.menus.contains_key(&id) && st.menus.len() >= 16 {
                return RC_INTERNAL;
            }
            st.menus.insert(id, v);
            RC_OK
        })
        .map_err(e)?;
    linker
        .func_wrap("bvx", "menu_remove", |mut caller: Caller<'_, AppCtx>, ptr: i32, len: i32| -> i32 {
            if !caller.data().dynamic_menus {
                return RC_FORBIDDEN;
            }
            let Some(b) = read_bytes(&mut caller, ptr, len) else { return RC_INTERNAL };
            let id = String::from_utf8_lossy(&b).into_owned();
            let mut st = caller.data().shared.lock().unwrap();
            st.menus.remove(&id);
            st.removed.push(id);
            RC_OK
        })
        .map_err(e)?;
    linker
        .func_wrap("bvx", "window_open", |mut caller: Caller<'_, AppCtx>, ptr: i32, len: i32| -> i32 {
            let max = caller.data().max_windows;
            if max == 0 {
                return RC_FORBIDDEN;
            }
            let Some(b) = read_bytes(&mut caller, ptr, len) else { return RC_INTERNAL };
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(&b) else { return RC_INTERNAL };
            let route = v.get("route").and_then(|x| x.as_str()).unwrap_or_default();
            let prefix = caller.data().menu_prefix.clone();
            if !route.starts_with(&prefix) || route.contains("..") {
                return RC_INTERNAL;
            }
            let mut st = caller.data().shared.lock().unwrap();
            if st.open_windows >= max {
                return WINDOW_LIMIT;
            }
            st.next_handle += 1;
            let handle = st.next_handle;
            st.open_windows += 1;
            st.windows.push(v);
            handle as i32
        })
        .map_err(e)?;
    linker
        .func_wrap("bvx", "window_close", |caller: Caller<'_, AppCtx>, handle: i32| -> i32 {
            if caller.data().max_windows == 0 || handle < 0 {
                return RC_FORBIDDEN;
            }
            let mut st = caller.data().shared.lock().unwrap();
            st.open_windows = st.open_windows.saturating_sub(1);
            RC_OK
        })
        .map_err(e)?;
    linker
        .func_wrap("bvx", "window_emit", |mut caller: Caller<'_, AppCtx>, handle: i32, ptr: i32, len: i32| -> i32 {
            if caller.data().max_windows == 0 || handle < 0 {
                return RC_FORBIDDEN;
            }
            let Some(b) = read_bytes(&mut caller, ptr, len) else { return RC_INTERNAL };
            caller.data().shared.lock().unwrap().emits.push((handle as u32, b));
            RC_OK
        })
        .map_err(e)?;
    linker
        .func_wrap("bvx", "api_request", |mut caller: Caller<'_, AppCtx>, _rp: i32, _rl: i32, op: i32, om: i32| -> i32 {
            if !caller.data().api_declared {
                return RC_FORBIDDEN;
            }
            let scripted = caller.data().shared.lock().unwrap().api_script.pop_front();
            match scripted {
                Some(body) => write_out(&mut caller, &body, op, om),
                None => RC_FORBIDDEN,
            }
        })
        .map_err(e)?;
    linker
        .func_wrap("bvx", "net_http", |mut caller: Caller<'_, AppCtx>, _rp: i32, _rl: i32, op: i32, om: i32| -> i32 {
            if !caller.data().net_granted {
                return NET_NOT_GRANTED;
            }
            let scripted = caller.data().shared.lock().unwrap().net_script.pop_front();
            match scripted {
                Some(Ok(body)) => write_out(&mut caller, &body, op, om),
                Some(Err(code)) => code,
                None => NET_HOST_DENIED,
            }
        })
        .map_err(e)?;
    Ok(())
}

/// Builder for [`AppTestHost`].
pub struct AppTestHostBuilder {
    name: String,
    dynamic_menus: bool,
    max_windows: u32,
    api_declared: bool,
    net_granted: bool,
    now_ms: i64,
    api_script: VecDeque<Vec<u8>>,
    net_script: VecDeque<Result<Vec<u8>, i32>>,
    fuel_budget: u64,
    memory_budget: usize,
}

impl AppTestHostBuilder {
    /// Grant the `dynamic_menus` capability (default off).
    pub fn dynamic_menus(mut self, on: bool) -> Self {
        self.dynamic_menus = on;
        self
    }
    /// Set the concurrent-window cap (default 0 = windows disabled).
    pub fn max_windows(mut self, n: u32) -> Self {
        self.max_windows = n;
        self
    }
    /// Declare a non-empty `api_paths` so `bvx.api_request` is enabled
    /// (default off → `FORBIDDEN`). Scripted responses drive the results.
    pub fn api_enabled(mut self, on: bool) -> Self {
        self.api_declared = on;
        self
    }
    /// Grant network (a non-empty admin grant) so `bvx.net_http` is
    /// enabled (default off → `NET_NOT_GRANTED`).
    pub fn net_granted(mut self, on: bool) -> Self {
        self.net_granted = on;
        self
    }
    /// Pin `bvx.now_unix_ms`.
    pub fn now_ms(mut self, ms: i64) -> Self {
        self.now_ms = ms;
        self
    }
    /// Queue a scripted `api_request` response (FIFO).
    pub fn script_api(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.api_script.push_back(body.into());
        self
    }
    /// Queue a scripted `net_http` success body (FIFO).
    pub fn script_net_ok(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.net_script.push_back(Ok(body.into()));
        self
    }
    /// Queue a scripted `net_http` refusal code (FIFO).
    pub fn script_net_err(mut self, code: i32) -> Self {
        self.net_script.push_back(Err(code));
        self
    }
    pub fn fuel(mut self, budget: u64) -> Self {
        self.fuel_budget = budget;
        self
    }

    /// Compile + instantiate the app module and wire the `bvx.*` mock
    /// imports. Fails if the module imports a symbol the mock doesn't
    /// register (the drift guard) or lacks `memory` / `bv_alloc`.
    pub fn build(self, wasm: &[u8]) -> Result<AppTestHost, TestkitError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.max_wasm_stack(1024 * 1024);
        let engine = Engine::new(&config).expect("wasmtime engine");
        let module = Module::new(&engine, wasm).map_err(|e| TestkitError::Compile(e.to_string()))?;

        let shared = Arc::new(Mutex::new(AppMockState {
            now_ms: self.now_ms,
            api_script: self.api_script,
            net_script: self.net_script,
            ..Default::default()
        }));
        let ctx = AppCtx {
            menu_prefix: format!("/plugin/{}/", self.name),
            dynamic_menus: self.dynamic_menus,
            max_windows: self.max_windows,
            api_declared: self.api_declared,
            net_granted: self.net_granted,
            response_window: None,
            limits: StoreLimitsBuilder::new().memory_size(self.memory_budget).build(),
            shared: Arc::clone(&shared),
        };
        let mut store = Store::new(&engine, ctx);
        store.limiter(|c| &mut c.limits);
        store.set_fuel(self.fuel_budget).map_err(|e| TestkitError::Instantiate(e.to_string()))?;

        let mut linker: Linker<AppCtx> = Linker::new(&engine);
        register_bvx_imports(&mut linker)?;
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| TestkitError::Instantiate(e.to_string()))?;
        instance.get_memory(&mut store, "memory").ok_or(TestkitError::MissingExport("memory"))?;
        instance
            .get_typed_func::<i32, i32>(&mut store, "bv_alloc")
            .map_err(|_| TestkitError::MissingExport("bv_alloc"))?;

        Ok(AppTestHost { store, instance, fuel_budget: self.fuel_budget, shared })
    }
}

/// A live app-module instance under test. Stateful — its linear memory
/// persists across [`init`](AppTestHost::init) / [`menu_click`] / … so a
/// test can assert on accumulated menus/windows.
pub struct AppTestHost {
    store: Store<AppCtx>,
    instance: Instance,
    fuel_budget: u64,
    shared: Arc<Mutex<AppMockState>>,
}

impl AppTestHost {
    pub fn builder(plugin_name: impl Into<String>) -> AppTestHostBuilder {
        AppTestHostBuilder {
            name: plugin_name.into(),
            dynamic_menus: false,
            max_windows: 0,
            api_declared: false,
            net_granted: false,
            now_ms: 0,
            api_script: VecDeque::new(),
            net_script: VecDeque::new(),
            fuel_budget: DEFAULT_FUEL,
            memory_budget: DEFAULT_MEMORY_BYTES,
        }
    }

    /// Call `bvx_init` with the given context JSON. Returns the status,
    /// or `Ok(None)` if the export is absent.
    pub fn init(&mut self, ctx_json: &serde_json::Value) -> Result<Option<i32>, TestkitError> {
        self.call_ptr_len("bvx_init", &serde_json::to_vec(ctx_json).unwrap())
    }
    pub fn menu_click(&mut self, id: &str) -> Result<Option<i32>, TestkitError> {
        let ev = serde_json::json!({ "id": id });
        self.call_ptr_len("bvx_menu_click", &serde_json::to_vec(&ev).unwrap())
    }
    pub fn window_event(&mut self, handle: u32, kind: &str) -> Result<Option<i32>, TestkitError> {
        let ev = serde_json::json!({ "handle": handle, "kind": kind });
        self.call_ptr_len("bvx_window_event", &serde_json::to_vec(&ev).unwrap())
    }
    pub fn tick(&mut self, now_ms: i64) -> Result<Option<i32>, TestkitError> {
        let Ok(f) = self.instance.get_typed_func::<i64, i32>(&mut self.store, "bvx_tick") else {
            return Ok(None);
        };
        self.refuel()?;
        f.call(&mut self.store, now_ms)
            .map(Some)
            .map_err(|e| TestkitError::Invoke(e.to_string()))
    }

    /// Menus the module currently has upserted, `(id, json)`.
    pub fn menus(&self) -> Vec<(String, serde_json::Value)> {
        self.shared.lock().unwrap().menus.clone().into_iter().collect()
    }
    /// `window_open` specs the module recorded.
    pub fn windows(&self) -> Vec<serde_json::Value> {
        self.shared.lock().unwrap().windows.clone()
    }
    /// `window_emit` payloads `(handle, bytes)`.
    pub fn emits(&self) -> Vec<(u32, Vec<u8>)> {
        self.shared.lock().unwrap().emits.clone()
    }
    /// Ids passed to `menu_remove`.
    pub fn removed(&self) -> Vec<String> {
        self.shared.lock().unwrap().removed.clone()
    }
    /// `bvx.log` lines captured so far.
    pub fn logs(&self) -> Vec<crate::LogLine> {
        self.shared.lock().unwrap().logs.clone()
    }

    fn refuel(&mut self) -> Result<(), TestkitError> {
        self.store
            .set_fuel(self.fuel_budget)
            .map_err(|e| TestkitError::Invoke(e.to_string()))?;
        self.store.data_mut().response_window = None;
        Ok(())
    }

    fn call_ptr_len(&mut self, export: &str, input: &[u8]) -> Result<Option<i32>, TestkitError> {
        let Ok(func) = self.instance.get_typed_func::<(i32, i32), i32>(&mut self.store, export)
        else {
            return Ok(None);
        };
        self.refuel()?;
        let alloc: TypedFunc<i32, i32> = self
            .instance
            .get_typed_func(&mut self.store, "bv_alloc")
            .map_err(|_| TestkitError::MissingExport("bv_alloc"))?;
        let len = input.len() as i32;
        let ptr = alloc
            .call(&mut self.store, len)
            .map_err(|e| TestkitError::Invoke(e.to_string()))?;
        let mem = self
            .instance
            .get_memory(&mut self.store, "memory")
            .ok_or(TestkitError::MissingExport("memory"))?;
        mem.write(&mut self.store, ptr as usize, input)
            .map_err(|e| TestkitError::Memory(e.to_string()))?;
        func.call(&mut self.store, (ptr, len))
            .map(Some)
            .map_err(|e| TestkitError::Invoke(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `Module::new` parses WAT directly (wasmtime `wat` feature), so a
    // fixture is just its text bytes — no separate `wat` crate needed.
    fn wat(module: &str) -> Vec<u8> {
        module.as_bytes().to_vec()
    }

    /// Module whose bvx_init upserts a menu; bvx_menu_click opens a window.
    fn demo_wasm() -> Vec<u8> {
        wat(r#"
        (module
          (import "bvx" "menu_upsert" (func $mu (param i32 i32) (result i32)))
          (import "bvx" "window_open" (func $wo (param i32 i32) (result i32)))
          (memory (export "memory") 2)
          (data (i32.const 0) "{\22id\22:\22demo.main\22,\22label\22:\22Demo\22,\22section\22:\22secrets\22,\22route\22:\22/plugin/demo/main\22}")
          (data (i32.const 512) "{\22route\22:\22/plugin/demo/review\22}")
          (func (export "bv_alloc") (param i32) (result i32) i32.const 4096)
          (func (export "bvx_init") (param i32 i32) (result i32)
            (call $mu (i32.const 0) (i32.const 81)))
          (func (export "bvx_menu_click") (param i32 i32) (result i32)
            (call $wo (i32.const 512) (i32.const 31))))
        "#)
    }

    #[test]
    fn conformance_module_instantiates() {
        let wasm = wat(&bvx_conformance_wat());
        let host = AppTestHost::builder("demo").build(&wasm);
        assert!(host.is_ok(), "conformance module must instantiate against the mock linker");
    }

    #[test]
    fn init_upserts_menu_click_opens_window() {
        let wasm = demo_wasm();
        let mut host = AppTestHost::builder("demo")
            .dynamic_menus(true)
            .max_windows(2)
            .build(&wasm)
            .unwrap();
        assert_eq!(host.init(&serde_json::json!({})).unwrap(), Some(0));
        let menus = host.menus();
        assert_eq!(menus.len(), 1);
        assert_eq!(menus[0].0, "demo.main");

        // bvx_menu_click returns window_open's handle (1 for the first
        // window), and the window is recorded.
        assert_eq!(host.menu_click("demo.main").unwrap(), Some(1));
        assert_eq!(host.windows().len(), 1);
    }

    #[test]
    fn menu_forbidden_without_capability() {
        let wasm = demo_wasm();
        // dynamic_menus off → bvx.menu_upsert returns -2, init propagates it.
        let mut host = AppTestHost::builder("demo").build(&wasm).unwrap();
        assert_eq!(host.init(&serde_json::json!({})).unwrap(), Some(RC_FORBIDDEN));
        assert!(host.menus().is_empty());
    }

    #[test]
    fn net_and_api_scripting() {
        // A module that calls api_request then net_http in bvx_init and
        // returns the sum of their codes (both should be >= 0 here).
        let wasm = wat(r#"
        (module
          (import "bvx" "api_request" (func $api (param i32 i32 i32 i32) (result i32)))
          (import "bvx" "net_http" (func $net (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 2)
          (func (export "bv_alloc") (param i32) (result i32) i32.const 8192)
          (func (export "bvx_init") (param i32 i32) (result i32)
            (i32.add
              (call $api (i32.const 0) (i32.const 0) (i32.const 4096) (i32.const 1024))
              (call $net (i32.const 0) (i32.const 0) (i32.const 5120) (i32.const 1024)))))
        "#);
        let mut host = AppTestHost::builder("demo")
            .api_enabled(true)
            .net_granted(true)
            .script_api(br#"{"data":{"n":1}}"#.to_vec())
            .script_net_ok(br#"{"status":200,"bytes":0,"body_b64":""}"#.to_vec())
            .build(&wasm)
            .unwrap();
        // Both writes succeed → each returns its byte length (>0) → sum > 0.
        let status = host.init(&serde_json::json!({})).unwrap().unwrap();
        assert!(status > 0, "expected both calls to write successfully, got {status}");
    }

    #[test]
    fn net_not_granted_without_grant() {
        let wasm = wat(r#"
        (module
          (import "bvx" "net_http" (func $net (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "bv_alloc") (param i32) (result i32) i32.const 4096)
          (func (export "bvx_init") (param i32 i32) (result i32)
            (call $net (i32.const 0) (i32.const 0) (i32.const 2048) (i32.const 512))))
        "#);
        let mut host = AppTestHost::builder("demo").build(&wasm).unwrap();
        assert_eq!(host.init(&serde_json::json!({})).unwrap(), Some(NET_NOT_GRANTED));
    }
}
