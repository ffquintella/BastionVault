//! Form-hook runner — mirrors the GUI's Tauri-backend sandbox
//! (`gui/src-tauri/src/plugin_hooks.rs`): empty linker (zero host
//! imports), 100 M fuel, 256 MiB memory, 4 MiB payload caps, and the
//! `(ptr << 32) | len`-packed `i64` return ABI emitted by the SDK's
//! `form_hook!` macro.
//!
//! ```no_run
//! let wasm = std::fs::read("target/wasm32-unknown-unknown/release/hooks.wasm").unwrap();
//! let out = bastion_plugin_testkit::hooks::run_form_hook(
//!     &wasm,
//!     "validate_create",
//!     &serde_json::json!({"name": "gh", "secret": "not base32!"}),
//! ).unwrap();
//! assert_eq!(out["ok"], false);
//! ```

use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, TypedFunc};

use crate::{map_call_err, TestkitError, DEFAULT_FUEL, DEFAULT_MEMORY_BYTES};

/// Payload cap in each direction — matches the GUI sandbox's
/// `MAX_PAYLOAD_BYTES`.
pub const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// Run a form-hook export with a JSON value in and a JSON value out.
pub fn run_form_hook(
    wasm: &[u8],
    export: &str,
    input: &serde_json::Value,
) -> Result<serde_json::Value, TestkitError> {
    let bytes = serde_json::to_vec(input).map_err(|e| TestkitError::Invoke(e.to_string()))?;
    let out = run_form_hook_raw(wasm, export, &bytes)?;
    serde_json::from_slice(&out)
        .map_err(|e| TestkitError::Invoke(format!("hook returned invalid JSON: {e}")))
}

/// Run a form-hook export on raw bytes. The module must export
/// `memory`, `bv_alloc(len: i32) -> i32`, and
/// `<export>(ptr: i32, len: i32) -> i64` (pointer/length packed).
pub fn run_form_hook_raw(
    wasm: &[u8],
    export: &str,
    input: &[u8],
) -> Result<Vec<u8>, TestkitError> {
    if input.len() > MAX_PAYLOAD_BYTES {
        return Err(TestkitError::PayloadTooLarge(format!(
            "hook input {} bytes exceeds {MAX_PAYLOAD_BYTES}",
            input.len()
        )));
    }

    let mut config = Config::new();
    config.consume_fuel(true);
    config.max_wasm_stack(1024 * 1024);
    let engine = Engine::new(&config).map_err(|e| TestkitError::Compile(e.to_string()))?;
    let module = Module::new(&engine, wasm).map_err(|e| TestkitError::Compile(e.to_string()))?;

    struct HookCtx {
        limits: StoreLimits,
    }
    let ctx = HookCtx {
        limits: StoreLimitsBuilder::new().memory_size(DEFAULT_MEMORY_BYTES).build(),
    };
    let mut store: Store<HookCtx> = Store::new(&engine, ctx);
    store.limiter(|c| &mut c.limits);
    store
        .set_fuel(DEFAULT_FUEL)
        .map_err(|e| TestkitError::Invoke(e.to_string()))?;

    // Empty linker: a hook that imports anything fails to instantiate,
    // exactly like the GUI sandbox.
    let linker: Linker<HookCtx> = Linker::new(&engine);
    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| TestkitError::Instantiate(e.to_string()))?;

    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or(TestkitError::MissingExport("memory"))?;
    let alloc: TypedFunc<i32, i32> = instance
        .get_typed_func(&mut store, "bv_alloc")
        .map_err(|_| TestkitError::MissingExport("bv_alloc"))?;
    let hook: TypedFunc<(i32, i32), i64> = instance
        .get_typed_func(&mut store, export)
        .map_err(|_| TestkitError::Invoke(format!("hook export `{export}` missing or wrong type")))?;

    let input_len = input.len() as i32;
    let input_ptr = alloc.call(&mut store, input_len).map_err(map_call_err)?;
    if input_ptr < 0 {
        return Err(TestkitError::Invoke("bv_alloc returned negative pointer".into()));
    }
    memory
        .write(&mut store, input_ptr as usize, input)
        .map_err(|e| TestkitError::Memory(e.to_string()))?;

    let packed = hook.call(&mut store, (input_ptr, input_len)).map_err(map_call_err)?;
    let out_ptr = (packed >> 32) as u32 as usize;
    let out_len = packed as u32 as usize;
    if out_len > MAX_PAYLOAD_BYTES {
        return Err(TestkitError::PayloadTooLarge(format!(
            "hook output {out_len} bytes exceeds {MAX_PAYLOAD_BYTES}"
        )));
    }
    let end = out_ptr
        .checked_add(out_len)
        .ok_or(TestkitError::ResponseOutOfBounds)?;
    let data = memory.data(&store);
    if end > data.len() {
        return Err(TestkitError::ResponseOutOfBounds);
    }
    Ok(data[out_ptr..end].to_vec())
}
