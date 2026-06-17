//! Plugin Extensibility v1 / Phase 4 — form-hook WASM sandbox.
//!
//! Form hooks are tiny WASM modules a plugin ships alongside its
//! `surface.json` to validate / rewrite / react to form data on the
//! client side. They run in the **Tauri backend process**, not in
//! the webview — no DOM access, no network, no clocks beyond what
//! Wasmtime gives them by default.
//!
//! The ABI mirrors the existing server-side `bv_run` shape so plugin
//! authors using `bastion-plugin-sdk` can reuse the same export
//! pattern:
//!
//! * `bv_alloc(size: i32) -> i32` — host calls this to reserve
//!   `size` bytes in the plugin's linear memory; returns the offset.
//! * `<export>(ptr: i32, len: i32) -> i64` — packs the output as
//!   `(ptr << 32) | len`. The host reads `len` bytes starting at
//!   `ptr` from the same linear memory and decodes them as a UTF-8
//!   JSON string.
//! * `memory` — the linear memory export.
//!
//! Limits:
//! * 100 M instructions per call (`FUEL_PER_CALL`).
//! * 256 MiB memory ceiling enforced via Wasmtime's
//!   [`StoreLimitsBuilder`].
//! * Compilation result is cached per `sha256` so repeated calls
//!   skip cranelift.

use std::sync::{Mutex, OnceLock};

use thiserror::Error;
use wasmtime::{Engine, Module, Store, StoreLimits, StoreLimitsBuilder};

/// Per-call instruction ceiling. Matches the server runtime's default.
pub const FUEL_PER_CALL: u64 = 100_000_000;

/// Per-call memory ceiling.
pub const MEMORY_BYTES: usize = 256 * 1024 * 1024;

/// Cap on the input/output JSON the hook can exchange with the host.
/// Form hooks shouldn't need more than this; refusing larger payloads
/// keeps a buggy or hostile hook from eating the entire memory budget
/// just by allocating a giant string.
pub const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum HookError {
    #[error("compile: {0}")]
    Compile(String),
    #[error("instantiate: {0}")]
    Instantiate(String),
    #[error("missing memory export")]
    MissingMemory,
    #[error("missing export `{0}`")]
    MissingExport(String),
    #[error("missing required `bv_alloc` export")]
    MissingAlloc,
    #[error("invocation: {0}")]
    Invocation(String),
    #[error("input too large ({0} bytes; max is 4 MiB)")]
    InputTooLarge(usize),
    #[error("hook returned an over-budget payload ({0} bytes; max is 4 MiB)")]
    OutputTooLarge(usize),
    #[error("hook returned out-of-bounds (ptr/len) into linear memory")]
    OutputOutOfBounds,
    #[error("output is not valid UTF-8")]
    OutputNotUtf8,
}

/// Lazily-built process-global Wasmtime engine with fuel metering on.
/// Fuel must be enabled at engine construction; storing one shared
/// engine lets the module cache hand out compiled modules across
/// every form-hook call without re-paying the cranelift cost.
fn engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        // Defence-in-depth: we don't trust the bytes; even though the
        // ABI surface is a string in / string out, we want NaN-canon
        // and SIMD-disabled-by-default semantics so the JIT'd code
        // is reproducible.
        config.cranelift_nan_canonicalization(true);
        Engine::new(&config).expect("wasmtime engine")
    })
}

/// Compiled-module cache keyed by content hash. The value is the
/// already-compiled `Module`, which is cheap to clone (an `Arc`
/// internally).
fn module_cache() -> &'static Mutex<std::collections::HashMap<String, Module>> {
    static CACHE: OnceLock<Mutex<std::collections::HashMap<String, Module>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn get_or_compile(sha256: &str, bytes: &[u8]) -> Result<Module, HookError> {
    {
        let cache = module_cache().lock().unwrap();
        if let Some(m) = cache.get(sha256) {
            return Ok(m.clone());
        }
    }
    let module =
        Module::from_binary(engine(), bytes).map_err(|e| HookError::Compile(e.to_string()))?;
    let mut cache = module_cache().lock().unwrap();
    cache.insert(sha256.to_string(), module.clone());
    Ok(module)
}

/// Drop a compiled module from the cache. Called when the asset bytes
/// behind a hash become invalid (e.g. after the user purges the
/// surface cache). Best-effort — a missed eviction wastes memory but
/// can't poison correctness because the cache is keyed by hash.
#[allow(dead_code)]
pub fn evict(sha256: &str) {
    let mut cache = module_cache().lock().unwrap();
    cache.remove(sha256);
}

/// Run one hook export with `input_json`, return its UTF-8 JSON
/// output. The caller passes `sha256` so the host module cache can
/// short-circuit recompilation across repeated hook calls.
pub fn run_hook(
    sha256: &str,
    wasm_bytes: &[u8],
    export: &str,
    input_json: &str,
) -> Result<String, HookError> {
    if input_json.len() > MAX_PAYLOAD_BYTES {
        return Err(HookError::InputTooLarge(input_json.len()));
    }
    let module = get_or_compile(sha256, wasm_bytes)?;

    let limits: StoreLimits = StoreLimitsBuilder::new()
        .memory_size(MEMORY_BYTES)
        .build();

    let mut store: Store<StoreLimits> = Store::new(engine(), limits);
    store.limiter(|s| s);
    store
        .set_fuel(FUEL_PER_CALL)
        .map_err(|e| HookError::Instantiate(e.to_string()))?;

    // No host imports — a hook either runs as pure compute on the
    // input string or fails to instantiate. Plugin authors who need
    // host services should build a server-side plugin instead.
    let linker = wasmtime::Linker::new(engine());
    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| HookError::Instantiate(e.to_string()))?;

    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or(HookError::MissingMemory)?;
    let bv_alloc = instance
        .get_typed_func::<i32, i32>(&mut store, "bv_alloc")
        .map_err(|_| HookError::MissingAlloc)?;
    let entry = instance
        .get_typed_func::<(i32, i32), i64>(&mut store, export)
        .map_err(|_| HookError::MissingExport(export.to_string()))?;

    // Allocate input space inside the plugin and write the JSON bytes
    // into it.
    let input_bytes = input_json.as_bytes();
    let in_len = input_bytes.len() as i32;
    let in_ptr = bv_alloc
        .call(&mut store, in_len)
        .map_err(|e| HookError::Invocation(e.to_string()))?;
    memory
        .write(&mut store, in_ptr as usize, input_bytes)
        .map_err(|e| HookError::Invocation(e.to_string()))?;

    let packed = entry
        .call(&mut store, (in_ptr, in_len))
        .map_err(|e| HookError::Invocation(e.to_string()))?;
    let out_ptr = (packed >> 32) as i32;
    let out_len = (packed as u32) as i32;

    if out_len < 0 || (out_len as usize) > MAX_PAYLOAD_BYTES {
        return Err(HookError::OutputTooLarge(out_len.max(0) as usize));
    }
    let out_ptr_u = out_ptr as usize;
    let out_len_u = out_len as usize;
    let mem_size = memory.data_size(&store);
    if out_ptr_u.checked_add(out_len_u).is_none_or(|end| end > mem_size) {
        return Err(HookError::OutputOutOfBounds);
    }
    let mut buf = vec![0u8; out_len_u];
    memory
        .read(&store, out_ptr_u, &mut buf)
        .map_err(|_| HookError::OutputOutOfBounds)?;
    String::from_utf8(buf).map_err(|_| HookError::OutputNotUtf8)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal WAT module that:
    /// * exports `memory`
    /// * `bv_alloc(size)` returns a fixed offset in linear memory
    /// * `validate(ptr, len)` writes the byte string `"ok"` to a
    ///   different offset and returns its packed (ptr,len).
    const ECHO_OK_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (data (i32.const 1024) "ok")
          (func (export "bv_alloc") (param i32) (result i32)
            i32.const 2048)
          (func (export "validate") (param i32 i32) (result i64)
            ;; output ptr=1024, len=2 packed as (ptr<<32)|len
            i64.const 4398046511106)) ;; (1024<<32)|2 = 4398046511104+2
    "#;

    fn compile_wat(wat: &str) -> Vec<u8> {
        wat::parse_str(wat).expect("valid wat")
    }

    fn sha(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(bytes))
    }

    #[test]
    fn runs_simple_hook_round_trip() {
        let bytes = compile_wat(ECHO_OK_WAT);
        let h = sha(&bytes);
        let out = run_hook(&h, &bytes, "validate", "{}").unwrap();
        assert_eq!(out, "ok");
    }

    #[test]
    fn cache_short_circuits_recompile() {
        let bytes = compile_wat(ECHO_OK_WAT);
        let h = sha(&bytes);
        // First call compiles; second call should hit the cache.
        let _ = run_hook(&h, &bytes, "validate", "{}").unwrap();
        let _ = run_hook(&h, &bytes, "validate", "{}").unwrap();
        // We can't easily observe the compile path from outside,
        // but at minimum the second call must succeed without
        // re-supplying bytes.
        let again =
            run_hook(&h, &[/* bogus, won't be parsed */], "validate", "{}").unwrap();
        assert_eq!(again, "ok");
    }

    #[test]
    fn missing_export_is_caught() {
        let bytes = compile_wat(ECHO_OK_WAT);
        let h = sha(&bytes);
        let err = run_hook(&h, &bytes, "no_such_thing", "{}").unwrap_err();
        assert!(matches!(err, HookError::MissingExport(_)));
    }

    #[test]
    fn missing_alloc_export_rejected() {
        // Same memory + entry but no `bv_alloc`.
        let wat = r#"
            (module
              (memory (export "memory") 1)
              (data (i32.const 1024) "ok")
              (func (export "validate") (param i32 i32) (result i64)
                i64.const 4398046511106))
        "#;
        let bytes = compile_wat(wat);
        let h = sha(&bytes);
        let err = run_hook(&h, &bytes, "validate", "{}").unwrap_err();
        assert!(matches!(err, HookError::MissingAlloc));
    }

    #[test]
    fn rejects_out_of_bounds_output() {
        // Hook claims the output starts at a wildly out-of-bounds
        // offset. We must refuse rather than read past memory.
        let wat = r#"
            (module
              (memory (export "memory") 1)
              (func (export "bv_alloc") (param i32) (result i32) i32.const 0)
              (func (export "validate") (param i32 i32) (result i64)
                ;; ptr=99999999, len=10 — well outside a single page
                i64.const 429496729600000010))
        "#;
        let bytes = compile_wat(wat);
        let h = sha(&bytes);
        let err = run_hook(&h, &bytes, "validate", "{}").unwrap_err();
        // Either OutOfBounds or OutputTooLarge depending on values;
        // both are correct refusal paths.
        assert!(matches!(
            err,
            HookError::OutputOutOfBounds | HookError::OutputTooLarge(_)
        ));
    }

    #[test]
    fn fuel_exhaustion_traps() {
        // Tight loop inside the hook entry — must run out of fuel.
        let wat = r#"
            (module
              (memory (export "memory") 1)
              (func (export "bv_alloc") (param i32) (result i32) i32.const 0)
              (func (export "validate") (param i32 i32) (result i64)
                (loop (br 0))
                i64.const 0))
        "#;
        let bytes = compile_wat(wat);
        let h = sha(&bytes);
        let err = run_hook(&h, &bytes, "validate", "{}").unwrap_err();
        assert!(matches!(err, HookError::Invocation(_)));
    }

    #[test]
    fn rejects_oversize_input() {
        let bytes = compile_wat(ECHO_OK_WAT);
        let h = sha(&bytes);
        let huge = "x".repeat(MAX_PAYLOAD_BYTES + 1);
        let err = run_hook(&h, &bytes, "validate", &huge).unwrap_err();
        assert!(matches!(err, HookError::InputTooLarge(_)));
    }

    #[test]
    fn no_host_imports_means_imports_fail_to_instantiate() {
        // A module that imports anything from the host should fail
        // because the linker is empty. Defence-in-depth proof.
        let wat = r#"
            (module
              (import "host" "log" (func (param i32 i32)))
              (memory (export "memory") 1)
              (func (export "bv_alloc") (param i32) (result i32) i32.const 0)
              (func (export "validate") (param i32 i32) (result i64) i64.const 0))
        "#;
        let bytes = compile_wat(wat);
        let h = sha(&bytes);
        let err = run_hook(&h, &bytes, "validate", "{}").unwrap_err();
        assert!(matches!(err, HookError::Instantiate(_)));
    }
}
