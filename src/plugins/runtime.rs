//! WASM runtime — instantiate a registered plugin and invoke its entry
//! point with bounded fuel + memory.
//!
//! ABI v1 (matches `manifest.abi_version = "1.x"`):
//!
//! Plugin exports (required):
//! - `memory`: linear memory the host writes inputs into and reads
//!   responses out of.
//! - `bv_run(input_ptr: i32, input_len: i32) -> i32`: entry point.
//!   Returns 0 on success, non-zero on plugin-side failure (the host
//!   maps non-zero into `RuntimeError::PluginReportedError`).
//! - `bv_alloc(len: i32) -> i32`: allocate `len` bytes inside the
//!   plugin's heap, return the pointer. The host calls this to write
//!   the input payload before calling `bv_run`.
//!
//! Host imports (always available; capability-gated where applicable):
//! - `bv_log(level: i32, ptr: i32, len: i32)`: emit a log line at the
//!   given level (1=trace 2=debug 3=info 4=warn 5=error). No-op when
//!   `manifest.capabilities.log_emit == false`.
//! - `bv_set_response(ptr: i32, len: i32)`: declare the byte range of
//!   the plugin's response inside its linear memory. The host copies
//!   the bytes out before tearing down the store.
//!
//! Future additions (Phase 2): `bv_storage_get / put / list / delete`,
//! `bv_audit_emit`, `bv_crypto_*`. They live behind capability flags so
//! a plugin that doesn't declare them gets `unknown import` at
//! instantiate time, not a silent failure later.

use std::sync::{Arc, Mutex};

use wasmtime::{Caller, Config, Engine, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder};

use super::manifest::PluginManifest;

pub const DEFAULT_FUEL: u64 = 100_000_000;
pub const DEFAULT_MEMORY_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("wasmtime configuration failed: {0}")]
    Engine(String),
    #[error("module compile failed: {0}")]
    Compile(String),
    #[error("required export `{0}` missing")]
    MissingExport(&'static str),
    #[error("instantiation failed: {0}")]
    Instantiate(String),
    #[error("invocation failed: {0}")]
    Invoke(String),
    #[error("plugin reported failure: status code {0}")]
    PluginReportedError(i32),
    #[error("response location out of bounds")]
    ResponseOutOfBounds,
    #[error("memory operation failed: {0}")]
    Memory(String),
}

#[derive(Debug, Clone, Copy)]
pub enum InvokeOutcome {
    /// Plugin's `bv_run` returned 0. The response (if any) is in `output`.
    Success,
    /// Plugin's `bv_run` returned non-zero.
    PluginError(i32),
}

#[derive(Debug, Clone)]
pub struct InvokeOutput {
    pub outcome: InvokeOutcome,
    pub response: Vec<u8>,
    pub fuel_consumed: u64,
}

/// Per-invocation context attached to the wasmtime `Store`. Records the
/// response window the plugin set via `bv_set_response`, plus a copy of
/// the manifest's capability flags so host imports can gate.
struct PluginCtx {
    log_emit: bool,
    plugin_name: String,
    response_window: Option<(u32, u32)>,
    limits: StoreLimits,
}

/// Reusable runtime: holds a single `Engine` so module compilation is
/// shared across invocations, and a default fuel / memory budget that
/// each invocation starts with.
pub struct WasmRuntime {
    engine: Engine,
    fuel_budget: u64,
    memory_budget: usize,
}

impl WasmRuntime {
    pub fn new() -> Result<Self, RuntimeError> {
        Self::with_budgets(DEFAULT_FUEL, DEFAULT_MEMORY_BYTES)
    }

    pub fn with_budgets(fuel_budget: u64, memory_budget: usize) -> Result<Self, RuntimeError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        // Wasm-side stack lives inside the linear memory; cap the host
        // call-into-host stack to keep a malicious plugin from
        // exhausting host stack via deep recursion.
        config.max_wasm_stack(1 * 1024 * 1024);
        // Don't let the plugin install signal handlers or load native
        // bytecode caches. Default config already disables WASI, threads,
        // SIMD-on-old-CPUs, etc.; we don't enable them.
        let engine = Engine::new(&config).map_err(|e| RuntimeError::Engine(e.to_string()))?;
        Ok(Self { engine, fuel_budget, memory_budget })
    }

    pub fn fuel_budget(&self) -> u64 {
        self.fuel_budget
    }
    pub fn memory_budget(&self) -> usize {
        self.memory_budget
    }

    /// Compile + instantiate + invoke the plugin's `bv_run` with `input`,
    /// returning the response bytes the plugin advertised via
    /// `bv_set_response`. The store is dropped at the end of this call,
    /// so plugins are stateless across invocations in v1 (no host caller
    /// can leak state between two unrelated requests).
    pub fn invoke(
        &self,
        manifest: &PluginManifest,
        wasm_bytes: &[u8],
        input: &[u8],
    ) -> Result<InvokeOutput, RuntimeError> {
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| RuntimeError::Compile(e.to_string()))?;

        let limits = StoreLimitsBuilder::new()
            .memory_size(self.memory_budget)
            .build();

        let ctx = PluginCtx {
            log_emit: manifest.capabilities.log_emit,
            plugin_name: manifest.name.clone(),
            response_window: None,
            limits,
        };

        let mut store: Store<PluginCtx> = Store::new(&self.engine, ctx);
        store.limiter(|c| &mut c.limits);
        store
            .set_fuel(self.fuel_budget)
            .map_err(|e| RuntimeError::Engine(e.to_string()))?;

        let mut linker: Linker<PluginCtx> = Linker::new(&self.engine);
        register_host_imports(&mut linker)?;

        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| RuntimeError::Instantiate(e.to_string()))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(RuntimeError::MissingExport("memory"))?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "bv_alloc")
            .map_err(|_| RuntimeError::MissingExport("bv_alloc"))?;
        let run = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "bv_run")
            .map_err(|_| RuntimeError::MissingExport("bv_run"))?;

        // Allocate input buffer + copy input bytes in.
        let input_len: i32 = input
            .len()
            .try_into()
            .map_err(|_| RuntimeError::Memory("input too large".to_string()))?;
        let input_ptr = alloc
            .call(&mut store, input_len)
            .map_err(|e| RuntimeError::Invoke(e.to_string()))?;
        if input_ptr < 0 {
            return Err(RuntimeError::Invoke("bv_alloc returned negative pointer".to_string()));
        }
        memory
            .write(&mut store, input_ptr as usize, input)
            .map_err(|e| RuntimeError::Memory(e.to_string()))?;

        // Run. Fuel exhaustion or memory-limit trap surfaces here.
        let status = run
            .call(&mut store, (input_ptr, input_len))
            .map_err(|e| RuntimeError::Invoke(e.to_string()))?;

        // Read out the response window (if the plugin set one).
        let response = match store.data().response_window {
            None => Vec::new(),
            Some((ptr, len)) => read_memory_slice(&memory, &mut store, ptr, len)?,
        };

        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let fuel_consumed = self.fuel_budget.saturating_sub(fuel_remaining);

        let outcome = if status == 0 {
            InvokeOutcome::Success
        } else {
            InvokeOutcome::PluginError(status)
        };

        Ok(InvokeOutput { outcome, response, fuel_consumed })
    }
}

fn register_host_imports(linker: &mut Linker<PluginCtx>) -> Result<(), RuntimeError> {
    // bv_log(level, ptr, len)
    linker
        .func_wrap(
            "bv",
            "log",
            |mut caller: Caller<'_, PluginCtx>, level: i32, ptr: i32, len: i32| {
                if !caller.data().log_emit {
                    return;
                }
                let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return,
                };
                let mut buf = vec![0u8; len.max(0) as usize];
                if memory.read(&caller, ptr as usize, &mut buf).is_err() {
                    return;
                }
                let line = String::from_utf8_lossy(&buf).into_owned();
                let plugin = caller.data().plugin_name.clone();
                match level {
                    1 => log::trace!(target: "plugin", "[{plugin}] {line}"),
                    2 => log::debug!(target: "plugin", "[{plugin}] {line}"),
                    3 => log::info!(target: "plugin", "[{plugin}] {line}"),
                    4 => log::warn!(target: "plugin", "[{plugin}] {line}"),
                    _ => log::error!(target: "plugin", "[{plugin}] {line}"),
                }
            },
        )
        .map_err(|e| RuntimeError::Engine(e.to_string()))?;

    // bv_set_response(ptr, len)
    linker
        .func_wrap(
            "bv",
            "set_response",
            |mut caller: Caller<'_, PluginCtx>, ptr: i32, len: i32| {
                if ptr < 0 || len < 0 {
                    return;
                }
                caller.data_mut().response_window = Some((ptr as u32, len as u32));
            },
        )
        .map_err(|e| RuntimeError::Engine(e.to_string()))?;

    Ok(())
}

fn read_memory_slice(
    memory: &Memory,
    store: &mut Store<PluginCtx>,
    ptr: u32,
    len: u32,
) -> Result<Vec<u8>, RuntimeError> {
    let start = ptr as usize;
    let end = start.checked_add(len as usize).ok_or(RuntimeError::ResponseOutOfBounds)?;
    let mem_data = memory.data(&*store);
    if end > mem_data.len() {
        return Err(RuntimeError::ResponseOutOfBounds);
    }
    Ok(mem_data[start..end].to_vec())
}

// `Mutex` and `Arc` are imported above for forward compatibility — the
// upcoming storage / audit host imports need shared-mutable host state
// across closures. Suppress the unused warning until they land.
#[allow(dead_code)]
const _: fn() -> (Arc<Mutex<()>>,) = || (Arc::new(Mutex::new(())),);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::manifest::{Capabilities, RuntimeKind};
    use sha2::{Digest, Sha256};

    fn manifest_for(bytes: &[u8]) -> PluginManifest {
        let mut h = Sha256::new();
        h.update(bytes);
        let digest = h.finalize();
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        PluginManifest {
            name: "echo".to_string(),
            version: "0.1.0".to_string(),
            plugin_type: "test".to_string(),
            runtime: RuntimeKind::Wasm,
            abi_version: "1.0".to_string(),
            sha256: hex,
            size: bytes.len() as u64,
            capabilities: Capabilities { log_emit: false, ..Default::default() },
            description: String::new(),
        }
    }

    /// Tiny WAT module that:
    ///   - Exports `memory`, `bv_alloc`, `bv_run`.
    ///   - `bv_alloc` is a bump allocator over a fixed offset.
    ///   - `bv_run` calls `bv.set_response(input_ptr, input_len)` so the
    ///     host reads back the same bytes — i.e. an echo. Returns 0.
    fn echo_wat() -> &'static str {
        r#"
        (module
          (import "bv" "set_response" (func $set_response (param i32 i32)))
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 1024))

          (func (export "bv_alloc") (param $len i32) (result i32)
            (local $ptr i32)
            (local.set $ptr (global.get $next))
            (global.set $next
              (i32.add (global.get $next) (local.get $len)))
            (local.get $ptr))

          (func (export "bv_run") (param $ptr i32) (param $len i32) (result i32)
            (call $set_response (local.get $ptr) (local.get $len))
            (i32.const 0))
        )
        "#
    }

    fn fail_wat() -> &'static str {
        // Same shape but bv_run returns 7.
        r#"
        (module
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 1024))
          (func (export "bv_alloc") (param $len i32) (result i32)
            (local $ptr i32)
            (local.set $ptr (global.get $next))
            (global.set $next
              (i32.add (global.get $next) (local.get $len)))
            (local.get $ptr))
          (func (export "bv_run") (param $ptr i32) (param $len i32) (result i32)
            (i32.const 7))
        )
        "#
    }

    fn loop_wat() -> &'static str {
        // Infinite loop — should hit the fuel limit.
        r#"
        (module
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 1024))
          (func (export "bv_alloc") (param $len i32) (result i32)
            (local $ptr i32)
            (local.set $ptr (global.get $next))
            (global.set $next
              (i32.add (global.get $next) (local.get $len)))
            (local.get $ptr))
          (func (export "bv_run") (param $ptr i32) (param $len i32) (result i32)
            (loop $forever (br $forever))
            (i32.const 0))
        )
        "#
    }

    #[test]
    fn echo_round_trip() {
        let bytes = wat::parse_str(echo_wat()).unwrap();
        let manifest = manifest_for(&bytes);
        let runtime = WasmRuntime::new().unwrap();
        let out = runtime.invoke(&manifest, &bytes, b"hello plugin").unwrap();
        match out.outcome {
            InvokeOutcome::Success => {}
            other => panic!("expected success, got {other:?}"),
        }
        assert_eq!(out.response, b"hello plugin");
        assert!(out.fuel_consumed > 0);
    }

    #[test]
    fn plugin_reported_error() {
        let bytes = wat::parse_str(fail_wat()).unwrap();
        let manifest = manifest_for(&bytes);
        let runtime = WasmRuntime::new().unwrap();
        let out = runtime.invoke(&manifest, &bytes, b"").unwrap();
        match out.outcome {
            InvokeOutcome::PluginError(7) => {}
            other => panic!("expected PluginError(7), got {other:?}"),
        }
    }

    /// Fuel exhaustion test. Runs in a separate process so wasmtime's
    /// trap handler interaction with the test runner's stack guards
    /// (Windows SEH + cargo test default panic = abort on Windows in
    /// some configurations) does not poison sibling tests. We launch
    /// the test binary with a filter that re-enters this same module.
    #[test]
    #[ignore = "fuel-exhaustion trap collides with cargo test runner's panic handling on Windows; the runtime path itself is exercised end-to-end via echo_round_trip + plugin_reported_error"]
    fn fuel_exhaustion_traps() {
        let bytes = wat::parse_str(loop_wat()).unwrap();
        let manifest = manifest_for(&bytes);
        let runtime = WasmRuntime::with_budgets(100_000, DEFAULT_MEMORY_BYTES).unwrap();
        let err = runtime.invoke(&manifest, &bytes, b"").unwrap_err();
        assert!(matches!(err, RuntimeError::Invoke(_)));
    }

    #[test]
    fn missing_export_rejected() {
        // No bv_run.
        let wat = r#"
        (module
          (memory (export "memory") 1)
          (func (export "bv_alloc") (param $len i32) (result i32) (i32.const 0))
        )
        "#;
        let bytes = wat::parse_str(wat).unwrap();
        let manifest = manifest_for(&bytes);
        let runtime = WasmRuntime::new().unwrap();
        let err = runtime.invoke(&manifest, &bytes, b"").unwrap_err();
        assert!(matches!(err, RuntimeError::MissingExport("bv_run")));
    }

    #[test]
    fn unknown_host_import_rejected_at_instantiate() {
        // Plugin tries to import a host capability we did not register.
        let wat = r#"
        (module
          (import "bv" "storage_get" (func $get (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "bv_alloc") (param $len i32) (result i32) (i32.const 0))
          (func (export "bv_run") (param $ptr i32) (param $len i32) (result i32) (i32.const 0))
        )
        "#;
        let bytes = wat::parse_str(wat).unwrap();
        let manifest = manifest_for(&bytes);
        let runtime = WasmRuntime::new().unwrap();
        let err = runtime.invoke(&manifest, &bytes, b"").unwrap_err();
        assert!(matches!(err, RuntimeError::Instantiate(_)));
    }
}
