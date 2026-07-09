//! Unit-test harness for BastionVault WASM plugins.
//!
//! Drives a compiled plugin artifact (`.wasm`, or WebAssembly text for
//! fixtures) through the exact `bv_run` ABI the BastionVault server
//! uses — same required exports (`memory`, `bv_alloc`, `bv_run`), same
//! `bv.*` host-import surface, same return-code conventions — but
//! backed by an in-memory mock host instead of a live vault:
//!
//! - **Storage** is a `BTreeMap` with the same prefix-rebase and
//!   isolation rules as the server (`core/plugins/<name>/data/...`,
//!   `STORAGE_FORBIDDEN` outside the declared prefix, `..` rejected).
//! - **Config** is a plain map seeded by the test.
//! - **Logs** and **audit events** are captured for assertion instead
//!   of being written to the host log / audit broker.
//! - **Clock** (`bv.now_unix_ms`) can be pinned to a fixed value for
//!   deterministic TOTP / expiry tests.
//! - **Crypto** (`bv.crypto_*`) is a deterministic mock — the
//!   `allowed_keys` capability gate is enforced exactly like the
//!   server's, but the transforms are reversible test stand-ins,
//!   **not** real cryptography (see [`mock crypto`](#mock-crypto)).
//!
//! ```no_run
//! use bastion_plugin_testkit::TestHost;
//!
//! let wasm = std::fs::read("target/wasm32-wasip1/release/my_plugin.wasm").unwrap();
//! let host = TestHost::builder("my-plugin")
//!     .storage_prefix("")                    // grant full data-root access
//!     .config("api_label", "prod")
//!     .now_ms(1_700_000_000_000)
//!     .build();
//! let out = host
//!     .invoke(&wasm, "write", "codes/gh", serde_json::json!({"secret": "JBSW"}))
//!     .unwrap();
//! assert!(out.is_success());
//! assert!(host.storage_dump().contains_key("codes/gh"));
//! ```
//!
//! # Mock crypto
//!
//! The `bv.crypto_*` mock is deliberately transparent so tests can
//! assert on outputs: `encrypt` → `bvault:test:<b64(plaintext)>`,
//! `sign` → `bvault:test:sig:<b64(sha256(msg))>`, `hmac` →
//! `bvault:test:hmac:<b64(sha256(key || 0x00 || msg))>`; `decrypt` and
//! `verify` invert those. `crypto_random` is a seeded SplitMix64
//! stream (see [`TestHostBuilder::rng_seed`]). None of this is secure;
//! it exists so a plugin's *plumbing* around the crypto capability is
//! testable without a Transit mount.
//!
//! # Keeping honest with the real runtime
//!
//! [`HOST_IMPORTS`] enumerates the mirrored import surface and
//! [`conformance_wat`] emits a module importing every entry. The host
//! repo runs that module through the real `WasmRuntime`
//! (`tests/test_plugin_testkit_parity.rs`) so drift between this crate
//! and `src/plugins/runtime.rs` fails CI instead of lying to plugin
//! authors.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use wasmtime::{
    AsContextMut, Caller, Config, Engine, Linker, Memory, Module, Store, StoreLimits,
    StoreLimitsBuilder, Trap, TypedFunc,
};

pub mod app;
pub mod hooks;

/// Default per-invocation fuel budget — matches
/// `bastion_vault::plugins::runtime::DEFAULT_FUEL`.
pub const DEFAULT_FUEL: u64 = 100_000_000;
/// Default linear-memory cap — matches
/// `bastion_vault::plugins::runtime::DEFAULT_MEMORY_BYTES`.
pub const DEFAULT_MEMORY_BYTES: usize = 256 * 1024 * 1024;

// Return codes — same values the server's host imports use.
pub const STORAGE_NOT_FOUND: i32 = -1;
pub const STORAGE_FORBIDDEN: i32 = -2;
pub const STORAGE_BUFFER_TOO_SMALL: i32 = -3;
pub const STORAGE_INTERNAL_ERROR: i32 = -4;
pub const AUDIT_FORBIDDEN: i32 = -2;
pub const CRYPTO_FORBIDDEN: i32 = -2;
pub const CRYPTO_BACKEND_ERROR: i32 = -5;

#[derive(Debug, thiserror::Error)]
pub enum TestkitError {
    #[error("module compile failed: {0}")]
    Compile(String),
    #[error("instantiation failed: {0}")]
    Instantiate(String),
    #[error("required export `{0}` missing")]
    MissingExport(&'static str),
    #[error("invocation failed: {0}")]
    Invoke(String),
    #[error("fuel budget exhausted")]
    FuelExhausted,
    #[error("memory operation failed: {0}")]
    Memory(String),
    #[error("response location out of bounds")]
    ResponseOutOfBounds,
    #[error("payload too large: {0}")]
    PayloadTooLarge(String),
}

/// Mirror of `bastion_vault::plugins::runtime::InvokeOutcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvokeOutcome {
    /// `bv_run` returned 0.
    Success,
    /// `bv_run` returned non-zero.
    PluginError(i32),
}

/// A captured `bv.log` line.
#[derive(Debug, Clone)]
pub struct LogLine {
    /// 1 = trace, 2 = debug, 3 = info, 4 = warn, ≥5 = error.
    pub level: i32,
    pub line: String,
}

/// Result of one `bv_run` invocation, plus everything the plugin did
/// to the mock host while it ran.
#[derive(Debug, Clone)]
pub struct TestInvocation {
    pub outcome: InvokeOutcome,
    /// Raw bytes the plugin advertised via `bv.set_response`.
    pub response: Vec<u8>,
    pub fuel_consumed: u64,
    /// `bv.log` lines emitted during this invocation.
    pub logs: Vec<LogLine>,
    /// `bv.audit_emit` payloads accepted during this invocation, in
    /// the same envelope the server would audit:
    /// `{"path": "sys/plugins/<name>/event", "data": {"plugin_event": ...}}`.
    pub audit_events: Vec<serde_json::Value>,
}

impl TestInvocation {
    pub fn is_success(&self) -> bool {
        matches!(self.outcome, InvokeOutcome::Success)
    }

    /// Plugin status code: 0 on success, the non-zero code otherwise.
    pub fn status(&self) -> i32 {
        match self.outcome {
            InvokeOutcome::Success => 0,
            InvokeOutcome::PluginError(c) => c,
        }
    }

    /// Response parsed as JSON, or `None` when empty / not JSON.
    pub fn response_json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.response).ok()
    }

    /// The `data` member of a JSON response — the same field the
    /// server's `translate_response` surfaces to callers. `None` for
    /// empty responses, non-JSON responses, and `{"data": null}`.
    pub fn data(&self) -> Option<serde_json::Value> {
        match self.response_json()?.get("data") {
            Some(serde_json::Value::Null) | None => None,
            Some(v) => Some(v.clone()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum TestClock {
    System,
    Fixed(i64),
}

/// SplitMix64 — tiny deterministic PRNG for `bv.crypto_random`.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

/// Mutable mock-host state shared across invocations of one
/// [`TestHost`]. Storage persists between invokes — the same semantics
/// a real plugin gets from barrier-backed storage.
struct HostState {
    storage: BTreeMap<String, Vec<u8>>,
    config: BTreeMap<String, String>,
    logs: Vec<LogLine>,
    audit: Vec<serde_json::Value>,
    clock: TestClock,
    rng: SplitMix64,
}

/// Per-invocation store context — the testkit's `PluginCtx`.
struct Ctx {
    plugin_name: String,
    log_emit: bool,
    audit_emit: bool,
    storage_prefix: Option<String>,
    allowed_keys: BTreeSet<String>,
    response_window: Option<(u32, u32)>,
    limits: StoreLimits,
    shared: Arc<Mutex<HostState>>,
}

impl Ctx {
    /// Same rules as `PluginCtx::rebase_key` in the server runtime.
    fn rebase_key(&self, requested: &str) -> Option<String> {
        let prefix = self.storage_prefix.as_deref()?;
        let prefix_norm = prefix.trim_end_matches('/');
        let req_norm = requested.trim_start_matches('/');
        if !prefix_norm.is_empty()
            && req_norm != prefix_norm
            && !req_norm.starts_with(&format!("{prefix_norm}/"))
        {
            return None;
        }
        if req_norm.contains("..") {
            return None;
        }
        Some(data_key(&self.plugin_name, req_norm))
    }
}

fn data_key(name: &str, rel: &str) -> String {
    format!("core/plugins/{name}/data/{rel}")
}

/// Builder for [`TestHost`]. The defaults mirror a manifest with
/// `log_emit = true` and every other capability off.
pub struct TestHostBuilder {
    name: String,
    log_emit: bool,
    audit_emit: bool,
    storage_prefix: Option<String>,
    allowed_keys: BTreeSet<String>,
    config: BTreeMap<String, String>,
    storage_seed: BTreeMap<String, Vec<u8>>,
    clock: TestClock,
    rng_seed: u64,
    fuel_budget: u64,
    memory_budget: usize,
}

impl TestHostBuilder {
    /// Grant the storage capability. The prefix has the same meaning
    /// as `manifest.capabilities.storage_prefix` — pass `""` for
    /// unrestricted access to the plugin's own data root.
    pub fn storage_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.storage_prefix = Some(prefix.into());
        self
    }

    /// Toggle the `log_emit` capability (default `true`). When off,
    /// `bv.log` lines are dropped — exactly like the server.
    pub fn log_emit(mut self, on: bool) -> Self {
        self.log_emit = on;
        self
    }

    /// Grant the `audit_emit` capability (default off — calls return
    /// `AUDIT_FORBIDDEN`).
    pub fn audit_emit(mut self, on: bool) -> Self {
        self.audit_emit = on;
        self
    }

    /// Add a Transit key handle (e.g. `"transit/keys/wrap"`) to the
    /// `allowed_keys` allowlist consulted by the `bv.crypto_*` mock.
    pub fn allow_key(mut self, key: impl Into<String>) -> Self {
        self.allowed_keys.insert(key.into());
        self
    }

    /// Seed an operator-config value readable via `bv.config_get`.
    pub fn config(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.insert(key.into(), value.into());
        self
    }

    /// Seed a storage value under the plugin's data root. The key is
    /// plugin-relative (the same string the plugin would pass to
    /// `bv.storage_get`); prefix enforcement is deliberately skipped
    /// so tests can stage out-of-prefix state.
    pub fn storage(mut self, rel_key: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        self.storage_seed.insert(rel_key.into(), value.into());
        self
    }

    /// Pin `bv.now_unix_ms` to a fixed value.
    pub fn now_ms(mut self, ms: i64) -> Self {
        self.clock = TestClock::Fixed(ms);
        self
    }

    /// Seed the deterministic `bv.crypto_random` stream (default
    /// `0xBA57_1011`). Two hosts built with the same seed produce the
    /// same byte stream.
    pub fn rng_seed(mut self, seed: u64) -> Self {
        self.rng_seed = seed;
        self
    }

    /// Override the per-invocation fuel budget (default 100 M, like
    /// the server).
    pub fn fuel(mut self, budget: u64) -> Self {
        self.fuel_budget = budget;
        self
    }

    /// Override the linear-memory cap (default 256 MiB, like the
    /// server).
    pub fn memory_bytes(mut self, bytes: usize) -> Self {
        self.memory_budget = bytes;
        self
    }

    pub fn build(self) -> TestHost {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.max_wasm_stack(1024 * 1024);
        let engine = Engine::new(&config).expect("wasmtime engine");
        let storage = self
            .storage_seed
            .into_iter()
            .map(|(k, v)| (data_key(&self.name, k.trim_start_matches('/')), v))
            .collect();
        TestHost {
            engine,
            name: self.name,
            log_emit: self.log_emit,
            audit_emit: self.audit_emit,
            storage_prefix: self.storage_prefix,
            allowed_keys: self.allowed_keys,
            fuel_budget: self.fuel_budget,
            memory_budget: self.memory_budget,
            state: Arc::new(Mutex::new(HostState {
                storage,
                config: self.config,
                logs: Vec::new(),
                audit: Vec::new(),
                clock: self.clock,
                rng: SplitMix64(self.rng_seed),
            })),
        }
    }
}

/// In-memory mock host. Build one per test with [`TestHost::builder`],
/// then [`invoke`](TestHost::invoke) the plugin as many times as the
/// scenario needs — storage, logs, and audit events accumulate across
/// invocations.
pub struct TestHost {
    engine: Engine,
    name: String,
    log_emit: bool,
    audit_emit: bool,
    storage_prefix: Option<String>,
    allowed_keys: BTreeSet<String>,
    fuel_budget: u64,
    memory_budget: usize,
    state: Arc<Mutex<HostState>>,
}

impl TestHost {
    pub fn builder(plugin_name: impl Into<String>) -> TestHostBuilder {
        TestHostBuilder {
            name: plugin_name.into(),
            log_emit: true,
            audit_emit: false,
            storage_prefix: None,
            allowed_keys: BTreeSet::new(),
            config: BTreeMap::new(),
            storage_seed: BTreeMap::new(),
            clock: TestClock::System,
            rng_seed: 0x0000_BA57_1011,
            fuel_budget: DEFAULT_FUEL,
            memory_budget: DEFAULT_MEMORY_BYTES,
        }
    }

    /// Invoke `bv_run` with the standard host→plugin envelope
    /// (`{"op": ..., "path": ..., "data": ...}`) — the same shape
    /// `PluginLogicalBackend::build_envelope` produces. `data` must be
    /// a JSON object (or `Value::Null` for none).
    pub fn invoke(
        &self,
        wasm: &[u8],
        op: &str,
        path: &str,
        data: serde_json::Value,
    ) -> Result<TestInvocation, TestkitError> {
        self.invoke_raw(wasm, &envelope(op, path, data))
    }

    /// Invoke `bv_run` with raw input bytes.
    pub fn invoke_raw(&self, wasm: &[u8], input: &[u8]) -> Result<TestInvocation, TestkitError> {
        let module =
            Module::new(&self.engine, wasm).map_err(|e| TestkitError::Compile(e.to_string()))?;

        let (logs_before, audit_before) = {
            let st = self.state.lock().unwrap();
            (st.logs.len(), st.audit.len())
        };

        let ctx = Ctx {
            plugin_name: self.name.clone(),
            log_emit: self.log_emit,
            audit_emit: self.audit_emit,
            storage_prefix: self.storage_prefix.clone(),
            allowed_keys: self.allowed_keys.clone(),
            response_window: None,
            limits: StoreLimitsBuilder::new().memory_size(self.memory_budget).build(),
            shared: self.state.clone(),
        };

        let mut store: Store<Ctx> = Store::new(&self.engine, ctx);
        store.limiter(|c| &mut c.limits);
        store
            .set_fuel(self.fuel_budget)
            .map_err(|e| TestkitError::Invoke(e.to_string()))?;

        let mut linker: Linker<Ctx> = Linker::new(&self.engine);
        register_test_imports(&mut linker)?;

        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| TestkitError::Instantiate(e.to_string()))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(TestkitError::MissingExport("memory"))?;
        let alloc: TypedFunc<i32, i32> = instance
            .get_typed_func(&mut store, "bv_alloc")
            .map_err(|_| TestkitError::MissingExport("bv_alloc"))?;
        let run: TypedFunc<(i32, i32), i32> = instance
            .get_typed_func(&mut store, "bv_run")
            .map_err(|_| TestkitError::MissingExport("bv_run"))?;

        let input_len: i32 = input
            .len()
            .try_into()
            .map_err(|_| TestkitError::PayloadTooLarge("input exceeds i32".into()))?;
        let input_ptr = alloc
            .call(&mut store, input_len)
            .map_err(map_call_err)?;
        if input_ptr < 0 {
            return Err(TestkitError::Invoke("bv_alloc returned negative pointer".into()));
        }
        memory
            .write(&mut store, input_ptr as usize, input)
            .map_err(|e| TestkitError::Memory(e.to_string()))?;

        let status = run.call(&mut store, (input_ptr, input_len)).map_err(map_call_err)?;

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

        let st = self.state.lock().unwrap();
        Ok(TestInvocation {
            outcome,
            response,
            fuel_consumed,
            logs: st.logs[logs_before..].to_vec(),
            audit_events: st.audit[audit_before..].to_vec(),
        })
    }

    /// Snapshot of the plugin's storage, keyed by plugin-relative key
    /// (the `core/plugins/<name>/data/` prefix stripped).
    pub fn storage_dump(&self) -> BTreeMap<String, Vec<u8>> {
        let root = data_key(&self.name, "");
        self.state
            .lock()
            .unwrap()
            .storage
            .iter()
            .filter_map(|(k, v)| k.strip_prefix(&root).map(|rel| (rel.to_string(), v.clone())))
            .collect()
    }

    /// All `bv.log` lines captured since the host was built.
    pub fn logs(&self) -> Vec<LogLine> {
        self.state.lock().unwrap().logs.clone()
    }

    /// All accepted audit events since the host was built.
    pub fn audit_events(&self) -> Vec<serde_json::Value> {
        self.state.lock().unwrap().audit.clone()
    }

    /// Re-pin the mock clock between invocations (e.g. to step a TOTP
    /// window forward).
    pub fn set_now_ms(&self, ms: i64) {
        self.state.lock().unwrap().clock = TestClock::Fixed(ms);
    }
}

/// Build the standard host→plugin envelope. Mirrors
/// `PluginLogicalBackend::build_envelope`.
pub fn envelope(op: &str, path: &str, data: serde_json::Value) -> Vec<u8> {
    let data = match data {
        serde_json::Value::Null => serde_json::Value::Object(Default::default()),
        other => other,
    };
    serde_json::to_vec(&serde_json::json!({ "op": op, "path": path, "data": data }))
        .expect("envelope serialise")
}

pub(crate) fn map_call_err(e: wasmtime::Error) -> TestkitError {
    if e.downcast_ref::<Trap>() == Some(&Trap::OutOfFuel) {
        TestkitError::FuelExhausted
    } else {
        TestkitError::Invoke(e.to_string())
    }
}

fn register_test_imports(linker: &mut Linker<Ctx>) -> Result<(), TestkitError> {
    let eng = |e: wasmtime::Error| TestkitError::Instantiate(e.to_string());

    // bv.log — capability-gated by log_emit; captured, not printed.
    linker
        .func_wrap("bv", "log", |mut caller: Caller<'_, Ctx>, level: i32, ptr: i32, len: i32| {
            if !caller.data().log_emit {
                return;
            }
            let line = match read_bytes(&mut caller, ptr, len) {
                Some(b) => String::from_utf8_lossy(&b).into_owned(),
                None => return,
            };
            caller.data().shared.lock().unwrap().logs.push(LogLine { level, line });
        })
        .map_err(eng)?;

    // bv.set_response — negative ptr/len ignored, like the server.
    linker
        .func_wrap("bv", "set_response", |mut caller: Caller<'_, Ctx>, ptr: i32, len: i32| {
            if ptr < 0 || len < 0 {
                return;
            }
            caller.data_mut().response_window = Some((ptr as u32, len as u32));
        })
        .map_err(eng)?;

    // bv.config_get — length on success, -1 not found, -3 buffer too
    // small, -4 internal.
    linker
        .func_wrap(
            "bv",
            "config_get",
            |mut caller: Caller<'_, Ctx>, key_ptr: i32, key_len: i32, out_ptr: i32, out_max: i32| -> i32 {
                let key = match read_string(&mut caller, key_ptr, key_len) {
                    Some(s) => s,
                    None => return STORAGE_INTERNAL_ERROR,
                };
                let value = caller.data().shared.lock().unwrap().config.get(&key).cloned();
                let bytes = match value {
                    Some(v) => v.into_bytes(),
                    None => return STORAGE_NOT_FOUND,
                };
                write_to_buffer(&mut caller, &bytes, out_ptr, out_max)
            },
        )
        .map_err(eng)?;

    // bv.now_unix_ms — fixed or system clock.
    linker
        .func_wrap("bv", "now_unix_ms", |caller: Caller<'_, Ctx>| -> i64 {
            let clock = caller.data().shared.lock().unwrap().clock;
            match clock {
                TestClock::Fixed(ms) => ms,
                TestClock::System => {
                    use std::time::{SystemTime, UNIX_EPOCH};
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_millis() as i64)
                        .unwrap_or(0)
                }
            }
        })
        .map_err(eng)?;

    // bv.storage_get
    linker
        .func_wrap(
            "bv",
            "storage_get",
            |mut caller: Caller<'_, Ctx>, key_ptr: i32, key_len: i32, out_ptr: i32, out_max: i32| -> i32 {
                let key = match read_string(&mut caller, key_ptr, key_len) {
                    Some(s) => s,
                    None => return STORAGE_INTERNAL_ERROR,
                };
                let full = match caller.data().rebase_key(&key) {
                    Some(f) => f,
                    None => return STORAGE_FORBIDDEN,
                };
                let value = caller.data().shared.lock().unwrap().storage.get(&full).cloned();
                match value {
                    Some(v) => write_to_buffer(&mut caller, &v, out_ptr, out_max),
                    None => STORAGE_NOT_FOUND,
                }
            },
        )
        .map_err(eng)?;

    // bv.storage_put
    linker
        .func_wrap(
            "bv",
            "storage_put",
            |mut caller: Caller<'_, Ctx>, key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32| -> i32 {
                let key = match read_string(&mut caller, key_ptr, key_len) {
                    Some(s) => s,
                    None => return STORAGE_INTERNAL_ERROR,
                };
                let value = match read_bytes(&mut caller, val_ptr, val_len) {
                    Some(b) => b,
                    None => return STORAGE_INTERNAL_ERROR,
                };
                let full = match caller.data().rebase_key(&key) {
                    Some(f) => f,
                    None => return STORAGE_FORBIDDEN,
                };
                caller.data().shared.lock().unwrap().storage.insert(full, value);
                0
            },
        )
        .map_err(eng)?;

    // bv.storage_delete — idempotent.
    linker
        .func_wrap(
            "bv",
            "storage_delete",
            |mut caller: Caller<'_, Ctx>, key_ptr: i32, key_len: i32| -> i32 {
                let key = match read_string(&mut caller, key_ptr, key_len) {
                    Some(s) => s,
                    None => return STORAGE_INTERNAL_ERROR,
                };
                let full = match caller.data().rebase_key(&key) {
                    Some(f) => f,
                    None => return STORAGE_FORBIDDEN,
                };
                caller.data().shared.lock().unwrap().storage.remove(&full);
                0
            },
        )
        .map_err(eng)?;

    // bv.storage_list — newline-separated immediate children; nested
    // subtrees appear once with a trailing `/`. Same prefix rules as
    // the server's storage_list_impl (empty prefix lists the data
    // root; `..` and out-of-prefix requests are refused).
    linker
        .func_wrap(
            "bv",
            "storage_list",
            |mut caller: Caller<'_, Ctx>, prefix_ptr: i32, prefix_len: i32, out_ptr: i32, out_max: i32| -> i32 {
                let prefix = match read_string(&mut caller, prefix_ptr, prefix_len) {
                    Some(s) => s,
                    None => return STORAGE_INTERNAL_ERROR,
                };
                let mut full_prefix = data_key(&caller.data().plugin_name, "");
                if !prefix.is_empty() {
                    if prefix.contains("..") {
                        return STORAGE_FORBIDDEN;
                    }
                    let prefix_norm = caller
                        .data()
                        .storage_prefix
                        .as_deref()
                        .unwrap_or("")
                        .trim_end_matches('/')
                        .to_string();
                    let req_norm = prefix.trim_start_matches('/').trim_end_matches('/').to_string();
                    if !prefix_norm.is_empty()
                        && req_norm != prefix_norm
                        && !req_norm.starts_with(&format!("{prefix_norm}/"))
                    {
                        return STORAGE_FORBIDDEN;
                    }
                    full_prefix.push_str(&req_norm);
                    full_prefix.push('/');
                }
                let names: BTreeSet<String> = caller
                    .data()
                    .shared
                    .lock()
                    .unwrap()
                    .storage
                    .keys()
                    .filter_map(|k| k.strip_prefix(&full_prefix))
                    .map(|rest| match rest.find('/') {
                        Some(i) => rest[..=i].to_string(),
                        None => rest.to_string(),
                    })
                    .collect();
                let joined = names.into_iter().collect::<Vec<_>>().join("\n");
                write_to_buffer(&mut caller, joined.as_bytes(), out_ptr, out_max)
            },
        )
        .map_err(eng)?;

    // bv.audit_emit — capability-gated; captured in the same envelope
    // the server would write to the audit broker.
    linker
        .func_wrap("bv", "audit_emit", |mut caller: Caller<'_, Ctx>, ptr: i32, len: i32| -> i32 {
            if !caller.data().audit_emit {
                return AUDIT_FORBIDDEN;
            }
            let payload = match read_bytes(&mut caller, ptr, len) {
                Some(b) => b,
                None => return STORAGE_INTERNAL_ERROR,
            };
            let payload_str = String::from_utf8_lossy(&payload).into_owned();
            let parsed = serde_json::from_str::<serde_json::Value>(&payload_str)
                .unwrap_or(serde_json::Value::String(payload_str));
            let name = caller.data().plugin_name.clone();
            caller.data().shared.lock().unwrap().audit.push(serde_json::json!({
                "path": format!("sys/plugins/{name}/event"),
                "data": { "plugin_event": parsed },
            }));
            0
        })
        .map_err(eng)?;

    // bv.crypto_random — deterministic seeded stream.
    linker
        .func_wrap(
            "bv",
            "crypto_random",
            |mut caller: Caller<'_, Ctx>, n_bytes: i32, out_ptr: i32, out_max: i32| -> i32 {
                if !(0..=4096).contains(&n_bytes) {
                    return STORAGE_INTERNAL_ERROR;
                }
                if n_bytes > out_max {
                    return STORAGE_BUFFER_TOO_SMALL;
                }
                let mut buf = vec![0u8; n_bytes as usize];
                caller.data().shared.lock().unwrap().rng.fill(&mut buf);
                write_to_buffer(&mut caller, &buf, out_ptr, out_max)
            },
        )
        .map_err(eng)?;

    // bv.crypto_{encrypt,decrypt,sign,verify,hmac} — allowlist gate
    // identical to the server; deterministic mock transforms after it.
    for op in ["encrypt", "decrypt", "sign", "verify", "hmac"] {
        linker
            .func_wrap(
                "bv",
                &format!("crypto_{op}"),
                move |mut caller: Caller<'_, Ctx>,
                      key_ptr: i32,
                      key_len: i32,
                      in_ptr: i32,
                      in_len: i32,
                      out_ptr: i32,
                      out_max: i32|
                      -> i32 {
                    crypto_mock(&mut caller, op, key_ptr, key_len, in_ptr, in_len, out_ptr, out_max)
                },
            )
            .map_err(eng)?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn crypto_mock(
    caller: &mut Caller<'_, Ctx>,
    op: &str,
    key_ptr: i32,
    key_len: i32,
    in_ptr: i32,
    in_len: i32,
    out_ptr: i32,
    out_max: i32,
) -> i32 {
    let key = match read_string(caller, key_ptr, key_len) {
        Some(s) => s,
        None => return STORAGE_INTERNAL_ERROR,
    };
    let input = match read_bytes(caller, in_ptr, in_len) {
        Some(b) => b,
        None => return STORAGE_INTERNAL_ERROR,
    };
    if !caller.data().allowed_keys.contains(&key) {
        return CRYPTO_FORBIDDEN;
    }
    // Same path-shape check as the server: `<mount>/keys/<name>`.
    match key.split_once("/keys/") {
        Some((m, n)) if !m.is_empty() && !n.is_empty() => {}
        _ => return CRYPTO_BACKEND_ERROR,
    }

    let out: Vec<u8> = match op {
        "encrypt" => format!("bvault:test:{}", B64.encode(&input)).into_bytes(),
        "decrypt" => {
            let ct = String::from_utf8_lossy(&input).into_owned();
            match ct.strip_prefix("bvault:test:").and_then(|b64| B64.decode(b64).ok()) {
                Some(pt) => pt,
                None => return CRYPTO_BACKEND_ERROR,
            }
        }
        "sign" => mock_signature(&input).into_bytes(),
        "hmac" => {
            let mut h = Sha256::new();
            h.update(key.as_bytes());
            h.update([0u8]);
            h.update(&input);
            format!("bvault:test:hmac:{}", B64.encode(h.finalize())).into_bytes()
        }
        "verify" => {
            // Input layout mirrors the server: u16-be(sig_len) || sig || message.
            if input.len() < 2 {
                return CRYPTO_BACKEND_ERROR;
            }
            let sig_len = u16::from_be_bytes([input[0], input[1]]) as usize;
            if input.len() < 2 + sig_len {
                return CRYPTO_BACKEND_ERROR;
            }
            let sig = &input[2..2 + sig_len];
            let message = &input[2 + sig_len..];
            let valid = sig == mock_signature(message).as_bytes();
            vec![if valid { 1 } else { 0 }]
        }
        _ => return CRYPTO_BACKEND_ERROR,
    };
    write_to_buffer(caller, &out, out_ptr, out_max)
}

fn mock_signature(message: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(message);
    format!("bvault:test:sig:{}", B64.encode(h.finalize()))
}

fn read_string(caller: &mut Caller<'_, Ctx>, ptr: i32, len: i32) -> Option<String> {
    let bytes = read_bytes(caller, ptr, len)?;
    String::from_utf8(bytes).ok()
}

fn read_bytes(caller: &mut Caller<'_, Ctx>, ptr: i32, len: i32) -> Option<Vec<u8>> {
    if ptr < 0 || len < 0 {
        return None;
    }
    let memory = caller.get_export("memory").and_then(|e| e.into_memory())?;
    let mut buf = vec![0u8; len as usize];
    memory.read(caller.as_context_mut(), ptr as usize, &mut buf).ok()?;
    Some(buf)
}

fn write_to_buffer(caller: &mut Caller<'_, Ctx>, src: &[u8], out_ptr: i32, out_max: i32) -> i32 {
    if out_ptr < 0 || out_max < 0 {
        return STORAGE_INTERNAL_ERROR;
    }
    if (src.len() as i64) > (out_max as i64) {
        return STORAGE_BUFFER_TOO_SMALL;
    }
    let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
        Some(m) => m,
        None => return STORAGE_INTERNAL_ERROR,
    };
    if memory.write(caller.as_context_mut(), out_ptr as usize, src).is_err() {
        return STORAGE_INTERNAL_ERROR;
    }
    src.len() as i32
}

fn read_memory_slice(
    memory: &Memory,
    store: &mut Store<Ctx>,
    ptr: u32,
    len: u32,
) -> Result<Vec<u8>, TestkitError> {
    let start = ptr as usize;
    let end = start
        .checked_add(len as usize)
        .ok_or(TestkitError::ResponseOutOfBounds)?;
    let mem_data = memory.data(&*store);
    if end > mem_data.len() {
        return Err(TestkitError::ResponseOutOfBounds);
    }
    Ok(mem_data[start..end].to_vec())
}

// ─── Conformance ────────────────────────────────────────────────────

/// The `bv.*` host-import surface this crate mirrors, as
/// `(name, wat_params, wat_results)` triples. Must stay in lockstep
/// with `register_host_imports` in `src/plugins/runtime.rs` — the host
/// repo's parity test instantiates [`conformance_wat`] against the
/// real runtime to enforce it.
pub const HOST_IMPORTS: &[(&str, &str, &str)] = &[
    ("log", "(param i32 i32 i32)", ""),
    ("set_response", "(param i32 i32)", ""),
    ("config_get", "(param i32 i32 i32 i32)", "(result i32)"),
    ("now_unix_ms", "", "(result i64)"),
    ("storage_get", "(param i32 i32 i32 i32)", "(result i32)"),
    ("storage_put", "(param i32 i32 i32 i32)", "(result i32)"),
    ("storage_delete", "(param i32 i32)", "(result i32)"),
    ("storage_list", "(param i32 i32 i32 i32)", "(result i32)"),
    ("audit_emit", "(param i32 i32)", "(result i32)"),
    ("crypto_random", "(param i32 i32 i32)", "(result i32)"),
    ("crypto_encrypt", "(param i32 i32 i32 i32 i32 i32)", "(result i32)"),
    ("crypto_decrypt", "(param i32 i32 i32 i32 i32 i32)", "(result i32)"),
    ("crypto_sign", "(param i32 i32 i32 i32 i32 i32)", "(result i32)"),
    ("crypto_verify", "(param i32 i32 i32 i32 i32 i32)", "(result i32)"),
    ("crypto_hmac", "(param i32 i32 i32 i32 i32 i32)", "(result i32)"),
];

/// A WebAssembly-text module that imports **every** entry in
/// [`HOST_IMPORTS`] and echoes its input via `bv.set_response`. If it
/// instantiates, the runtime under test registers the full surface
/// this crate mirrors.
pub fn conformance_wat() -> String {
    let imports: String = HOST_IMPORTS
        .iter()
        .map(|(name, params, results)| {
            format!("  (import \"bv\" \"{name}\" (func ${name} {params} {results}))\n")
        })
        .collect();
    format!(
        r#"(module
{imports}  (memory (export "memory") 1)
  (global $next (mut i32) (i32.const 1024))
  (func (export "bv_alloc") (param $len i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $next))
    (global.set $next (i32.add (global.get $next) (local.get $len)))
    (local.get $ptr))
  (func (export "bv_run") (param $ptr i32) (param $len i32) (result i32)
    (call $set_response (local.get $ptr) (local.get $len))
    (i32.const 0))
)"#
    )
}

#[cfg(test)]
mod tests;
