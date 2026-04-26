//! Shared wasmtime Engine + compiled-Module cache.
//!
//! Phase 3 deliverable. Before the cache, every plugin invocation
//! spent O(MB) per-call recompiling the WASM module — wasmtime's
//! cranelift is fast but not free. The cache holds one compiled
//! `Module` per `(plugin_name, sha256)` pair so concurrent invocations
//! of the same plugin share a single compilation.
//!
//! The cache key intentionally includes sha256, not just the plugin
//! name. When an operator re-registers a plugin with a new binary,
//! the catalog persists the new sha256 in the manifest; the next
//! invocation looks up `(name, new_sha)` which misses the cache and
//! triggers a fresh compile. The old `(name, old_sha)` entry stays
//! in the map until [`ModuleCache::invalidate`] (called by the
//! reload endpoint) or process restart — bounded by the
//! `MAX_CACHED_MODULES` LRU cap so we don't leak.
//!
//! Hot reload semantics: the operator hits
//! `POST /v1/sys/plugins/<name>/reload` → catalog re-reads the binary
//! from storage and recomputes sha256 → cache is invalidated for that
//! plugin → the next invoke compiles fresh. This is meaningful even
//! though our runtime is single-shot per invoke: it lets operators
//! force a recompile without bouncing the BastionVault process.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use wasmtime::{Config, Engine, Module};

use super::runtime::RuntimeError;

/// Bound on the number of compiled modules we keep alive. Each entry
/// is a wasmtime `Module` which holds the compiled native code; one
/// `Module` for a typical plugin is a few MiB. 128 cached modules
/// caps memory at low hundreds of MiB even for catalogs with many
/// hot versions.
const MAX_CACHED_MODULES: usize = 128;

/// Process-global engine + cache. The wasmtime `Engine` is designed
/// to be shared across stores, so one `Engine` is enough for the
/// whole BastionVault process. We initialise it once on first use.
static SHARED: OnceLock<ModuleCache> = OnceLock::new();

#[derive(Clone)]
pub struct ModuleCache {
    engine: Engine,
    /// Insertion-order vector of `(name, sha256)` so the cap is
    /// enforced FIFO. Modules are not cheap to drop (they free large
    /// chunks of native code), but FIFO gives O(1) eviction without
    /// the bookkeeping cost of true LRU. For our access pattern
    /// (a small set of hot plugins) FIFO is indistinguishable.
    order: Arc<Mutex<Vec<(String, String)>>>,
    map: Arc<Mutex<HashMap<(String, String), Module>>>,
}

impl ModuleCache {
    /// Process-global handle. Constructs the underlying `Engine` on
    /// first call; every subsequent call returns the same handle.
    pub fn shared() -> Result<Self, RuntimeError> {
        if let Some(c) = SHARED.get() {
            return Ok(c.clone());
        }
        let c = Self::new_engine()?;
        // Race-tolerant: if two callers hit this at once, one wins,
        // the loser's engine drops cleanly.
        let _ = SHARED.set(c.clone());
        Ok(SHARED.get().cloned().unwrap_or(c))
    }

    fn new_engine() -> Result<Self, RuntimeError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.async_support(true);
        config.async_stack_size(1 * 1024 * 1024);
        config.max_wasm_stack(1 * 1024 * 1024);
        let engine = Engine::new(&config).map_err(|e| RuntimeError::Engine(e.to_string()))?;
        Ok(Self {
            engine,
            order: Arc::new(Mutex::new(Vec::new())),
            map: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Look up a compiled module. Cache hit → cloned `Module`
    /// (cheap; `Module` is internally `Arc`-shared). Cache miss →
    /// compile + insert + return. Subsequent calls for the same
    /// `(name, sha)` skip compilation.
    pub fn get_or_compile(
        &self,
        name: &str,
        sha256: &str,
        wasm_bytes: &[u8],
    ) -> Result<Module, RuntimeError> {
        let key = (name.to_string(), sha256.to_string());
        if let Some(m) = self.map.lock().unwrap().get(&key) {
            return Ok(m.clone());
        }
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| RuntimeError::Compile(e.to_string()))?;
        self.insert_capped(key, module.clone());
        Ok(module)
    }

    fn insert_capped(&self, key: (String, String), module: Module) {
        let mut map = self.map.lock().unwrap();
        let mut order = self.order.lock().unwrap();
        if map.contains_key(&key) {
            return;
        }
        if map.len() >= MAX_CACHED_MODULES {
            if let Some(victim) = order.first().cloned() {
                order.remove(0);
                map.remove(&victim);
            }
        }
        order.push(key.clone());
        map.insert(key, module);
    }

    /// Drop every cached compilation for `name`, regardless of sha256.
    /// Called by the reload endpoint after the catalog re-verifies
    /// the binary. Returns the number of entries evicted.
    pub fn invalidate(&self, name: &str) -> usize {
        let mut map = self.map.lock().unwrap();
        let mut order = self.order.lock().unwrap();
        let before = map.len();
        map.retain(|(n, _), _| n != name);
        order.retain(|(n, _)| n != name);
        before.saturating_sub(map.len())
    }

    /// Drop every cached compilation. Useful for the `flush_caches`
    /// admin path; never necessary for correctness.
    pub fn clear(&self) -> usize {
        let mut map = self.map.lock().unwrap();
        let mut order = self.order.lock().unwrap();
        let n = map.len();
        map.clear();
        order.clear();
        n
    }

    #[cfg(test)]
    pub fn entries(&self) -> usize {
        self.map.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_wat_bytes(global: i32) -> Vec<u8> {
        let wat = format!(
            r#"(module
                (memory (export "memory") 1)
                (global $g i32 (i32.const {global}))
                (func (export "bv_alloc") (param i32) (result i32) (i32.const 0))
                (func (export "bv_run") (param i32 i32) (result i32) (global.get $g)))"#,
        );
        wat::parse_str(&wat).unwrap()
    }

    #[test]
    #[serial_test::serial]
    fn hit_then_miss_on_sha_change() {
        let c = ModuleCache::shared().unwrap();
        // The cache is process-global and shared with every other
        // test that touches the wasm runtime, so don't compare absolute
        // counts. Instead use a unique plugin name per test and
        // assert the relative invariants for that name only.
        c.invalidate("test-mc-hit-miss");
        let b1 = tiny_wat_bytes(1);
        let _m1 = c.get_or_compile("test-mc-hit-miss", "sha-aaa", &b1).unwrap();
        let _m1_again = c.get_or_compile("test-mc-hit-miss", "sha-aaa", &b1).unwrap();
        // Same sha → no growth for this name.
        assert_eq!(
            entries_for(&c, "test-mc-hit-miss"),
            1,
            "duplicate insert grew the cache",
        );

        let b2 = tiny_wat_bytes(2);
        let _m2 = c.get_or_compile("test-mc-hit-miss", "sha-bbb", &b2).unwrap();
        // Fresh sha → one new entry.
        assert_eq!(
            entries_for(&c, "test-mc-hit-miss"),
            2,
            "fresh sha should miss + insert",
        );
        c.invalidate("test-mc-hit-miss");
    }

    /// Count cache entries scoped to a single plugin name so tests
    /// don't have to dance around process-global counts.
    fn entries_for(cache: &ModuleCache, name: &str) -> usize {
        cache.map.lock().unwrap().keys().filter(|(n, _)| n == name).count()
    }

    #[test]
    #[serial_test::serial]
    fn invalidate_drops_all_versions_for_a_name() {
        let c = ModuleCache::shared().unwrap();
        let _ = c.get_or_compile("test-invalidate", "sha-1", &tiny_wat_bytes(11)).unwrap();
        let _ = c.get_or_compile("test-invalidate", "sha-2", &tiny_wat_bytes(12)).unwrap();
        let evicted = c.invalidate("test-invalidate");
        assert!(evicted >= 2);
    }
}
