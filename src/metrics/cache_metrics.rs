//! Prometheus counters and gauges for the cache subsystem.
//!
//! Three counters plus one gauge, labelled by `layer` (`token`, `policy`,
//! `secret`). Metric shape follows the spec in `features/caching.md`:
//!
//!   bvault_cache_hits_total{layer}
//!   bvault_cache_misses_total{layer}
//!   bvault_cache_evictions_total{layer}
//!   bvault_cache_size{layer}
//!
//! ## Access pattern
//!
//! `CacheMetrics` values are cheap to clone (each field is a
//! `prometheus_client::metrics::family::Family`, which is `Arc` inside). A
//! single process-wide instance is lazily created in the `OnceLock` below
//! the first time any caller records a value. `MetricsManager::new`
//! registers the same instance's families with its `Registry` so Prometheus
//! scrapes see the counts.
//!
//! Callers that only record values (the cache code paths in
//! `src/cache/*` and `src/modules/policy/policy_store.rs`) reach the
//! instance via [`cache_metrics()`]. Callers in code paths that do not
//! have a `MetricsManager` in scope (unit tests, the CLI, embedded vault
//! mode) still get a working instance — their counts just aren't exported
//! because no `Registry` is scraping them.

use std::{
    fmt::Write,
    sync::{atomic::AtomicI64, OnceLock},
};

use prometheus_client::{
    encoding::{EncodeLabelSet, EncodeLabelValue, LabelValueEncoder},
    metrics::{counter::Counter, family::Family, gauge::Gauge},
    registry::Registry,
};

pub const CACHE_HITS_TOTAL: &str = "bvault_cache_hits_total";
pub const CACHE_HITS_TOTAL_HELP: &str = "Total cache hits, labelled by cache layer";

pub const CACHE_MISSES_TOTAL: &str = "bvault_cache_misses_total";
pub const CACHE_MISSES_TOTAL_HELP: &str = "Total cache misses, labelled by cache layer";

pub const CACHE_EVICTIONS_TOTAL: &str = "bvault_cache_evictions_total";
pub const CACHE_EVICTIONS_TOTAL_HELP: &str = "Total cache evictions, labelled by cache layer";

pub const CACHE_SIZE: &str = "bvault_cache_size";
pub const CACHE_SIZE_HELP: &str = "Current number of entries in the cache, labelled by cache layer";

/// Cache layers. Order is stable and values are the strings Prometheus
/// clients will see in the `layer` label.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub enum CacheLayer {
    Token,
    Policy,
    Secret,
}

impl EncodeLabelValue for CacheLayer {
    fn encode(&self, writer: &mut LabelValueEncoder<'_>) -> Result<(), std::fmt::Error> {
        match self {
            CacheLayer::Token => writer.write_str("token"),
            CacheLayer::Policy => writer.write_str("policy"),
            CacheLayer::Secret => writer.write_str("secret"),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct CacheLabel {
    pub layer: CacheLayer,
}

/// Clone-cheap collection of cache-subsystem Prometheus metrics. See the
/// module docstring for how callers get at the shared instance.
#[derive(Clone)]
pub struct CacheMetrics {
    hits: Family<CacheLabel, Counter>,
    misses: Family<CacheLabel, Counter>,
    evictions: Family<CacheLabel, Counter>,
    size: Family<CacheLabel, Gauge<i64, AtomicI64>>,
}

impl Default for CacheMetrics {
    fn default() -> Self {
        Self {
            hits: Family::default(),
            misses: Family::default(),
            evictions: Family::default(),
            size: Family::default(),
        }
    }
}

static GLOBAL: OnceLock<CacheMetrics> = OnceLock::new();

/// Return the shared process-wide `CacheMetrics` instance, lazily
/// initializing it on first access. Safe to call from any thread.
pub fn cache_metrics() -> &'static CacheMetrics {
    GLOBAL.get_or_init(CacheMetrics::default)
}

impl CacheMetrics {
    /// Register this instance's families with `registry`. Idempotent across
    /// multiple registries (each registry gets its own clone of the
    /// `Family`, which shares the underlying counter storage via `Arc`).
    /// Called from `MetricsManager::new`.
    pub fn register(&self, registry: &mut Registry) {
        registry.register(CACHE_HITS_TOTAL, CACHE_HITS_TOTAL_HELP, self.hits.clone());
        registry.register(CACHE_MISSES_TOTAL, CACHE_MISSES_TOTAL_HELP, self.misses.clone());
        registry.register(CACHE_EVICTIONS_TOTAL, CACHE_EVICTIONS_TOTAL_HELP, self.evictions.clone());
        registry.register(CACHE_SIZE, CACHE_SIZE_HELP, self.size.clone());
    }

    pub fn record_hit(&self, layer: CacheLayer) {
        self.hits.get_or_create(&CacheLabel { layer }).inc();
    }

    pub fn record_miss(&self, layer: CacheLayer) {
        self.misses.get_or_create(&CacheLabel { layer }).inc();
    }

    pub fn record_eviction(&self, layer: CacheLayer) {
        self.evictions.get_or_create(&CacheLabel { layer }).inc();
    }

    /// Set the current cache size. Callers pass an absolute value rather
    /// than a delta so the gauge is self-correcting against miscounted
    /// insert/evict pairs.
    pub fn set_size(&self, layer: CacheLayer, size: i64) {
        self.size.get_or_create(&CacheLabel { layer }).set(size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hits_and_misses_record_independently() {
        let m = CacheMetrics::default();
        m.record_hit(CacheLayer::Token);
        m.record_hit(CacheLayer::Token);
        m.record_miss(CacheLayer::Token);
        m.record_hit(CacheLayer::Policy);

        assert_eq!(m.hits.get_or_create(&CacheLabel { layer: CacheLayer::Token }).get(), 2);
        assert_eq!(m.misses.get_or_create(&CacheLabel { layer: CacheLayer::Token }).get(), 1);
        assert_eq!(m.hits.get_or_create(&CacheLabel { layer: CacheLayer::Policy }).get(), 1);
        assert_eq!(m.hits.get_or_create(&CacheLabel { layer: CacheLayer::Secret }).get(), 0);
    }

    #[test]
    fn size_is_absolute() {
        let m = CacheMetrics::default();
        m.set_size(CacheLayer::Token, 42);
        m.set_size(CacheLayer::Token, 7);
        assert_eq!(m.size.get_or_create(&CacheLabel { layer: CacheLayer::Token }).get(), 7);
    }

    #[test]
    fn global_returns_same_instance() {
        let a = cache_metrics();
        let b = cache_metrics();
        assert!(std::ptr::eq(a, b));
    }

    #[test]
    fn register_with_registry_exports_names() {
        let mut registry = Registry::default();
        let m = CacheMetrics::default();
        m.register(&mut registry);
        // prometheus-client only emits a family in the text encoding once
        // it has at least one recorded data point — record once in each
        // so all four appear in the scrape.
        m.record_hit(CacheLayer::Token);
        m.record_miss(CacheLayer::Token);
        m.record_eviction(CacheLayer::Token);
        m.set_size(CacheLayer::Token, 3);

        let mut buf = String::new();
        prometheus_client::encoding::text::encode(&mut buf, &registry).unwrap();
        assert!(buf.contains(CACHE_HITS_TOTAL), "missing hits counter in: {buf}");
        assert!(buf.contains(CACHE_MISSES_TOTAL), "missing misses counter in: {buf}");
        assert!(buf.contains(CACHE_EVICTIONS_TOTAL), "missing evictions counter in: {buf}");
        assert!(buf.contains(CACHE_SIZE), "missing size gauge in: {buf}");
        assert!(buf.contains("layer=\"token\""));
    }
}
