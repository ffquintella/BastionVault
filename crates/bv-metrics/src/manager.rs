//! `MetricManager` holds the Prometheus registry and metrics.
use std::sync::{Arc, Mutex};

use prometheus_client::registry::Registry;

use crate::{cache_metrics::cache_metrics, http_metrics::HttpMetrics, system_metrics::SystemMetrics};

#[derive(Clone)]
pub struct MetricsManager {
    pub registry: Arc<Mutex<Registry>>,
    pub system_metrics: Arc<SystemMetrics>,
    pub http_metrics: Arc<HttpMetrics>,
}

impl MetricsManager {
    pub fn new(collection_interval: u64) -> Self {
        let registry = Arc::new(Mutex::new(Registry::default()));
        let system_metrics = Arc::new(SystemMetrics::new(&mut registry.lock().unwrap(), collection_interval));
        let http_metrics = Arc::new(HttpMetrics::new(&mut registry.lock().unwrap()));
        // Cache metrics are a process-wide singleton (see
        // `crate::cache_metrics`); we just register its Families with
        // this registry so scrapes see them. Safe to call repeatedly in
        // tests that build multiple MetricsManagers — each registry gets
        // its own clone of the Family, all sharing the same counter
        // storage via Arc.
        cache_metrics().register(&mut registry.lock().unwrap());
        // FerroGate machine-auth counters (same singleton pattern).
        crate::ferrogate_metrics::ferrogate_metrics().register(&mut registry.lock().unwrap());
        MetricsManager { registry, system_metrics, http_metrics }
    }

    /// Register metric families that are defined outside this crate.
    ///
    /// The per-plugin counters (`bastion_vault::plugins::metrics`) are the
    /// only caller today. They used to be registered by name from inside
    /// [`MetricsManager::new`], which made the metrics substrate depend on
    /// the plugin runtime — the one edge that kept `bv-metrics` from being a
    /// Tier 0 leaf. The dependency now points the other way: whoever builds
    /// the manager hands it the collectors it should export.
    ///
    /// Registration order is irrelevant to Prometheus, so this may be called
    /// at any point after construction and before the first scrape.
    pub fn register_collector(&self, register: impl FnOnce(&mut Registry)) {
        register(&mut self.registry.lock().unwrap());
    }
}
