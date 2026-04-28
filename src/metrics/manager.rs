//! `MetricManager` holds the Prometheus registry and metrics.
use std::sync::{Arc, Mutex};

use prometheus_client::registry::Registry;

use crate::metrics::{cache_metrics::cache_metrics, http_metrics::HttpMetrics, system_metrics::SystemMetrics};

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
        // `metrics::cache_metrics`); we just register its Families with
        // this registry so scrapes see them. Safe to call repeatedly in
        // tests that build multiple MetricsManagers — each registry gets
        // its own clone of the Family, all sharing the same counter
        // storage via Arc.
        cache_metrics().register(&mut registry.lock().unwrap());
        // Phase 5.10: per-plugin counters. Same singleton pattern.
        crate::plugins::metrics::register(&mut registry.lock().unwrap());
        MetricsManager { registry, system_metrics, http_metrics }
    }
}
