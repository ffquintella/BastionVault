//! BastionVault's Prometheus instrumentation: the metric families, the
//! process-wide singletons that record into them, and the [`MetricsManager`]
//! that owns the registry a scrape reads.
//!
//! Tier 0 of the workspace decomposition
//! (`roadmaps/workspace-decomposition.md` § Phase 1). Re-exported by the
//! root crate as `bastion_vault::metrics`, so no call site outside this
//! directory changed when it moved.
//!
//! [`manager::MetricsManager`] registers the families defined here. Families
//! defined *above* this crate — today the per-plugin counters in
//! `bastion_vault::plugins::metrics` — register themselves through
//! [`manager::MetricsManager::register_collector`]; the substrate does not
//! name the layers above it.
//!
//! The actix-web middleware that feeds [`http_metrics`] is **not** here. It
//! stays in the root crate as `bastion_vault::metrics::middleware`, because
//! `bv-storage` depends on this crate for the cache counters and actix must
//! not end up underneath every leaf engine.
//!
//! # How to add a new metric
//!
//! 1. **Define and implement it.** Add a module here and register its
//!    families with a `Registry`:
//!
//! ```text
//! pub const HTTP_REQUEST_COUNT: &str = "http_request_count";
//! pub const HTTP_REQUEST_COUNT_HELP: &str = "Number of HTTP requests received, labeled by method and status";
//!
//! pub struct HttpMetrics {
//!     requests: Family<HttpLabel, Counter>,
//! }
//!
//! impl HttpMetrics {
//!     pub fn new(registry: &mut Registry) -> Self {
//!         let requests = Family::<HttpLabel, Counter>::default();
//!         registry.register(HTTP_REQUEST_COUNT, HTTP_REQUEST_COUNT_HELP, requests.clone());
//!         Self { requests }
//!     }
//!
//!     pub fn increment_request_count(&self, label: &HttpLabel) {
//!         self.requests.get_or_create(label).inc();
//!     }
//! }
//! ```
//!
//! 2. **Add it to [`manager::MetricsManager`]** if it belongs to this crate,
//!    or call `register_collector` from the assembly layer if it does not.
//!
//! 3. **Update it where the event happens.** In actix handlers the manager
//!    arrives through `app_data`:
//!
//! ```text
//! if let Some(m) = res.request().app_data::<Data<Arc<RwLock<MetricsManager>>>>() {
//!     let metrics_manager = m.read().unwrap();
//!     metrics_manager.http_metrics.increment_request_count(&label);
//! }
//! ```
//!
//! # Methodology
//!
//! Prometheus [categorises services](https://prometheus.io/docs/practices/instrumentation/#the-three-types-of-services)
//! into online services, offline processing and batch jobs. BastionVault
//! serves a RESTful API, so it is an online service: the
//! [RED method](https://grafana.com/blog/2018/08/02/the-red-method-how-to-instrument-your-services/)
//! (rate, errors, duration) covers the service in [`http_metrics`], and the
//! [USE method](https://www.brendangregg.com/usemethod.html) (utilization,
//! saturation, errors) covers the host in [`system_metrics`].

pub mod cache_metrics;
pub mod ferrogate_metrics;
pub mod http_metrics;
pub mod manager;
pub mod system_metrics;
