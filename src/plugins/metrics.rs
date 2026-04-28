//! Per-plugin Prometheus counters — Phase 5.10.
//!
//! Three counters keyed by plugin name + outcome label:
//!
//!   * `bvault_plugin_invokes_total{plugin, outcome="success"|"plugin_error"|"runtime_error"}`
//!   * `bvault_plugin_fuel_consumed_total{plugin}` — only for WASM
//!     (the process runtime has no equivalent of fuel).
//!   * `bvault_plugin_invoke_duration_seconds{plugin}` — histogram
//!     bucketed at the standard latency tiers used elsewhere in
//!     `crate::metrics`.
//!
//! The GUI's PluginsPage reads these via the existing Prometheus
//! scrape; per-plugin metrics on the page itself are a Phase 5.10
//! follow-up that pivots the same data into the Tauri command surface.

use std::sync::OnceLock;

use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family, histogram::Histogram},
    registry::Registry,
};

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PluginInvokeLabels {
    pub plugin: String,
    pub outcome: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PluginLabels {
    pub plugin: String,
}

pub struct PluginMetrics {
    pub invokes: Family<PluginInvokeLabels, Counter>,
    pub fuel_consumed: Family<PluginLabels, Counter>,
    pub invoke_duration: Family<PluginLabels, Histogram>,
}

static METRICS: OnceLock<PluginMetrics> = OnceLock::new();

/// Latency buckets matching the rest of the project's HTTP histograms
/// — milliseconds rendered as fractional seconds.
fn latency_buckets() -> impl Iterator<Item = f64> {
    [0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0].into_iter()
}

pub fn metrics() -> &'static PluginMetrics {
    METRICS.get_or_init(|| PluginMetrics {
        invokes: Family::default(),
        fuel_consumed: Family::default(),
        invoke_duration: Family::<PluginLabels, Histogram>::new_with_constructor(|| {
            Histogram::new(latency_buckets())
        }),
    })
}

/// Register the per-plugin counters on the supplied Prometheus
/// registry. Idempotent — the underlying `Family` is process-global,
/// so calling this twice from two different metrics-init paths is
/// safe (the second call wires the same handles into the second
/// registry, which is fine for the test harness).
pub fn register(registry: &mut Registry) {
    let m = metrics();
    registry.register(
        "bvault_plugin_invokes",
        "Plugin invocations by outcome",
        m.invokes.clone(),
    );
    registry.register(
        "bvault_plugin_fuel_consumed",
        "Total fuel consumed by WASM plugin invocations",
        m.fuel_consumed.clone(),
    );
    registry.register(
        "bvault_plugin_invoke_duration_seconds",
        "Plugin invocation wall-clock duration",
        m.invoke_duration.clone(),
    );
}

pub fn record_invoke(plugin: &str, outcome: &'static str, duration_secs: f64, fuel: u64) {
    let m = metrics();
    m.invokes
        .get_or_create(&PluginInvokeLabels {
            plugin: plugin.to_string(),
            outcome,
        })
        .inc();
    m.invoke_duration
        .get_or_create(&PluginLabels {
            plugin: plugin.to_string(),
        })
        .observe(duration_secs);
    if fuel > 0 {
        m.fuel_consumed
            .get_or_create(&PluginLabels {
                plugin: plugin.to_string(),
            })
            .inc_by(fuel);
    }
}
