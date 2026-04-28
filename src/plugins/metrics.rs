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

use dashmap::DashMap;
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
    // Phase 5.12: parallel read-side snapshot for the GUI panel.
    // `prometheus_client::metrics::family::Family` doesn't expose an
    // iterator on the stable API, so we shadow the per-plugin counts
    // here. Both writes are O(1) and protected by `DashMap`'s
    // per-shard locks; no extra allocation on the hot path beyond
    // the entry's `Default::default` on first sight of the plugin.
    let snap_arc = snapshots()
        .entry(plugin.to_string())
        .or_insert_with(|| std::sync::Arc::new(std::sync::Mutex::new(SnapshotInner::default())))
        .clone();
    let mut snap = snap_arc.lock().expect("plugin metrics mutex poisoned");
    match outcome {
        "success" => snap.invokes_success += 1,
        "plugin_error" => snap.invokes_plugin_error += 1,
        "runtime_error" => snap.invokes_runtime_error += 1,
        _ => {}
    }
    snap.fuel_consumed_total += fuel;
    snap.invoke_duration_count += 1;
    snap.invoke_duration_sum_secs += duration_secs;
}

/// Phase 5.12 — snapshot of the per-plugin counters, keyed by plugin
/// name. Returned as a plain serde struct so the Tauri command and
/// the GUI panel can consume it without touching `prometheus_client`
/// types directly.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct PluginMetricsSnapshot {
    pub plugin: String,
    pub invokes_success: u64,
    pub invokes_plugin_error: u64,
    pub invokes_runtime_error: u64,
    pub fuel_consumed_total: u64,
    pub invoke_duration_count: u64,
    pub invoke_duration_sum_secs: f64,
}

impl PluginMetricsSnapshot {
    /// Convenience: average wall-clock invoke time. `None` when the
    /// histogram is empty (so the GUI can render `—` rather than `NaN`).
    pub fn avg_duration_secs(&self) -> Option<f64> {
        if self.invoke_duration_count == 0 {
            None
        } else {
            Some(self.invoke_duration_sum_secs / (self.invoke_duration_count as f64))
        }
    }
}

/// Internal mirror of `PluginMetricsSnapshot`'s fields, used by the
/// per-plugin counter shadow the writer maintains alongside the
/// Prometheus Families.
#[derive(Debug, Default)]
struct SnapshotInner {
    invokes_success: u64,
    invokes_plugin_error: u64,
    invokes_runtime_error: u64,
    fuel_consumed_total: u64,
    invoke_duration_count: u64,
    invoke_duration_sum_secs: f64,
}

type SnapshotMap = DashMap<String, std::sync::Arc<std::sync::Mutex<SnapshotInner>>>;
static SNAPSHOTS: OnceLock<SnapshotMap> = OnceLock::new();

fn snapshots() -> &'static SnapshotMap {
    SNAPSHOTS.get_or_init(DashMap::new)
}

/// Read the per-plugin snapshot. Returns a record with all-zero
/// fields for a plugin that's been registered but never invoked, so
/// the GUI can render every catalog entry without a special "no
/// data" path.
pub fn snapshot_for(plugin: &str) -> PluginMetricsSnapshot {
    let map = snapshots();
    if let Some(arc) = map.get(plugin) {
        let inner = arc.value().lock().expect("plugin metrics mutex poisoned");
        PluginMetricsSnapshot {
            plugin: plugin.to_string(),
            invokes_success: inner.invokes_success,
            invokes_plugin_error: inner.invokes_plugin_error,
            invokes_runtime_error: inner.invokes_runtime_error,
            fuel_consumed_total: inner.fuel_consumed_total,
            invoke_duration_count: inner.invoke_duration_count,
            invoke_duration_sum_secs: inner.invoke_duration_sum_secs,
        }
    } else {
        PluginMetricsSnapshot { plugin: plugin.to_string(), ..Default::default() }
    }
}

/// Snapshot every plugin that has *any* metric recorded. Used by the
/// GUI's per-plugin metrics panel as a one-shot read on page load.
pub fn snapshot_all() -> Vec<PluginMetricsSnapshot> {
    let map = snapshots();
    let names: std::collections::BTreeSet<String> =
        map.iter().map(|e| e.key().clone()).collect();
    names.into_iter().map(|n| snapshot_for(&n)).collect()
}
