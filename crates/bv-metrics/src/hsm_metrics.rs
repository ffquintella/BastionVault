//! Prometheus families for the HSM pool (`features/hsm-pool-ha.md` § Metrics).
//!
//! Process-wide singleton, like [`crate::ferrogate_metrics`]: `bv-core`'s pool
//! records through [`hsm_metrics`] and [`MetricsManager`](crate::manager)
//! registers the families. Labels are the operator-chosen member name and a
//! closed `kind` set; never a key id, serial or node credential.

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use prometheus_client::{
    encoding::{EncodeLabelSet, EncodeLabelValue, LabelValueEncoder},
    metrics::{
        counter::Counter,
        family::Family,
        gauge::Gauge,
        histogram::{exponential_buckets, Histogram},
    },
    registry::Registry,
};

/// Gauge, 1 while the member's circuit breaker is closed, 0 while it is down.
pub const MEMBER_UP: &str = "bv_hsm_member_up";
pub const MEMBER_UP_HELP: &str =
    "1 when the HSM pool member is usable, 0 when its circuit breaker is open or it is faulted";

/// Counter; exported with the `_total` suffix.
pub const SESSION_ERRORS: &str = "bv_hsm_session_errors";
pub const SESSION_ERRORS_HELP: &str = "HSM pool member failures, labelled by member and kind";

pub const UNDER_REPLICATED_SETS: &str = "bv_hsm_under_replicated_sets";
pub const UNDER_REPLICATED_SETS_HELP: &str = "HSM blob sets holding fewer copies than there are active pool members";

/// Why a pool member operation failed. Stable values for the `kind` label.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub enum SessionErrorKind {
    /// The device or its link could not be reached, or the session failed.
    Transport,
    /// The device returned `SESSIONS_FULL`.
    SessionsFull,
    /// Any other device-side error.
    Device,
    /// AAD, authorization or MAC mismatch: a security event, never an outage.
    Crypto,
}

impl EncodeLabelValue for SessionErrorKind {
    fn encode(&self, writer: &mut LabelValueEncoder<'_>) -> Result<(), std::fmt::Error> {
        use std::fmt::Write;
        writer.write_str(match self {
            SessionErrorKind::Transport => "transport",
            SessionErrorKind::SessionsFull => "sessions_full",
            SessionErrorKind::Device => "device",
            SessionErrorKind::Crypto => "crypto",
        })
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct MemberLabel {
    pub member: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SessionErrorLabels {
    pub member: String,
    pub kind: SessionErrorKind,
}

/// Who reports an under-replicated count. The gauge is their sum, so the seal
/// record and the custody store never overwrite each other's figure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UnderReplicatedScope {
    SealRecord,
    Custody,
}

/// Histogram of one member operation's wall time (T454 phase 6).
pub const COMMAND_DURATION: &str = "bv_hsm_command_duration_seconds";
pub const COMMAND_DURATION_HELP: &str = "Wall time of an HSM pool member operation, by member and operation";

/// Counter; exported with the `_total` suffix.
pub const REPAIR: &str = "bv_hsm_repair";
pub const REPAIR_HELP: &str = "HSM repair outcomes: copies added, copies removed, recovery copies added, failures";

/// Counter; exported with the `_total` suffix.
pub const DEVICE_LOG_GAP: &str = "bv_hsm_device_log_gap";
pub const DEVICE_LOG_GAP_HELP: &str =
    "Device audit log gaps: an index jump, a digest-chain break or unlogged events reported by the device";

/// Counter; exported with the `_total` suffix.
pub const LINK_REQUESTS: &str = "bv_hsm_link_requests";
pub const LINK_REQUESTS_HELP: &str =
    "Requests this node's HSM link relay sent to a member's gateway, by member and outcome (ok, failed)";

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct CommandLabels {
    pub member: String,
    pub op: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ResultLabel {
    pub result: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct LinkLabels {
    pub member: String,
    pub code: String,
}

type HistogramFamily = Family<CommandLabels, Histogram, fn() -> Histogram>;

fn command_histogram() -> Histogram {
    // 5 ms .. ~10 s: a device command is ~10-160 ms (spec § budget).
    Histogram::new(exponential_buckets(0.005, 2.0, 12))
}

pub struct HsmMetrics {
    member_up: Family<MemberLabel, Gauge>,
    session_errors: Family<SessionErrorLabels, Counter>,
    under_replicated: Gauge,
    /// (seal record, custody) counts behind `under_replicated`.
    under_replicated_parts: Mutex<(i64, i64)>,
    command_duration: HistogramFamily,
    repair: Family<ResultLabel, Counter>,
    device_log_gap: Family<MemberLabel, Counter>,
    link_requests: Family<LinkLabels, Counter>,
    /// Last cumulative relay totals seen per (member, code), to turn the
    /// relay's running totals into counter increments.
    link_last: Mutex<HashMap<(String, String), u64>>,
}

impl Default for HsmMetrics {
    fn default() -> Self {
        Self {
            member_up: Family::default(),
            session_errors: Family::default(),
            under_replicated: Gauge::default(),
            under_replicated_parts: Mutex::new((0, 0)),
            command_duration: Family::new_with_constructor(command_histogram as fn() -> Histogram),
            repair: Family::default(),
            device_log_gap: Family::default(),
            link_requests: Family::default(),
            link_last: Mutex::new(HashMap::new()),
        }
    }
}

static GLOBAL: OnceLock<HsmMetrics> = OnceLock::new();

/// Shared process-wide instance, lazily initialised on first access.
pub fn hsm_metrics() -> &'static HsmMetrics {
    GLOBAL.get_or_init(HsmMetrics::default)
}

impl HsmMetrics {
    /// Register the families with `registry`. Idempotent across registries.
    pub fn register(&self, registry: &mut Registry) {
        registry.register(MEMBER_UP, MEMBER_UP_HELP, self.member_up.clone());
        registry.register(SESSION_ERRORS, SESSION_ERRORS_HELP, self.session_errors.clone());
        registry.register(UNDER_REPLICATED_SETS, UNDER_REPLICATED_SETS_HELP, self.under_replicated.clone());
        registry.register(COMMAND_DURATION, COMMAND_DURATION_HELP, self.command_duration.clone());
        registry.register(REPAIR, REPAIR_HELP, self.repair.clone());
        registry.register(DEVICE_LOG_GAP, DEVICE_LOG_GAP_HELP, self.device_log_gap.clone());
        registry.register(LINK_REQUESTS, LINK_REQUESTS_HELP, self.link_requests.clone());
    }

    /// One member operation took `seconds` (`op`: a closed set chosen by the
    /// caller, such as `wrap`, `read`, `get_log_entries`).
    pub fn observe_command(&self, member: &str, op: &str, seconds: f64) {
        self.command_duration.get_or_create(&CommandLabels { member: member.into(), op: op.into() }).observe(seconds);
    }

    /// `result`: `added`, `removed`, `recovery_added` or `failed`.
    pub fn record_repair(&self, result: &str, count: usize) {
        if count > 0 {
            self.repair.get_or_create(&ResultLabel { result: result.into() }).inc_by(count as u64);
        }
    }

    pub fn repair_total(&self, result: &str) -> u64 {
        self.repair.get(&ResultLabel { result: result.into() }).map(|c| c.get()).unwrap_or(0)
    }

    pub fn record_device_log_gap(&self, member: &str) {
        self.device_log_gap.get_or_create(&MemberLabel { member: member.into() }).inc();
    }

    pub fn device_log_gaps(&self, member: &str) -> u64 {
        self.device_log_gap.get(&MemberLabel { member: member.into() }).map(|c| c.get()).unwrap_or(0)
    }

    /// The relay's running totals for `member`. A total below the last one
    /// seen is a new relay (a reopened client): it counts from zero again.
    pub fn record_link_totals(&self, member: &str, ok: u64, failed: u64) {
        let mut last = self.link_last.lock().unwrap_or_else(|p| p.into_inner());
        for (code, total) in [("ok", ok), ("failed", failed)] {
            let seen = last.entry((member.to_string(), code.to_string())).or_insert(0);
            let delta = if total >= *seen { total - *seen } else { total };
            *seen = total;
            if delta > 0 {
                self.link_requests.get_or_create(&LinkLabels { member: member.into(), code: code.into() }).inc_by(delta);
            }
        }
    }

    pub fn link_requests(&self, member: &str, code: &str) -> u64 {
        self.link_requests.get(&LinkLabels { member: member.into(), code: code.into() }).map(|c| c.get()).unwrap_or(0)
    }

    pub fn set_member_up(&self, member: &str, up: bool) {
        self.member_up.get_or_create(&MemberLabel { member: member.to_string() }).set(i64::from(up));
    }

    pub fn member_up(&self, member: &str) -> Option<bool> {
        let label = MemberLabel { member: member.to_string() };
        self.member_up.get(&label).map(|g| g.get() == 1)
    }

    pub fn record_session_error(&self, member: &str, kind: SessionErrorKind) {
        self.session_errors.get_or_create(&SessionErrorLabels { member: member.to_string(), kind }).inc();
    }

    pub fn session_errors(&self, member: &str, kind: SessionErrorKind) -> u64 {
        let label = SessionErrorLabels { member: member.to_string(), kind };
        self.session_errors.get(&label).map(|c| c.get()).unwrap_or(0)
    }

    pub fn set_under_replicated(&self, scope: UnderReplicatedScope, count: usize) {
        let count = i64::try_from(count).unwrap_or(i64::MAX);
        let mut parts = self.under_replicated_parts.lock().unwrap_or_else(|p| p.into_inner());
        match scope {
            UnderReplicatedScope::SealRecord => parts.0 = count,
            UnderReplicatedScope::Custody => parts.1 = count,
        }
        self.under_replicated.set(parts.0.saturating_add(parts.1));
    }

    pub fn under_replicated(&self) -> i64 {
        self.under_replicated.get()
    }
}

#[cfg(test)]
mod tests {
    use prometheus_client::encoding::text::encode;

    use super::*;

    #[test]
    fn families_export_under_the_spec_names() {
        let metrics = HsmMetrics::default();
        let mut registry = Registry::default();
        metrics.register(&mut registry);
        metrics.set_member_up("hsm-a", true);
        metrics.set_member_up("hsm-b", false);
        metrics.record_session_error("hsm-b", SessionErrorKind::SessionsFull);
        metrics.set_under_replicated(UnderReplicatedScope::SealRecord, 1);
        metrics.set_under_replicated(UnderReplicatedScope::Custody, 2);

        let mut text = String::new();
        encode(&mut text, &registry).unwrap();
        assert!(text.contains("bv_hsm_member_up{member=\"hsm-a\"} 1"), "{text}");
        assert!(text.contains("bv_hsm_member_up{member=\"hsm-b\"} 0"), "{text}");
        assert!(text.contains("bv_hsm_session_errors_total{member=\"hsm-b\",kind=\"sessions_full\"} 1"), "{text}");
        assert!(text.contains("bv_hsm_under_replicated_sets 3"), "{text}");

        metrics.set_under_replicated(UnderReplicatedScope::Custody, 0);
        assert_eq!(metrics.under_replicated(), 1, "one scope never overwrites the other");
    }

    #[test]
    fn phase_6_families_export_under_the_spec_names() {
        let metrics = HsmMetrics::default();
        let mut registry = Registry::default();
        metrics.register(&mut registry);
        metrics.observe_command("hsm-a", "wrap", 0.012);
        metrics.record_repair("added", 2);
        metrics.record_repair("failed", 0);
        metrics.record_device_log_gap("hsm-b");
        metrics.record_link_totals("hsm-a", 5, 1);
        metrics.record_link_totals("hsm-a", 8, 1);
        // A reopened relay restarts its totals: counted from zero, never negative.
        metrics.record_link_totals("hsm-a", 2, 0);

        let mut text = String::new();
        encode(&mut text, &registry).unwrap();
        assert!(text.contains("bv_hsm_command_duration_seconds_count{member=\"hsm-a\",op=\"wrap\"} 1"), "{text}");
        assert!(text.contains("bv_hsm_repair_total{result=\"added\"} 2"), "{text}");
        assert!(!text.contains("result=\"failed\""), "zero counts create no series: {text}");
        assert!(text.contains("bv_hsm_device_log_gap_total{member=\"hsm-b\"} 1"), "{text}");
        assert_eq!(metrics.link_requests("hsm-a", "ok"), 10);
        assert_eq!(metrics.link_requests("hsm-a", "failed"), 1);
        assert!(text.contains("bv_hsm_link_requests_total{member=\"hsm-a\",code=\"ok\"}"), "{text}");
    }
}
