//! Prometheus families for the HSM pool (`features/hsm-pool-ha.md` § Metrics).
//!
//! Process-wide singleton, like [`crate::ferrogate_metrics`]: `bv-core`'s pool
//! records through [`hsm_metrics`] and [`MetricsManager`](crate::manager)
//! registers the families. Labels are the operator-chosen member name and a
//! closed `kind` set; never a key id, serial or node credential.

use std::sync::{Mutex, OnceLock};

use prometheus_client::{
    encoding::{EncodeLabelSet, EncodeLabelValue, LabelValueEncoder},
    metrics::{counter::Counter, family::Family, gauge::Gauge},
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

#[derive(Default)]
pub struct HsmMetrics {
    member_up: Family<MemberLabel, Gauge>,
    session_errors: Family<SessionErrorLabels, Counter>,
    under_replicated: Gauge,
    /// (seal record, custody) counts behind `under_replicated`.
    under_replicated_parts: Mutex<(i64, i64)>,
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
}
