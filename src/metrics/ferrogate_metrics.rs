//! Prometheus counters for the FerroGate machine-auth backend.
//!
//! Process-wide singleton in the [`GLOBAL`] `OnceLock`, mirroring
//! [`crate::metrics::cache_metrics`]: the backend increments counters through
//! [`ferrogate_metrics`], and [`MetricsManager`](crate::metrics::manager) calls
//! [`FerroGateMetrics::register`] so scrapes see them. Counters are unlabelled
//! except `login_denied`, which carries a `reason` label.

use std::sync::OnceLock;

use prometheus_client::{
    encoding::{EncodeLabelSet, EncodeLabelValue, LabelValueEncoder},
    metrics::{counter::Counter, family::Family},
    registry::Registry,
};

pub const LOGIN_TOTAL: &str = "bvault_ferrogate_login_total";
pub const LOGIN_TOTAL_HELP: &str = "Successful FerroGate machine logins (tokens minted)";

pub const LOGIN_DENIED_TOTAL: &str = "bvault_ferrogate_login_denied_total";
pub const LOGIN_DENIED_TOTAL_HELP: &str = "Denied FerroGate logins, labelled by reason";

pub const PENDING_TOTAL: &str = "bvault_ferrogate_pending_total";
pub const PENDING_TOTAL_HELP: &str = "Machines newly recorded as pending (first seen)";

pub const APPROVED_TOTAL: &str = "bvault_ferrogate_approved_total";
pub const APPROVED_TOTAL_HELP: &str = "Machine approvals (admin or first-machine bootstrap)";

/// Why a login was denied. Stable string values for the `reason` label.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub enum DenyReason {
    /// Token signature / audience / trust-domain / DPoP verification failed.
    VerifyFailed,
    /// Machine known but awaiting approval.
    Pending,
    /// Machine rejected.
    Rejected,
    /// Machine revoked.
    Revoked,
    /// Per-source-IP rate limit hit.
    RateLimited,
}

impl EncodeLabelValue for DenyReason {
    fn encode(&self, writer: &mut LabelValueEncoder<'_>) -> Result<(), std::fmt::Error> {
        use std::fmt::Write;
        match self {
            DenyReason::VerifyFailed => writer.write_str("verify_failed"),
            DenyReason::Pending => writer.write_str("pending"),
            DenyReason::Rejected => writer.write_str("rejected"),
            DenyReason::Revoked => writer.write_str("revoked"),
            DenyReason::RateLimited => writer.write_str("rate_limited"),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DenyLabel {
    pub reason: DenyReason,
}

/// Clone-cheap collection of FerroGate backend counters.
#[derive(Clone, Default)]
pub struct FerroGateMetrics {
    login: Counter,
    login_denied: Family<DenyLabel, Counter>,
    pending: Counter,
    approved: Counter,
}

static GLOBAL: OnceLock<FerroGateMetrics> = OnceLock::new();

/// Shared process-wide instance, lazily initialised on first access.
pub fn ferrogate_metrics() -> &'static FerroGateMetrics {
    GLOBAL.get_or_init(FerroGateMetrics::default)
}

impl FerroGateMetrics {
    /// Register this instance's families with `registry`. Called from
    /// `MetricsManager::new`; idempotent across registries.
    pub fn register(&self, registry: &mut Registry) {
        registry.register(LOGIN_TOTAL, LOGIN_TOTAL_HELP, self.login.clone());
        registry.register(LOGIN_DENIED_TOTAL, LOGIN_DENIED_TOTAL_HELP, self.login_denied.clone());
        registry.register(PENDING_TOTAL, PENDING_TOTAL_HELP, self.pending.clone());
        registry.register(APPROVED_TOTAL, APPROVED_TOTAL_HELP, self.approved.clone());
    }

    pub fn record_login(&self) {
        self.login.inc();
    }

    pub fn record_denied(&self, reason: DenyReason) {
        self.login_denied.get_or_create(&DenyLabel { reason }).inc();
    }

    pub fn record_pending(&self) {
        self.pending.inc();
    }

    pub fn record_approved(&self) {
        self.approved.inc();
    }
}
