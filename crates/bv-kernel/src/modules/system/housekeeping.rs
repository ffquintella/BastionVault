//! Background housekeeping: dashboard statistics and audit retention.
//!
//! One detached task per system-module instance, ticking every
//! [`TICK_INTERVAL`] and skipping while the vault is sealed. Each tick:
//!
//! 1. decides whether this node is the runner ([`runner_role`]): the Raft
//!    leader on a hiqlite cluster, or the only node otherwise. Followers do
//!    nothing — every node reads the replicated results;
//! 2. refreshes the dashboard statistics record when it is missing or
//!    [`dashboard_stats::REFRESH_INTERVAL`] old (so a missing record is
//!    computed on the first tick after start);
//! 3. arms the retention schedule on first sight, and runs retention when the
//!    daily 00:00 UTC run is due ([`audit_retention::run_due`]), catching up a
//!    missed run once.
//!
//! There is no distributed lock. Both jobs are idempotent — re-deleting an
//! already-deleted key is a no-op and the stats record is derived data — so a
//! deposed leader that has not yet noticed costs duplicate work, never a wrong
//! result. Within one process the single task cannot overlap itself.

use std::{sync::Weak, time::Duration};

use chrono::{DateTime, Utc};
use tokio::time::MissedTickBehavior;

use super::{audit_retention, dashboard_stats, SystemBackend};
use crate::{core::Core, errors::RvError};

/// How often the housekeeping task wakes.
pub const TICK_INTERVAL: Duration = Duration::from_secs(60);

/// This node's part in the cluster-wide jobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerRole {
    /// Not clustered: this node is the runner.
    Single,
    /// The Raft leader: this node is the runner.
    Leader,
    /// A Raft follower: the leader runs the jobs.
    Follower,
}

impl RunnerRole {
    pub fn runs_jobs(self) -> bool {
        !matches!(self, RunnerRole::Follower)
    }
}

/// Ask the storage layer whether this node runs the cluster-wide jobs.
pub async fn runner_role(core: &Core) -> RunnerRole {
    match crate::storage::cluster::status(core.physical.as_ref()).await {
        None => RunnerRole::Single,
        Some(status) if status.is_leader => RunnerRole::Leader,
        Some(_) => RunnerRole::Follower,
    }
}

/// What one tick did. Returned for tests and for the debug log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickReport {
    /// The tick was skipped because this node is a follower.
    pub skipped_follower: bool,
    pub stats_refreshed: bool,
    /// The retention schedule was armed by this tick (first sight).
    pub retention_armed: bool,
    /// A retention run happened in this tick.
    pub retention_ran: Option<audit_retention::RunOutcome>,
}

/// One housekeeping tick at `now` for a node in `role`.
pub async fn tick(
    backend: &SystemBackend,
    now: DateTime<Utc>,
    role: RunnerRole,
    params: audit_retention::PruneParams,
) -> TickReport {
    let mut report = TickReport::default();
    if !role.runs_jobs() {
        report.skipped_follower = true;
        return report;
    }
    let core = backend.core.as_ref();

    // 1. Dashboard statistics.
    match dashboard_stats::load(core).await {
        Ok(stored) if dashboard_stats::needs_refresh(&stored, now) => match backend.refresh_dashboard_stats().await {
            Ok(_) => report.stats_refreshed = true,
            Err(e) => log::warn!("dashboard-stats: refresh failed: {e}"),
        },
        Ok(_) => {}
        Err(e) => log::warn!("dashboard-stats: the stored record could not be read: {e}"),
    }

    // 2. Audit retention.
    let due_status = match audit_retention::load_status(core).await {
        Ok(audit_retention::StoredStatus::Missing) => {
            let status = audit_retention::AuditRetentionStatus::armed(now);
            match audit_retention::save_status(core, &status).await {
                Ok(()) => {
                    report.retention_armed = true;
                    log::info!(
                        target: "security",
                        "audit-retention: schedule armed; first run at {} (the first 00:00 UTC at least 24 hours from now, then daily)",
                        audit_retention::first_scheduled_run(now).to_rfc3339()
                    );
                }
                Err(e) => log::warn!("audit-retention: arming the schedule failed: {e}"),
            }
            None
        }
        Ok(audit_retention::StoredStatus::Present(status)) if audit_retention::run_due(&status, now) => Some(status),
        Ok(audit_retention::StoredStatus::Present(_)) => None,
        Ok(audit_retention::StoredStatus::Unreadable(reason)) => {
            // Same rule as an unparseable timestamp in `run_due`: run now and
            // let the run's report replace the damaged record, rather than
            // leaving retention stopped until someone notices.
            log::warn!(
                target: "security",
                "audit-retention: the schedule record is unreadable ({reason}); running now to replace it"
            );
            Some(audit_retention::AuditRetentionStatus::armed(now))
        }
        Err(e) => {
            // Transient storage trouble: try again next tick. Never re-arm on
            // a read error — that would push today's run to tomorrow.
            log::warn!("audit-retention: the schedule record could not be read: {e}");
            None
        }
    };
    if let Some(status) = due_status {
        let run = audit_retention::run_retention(core, now, params).await;
        report.retention_ran = Some(run.outcome);
        let updated = audit_retention::AuditRetentionStatus { last_run: Some(run), ..status };
        if let Err(e) = audit_retention::save_status(core, &updated).await {
            // The run itself happened; the next tick will find it due again
            // and re-run, which deletes nothing new.
            log::warn!(target: "security", "audit-retention: recording the run failed: {e}");
        }
    }
    report
}

/// The startup line about retention: the effective setting and the next run.
///
/// Running on the built-in default is said loudly (`warn`): on an upgrade the
/// first 00:00 UTC run permanently deletes every audit record older than 365
/// days without anyone having configured anything, and this line is the
/// operator's warning in the log before that happens.
pub fn retention_announcement(
    cfg: &audit_retention::AuditRetentionConfig,
    source: audit_retention::ConfigSource,
    next_run: DateTime<Utc>,
) -> (log::Level, String) {
    let next = next_run.to_rfc3339();
    if !cfg.enabled {
        return (
            log::Level::Info,
            "audit-retention: retention is disabled; audit records are kept forever".to_string(),
        );
    }
    match source {
        audit_retention::ConfigSource::Default => (
            log::Level::Warn,
            format!(
                "audit-retention: no retention is configured, so the built-in default applies: audit records older \
                 than {} days are PERMANENTLY DELETED by the daily run on the cluster leader, the next at {next} \
                 (00:00 UTC). To keep them longer, set `v2/sys/audit-retention` (`retention_days`, or \
                 `enabled: false`) before then.",
                cfg.retention_days
            ),
        ),
        audit_retention::ConfigSource::Stored => (
            log::Level::Info,
            format!(
                "audit-retention: retention is {} days (set by {} at {}); the next run is at {next} (00:00 UTC)",
                cfg.retention_days,
                if cfg.updated_by.is_empty() { "(unknown)" } else { cfg.updated_by.as_str() },
                if cfg.updated_at.is_empty() { "(unknown)" } else { cfg.updated_at.as_str() },
            ),
        ),
    }
}

/// Log [`retention_announcement`] once. Returns false when the configuration
/// could not be read for a reason worth retrying (sealed / storage), so the
/// caller tries again on the next tick.
async fn announce_retention(core: &Core, now: DateTime<Utc>) -> bool {
    match audit_retention::load_config(core).await {
        Ok((cfg, source)) => {
            // Without a readable schedule record, assume a fresh arm: the
            // earliest the first run can be.
            let status = audit_retention::load_status(core).await.unwrap_or(audit_retention::StoredStatus::Missing);
            let next_run = audit_retention::next_run_at(&status, now);
            let (level, message) = retention_announcement(&cfg, source, next_run);
            log::log!(target: "security", level, "{message}");
            true
        }
        Err(RvError::ErrString(reason)) => {
            // Present but undecodable: say so once; runs will refuse to delete.
            log::error!(
                target: "security",
                "audit-retention: {reason}; no audit records will be deleted until `v2/sys/audit-retention` is written again"
            );
            true
        }
        Err(e) => {
            log::warn!("audit-retention: the retention configuration could not be read yet: {e}");
            false
        }
    }
}

/// Spawn the housekeeping task. Holds the backend weakly and stops when it is
/// gone. Detached: dropping the handle does not stop it.
pub fn start_housekeeping(backend: Weak<SystemBackend>) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn(async move {
        log::info!(
            "housekeeping: started (tick every {}s; dashboard statistics every {}s; audit retention daily at 00:00 UTC on the cluster leader)",
            TICK_INTERVAL.as_secs(),
            dashboard_stats::REFRESH_INTERVAL.as_secs()
        );
        let mut interval = tokio::time::interval(TICK_INTERVAL);
        // A retention run can outlast a tick; do not fire a burst afterwards.
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut announced = false;
        loop {
            interval.tick().await;
            let Some(backend) = backend.upgrade() else {
                log::debug!("housekeeping: system backend dropped; stopping");
                break;
            };
            if backend.core.sealed() {
                continue;
            }
            // Every node says once, at its first unsealed tick, what retention
            // will do — not only the leader, so the warning is in whichever
            // node's log an operator reads.
            if !announced {
                announced = announce_retention(&backend.core, Utc::now()).await;
            }
            let role = runner_role(&backend.core).await;
            let report = tick(&backend, Utc::now(), role, audit_retention::PruneParams::production()).await;
            log::debug!("housekeeping: tick as {role:?}: {report:?}");
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_on_the_default_is_announced_as_a_warning_with_the_next_run() {
        let now = DateTime::parse_from_rfc3339("2026-10-14T13:00:00Z").unwrap().with_timezone(&Utc);
        let next = audit_retention::next_run_at(&audit_retention::StoredStatus::Missing, now);
        let default = audit_retention::AuditRetentionConfig::default();
        let (level, msg) = retention_announcement(&default, audit_retention::ConfigSource::Default, next);
        assert_eq!(level, log::Level::Warn);
        for needle in ["365 days", "PERMANENTLY DELETED", "2026-10-16T00:00:00+00:00", "v2/sys/audit-retention"] {
            assert!(msg.contains(needle), "{needle:?} missing from: {msg}");
        }

        let stored = audit_retention::AuditRetentionConfig {
            retention_days: 730,
            updated_by: "root".into(),
            ..Default::default()
        };
        let (level, msg) = retention_announcement(&stored, audit_retention::ConfigSource::Stored, next);
        assert_eq!(level, log::Level::Info);
        assert!(msg.contains("730 days") && msg.contains("root"), "{msg}");

        let off = audit_retention::AuditRetentionConfig { enabled: false, ..Default::default() };
        let (level, msg) = retention_announcement(&off, audit_retention::ConfigSource::Stored, next);
        assert_eq!(level, log::Level::Info);
        assert!(msg.contains("kept forever"), "{msg}");
    }

    #[test]
    fn only_followers_skip() {
        assert!(RunnerRole::Single.runs_jobs());
        assert!(RunnerRole::Leader.runs_jobs());
        assert!(!RunnerRole::Follower.runs_jobs());
    }
}
