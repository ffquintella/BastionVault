//! Retention for the replicated, append-only audit stores.
//!
//! Every store listed in [`RETENTION_STORES`] is a flat system-view log whose
//! keys begin with 20-digit zero-padded nanoseconds since the epoch. "Older
//! than the cutoff" is therefore a key comparison: the pruner lists keys only
//! (no value is read or decrypted) and deletes the expired ones oldest first, in
//! bounded batches.
//!
//! Configuration is a replicated record (`sys/audit-retention/config`) edited
//! through the sudo-gated `v2/sys/audit-retention` endpoint; the built-in
//! default applies only when no record exists. An unreadable record is an
//! error, never a fallback: the default (365 days) could delete what an operator
//! configured to keep for longer.
//!
//! When the job runs, and on which node, is decided by
//! [`super::housekeeping`]; this module holds the record formats, the schedule
//! arithmetic and the pruning itself.
//!
//! Not pruned, on purpose: the policy / identity-group / asset-group change
//! histories (`{name}/{nanos}` keys) — they are the provenance of objects that
//! still exist and grow with administrative changes, not with requests — and
//! the hash-chained `audit.log` file device, which rotation already bounds.
//! See `features/audit-retention-and-dashboard-stats.md`.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    core::Core,
    errors::RvError,
    kernel_api::VaultCtx,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

/// Retention applied when no configuration record exists.
pub const DEFAULT_RETENTION_DAYS: u32 = 365;
/// Smallest accepted retention. `0` is refused rather than read as either
/// "delete everything" or "keep forever"; keeping forever is `enabled = false`.
pub const MIN_RETENTION_DAYS: u32 = 1;
/// Largest accepted retention (100 years). Bounds the cutoff arithmetic.
pub const MAX_RETENTION_DAYS: u32 = 36_500;

/// Keys deleted per batch. Each delete is one barrier write (one Raft entry on
/// hiqlite), so a batch is 500 small writes, never one large transaction.
pub const DELETE_BATCH_SIZE: usize = 500;
/// Pause between batches, so a large backlog does not monopolise the
/// replication log while requests are being served.
pub const DELETE_BATCH_PAUSE: Duration = Duration::from_millis(50);

/// Minimum time between the job arming (first start of a version that has it)
/// and its first run; see [`run_due`].
pub const FIRST_RUN_GRACE: chrono::TimeDelta = chrono::TimeDelta::days(1);

/// How far the runner's clock may be past the newest audit record before a run
/// refuses to delete (see [`clock_check`]).
pub const MAX_CLOCK_LEAD: chrono::TimeDelta = chrono::TimeDelta::days(2);

/// Current version of [`AuditRetentionConfig`] and [`AuditRetentionStatus`].
pub const RETENTION_RECORD_VERSION: u32 = 1;

const RETENTION_SUB_PATH: &str = "audit-retention/";
const CONFIG_KEY: &str = "config";
const STATUS_KEY: &str = "status";

/// Width of the nanosecond prefix every pruned store's keys start with.
const NANOS_KEY_WIDTH: usize = 20;

/// One prunable store: its operator-facing name and its system-view sub-path.
#[derive(Debug, Clone, Copy)]
pub struct RetentionStore {
    pub name: &'static str,
    pub sub_path: &'static str,
}

/// Every store the housekeeping job prunes. All are flat logs under the
/// system view whose keys start with 20-digit nanoseconds.
pub const RETENTION_STORES: &[RetentionStore] = &[
    RetentionStore { name: "access-audit", sub_path: super::access_audit_store::ACCESS_AUDIT_SUB_PATH },
    RetentionStore { name: "denial-audit", sub_path: super::denial_audit_store::DENIAL_AUDIT_SUB_PATH },
    RetentionStore {
        name: "login-audit",
        sub_path: crate::modules::credential::login_audit_store::LOGIN_AUDIT_SUB_PATH,
    },
    RetentionStore { name: "user-audit", sub_path: crate::modules::identity::user_audit_store::USER_AUDIT_SUB_PATH },
    RetentionStore { name: "share-history", sub_path: crate::modules::identity::share_store::SHARE_HISTORY_SUB_PATH },
    RetentionStore { name: "files-audit", sub_path: crate::modules::files::files_audit_store::FILES_AUDIT_SUB_PATH },
    RetentionStore {
        name: "ssh-sign-audit",
        sub_path: crate::modules::ssh::ssh_sign_audit_store::SSH_SIGN_AUDIT_SUB_PATH,
    },
    RetentionStore { name: "ssh-ca-audit", sub_path: crate::modules::ssh::ssh_ca_audit_store::SSH_CA_AUDIT_SUB_PATH },
];

/// Operator configuration. Persisted at `sys/audit-retention/config`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRetentionConfig {
    pub version: u32,
    /// Records whose key timestamp is older than this many days are deleted.
    pub retention_days: u32,
    /// `false` keeps every record forever; the job still runs and reports
    /// `disabled`.
    pub enabled: bool,
    /// RFC3339 instant of the last change; empty for the built-in default.
    #[serde(default)]
    pub updated_at: String,
    /// Display name of the principal that made the last change. Never a token.
    #[serde(default)]
    pub updated_by: String,
}

impl Default for AuditRetentionConfig {
    fn default() -> Self {
        Self {
            version: RETENTION_RECORD_VERSION,
            retention_days: DEFAULT_RETENTION_DAYS,
            enabled: true,
            updated_at: String::new(),
            updated_by: String::new(),
        }
    }
}

/// Where the effective configuration came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    /// No record exists; the built-in default applies.
    Default,
    /// The persisted record.
    Stored,
}

impl ConfigSource {
    pub fn as_str(self) -> &'static str {
        match self {
            ConfigSource::Default => "default",
            ConfigSource::Stored => "stored",
        }
    }
}

/// Per-store result of one run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreRunReport {
    pub store: String,
    /// Records deleted by this run.
    pub deleted: u64,
    /// Records at or after the cutoff, left in place.
    pub remaining: u64,
    /// Keys that do not carry a nanosecond prefix. Never deleted.
    pub unrecognised: u64,
    /// Delete batches issued.
    pub batches: u64,
    /// Why the store could not be pruned completely, if it could not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Outcome of one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunOutcome {
    /// Every store was pruned.
    Completed,
    /// At least one store failed; the others were pruned.
    Partial,
    /// Retention is disabled; nothing was deleted.
    Disabled,
    /// The run could not start (e.g. the configuration is unreadable).
    Failed,
    /// The vault was sealed mid-run; the next run continues.
    Interrupted,
    /// Nothing deleted: the runner's clock failed [`clock_check`].
    Refused,
}

/// Report of one run, kept as `last_run` in the status record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionRunReport {
    pub started_at: String,
    pub finished_at: String,
    /// RFC3339 cutoff; records strictly older were deleted. Empty when the
    /// run did not get as far as computing one.
    #[serde(default)]
    pub cutoff: String,
    pub retention_days: u32,
    pub outcome: RunOutcome,
    #[serde(default)]
    pub stores: Vec<StoreRunReport>,
    /// Why the run failed as a whole, for [`RunOutcome::Failed`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Raft node id of the node that ran it; `None` when not clustered.
    #[serde(default)]
    pub node_id: Option<u64>,
}

/// Scheduler state. Persisted at `sys/audit-retention/status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRetentionStatus {
    pub version: u32,
    /// When the job first saw this deployment. The first run is the first
    /// 00:00 UTC after it, so an upgrade never deletes in the middle of the day.
    pub armed_at: String,
    #[serde(default)]
    pub last_run: Option<RetentionRunReport>,
}

impl AuditRetentionStatus {
    pub fn armed(now: DateTime<Utc>) -> Self {
        Self { version: RETENTION_RECORD_VERSION, armed_at: now.to_rfc3339(), last_run: None }
    }
}

/// Batch size and pause for [`prune_keys`] / [`run_retention`].
/// Production uses [`PruneParams::production`]; tests shrink the batch to see
/// batching and drop the pause.
#[derive(Debug, Clone, Copy)]
pub struct PruneParams {
    pub batch_size: usize,
    pub pause: Duration,
}

impl PruneParams {
    pub fn production() -> Self {
        Self { batch_size: DELETE_BATCH_SIZE, pause: DELETE_BATCH_PAUSE }
    }
}

/// Validate a requested retention, in days. The error is operator-facing.
pub fn validate_retention_days(raw: &serde_json::Value) -> Result<u32, String> {
    let days = match raw {
        serde_json::Value::Number(n) => n.as_i64(),
        serde_json::Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
    .ok_or_else(|| "`retention_days` must be an integer number of days".to_string())?;
    if days < MIN_RETENTION_DAYS as i64 {
        return Err(format!(
            "`retention_days` must be at least {MIN_RETENTION_DAYS}; to keep audit records forever set `enabled` to false"
        ));
    }
    if days > MAX_RETENTION_DAYS as i64 {
        return Err(format!("`retention_days` must be at most {MAX_RETENTION_DAYS}"));
    }
    Ok(days as u32)
}

fn retention_view(core: &Core) -> Result<BarrierView, RvError> {
    let system_view = core.system_view().ok_or(RvError::ErrBarrierSealed)?;
    Ok(system_view.new_sub_view(RETENTION_SUB_PATH))
}

/// Decode a stored configuration. An unknown version or a malformed record is
/// an error: retention must not silently fall back to the default.
pub fn decode_config(bytes: &[u8]) -> Result<AuditRetentionConfig, String> {
    let cfg: AuditRetentionConfig =
        serde_json::from_slice(bytes).map_err(|e| format!("audit retention config is unreadable: {e}"))?;
    if cfg.version != RETENTION_RECORD_VERSION {
        return Err(format!(
            "audit retention config has unsupported version {} (this build reads {RETENTION_RECORD_VERSION})",
            cfg.version
        ));
    }
    if !(MIN_RETENTION_DAYS..=MAX_RETENTION_DAYS).contains(&cfg.retention_days) {
        return Err(format!("audit retention config holds an out-of-range retention of {} days", cfg.retention_days));
    }
    Ok(cfg)
}

/// The effective configuration and its source. Storage errors and an
/// unreadable record propagate.
pub async fn load_config(core: &Core) -> Result<(AuditRetentionConfig, ConfigSource), RvError> {
    let view = retention_view(core)?;
    match view.get(CONFIG_KEY).await? {
        None => Ok((AuditRetentionConfig::default(), ConfigSource::Default)),
        Some(entry) => decode_config(&entry.value).map(|cfg| (cfg, ConfigSource::Stored)).map_err(RvError::ErrString),
    }
}

pub async fn save_config(core: &Core, cfg: &AuditRetentionConfig) -> Result<(), RvError> {
    let view = retention_view(core)?;
    view.put(&StorageEntry { key: CONFIG_KEY.to_string(), value: serde_json::to_vec(cfg)? }).await
}

/// The scheduler state as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredStatus {
    /// The job has never armed itself on this deployment.
    Missing,
    Present(AuditRetentionStatus),
    /// Present but not decodable; the reason, for the log.
    Unreadable(String),
}

/// Read the scheduler state. A storage error propagates (the caller retries on
/// its next tick); a record that does not decode is [`StoredStatus::Unreadable`].
pub async fn load_status(core: &Core) -> Result<StoredStatus, RvError> {
    let view = retention_view(core)?;
    Ok(match view.get(STATUS_KEY).await? {
        None => StoredStatus::Missing,
        Some(entry) => match serde_json::from_slice::<AuditRetentionStatus>(&entry.value) {
            Ok(status) => StoredStatus::Present(status),
            Err(e) => StoredStatus::Unreadable(e.to_string()),
        },
    })
}

pub async fn save_status(core: &Core, status: &AuditRetentionStatus) -> Result<(), RvError> {
    let view = retention_view(core)?;
    view.put(&StorageEntry { key: STATUS_KEY.to_string(), value: serde_json::to_vec(status)? }).await
}

/// The most recent scheduled instant at or before `now`: 00:00 UTC today.
pub fn last_scheduled_run(now: DateTime<Utc>) -> DateTime<Utc> {
    now.date_naive().and_hms_opt(0, 0, 0).map(|t| t.and_utc()).unwrap_or(now)
}

/// The next scheduled instant strictly after `now`.
pub fn next_scheduled_run(now: DateTime<Utc>) -> DateTime<Utc> {
    last_scheduled_run(now) + chrono::Duration::days(1)
}

/// Whether a run is due at `now`.
///
/// Due when the most recent 00:00 UTC is later than the last run's start. That
/// one rule gives both the daily cadence and the catch-up: a node that was
/// down at midnight runs at its first tick afterwards, once.
///
/// Before the first run the reference is [`FIRST_RUN_GRACE`] after the instant
/// the job armed, so the first run is the first 00:00 UTC at least 24 hours
/// after an install or upgrade first started the job. The retention endpoint
/// only exists once the new version runs, and the first run on the default is
/// destructive (it deletes everything older than 365 days); the grace gives an
/// operator between 24 and 48 hours to configure it, whatever the time of day
/// of the upgrade.
///
/// An unparseable timestamp in the status record makes the run due, so a
/// damaged record is replaced by the run's own instead of stopping retention
/// for good.
pub fn run_due(status: &AuditRetentionStatus, now: DateTime<Utc>) -> bool {
    let (reference, grace) = match &status.last_run {
        Some(run) => (run.started_at.as_str(), chrono::TimeDelta::zero()),
        None => (status.armed_at.as_str(), FIRST_RUN_GRACE),
    };
    match DateTime::parse_from_rfc3339(reference) {
        Ok(t) => last_scheduled_run(now) > t.with_timezone(&Utc) + grace,
        Err(_) => true,
    }
}

/// The first scheduled run after the job armed at `armed_at` (see [`run_due`]).
pub fn first_scheduled_run(armed_at: DateTime<Utc>) -> DateTime<Utc> {
    next_scheduled_run(armed_at + FIRST_RUN_GRACE)
}

/// When the next run will happen, as far as the schedule knows at `now`: `now`
/// itself when one is already due (it starts at the next tick), the first run
/// after arming when none has happened, the next 00:00 UTC otherwise.
pub fn next_run_at(status: &StoredStatus, now: DateTime<Utc>) -> DateTime<Utc> {
    match status {
        StoredStatus::Missing => first_scheduled_run(now),
        StoredStatus::Unreadable(_) => now,
        StoredStatus::Present(st) if run_due(st, now) => now,
        StoredStatus::Present(st) => match (&st.last_run, DateTime::parse_from_rfc3339(&st.armed_at)) {
            (None, Ok(armed)) => first_scheduled_run(armed.with_timezone(&Utc)),
            _ => next_scheduled_run(now),
        },
    }
}

/// Zero-padded 20-digit nanoseconds for `t`, the key prefix every pruned store
/// uses. Instants before the epoch clamp to zero.
pub fn nanos_key(t: DateTime<Utc>) -> String {
    let nanos = t.timestamp_nanos_opt().unwrap_or(0).max(0) as u128;
    format!("{nanos:0width$}", width = NANOS_KEY_WIDTH)
}

/// How one listed key relates to the cutoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyClass {
    /// Its timestamp is strictly older than the cutoff.
    Expired,
    /// At or after the cutoff.
    Retained,
    /// Not a `<20 digits>` or `<20 digits>-…` key (or a sub-directory). Never deleted.
    Unrecognised,
}

/// Classify `key` against `cutoff_key` (from [`nanos_key`]). A record stamped
/// exactly at the cutoff is retained.
pub fn classify_key(key: &str, cutoff_key: &str) -> KeyClass {
    let bytes = key.as_bytes();
    if bytes.len() < NANOS_KEY_WIDTH || !bytes[..NANOS_KEY_WIDTH].iter().all(u8::is_ascii_digit) {
        return KeyClass::Unrecognised;
    }
    if bytes.len() > NANOS_KEY_WIDTH && bytes[NANOS_KEY_WIDTH] != b'-' {
        return KeyClass::Unrecognised;
    }
    if key.contains('/') {
        return KeyClass::Unrecognised;
    }
    if &key[..NANOS_KEY_WIDTH] < cutoff_key {
        KeyClass::Expired
    } else {
        KeyClass::Retained
    }
}

/// The keys of one store, keys only — no value is read or decrypted.
pub async fn list_store(view: &BarrierView) -> Result<Vec<String>, RvError> {
    view.list("").await
}

/// The timestamp of the newest recognised key among `keys`, if any.
pub fn newest_key_time(keys: &[String]) -> Option<DateTime<Utc>> {
    keys.iter()
        .filter(|k| classify_key(k, "") != KeyClass::Unrecognised)
        .map(|k| &k[..NANOS_KEY_WIDTH])
        .max()
        .and_then(|prefix| prefix.parse::<i64>().ok())
        .map(DateTime::from_timestamp_nanos)
}

/// Sanity check of the runner's clock before anything is deleted.
///
/// The cutoff is `now - retention`, so a runner whose clock has jumped ahead
/// would delete records early. The reference is the newest record across every
/// pruned store: in a live deployment the access, denial and login stores are
/// written continuously by every node, so the newest record is minutes old. If
/// `now` is more than [`MAX_CLOCK_LEAD`] past it, either this clock is wrong or
/// the deployment has been idle that long — and in both cases waiting is free
/// (an idle deployment is not growing), so the run refuses instead of guessing.
/// The reference is deployment-wide rather than per store because a single
/// store can legitimately go quiet for months (SSH CA changes) and must still
/// be pruned. No records at all means nothing to delete, so the check passes.
pub fn clock_check(now: DateTime<Utc>, newest_record: Option<DateTime<Utc>>) -> Result<(), String> {
    match newest_record {
        Some(newest) if now - newest > MAX_CLOCK_LEAD => Err(format!(
            "this node's clock ({}) is {} hours past the newest audit record ({}); refusing to delete \
             until the clock is checked or new audit records arrive (limit {} hours)",
            now.to_rfc3339(),
            (now - newest).num_hours(),
            newest.to_rfc3339(),
            MAX_CLOCK_LEAD.num_hours()
        )),
        _ => Ok(()),
    }
}

/// Delete every expired key among `keys` (one store's listing), oldest first,
/// in batches of `params.batch_size`, pausing `params.pause` between batches
/// and checking `sealed()` before each.
///
/// Returns the report even when a delete fails or the vault seals: the counts
/// up to that point are kept and the reason is in `error`; the flag is true
/// when the run was interrupted by a seal. Idempotent — a second call with the
/// same cutoff deletes nothing.
pub async fn prune_keys(
    view: &BarrierView,
    store: &str,
    keys: Vec<String>,
    cutoff_key: &str,
    params: PruneParams,
    sealed: &(dyn Fn() -> bool + Send + Sync),
) -> (StoreRunReport, bool) {
    let mut report = StoreRunReport { store: store.to_string(), ..Default::default() };
    let mut expired: Vec<String> = Vec::new();
    for key in keys {
        match classify_key(&key, cutoff_key) {
            KeyClass::Expired => expired.push(key),
            KeyClass::Retained => report.remaining += 1,
            KeyClass::Unrecognised => report.unrecognised += 1,
        }
    }
    expired.sort();

    let batch_size = params.batch_size.max(1);
    for batch in expired.chunks(batch_size) {
        if sealed() {
            report.remaining += (expired.len() as u64).saturating_sub(report.deleted);
            report.error = Some("the vault sealed during the run".to_string());
            return (report, true);
        }
        report.batches += 1;
        for key in batch {
            if let Err(e) = view.delete(key).await {
                report.remaining += (expired.len() as u64).saturating_sub(report.deleted);
                report.error = Some(format!("deleting an expired record failed: {e}"));
                return (report, false);
            }
            report.deleted += 1;
        }
        if !params.pause.is_zero() {
            tokio::time::sleep(params.pause).await;
        }
    }
    (report, false)
}

/// One retention run over every store in [`RETENTION_STORES`], at `now`.
///
/// Reads the configuration first; an unreadable configuration fails the run
/// without deleting anything. Logs one `security` line per store and one
/// summary line, never record contents.
pub async fn run_retention(core: &Core, now: DateTime<Utc>, params: PruneParams) -> RetentionRunReport {
    let node_id = crate::storage::cluster::node_id(core.physical.as_ref());
    let started_at = now.to_rfc3339();
    let failed = |error: String, retention_days: u32| RetentionRunReport {
        started_at: started_at.clone(),
        finished_at: Utc::now().to_rfc3339(),
        cutoff: String::new(),
        retention_days,
        outcome: RunOutcome::Failed,
        stores: Vec::new(),
        error: Some(error),
        node_id,
    };

    let cfg = match load_config(core).await {
        Ok((cfg, _)) => cfg,
        Err(e) => {
            log::error!(
                target: "security",
                "audit-retention: run refused, nothing deleted: the retention configuration could not be read ({e})"
            );
            return failed(format!("the retention configuration could not be read: {e}"), 0);
        }
    };

    if !cfg.enabled {
        log::info!(target: "security", "audit-retention: retention is disabled; no audit records deleted");
        return RetentionRunReport {
            started_at: started_at.clone(),
            finished_at: Utc::now().to_rfc3339(),
            cutoff: String::new(),
            retention_days: cfg.retention_days,
            outcome: RunOutcome::Disabled,
            stores: Vec::new(),
            error: None,
            node_id,
        };
    }

    let Some(system_view) = core.system_view() else {
        return failed("the vault is sealed".to_string(), cfg.retention_days);
    };

    let cutoff = now - chrono::Duration::days(cfg.retention_days as i64);
    let cutoff_key = nanos_key(cutoff);
    let cutoff_rfc = cutoff.to_rfc3339();
    let sealed = || core.sealed();

    // List every store first (keys only): the clock check needs the newest
    // record across all of them before anything is deleted.
    let mut listings: Vec<(&RetentionStore, Result<Vec<String>, String>)> = Vec::with_capacity(RETENTION_STORES.len());
    for store in RETENTION_STORES {
        let view = system_view.new_sub_view(store.sub_path);
        let listed = list_store(&view).await.map_err(|e| format!("listing the store failed: {e}"));
        listings.push((store, listed));
    }
    let newest = listings.iter().filter_map(|(_, l)| l.as_ref().ok()).filter_map(|keys| newest_key_time(keys)).max();

    if let Err(reason) = clock_check(now, newest) {
        log::error!(target: "security", "audit-retention: run refused, nothing deleted: {reason}");
        let stores = listings
            .into_iter()
            .map(|(store, listed)| StoreRunReport {
                store: store.name.to_string(),
                remaining: listed.as_ref().map(|k| k.len() as u64).unwrap_or(0),
                error: Some(match listed {
                    Ok(_) => "not pruned: clock check failed".to_string(),
                    Err(e) => e,
                }),
                ..Default::default()
            })
            .collect();
        return RetentionRunReport {
            started_at,
            finished_at: Utc::now().to_rfc3339(),
            cutoff: cutoff_rfc,
            retention_days: cfg.retention_days,
            outcome: RunOutcome::Refused,
            stores,
            error: Some(reason),
            node_id,
        };
    }

    let mut stores = Vec::with_capacity(RETENTION_STORES.len());
    let mut outcome = RunOutcome::Completed;
    for (store, listed) in listings {
        let view = system_view.new_sub_view(store.sub_path);
        let (report, interrupted) = match listed {
            Ok(keys) => prune_keys(&view, store.name, keys, &cutoff_key, params, &sealed).await,
            Err(e) => (StoreRunReport { store: store.name.to_string(), error: Some(e), ..Default::default() }, false),
        };
        match &report.error {
            None => log::info!(
                target: "security",
                "audit-retention: store={} deleted={} remaining={} unrecognised={} cutoff={} retention_days={}",
                report.store, report.deleted, report.remaining, report.unrecognised, cutoff_rfc, cfg.retention_days
            ),
            Some(err) => log::warn!(
                target: "security",
                "audit-retention: store={} deleted={} before stopping: {err} (cutoff={})",
                report.store, report.deleted, cutoff_rfc
            ),
        }
        if report.error.is_some() && outcome == RunOutcome::Completed {
            outcome = RunOutcome::Partial;
        }
        stores.push(report);
        if interrupted {
            outcome = RunOutcome::Interrupted;
            break;
        }
    }

    let deleted: u64 = stores.iter().map(|s| s.deleted).sum();
    log::info!(
        target: "security",
        "audit-retention: run {} — {deleted} audit records older than {cutoff_rfc} deleted across {} stores",
        match outcome {
            RunOutcome::Completed => "completed",
            RunOutcome::Partial => "partially completed",
            RunOutcome::Interrupted => "interrupted",
            RunOutcome::Disabled => "disabled",
            RunOutcome::Failed => "failed",
            RunOutcome::Refused => "refused",
        },
        stores.len()
    );

    RetentionRunReport {
        started_at,
        finished_at: Utc::now().to_rfc3339(),
        cutoff: cutoff_rfc,
        retention_days: cfg.retention_days,
        outcome,
        stores,
        error: None,
        node_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn retention_days_bounds_are_explicit() {
        assert_eq!(validate_retention_days(&json!(365)), Ok(365));
        assert_eq!(validate_retention_days(&json!(1)), Ok(1));
        assert_eq!(validate_retention_days(&json!(MAX_RETENTION_DAYS)), Ok(MAX_RETENTION_DAYS));
        assert_eq!(validate_retention_days(&json!("30")), Ok(30));
        // `0` is refused, and the message points at the explicit way to keep
        // records forever instead of guessing what `0` meant.
        let zero = validate_retention_days(&json!(0)).unwrap_err();
        assert!(zero.contains("at least 1") && zero.contains("enabled"), "{zero}");
        assert!(validate_retention_days(&json!(-5)).is_err());
        assert!(validate_retention_days(&json!(MAX_RETENTION_DAYS + 1)).is_err());
        assert!(validate_retention_days(&json!(1.5)).is_err());
        assert!(validate_retention_days(&json!("thirty")).is_err());
        assert!(validate_retention_days(&json!(true)).is_err());
        assert!(validate_retention_days(&json!(null)).is_err());
    }

    #[test]
    fn config_round_trips_and_refuses_unknown_versions() {
        let cfg = AuditRetentionConfig {
            retention_days: 90,
            enabled: false,
            updated_at: "2026-10-14T00:00:00+00:00".into(),
            updated_by: "root".into(),
            ..Default::default()
        };
        let bytes = serde_json::to_vec(&cfg).unwrap();
        assert_eq!(decode_config(&bytes).unwrap(), cfg);

        let future = serde_json::to_vec(&json!({"version": 2, "retention_days": 90, "enabled": true})).unwrap();
        assert!(decode_config(&future).unwrap_err().contains("unsupported version 2"));
        let zero = serde_json::to_vec(&json!({"version": 1, "retention_days": 0, "enabled": true})).unwrap();
        assert!(decode_config(&zero).unwrap_err().contains("out-of-range"));
        assert!(decode_config(b"not json").is_err());
        assert!(decode_config(br#"{"version":1}"#).is_err(), "a record without retention_days is unreadable");
    }

    #[test]
    fn schedule_is_daily_at_midnight_utc() {
        let now = at("2026-10-14T13:45:10Z");
        assert_eq!(last_scheduled_run(now), at("2026-10-14T00:00:00Z"));
        assert_eq!(next_scheduled_run(now), at("2026-10-15T00:00:00Z"));
        assert_eq!(last_scheduled_run(at("2026-10-14T00:00:00Z")), at("2026-10-14T00:00:00Z"));
    }

    #[test]
    fn a_fresh_arm_waits_at_least_a_day_for_its_first_midnight() {
        let status = AuditRetentionStatus::armed(at("2026-10-14T13:00:00Z"));
        assert!(!run_due(&status, at("2026-10-14T13:00:00Z")));
        assert!(!run_due(&status, at("2026-10-15T00:00:30Z")), "the first midnight is only 11 hours away");
        assert!(!run_due(&status, at("2026-10-15T23:59:59Z")));
        assert!(run_due(&status, at("2026-10-16T00:00:30Z")));
        assert_eq!(first_scheduled_run(at("2026-10-14T13:00:00Z")), at("2026-10-16T00:00:00Z"));

        // Armed a second before midnight: still a full day of grace.
        let late = AuditRetentionStatus::armed(at("2026-10-14T23:59:59Z"));
        assert!(!run_due(&late, at("2026-10-15T00:00:30Z")));
        assert!(run_due(&late, at("2026-10-16T00:00:30Z")));
        assert_eq!(first_scheduled_run(at("2026-10-14T23:59:59Z")), at("2026-10-16T00:00:00Z"));
    }

    fn ran_at(started_at: &str) -> AuditRetentionStatus {
        AuditRetentionStatus {
            version: RETENTION_RECORD_VERSION,
            armed_at: "2026-01-01T12:00:00+00:00".into(),
            last_run: Some(RetentionRunReport {
                started_at: started_at.into(),
                finished_at: started_at.into(),
                cutoff: String::new(),
                retention_days: 365,
                outcome: RunOutcome::Completed,
                stores: Vec::new(),
                error: None,
                node_id: None,
            }),
        }
    }

    #[test]
    fn the_next_run_accounts_for_the_first_run_grace() {
        let now = at("2026-10-14T13:00:00Z");
        assert_eq!(next_run_at(&StoredStatus::Missing, now), at("2026-10-16T00:00:00Z"));
        let armed = StoredStatus::Present(AuditRetentionStatus::armed(at("2026-10-14T09:00:00Z")));
        assert_eq!(next_run_at(&armed, now), at("2026-10-16T00:00:00Z"));
        let ran = StoredStatus::Present(ran_at("2026-10-14T00:00:05+00:00"));
        assert_eq!(next_run_at(&ran, now), at("2026-10-15T00:00:00Z"));
        let overdue = StoredStatus::Present(ran_at("2026-10-12T00:00:05+00:00"));
        assert_eq!(next_run_at(&overdue, now), now, "a missed run starts at the next tick");
        assert_eq!(next_run_at(&StoredStatus::Unreadable("x".into()), now), now);
    }

    #[test]
    fn a_run_is_due_once_per_day_and_catches_up_after_downtime() {
        let status = ran_at("2026-10-14T00:00:05+00:00");
        assert!(!run_due(&status, at("2026-10-14T00:01:00Z")), "already ran today");
        assert!(!run_due(&status, at("2026-10-14T23:59:00Z")));
        assert!(run_due(&status, at("2026-10-15T00:00:10Z")), "next midnight");
        // The node was down from before midnight until 03:00 two days later:
        // one catch-up run, not one per missed day.
        assert!(run_due(&status, at("2026-10-16T03:00:00Z")));
        let caught_up = ran_at("2026-10-16T03:00:00+00:00");
        assert!(!run_due(&caught_up, at("2026-10-16T03:01:00Z")));
        assert!(!run_due(&caught_up, at("2026-10-16T23:59:59Z")));
    }

    #[test]
    fn a_damaged_status_timestamp_makes_the_run_due() {
        assert!(run_due(&ran_at("yesterday"), at("2026-10-14T10:00:00Z")));
    }

    #[test]
    fn keys_are_classified_against_the_cutoff_and_the_boundary_is_kept() {
        let cutoff = nanos_key(at("2026-01-01T00:00:00Z"));
        let just_before = nanos_key(at("2025-12-31T23:59:59.999999999Z"));
        let exactly = cutoff.clone();
        assert_eq!(classify_key(&just_before, &cutoff), KeyClass::Expired);
        assert_eq!(classify_key(&exactly, &cutoff), KeyClass::Retained, "a record at the cutoff is kept");
        assert_eq!(classify_key(&format!("{exactly}-0123456789abcdef"), &cutoff), KeyClass::Retained);
        assert_eq!(classify_key(&format!("{just_before}-0123456789abcdef"), &cutoff), KeyClass::Expired);
        for odd in [
            "",
            "config",
            "0000000000000000001",
            "00000000000000000001x",
            "0000000000000000000a",
            "00000000000000000001-a/b",
            "dir/",
        ] {
            assert_eq!(classify_key(odd, &cutoff), KeyClass::Unrecognised, "{odd:?}");
        }
    }

    #[test]
    fn the_clock_check_refuses_a_runner_far_ahead_of_the_newest_record() {
        let now = at("2026-10-14T00:00:30Z");
        assert!(clock_check(now, None).is_ok(), "no records: nothing to delete, nothing to guard");
        assert!(clock_check(now, Some(at("2026-10-13T23:59:00Z"))).is_ok());
        assert!(clock_check(now, Some(at("2026-10-12T00:00:31Z"))).is_ok(), "just inside two days");
        let err = clock_check(now, Some(at("2026-10-12T00:00:00Z"))).unwrap_err();
        assert!(err.contains("48 hours") && err.contains("refusing"), "{err}");
        // A clock that jumped a year ahead of a live deployment is refused.
        assert!(clock_check(at("2027-10-14T00:00:00Z"), Some(at("2026-10-13T23:00:00Z"))).is_err());
        // Records stamped ahead of this clock are not a reason to refuse.
        assert!(clock_check(now, Some(at("2026-10-20T00:00:00Z"))).is_ok());
    }

    #[test]
    fn the_newest_record_ignores_unrecognised_keys() {
        let a = nanos_key(at("2026-01-01T00:00:00Z"));
        let b = format!("{}-00000000000000ff", nanos_key(at("2026-03-01T00:00:00Z")));
        let keys = vec![a, b, "zzzzzzzzzzzzzzzzzzzzzzzz".to_string(), "99999999999999999999x".to_string()];
        assert_eq!(newest_key_time(&keys), Some(at("2026-03-01T00:00:00Z")));
        assert_eq!(newest_key_time(&["config".to_string()]), None);
        assert_eq!(newest_key_time(&[]), None);
    }

    #[test]
    fn nanos_key_matches_the_append_stores_format() {
        let k = nanos_key(at("2026-07-21T09:15:19Z"));
        assert_eq!(k.len(), 20);
        assert_eq!(k, format!("{:020}", at("2026-07-21T09:15:19Z").timestamp_nanos_opt().unwrap()));
        assert_eq!(nanos_key(at("1960-01-01T00:00:00Z")), "0".repeat(20), "pre-epoch clamps to zero");
    }
}
