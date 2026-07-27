//! Single-process tick-loop scheduler.
//!
//! Spawned by `Core::post_unseal` once the barrier is open. Walks every
//! schedule on a fixed cadence; when a cron instant has passed since the
//! schedule last fired, the schedule fires once and the new fire time is
//! recorded.
//!
//! Cron expressions are evaluated in the **server's local timezone**, which
//! is what the spec and the GUI editor promise the operator ("`0 0 3 * * *`
//! — 03:00 daily, server local time").
//!
//! First sighting of a schedule after process start resumes from that
//! schedule's most recent persisted run record, so a restart between two
//! cron instants does not silently swallow the window: one missed instance
//! is run (never a burst of every instance since the last run — catch-up is
//! `single`, and the per-tick scan is bounded). A schedule that has never
//! run resumes from "now".
//!
//! HA + leader gating land in a follow-up per
//! `features/scheduled-exports.md` Phase 1 (deferred) — on a cluster every
//! node runs its own copy of each schedule against its own destination.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Local, Utc};
use cron::Schedule as CronSchedule;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::{
    core::Core,
    errors::RvError,
    exchange,
    storage::Storage,
};

use super::schedule::{
    DestinationKind, ExportFormat, PasswordRefKind, RunRecord, RunStatus, Schedule,
};
use super::store::ScheduleStore;

const TICK_INTERVAL: Duration = Duration::from_secs(30);

/// Upper bound on how many cron instants a single tick will walk when
/// catching up. A frequent cron (`* * * * * *`) plus a stale resume point
/// would otherwise make one tick enumerate unbounded history; the scan stops
/// here and the next tick continues from where this one left off.
const MAX_CATCHUP_SCAN: usize = 10_000;

/// Spawn the scheduler tick loop. The returned task runs until the
/// process exits or until the supplied `Core` is dropped.
pub fn start_scheduler(core: Arc<Core>) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn(async move {
        let store = ScheduleStore::new();
        let last_fired: Arc<Mutex<HashMap<String, DateTime<Utc>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        log::info!("scheduled-exports: scheduler started (tick every {}s)", TICK_INTERVAL.as_secs());

        let mut interval = tokio::time::interval(TICK_INTERVAL);
        loop {
            interval.tick().await;
            if core.state.load().sealed {
                continue;
            }
            if let Err(e) = tick(&core, &store, last_fired.clone()).await {
                log::warn!("scheduled-exports: tick failed: {e}");
            }
        }
    })
}

async fn tick(
    core: &Arc<Core>,
    store: &ScheduleStore,
    last_fired: Arc<Mutex<HashMap<String, DateTime<Utc>>>>,
) -> Result<(), RvError> {
    let schedules = store.list(core.barrier.as_storage()).await?;
    let now = Utc::now();
    for sched in schedules {
        if !sched.enabled {
            continue;
        }
        let cron_expr = match CronSchedule::from_str(&sched.cron) {
            Ok(c) => c,
            Err(e) => {
                log::warn!(
                    "scheduled-exports: schedule {} has invalid cron `{}`: {e}",
                    sched.id, sched.cron
                );
                continue;
            }
        };

        let known = last_fired.lock().await.get(&sched.id).copied();
        let prev = match known {
            Some(p) => p,
            // First sighting of this schedule after process start: resume from
            // its most recent persisted run so a restart between two cron
            // instants does not swallow the window. A schedule that has never
            // run resumes from "now" — we do not reach back to its creation
            // date.
            None => {
                let resume = resume_point(core, store, &sched.id).await.unwrap_or(now);
                last_fired.lock().await.insert(sched.id.clone(), resume);
                resume
            }
        };

        let due = match latest_due(&cron_expr, prev, now) {
            Some(t) => t,
            None => continue,
        };
        // Fire once and remember the instant we fired for, so the missed
        // instants between `prev` and `due` are skipped rather than replayed.
        last_fired.lock().await.insert(sched.id.clone(), due);
        log::info!(
            "scheduled-exports: firing schedule {} ({}) for cron instant {}",
            sched.id,
            sched.name,
            due.with_timezone(&Local).to_rfc3339()
        );

        let core_clone = Arc::clone(core);
        let store_clone = store.clone();
        let sched_clone = sched.clone();
        tokio::task::spawn(async move {
            let outcome = run_once(&core_clone, &sched_clone).await;
            let record = match outcome {
                Ok((bytes, dest)) => RunRecord {
                    schedule_id: sched_clone.id.clone(),
                    run_at: Utc::now().to_rfc3339(),
                    status: RunStatus::Success,
                    bytes_written: bytes,
                    destination: dest,
                    error: None,
                },
                Err(e) => RunRecord {
                    schedule_id: sched_clone.id.clone(),
                    run_at: Utc::now().to_rfc3339(),
                    status: RunStatus::Failed,
                    bytes_written: 0,
                    destination: sched_clone.destination.clone(),
                    error: Some(format!("{e}")),
                },
            };
            if let Err(e) = store_clone.append_run(core_clone.barrier.as_storage(), &record).await {
                log::warn!("scheduled-exports: append_run failed: {e}");
            }
            // Cron-fired runs are unattended by definition — there's no
            // bearer token to log against. We emit the audit event with
            // an empty token so the entry is still HMAC-correlatable as
            // "scheduler-driven" (every other field is populated). The
            // schedule id appears in the path so an auditor can group by
            // schedule.
            let mut body = serde_json::Map::new();
            body.insert("schedule_id".into(), serde_json::Value::String(sched_clone.id.clone()));
            body.insert("schedule_name".into(), serde_json::Value::String(sched_clone.name.clone()));
            body.insert("status".into(), serde_json::Value::String(format!("{:?}", record.status).to_lowercase()));
            body.insert("bytes_written".into(), serde_json::Value::Number(record.bytes_written.into()));
            let err_str = record.error.clone();
            crate::audit::emit_sys_audit(
                &core_clone,
                "",
                &format!("sys/scheduled-exports/{}/run", sched_clone.id),
                crate::logical::Operation::Write,
                Some(body),
                err_str.as_deref(),
            )
            .await;
        });
    }
    Ok(())
}

/// The most recent cron instant in `(prev, now]`, or `None` when the schedule
/// is not due yet.
///
/// Cron is evaluated in the server's local timezone (the contract the GUI
/// editor states); the returned instant is converted back to UTC because that
/// is what the runner tracks. Returning only the *latest* due instant is what
/// makes catch-up `single`: a schedule that missed five nights runs once, not
/// five times.
fn latest_due(
    cron: &CronSchedule,
    prev: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let prev_local = prev.with_timezone(&Local);
    let now_local = now.with_timezone(&Local);
    let mut due = None;
    for instant in cron.after(&prev_local).take(MAX_CATCHUP_SCAN) {
        if instant > now_local {
            break;
        }
        due = Some(instant);
    }
    due.map(|t| t.with_timezone(&Utc))
}

/// Timestamp of a schedule's most recent run record, used as the resume point
/// on first sighting after process start. `None` when the schedule has never
/// run or the record is unreadable.
async fn resume_point(
    core: &Arc<Core>,
    store: &ScheduleStore,
    schedule_id: &str,
) -> Option<DateTime<Utc>> {
    let runs = store.list_runs(core.barrier.as_storage(), schedule_id).await.ok()?;
    // `list_runs` sorts newest-first.
    let newest = runs.first()?;
    DateTime::parse_from_rfc3339(&newest.run_at)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// Execute one schedule: build the export bytes, write to the destination,
/// return (bytes_written, destination_used) on success.
pub async fn run_once(
    core: &Arc<Core>,
    sched: &Schedule,
) -> Result<(u64, DestinationKind), RvError> {
    let storage = core.barrier.as_storage();

    // 1. Build the bvx.v1 document.
    let mounts = exchange::scope::MountIndex::from_core(core)?;
    let document = exchange::scope::export_to_document(
        storage,
        &mounts,
        exchange::ExporterInfo::default(),
        sched.scope.clone(),
    )
    .await?;
    let inner_bytes = exchange::canonical::to_canonical_vec(&document)?;

    // 2. Wrap or pass through.
    let bytes = match sched.format {
        ExportFormat::Json => {
            if !sched.allow_plaintext {
                return Err(RvError::ErrRequestInvalid);
            }
            inner_bytes
        }
        ExportFormat::Bvx => {
            let password = resolve_password(storage, sched.password_ref.as_ref()).await?;
            exchange::encrypt_bvx(&inner_bytes, &password, "", sched.comment.clone())?
        }
    };

    // 3. Write to destination.
    match &sched.destination {
        DestinationKind::LocalPath { path } => {
            write_local(path, &sched.id, &sched.format, &bytes)?;
        }
    }

    Ok((bytes.len() as u64, sched.destination.clone()))
}

async fn resolve_password(
    storage: &dyn Storage,
    password_ref: Option<&PasswordRefKind>,
) -> Result<String, RvError> {
    match password_ref {
        None => Err(RvError::ErrRequestInvalid),
        Some(PasswordRefKind::Literal { password }) => Ok(password.clone()),
        Some(PasswordRefKind::StaticSecret { mount, path }) => {
            let mount_norm = if mount.ends_with('/') { mount.clone() } else { format!("{mount}/") };
            let key = format!("{mount_norm}{}", path.trim_start_matches('/'));
            let entry = storage.get(&key).await?.ok_or(RvError::ErrRequestInvalid)?;
            let value: Value = serde_json::from_slice(&entry.value)
                .map_err(|_| RvError::ErrRequestInvalid)?;
            value
                .get("password")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or(RvError::ErrRequestInvalid)
        }
    }
}

fn write_local(dir: &str, schedule_id: &str, format: &ExportFormat, bytes: &[u8]) -> Result<(), RvError> {
    use std::fs;
    use std::io::Write;

    let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let ext = match format {
        ExportFormat::Bvx => "bvx",
        ExportFormat::Json => "json",
    };
    let dir_path = std::path::Path::new(dir);
    fs::create_dir_all(dir_path)
        .map_err(|e| { log::warn!("create_dir_all({dir}) failed: {e}"); RvError::ErrUnknown })?;
    let final_path = dir_path.join(format!("{schedule_id}-{timestamp}.{ext}"));
    let tmp_path = dir_path.join(format!(".{schedule_id}-{timestamp}.{ext}.tmp"));

    {
        let mut f = fs::File::create(&tmp_path)
            .map_err(|e| { log::warn!("File::create({}) failed: {e}", tmp_path.display()); RvError::ErrUnknown })?;
        f.write_all(bytes)
            .map_err(|e| { log::warn!("write failed: {e}"); RvError::ErrUnknown })?;
        f.sync_all().ok();
    }
    fs::rename(&tmp_path, &final_path).map_err(|e| {
        log::warn!("rename failed: {e}");
        let _ = fs::remove_file(&tmp_path);
        RvError::ErrUnknown
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, TimeZone, Timelike};

    /// `0 0 3 * * *` — 03:00 daily, the GUI editor's default.
    fn daily_at_3am() -> CronSchedule {
        CronSchedule::from_str("0 0 3 * * *").expect("valid cron")
    }

    /// A UTC instant for a known local wall-clock time, so assertions hold in
    /// any server timezone.
    fn local(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
        Local
            .with_ymd_and_hms(y, m, d, h, min, 0)
            .single()
            .expect("unambiguous local time")
            .with_timezone(&Utc)
    }

    #[test]
    fn not_due_before_the_next_instant() {
        // Fired at 03:00, asked again at 09:00 the same day: nothing due.
        let prev = local(2026, 7, 20, 3, 0);
        let now = local(2026, 7, 20, 9, 0);
        assert_eq!(latest_due(&daily_at_3am(), prev, now), None);
    }

    #[test]
    fn due_once_the_instant_has_passed() {
        let prev = local(2026, 7, 20, 9, 0);
        let now = local(2026, 7, 21, 3, 0) + ChronoDuration::seconds(20);
        let due = latest_due(&daily_at_3am(), prev, now).expect("due");
        assert_eq!(due, local(2026, 7, 21, 3, 0));
    }

    #[test]
    fn cron_is_evaluated_in_server_local_time() {
        // The schedule promises "03:00 server local time" — the instant it
        // fires for must be 03:00 local, whatever the host's offset is.
        let prev = local(2026, 7, 20, 9, 0);
        let now = local(2026, 7, 22, 12, 0);
        let due = latest_due(&daily_at_3am(), prev, now).expect("due");
        let due_local = due.with_timezone(&Local);
        assert_eq!(due_local.hour(), 3);
        assert_eq!(due_local.minute(), 0);
    }

    #[test]
    fn missed_windows_collapse_to_a_single_run() {
        // The scheduler was down for five nights. Catch-up is `single`: the
        // most recent missed instant is returned, not the oldest, so five
        // nights of downtime produce one backup and not five.
        let prev = local(2026, 7, 16, 3, 0);
        let now = local(2026, 7, 21, 9, 0);
        let due = latest_due(&daily_at_3am(), prev, now).expect("due");
        assert_eq!(due, local(2026, 7, 21, 3, 0));
    }

    #[test]
    fn firing_clears_the_backlog() {
        // Advancing `prev` to the returned instant — what `tick` does — must
        // leave nothing due, otherwise the next tick 30s later fires again.
        let prev = local(2026, 7, 16, 3, 0);
        let now = local(2026, 7, 21, 9, 0);
        let due = latest_due(&daily_at_3am(), prev, now).expect("due");
        assert_eq!(latest_due(&daily_at_3am(), due, now), None);
    }

    #[test]
    fn catchup_scan_is_bounded_and_converges() {
        // A per-second cron with a resume point far in the past must not walk
        // unbounded history in one tick: the scan stops at MAX_CATCHUP_SCAN
        // and the following tick continues from there.
        let every_second = CronSchedule::from_str("* * * * * *").expect("valid cron");
        let now = local(2026, 7, 21, 9, 0);
        let prev = now - ChronoDuration::days(30);
        let due = latest_due(&every_second, prev, now).expect("due");
        assert!(due <= now);
        assert_eq!(due, prev + ChronoDuration::seconds(MAX_CATCHUP_SCAN as i64));
        // Still behind, so the next tick keeps making progress.
        assert!(latest_due(&every_second, due, now).is_some());
    }
}
