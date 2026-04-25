//! Single-process tick-loop scheduler.
//!
//! Spawned by `Core::post_unseal_init_scheduled_exports` once the barrier
//! is open. Walks every schedule on a fixed cadence; when `next_after(prev)`
//! is in the past relative to the last-known fire time, the schedule fires
//! once and the new fire time is recorded.
//!
//! The runner deliberately tracks last-fired in-memory only — losing it on
//! restart simply means we re-evaluate from "now" and miss the brief
//! window between previous-fire-and-restart. That's the right tradeoff for
//! a single-process scheduler; HA + leader gating land in a follow-up
//! per `features/scheduled-exports.md` Phase 1 (deferred).

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
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

        let mut last = last_fired.lock().await;
        // First sighting of a schedule after process start: pretend the
        // last fire is "right now" so we don't burst-fire every missed
        // instance from history. (Catch-up policy is a Phase-2 knob.)
        let prev = last.entry(sched.id.clone()).or_insert(now);
        let next = match cron_expr.after(prev).next() {
            Some(t) => t,
            None => continue,
        };
        if next > now {
            continue;
        }
        // Fire and remember.
        *prev = next;
        drop(last);

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
