//! Barrier-encrypted CRUD over schedules + run records.
//!
//! Layout:
//! ```text
//! core/scheduled_exports/schedules/<id>          — Schedule JSON
//! core/scheduled_exports/runs/<id>/<rfc3339>     — RunRecord JSON
//! ```
//!
//! Run records are append-only and capped at the most recent
//! `MAX_RUNS_PER_SCHEDULE` entries (oldest pruned on insert) so the
//! storage footprint stays bounded. Retention-policy semantics (count /
//! age / GFS) are a Phase-3 deliverable per
//! `features/scheduled-exports.md`; the cap here is just a sanity guard.

use crate::{
    errors::RvError,
    storage::{Storage, StorageEntry},
};

use super::schedule::{RunRecord, Schedule};

pub const STORE_PREFIX: &str = "core/scheduled_exports/";
const SCHEDULES_PREFIX: &str = "core/scheduled_exports/schedules/";
const RUNS_PREFIX: &str = "core/scheduled_exports/runs/";
const MAX_RUNS_PER_SCHEDULE: usize = 100;

/// Stateless helper struct. Storage is passed per-call so the caller can
/// supply the barrier-decrypted view (`core.barrier.as_storage()`) without
/// us holding a long-lived `Arc<dyn Storage>` across the seal/unseal
/// cycle.
#[derive(Default, Clone)]
pub struct ScheduleStore;

impl ScheduleStore {
    pub fn new() -> Self {
        Self
    }

    pub async fn list(&self, storage: &dyn Storage) -> Result<Vec<Schedule>, RvError> {
        let keys = storage.list(SCHEDULES_PREFIX).await?;
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            if let Some(entry) = storage.get(&format!("{SCHEDULES_PREFIX}{k}")).await? {
                if let Ok(sched) = serde_json::from_slice::<Schedule>(&entry.value) {
                    out.push(sched);
                }
            }
        }
        out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(out)
    }

    pub async fn get(&self, storage: &dyn Storage, id: &str) -> Result<Option<Schedule>, RvError> {
        let key = format!("{SCHEDULES_PREFIX}{id}");
        match storage.get(&key).await? {
            None => Ok(None),
            Some(entry) => serde_json::from_slice::<Schedule>(&entry.value)
                .map(Some)
                .map_err(|_| RvError::ErrRequestInvalid),
        }
    }

    pub async fn put(&self, storage: &dyn Storage, sched: &Schedule) -> Result<(), RvError> {
        let key = format!("{SCHEDULES_PREFIX}{}", sched.id);
        let value = serde_json::to_vec(sched)?;
        storage.put(&StorageEntry { key, value }).await
    }

    pub async fn delete(&self, storage: &dyn Storage, id: &str) -> Result<(), RvError> {
        let key = format!("{SCHEDULES_PREFIX}{id}");
        storage.delete(&key).await?;
        let runs_prefix = format!("{RUNS_PREFIX}{id}/");
        if let Ok(run_keys) = storage.list(&runs_prefix).await {
            for k in run_keys {
                let _ = storage.delete(&format!("{runs_prefix}{k}")).await;
            }
        }
        Ok(())
    }

    pub async fn append_run(&self, storage: &dyn Storage, run: &RunRecord) -> Result<(), RvError> {
        let key = format!("{RUNS_PREFIX}{}/{}", run.schedule_id, run.run_at);
        let value = serde_json::to_vec(run)?;
        storage.put(&StorageEntry { key, value }).await?;
        self.prune_runs(storage, &run.schedule_id).await
    }

    pub async fn list_runs(
        &self,
        storage: &dyn Storage,
        schedule_id: &str,
    ) -> Result<Vec<RunRecord>, RvError> {
        let prefix = format!("{RUNS_PREFIX}{schedule_id}/");
        let keys = storage.list(&prefix).await?;
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            if let Some(entry) = storage.get(&format!("{prefix}{k}")).await? {
                if let Ok(rec) = serde_json::from_slice::<RunRecord>(&entry.value) {
                    out.push(rec);
                }
            }
        }
        out.sort_by(|a, b| b.run_at.cmp(&a.run_at));
        Ok(out)
    }

    async fn prune_runs(&self, storage: &dyn Storage, schedule_id: &str) -> Result<(), RvError> {
        let prefix = format!("{RUNS_PREFIX}{schedule_id}/");
        let mut keys = storage.list(&prefix).await?;
        if keys.len() <= MAX_RUNS_PER_SCHEDULE {
            return Ok(());
        }
        keys.sort();
        let drop_count = keys.len() - MAX_RUNS_PER_SCHEDULE;
        for k in keys.iter().take(drop_count) {
            let _ = storage.delete(&format!("{prefix}{k}")).await;
        }
        Ok(())
    }
}
