//! File Resources periodic re-sync scheduler.
//!
//! Mirrors the LDAP / PKI auto-tidy schedulers: a single tokio task
//! started from [`Core::post_unseal`](crate::core::Core), tick every
//! 60 s, walk every `files`-typed mount, list every file's sync
//! targets, and run a push against each target whose
//! `auto_sync_interval_seconds > 0` AND whose
//! `(now - state.last_attempt_at_unix) >= auto_sync_interval_seconds`
//! AND whose `next_retry_at_unix <= now` (the latter implements
//! exponential backoff after consecutive failures — see
//! [`super::backoff_secs`]).
//!
//! Cluster coordination: deferred. The sync push is idempotent — the
//! same content written twice produces the same final file thanks to
//! the tmp+rename pattern every transport uses. In an HA cluster
//! every node will run its own scheduler and may double-push under
//! load; the second write supersedes the first and the operator pays
//! the bandwidth cost of one extra round-trip per replicated node.
//! Same posture the LDAP and PKI schedulers ship with today; HA
//! leader gating via `hiqlite::dlock` is tracked as a single
//! cross-cutting follow-up alongside both.
//!
//! Manual trigger: `POST /v1/<mount>/sync-tick` runs this same sweep
//! on demand. Operators that disable the internal scheduler (config
//! is read by [`load_files_sync_config`]; `enabled = false` flips the
//! task into "wake every 60 s but skip the sweep") can drive the
//! sweep externally via `cron` + that endpoint.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::{run_sync_tick_for_storage, FilesBackendInner};
#[cfg(test)]
use super::{sync_target_due, FileSyncState};
use crate::{
    core::Core,
    errors::RvError,
    logical::{Operation, Request},
    storage::Storage,
};

/// How often the scheduler wakes. Per-target cadence is driven by
/// each target's `auto_sync_interval_seconds`; the 60 s tick is the
/// worst-case firing jitter.
pub const TICK_INTERVAL: Duration = Duration::from_secs(60);

pub const FILES_SYNC_CONFIG_KEY: &str = "sync/config";

/// Per-mount scheduler config. Persisted at `sync/config` under each
/// `files` mount. Not required — a mount with no record uses defaults
/// (scheduler enabled, cap of 8 concurrent pushes per tick).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesSyncConfig {
    /// Master switch. When false the per-mount sweep is skipped on
    /// every tick — the operator drives via the manual `sync-tick`
    /// endpoint instead.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Max parallel pushes per mount per tick. Bounds the network /
    /// CPU spike when many targets come due simultaneously.
    /// Defaults to 8.
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_pushes: u32,
}

fn default_true() -> bool {
    true
}
fn default_max_concurrent() -> u32 {
    8
}

impl Default for FilesSyncConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_concurrent_pushes: default_max_concurrent(),
        }
    }
}

/// Spawn the files-sync scheduler. Detached task; the loop runs
/// until the process exits and self-skips when sealed.
pub fn start_files_sync_scheduler(core: Arc<Core>) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn(async move {
        let last_fired: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
        log::info!(
            "files/sync: scheduler started (tick every {}s)",
            TICK_INTERVAL.as_secs()
        );

        let mut interval = tokio::time::interval(TICK_INTERVAL);
        loop {
            interval.tick().await;
            if core.state.load().sealed {
                continue;
            }
            // Best-effort serialise overlapping ticks (a slow target
            // can stretch a tick past 60 s). The mutex is per-process
            // — HA leader gating is the cross-cutting follow-up
            // tracked alongside the existing PKI / LDAP schedulers.
            let _guard = last_fired.lock().await;
            let started = Instant::now();
            if let Err(e) = run_tick(&core).await {
                log::warn!("files/sync: tick failed: {e}");
            } else {
                log::debug!(
                    "files/sync: tick completed in {} ms",
                    started.elapsed().as_millis()
                );
            }
        }
    })
}

/// Run one sweep across every `files`-typed mount. Exposed so the
/// `POST /v1/<mount>/sync-tick` admin endpoint and integration tests
/// can drive the same logic without waiting 60 s for the scheduler.
#[maybe_async::maybe_async]
pub async fn run_tick(core: &Arc<Core>) -> Result<(), RvError> {
    let mounts: Vec<(String, String)> = {
        let entries = core.mounts_router.entries.read()?;
        entries
            .values()
            .filter_map(|me| {
                let entry = me.read().ok()?;
                if entry.logical_type == "files" {
                    Some((entry.uuid.clone(), entry.path.clone()))
                } else {
                    None
                }
            })
            .collect()
    };
    for (uuid, path) in mounts {
        if let Err(e) = run_one_mount(core, &uuid, &path).await {
            log::warn!("files/sync: mount {path} (uuid {uuid}): tick error: {e}");
        }
    }
    Ok(())
}

#[maybe_async::maybe_async]
async fn run_one_mount(
    core: &Arc<Core>,
    _uuid: &str,
    mount_path: &str,
) -> Result<(), RvError> {
    let view = match core.router.matching_view(mount_path)? {
        Some(v) => v,
        None => return Ok(()),
    };
    let storage_arc: Arc<dyn Storage> = view;
    let mut req = Request::new("");
    req.operation = Operation::Read;
    req.storage = Some(storage_arc);

    // Per-mount config. Missing record == defaults (scheduler on).
    let cfg: FilesSyncConfig = match req.storage_get(FILES_SYNC_CONFIG_KEY).await? {
        Some(e) => serde_json::from_slice(&e.value).unwrap_or_default(),
        None => FilesSyncConfig::default(),
    };
    if !cfg.enabled {
        return Ok(());
    }

    // Drive the sweep through the shared free function so the
    // scheduler-driven and operator-driven paths behave identically.
    // `max_concurrent_pushes` is currently advisory — the sweep
    // walks targets sequentially since each transport already runs
    // on its own OS thread; the cap will become load-bearing once a
    // future slice parallelises pushes within a tick.
    let _ = cfg.max_concurrent_pushes;
    let inner = FilesBackendInner { core: core.clone() };
    let report = run_sync_tick_for_storage(&inner, &mut req).await?;
    if report.attempted > 0 || report.failed > 0 {
        log::info!(
            "files/sync: mount {mount_path}: attempted={} succeeded={} failed={} skipped={}",
            report.attempted, report.succeeded, report.failed, report.skipped,
        );
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    fn fixed(state: FileSyncState) -> FileSyncState {
        state
    }

    #[test]
    fn target_due_when_never_attempted() {
        assert!(sync_target_due(1000, 60, &FileSyncState::default()));
    }

    #[test]
    fn target_due_when_window_elapsed() {
        let s = fixed(FileSyncState {
            last_attempt_at_unix: 940,
            ..Default::default()
        });
        assert!(sync_target_due(1000, 60, &s));
    }

    #[test]
    fn target_not_due_when_inside_window() {
        let s = fixed(FileSyncState {
            last_attempt_at_unix: 970,
            ..Default::default()
        });
        assert!(!sync_target_due(1000, 60, &s));
    }

    #[test]
    fn target_not_due_when_in_backoff() {
        let s = fixed(FileSyncState {
            last_attempt_at_unix: 940,
            next_retry_at_unix: 1010,
            ..Default::default()
        });
        assert!(!sync_target_due(1000, 60, &s));
    }

    #[test]
    fn target_due_after_backoff_clears() {
        let s = fixed(FileSyncState {
            last_attempt_at_unix: 940,
            next_retry_at_unix: 990,
            ..Default::default()
        });
        assert!(sync_target_due(1000, 60, &s));
    }

    #[test]
    fn config_defaults_enable_with_cap() {
        let c = FilesSyncConfig::default();
        assert!(c.enabled);
        assert!(c.max_concurrent_pushes >= 1);
    }

}
