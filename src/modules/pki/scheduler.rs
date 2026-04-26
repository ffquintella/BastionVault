//! Periodic auto-tidy scheduler — Phase 4.1.
//!
//! A single tokio task started from [`Core::post_unseal`](crate::core::Core)
//! ticks every 30 seconds, enumerates every mount of type `"pki"`, reads
//! that mount's persisted [`AutoTidyConfig`](super::storage::AutoTidyConfig),
//! and fires [`run_tidy_inner`](super::path_tidy::run_tidy_inner) when the
//! mount's interval has elapsed since the last fire.
//!
//! Design choices and why:
//!
//! - **One scheduler, many mounts.** A single task iterates all PKI mounts
//!   each tick. This keeps the lifecycle trivial (no spawn-on-mount /
//!   abort-on-unmount dance) and the tick budget is dominated by storage
//!   reads which are already async-friendly. The 30 s tick is a worst-case
//!   firing-jitter — the actual `run_tidy_inner` call still respects each
//!   mount's `interval_seconds`.
//! - **In-memory last-fire table.** `HashMap<mount_uuid, Instant>` is *not*
//!   persisted: a process restart resets the timer, which means tidy fires
//!   "immediately" on first tick after restart for any enabled mount. That's
//!   the same semantics the existing `scheduled_exports` runner uses, and is
//!   the right safe default for a sweep that's idempotent (re-running it
//!   does nothing if everything is already swept).
//! - **Self-skip on sealed.** `core.state.load().sealed` is checked every
//!   tick. The barrier reads inside `run_tidy_inner` would fail anyway, but
//!   skipping early avoids logging an avalanche of barrier-locked errors
//!   right after a seal.
//! - **Single-process scheduler.** No HA leader gating yet — every node in
//!   a Hiqlite cluster runs its own scheduler. Idempotence saves us from
//!   storage corruption (last writer wins on identical deletes), but we do
//!   pay the cost of N redundant sweeps per tick. HA leader gating tracks as
//!   a Phase 4.2 follow-up alongside the same gap in `scheduled_exports`.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;

use super::{
    path_tidy::run_tidy_inner,
    storage::{self, AutoTidyConfig, KEY_CONFIG_AUTO_TIDY},
};
use crate::{
    core::Core,
    errors::RvError,
    logical::{Operation, Request},
    storage::Storage,
};

const TICK_INTERVAL: Duration = Duration::from_secs(30);

/// Spawn the PKI auto-tidy scheduler. Returns the JoinHandle so the caller
/// can hold it for the process lifetime; dropping the handle does not stop
/// the task (tokio detaches automatically when the handle drops in
/// fire-and-forget mode), matching the existing `scheduled_exports` pattern.
pub fn start_pki_tidy_scheduler(core: Arc<Core>) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn(async move {
        let last_fired: Arc<Mutex<HashMap<String, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
        log::info!("pki/auto-tidy: scheduler started (tick every {}s)", TICK_INTERVAL.as_secs());

        let mut interval = tokio::time::interval(TICK_INTERVAL);
        loop {
            interval.tick().await;
            if core.state.load().sealed {
                continue;
            }
            if let Err(e) = tick(&core, last_fired.clone()).await {
                log::warn!("pki/auto-tidy: tick failed: {e}");
            }
        }
    })
}

/// Run a single tidy pass across every PKI mount that has auto-tidy
/// enabled and whose interval has elapsed. Exposed publicly so:
///
/// 1. integration tests can drive the scheduler deterministically without
///    waiting 30 s for a real tick;
/// 2. an operator (or future `sys/pki/tidy-all` admin endpoint) has a
///    no-wait way to force the same sweep the background scheduler would
///    do on its own.
///
/// Pass `None` for `last_fired` to use a fresh map (every enabled mount
/// fires this call); pass an `Arc<Mutex<HashMap<...>>>` to share state
/// with a longer-lived caller.
#[maybe_async::maybe_async]
pub async fn run_pki_tidy_pass(
    core: &Arc<Core>,
    last_fired: Option<Arc<Mutex<HashMap<String, Instant>>>>,
) -> Result<(), RvError> {
    let map = last_fired.unwrap_or_else(|| Arc::new(Mutex::new(HashMap::new())));
    tick(core, map).await
}

#[maybe_async::maybe_async]
async fn tick(core: &Arc<Core>, last_fired: Arc<Mutex<HashMap<String, Instant>>>) -> Result<(), RvError> {
    // Snapshot the mount table — we drop the read lock immediately so the
    // sweeps below don't hold it across awaits.
    let pki_mounts: Vec<(String, String)> = {
        let entries = core.mounts_router.entries.read()?;
        entries
            .values()
            .filter_map(|me| {
                let entry = me.read().ok()?;
                if entry.logical_type == "pki" {
                    Some((entry.uuid.clone(), entry.path.clone()))
                } else {
                    None
                }
            })
            .collect()
    };

    if pki_mounts.is_empty() {
        return Ok(());
    }

    for (uuid, path) in pki_mounts {
        if let Err(e) = run_one(core, &uuid, &path, last_fired.clone()).await {
            log::warn!("pki/auto-tidy: mount {path} (uuid {uuid}): tick error: {e}");
        }
    }
    Ok(())
}

#[maybe_async::maybe_async]
async fn run_one(
    core: &Arc<Core>,
    mount_uuid: &str,
    mount_path: &str,
    last_fired: Arc<Mutex<HashMap<String, Instant>>>,
) -> Result<(), RvError> {
    // The mount's BarrierView is what `run_tidy_inner` will read from. We
    // resolve it via the router so we don't have to reconstruct the
    // `LOGICAL_BARRIER_PREFIX/<uuid>/` path manually — the router is the
    // single source of truth for live mount routing.
    let view = match core.router.matching_view(mount_path)? {
        Some(v) => v,
        None => return Ok(()),
    };
    let storage_arc: Arc<dyn Storage> = view;

    // Build a synthetic Request whose storage is the mount's barrier view.
    // The handler only consumes the storage methods, not auth or path
    // matching, so a minimal Request is enough.
    let mut req = Request::new("");
    req.operation = Operation::Write;
    req.storage = Some(storage_arc);

    let cfg: AutoTidyConfig = storage::get_json(&req, KEY_CONFIG_AUTO_TIDY).await?.unwrap_or_default();
    if !cfg.enabled {
        return Ok(());
    }

    let interval = Duration::from_secs(cfg.interval_seconds.max(60));

    // Decide whether enough time has elapsed since this mount last fired.
    let should_fire = {
        let mut map = last_fired.lock().await;
        match map.get(mount_uuid).copied() {
            None => {
                // First sighting after process start — fire immediately so a
                // freshly restarted node does not silently skip a window.
                map.insert(mount_uuid.to_string(), Instant::now());
                true
            }
            Some(last) if last.elapsed() >= interval => {
                map.insert(mount_uuid.to_string(), Instant::now());
                true
            }
            _ => false,
        }
    };

    if !should_fire {
        return Ok(());
    }

    log::info!(
        "pki/auto-tidy: firing on mount {mount_path} (interval={}s, safety_buffer={}s)",
        cfg.interval_seconds, cfg.safety_buffer_seconds,
    );
    let summary = run_tidy_inner(
        &req,
        cfg.tidy_cert_store,
        cfg.tidy_revoked_certs,
        cfg.safety_buffer_seconds,
        "auto",
    )
    .await?;
    log::info!(
        "pki/auto-tidy: mount {mount_path} swept: certs_deleted={} revoked_entries_deleted={} duration_ms={}",
        summary.certs_deleted, summary.revoked_entries_deleted, summary.last_run_duration_ms,
    );
    Ok(())
}
