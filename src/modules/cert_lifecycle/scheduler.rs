//! Periodic renewal scheduler — Phase L6.
//!
//! Single tokio task started from [`Core::post_unseal`](crate::core::Core)
//! ticks every 30 seconds at the outer loop, enumerates every mount of
//! type `cert-lifecycle`, reads that mount's persisted
//! [`SchedulerConfig`](super::storage::SchedulerConfig), and — when
//! `enabled = true` and the per-mount tick window has elapsed — walks
//! every target on that mount and renews the ones whose
//! `current_not_after - renew_before` window has passed (or which are
//! healing from a backoff).
//!
//! Renewal goes through `Core::handle_request` against
//! `cert-lifecycle/renew/<name>` carrying the operator-supplied
//! `client_token` so the same PKI ACL boundary that gates a manual
//! call applies here. There is no scheduler-side ACL bypass.
//!
//! Backoff: `next_attempt_unix = now + min(max_backoff,
//! base_backoff * 2^(failure_count - 1))` after a failure; on success
//! `next_attempt_unix = current_not_after - renew_before`.
//!
//! Same lifecycle posture as the PKI auto-tidy scheduler:
//! single-process (no HA leader gate yet), self-skip while sealed,
//! detached task running until the process exits.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use humantime::parse_duration;
use serde_json::Map;
use tokio::sync::Mutex;

use super::storage::{self, SchedulerConfig, Target, TargetState, KEY_SCHEDULER_CONFIG};
use crate::{
    core::Core,
    errors::RvError,
    logical::{Operation, Request},
    storage::Storage,
};

const OUTER_TICK_INTERVAL: Duration = Duration::from_secs(30);

/// Spawn the cert-lifecycle scheduler. Returns the JoinHandle for the
/// caller's reference; dropping it does not stop the task.
pub fn start_cert_lifecycle_scheduler(core: Arc<Core>) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn(async move {
        let last_fired: Arc<Mutex<HashMap<String, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
        log::info!(
            "cert-lifecycle: scheduler started (outer tick every {}s)",
            OUTER_TICK_INTERVAL.as_secs(),
        );

        let mut interval = tokio::time::interval(OUTER_TICK_INTERVAL);
        loop {
            interval.tick().await;
            if core.state.load().sealed {
                continue;
            }
            if let Err(e) = tick(&core, last_fired.clone()).await {
                log::warn!("cert-lifecycle: scheduler tick failed: {e}");
            }
        }
    })
}

/// Run a single scheduler pass across every cert-lifecycle mount that
/// has scheduling enabled and whose tick window has elapsed. Exposed
/// publicly so integration tests can drive the scheduler
/// deterministically without waiting 30s for a real tick.
///
/// `last_fired` is shared across calls so the in-memory throttle
/// table survives multiple invocations. Pass `None` for a fresh map
/// (every enabled mount fires this call).
#[maybe_async::maybe_async]
pub async fn run_cert_lifecycle_pass(
    core: &Arc<Core>,
    last_fired: Option<Arc<Mutex<HashMap<String, Instant>>>>,
) -> Result<(), RvError> {
    let map = last_fired.unwrap_or_else(|| Arc::new(Mutex::new(HashMap::new())));
    tick(core, map).await
}

#[maybe_async::maybe_async]
async fn tick(
    core: &Arc<Core>,
    last_fired: Arc<Mutex<HashMap<String, Instant>>>,
) -> Result<(), RvError> {
    let lifecycle_mounts: Vec<(String, String)> = {
        let entries = core.mounts_router.entries.read()?;
        entries
            .values()
            .filter_map(|me| {
                let entry = me.read().ok()?;
                if entry.logical_type == "cert-lifecycle" {
                    Some((entry.uuid.clone(), entry.path.clone()))
                } else {
                    None
                }
            })
            .collect()
    };

    if lifecycle_mounts.is_empty() {
        return Ok(());
    }

    for (uuid, path) in lifecycle_mounts {
        if let Err(e) = run_one_mount(core, &uuid, &path, last_fired.clone()).await {
            log::warn!("cert-lifecycle: mount {path} (uuid {uuid}): tick error: {e}");
        }
    }
    Ok(())
}

#[maybe_async::maybe_async]
async fn run_one_mount(
    core: &Arc<Core>,
    mount_uuid: &str,
    mount_path: &str,
    last_fired: Arc<Mutex<HashMap<String, Instant>>>,
) -> Result<(), RvError> {
    // Resolve the BarrierView for this mount so we can read config +
    // targets + state directly. PKI dispatch goes through the routed
    // path below.
    let view = match core.router.matching_view(mount_path)? {
        Some(v) => v,
        None => return Ok(()),
    };
    let storage_arc: Arc<dyn Storage> = view;

    let mut storage_req = Request::new("");
    storage_req.operation = Operation::Read;
    storage_req.storage = Some(storage_arc);

    let cfg: SchedulerConfig =
        storage::get_json(&storage_req, KEY_SCHEDULER_CONFIG).await?.unwrap_or_default();
    if !cfg.enabled || cfg.client_token.is_empty() {
        return Ok(());
    }
    let interval = Duration::from_secs(cfg.tick_interval_seconds.max(30));

    // Per-mount throttle: respect the configured tick interval even
    // though the outer loop wakes every 30s.
    let should_fire = {
        let mut map = last_fired.lock().await;
        match map.get(mount_uuid).copied() {
            None => {
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

    // Snapshot the target list. New targets added while the loop is
    // running get picked up on the next tick.
    let names = storage_req.storage_list("targets/").await?;
    if names.is_empty() {
        return Ok(());
    }

    let now = unix_now();
    for name in names {
        if let Err(e) =
            consider_target(core, mount_path, &storage_req, &cfg, &name, now).await
        {
            log::warn!(
                "cert-lifecycle: mount {mount_path}: target `{name}`: scheduler error: {e}"
            );
        }
    }
    Ok(())
}

#[maybe_async::maybe_async]
async fn consider_target(
    core: &Arc<Core>,
    mount_path: &str,
    storage_req: &Request,
    cfg: &SchedulerConfig,
    name: &str,
    now: u64,
) -> Result<(), RvError> {
    let target: Target = match storage::get_json(storage_req, &storage::target_storage_key(name))
        .await?
    {
        Some(t) => t,
        None => return Ok(()),
    };
    let state: TargetState =
        storage::get_json(storage_req, &storage::state_storage_key(name)).await?.unwrap_or_default();

    if !is_due(&target, &state, now) {
        return Ok(());
    }

    log::info!(
        "cert-lifecycle: mount {mount_path}: target `{name}` is due (current_not_after={}, failure_count={}); firing renew",
        state.current_not_after_unix, state.failure_count,
    );

    // Dispatch the renew via Core::handle_request so the manual and
    // scheduled paths share one implementation. Path is constructed
    // from the mount's actual path (an operator may have mounted the
    // engine somewhere other than `cert-lifecycle/`).
    let trimmed_mount = mount_path.trim_end_matches('/');
    let mut renew_req =
        Request::new(&format!("{trimmed_mount}/renew/{name}"));
    renew_req.operation = Operation::Write;
    renew_req.client_token = cfg.client_token.clone();
    renew_req.body = Some(Map::new());

    let outcome = core.handle_request(&mut renew_req).await;

    // Re-read state — the renew handler updated the success/error
    // fields. We layer `next_attempt_unix` on top, since that's the
    // scheduler's responsibility (the manual handler doesn't know the
    // backoff config).
    let mut updated: TargetState =
        storage::get_json(storage_req, &storage::state_storage_key(name)).await?.unwrap_or_default();

    match outcome {
        Ok(_) => {
            // Schedule the next natural renewal at NotAfter -
            // renew_before. If the cert lacks a NotAfter (shouldn't
            // happen post-success, but be defensive) fall back to one
            // tick interval from now.
            let renew_before = parse_duration(&target.renew_before).unwrap_or(Duration::from_secs(168 * 3600));
            updated.next_attempt_unix = if updated.current_not_after_unix > 0 {
                let raw = updated.current_not_after_unix
                    - renew_before.as_secs() as i64;
                raw.max(now as i64 + 30) as u64
            } else {
                now + cfg.tick_interval_seconds
            };
        }
        Err(_) => {
            // Renew handler already bumped failure_count + recorded
            // last_error. Apply the exponential backoff cap.
            let exp = (updated.failure_count.saturating_sub(1)).min(20);
            let raw = cfg.base_backoff_seconds.saturating_mul(1u64 << exp);
            let delay = raw.min(cfg.max_backoff_seconds);
            updated.next_attempt_unix = now + delay;
        }
    }
    storage::put_json(storage_req, &storage::state_storage_key(name), &updated).await?;
    Ok(())
}

/// Decide whether a target is due for renewal.
///
/// - If it has never been issued (`current_serial` empty) → due now,
///   subject to backoff.
/// - If `now` is before `next_attempt_unix` → backoff in flight, skip.
/// - If `current_not_after - renew_before <= now` → renewal window open.
fn is_due(target: &Target, state: &TargetState, now: u64) -> bool {
    if state.next_attempt_unix > now {
        return false;
    }
    if state.current_serial.is_empty() {
        return true;
    }
    let renew_before = parse_duration(&target.renew_before).unwrap_or(Duration::from_secs(168 * 3600));
    let renew_at_unix = state.current_not_after_unix - renew_before.as_secs() as i64;
    (now as i64) >= renew_at_unix
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
