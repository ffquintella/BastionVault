//! 24h recording-fallback poller — Phase 6.4 of
//! `features/rustion-integration.md`.
//!
//! Periodic background task that walks `recordings_pending/<sid>` and,
//! for every pending entry whose `expected_by` is in the past, calls
//! `recordings::pull_recording` to fetch the sidecar from the
//! originating bastion. Successful pulls clear the pending entry.
//!
//! Mirrors the scheduling shape of `rustion::probe::start_pinger` — a
//! detached `tokio::time::interval` loop. The tick interval is the
//! polling cadence (default 1 h); the `expected_by` deadline is the
//! per-session SLA (defaults to session expiry + 5 min, stamped at
//! session-open time).
//!
//! "24h" in the spec name is the *outer* horizon BV will keep trying:
//! pending entries older than `MAX_RETENTION` (24 h past their
//! `expected_by`) are dropped as unrecoverable. SOC tooling can still
//! query the bastion directly using the bastion_id + session_id
//! recorded on the audit chain.

#![deny(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use crate::core::Core;
use crate::errors::RvError;
use crate::modules::rustion::{recordings, RustionModule};

/// How often the poller ticks. 1 h by default — much slower than the
/// 30 s probe pinger because the failure mode this guards against
/// (webhook missed, session already closed) is rare.
pub const TICK_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Hard ceiling on how long BV keeps trying to pull a recording.
/// Past this threshold the pending entry is dropped — the recording
/// is considered unrecoverable via the automated loop. Operators
/// can still pull manually via `POST rustion/recordings/pull`.
pub const MAX_RETENTION: chrono::Duration = chrono::Duration::hours(24);

/// Spawn the background poller. Returns the JoinHandle so the caller
/// can hold it; dropping the handle does not stop the task (tokio
/// detaches when the parent crate-level futures terminate). Same
/// shape as `rustion::probe::start_pinger`.
pub fn start_poller(core: Arc<Core>) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn(async move {
        log::info!(
            "rustion/poller: started (tick every {}s, max retention {}h)",
            TICK_INTERVAL.as_secs(),
            MAX_RETENTION.num_hours()
        );
        let mut interval = tokio::time::interval(TICK_INTERVAL);
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            if core.state.load().sealed {
                continue;
            }
            if let Err(e) = tick(&core).await {
                log::warn!("rustion/poller: tick failed: {e}");
            }
        }
    })
}

/// Run one polling pass. Exposed so tests + admin endpoints can
/// trigger a sweep without waiting for the interval.
pub async fn run_poll_pass(core: &Arc<Core>) -> Result<(), RvError> {
    tick(core).await
}

async fn tick(core: &Arc<Core>) -> Result<(), RvError> {
    let module = core
        .module_manager
        .get_module::<RustionModule>("rustion")
        .ok_or_else(|| crate::bv_error_string!("rustion module not registered"))?;
    let Some(store) = module.store() else {
        return Ok(());
    };
    let Some(recs) = module.recordings_store() else {
        return Ok(());
    };

    let pending = recs.pending_list().await?;
    if pending.is_empty() {
        return Ok(());
    }
    let now = Utc::now();
    let mut attempted = 0usize;
    let mut pulled = 0usize;
    let mut dropped = 0usize;

    for pr in pending {
        // Past the 24h retention horizon → give up.
        if now > pr.expected_by + MAX_RETENTION {
            let _ = recs.pending_remove(&pr.session_id).await;
            dropped += 1;
            log::warn!(
                "rustion/poller: dropping unrecoverable pending recording \
                 session_id={} bastion={} expected_by={} (past {}h horizon)",
                pr.session_id,
                pr.bastion_id,
                pr.expected_by,
                MAX_RETENTION.num_hours()
            );
            continue;
        }
        // Not yet past the per-session SLA → leave it alone.
        if now < pr.expected_by {
            continue;
        }
        attempted += 1;
        match recordings::pull_recording(&store, &recs, &pr.bastion_id, &pr.session_id)
            .await
        {
            Ok(entry) => {
                pulled += 1;
                log::info!(
                    "rustion/poller: pulled session_id={} recording_id={} bastion={}",
                    entry.session_id,
                    entry.recording_id,
                    entry.bastion_id
                );
            }
            Err(e) => {
                log::warn!(
                    "rustion/poller: pull failed for session_id={} bastion={}: {e}",
                    pr.session_id,
                    pr.bastion_id
                );
            }
        }
    }
    if attempted > 0 || dropped > 0 {
        log::info!(
            "rustion/poller: tick complete — attempted={} pulled={} dropped={}",
            attempted,
            pulled,
            dropped
        );
    }
    Ok(())
}
