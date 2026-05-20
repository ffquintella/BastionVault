//! Phase 9.2 — weekly re-attestation sweep.
//!
//! Walks every enrolled bastion once a week and sends an `attest`
//! envelope. Rustion bumps the authority record's
//! `attestation_renew_at` on acceptance; if the bastion never sees a
//! refresh past that timestamp, future envelopes will be refused
//! with `attestation_expired` (a Rustion-side check the spec calls
//! out, even though the in-memory store doesn't enforce it yet).
//!
//! Same scheduling shape as `rustion::poller::start_poller` —
//! detached `tokio::time::interval` loop. Per-tick failures don't
//! short-circuit the sweep (one offline bastion shouldn't drop
//! everyone else's attestation window).

#![deny(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use crate::core::Core;
use crate::errors::RvError;
use crate::modules::rustion::{enrolment, RustionModule};

/// How often the attestation sweep runs. The spec calls for "weekly";
/// 6 days gives a safety margin against the Rustion-side renew window
/// (also ~weekly) so a single missed tick doesn't expire anyone.
pub const TICK_INTERVAL: Duration = Duration::from_secs(60 * 60 * 24 * 6);

/// Spawn the background attest-timer. Same shape as
/// `rustion::poller::start_poller` — fire-and-forget; tokio detaches
/// when the parent terminates.
pub fn start_attest_timer(core: Arc<Core>) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn(async move {
        log::info!(
            "rustion/attest: started (tick every {}d)",
            TICK_INTERVAL.as_secs() / 86_400
        );
        let mut interval = tokio::time::interval(TICK_INTERVAL);
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            if core.state.load().sealed {
                continue;
            }
            if let Err(e) = tick(&core).await {
                log::warn!("rustion/attest: tick failed: {e}");
            }
        }
    })
}

/// Run one attestation sweep. Exposed for the manual-trigger Tauri
/// command + tests.
pub async fn run_attest_pass(core: &Arc<Core>) -> Result<enrolment::AttestAllResult, RvError> {
    tick(core).await
}

async fn tick(core: &Arc<Core>) -> Result<enrolment::AttestAllResult, RvError> {
    let module = core
        .module_manager
        .get_module::<RustionModule>("rustion")
        .ok_or_else(|| crate::bv_error_string!("rustion module not registered"))?;
    let Some(store) = module.store() else {
        return Ok(enrolment::AttestAllResult {
            attempted: 0,
            succeeded: 0,
            failed: 0,
            results: Vec::new(),
        });
    };
    let Some(master_store) = module.master_store() else {
        return Ok(enrolment::AttestAllResult {
            attempted: 0,
            succeeded: 0,
            failed: 0,
            results: Vec::new(),
        });
    };
    let master = master_store
        .get_or_init_signing_key()
        .await
        .map_err(|e| crate::bv_error_string!(&format!("master signing key: {e}")))?;
    let deployment_id = master_store
        .get_or_init_deployment_id()
        .await
        .unwrap_or_default();
    let operator = super::envelope::OperatorContext {
        vault_user_id: "system".into(),
        vault_user_name: "rustion-attest-timer".into(),
        vault_session_id: String::new(),
        src_ip: "0.0.0.0".into(),
        deployment_id,
    };
    let r = enrolment::attest_all(&store, &master, &operator)
        .await
        .map_err(|e| crate::bv_error_string!(&format!("attest_all: {e}")))?;

    for o in &r.results {
        if let enrolment::AttestOutcome::Ok(ok) = o {
            log::info!(
                "{}: bastion={} correlation={} (timer)",
                super::audit::MASTER_ATTEST,
                ok.bastion_id,
                ok.correlation_id
            );
        }
    }
    log::info!(
        "rustion/attest: pass complete ({}/{} succeeded, {} failed)",
        r.succeeded,
        r.attempted,
        r.failed
    );
    Ok(r)
}
