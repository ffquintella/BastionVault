//! Phase 9.2 — weekly re-attestation sweep.
//!
//! Walks every enrolled bastion once a week and sends an `attest`
//! envelope. Rustion bumps the authority record's
//! `attestation_renew_at` on acceptance; if the bastion never sees a
//! refresh past that timestamp, future envelopes will be refused
//! with `attestation_expired` (a Rustion-side check the spec calls
//! out, even though the in-memory store doesn't enforce it yet).
//!
//! Detached sleep loop: one sweep shortly after unseal, then every
//! `TICK_INTERVAL`, with shorter retries while sealed or after a
//! failure (`next_delay`). Per-tick failures don't short-circuit the
//! sweep (one offline bastion shouldn't drop everyone else's
//! attestation window).

#![deny(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use crate::kernel_api::VaultCtx;
use crate::errors::RvError;
use crate::enrolment;

/// How often the attestation sweep runs. The spec calls for "weekly";
/// 6 days gives a safety margin against the Rustion-side renew window
/// (also ~weekly) so a single missed tick doesn't expire anyone.
pub const TICK_INTERVAL: Duration = Duration::from_secs(60 * 60 * 24 * 6);

/// Delay before the *first* sweep after unseal. The loop used to skip
/// its immediate tick outright, which made the first attestation land
/// at uptime + `TICK_INTERVAL` — unreachable for any process that does
/// not stay up for six days, so the desktop GUI's embedded vault never
/// attested at all and its authority lapsed into
/// `403 attestation_expired` fourteen days after approval. Sweeping at
/// boot instead makes the schedule independent of process lifetime; the
/// short grace lets the mount table and the PKI mount that mints the
/// master keypair settle first, since `start_background` runs inside
/// `post_unseal`.
pub const STARTUP_DELAY: Duration = Duration::from_secs(60);

/// Retry delay while the vault is sealed. Skipping straight to the next
/// `TICK_INTERVAL` spent a whole six-day window on a seal that may have
/// lasted a minute.
pub const SEALED_RETRY: Duration = Duration::from_secs(5 * 60);

/// Retry delay after a sweep that failed, wholly or for one bastion. An
/// unreachable bastion must not have to wait a full interval for its
/// next chance — two consecutive misses is already 12 of Rustion's 14
/// days.
pub const FAILURE_RETRY: Duration = Duration::from_secs(60 * 60);

/// How long to wait before the next sweep, given what this one did.
/// Split out from the loop so the schedule is testable without running
/// a six-day timer.
fn next_delay(sealed: bool, failed: usize) -> Duration {
    if sealed {
        SEALED_RETRY
    } else if failed > 0 {
        FAILURE_RETRY
    } else {
        TICK_INTERVAL
    }
}

/// Spawn the background attest-timer. Same shape as
/// `rustion::poller::start_poller` — fire-and-forget; tokio detaches
/// when the parent terminates.
pub fn start_attest_timer(
    core: Arc<dyn VaultCtx>,
    stores: Arc<super::RustionStores>,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn(async move {
        log::info!(
            "rustion/attest: started (first sweep in {}s, then every {}d)",
            STARTUP_DELAY.as_secs(),
            TICK_INTERVAL.as_secs() / 86_400
        );
        let mut delay = STARTUP_DELAY;
        loop {
            tokio::time::sleep(delay).await;
            if core.sealed() {
                delay = next_delay(true, 0);
                continue;
            }
            delay = match tick(&stores).await {
                Ok(r) => next_delay(false, r.failed),
                Err(e) => {
                    log::warn!("rustion/attest: tick failed: {e}");
                    next_delay(false, 1)
                }
            };
        }
    })
}

/// Run one attestation sweep. Exposed for the manual-trigger Tauri
/// command + tests.
pub async fn run_attest_pass(
    stores: &super::RustionStores,
) -> Result<enrolment::AttestAllResult, RvError> {
    tick(stores).await
}

async fn tick(stores: &super::RustionStores) -> Result<enrolment::AttestAllResult, RvError> {
    let Some(store) = stores.store() else {
        return Ok(enrolment::AttestAllResult {
            attempted: 0,
            succeeded: 0,
            failed: 0,
            results: Vec::new(),
        });
    };
    let Some(master_store) = stores.master() else {
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
    let authority = master_store.authority_name().await?;
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
    let r = enrolment::attest_all(&store, &master, &authority, &operator)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sweep_does_not_wait_a_full_interval() {
        // The regression: a process that lives less than TICK_INTERVAL
        // must still attest. Anything on the order of the tick interval
        // here means the desktop GUI never attests again.
        assert!(STARTUP_DELAY < TICK_INTERVAL);
        assert!(STARTUP_DELAY <= Duration::from_secs(5 * 60));
    }

    #[test]
    fn sealed_retries_soon_not_next_interval() {
        assert_eq!(next_delay(true, 0), SEALED_RETRY);
        assert_eq!(next_delay(true, 3), SEALED_RETRY);
        assert!(SEALED_RETRY < TICK_INTERVAL);
    }

    #[test]
    fn partial_failure_retries_before_the_next_interval() {
        assert_eq!(next_delay(false, 1), FAILURE_RETRY);
        assert!(FAILURE_RETRY < TICK_INTERVAL);
    }

    #[test]
    fn clean_sweep_waits_the_full_interval() {
        assert_eq!(next_delay(false, 0), TICK_INTERVAL);
    }

    #[test]
    fn retry_cadence_fits_inside_rustions_renew_window() {
        // Rustion's ATTESTATION_WINDOW is 14 days. Two consecutive
        // clean intervals (12 days) must still land inside it, and a
        // failing sweep must get several attempts before the deadline.
        assert!(TICK_INTERVAL.as_secs() * 2 < 60 * 60 * 24 * 14);
        assert!(FAILURE_RETRY.as_secs() * 24 <= TICK_INTERVAL.as_secs());
    }
}
