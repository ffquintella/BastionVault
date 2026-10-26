//! The `revoke_failed` lease state, its retry schedule, the per-lease
//! operation guard and the lease audit events (T62 slice 1,
//! `features/dynamic-secrets.md` § Lease Integration).
//!
//! Kept out of `expiration.rs` so the pieces that decide *what happens* — the
//! backoff schedule, when a lease is exhausted, which event carries which
//! fields — are pure and tested on their own.

use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use serde::{Deserialize, Serialize};

use crate::{
    bv_error_response_status,
    errors::RvError,
    kernel_api::{mcp_events::McpAuditEvent, VaultCtx},
    logical::Request,
    utils::{deserialize_system_time, serialize_system_time},
};

use super::expiration::{MAX_REVOKE_ATTEMPTS, REVOKE_RETRY_SECS};

/// Longest backend error a lease record, listing or audit event carries.
pub(crate) const MAX_REVOKE_ERROR_LEN: usize = 256;

/// Ceiling on the wait between two revoke attempts of one lease.
pub(crate) const MAX_REVOKE_RETRY_DELAY: Duration = Duration::from_secs(60 * 60);

/// What asked for the revoke that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RevokeOrigin {
    /// The lease expired and the sweeper revoked it.
    Expiry,
    /// The reaper retried a lease already in `revoke_failed`.
    Retry,
    /// `sys/revoke/<lease_id>`.
    Operator,
    /// `sys/revoke-prefix/<prefix>`.
    Prefix,
    /// The token that owns the lease was revoked.
    Token,
    /// The issuing mount revoked it early (`OwnedLeaseRevoker`).
    Owner,
}

/// A secret lease whose backend revoke failed: still on record, still owed a
/// revoke. Persisted inside the lease row; rows written before T62 have none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RevokeFailure {
    /// Revokes of this lease that have failed, the first included.
    pub attempts: u32,
    #[serde(serialize_with = "serialize_system_time", deserialize_with = "deserialize_system_time")]
    pub first_failed_at: SystemTime,
    #[serde(serialize_with = "serialize_system_time", deserialize_with = "deserialize_system_time")]
    pub last_failed_at: SystemTime,
    /// When the reaper tries again; ignored once the policy says exhausted.
    #[serde(serialize_with = "serialize_system_time", deserialize_with = "deserialize_system_time")]
    pub next_attempt_at: SystemTime,
    /// The backend's last error, cut to [`MAX_REVOKE_ERROR_LEN`].
    pub last_error: String,
    /// What asked for the first revoke that failed.
    pub origin: RevokeOrigin,
}

/// How often, and how many times, a failed revoke is retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RevokeRetryPolicy {
    /// Failed attempts after which the reaper stops; the lease stays listed.
    pub max_attempts: u32,
    /// Wait after the first failure; doubled after each further one.
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl Default for RevokeRetryPolicy {
    fn default() -> Self {
        Self { max_attempts: MAX_REVOKE_ATTEMPTS, base_delay: REVOKE_RETRY_SECS, max_delay: MAX_REVOKE_RETRY_DELAY }
    }
}

impl RevokeRetryPolicy {
    /// The wait before the next attempt, after `attempts` failures (>= 1):
    /// `base_delay * 2^(attempts - 1)`, capped at `max_delay`.
    pub fn delay_after(&self, attempts: u32) -> Duration {
        let doublings = attempts.saturating_sub(1).min(31);
        self.base_delay.saturating_mul(1u32 << doublings).min(self.max_delay)
    }

    pub fn exhausted(&self, failure: &RevokeFailure) -> bool {
        failure.attempts >= self.max_attempts
    }

    /// The state after one more failed revoke at `now`.
    pub fn record(
        &self,
        previous: Option<&RevokeFailure>,
        origin: RevokeOrigin,
        now: SystemTime,
        error: &RvError,
    ) -> RevokeFailure {
        let attempts = previous.map_or(0, |p| p.attempts).saturating_add(1);
        RevokeFailure {
            attempts,
            first_failed_at: previous.map_or(now, |p| p.first_failed_at),
            last_failed_at: now,
            next_attempt_at: now + self.delay_after(attempts),
            last_error: bounded_error(error),
            origin: previous.map_or(origin, |p| p.origin),
        }
    }
}

/// `error`'s message, cut to [`MAX_REVOKE_ERROR_LEN`] characters with a `…`.
pub(crate) fn bounded_error(error: &RvError) -> String {
    let message = error.to_string();
    if message.chars().count() <= MAX_REVOKE_ERROR_LEN {
        return message;
    }
    let mut cut: String = message.chars().take(MAX_REVOKE_ERROR_LEN).collect();
    cut.push('…');
    cut
}

/// The lease ids a renew or revoke is running on right now.
///
/// Non-blocking on purpose: a second operation on a busy lease is refused with
/// a `409` instead of waiting, so a backend that re-enters the lease manager
/// for the same lease cannot deadlock it, and the loser of a revoke/renew race
/// gets a deterministic error instead of undoing the winner's write.
#[derive(Default)]
pub(crate) struct LeaseLocks {
    busy: RwLock<HashSet<String>>,
}

/// Held for the whole of one renew or revoke; releases the lease on drop.
pub(crate) struct LeaseOpGuard {
    locks: Arc<LeaseLocks>,
    lease_id: String,
}

impl LeaseLocks {
    pub fn try_acquire(self: &Arc<Self>, lease_id: &str) -> Result<LeaseOpGuard, RvError> {
        if !self.busy.write()?.insert(lease_id.to_string()) {
            return Err(lease_busy_error());
        }
        Ok(LeaseOpGuard { locks: self.clone(), lease_id: lease_id.to_string() })
    }
}

impl Drop for LeaseOpGuard {
    fn drop(&mut self) {
        match self.locks.busy.write() {
            Ok(mut busy) => {
                busy.remove(&self.lease_id);
            }
            // Poisoned only by a panic inside insert/remove. The lease then
            // stays busy and every later operation on it gets the 409: loud,
            // not a silent second writer.
            Err(_) => log::error!("lease operation guard poisoned; lease {} stays busy", self.lease_id),
        }
    }
}

/// The deterministic refusal for an operation on a lease another one holds.
pub(crate) fn lease_busy_error() -> RvError {
    bv_error_response_status!(
        409,
        "another renew or revoke of this lease is in progress; nothing was changed, retry once it completes"
    )
}

/// `lease.revoke_failed`: a backend revoke failed and the lease was kept.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct LeaseRevokeFailedEvent {
    pub lease_id: String,
    pub origin: RevokeOrigin,
    pub attempts: u32,
    pub max_attempts: u32,
    /// The reaper has stopped; only an operator clears it now.
    pub exhausted: bool,
    /// RFC 3339; absent once exhausted.
    pub next_attempt_at: Option<String>,
    /// The backend's error, bounded ([`MAX_REVOKE_ERROR_LEN`]).
    pub error: String,
}

impl McpAuditEvent for LeaseRevokeFailedEvent {
    const NAME: &'static str = "lease.revoke_failed";
}

/// `lease.revoked`: a lease left `revoke_failed`, or its issuing mount ended
/// it early. Ordinary expiry and operator revokes are not events: the request
/// audit already records the latter, and the former is the normal lifecycle.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct LeaseRevokedEvent {
    pub lease_id: String,
    pub origin: RevokeOrigin,
    /// Failed attempts before this one succeeded; 0 for a first-time revoke.
    pub failed_attempts: u32,
}

impl McpAuditEvent for LeaseRevokedEvent {
    const NAME: &'static str = "lease.revoked";
}

/// `lease.revoke_failed_cleared`: an operator dropped a `revoke_failed` lease
/// without its backend revoking it (after cleaning up the target by hand).
#[derive(Debug, Clone, Serialize)]
pub(crate) struct LeaseRevokeFailedClearedEvent {
    pub lease_id: String,
    pub attempts: u32,
    pub last_error: String,
}

impl McpAuditEvent for LeaseRevokeFailedClearedEvent {
    const NAME: &'static str = "lease.revoke_failed_cleared";
}

/// RFC 3339, to the second, for an event or a listing.
pub(crate) fn rfc3339(time: SystemTime) -> String {
    humantime::format_rfc3339_seconds(time).to_string()
}

/// Emit a lease event through the kernel's audit-event path (one `security`
/// log line, plus a broker `event` entry when a device is enabled). Returns
/// the broker's error so a caller can fail closed; the sweeper only logs it.
#[maybe_async::maybe_async]
pub(crate) async fn emit_lease_event<E: McpAuditEvent + Sync>(
    ctx: Option<&dyn VaultCtx>,
    event: &E,
    req: Option<&Request>,
) -> Result<(), RvError> {
    match ctx {
        Some(ctx) => crate::kernel_api::mcp_events::emit(ctx, event, req).await,
        // No kernel handle (a bare manager in a unit test): the log line is
        // all there is to write.
        None => {
            let fields = crate::kernel_api::mcp_events::event_fields(event);
            log::info!(target: "security", "{} {}", E::NAME, serde_json::Value::Object(fields));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn backoff_doubles_from_the_base_and_is_capped() {
        let policy = RevokeRetryPolicy::default();
        let delays: Vec<u64> = (1..=6).map(|n| policy.delay_after(n).as_secs()).collect();
        assert_eq!(delays, vec![10, 20, 40, 80, 160, 320]);
        assert_eq!(policy.delay_after(40), MAX_REVOKE_RETRY_DELAY, "a large attempt count must not overflow");
        assert_eq!(policy.max_attempts, 6, "spec default for max_revoke_attempts");
    }

    #[test]
    fn recording_failures_counts_attempts_and_stops_at_the_cap() {
        let policy = RevokeRetryPolicy { max_attempts: 3, ..Default::default() };
        let err = RvError::ErrRouterMountNotFound;

        let first = policy.record(None, RevokeOrigin::Expiry, at(1_000), &err);
        assert_eq!(first.attempts, 1);
        assert_eq!(first.first_failed_at, at(1_000));
        assert_eq!(first.next_attempt_at, at(1_010));
        assert!(!policy.exhausted(&first));

        let second = policy.record(Some(&first), RevokeOrigin::Retry, at(1_010), &err);
        assert_eq!((second.attempts, second.next_attempt_at), (2, at(1_030)));
        assert_eq!(second.first_failed_at, at(1_000), "the first failure is kept");
        assert_eq!(second.origin, RevokeOrigin::Expiry, "the origin is the first failure's");

        let third = policy.record(Some(&second), RevokeOrigin::Retry, at(1_030), &err);
        assert_eq!(third.attempts, 3);
        assert!(policy.exhausted(&third));
    }

    #[test]
    fn a_long_backend_error_is_bounded() {
        let long = RvError::ErrString("x".repeat(MAX_REVOKE_ERROR_LEN * 4));
        let cut = bounded_error(&long);
        assert_eq!(cut.chars().count(), MAX_REVOKE_ERROR_LEN + 1);
        assert!(cut.ends_with('…'));
    }

    #[test]
    fn a_busy_lease_is_refused_until_its_guard_drops() {
        let locks = Arc::new(LeaseLocks::default());
        let guard = locks.try_acquire("kv/a/1").expect("free lease");
        let refused = locks.try_acquire("kv/a/1").err();
        assert!(matches!(refused, Some(RvError::ErrResponseStatus(409, _))), "{refused:?}");
        assert!(locks.try_acquire("kv/a/2").is_ok(), "other leases are independent");
        drop(guard);
        assert!(locks.try_acquire("kv/a/1").is_ok(), "released on drop");
    }

    #[test]
    fn a_revoke_failure_round_trips_through_json() {
        let policy = RevokeRetryPolicy::default();
        let failure = policy.record(None, RevokeOrigin::Owner, at(1_700_000_000), &RvError::ErrUnknown);
        let json = serde_json::to_string(&failure).unwrap();
        assert!(json.contains("\"origin\":\"owner\""), "{json}");
        let back: RevokeFailure = serde_json::from_str(&json).unwrap();
        assert_eq!(back, failure);
    }
}
