//! Health-state machine for the Rustion target registry.
//!
//! The probe layer itself (HTTP/2 client, signed-nonce auth) lands in
//! Phase 2 alongside the rest of the control-plane client. This module
//! ships the **debouncing state machine** that turns a stream of
//! per-target probe outcomes into the `Up | Degraded | Down | Unknown`
//! verdict the dispatcher reads. Pulling it out from the network
//! transport keeps the state-machine unit-testable without standing
//! up a TLS listener.
//!
//! Transitions:
//!
//!   Unknown → Up        on first success
//!   Up      → Degraded  on first failure
//!   Degraded → Down     on third consecutive failure
//!   Degraded → Up       on first success (resets `consecutive_failures`)
//!   Down    → Up        on first success
//!
//! `Degraded` exists so operators see a yellow chip on the very first
//! probe miss (network blip, restart, …) without the dispatcher
//! treating the target as routable. From the dispatcher's POV
//! `Degraded` is equivalent to `Down`; from the GUI's POV the two are
//! distinct so users can spot a transient wobble.

use chrono::{DateTime, Utc};

use super::config::{HealthStatus, RustionTargetHealth};

/// Threshold: this many consecutive failures flips the verdict to
/// `Down`. The spec calls out "three strikes" — `Degraded` covers
/// strikes 1 and 2.
pub const FAILURE_THRESHOLD: u32 = 3;

/// Outcome reported by a single probe attempt.
#[derive(Debug, Clone)]
pub enum ProbeOutcome {
    /// Probe succeeded; carries the body Rustion returned.
    Success {
        latency_ms: u32,
        version: String,
        active_sessions: u64,
    },
    /// Probe failed (network error, non-2xx, body parse failure, …).
    Failure { error: String },
}

/// Apply a probe outcome to a cached `RustionTargetHealth` and return
/// (a) the new record, and (b) whether the status field actually
/// changed (callers emit `rustion.target.health.changed` audit events
/// only on transitions).
pub fn apply_probe(
    prev: &RustionTargetHealth,
    outcome: ProbeOutcome,
    now: DateTime<Utc>,
) -> (RustionTargetHealth, bool) {
    let mut next = prev.clone();
    next.updated_at = now;

    let prev_status = prev.status;
    match outcome {
        ProbeOutcome::Success {
            latency_ms,
            version,
            active_sessions,
        } => {
            next.status = HealthStatus::Up;
            next.last_ok_at = Some(now);
            next.last_error.clear();
            next.consecutive_failures = 0;
            next.version = version;
            next.active_sessions = active_sessions;
            // Cheap EWMA-ish p50: weight new sample at 1/4, prior at
            // 3/4. Avoids carrying a ring buffer on disk for what's
            // ultimately a display value.
            next.latency_ms_p50 = if prev.latency_ms_p50 == 0 {
                latency_ms
            } else {
                ((3 * prev.latency_ms_p50 as u64 + latency_ms as u64) / 4) as u32
            };
        }
        ProbeOutcome::Failure { error } => {
            let strikes = prev.consecutive_failures.saturating_add(1);
            next.consecutive_failures = strikes;
            next.last_error = error;
            next.status = if strikes >= FAILURE_THRESHOLD {
                HealthStatus::Down
            } else {
                HealthStatus::Degraded
            };
            // Leave latency_ms_p50 untouched on failure — the metric
            // tracks successful round trips only.
        }
    }

    let changed = prev_status != next.status;
    (next, changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    #[test]
    fn first_success_promotes_unknown_to_up_with_latency() {
        let prev = RustionTargetHealth::default();
        let (next, changed) = apply_probe(
            &prev,
            ProbeOutcome::Success {
                latency_ms: 12,
                version: "rustion 0.4.2".into(),
                active_sessions: 0,
            },
            at(1_000),
        );
        assert!(changed);
        assert_eq!(next.status, HealthStatus::Up);
        assert_eq!(next.latency_ms_p50, 12);
        assert_eq!(next.consecutive_failures, 0);
        assert_eq!(next.version, "rustion 0.4.2");
        assert_eq!(next.last_ok_at, Some(at(1_000)));
    }

    #[test]
    fn first_failure_lands_on_degraded_not_down() {
        let prev = RustionTargetHealth {
            status: HealthStatus::Up,
            ..Default::default()
        };
        let (next, changed) = apply_probe(
            &prev,
            ProbeOutcome::Failure {
                error: "tcp connect timeout".into(),
            },
            at(2_000),
        );
        assert!(changed);
        assert_eq!(next.status, HealthStatus::Degraded);
        assert_eq!(next.consecutive_failures, 1);
        assert_eq!(next.last_error, "tcp connect timeout");
    }

    #[test]
    fn third_failure_flips_to_down() {
        let mut h = RustionTargetHealth {
            status: HealthStatus::Up,
            ..Default::default()
        };
        for i in 1..=FAILURE_THRESHOLD {
            let (next, _) = apply_probe(
                &h,
                ProbeOutcome::Failure {
                    error: format!("strike {i}"),
                },
                at(3_000 + i as i64),
            );
            h = next;
        }
        assert_eq!(h.status, HealthStatus::Down);
        assert_eq!(h.consecutive_failures, FAILURE_THRESHOLD);
    }

    #[test]
    fn one_success_clears_failures_from_down() {
        let prev = RustionTargetHealth {
            status: HealthStatus::Down,
            consecutive_failures: 5,
            last_error: "old".into(),
            ..Default::default()
        };
        let (next, changed) = apply_probe(
            &prev,
            ProbeOutcome::Success {
                latency_ms: 30,
                version: "rustion 0.4.2".into(),
                active_sessions: 2,
            },
            at(4_000),
        );
        assert!(changed);
        assert_eq!(next.status, HealthStatus::Up);
        assert_eq!(next.consecutive_failures, 0);
        assert!(next.last_error.is_empty());
        assert_eq!(next.active_sessions, 2);
    }

    #[test]
    fn stable_status_reports_no_change() {
        let prev = RustionTargetHealth {
            status: HealthStatus::Up,
            latency_ms_p50: 20,
            ..Default::default()
        };
        let (next, changed) = apply_probe(
            &prev,
            ProbeOutcome::Success {
                latency_ms: 24,
                version: "rustion 0.4.2".into(),
                active_sessions: 1,
            },
            at(5_000),
        );
        assert!(!changed);
        assert_eq!(next.status, HealthStatus::Up);
        // EWMA: (3*20 + 24) / 4 = 21
        assert_eq!(next.latency_ms_p50, 21);
    }
}
