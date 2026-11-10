//! Operator-set Raft timing for the hiqlite backend (T479, S117; see
//! `features/raft-timeout-tuning.md`).
//!
//! `heartbeat_interval` is also the time-to-live of every `AppendEntries` RPC,
//! so it is the 500 ms behind `Cluster lost quorum` on a lossy link. Only
//! liveness depends on it, never Raft safety. Absent keys keep hiqlite's
//! defaults; every invalid value is a startup error, never a clamp.

use std::collections::HashMap;

use bv_errors::RvError;
use serde_json::Value;

const KEY_HEARTBEAT: &str = "raft_heartbeat_interval_ms";
const KEY_ELECTION_MIN: &str = "raft_election_timeout_min_ms";
const KEY_ELECTION_MAX: &str = "raft_election_timeout_max_ms";
const KEY_ALLOW_AGGRESSIVE: &str = "raft_allow_aggressive_timeouts";

/// Smallest accepted heartbeat.
const MIN_HEARTBEAT_MS: u64 = 100;
/// Largest accepted heartbeat (one minute).
const MAX_HEARTBEAT_MS: u64 = 60_000;
/// Largest accepted election timeout (five minutes).
const MAX_ELECTION_MS: u64 = 300_000;
/// The election minimum must span at least this many heartbeats, so one slow
/// heartbeat cannot start an election.
const MIN_ELECTION_HEARTBEATS: u64 = 3;

/// Floor of the isolated-leader threshold: the value used before T479.
const STALE_ACK_FLOOR_MS: u64 = 3_000;
/// Heartbeats of silence that make a leader "isolated" past the floor.
const STALE_ACK_HEARTBEATS: u64 = 6;

/// The three timings, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RaftTiming {
    pub heartbeat_ms: u64,
    pub election_min_ms: u64,
    pub election_max_ms: u64,
}

impl RaftTiming {
    /// Apply the operator's overrides on top of `defaults` (hiqlite's own
    /// values), validating the result.
    pub(super) fn resolve(conf: &HashMap<String, Value>, defaults: RaftTiming) -> Result<Self, RvError> {
        let allow_aggressive = match conf.get(KEY_ALLOW_AGGRESSIVE) {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(config_error(format!("`{KEY_ALLOW_AGGRESSIVE}` must be true or false"))),
        };

        let timing = RaftTiming {
            heartbeat_ms: read_ms(conf, KEY_HEARTBEAT)?.unwrap_or(defaults.heartbeat_ms),
            election_min_ms: read_ms(conf, KEY_ELECTION_MIN)?.unwrap_or(defaults.election_min_ms),
            election_max_ms: read_ms(conf, KEY_ELECTION_MAX)?.unwrap_or(defaults.election_max_ms),
        };

        if !(MIN_HEARTBEAT_MS..=MAX_HEARTBEAT_MS).contains(&timing.heartbeat_ms) {
            return Err(config_error(format!(
                "`{KEY_HEARTBEAT}` = {} is outside {MIN_HEARTBEAT_MS}..={MAX_HEARTBEAT_MS}",
                timing.heartbeat_ms
            )));
        }
        if timing.election_max_ms > MAX_ELECTION_MS {
            return Err(config_error(format!(
                "`{KEY_ELECTION_MAX}` = {} is above {MAX_ELECTION_MS}",
                timing.election_max_ms
            )));
        }
        let min_election = timing.heartbeat_ms.saturating_mul(MIN_ELECTION_HEARTBEATS);
        if timing.election_min_ms < min_election {
            return Err(config_error(format!(
                "`{KEY_ELECTION_MIN}` = {} must be at least {MIN_ELECTION_HEARTBEATS} x `{KEY_HEARTBEAT}` \
                 ({min_election}); raising the heartbeat means raising the election timeouts explicitly",
                timing.election_min_ms
            )));
        }
        if timing.election_max_ms <= timing.election_min_ms {
            return Err(config_error(format!(
                "`{KEY_ELECTION_MAX}` = {} must be greater than `{KEY_ELECTION_MIN}` = {}",
                timing.election_max_ms, timing.election_min_ms
            )));
        }

        // Shorter than the defaults makes quorum loss more likely, so it takes
        // an explicit, auditable opt-in.
        let below_default =
            timing.heartbeat_ms < defaults.heartbeat_ms || timing.election_min_ms < defaults.election_min_ms;
        if below_default && !allow_aggressive {
            return Err(config_error(format!(
                "timeouts shorter than the defaults (heartbeat {} ms, election minimum {} ms) make \
                 quorum loss more likely; set `{KEY_ALLOW_AGGRESSIVE} = true` to accept that",
                defaults.heartbeat_ms, defaults.election_min_ms
            )));
        }

        Ok(timing)
    }

    /// Age (ms) of a leader's last quorum acknowledgement past which it is
    /// reported unhealthy: never below the historical 3 s, and six heartbeats
    /// once the heartbeat is longer than the default.
    pub(super) fn stale_ack_ms(&self) -> u64 {
        STALE_ACK_FLOOR_MS.max(self.heartbeat_ms.saturating_mul(STALE_ACK_HEARTBEATS))
    }

    /// Whether any of the three differs from `defaults`.
    pub(super) fn differs_from(&self, defaults: RaftTiming) -> bool {
        *self != defaults
    }
}

/// Read an optional millisecond value. A key that is present but is not a
/// non-negative integer is an error, never ignored.
fn read_ms(conf: &HashMap<String, Value>, key: &str) -> Result<Option<u64>, RvError> {
    match conf.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| config_error(format!("`{key}` must be a whole number of milliseconds, got {v}"))),
    }
}

fn config_error(msg: String) -> RvError {
    RvError::ErrString(format!("hiqlite storage: {msg}"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const DEFAULTS: RaftTiming = RaftTiming { heartbeat_ms: 500, election_min_ms: 1500, election_max_ms: 3000 };

    fn conf(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    fn err_text(r: Result<RaftTiming, RvError>) -> String {
        r.expect_err("must be rejected").to_string()
    }

    #[test]
    fn absent_keys_keep_the_defaults_exactly() {
        let t = RaftTiming::resolve(&HashMap::new(), DEFAULTS).unwrap();
        assert_eq!(t, DEFAULTS);
        assert!(!t.differs_from(DEFAULTS));
        assert_eq!(t.stale_ack_ms(), 3_000);
    }

    #[test]
    fn unrelated_keys_do_not_change_the_result() {
        let c = conf(&[("node_id", json!(1)), ("port_raft", json!(8210))]);
        assert_eq!(RaftTiming::resolve(&c, DEFAULTS).unwrap(), DEFAULTS);
    }

    #[test]
    fn a_longer_heartbeat_with_matching_election_timeouts_is_accepted() {
        let c =
            conf(&[(KEY_HEARTBEAT, json!(2000)), (KEY_ELECTION_MIN, json!(6000)), (KEY_ELECTION_MAX, json!(12000))]);
        let t = RaftTiming::resolve(&c, DEFAULTS).unwrap();
        assert_eq!(t, RaftTiming { heartbeat_ms: 2000, election_min_ms: 6000, election_max_ms: 12000 });
        assert!(t.differs_from(DEFAULTS));
    }

    #[test]
    fn raising_only_the_heartbeat_is_refused_with_a_message_naming_the_fix() {
        let c = conf(&[(KEY_HEARTBEAT, json!(2000))]);
        let msg = err_text(RaftTiming::resolve(&c, DEFAULTS));
        assert!(msg.contains(KEY_ELECTION_MIN), "{msg}");
        assert!(msg.contains("explicitly"), "{msg}");
    }

    #[test]
    fn election_max_must_exceed_election_min() {
        let c = conf(&[(KEY_ELECTION_MIN, json!(3000)), (KEY_ELECTION_MAX, json!(3000))]);
        assert!(err_text(RaftTiming::resolve(&c, DEFAULTS)).contains(KEY_ELECTION_MAX));
    }

    #[test]
    fn non_integer_and_non_numeric_values_are_rejected() {
        for bad in [json!("2000"), json!(2000.5), json!(-1), json!(true), json!(null), json!([2000])] {
            let c = conf(&[(KEY_HEARTBEAT, bad.clone())]);
            let msg = err_text(RaftTiming::resolve(&c, DEFAULTS));
            assert!(msg.contains(KEY_HEARTBEAT), "{bad}: {msg}");
        }
    }

    #[test]
    fn out_of_range_values_are_rejected_not_clamped() {
        let zero = conf(&[(KEY_HEARTBEAT, json!(0))]);
        assert!(err_text(RaftTiming::resolve(&zero, DEFAULTS)).contains("outside"));

        let huge = conf(&[(KEY_HEARTBEAT, json!(MAX_HEARTBEAT_MS + 1))]);
        assert!(err_text(RaftTiming::resolve(&huge, DEFAULTS)).contains("outside"));

        let long_election = conf(&[(KEY_ELECTION_MAX, json!(MAX_ELECTION_MS + 1))]);
        assert!(err_text(RaftTiming::resolve(&long_election, DEFAULTS)).contains(KEY_ELECTION_MAX));
    }

    #[test]
    fn election_min_below_three_heartbeats_is_rejected() {
        let c = conf(&[(KEY_ELECTION_MIN, json!(1500)), (KEY_HEARTBEAT, json!(501))]);
        assert!(err_text(RaftTiming::resolve(&c, DEFAULTS)).contains("at least"));
    }

    #[test]
    fn shorter_than_default_needs_the_explicit_opt_in() {
        let c = conf(&[(KEY_HEARTBEAT, json!(250))]);
        assert!(err_text(RaftTiming::resolve(&c, DEFAULTS)).contains(KEY_ALLOW_AGGRESSIVE));

        let allowed = conf(&[(KEY_HEARTBEAT, json!(250)), (KEY_ALLOW_AGGRESSIVE, json!(true))]);
        assert_eq!(RaftTiming::resolve(&allowed, DEFAULTS).unwrap().heartbeat_ms, 250);

        let refused_again = conf(&[(KEY_HEARTBEAT, json!(250)), (KEY_ALLOW_AGGRESSIVE, json!(false))]);
        assert!(RaftTiming::resolve(&refused_again, DEFAULTS).is_err());
    }

    #[test]
    fn the_opt_in_flag_must_be_a_boolean() {
        let c = conf(&[(KEY_ALLOW_AGGRESSIVE, json!("true"))]);
        assert!(err_text(RaftTiming::resolve(&c, DEFAULTS)).contains(KEY_ALLOW_AGGRESSIVE));
    }

    #[test]
    fn stale_ack_threshold_follows_the_heartbeat_and_never_drops_below_the_old_value() {
        let t = |hb: u64| RaftTiming { heartbeat_ms: hb, election_min_ms: hb * 3, election_max_ms: hb * 6 };
        assert_eq!(t(500).stale_ack_ms(), 3_000);
        assert_eq!(t(250).stale_ack_ms(), 3_000);
        assert_eq!(t(1000).stale_ack_ms(), 6_000);
        assert_eq!(t(2000).stale_ack_ms(), 12_000);
    }
}
