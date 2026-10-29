//! Rate and concurrency limits for MCP brokered sessions
//! (`features/mcp-brokered-sessions.md` §11 "Limits", §3 step 5.9).
//!
//! **In memory and per node.** Nothing here is replicated: in an HA cluster
//! each node enforces its own budget, so a binding whose calls are spread
//! over N nodes can make up to N times the per-minute rate and hold up to N
//! sessions. That is stated rather than hidden; the per-call operator
//! confirmation, not this limiter, is what bounds what an agent can do.
//!
//! Three limits:
//!
//! * session calls per binding per minute (default 6, ceiling 60), a sliding
//!   60-second window. A call counts when it is granted a session; a refused
//!   call does not, so a client that backs off recovers once the window has
//!   moved on;
//! * concurrent sessions per binding: exactly [`PER_BINDING_CONCURRENCY`];
//! * concurrent sessions per node (default 4, ceiling 32).
//!
//! Ceilings are enforced where the values are configured
//! (`mcp.brokered_sessions` in the server config); this module takes any
//! positive values.
//!
//! A granted call holds a [`SessionPermit`]. The permit is released when it is
//! dropped, so the session executor — which runs in its own task, outliving a
//! request the endpoint timed out — keeps the slot exactly as long as the
//! session is open.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    num::NonZeroU32,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::logical::{McpBinding, McpBindingKind};

/// Concurrent sessions one binding may hold. Fixed by the spec (default 1,
/// ceiling 1), so not configurable.
pub const PER_BINDING_CONCURRENCY: usize = 1;

/// The rate window.
pub const RATE_WINDOW: Duration = Duration::from_secs(60);

/// Above this many tracked bindings, an acquisition also sweeps bindings
/// with no recent call and no open session, so the map cannot grow without
/// bound on a long-running node.
const SWEEP_THRESHOLD: usize = 1024;

/// The configurable limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLimits {
    pub rate_per_binding_per_min: NonZeroU32,
    pub max_concurrent: NonZeroU32,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            rate_per_binding_per_min: NonZeroU32::new(6).expect("6 is non-zero"),
            max_concurrent: NonZeroU32::new(4).expect("4 is non-zero"),
        }
    }
}

/// Why a call did not get a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitRefusal {
    /// The binding has used its calls for this window; the oldest leaves it
    /// after `retry_after`.
    RateLimited { retry_after: Duration },
    /// The binding already has a session open.
    BindingBusy,
    /// This node has `max_concurrent` sessions open.
    NodeBusy,
    /// The limiter's state is unusable (a panic while it was held). Refused,
    /// never waved through.
    Unavailable,
}

impl LimitRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::RateLimited { .. } => "mcp_rate_limited",
            Self::BindingBusy | Self::NodeBusy | Self::Unavailable => "mcp_session_busy",
        }
    }
}

impl fmt::Display for LimitRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RateLimited { retry_after } => write!(
                f,
                "mcp_rate_limited: this pairing has used its brokered-session calls for this minute; retry in {}s",
                retry_after.as_secs().max(1)
            ),
            Self::BindingBusy => write!(f, "mcp_session_busy: this pairing already has a brokered session open"),
            Self::NodeBusy => write!(f, "mcp_session_busy: this server is at its brokered-session limit"),
            Self::Unavailable => write!(f, "mcp_session_busy: the session limiter is unavailable"),
        }
    }
}

#[derive(Debug, Default)]
struct BindingState {
    granted: VecDeque<Instant>,
    active: usize,
}

#[derive(Debug, Default)]
struct LimiterState {
    bindings: HashMap<String, BindingState>,
    active_total: usize,
}

impl LimiterState {
    fn prune(state: &mut BindingState, now: Instant) {
        while state.granted.front().is_some_and(|t| now.saturating_duration_since(*t) >= RATE_WINDOW) {
            state.granted.pop_front();
        }
    }

    fn sweep(&mut self, now: Instant) {
        self.bindings.retain(|_, s| {
            Self::prune(s, now);
            s.active > 0 || !s.granted.is_empty()
        });
    }
}

/// One node's limiter. Cheap to clone; clones share state.
#[derive(Debug, Clone, Default)]
pub struct SessionLimiter {
    limits: SessionLimits,
    state: Arc<Mutex<LimiterState>>,
}

/// The key a binding is limited under: its pairing (or app) id, not the
/// token. Re-exchanging for a fresh token therefore does not reset the
/// budget.
pub fn binding_limit_key(binding: &McpBinding) -> String {
    match &binding.kind {
        McpBindingKind::Pairing(id) => format!("pairing:{id}"),
        McpBindingKind::App(name) => format!("app:{name}"),
    }
}

impl SessionLimiter {
    pub fn new(limits: SessionLimits) -> Self {
        Self { limits, state: Arc::new(Mutex::new(LimiterState::default())) }
    }

    pub fn limits(&self) -> SessionLimits {
        self.limits
    }

    /// Ask for a session for `binding_key` now.
    pub fn try_acquire(&self, binding_key: &str) -> Result<SessionPermit, LimitRefusal> {
        self.try_acquire_at(binding_key, Instant::now())
    }

    fn try_acquire_at(&self, binding_key: &str, now: Instant) -> Result<SessionPermit, LimitRefusal> {
        let mut state = self.state.lock().map_err(|_| LimitRefusal::Unavailable)?;
        if state.bindings.len() > SWEEP_THRESHOLD {
            state.sweep(now);
        }
        let rate = self.limits.rate_per_binding_per_min.get() as usize;
        let max_concurrent = self.limits.max_concurrent.get() as usize;
        let active_total = state.active_total;

        let binding = state.bindings.entry(binding_key.to_string()).or_default();
        LimiterState::prune(binding, now);
        if binding.granted.len() >= rate {
            let oldest = *binding.granted.front().expect("len >= rate >= 1");
            return Err(LimitRefusal::RateLimited {
                retry_after: RATE_WINDOW.saturating_sub(now.saturating_duration_since(oldest)),
            });
        }
        if binding.active >= PER_BINDING_CONCURRENCY {
            return Err(LimitRefusal::BindingBusy);
        }
        if active_total >= max_concurrent {
            return Err(LimitRefusal::NodeBusy);
        }
        binding.granted.push_back(now);
        binding.active += 1;
        state.active_total += 1;
        Ok(SessionPermit { state: Arc::clone(&self.state), key: binding_key.to_string() })
    }

    /// Sessions open on this node right now.
    pub fn active_sessions(&self) -> usize {
        self.state.lock().map(|s| s.active_total).unwrap_or(0)
    }
}

/// A granted session slot. Dropping it frees the slot (its rate-window entry
/// stays until the window moves past it).
#[derive(Debug)]
pub struct SessionPermit {
    state: Arc<Mutex<LimiterState>>,
    key: String,
}

impl Drop for SessionPermit {
    fn drop(&mut self) {
        // A poisoned lock means acquisition already refuses everything
        // (`Unavailable`); there is nothing left to release into.
        if let Ok(mut state) = self.state.lock() {
            state.active_total = state.active_total.saturating_sub(1);
            if let Some(b) = state.bindings.get_mut(&self.key) {
                b.active = b.active.saturating_sub(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(rate: u32, max_concurrent: u32) -> SessionLimits {
        SessionLimits {
            rate_per_binding_per_min: NonZeroU32::new(rate).unwrap(),
            max_concurrent: NonZeroU32::new(max_concurrent).unwrap(),
        }
    }

    #[test]
    fn defaults_match_the_spec() {
        let d = SessionLimits::default();
        assert_eq!((d.rate_per_binding_per_min.get(), d.max_concurrent.get()), (6, 4));
        assert_eq!(PER_BINDING_CONCURRENCY, 1);
    }

    #[test]
    fn the_rate_is_a_sliding_minute_per_binding() {
        let limiter = SessionLimiter::new(limits(3, 32));
        let t0 = Instant::now();
        for i in 0..3u64 {
            drop(limiter.try_acquire_at("pairing:a", t0 + Duration::from_secs(i)).unwrap());
        }
        let err = limiter.try_acquire_at("pairing:a", t0 + Duration::from_secs(10)).unwrap_err();
        assert_eq!(err, LimitRefusal::RateLimited { retry_after: Duration::from_secs(50) });
        assert_eq!(err.code(), "mcp_rate_limited");
        // Another binding has its own budget.
        drop(limiter.try_acquire_at("pairing:b", t0 + Duration::from_secs(10)).unwrap());
        // The first call leaves the window at t0+60s.
        assert!(limiter.try_acquire_at("pairing:a", t0 + Duration::from_secs(59)).is_err());
        drop(limiter.try_acquire_at("pairing:a", t0 + Duration::from_secs(60)).unwrap());
        assert!(limiter.try_acquire_at("pairing:a", t0 + Duration::from_secs(60)).is_err());
    }

    #[test]
    fn refused_calls_do_not_consume_the_rate() {
        let limiter = SessionLimiter::new(limits(2, 32));
        let t0 = Instant::now();
        let held = limiter.try_acquire_at("pairing:a", t0).unwrap();
        for i in 1..10u64 {
            assert_eq!(
                limiter.try_acquire_at("pairing:a", t0 + Duration::from_secs(i)).unwrap_err(),
                LimitRefusal::BindingBusy
            );
        }
        drop(held);
        drop(limiter.try_acquire_at("pairing:a", t0 + Duration::from_secs(10)).unwrap());
        let err = limiter.try_acquire_at("pairing:a", t0 + Duration::from_secs(11)).unwrap_err();
        assert!(matches!(err, LimitRefusal::RateLimited { .. }), "two granted calls, then the rate");
    }

    #[test]
    fn one_session_per_binding_until_the_permit_drops() {
        let limiter = SessionLimiter::new(limits(60, 32));
        let permit = limiter.try_acquire("pairing:a").unwrap();
        let err = limiter.try_acquire("pairing:a").unwrap_err();
        assert_eq!((err.clone(), err.code()), (LimitRefusal::BindingBusy, "mcp_session_busy"));
        assert_eq!(limiter.active_sessions(), 1);
        drop(permit);
        assert_eq!(limiter.active_sessions(), 0);
        let _again = limiter.try_acquire("pairing:a").unwrap();
    }

    #[test]
    fn the_node_ceiling_holds_across_bindings() {
        let limiter = SessionLimiter::new(limits(60, 2));
        let a = limiter.try_acquire("pairing:a").unwrap();
        let _b = limiter.try_acquire("pairing:b").unwrap();
        assert_eq!(limiter.try_acquire("pairing:c").unwrap_err(), LimitRefusal::NodeBusy);
        drop(a);
        let _c = limiter.try_acquire("pairing:c").unwrap();
        assert_eq!(limiter.active_sessions(), 2);
    }

    #[test]
    fn a_permit_moved_into_another_task_keeps_the_slot() {
        let limiter = SessionLimiter::new(limits(60, 32));
        let permit = limiter.try_acquire("pairing:a").unwrap();
        let handle = std::thread::spawn(move || {
            let _held = permit;
        });
        handle.join().unwrap();
        assert_eq!(limiter.active_sessions(), 0, "dropped where the executor finished");
    }

    #[test]
    fn idle_bindings_are_swept() {
        let limiter = SessionLimiter::new(limits(60, 32));
        let t0 = Instant::now();
        for i in 0..=SWEEP_THRESHOLD {
            drop(limiter.try_acquire_at(&format!("pairing:{i}"), t0).unwrap());
        }
        drop(limiter.try_acquire_at("pairing:late", t0 + RATE_WINDOW).unwrap());
        assert_eq!(limiter.state.lock().unwrap().bindings.len(), 1);
    }

    #[test]
    fn the_key_is_the_pairing_not_the_token() {
        let binding = |kind| McpBinding {
            policy_namespace: None,
            policy_namespaces: Vec::new(),
            kind,
            catalogue_hash: String::new(),
            tool_allowlist: vec![],
            path_scope: vec![],
            reveal_allowed: false,
            destructive_allowed: false,
            client_name: String::new(),
            client_version: String::new(),
            waived_until: None,
            connect_allowed: true,
            confirm_connect: true,
            operator: None,
        };
        assert_eq!(binding_limit_key(&binding(McpBindingKind::Pairing("abc".into()))), "pairing:abc");
        assert_eq!(binding_limit_key(&binding(McpBindingKind::App("abc".into()))), "app:abc");
    }
}
