//! `HsmPool` — one node's view of the pool devices (T454 phase 2).
//!
//! Members are ordered by `SHA-256(node_id ‖ hsm_id)` unless one sets `prefer`.
//! Reads fail over on transport, session and device errors, never on a
//! cryptographic one (AAD, authorization, MAC), which is a security event.
//! Writes wrap on every usable member at once and need `min_wrap_copies`.
//! Spec: `features/hsm-pool-ha.md` § Member selection and failover.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use bv_metrics::hsm_metrics::{hsm_metrics, SessionErrorKind};
use rand::Rng;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    errors::RvError,
    hsm::{
        blob::{BvHsmBlob, Context, HsmId},
        clock::Clock,
        HsmBackend, HsmObjectId,
    },
};

/// How often each member is probed with `device-info`.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(10);
/// Members one pool can hold: the two devices, plus a replacement while it
/// is joining and until the failed device is retired (spec § Replace).
pub const MAX_LIVE_MEMBERS: usize = 3;
/// Consecutive transport or session failures that open a member's breaker.
pub const BREAKER_THRESHOLD: u32 = 3;
pub const BREAKER_BACKOFF_MIN: Duration = Duration::from_secs(1);
pub const BREAKER_BACKOFF_MAX: Duration = Duration::from_secs(60);
pub const SESSIONS_FULL_BACKOFF_MIN: Duration = Duration::from_millis(100);
pub const SESSIONS_FULL_BACKOFF_MAX: Duration = Duration::from_secs(5);

/// How a member failure is treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// Device or link unreachable, or the session failed: counts towards the
    /// breaker, fails over.
    Transport,
    /// `SESSIONS_FULL`: jittered backoff on that member, fails over.
    SessionsFull,
    /// Any other device error: fails over, does not open the breaker.
    Device,
    /// AAD, authorization or MAC mismatch: stops, raises `hsm.crypto_failure`.
    Crypto,
}

/// The single place that decides whether an error may be failed over.
pub fn classify(err: &RvError) -> FailureClass {
    match err {
        RvError::ErrHsmContextMismatch | RvError::ErrHsmAuthzInvalid | RvError::ErrHsmBlobInvalid => {
            FailureClass::Crypto
        }
        RvError::ErrHsmSessionsFull => FailureClass::SessionsFull,
        RvError::ErrHsmTransport(_) => FailureClass::Transport,
        _ => FailureClass::Device,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolEventKind {
    MemberDown,
    MemberUp,
    MemberFaulted,
    CryptoFailure,
    SetUnderReplicated,
    SetRepaired,
    NodeEnrolled,
    NodeRevoked,
    RevocationPending,
    MemberAdded,
    MemberRetired,
    MemberPromoted,
    EpochRotated,
    RecoveryCeremony,
    /// One drained device-log entry (T454 phase 6).
    DeviceLog,
    /// An index jump, chain break, reset or unlogged events in a device log.
    DeviceLogGap,
}

impl PoolEventKind {
    /// Audit event name (spec § Audit).
    pub fn name(&self) -> &'static str {
        match self {
            PoolEventKind::MemberDown => "hsm.member_down",
            PoolEventKind::MemberUp => "hsm.member_up",
            PoolEventKind::MemberFaulted => "hsm.member_faulted",
            PoolEventKind::CryptoFailure => "hsm.crypto_failure",
            PoolEventKind::SetUnderReplicated => "hsm.set_under_replicated",
            PoolEventKind::SetRepaired => "hsm.set_repaired",
            PoolEventKind::NodeEnrolled => "hsm.node_enrolled",
            PoolEventKind::NodeRevoked => "hsm.node_revoked",
            PoolEventKind::RevocationPending => "hsm.revocation_pending",
            PoolEventKind::MemberAdded => "hsm.member_added",
            PoolEventKind::MemberRetired => "hsm.member_retired",
            PoolEventKind::MemberPromoted => "hsm.member_promoted",
            PoolEventKind::EpochRotated => "hsm.epoch_rotated",
            PoolEventKind::RecoveryCeremony => "hsm.recovery_ceremony",
            PoolEventKind::DeviceLog => "hsm.device_log",
            PoolEventKind::DeviceLogGap => "hsm.device_log_gap",
        }
    }
}

/// A pool event. Carries names, ids and error text only; never key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolEvent {
    pub kind: PoolEventKind,
    /// Member name; empty for a set-level event.
    pub member: String,
    /// The member's id, or the missing members' ids for a set-level event.
    pub hsm_id: String,
    pub detail: String,
}

/// Where pool events go. The audit broker is not up before unseal, so the
/// default is the `security` log; phase 6 adds an audit-broker sink.
pub trait PoolEventSink: Send + Sync {
    fn emit(&self, event: &PoolEvent);
}

#[derive(Default)]
pub struct LogEventSink;

impl PoolEventSink for LogEventSink {
    fn emit(&self, e: &PoolEvent) {
        let (name, member, hsm_id, detail) = (e.kind.name(), &e.member, &e.hsm_id, &e.detail);
        match e.kind {
            PoolEventKind::MemberUp
            | PoolEventKind::SetRepaired
            | PoolEventKind::NodeEnrolled
            | PoolEventKind::MemberAdded
            | PoolEventKind::MemberPromoted
            | PoolEventKind::EpochRotated => {
                log::info!(target: "security", "{name}: member={member} hsm_id={hsm_id} {detail}")
            }
            PoolEventKind::NodeRevoked
            | PoolEventKind::MemberRetired
            | PoolEventKind::RevocationPending
            | PoolEventKind::RecoveryCeremony => {
                log::warn!(target: "security", "{name}: member={member} hsm_id={hsm_id} {detail}")
            }
            PoolEventKind::SetUnderReplicated => {
                log::warn!(target: "security", "{name}: {detail} has no copy on {hsm_id}")
            }
            // One per device command: the audit device is its record, the
            // security log only at debug.
            PoolEventKind::DeviceLog => {
                log::debug!(target: "security", "{name}: member={member} hsm_id={hsm_id} {detail}")
            }
            _ => log::error!(target: "security", "{name}: member={member} hsm_id={hsm_id} {detail}"),
        }
    }
}

/// One member as the pool is built: id from the seal record (or the config at
/// bootstrap), and this node's client for it or why it could not be opened.
pub struct PoolMemberSpec {
    pub name: String,
    pub hsm_id: HsmId,
    pub prefer: bool,
    pub device: Result<Arc<dyn HsmBackend>, String>,
}

#[derive(Debug, Default)]
struct Health {
    consecutive_failures: u32,
    down: bool,
    /// Wrong device behind the path: stays unusable until an operator acts.
    faulted: Option<String>,
    breaker_backoff: Duration,
    retry_at: Duration,
    sessions_full_backoff: Duration,
    sessions_full_until: Duration,
    last_error: Option<String>,
    /// Wall time of the last command that succeeded (status `latency_ms`).
    last_latency: Option<Duration>,
}

pub struct PoolMember {
    name: String,
    hsm_id: HsmId,
    prefer: bool,
    device: Result<Arc<dyn HsmBackend>, String>,
    health: Mutex<Health>,
}

impl PoolMember {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn hsm_id(&self) -> &HsmId {
        &self.hsm_id
    }

    pub fn backend(&self) -> Result<&Arc<dyn HsmBackend>, RvError> {
        self.device.as_ref().map_err(|e| RvError::ErrHsmTransport(e.clone()))
    }

    fn label(&self) -> String {
        format!("{} ({})", self.name, self.hsm_id)
    }

    fn health(&self) -> MutexGuard<'_, Health> {
        // Health is bookkeeping; a panic elsewhere must not wedge failover.
        self.health.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// `Err(reason)` when operations must skip this member right now.
    fn usable(&self, now: Duration) -> Result<(), String> {
        if let Err(e) = &self.device {
            return Err(format!("unavailable: {e}"));
        }
        let h = self.health();
        if let Some(reason) = &h.faulted {
            return Err(format!("faulted: {reason}"));
        }
        if h.down && now < h.retry_at {
            let last = h.last_error.as_deref().unwrap_or("-");
            return Err(format!(
                "down (circuit open, next try in {} ms; last error: {last})",
                (h.retry_at - now).as_millis()
            ));
        }
        if now < h.sessions_full_until {
            return Err(format!("SESSIONS_FULL, backing off for {} ms", (h.sessions_full_until - now).as_millis()));
        }
        Ok(())
    }

    fn is_up(&self) -> bool {
        let h = self.health();
        self.device.is_ok() && h.faulted.is_none() && !h.down
    }
}

/// Operator-facing state of one member. No secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemberStatus {
    pub name: String,
    pub hsm_id: String,
    pub serial: String,
    pub up: bool,
    pub faulted: bool,
    pub prefer: bool,
    pub last_error: Option<String>,
    /// Wall time of the last successful command on this node, in ms.
    pub latency_ms: Option<u64>,
}

/// What a pool-wide wrap produced.
#[derive(Debug)]
pub struct WrapOutcome {
    pub copies: BTreeMap<HsmId, BvHsmBlob>,
    /// Members that produced no copy; non-empty means under-replicated.
    pub missing: Vec<HsmId>,
}

pub struct HsmPool {
    node_id: String,
    /// In this node's preference order.
    members: Vec<PoolMember>,
    min_wrap_copies: usize,
    clock: Arc<dyn Clock>,
    events: Arc<dyn PoolEventSink>,
}

fn preference_key(node_id: &str, hsm_id: &HsmId) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(node_id.as_bytes());
    h.update(hsm_id.as_str().as_bytes());
    h.finalize().into()
}

/// `backoff` jittered into `[backoff / 2, backoff]`, so nodes refused at the
/// same moment do not retry in lockstep. Not security-relevant randomness.
fn jittered(backoff: Duration) -> Duration {
    let half = backoff / 2;
    let span = u64::try_from(half.as_millis()).unwrap_or(u64::MAX).saturating_add(1);
    let mut raw = [0u8; 8];
    rand::rng().fill_bytes(&mut raw);
    half + Duration::from_millis(u64::from_le_bytes(raw) % span)
}

fn metric_kind(class: FailureClass) -> SessionErrorKind {
    match class {
        FailureClass::Transport => SessionErrorKind::Transport,
        FailureClass::SessionsFull => SessionErrorKind::SessionsFull,
        FailureClass::Device => SessionErrorKind::Device,
        FailureClass::Crypto => SessionErrorKind::Crypto,
    }
}

impl HsmPool {
    /// Build the pool. A device whose own id is not `hsm_id` is faulted, not
    /// trusted: the record (or bootstrap config) says which device it must be.
    pub fn new(
        node_id: &str,
        specs: Vec<PoolMemberSpec>,
        min_wrap_copies: usize,
        clock: Arc<dyn Clock>,
        events: Arc<dyn PoolEventSink>,
    ) -> Result<Self, RvError> {
        let invalid = |why: String| RvError::ErrHsmConfigInvalid(format!("HSM pool: {why}"));
        if specs.is_empty() || specs.len() > MAX_LIVE_MEMBERS {
            return Err(invalid(format!("{} members; a pool has 1 to {MAX_LIVE_MEMBERS}", specs.len())));
        }
        let names: BTreeSet<&str> = specs.iter().map(|s| s.name.as_str()).collect();
        let ids: BTreeSet<&HsmId> = specs.iter().map(|s| &s.hsm_id).collect();
        if names.len() != specs.len() || ids.len() != specs.len() {
            return Err(invalid("member names and devices must be unique".into()));
        }
        if specs.iter().filter(|s| s.prefer).count() > 1 {
            return Err(invalid("at most one member may be preferred".into()));
        }
        if min_wrap_copies == 0 || min_wrap_copies > specs.len() {
            return Err(invalid(format!("min_wrap_copies {min_wrap_copies} with {} members", specs.len())));
        }

        let mut faulted = Vec::new();
        let mut members: Vec<PoolMember> = specs
            .into_iter()
            .map(|spec| {
                let mut health = Health::default();
                if let Ok(device) = &spec.device {
                    match device.hsm_id() {
                        Ok(actual) if actual == spec.hsm_id => {}
                        Ok(actual) => {
                            health.faulted = Some(format!("the device here is {actual}, not {}", spec.hsm_id))
                        }
                        Err(e) => health.faulted = Some(format!("the device identity is unreadable: {e}")),
                    }
                }
                if let Some(reason) = &health.faulted {
                    health.last_error = Some(reason.clone());
                    faulted.push((spec.name.clone(), spec.hsm_id.clone(), reason.clone()));
                }
                PoolMember {
                    name: spec.name,
                    hsm_id: spec.hsm_id,
                    prefer: spec.prefer,
                    device: spec.device,
                    health: Mutex::new(health),
                }
            })
            .collect();
        members.sort_by_cached_key(|m| (!m.prefer, preference_key(node_id, &m.hsm_id)));

        let pool = Self { node_id: node_id.to_string(), members, min_wrap_copies, clock, events };
        for m in &pool.members {
            if let Err(e) = &m.device {
                log::error!(target: "security", "hsm pool member {} is unavailable on this node: {e}", m.label());
            }
            hsm_metrics().set_member_up(&m.name, m.is_up());
        }
        for (member, hsm_id, reason) in faulted {
            pool.emit(PoolEventKind::MemberFaulted, &member, hsm_id.as_str(), &reason);
        }
        Ok(pool)
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn min_wrap_copies(&self) -> usize {
        self.min_wrap_copies
    }

    /// Members in this node's preference order.
    pub fn members(&self) -> &[PoolMember] {
        &self.members
    }

    pub fn member(&self, hsm_id: &HsmId) -> Option<&PoolMember> {
        self.members.iter().find(|m| &m.hsm_id == hsm_id)
    }

    /// The members a set must have a copy for to be fully replicated.
    pub fn active_ids(&self) -> BTreeSet<HsmId> {
        self.members.iter().map(|m| m.hsm_id.clone()).collect()
    }

    fn emit(&self, kind: PoolEventKind, member: &str, hsm_id: &str, detail: &str) {
        self.events.emit(&PoolEvent {
            kind,
            member: member.to_string(),
            hsm_id: hsm_id.to_string(),
            detail: detail.to_string(),
        });
    }

    /// Raise `hsm.set_under_replicated` for `what` when `missing` is not empty.
    pub fn report_under_replicated(&self, what: &str, missing: &[HsmId]) {
        if !missing.is_empty() {
            let ids: Vec<&str> = missing.iter().map(HsmId::as_str).collect();
            self.emit(PoolEventKind::SetUnderReplicated, "", &ids.join(","), what);
        }
    }

    /// Start a read over the members `holds` a copy for, in preference order.
    pub fn read<'p>(&'p self, holds: impl Fn(&HsmId) -> bool) -> ReadAttempt<'p> {
        let mut failures = Vec::new();
        let mut order = Vec::new();
        for m in &self.members {
            if holds(&m.hsm_id) {
                order.push(m);
            } else {
                failures.push(format!("{}: holds no copy", m.label()));
            }
        }
        ReadAttempt { pool: self, order: order.into_iter(), failures, started: Duration::ZERO }
    }

    /// `bv_hsm_command_duration_seconds{member,op}` for a command that
    /// started at `started` (this pool's clock), and the member's latency
    /// when it succeeded.
    fn observe(&self, m: &PoolMember, op: &str, started: Duration, ok: bool) {
        let took = self.clock.now().saturating_sub(started);
        hsm_metrics().observe_command(&m.name, op, took.as_secs_f64());
        if ok {
            m.health().last_latency = Some(took);
        }
    }

    fn record_success(&self, m: &PoolMember, reset_sessions_full: bool) {
        let mut h = m.health();
        let was_down = h.down;
        h.consecutive_failures = 0;
        h.down = false;
        h.breaker_backoff = Duration::ZERO;
        if reset_sessions_full {
            h.sessions_full_backoff = Duration::ZERO;
            h.sessions_full_until = Duration::ZERO;
        }
        drop(h);
        if was_down {
            hsm_metrics().set_member_up(&m.name, true);
            self.emit(PoolEventKind::MemberUp, &m.name, m.hsm_id.as_str(), "member answers again");
        }
    }

    /// Book a failure on `m` and return how it must be treated.
    fn record_failure(&self, m: &PoolMember, op: &str, err: &RvError) -> FailureClass {
        let class = classify(err);
        let now = self.clock.now();
        hsm_metrics().record_session_error(&m.name, metric_kind(class));
        let mut h = m.health();
        h.last_error = Some(format!("{op}: {err}"));
        let mut went_down = false;
        match class {
            FailureClass::Transport => {
                h.consecutive_failures = h.consecutive_failures.saturating_add(1);
                if h.down {
                    h.breaker_backoff = (h.breaker_backoff * 2).clamp(BREAKER_BACKOFF_MIN, BREAKER_BACKOFF_MAX);
                    h.retry_at = now + h.breaker_backoff;
                } else if h.consecutive_failures >= BREAKER_THRESHOLD {
                    h.down = true;
                    h.breaker_backoff = BREAKER_BACKOFF_MIN;
                    h.retry_at = now + BREAKER_BACKOFF_MIN;
                    went_down = true;
                }
            }
            FailureClass::SessionsFull => {
                h.sessions_full_backoff = if h.sessions_full_backoff.is_zero() {
                    SESSIONS_FULL_BACKOFF_MIN
                } else {
                    (h.sessions_full_backoff * 2).min(SESSIONS_FULL_BACKOFF_MAX)
                };
                h.sessions_full_until = now + jittered(h.sessions_full_backoff);
            }
            FailureClass::Device | FailureClass::Crypto => {}
        }
        drop(h);
        match class {
            FailureClass::Crypto => {
                self.emit(PoolEventKind::CryptoFailure, &m.name, m.hsm_id.as_str(), &format!("{op}: {err}"))
            }
            FailureClass::SessionsFull => log::warn!(
                target: "security",
                "hsm pool member {} returned SESSIONS_FULL on {op}; backing off and trying the other member",
                m.label()
            ),
            _ => log::warn!(target: "security", "hsm pool member {} failed {op}: {err}", m.label()),
        }
        if went_down {
            hsm_metrics().set_member_up(&m.name, false);
            self.emit(PoolEventKind::MemberDown, &m.name, m.hsm_id.as_str(), &format!("{op}: {err}"));
        }
        class
    }

    fn fault(&self, m: &PoolMember, reason: String) {
        let first = {
            let mut h = m.health();
            let first = h.faulted.is_none();
            h.faulted = Some(reason.clone());
            h.last_error = Some(reason.clone());
            first
        };
        hsm_metrics().set_member_up(&m.name, false);
        if first {
            self.emit(PoolEventKind::MemberFaulted, &m.name, m.hsm_id.as_str(), &reason);
        }
    }

    /// Wrap `plaintext` under `key` on every usable member at once. Needs
    /// [`Self::min_wrap_copies`] copies; fewer is `ErrHsmInsufficientCopies`.
    #[maybe_async::maybe_async]
    pub async fn wrap_all(&self, key: HsmObjectId, ctx: &Context, plaintext: &[u8]) -> Result<WrapOutcome, RvError> {
        self.wrap_with_minimum(key, ctx, plaintext, self.min_wrap_copies).await
    }

    /// [`Self::wrap_all`] requiring a copy on every member (pool init).
    #[maybe_async::maybe_async]
    pub async fn wrap_on_every_member(
        &self,
        key: HsmObjectId,
        ctx: &Context,
        plaintext: &[u8],
    ) -> Result<WrapOutcome, RvError> {
        self.wrap_with_minimum(key, ctx, plaintext, self.members.len()).await
    }

    #[maybe_async::maybe_async]
    async fn wrap_with_minimum(
        &self,
        key: HsmObjectId,
        ctx: &Context,
        plaintext: &[u8],
        need: usize,
    ) -> Result<WrapOutcome, RvError> {
        let now = self.clock.now();
        let mut targets = Vec::new();
        let mut unreachable = Vec::new();
        let mut missing = Vec::new();
        for m in &self.members {
            match m.usable(now) {
                Ok(()) => targets.push(m),
                Err(why) => {
                    unreachable.push(format!("{}: {why}", m.label()));
                    missing.push(m.hsm_id.clone());
                }
            }
        }

        #[cfg(not(feature = "sync_handler"))]
        let results = join_all(targets.iter().map(|m| self.wrap_one(m, key, ctx, plaintext)).collect()).await;
        #[cfg(feature = "sync_handler")]
        let results: Vec<Result<BvHsmBlob, RvError>> =
            targets.iter().map(|m| self.wrap_one(m, key, ctx, plaintext)).collect();

        let mut copies = BTreeMap::new();
        for (m, result) in targets.into_iter().zip(results) {
            match result {
                Ok(blob) => {
                    self.record_success(m, true);
                    copies.insert(m.hsm_id.clone(), blob);
                }
                Err(e) => {
                    if self.record_failure(m, "wrap", &e) == FailureClass::Crypto {
                        return Err(e);
                    }
                    unreachable.push(format!("{}: wrap: {e}", m.label()));
                    missing.push(m.hsm_id.clone());
                }
            }
        }
        if copies.len() < need {
            log::error!(
                target: "security",
                "hsm pool wrap refused: {} of {need} required copies; unreachable: {}",
                copies.len(),
                unreachable.join("; ")
            );
            return Err(RvError::ErrHsmInsufficientCopies { have: copies.len(), need, unreachable });
        }
        Ok(WrapOutcome { copies, missing })
    }

    /// Wrap on one member (repair). A member that is unusable right now, or
    /// that answers with a copy bound to another device, is an error.
    #[maybe_async::maybe_async]
    pub async fn wrap_on(
        &self,
        hsm_id: &HsmId,
        key: HsmObjectId,
        ctx: &Context,
        plaintext: &[u8],
    ) -> Result<BvHsmBlob, RvError> {
        let m = self.member(hsm_id).ok_or_else(|| RvError::ErrHsm(format!("{hsm_id} is not in this pool")))?;
        m.usable(self.clock.now()).map_err(|why| RvError::ErrHsmTransport(format!("{}: {why}", m.label())))?;
        match self.wrap_one(m, key, ctx, plaintext).await {
            Ok(blob) => {
                self.record_success(m, true);
                Ok(blob)
            }
            Err(e) => {
                self.record_failure(m, "wrap", &e);
                Err(e)
            }
        }
    }

    /// Probe every member with `device-info` (unauthenticated, no session).
    /// A down member is probed only once its backoff has elapsed.
    #[maybe_async::maybe_async]
    pub async fn probe_all(&self) {
        for m in &self.members {
            let Ok(backend) = &m.device else { continue };
            let skip = {
                let h = m.health();
                h.faulted.is_some() || (h.down && self.clock.now() < h.retry_at)
            };
            if let Some((ok, failed)) = backend.link_totals() {
                hsm_metrics().record_link_totals(&m.name, ok, failed);
            }
            if skip {
                continue;
            }
            let started = self.clock.now();
            let probed = backend.probe().await;
            self.observe(m, "probe", started, probed.is_ok());
            match probed {
                Ok(serial) => match HsmId::from_parts(m.hsm_id.backend_type(), &serial) {
                    Ok(id) if id == m.hsm_id => self.record_success(m, false),
                    _ => self.fault(m, format!("device-info reports serial {serial:?}; expected {}", m.hsm_id)),
                },
                Err(e) => {
                    self.record_failure(m, "probe", &e);
                }
            }
        }
    }

    /// Release this node's session on every member (shutdown, seal).
    #[maybe_async::maybe_async]
    pub async fn close_sessions(&self) {
        for m in &self.members {
            if let Ok(backend) = &m.device {
                if let Err(e) = backend.close_session().await {
                    log::debug!(target: "security", "closing the session on {} failed: {e}", m.label());
                }
            }
        }
    }

    /// Probe every [`PROBE_INTERVAL`] until the pool is dropped. `None` when
    /// there is no Tokio runtime to run on (logged: the probe is not optional).
    #[cfg(not(feature = "sync_handler"))]
    pub fn spawn_health_probe(self: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            log::error!(target: "security", "no async runtime: the HSM pool health probe is not running");
            return None;
        };
        let pool = Arc::downgrade(self);
        Some(runtime.spawn(async move {
            loop {
                tokio::time::sleep(PROBE_INTERVAL).await;
                let Some(pool) = pool.upgrade() else { break };
                pool.probe_all().await;
            }
        }))
    }

    pub fn member_status(&self) -> Vec<MemberStatus> {
        self.members
            .iter()
            .map(|m| {
                let h = m.health();
                MemberStatus {
                    name: m.name.clone(),
                    hsm_id: m.hsm_id.to_string(),
                    serial: m.hsm_id.as_str().split_once(':').map(|(_, s)| s.to_string()).unwrap_or_default(),
                    up: m.device.is_ok() && h.faulted.is_none() && !h.down,
                    faulted: h.faulted.is_some(),
                    prefer: m.prefer,
                    last_error: h.last_error.clone().or_else(|| m.device.as_ref().err().cloned()),
                    latency_ms: h.last_latency.map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
                }
            })
            .collect()
    }
}

/// One read (unwrap) across the members that hold a copy. The caller drives
/// it — `next_member`, then `succeeded` or `failed` — so the per-member steps
/// (authorization, counter, unwrap) stay explicit at the call site.
pub struct ReadAttempt<'p> {
    pool: &'p HsmPool,
    order: std::vec::IntoIter<&'p PoolMember>,
    failures: Vec<String>,
    /// When the current member was handed out (command duration).
    started: Duration,
}

impl<'p> ReadAttempt<'p> {
    /// The next usable member; skipped ones are recorded for the error.
    pub fn next_member(&mut self) -> Option<&'p PoolMember> {
        let now = self.pool.clock.now();
        for m in self.order.by_ref() {
            match m.usable(now) {
                Ok(()) => {
                    self.started = now;
                    return Some(m);
                }
                Err(why) => self.failures.push(format!("{}: {why}", m.label())),
            }
        }
        None
    }

    pub fn succeeded(&self, m: &PoolMember) {
        self.pool.observe(m, "read", self.started, true);
        self.pool.record_success(m, true);
    }

    /// `Ok(())`: try the next member. `Err`: a cryptographic failure, which is
    /// returned as it is and never retried elsewhere as if it were an outage.
    pub fn failed(&mut self, m: &PoolMember, op: &str, err: RvError) -> Result<(), RvError> {
        self.pool.observe(m, "read", self.started, false);
        if self.pool.record_failure(m, op, &err) == FailureClass::Crypto {
            return Err(err);
        }
        self.failures.push(format!("{}: {op}: {err}", m.label()));
        Ok(())
    }

    /// Every member failed or was skipped: one error naming each of them.
    pub fn into_error(self, what: &str) -> RvError {
        let msg = format!("{what}: {}", self.failures.join("; "));
        log::error!(target: "security", "hsm pool: {msg}");
        RvError::ErrHsmPoolUnavailable(msg)
    }
}

impl HsmPool {
    #[maybe_async::maybe_async]
    async fn wrap_one(
        &self,
        m: &PoolMember,
        key: HsmObjectId,
        ctx: &Context,
        plaintext: &[u8],
    ) -> Result<BvHsmBlob, RvError> {
        let started = self.clock.now();
        let wrapped = m.backend()?.wrap_data(key, ctx, plaintext).await;
        self.observe(m, "wrap", started, wrapped.is_ok());
        let blob = BvHsmBlob::from_bytes(&wrapped?)?;
        if blob.aad.hsm_id() != Some(&m.hsm_id) {
            log::error!(target: "security", "hsm pool member {} returned a copy bound to another device", m.label());
            return Err(RvError::ErrHsmContextMismatch);
        }
        Ok(blob)
    }
}

/// Drive every future to completion concurrently on the current task.
#[cfg(not(feature = "sync_handler"))]
async fn join_all<F: std::future::Future>(futures: Vec<F>) -> Vec<F::Output> {
    use std::task::Poll;
    let mut pending: Vec<std::pin::Pin<Box<F>>> = futures.into_iter().map(Box::pin).collect();
    let mut outputs: Vec<Option<F::Output>> = pending.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut all_ready = true;
        for (future, output) in pending.iter_mut().zip(outputs.iter_mut()) {
            if output.is_none() {
                match future.as_mut().poll(cx) {
                    Poll::Ready(value) => *output = Some(value),
                    Poll::Pending => all_ready = false,
                }
            }
        }
        if all_ready {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    outputs.into_iter().map(|o| o.expect("poll_fn is Ready only once every future has completed")).collect()
}

/// Storage backends with a real cluster lock for `hsm-custody` (spec § Write
/// atomicity): hiqlite, or a single-node `file` backend for dev and homolog.
pub fn check_pool_storage_backend(kind: &str) -> Result<(), RvError> {
    match kind {
        "hiqlite" | "file" => Ok(()),
        other => Err(RvError::ErrHsmConfigInvalid(format!(
            "the HSM pool topology needs a storage backend with a cluster lock (hiqlite, or a single-node `file` \
             backend for dev); this node's storage backend is {other:?}"
        ))),
    }
}

#[cfg(all(test, feature = "hsm_mock", not(feature = "sync_handler")))]
mod tests {
    use super::*;
    use crate::hsm::{
        clock::ManualClock,
        mock::{MockHsmBackend, MockHsmDevice},
        HsmObjectIds,
    };

    fn spec(name: &str, serial: &str, prefer: bool, device: Option<Arc<dyn HsmBackend>>) -> PoolMemberSpec {
        PoolMemberSpec {
            name: name.into(),
            hsm_id: HsmId::from_parts("mock", serial).unwrap(),
            prefer,
            device: device.ok_or_else(|| "not opened".to_string()),
        }
    }

    fn pool(node: &str, prefer_b: bool) -> HsmPool {
        let specs = vec![spec("a", "A", false, None), spec("b", "B", prefer_b, None)];
        HsmPool::new(node, specs, 1, ManualClock::new(), Arc::new(LogEventSink)).unwrap()
    }

    #[test]
    fn preference_is_deterministic_spreads_nodes_and_prefer_overrides_it() {
        let mut first_a = 0;
        for n in 0..200 {
            let node = format!("vault-{n}");
            let order: Vec<String> = pool(&node, false).members().iter().map(|m| m.name().to_string()).collect();
            let again: Vec<String> = pool(&node, false).members().iter().map(|m| m.name().to_string()).collect();
            assert_eq!(order, again, "the order is a pure function of node and device");
            if order[0] == "a" {
                first_a += 1;
            }
            assert_eq!(pool(&node, true).members()[0].name(), "b", "prefer = true wins for every node");
        }
        assert!((60..=140).contains(&first_a), "nodes spread over both members: {first_a} of 200 prefer a");
    }

    #[test]
    fn only_cryptographic_failures_stop_a_read() {
        for crypto in [RvError::ErrHsmContextMismatch, RvError::ErrHsmAuthzInvalid, RvError::ErrHsmBlobInvalid] {
            assert_eq!(classify(&crypto), FailureClass::Crypto);
        }
        assert_eq!(classify(&RvError::ErrHsmSessionsFull), FailureClass::SessionsFull);
        assert_eq!(classify(&RvError::ErrHsmTransport("x".into())), FailureClass::Transport);
        assert_eq!(classify(&RvError::ErrHsm("object not found".into())), FailureClass::Device);
        assert_eq!(classify(&RvError::ErrHsmUnavailable), FailureClass::Device);
    }

    #[test]
    fn pool_construction_is_validated() {
        let clock = ManualClock::new();
        let new = |specs, min| HsmPool::new("n", specs, min, clock.clone(), Arc::new(LogEventSink));
        assert!(new(vec![], 1).is_err());
        assert!(new(vec![spec("a", "A", false, None), spec("a", "B", false, None)], 1).is_err(), "names");
        assert!(new(vec![spec("a", "A", false, None), spec("b", "A", false, None)], 1).is_err(), "devices");
        assert!(new(vec![spec("a", "A", true, None), spec("b", "B", true, None)], 1).is_err(), "prefer");
        assert!(new(vec![spec("a", "A", false, None)], 2).is_err(), "min_wrap_copies above members");
        let three = vec![spec("a", "A", false, None), spec("b", "B", false, None), spec("c", "C", false, None)];
        assert!(new(three, 1).is_ok(), "two members plus a replacement");
        let four = vec![
            spec("a", "A", false, None),
            spec("b", "B", false, None),
            spec("c", "C", false, None),
            spec("d", "D", false, None),
        ];
        assert!(new(four, 1).is_err(), "at most three live members");
    }

    #[tokio::test]
    async fn a_device_that_is_not_the_named_member_is_faulted_not_used() {
        let clock = ManualClock::new();
        let device = MockHsmDevice::open("", Some("REAL"), clock.clone()).unwrap();
        let client: Arc<dyn HsmBackend> =
            Arc::new(MockHsmBackend::connect(device, "n", HsmObjectIds::default()).unwrap());
        let p = HsmPool::new("n", vec![spec("a", "EXPECTED", false, Some(client))], 1, clock, Arc::new(LogEventSink))
            .unwrap();
        let status = &p.member_status()[0];
        assert!(status.faulted && !status.up, "{status:?}");
        assert!(status.last_error.as_deref().unwrap().contains("mock:REAL"), "{status:?}");
        let ctx = Context::new("c", crate::hsm::Purpose::BarrierKek, 0, "n");
        let err = p.wrap_all(HsmObjectIds::default().wrap_barrier, &ctx, b"x").await.unwrap_err();
        assert!(matches!(err, RvError::ErrHsmInsufficientCopies { have: 0, need: 1, .. }), "{err}");
        assert!(p.read(|_| true).next_member().is_none(), "a faulted member is never offered");
    }

    #[test]
    fn sessions_full_jitter_stays_within_the_backoff() {
        for backoff in [SESSIONS_FULL_BACKOFF_MIN, Duration::from_millis(800), SESSIONS_FULL_BACKOFF_MAX] {
            for _ in 0..100 {
                let j = jittered(backoff);
                assert!(j >= backoff / 2 && j <= backoff, "{j:?} outside [{:?}, {backoff:?}]", backoff / 2);
            }
        }
    }

    #[test]
    fn only_storage_with_a_cluster_lock_is_accepted() {
        check_pool_storage_backend("hiqlite").unwrap();
        check_pool_storage_backend("file").unwrap();
        for kind in ["mysql", "mock", "unknown"] {
            let err = check_pool_storage_backend(kind).unwrap_err();
            assert!(err.to_string().contains(&format!("{kind:?}")), "{err}");
        }
    }
}
