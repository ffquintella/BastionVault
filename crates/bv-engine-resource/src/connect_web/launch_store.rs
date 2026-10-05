//! Launch records for `v2/connect/web/*` (`features/web-application-connect.md`
//! §3, "launch_id binding").
//!
//! ## Storage layout (barrier root, the connect-MFA ticket pattern)
//!
//! ```text
//! connect/web-launches/<hex(sha256(launch_id))> -> WebLaunchRecord (JSON, `v: 2`)
//! ```
//!
//! Only the SHA-256 of a `launch_id` is persisted, so a dump of the barrier
//! yields no usable handle. The record never holds a credential: the TOTP seed
//! is re-read from the resource's own secret on each refresh, and an LDAP
//! check-out is recorded by account and lease only.
//!
//! ## Lifetime
//!
//! * **Login window** — [`LOGIN_WINDOW_SECS`] (60 s) from launch. TOTP
//!   refreshes are issued only inside it.
//! * **Session** — until `close`. `result` and `close` are accepted for as long
//!   as the record exists, so a session that outlives the login window can
//!   still be closed and its LDAP account checked in.
//! * **Reaping** — [`WebLaunchStore::tidy`] drops closed records after
//!   [`CLOSED_RETENTION_SECS`] (so a repeated `close` still answers
//!   idempotently) and never-closed records after
//!   [`UNCLOSED_RETENTION_SECS`]. A never-closed LDAP check-out is then left to
//!   the LDAP engine's own lease expiry, and the reap is logged. Reaping
//!   runs from `launch`, at most once per [`TIDY_INTERVAL_MS`] per process
//!   ([`TidyThrottle`]), after the launch is persisted, and never fails it.
//!
//! ## Concurrency — per process only
//!
//! [`LaunchGuard`] serialises follow-up calls on one launch **inside one
//! server process**. On a multi-node deployment where two nodes serve requests
//! against shared storage, two concurrent calls for the same launch on
//! different nodes are not excluded: both could refresh the same TOTP step,
//! and both could attempt the LDAP check-in (the LDAP engine's own per-set
//! lock and record delete make the second check-in fail rather than double
//! up). Storage offers no compare-and-swap to close this; standby nodes
//! forwarding to the active node is what keeps it a single process today.
//!
//! ## Versioning
//!
//! `v` is read before anything else. A record of a version this server does
//! not know is refused (and never reaped), so a rolled-back server cannot
//! misread — or delete — a newer server's state. `v: 1` (no `fill_scope`) is
//! still read; every record is written as [`LAUNCH_RECORD_VERSION`].

use std::{
    collections::HashSet,
    fmt,
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc, Mutex, OnceLock,
    },
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::totp::TotpParams;
use crate::kernel_api::VaultCtx;
use crate::{
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

pub const LAUNCH_PREFIX: &str = "connect/web-launches/";
pub const LAUNCH_RECORD_VERSION: u64 = 2;
/// Oldest record version still read.
pub const MIN_READABLE_RECORD_VERSION: u64 = 1;
/// How long after `launch` TOTP refreshes are issued (spec: "valid for 60 s").
pub const LOGIN_WINDOW_SECS: i64 = 60;
/// How long a closed record is kept so a repeated `close` stays idempotent.
pub const CLOSED_RETENTION_SECS: i64 = 15 * 60;
/// How long a record that was never closed is kept.
pub const UNCLOSED_RETENTION_SECS: i64 = 24 * 3600;
/// Longest accepted `aborted:<check>` check name.
pub const MAX_CHECK_NAME_LEN: usize = 32;
/// Minimum spacing between two reaping passes in one process.
pub const TIDY_INTERVAL_MS: i64 = 60_000;

/// Who a launch belongs to. Every follow-up call must come from the same
/// principal (auth mount + name) in the same namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerIdentity {
    pub mount: String,
    pub principal: String,
    /// `""` = root.
    pub namespace: String,
}

/// Where a refresh re-reads the TOTP seed from. Never the seed itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpSource {
    pub secret_id: String,
    pub seed_field: String,
    pub params: TotpParams,
    /// Recipe steps allowed one refresh each.
    pub refresh_steps: Vec<u32>,
    #[serde(default)]
    pub refreshed_steps: Vec<u32>,
}

/// An LDAP library check-out made by `launch`, to be checked in by `close`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LdapCheckout {
    /// Mount path with a trailing `/`, without the namespace prefix.
    pub mount: String,
    pub library_set: String,
    pub account: String,
    pub lease_id: String,
    pub checked_in: bool,
}

/// Where the host may fill the credential: the profile's normalised origin set
/// and start URL as checked at launch. Bound to the launch and returned in the
/// bundle as the authoritative fill scope — the recipe hash does not cover
/// these profile fields, and in heuristic mode they are the only constraint on
/// where a fill happens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FillScope {
    pub start_url: String,
    /// Exact `scheme://host[:port]` keys, the start URL's origin first.
    pub origins: Vec<String>,
    pub allow_insecure_http: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchOutcome {
    pub outcome: String,
    pub step: Option<u32>,
    pub at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebLaunchRecord {
    pub v: u64,
    pub caller: CallerIdentity,
    pub resource: String,
    pub profile_id: String,
    pub recipe_hash: String,
    pub login_mode: String,
    pub exposure: String,
    pub credential_kind: String,
    pub mfa_method: Option<String>,
    pub issued_at_ms: i64,
    pub login_expires_at_ms: i64,
    pub step_count: u32,
    pub totp: Option<TotpSource>,
    pub ldap: Option<LdapCheckout>,
    pub result: Option<LaunchOutcome>,
    pub closed_at_ms: Option<i64>,
    /// Absent on `v: 1` records only.
    #[serde(default)]
    pub fill_scope: Option<FillScope>,
}

/// Why a follow-up call on a launch was refused. Every variant is a refusal.
#[derive(Debug)]
pub enum LaunchError {
    Unknown,
    Mismatch(&'static str),
    UnsupportedVersion(u64),
    Closed,
    LoginWindowExpired,
    TotpNotConfigured,
    TotpStepInvalid(u32),
    TotpStepUsed(u32),
    InvalidOutcome,
    StepOutOfRange(u32),
    ResultConflict,
    Busy,
    Storage(RvError),
}

impl LaunchError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unknown => "launch_unknown",
            Self::Mismatch(_) => "launch_binding_mismatch",
            Self::UnsupportedVersion(_) => "launch_record_unsupported",
            Self::Closed => "launch_closed",
            Self::LoginWindowExpired => "launch_expired",
            Self::TotpNotConfigured => "totp_not_configured",
            Self::TotpStepInvalid(_) => "totp_step_invalid",
            Self::TotpStepUsed(_) => "totp_step_used",
            Self::InvalidOutcome => "invalid_outcome",
            Self::StepOutOfRange(_) => "invalid_step",
            Self::ResultConflict => "result_conflict",
            Self::Busy => "launch_busy",
            Self::Storage(_) => "storage_error",
        }
    }

    pub fn status(&self) -> u16 {
        match self {
            Self::Unknown => 404,
            Self::Mismatch(_) => 403,
            Self::LoginWindowExpired => 410,
            Self::TotpStepInvalid(_) | Self::InvalidOutcome | Self::StepOutOfRange(_) => 400,
            Self::Storage(_) => 500,
            _ => 409,
        }
    }
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "launch_id is unknown, or its record has been reaped; launch again"),
            Self::Mismatch(what) => write!(f, "launch_id was not issued to this {what}"),
            Self::UnsupportedVersion(v) => {
                write!(f, "launch record version {v} is not supported by this server")
            }
            Self::Closed => write!(f, "this launch has already been closed"),
            Self::LoginWindowExpired => {
                write!(f, "the launch's {LOGIN_WINDOW_SECS}-second login window has passed; launch again")
            }
            Self::TotpNotConfigured => {
                write!(f, "this launch carries no TOTP: its recipe fills none, or its source has no seed")
            }
            Self::TotpStepInvalid(s) => write!(f, "recipe step {s} does not fill `totp`"),
            Self::TotpStepUsed(s) => {
                write!(f, "recipe step {s} has already had its one TOTP refresh; launch again")
            }
            Self::InvalidOutcome => write!(
                f,
                "outcome must be `success`, `failure`, `timeout` or `aborted:<check>` \
                 (check = 1..={MAX_CHECK_NAME_LEN} of [a-z0-9_])"
            ),
            Self::StepOutOfRange(s) => write!(f, "step {s} is outside the recipe"),
            Self::ResultConflict => {
                write!(f, "a different outcome has already been recorded for this launch")
            }
            Self::Busy => write!(f, "another request for this launch is in progress; retry"),
            Self::Storage(e) => write!(f, "launch record storage error: {e}"),
        }
    }
}

/// Hex SHA-256 of a `launch_id`: the storage key suffix and the value the
/// audit lines carry. Not reversible to a usable handle.
pub fn launch_id_hash(launch_id: &str) -> String {
    hex::encode(Sha256::digest(launch_id.trim().as_bytes()))
}

pub fn launch_key(launch_id: &str) -> String {
    format!("{LAUNCH_PREFIX}{}", launch_id_hash(launch_id))
}

/// `success` | `failure` | `timeout` | `aborted:<check>`. The check name is
/// a bounded `[a-z0-9_]` token so an outcome can never smuggle a URL, a
/// selector match or a line break into an audit line.
pub fn validate_outcome(raw: &str) -> Result<String, LaunchError> {
    match raw {
        "success" | "failure" | "timeout" => Ok(raw.to_string()),
        _ => {
            let check = raw.strip_prefix("aborted:").ok_or(LaunchError::InvalidOutcome)?;
            let ok = (1..=MAX_CHECK_NAME_LEN).contains(&check.len())
                && check.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
            if ok {
                Ok(raw.to_string())
            } else {
                Err(LaunchError::InvalidOutcome)
            }
        }
    }
}

fn decode_record(bytes: &[u8]) -> Result<WebLaunchRecord, LaunchError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|e| LaunchError::Storage(e.into()))?;
    let v = value.get("v").and_then(Value::as_u64).unwrap_or(0);
    if !(MIN_READABLE_RECORD_VERSION..=LAUNCH_RECORD_VERSION).contains(&v) {
        return Err(LaunchError::UnsupportedVersion(v));
    }
    serde_json::from_value(value).map_err(|e| LaunchError::Storage(e.into()))
}

impl WebLaunchRecord {
    /// Consume `step`'s one TOTP refresh. The record must be open, inside its
    /// login window, carry TOTP, and `step` must be a TOTP step not yet
    /// refreshed.
    pub fn take_totp_refresh(&mut self, step: u32, now_ms: i64) -> Result<TotpSource, LaunchError> {
        if self.closed_at_ms.is_some() {
            return Err(LaunchError::Closed);
        }
        if now_ms >= self.login_expires_at_ms {
            return Err(LaunchError::LoginWindowExpired);
        }
        let totp = self.totp.as_mut().ok_or(LaunchError::TotpNotConfigured)?;
        if !totp.refresh_steps.contains(&step) {
            return Err(LaunchError::TotpStepInvalid(step));
        }
        if totp.refreshed_steps.contains(&step) {
            return Err(LaunchError::TotpStepUsed(step));
        }
        totp.refreshed_steps.push(step);
        Ok(totp.clone())
    }

    /// Record the recipe's outcome once. Repeating the same outcome is a
    /// no-op (`Ok(false)`); a different one is a conflict.
    pub fn record_result(&mut self, outcome: &str, step: Option<u32>, now_ms: i64) -> Result<bool, LaunchError> {
        if self.closed_at_ms.is_some() {
            return Err(LaunchError::Closed);
        }
        let outcome = validate_outcome(outcome)?;
        if let Some(s) = step {
            if s >= self.step_count {
                return Err(LaunchError::StepOutOfRange(s));
            }
        }
        match &self.result {
            Some(r) if r.outcome == outcome && r.step == step => Ok(false),
            Some(_) => Err(LaunchError::ResultConflict),
            None => {
                self.result = Some(LaunchOutcome { outcome, step, at_ms: now_ms });
                Ok(true)
            }
        }
    }

    /// Mark the session closed. `true` the first time only.
    pub fn mark_closed(&mut self, now_ms: i64) -> bool {
        if self.closed_at_ms.is_some() {
            return false;
        }
        self.closed_at_ms = Some(now_ms);
        true
    }

    pub fn duration_ms(&self) -> i64 {
        self.closed_at_ms.map(|c| (c - self.issued_at_ms).max(0)).unwrap_or(0)
    }
}

// ── Reaping throttle ───────────────────────────────────────────────

/// At most one reaping pass per [`TIDY_INTERVAL_MS`]: a launch claims the slot
/// with one compare-and-swap, so concurrent launches never both scan.
pub struct TidyThrottle {
    last_ms: AtomicI64,
}

impl Default for TidyThrottle {
    fn default() -> Self {
        Self::new()
    }
}

impl TidyThrottle {
    pub const fn new() -> Self {
        Self { last_ms: AtomicI64::new(i64::MIN) }
    }

    /// `true` when this caller should run a pass now.
    pub fn claim(&self, now_ms: i64) -> bool {
        let last = self.last_ms.load(Ordering::Acquire);
        if last != i64::MIN && now_ms.saturating_sub(last) < TIDY_INTERVAL_MS {
            return false;
        }
        self.last_ms.compare_exchange(last, now_ms, Ordering::AcqRel, Ordering::Acquire).is_ok()
    }
}

/// The process-wide throttle `launch` uses.
pub static TIDY_THROTTLE: TidyThrottle = TidyThrottle::new();

// ── Per-launch mutual exclusion ────────────────────────────────────

fn in_flight() -> &'static Mutex<HashSet<String>> {
    static IN_FLIGHT: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    IN_FLIGHT.get_or_init(Default::default)
}

/// Serialises the follow-up calls on one launch inside this process (see the
/// module docs for the multi-node limitation), so a
/// TOTP step cannot be refreshed twice and an LDAP account cannot be checked
/// in twice by racing requests. A concurrent call is refused with
/// [`LaunchError::Busy`] rather than queued. Only the key's presence in the set
/// spans `.await`s; the mutex itself is held for an insert or a remove.
pub struct LaunchGuard {
    key: String,
}

impl LaunchGuard {
    pub fn acquire(launch_id: &str) -> Result<Self, LaunchError> {
        let key = launch_key(launch_id);
        let mut set = in_flight().lock().unwrap_or_else(|p| p.into_inner());
        if !set.insert(key.clone()) {
            return Err(LaunchError::Busy);
        }
        Ok(Self { key })
    }
}

impl Drop for LaunchGuard {
    fn drop(&mut self) {
        in_flight().lock().unwrap_or_else(|p| p.into_inner()).remove(&self.key);
    }
}

// ── Close and check-in ─────────────────────────────────────────────

/// Checks an LDAP library account back in. The handler's implementation
/// dispatches `<mount>library/<set>/check-in` through the full request
/// pipeline *as the caller*; tests substitute a fake.
// `async_trait` (which `maybe_async` expands to) marks the boxed future it
// returns `#[must_use]`, and clippy reports that as `double_must_use` on every
// `maybe_async` trait in the workspace (`SecurityBarrier`, the kernel-api
// traits). The attribute is the macro's, not ours to remove.
#[allow(clippy::double_must_use)]
#[maybe_async::maybe_async]
pub trait LdapCheckIn: Send + Sync {
    async fn check_in(&self, checkout: &LdapCheckout) -> Result<(), RvError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckInState {
    NotApplicable,
    Done,
    /// The check-in failed; the record keeps it pending and the next `close`
    /// retries it.
    Failed,
}

impl CheckInState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::Done => "done",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug)]
pub struct CloseReport {
    pub already_closed: bool,
    pub duration_ms: i64,
    pub ldap_checkin: CheckInState,
    /// The check-in error, when `ldap_checkin` is `Failed`.
    pub checkin_error: Option<String>,
    pub resource: String,
    pub profile_id: String,
}

/// A record dropped by [`WebLaunchStore::tidy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reaped {
    pub launch_id_hash: String,
    /// The launch checked out an LDAP account that was never checked in.
    pub ldap_pending: bool,
}

pub struct WebLaunchStore {
    view: Arc<dyn Storage>,
}

impl WebLaunchStore {
    /// The store at the barrier root, like the connect-MFA tickets.
    pub fn new(core: &dyn VaultCtx) -> Self {
        Self { view: Arc::new(BarrierView::new(core.barrier().clone(), "")) }
    }

    /// The store over any `Storage` — the tests use an in-memory one.
    pub fn with_storage(view: Arc<dyn Storage>) -> Self {
        Self { view }
    }
}

#[maybe_async::maybe_async]
impl WebLaunchStore {
    /// Persist a new record and return its `launch_id` — the only time the
    /// raw handle exists.
    pub async fn create(&self, record: &WebLaunchRecord) -> Result<String, RvError> {
        // ThreadRng is `!Send`: scope it so it is gone before the await.
        let launch_id = {
            let mut raw = [0u8; 32];
            rand::rng().fill_bytes(&mut raw);
            URL_SAFE_NO_PAD.encode(raw)
        };
        let value = serde_json::to_vec(record)?;
        self.view.put(&StorageEntry { key: launch_key(&launch_id), value }).await?;
        Ok(launch_id)
    }

    /// Load the record behind `launch_id`, refusing it unless it was issued to
    /// `caller`. Returns the storage key alongside it.
    pub async fn load(
        &self,
        launch_id: &str,
        caller: &CallerIdentity,
    ) -> Result<(String, WebLaunchRecord), LaunchError> {
        if launch_id.trim().is_empty() {
            return Err(LaunchError::Unknown);
        }
        let key = launch_key(launch_id);
        let entry = self.view.get(&key).await.map_err(LaunchError::Storage)?.ok_or(LaunchError::Unknown)?;
        let record = decode_record(&entry.value)?;
        if record.caller.mount != caller.mount || record.caller.principal != caller.principal {
            return Err(LaunchError::Mismatch("principal"));
        }
        if record.caller.namespace != caller.namespace {
            return Err(LaunchError::Mismatch("namespace"));
        }
        Ok((key, record))
    }

    pub async fn save(&self, key: &str, record: &WebLaunchRecord) -> Result<(), RvError> {
        let value = serde_json::to_vec(record)?;
        self.view.put(&StorageEntry { key: key.to_string(), value }).await
    }

    /// `close`: mark the session closed (once), then check the LDAP account
    /// in if the launch checked one out and it is still pending. Idempotent: a
    /// repeated close reports `already_closed` and only retries a check-in
    /// that previously failed.
    pub async fn close(
        &self,
        launch_id: &str,
        caller: &CallerIdentity,
        now_ms: i64,
        checkin: &dyn LdapCheckIn,
    ) -> Result<CloseReport, LaunchError> {
        let _guard = LaunchGuard::acquire(launch_id)?;
        let (key, mut record) = self.load(launch_id, caller).await?;

        let first = record.mark_closed(now_ms);
        if first {
            // Persisted before the check-in so the close is on record even if
            // the check-in then fails.
            self.save(&key, &record).await.map_err(LaunchError::Storage)?;
        }

        let mut report = CloseReport {
            already_closed: !first,
            duration_ms: record.duration_ms(),
            ldap_checkin: CheckInState::NotApplicable,
            checkin_error: None,
            resource: record.resource.clone(),
            profile_id: record.profile_id.clone(),
        };
        let pending = match &record.ldap {
            None => return Ok(report),
            Some(c) if c.checked_in => {
                report.ldap_checkin = CheckInState::Done;
                return Ok(report);
            }
            Some(c) => c.clone(),
        };
        match checkin.check_in(&pending).await {
            Ok(()) => {
                if let Some(c) = record.ldap.as_mut() {
                    c.checked_in = true;
                }
                self.save(&key, &record).await.map_err(LaunchError::Storage)?;
                report.ldap_checkin = CheckInState::Done;
            }
            Err(e) => {
                report.ldap_checkin = CheckInState::Failed;
                report.checkin_error = Some(e.to_string());
            }
        }
        Ok(report)
    }

    /// Drop expired records (see the module docs). Hygiene, not a control:
    /// every follow-up call enforces its own window regardless.
    pub async fn tidy(&self, now_ms: i64) -> Result<Vec<Reaped>, RvError> {
        let mut reaped = Vec::new();
        for child in self.view.list(LAUNCH_PREFIX).await? {
            let hash = child.trim_end_matches('/').to_string();
            let key = format!("{LAUNCH_PREFIX}{hash}");
            let Some(entry) = self.view.get(&key).await? else { continue };
            // Only records this version understands are reaped.
            let Ok(record) = decode_record(&entry.value) else { continue };
            let stale = match record.closed_at_ms {
                Some(closed) => now_ms >= closed + CLOSED_RETENTION_SECS * 1000,
                None => now_ms >= record.issued_at_ms + UNCLOSED_RETENTION_SECS * 1000,
            };
            if stale {
                self.view.delete(&key).await?;
                reaped.push(Reaped {
                    launch_id_hash: hash,
                    ldap_pending: record.ldap.as_ref().is_some_and(|c| !c.checked_in),
                });
            }
        }
        Ok(reaped)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use super::*;

    /// A flat in-memory `Storage` with the barrier's `list` semantics
    /// (immediate children, sub-trees as `name/`).
    #[derive(Default)]
    struct MemStorage(Mutex<BTreeMap<String, Vec<u8>>>);

    #[maybe_async::maybe_async]
    impl Storage for MemStorage {
        async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
            let map = self.0.lock().unwrap();
            let mut out: Vec<String> = Vec::new();
            for k in map.keys().filter(|k| k.starts_with(prefix)) {
                let rest = &k[prefix.len()..];
                let child = match rest.find('/') {
                    Some(i) => rest[..=i].to_string(),
                    None => rest.to_string(),
                };
                if !out.contains(&child) {
                    out.push(child);
                }
            }
            Ok(out)
        }
        async fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError> {
            Ok(self.0.lock().unwrap().get(key).map(|v| StorageEntry { key: key.into(), value: v.clone() }))
        }
        async fn put(&self, entry: &StorageEntry) -> Result<(), RvError> {
            self.0.lock().unwrap().insert(entry.key.clone(), entry.value.clone());
            Ok(())
        }
        async fn delete(&self, key: &str) -> Result<(), RvError> {
            self.0.lock().unwrap().remove(key);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeCheckIn {
        calls: AtomicUsize,
        fail: AtomicBool,
    }

    #[maybe_async::maybe_async]
    impl LdapCheckIn for FakeCheckIn {
        async fn check_in(&self, checkout: &LdapCheckout) -> Result<(), RvError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(checkout.account, "svc-web-1");
            if self.fail.load(Ordering::SeqCst) {
                return Err(RvError::ErrString("check-in: bind: connection refused".into()));
            }
            Ok(())
        }
    }

    const T0: i64 = 1_800_000_000_000;

    fn alice() -> CallerIdentity {
        CallerIdentity { mount: "userpass/".into(), principal: "alice".into(), namespace: String::new() }
    }

    fn record() -> WebLaunchRecord {
        WebLaunchRecord {
            v: LAUNCH_RECORD_VERSION,
            caller: alice(),
            resource: "fw01".into(),
            profile_id: "p_web".into(),
            recipe_hash: "sha256:00".into(),
            login_mode: "form".into(),
            exposure: "dom".into(),
            credential_kind: "secret".into(),
            mfa_method: None,
            issued_at_ms: T0,
            login_expires_at_ms: T0 + LOGIN_WINDOW_SECS * 1000,
            step_count: 2,
            totp: Some(TotpSource {
                secret_id: "admin".into(),
                seed_field: "totp_seed".into(),
                params: TotpParams::default(),
                refresh_steps: vec![1],
                refreshed_steps: Vec::new(),
            }),
            ldap: None,
            result: None,
            closed_at_ms: None,
            fill_scope: Some(FillScope {
                start_url: "https://fw01.example.com/login".into(),
                origins: vec!["https://fw01.example.com".into()],
                allow_insecure_http: false,
            }),
        }
    }

    fn store() -> (WebLaunchStore, Arc<MemStorage>) {
        let mem = Arc::new(MemStorage::default());
        (WebLaunchStore::with_storage(mem.clone()), mem)
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn records_are_stored_by_hash_and_bound_to_the_caller() {
        let (store, mem) = store();
        let id = store.create(&record()).await.unwrap();
        let keys: Vec<String> = mem.0.lock().unwrap().keys().cloned().collect();
        assert_eq!(keys, vec![launch_key(&id)]);
        assert!(!keys[0].contains(&id), "the raw launch_id must never be a storage key");

        let (_, got) = store.load(&id, &alice()).await.unwrap();
        assert_eq!(got, record());

        assert!(matches!(store.load("never-issued", &alice()).await, Err(LaunchError::Unknown)));
        assert!(matches!(store.load("  ", &alice()).await, Err(LaunchError::Unknown)));

        let mut bob = alice();
        bob.principal = "bob".into();
        assert!(matches!(store.load(&id, &bob).await, Err(LaunchError::Mismatch("principal"))));
        let mut other_mount = alice();
        other_mount.mount = "ldap/".into();
        assert!(matches!(store.load(&id, &other_mount).await, Err(LaunchError::Mismatch("principal"))));
        let mut tenant = alice();
        tenant.namespace = "tenant-b".into();
        assert!(matches!(store.load(&id, &tenant).await, Err(LaunchError::Mismatch("namespace"))));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn unknown_record_versions_are_refused_and_left_alone() {
        let (store, mem) = store();
        let id = store.create(&record()).await.unwrap();
        // A v1 record — written before `fill_scope` existed — still reads.
        let mut v1: Value = serde_json::to_value(record()).unwrap();
        v1["v"] = Value::from(1);
        v1.as_object_mut().unwrap().remove("fill_scope");
        mem.0.lock().unwrap().insert(launch_key(&id), serde_json::to_vec(&v1).unwrap());
        let (_, old) = store.load(&id, &alice()).await.unwrap();
        assert_eq!((old.v, old.fill_scope), (1, None));

        let mut v: Value = serde_json::to_value(record()).unwrap();
        v["v"] = Value::from(3);
        v["future_field"] = Value::from(true);
        mem.0.lock().unwrap().insert(launch_key(&id), serde_json::to_vec(&v).unwrap());
        assert!(matches!(store.load(&id, &alice()).await, Err(LaunchError::UnsupportedVersion(3))));
        // Never reaped, however old.
        assert!(store.tidy(T0 + 365 * 86_400_000).await.unwrap().is_empty());

        // A v1 record with an unknown field is malformed, not silently trimmed.
        let mut v: Value = serde_json::to_value(record()).unwrap();
        v["surprise"] = Value::from(1);
        mem.0.lock().unwrap().insert(launch_key(&id), serde_json::to_vec(&v).unwrap());
        assert!(matches!(store.load(&id, &alice()).await, Err(LaunchError::Storage(_))));
    }

    #[test]
    fn totp_refresh_is_once_per_totp_step_inside_the_login_window() {
        let mut r = record();
        assert!(matches!(r.take_totp_refresh(0, T0), Err(LaunchError::TotpStepInvalid(0))));
        assert!(matches!(r.take_totp_refresh(7, T0), Err(LaunchError::TotpStepInvalid(7))));
        let src = r.take_totp_refresh(1, T0 + 1000).unwrap();
        assert_eq!(src.secret_id, "admin");
        assert!(matches!(r.take_totp_refresh(1, T0 + 2000), Err(LaunchError::TotpStepUsed(1))));

        let mut r = record();
        assert!(matches!(r.take_totp_refresh(1, T0 + LOGIN_WINDOW_SECS * 1000), Err(LaunchError::LoginWindowExpired)));

        let mut r = record();
        r.totp = None;
        assert!(matches!(r.take_totp_refresh(1, T0), Err(LaunchError::TotpNotConfigured)));

        let mut r = record();
        r.mark_closed(T0);
        assert!(matches!(r.take_totp_refresh(1, T0), Err(LaunchError::Closed)));
    }

    #[test]
    fn result_is_recorded_once_and_validated() {
        let mut r = record();
        for bad in
            ["", "ok", "aborted:", "aborted:Bad Check", "aborted:origin\nx=1", &format!("aborted:{}", "a".repeat(33))]
        {
            assert!(matches!(r.record_result(bad, None, T0), Err(LaunchError::InvalidOutcome)), "{bad:?}");
        }
        assert!(matches!(r.record_result("success", Some(2), T0), Err(LaunchError::StepOutOfRange(2))));
        assert_eq!(r.record_result("aborted:form_action", Some(1), T0).unwrap(), true);
        assert_eq!(r.record_result("aborted:form_action", Some(1), T0 + 5).unwrap(), false, "repeat is idempotent");
        assert!(matches!(r.record_result("success", Some(1), T0), Err(LaunchError::ResultConflict)));
        assert_eq!(r.result.as_ref().unwrap().at_ms, T0);

        let mut r = record();
        r.mark_closed(T0);
        assert!(matches!(r.record_result("success", None, T0), Err(LaunchError::Closed)));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn close_is_idempotent_without_ldap() {
        let (store, _mem) = store();
        let mut rec = record();
        rec.totp = None;
        let id = store.create(&rec).await.unwrap();
        let checkin = FakeCheckIn::default();

        let first = store.close(&id, &alice(), T0 + 90_000, &checkin).await.unwrap();
        assert!(!first.already_closed);
        assert_eq!(first.duration_ms, 90_000);
        assert_eq!(first.ldap_checkin, CheckInState::NotApplicable);

        let again = store.close(&id, &alice(), T0 + 500_000, &checkin).await.unwrap();
        assert!(again.already_closed);
        assert_eq!(again.duration_ms, 90_000, "the first close's time stands");
        assert_eq!(checkin.calls.load(Ordering::SeqCst), 0);

        let mut bob = alice();
        bob.principal = "bob".into();
        assert!(matches!(store.close(&id, &bob, T0, &checkin).await, Err(LaunchError::Mismatch("principal"))));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn close_checks_the_ldap_account_in_exactly_once_and_retries_a_failure() {
        let (store, _mem) = store();
        let mut rec = record();
        rec.credential_kind = "ldap".into();
        rec.totp = None;
        rec.ldap = Some(LdapCheckout {
            mount: "openldap/".into(),
            library_set: "web-admins".into(),
            account: "svc-web-1".into(),
            lease_id: "ldap-library-1".into(),
            checked_in: false,
        });
        let id = store.create(&rec).await.unwrap();
        let checkin = FakeCheckIn::default();

        // A failing check-in is reported, and the close itself still stands.
        checkin.fail.store(true, Ordering::SeqCst);
        let r = store.close(&id, &alice(), T0 + 1000, &checkin).await.unwrap();
        assert!(!r.already_closed);
        assert_eq!(r.ldap_checkin, CheckInState::Failed);
        assert!(r.checkin_error.unwrap().contains("connection refused"));
        let (_, stored) = store.load(&id, &alice()).await.unwrap();
        assert!(stored.closed_at_ms.is_some());
        assert!(!stored.ldap.unwrap().checked_in, "the check-in stays pending");

        // The next close retries it …
        checkin.fail.store(false, Ordering::SeqCst);
        let r = store.close(&id, &alice(), T0 + 2000, &checkin).await.unwrap();
        assert!(r.already_closed);
        assert_eq!(r.ldap_checkin, CheckInState::Done);
        assert_eq!(checkin.calls.load(Ordering::SeqCst), 2);

        // … and once it has succeeded it is never repeated.
        let r = store.close(&id, &alice(), T0 + 3000, &checkin).await.unwrap();
        assert_eq!(r.ldap_checkin, CheckInState::Done);
        assert_eq!(checkin.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn tidy_runs_at_most_once_per_interval() {
        let t = TidyThrottle::new();
        assert!(t.claim(T0), "the first launch tidies");
        assert!(!t.claim(T0 + 1), "a launch right after does not");
        assert!(!t.claim(T0 + TIDY_INTERVAL_MS - 1));
        assert!(t.claim(T0 + TIDY_INTERVAL_MS), "the interval elapsed");
        assert!(!t.claim(T0 + TIDY_INTERVAL_MS));
    }

    #[test]
    fn concurrent_calls_on_one_launch_are_refused() {
        let g = LaunchGuard::acquire("launch-a").unwrap();
        assert!(matches!(LaunchGuard::acquire("launch-a"), Err(LaunchError::Busy)));
        assert!(LaunchGuard::acquire("launch-b").is_ok(), "other launches are unaffected");
        drop(g);
        assert!(LaunchGuard::acquire("launch-a").is_ok());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn tidy_reaps_only_expired_records() {
        let (store, _mem) = store();
        let live = store.create(&record()).await.unwrap();

        let mut closed = record();
        closed.closed_at_ms = Some(T0);
        let closed_id = store.create(&closed).await.unwrap();

        let mut abandoned = record();
        abandoned.issued_at_ms = T0 - UNCLOSED_RETENTION_SECS * 1000;
        abandoned.ldap = Some(LdapCheckout {
            mount: "openldap/".into(),
            library_set: "s1".into(),
            account: "svc-web-1".into(),
            lease_id: "l".into(),
            checked_in: false,
        });
        let abandoned_id = store.create(&abandoned).await.unwrap();

        let now = T0 + CLOSED_RETENTION_SECS * 1000;
        let mut reaped = store.tidy(now).await.unwrap();
        reaped.sort_by(|a, b| a.launch_id_hash.cmp(&b.launch_id_hash));
        let mut want = vec![
            Reaped { launch_id_hash: launch_id_hash(&closed_id), ldap_pending: false },
            Reaped { launch_id_hash: launch_id_hash(&abandoned_id), ldap_pending: true },
        ];
        want.sort_by(|a, b| a.launch_id_hash.cmp(&b.launch_id_hash));
        assert_eq!(reaped, want);
        assert!(store.load(&live, &alice()).await.is_ok());
        assert!(matches!(store.load(&closed_id, &alice()).await, Err(LaunchError::Unknown)));
    }
}
