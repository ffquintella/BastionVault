//! Request-denial audit trail.
//!
//! Captures every permission-denied request (the 403 path) in a
//! system-view-backed append log, so denials surface on the admin
//! Audit page alongside login / policy / share / file events. Before
//! this store existed the only trace of a denial was the in-memory
//! per-node dashboard counter (`core.stats`), which is invisible on
//! the Audit page and lost on restart.
//!
//! Recorded from a single chokepoint — `Core::handle_request`, after
//! the outcome is known — so it covers denials raised anywhere in the
//! pipeline (invalid/missing token, ACL rejection, machine-identity
//! enforcement) without per-handler wiring.
//!
//! Storage:
//!   sys/denial-audit/<20-digit-nanos> -> DenialAuditEntry JSON
//!
//! Mirrors `LoginAuditStore`: flat, timestamp-keyed, immutable
//! entries, one bulk read to list, constructed lazily from the system
//! view (no post_unseal wiring needed). The append is best-effort and
//! never alters the request outcome — the caller already has its 403.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::kernel_api::VaultCtx;
use crate::{
    errors::RvError,
    logical::Request,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

/// System-view sub-path of this store; read by the audit-retention housekeeping.
pub(crate) const DENIAL_AUDIT_SUB_PATH: &str = "denial-audit/";

/// One row in the denial-audit log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DenialAuditEntry {
    pub ts: String,
    /// The *human* principal behind the denied request: the bound
    /// username (or entity id) for a FerroGate machine+user session,
    /// otherwise the token's display name. `"(unauthenticated)"` when
    /// the request carried a missing/invalid token. Never the token
    /// itself.
    pub user: String,
    /// The attesting machine's SPIFFE id when the denied request rode a
    /// FerroGate machine-bound token, else empty. Recorded separately so
    /// a denial can be traced to both the human and the machine — the
    /// machine-identity denial reason in particular is meaningless
    /// without it. `serde(default)` so entries written before this field
    /// read back with an empty machine.
    #[serde(default)]
    pub machine: String,
    /// The request path that was denied.
    pub path: String,
    /// The attempted operation (`read`, `write`, `list`, `delete`, …).
    pub operation: String,
    /// `true` when the token was valid but policy denied the operation;
    /// `false` when authentication itself failed. Distinguishes "who is
    /// probing with bad tokens" from "who is overreaching their policy".
    pub authenticated: bool,
    /// Peer address of the caller when available (best-effort; empty
    /// when the connection info is absent).
    #[serde(default)]
    pub remote_addr: String,
    /// Why the request was refused — see [`denial_reason`]. Empty on
    /// entries written before this field existed; readers fall back to
    /// [`Self::authenticated`] for those.
    #[serde(default)]
    pub reason: String,
    /// The namespace the refused check was evaluated in (`""` = root). Set
    /// only on SQL privilege refusals (`reason = "sql-privilege"`); request
    /// denials carry the namespace in `path`. Omitted when empty, so request
    /// denials serialize exactly as before and older readers ignore it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub namespace: String,
    /// The refused capability (`sql_select`, …) of a SQL privilege refusal.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub capability: String,
    /// The plugin on whose behalf the host evaluated a SQL privilege check.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub plugin: String,
}

/// `reason` of a refused SQL privilege check ([`record_sql_denials`]).
pub const SQL_PRIVILEGE_REASON: &str = "sql-privilege";

/// One refused SQL privilege check, as [`record_sql_denials`] records it.
pub struct SqlDenial<'a> {
    /// The resolved namespace the check was evaluated in (`""` = root).
    pub namespace: &'a str,
    /// The synthetic ACL path (`…/resources/resources/<r>/sql/…`).
    pub path: &'a str,
    pub capability: &'a str,
    pub plugin: &'a str,
}

/// The human principal and the machine behind `req`, as the denial trail
/// names them. Never the token.
fn denial_actor(req: &Request) -> (String, String) {
    match req.auth.as_ref() {
        Some(auth) => {
            let meta = |k: &str| auth.metadata.get(k).map(String::as_str).unwrap_or_default();
            let (mut user, machine) = bv_logical::split_principal(
                &auth.display_name,
                meta(bv_logical::SPIFFE_ID_META),
                meta(bv_logical::USERNAME_META),
                meta(bv_logical::ENTITY_ID_META),
            );
            if user.is_empty() {
                user = "(unnamed principal)".to_string();
            }
            (user, machine)
        }
        None => ("(unauthenticated)".to_string(), String::new()),
    }
}

/// Classify a 403 for the audit trail.
///
/// A denial on an *unauth* path (every `…/login/…` route, `sys/unseal`, the SSO
/// callbacks) can never be a token problem: those paths are reached without one
/// by design, so the refusal came from the backend that handled the credential
/// — a wrong namespace assignment, a disabled account, a machine-identity or
/// binding check. Labelling those `invalid-token` sent operators hunting for a
/// bad token when the credential was fine and the *namespace* was the problem.
///
/// An authenticated denial is `policy` — *unless* the FerroGate
/// machine-identity chokepoint is what refused it. That check lives in
/// `TokenStore::pre_route`, which runs after `req.auth` is set but *before* any
/// ACL evaluation, so a request matching its predicate cannot have reached a
/// policy decision at all. Re-evaluating the predicate here is therefore exact,
/// and it keeps the two enforcement kinds distinguishable in the trail: a
/// machine-gate rejection reported as `reason=policy` sends operators auditing
/// policies for a denial no policy change can fix.
fn denial_reason(core: &dyn VaultCtx, req: &Request) -> &'static str {
    if let Some(auth) = req.auth.as_ref() {
        // The gate's own predicate, called rather than restated, so the label
        // cannot drift from the enforcement (see
        // `token_store::machine_identity_satisfied`).
        if core.require_machine_identity().load(Ordering::Relaxed)
            && !crate::modules::auth::token_store::machine_identity_satisfied(auth)
        {
            return "machine-identity";
        }
        return "policy";
    }
    // `is_unauth_path` needs the full, mount-qualified path — which the router
    // restores before this runs. A lookup failure (sealed router) falls back to
    // the conservative token verdict rather than guessing.
    match core.router().is_unauth_path(&req.path) {
        Ok(true) => "credential-refused",
        _ => "invalid-token",
    }
}

pub struct DenialAuditStore {
    view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl DenialAuditStore {
    pub fn from_core(core: &dyn VaultCtx) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.system_view() else {
            return Err(RvError::ErrBarrierSealed);
        };
        let view = Arc::new(system_view.new_sub_view(DENIAL_AUDIT_SUB_PATH));
        Ok(Arc::new(Self { view }))
    }

    /// Append an entry. `ts` is stamped here if empty. Key is monotonic
    /// nanoseconds so `get_keys` + sort yields chronological order.
    pub async fn append(&self, mut entry: DenialAuditEntry) -> Result<(), RvError> {
        if entry.ts.is_empty() {
            entry.ts = Utc::now().to_rfc3339();
        }
        let key = hist_seq();
        let value = serde_json::to_vec(&entry)?;
        self.view.put(&StorageEntry { key, value }).await
    }

    /// Full log, newest first. One bulk read instead of a prefix walk
    /// plus a `get` per entry.
    pub async fn list_all(&self) -> Result<Vec<DenialAuditEntry>, RvError> {
        Ok(Self::decode(self.view.get_entries("").await?))
    }

    /// Entries from `since_key` onward (inclusive), newest first.
    /// `since_key` is a zero-padded nanosecond key (see [`hist_seq`]),
    /// so the aggregator can bound a time-window scan to the recent
    /// tail instead of reading all history.
    pub async fn list_since(&self, since_key: &str) -> Result<Vec<DenialAuditEntry>, RvError> {
        Ok(Self::decode(self.view.get_entries_since("", since_key).await?))
    }

    /// Sort newest-first (keys are monotonic nanoseconds, so descending
    /// key order is reverse-chronological) and decode each value,
    /// skipping any that fail to parse.
    fn decode(mut entries: Vec<StorageEntry>) -> Vec<DenialAuditEntry> {
        entries.sort_by(|a, b| b.key.cmp(&a.key));
        entries.into_iter().filter_map(|e| serde_json::from_slice::<DenialAuditEntry>(&e.value).ok()).collect()
    }
}

/// Best-effort append of a denial event. Never fails the request: a
/// sealed barrier or storage error is logged at WARN and swallowed, so
/// the caller's 403 is returned unchanged either way.
#[maybe_async::maybe_async]
pub async fn record_denial(core: &dyn VaultCtx, req: &Request) {
    let store = match DenialAuditStore::from_core(core) {
        Ok(s) => s,
        Err(e) => {
            log::warn!(target: "security", "denial audit skipped (store unavailable): {e}");
            return;
        }
    };
    // A FerroGate machine+user token names the *machine* in
    // display_name and the bound human in metadata; audit both, so a
    // denial is attributable to the person as well as the host.
    let (user, machine) = denial_actor(req);
    let entry = DenialAuditEntry {
        ts: String::new(),
        user,
        machine,
        path: req.path.clone(),
        operation: req.operation.to_string(),
        authenticated: req.auth.is_some(),
        remote_addr: req.connection.as_ref().map(|c| c.peer_addr.clone()).unwrap_or_default(),
        reason: denial_reason(core, req).to_string(),
        ..Default::default()
    };
    if let Err(e) = store.append(entry).await {
        log::warn!(target: "security", "denial audit append failed: {e}");
    }
}

/// Append refused SQL privilege checks for the caller behind `req`, so they
/// appear on the Audit page's denied view beside every other 403. Best-effort
/// like [`record_denial`]: the checks are refused whether or not this lands,
/// and a failure is logged at WARN.
#[maybe_async::maybe_async]
pub async fn record_sql_denials(core: &dyn VaultCtx, req: &Request, denials: &[SqlDenial<'_>]) {
    if denials.is_empty() {
        return;
    }
    let store = match DenialAuditStore::from_core(core) {
        Ok(s) => s,
        Err(e) => {
            log::warn!(target: "security", "SQL privilege denial audit skipped (store unavailable): {e}");
            return;
        }
    };
    let (user, machine) = denial_actor(req);
    let remote_addr = req.connection.as_ref().map(|c| c.peer_addr.clone()).unwrap_or_default();
    for d in denials {
        let entry = DenialAuditEntry {
            ts: String::new(),
            user: user.clone(),
            machine: machine.clone(),
            path: d.path.to_string(),
            operation: "sql".to_string(),
            authenticated: req.auth.is_some(),
            remote_addr: remote_addr.clone(),
            reason: SQL_PRIVILEGE_REASON.to_string(),
            namespace: d.namespace.to_string(),
            capability: d.capability.to_string(),
            plugin: d.plugin.to_string(),
        };
        if let Err(e) = store.append(entry).await {
            log::warn!(target: "security", "SQL privilege denial audit append failed: {e}");
        }
    }
}

/// 20-digit zero-padded nanoseconds since UNIX epoch. Matches the
/// other append-only audit stores so logs sort chronologically.
///
/// Strictly increasing within this process: one refused SQL statement can
/// append several entries back to back, and two appends that read the same
/// clock tick would otherwise share a key and the second would overwrite the
/// first.
fn hist_seq() -> String {
    use std::sync::atomic::AtomicU64;
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now =
        Utc::now().timestamp_nanos_opt().unwrap_or_else(|| Utc::now().timestamp_millis() * 1_000_000).max(0) as u64;
    let mut prev = LAST.load(Ordering::Relaxed);
    loop {
        let next = now.max(prev + 1);
        match LAST.compare_exchange_weak(prev, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return format!("{next:020}"),
            Err(seen) => prev = seen,
        }
    }
}

/// The system module as the vault's permission-denial audit sink.
///
/// `Core::handle_request` used to call [`record_denial`] by name on the 403
/// path. It forwards to the same function with this module's own handle — the
/// same `Core` the caller would have passed, since there is one per server.
#[maybe_async::maybe_async]
impl crate::kernel_api::pipeline::DenialAudit for super::SystemModule {
    async fn record_denial(&self, req: &Request) {
        record_denial(self.backend.core.as_ref(), req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record written before the SQL fields existed reads back with them
    /// empty (read-old).
    #[test]
    fn a_pre_t124_record_reads_back_with_empty_sql_fields() {
        let stored = br#"{"ts":"2026-10-01T00:00:00Z","user":"ana","machine":"","path":"secret/x","operation":"read","authenticated":true,"remote_addr":"10.0.0.1","reason":"policy"}"#;
        let e: DenialAuditEntry = serde_json::from_slice(stored).expect("a pre-T124 denial record parses");
        assert_eq!((e.user.as_str(), e.path.as_str(), e.reason.as_str()), ("ana", "secret/x", "policy"));
        assert!(e.namespace.is_empty() && e.capability.is_empty() && e.plugin.is_empty());
    }

    /// A request denial serializes exactly as before (write-new adds no key
    /// an older reader has not seen); a SQL refusal carries its three fields
    /// and round-trips.
    #[test]
    fn only_sql_refusals_write_the_new_fields() {
        let request_denial = DenialAuditEntry {
            user: "ana".into(),
            path: "secret/x".into(),
            operation: "read".into(),
            reason: "policy".into(),
            ..Default::default()
        };
        let json = serde_json::to_value(&request_denial).unwrap();
        for key in ["namespace", "capability", "plugin"] {
            assert!(json.get(key).is_none(), "{key} written on a request denial: {json}");
        }

        let sql = DenialAuditEntry {
            path: "tenant/resources/resources/db/sql/server".into(),
            operation: "sql".into(),
            reason: SQL_PRIVILEGE_REASON.into(),
            namespace: "tenant".into(),
            capability: "sql_select".into(),
            plugin: "dbms-management".into(),
            ..Default::default()
        };
        let back: DenialAuditEntry = serde_json::from_slice(&serde_json::to_vec(&sql).unwrap()).unwrap();
        assert_eq!(
            (back.namespace.as_str(), back.capability.as_str(), back.plugin.as_str()),
            ("tenant", "sql_select", "dbms-management")
        );
    }

    /// Keys never repeat, so back-to-back appends for one refused statement
    /// cannot overwrite each other.
    #[test]
    fn hist_seq_is_strictly_increasing() {
        let keys: Vec<String> = (0..10_000).map(|_| hist_seq()).collect();
        for pair in keys.windows(2) {
            assert!(pair[0] < pair[1], "{} then {}", pair[0], pair[1]);
            assert_eq!(pair[1].len(), 20);
        }
    }
}
