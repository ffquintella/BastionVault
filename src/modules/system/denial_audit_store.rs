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

use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    core::Core,
    errors::RvError,
    logical::Request,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

const DENIAL_AUDIT_SUB_PATH: &str = "denial-audit/";

/// One row in the denial-audit log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DenialAuditEntry {
    pub ts: String,
    /// Display name of the caller when the token resolved to a valid
    /// principal (an ACL denial), or `"(unauthenticated)"` when the
    /// request carried a missing/invalid token. Never the token itself.
    pub user: String,
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
}

pub struct DenialAuditStore {
    view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl DenialAuditStore {
    pub fn from_core(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
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
pub async fn record_denial(core: &Core, req: &Request) {
    let store = match DenialAuditStore::from_core(core) {
        Ok(s) => s,
        Err(e) => {
            log::warn!(target: "security", "denial audit skipped (store unavailable): {e}");
            return;
        }
    };
    let user = match req.auth.as_ref() {
        Some(auth) if !auth.display_name.is_empty() => auth.display_name.clone(),
        Some(_) => "(unnamed principal)".to_string(),
        None => "(unauthenticated)".to_string(),
    };
    let entry = DenialAuditEntry {
        ts: String::new(),
        user,
        path: req.path.clone(),
        operation: req.operation.to_string(),
        authenticated: req.auth.is_some(),
        remote_addr: req.connection.as_ref().map(|c| c.peer_addr.clone()).unwrap_or_default(),
    };
    if let Err(e) = store.append(entry).await {
        log::warn!(target: "security", "denial audit append failed: {e}");
    }
}

/// 20-digit zero-padded nanoseconds since UNIX epoch. Matches the
/// other append-only audit stores so logs sort chronologically.
fn hist_seq() -> String {
    let n = Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_else(|| Utc::now().timestamp_millis() * 1_000_000);
    format!("{:020}", n.max(0) as u128)
}
