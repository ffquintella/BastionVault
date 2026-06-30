//! User-operation audit trail.
//!
//! Captures principal lifecycle events (create, update, delete,
//! password-change, etc.) from the userpass and approle backends.
//! Surfaced by the admin audit aggregator at `sys/audit/events`
//! under the `user` category, so operators can see who created or
//! removed whom, and who changed passwords, without digging through
//! every per-subsystem log.
//!
//! Storage:
//!   sys/identity/user-audit/<20-digit-nanos> -> UserAuditEntry JSON
//!
//! A flat, timestamp-keyed view keeps listing cheap (one prefix
//! walk, sort, reverse). Entries are immutable once written.

use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    core::Core,
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

const USER_AUDIT_SUB_PATH: &str = "identity/user-audit/";

/// One row in the user-operation audit log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserAuditEntry {
    pub ts: String,
    /// `entity_id` of the caller that performed the action, or empty
    /// for root-token operations.
    pub actor_entity_id: String,
    /// `"create" | "update" | "delete" | "password-change"`.
    pub op: String,
    /// Auth mount the target lives on: `"userpass/"` or `"approle/"`.
    pub mount: String,
    /// Target principal name (username or role name).
    pub target: String,
    /// Human-readable detail (e.g., "policies=admin,default" for an
    /// update). Optional; aggregator includes it as `summary`.
    #[serde(default)]
    pub details: String,
}

pub struct UserAuditStore {
    view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl UserAuditStore {
    pub async fn new(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };
        let view = Arc::new(system_view.new_sub_view(USER_AUDIT_SUB_PATH));
        Ok(Arc::new(Self { view }))
    }

    /// Append an entry to the audit log. `ts` is stamped here if the
    /// caller left it empty, and the storage key is monotonic
    /// nanoseconds so `get_keys` + sort yields chronological order.
    pub async fn append(&self, mut entry: UserAuditEntry) -> Result<(), RvError> {
        if entry.ts.is_empty() {
            entry.ts = Utc::now().to_rfc3339();
        }
        let key = hist_seq();
        let value = serde_json::to_vec(&entry)?;
        self.view.put(&StorageEntry { key, value }).await
    }

    /// Full log, newest first. One bulk read instead of a prefix walk
    /// plus a `get` per entry.
    pub async fn list_all(&self) -> Result<Vec<UserAuditEntry>, RvError> {
        Ok(Self::decode(self.view.get_entries("").await?))
    }

    /// Entries from `since_key` onward (inclusive), newest first.
    /// `since_key` is a zero-padded nanosecond key (see [`hist_seq`]),
    /// so the aggregator can bound a time-window scan to the recent tail
    /// instead of reading all history.
    pub async fn list_since(&self, since_key: &str) -> Result<Vec<UserAuditEntry>, RvError> {
        Ok(Self::decode(self.view.get_entries_since("", since_key).await?))
    }

    /// Sort newest-first (keys are monotonic nanoseconds, so descending
    /// key order is reverse-chronological) and decode each value,
    /// skipping any that fail to parse.
    fn decode(mut entries: Vec<StorageEntry>) -> Vec<UserAuditEntry> {
        entries.sort_by(|a, b| b.key.cmp(&a.key));
        entries.into_iter().filter_map(|e| serde_json::from_slice::<UserAuditEntry>(&e.value).ok()).collect()
    }
}

/// 20-digit zero-padded nanoseconds since UNIX epoch. Matches the
/// helper used elsewhere in the identity module for chronological
/// append-only log keys.
fn hist_seq() -> String {
    let n = Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_else(|| Utc::now().timestamp_millis() * 1_000_000);
    format!("{:020}", n.max(0) as u128)
}
