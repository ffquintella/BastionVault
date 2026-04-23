//! File-operation audit trail.
//!
//! Captures file lifecycle events (create, update, delete, restore)
//! in a system-view-backed append log so they surface on the admin
//! Audit page alongside policy / identity-group / asset-group /
//! share / user events. The file module also keeps a per-file
//! history under its own mount (`hist/<id>/…`) for the per-file
//! timeline UI; that view isn't reachable from the system backend
//! without routing a sub-request, which is why this parallel store
//! exists.
//!
//! Storage:
//!   sys/files-audit/<20-digit-nanos> -> FileAuditEntry JSON
//!
//! Mirrors `UserAuditStore`: flat, timestamp-keyed, immutable
//! entries, cheap prefix-walk to list.
//!
//! Constructed lazily by the file-module handlers on first access
//! (no post_unseal wiring needed). The underlying `BarrierView` is
//! an `Arc`, so re-deriving it on each audit write is cheap.

use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    core::Core,
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

const FILES_AUDIT_SUB_PATH: &str = "files-audit/";

/// One row in the file-operation audit log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileAuditEntry {
    pub ts: String,
    /// `entity_id` of the caller that performed the action, with the
    /// same `caller_audit_actor` fallback as elsewhere in the module:
    /// empty for bare root-token operations becomes `"root"`, or
    /// falls back to the display name when the entity id is missing.
    pub actor_entity_id: String,
    /// `"create" | "update" | "delete" | "restore"`.
    pub op: String,
    /// The file id.
    pub file_id: String,
    /// Snapshot of the human-readable name at the time of the event
    /// (so deleting a file still shows a usable label in the audit UI
    /// even after the meta row is gone).
    #[serde(default)]
    pub name: String,
    /// Optional free-form detail (e.g. `"fields=resource,notes"` on
    /// update, `"content"` on a content-only write, `"v3"` on a
    /// version restore). Surfaced via the aggregator as a `summary`.
    #[serde(default)]
    pub details: String,
}

pub struct FileAuditStore {
    view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl FileAuditStore {
    pub fn from_core(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };
        let view = Arc::new(system_view.new_sub_view(FILES_AUDIT_SUB_PATH));
        Ok(Arc::new(Self { view }))
    }

    /// Append an entry. `ts` is stamped here if empty. Key is
    /// monotonic nanoseconds so `get_keys` + sort yields chronological
    /// order.
    pub async fn append(&self, mut entry: FileAuditEntry) -> Result<(), RvError> {
        if entry.ts.is_empty() {
            entry.ts = Utc::now().to_rfc3339();
        }
        let key = hist_seq();
        let value = serde_json::to_vec(&entry)?;
        self.view.put(&StorageEntry { key, value }).await
    }

    /// Full log, newest first.
    pub async fn list_all(&self) -> Result<Vec<FileAuditEntry>, RvError> {
        let mut keys = self.view.get_keys().await?;
        keys.sort();
        keys.reverse();
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            if let Some(raw) = self.view.get(&k).await? {
                if let Ok(e) = serde_json::from_slice::<FileAuditEntry>(&raw.value) {
                    out.push(e);
                }
            }
        }
        Ok(out)
    }
}

/// 20-digit zero-padded nanoseconds since UNIX epoch. Matches
/// `UserAuditStore::hist_seq` and the file-module's per-file
/// history so append-only logs sort chronologically.
fn hist_seq() -> String {
    let n = Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_else(|| Utc::now().timestamp_millis() * 1_000_000);
    format!("{:020}", n.max(0) as u128)
}
