//! SSH CA configuration audit trail.
//!
//! Captures lifecycle events for the SSH engine's signing CA — create
//! (write `config/ca`, classical or PQC) and delete — in a
//! system-view-backed append log so they surface on the admin Audit
//! page alongside policy / identity-group / asset-group / share /
//! user / file / login events.
//!
//! Storage:
//!   sys/ssh-ca-audit/<20-digit-nanos> -> SshCaAuditEntry JSON
//!
//! Mirrors `FileAuditStore` / `LoginAuditStore`: flat, timestamp-keyed,
//! immutable entries, cheap prefix-walk to list. Constructed lazily by
//! the SSH-module handlers on first access (no post_unseal wiring
//! needed). The underlying `BarrierView` is an `Arc`, so re-deriving it
//! on each audit write is cheap.

use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    core::Core,
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

const SSH_CA_AUDIT_SUB_PATH: &str = "ssh-ca-audit/";

/// One row in the SSH CA audit log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SshCaAuditEntry {
    pub ts: String,
    /// `entity_id` of the caller, with the same `caller_audit_actor`
    /// fallback used elsewhere (display name, then empty → "root" at
    /// the aggregator).
    pub actor_entity_id: String,
    /// `"create" | "delete"`.
    pub op: String,
    /// Mount path the CA lives under (e.g. `"ssh/"`), so the audit row
    /// points at the right engine when multiple SSH mounts exist.
    #[serde(default)]
    pub mount: String,
    /// CA algorithm at the time of the event (e.g. `"ssh-ed25519"` or
    /// `"ssh-mldsa65@openssh.com"`). Empty on delete.
    #[serde(default)]
    pub algorithm: String,
}

pub struct SshCaAuditStore {
    view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl SshCaAuditStore {
    pub fn from_core(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };
        let view = Arc::new(system_view.new_sub_view(SSH_CA_AUDIT_SUB_PATH));
        Ok(Arc::new(Self { view }))
    }

    /// Append an entry. `ts` is stamped here if empty. Key is monotonic
    /// nanoseconds so `get_keys` + sort yields chronological order.
    pub async fn append(&self, mut entry: SshCaAuditEntry) -> Result<(), RvError> {
        if entry.ts.is_empty() {
            entry.ts = Utc::now().to_rfc3339();
        }
        let key = hist_seq();
        let value = serde_json::to_vec(&entry)?;
        self.view.put(&StorageEntry { key, value }).await
    }

    /// Full log, newest first.
    pub async fn list_all(&self) -> Result<Vec<SshCaAuditEntry>, RvError> {
        let mut keys = self.view.get_keys().await?;
        keys.sort();
        keys.reverse();
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            if let Some(raw) = self.view.get(&k).await? {
                if let Ok(e) = serde_json::from_slice::<SshCaAuditEntry>(&raw.value) {
                    out.push(e);
                }
            }
        }
        Ok(out)
    }
}

/// 20-digit zero-padded nanoseconds since UNIX epoch. Matches the
/// other append-only audit logs so they sort chronologically.
fn hist_seq() -> String {
    let n = Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_else(|| Utc::now().timestamp_millis() * 1_000_000);
    format!("{:020}", n.max(0) as u128)
}
