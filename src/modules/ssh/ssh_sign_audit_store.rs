//! SSH certificate-signing audit trail.
//!
//! Captures every successful `POST /v1/ssh/sign/:role` — the issuance
//! of an OpenSSH user/host certificate (classical Ed25519 or PQC
//! ML-DSA-65) — in a system-view-backed append log so issued certs
//! surface on the admin Audit page alongside the CA lifecycle, policy,
//! identity-group, share, user, file and login events.
//!
//! Storage:
//!   sys/ssh-sign-audit/<20-digit-nanos> -> SshSignAuditEntry JSON
//!
//! Mirrors `SshCaAuditStore` / `FileAuditStore` / `LoginAuditStore`:
//! flat, timestamp-keyed, immutable entries, cheap prefix-walk to list.
//! Constructed lazily by the SSH-module handlers on first access (no
//! post_unseal wiring needed). The serial is recorded so revocation /
//! forensics has a stable identifier tying the audit row to a cert.

use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    core::Core,
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

const SSH_SIGN_AUDIT_SUB_PATH: &str = "ssh-sign-audit/";

/// One row in the SSH sign audit log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SshSignAuditEntry {
    pub ts: String,
    /// `entity_id` of the caller, with the same `caller_audit_actor`
    /// fallback used elsewhere (display name, then empty → "root" at
    /// the aggregator).
    pub actor_entity_id: String,
    /// Always `"sign"` today; kept as a field so a future
    /// sign-denied / sign-renew distinction stays additive.
    pub op: String,
    /// Mount path the engine lives under (e.g. `"ssh/"`), so the audit
    /// row points at the right engine when multiple SSH mounts exist.
    #[serde(default)]
    pub mount: String,
    /// Role the cert was signed under.
    #[serde(default)]
    pub role: String,
    /// Principals baked into the cert, comma-joined.
    #[serde(default)]
    pub principals: String,
    /// `"user"` or `"host"`.
    #[serde(default)]
    pub cert_type: String,
    /// Cert serial as 16-hex-digit string (matches the `serial_number`
    /// returned to the caller), so an audit row maps to a specific
    /// issued certificate.
    #[serde(default)]
    pub serial: String,
    /// Signing algorithm (`"ssh-ed25519"` or
    /// `"ssh-mldsa65@openssh.com"`).
    #[serde(default)]
    pub algorithm: String,
}

pub struct SshSignAuditStore {
    view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl SshSignAuditStore {
    pub fn from_core(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };
        let view = Arc::new(system_view.new_sub_view(SSH_SIGN_AUDIT_SUB_PATH));
        Ok(Arc::new(Self { view }))
    }

    /// Append an entry. `ts` is stamped here if empty. Key is monotonic
    /// nanoseconds so `get_keys` + sort yields chronological order.
    pub async fn append(&self, mut entry: SshSignAuditEntry) -> Result<(), RvError> {
        if entry.ts.is_empty() {
            entry.ts = Utc::now().to_rfc3339();
        }
        let key = hist_seq();
        let value = serde_json::to_vec(&entry)?;
        self.view.put(&StorageEntry { key, value }).await
    }

    /// Full log, newest first.
    pub async fn list_all(&self) -> Result<Vec<SshSignAuditEntry>, RvError> {
        let mut keys = self.view.get_keys().await?;
        keys.sort();
        keys.reverse();
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            if let Some(raw) = self.view.get(&k).await? {
                if let Ok(e) = serde_json::from_slice::<SshSignAuditEntry>(&raw.value) {
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
