//! Backend storage helpers and replay-protection cache.
//!
//! Layout under the engine's per-mount barrier prefix:
//!
//! ```text
//! key/<name>            → JSON(KeyPolicy)
//! used/<name>/<step>    → JSON(UsedEntry)   (replay index, Phase 3)
//! ```
//!
//! All storage I/O goes through `req.storage_*`, which means the
//! barrier (ChaCha20-Poly1305) wraps the bytes at rest.

use serde::{Deserialize, Serialize};

use super::{
    policy::{KeyPolicy, KEY_PREFIX, USED_PREFIX},
    TotpBackendInner,
};
use crate::{
    errors::RvError,
    logical::Request,
    storage::StorageEntry,
};

/// Per-step replay record. `code_hash` lets the validator detect a
/// re-presented code within the same step window even if two
/// different callers pick the same step (paranoia: the (name, step)
/// key alone is enough today, but storing the hash means a future
/// "show me which code was used" audit query is a one-line addition).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsedEntry {
    pub step: u64,
    /// Hex-encoded SHA-256 of the validated code. Not the code
    /// itself — keeps the replay index from being a quick path to
    /// recovering recent codes if the barrier is compromised.
    pub code_hash: String,
    /// Wall-clock seconds (Unix epoch) when the entry was written;
    /// used by the tidy sweep to drop stale rows.
    pub written_at: u64,
}

#[maybe_async::maybe_async]
impl TotpBackendInner {
    pub fn key_storage_path(name: &str) -> String {
        format!("{KEY_PREFIX}{name}")
    }

    pub async fn get_key(
        &self,
        req: &Request,
        name: &str,
    ) -> Result<Option<KeyPolicy>, RvError> {
        match req.storage_get(&Self::key_storage_path(name)).await? {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    pub async fn put_key(
        &self,
        req: &mut Request,
        name: &str,
        policy: &KeyPolicy,
    ) -> Result<(), RvError> {
        let bytes = serde_json::to_vec(policy)?;
        req.storage_put(&StorageEntry {
            key: Self::key_storage_path(name),
            value: bytes,
        })
        .await
    }

    pub async fn delete_key(&self, req: &mut Request, name: &str) -> Result<(), RvError> {
        // Drop the key entry plus any replay-cache rows under it so a
        // subsequent re-create with the same name doesn't inherit a
        // stale "this step was already used" verdict.
        req.storage_delete(&Self::key_storage_path(name)).await?;
        let prefix = format!("{USED_PREFIX}{name}/");
        if let Ok(children) = req.storage_list(&prefix).await {
            for child in children {
                let _ = req.storage_delete(&format!("{prefix}{child}")).await;
            }
        }
        Ok(())
    }

    pub async fn list_keys(&self, req: &Request) -> Result<Vec<String>, RvError> {
        req.storage_list(KEY_PREFIX).await
    }

    // ── Replay cache (Phase 3) ────────────────────────────────────

    pub fn used_storage_path(name: &str, step: u64) -> String {
        format!("{USED_PREFIX}{name}/{step}")
    }

    pub async fn get_used(
        &self,
        req: &Request,
        name: &str,
        step: u64,
    ) -> Result<Option<UsedEntry>, RvError> {
        match req
            .storage_get(&Self::used_storage_path(name, step))
            .await?
        {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    pub async fn put_used(
        &self,
        req: &mut Request,
        name: &str,
        entry: &UsedEntry,
    ) -> Result<(), RvError> {
        let bytes = serde_json::to_vec(entry)?;
        req.storage_put(&StorageEntry {
            key: Self::used_storage_path(name, entry.step),
            value: bytes,
        })
        .await
    }
}

/// Hex SHA-256 of the candidate code, for the replay cache.
pub fn code_hash(code: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(code.as_bytes());
    hex::encode(h.finalize())
}
