//! Quarantined-plugin tracking — Phase 5.7.
//!
//! Spec ([features/plugin-system.md](../../features/plugin-system.md)
//! § Security Considerations): "Disabling a plugin does not delete its
//! data. Mounts using a deleted plugin enter a `quarantined` state;
//! the storage prefix is preserved." The catalog's `delete` semantics
//! today purge versioned + legacy + active + config records but
//! leave the per-plugin **data prefix** (`core/plugins/<name>/data/`)
//! intact — this module records the quarantine flag so a re-register
//! of the same name picks up where it left off, and so mounts that
//! still reference the deleted plugin can present a clear
//! "quarantined: register the plugin again to recover" error rather
//! than a generic "unknown plugin."

use serde::{Deserialize, Serialize};

use crate::{
    errors::RvError,
    storage::{Storage, StorageEntry},
};

/// Storage key prefix for quarantine markers. One key per quarantined
/// plugin name; presence = quarantined, absence = active or never-existed.
const PREFIX: &str = "core/plugins/engine/quarantine/";

/// Quarantine record. Records the timestamp of the delete + the actor
/// (when the audit-broadcaster context surfaces it; empty otherwise)
/// so an auditor can answer "who quarantined `<plugin>` and when?"
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub quarantined_at_unix_secs: u64,
    #[serde(default)]
    pub actor_entity_id: String,
    /// Last-known active version before delete — operators re-uploading
    /// the same plugin can use this to confirm they're recovering the
    /// same code.
    #[serde(default)]
    pub last_active_version: String,
}

fn key(name: &str) -> String {
    format!("{PREFIX}{name}")
}

pub async fn quarantine(
    storage: &dyn Storage,
    name: &str,
    actor_entity_id: &str,
    last_active_version: &str,
) -> Result<(), RvError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let rec = QuarantineRecord {
        quarantined_at_unix_secs: now,
        actor_entity_id: actor_entity_id.to_string(),
        last_active_version: last_active_version.to_string(),
    };
    storage
        .put(&StorageEntry {
            key: key(name),
            value: serde_json::to_vec(&rec)?,
        })
        .await
}

pub async fn lookup(storage: &dyn Storage, name: &str) -> Result<Option<QuarantineRecord>, RvError> {
    match storage.get(&key(name)).await? {
        None => Ok(None),
        Some(entry) => Ok(serde_json::from_slice(&entry.value).ok()),
    }
}

/// Clear the quarantine marker. Called by the catalog on `put` when a
/// previously-quarantined name is re-registered — the new version is
/// active, the old data prefix is preserved, the marker goes away.
pub async fn clear(storage: &dyn Storage, name: &str) -> Result<(), RvError> {
    storage.delete(&key(name)).await
}

pub async fn list(storage: &dyn Storage) -> Result<Vec<String>, RvError> {
    let entries = storage.list(PREFIX).await.unwrap_or_default();
    Ok(entries.into_iter().map(|e| e.trim_end_matches('/').to_string()).collect())
}
