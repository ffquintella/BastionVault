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
    /// Why the plugin was quarantined while still registered (T62: a host
    /// call outside its manifest). Empty for a delete, and for every record
    /// written before the field existed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

impl QuarantineRecord {
    /// The operator-facing reason the plugin's mounts are refused.
    pub fn describe(&self, name: &str) -> String {
        if self.reason.is_empty() {
            format!(
                "plugin `{name}` is quarantined (deleted at unix-secs {}; last active version `{}`)",
                self.quarantined_at_unix_secs, self.last_active_version
            )
        } else {
            format!(
                "plugin `{name}` is quarantined at unix-secs {} (version `{}`): {}",
                self.quarantined_at_unix_secs, self.last_active_version, self.reason
            )
        }
    }
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
    quarantine_for(storage, name, actor_entity_id, last_active_version, "").await
}

/// Quarantine a plugin, recording why. The marker refuses every mount and
/// invocation of the plugin until the operator re-registers it.
pub async fn quarantine_for(
    storage: &dyn Storage,
    name: &str,
    actor_entity_id: &str,
    last_active_version: &str,
    reason: &str,
) -> Result<(), RvError> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let rec = QuarantineRecord {
        quarantined_at_unix_secs: now,
        actor_entity_id: actor_entity_id.to_string(),
        last_active_version: last_active_version.to_string(),
        reason: reason.to_string(),
    };
    storage.put(&StorageEntry { key: key(name), value: serde_json::to_vec(&rec)? }).await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_written_before_the_reason_field_still_read() {
        let old = br#"{"quarantined_at_unix_secs":7,"actor_entity_id":"","last_active_version":"0.1.0"}"#;
        let rec: QuarantineRecord = serde_json::from_slice(old).unwrap();
        assert!(rec.reason.is_empty());
        assert!(rec.describe("p").contains("deleted at unix-secs 7"));
        // And a delete still writes the old shape.
        let v = serde_json::to_value(&rec).unwrap();
        assert!(v.get("reason").is_none());
    }

    #[test]
    fn a_reason_is_reported() {
        let rec = QuarantineRecord { reason: "called dynamic_pool_checkout".into(), ..Default::default() };
        assert!(rec.describe("p").ends_with("called dynamic_pool_checkout"));
    }
}
