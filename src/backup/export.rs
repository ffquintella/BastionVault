//! Export decrypted secrets from a vault subtree to JSON format.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    errors::RvError,
    storage::Storage,
};

/// JSON export format for a subtree of secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportData {
    pub version: u32,
    pub created_at: String,
    pub mount: String,
    pub prefix: String,
    pub entries: Vec<ExportEntry>,
}

/// A single exported entry with its decrypted value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    pub key: String,
    pub value: Value,
}

/// Recursively list all keys from storage by walking prefixes.
fn list_all_storage_keys<'a>(
    storage: &'a dyn Storage,
    prefix: &'a str,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<String>, RvError>> + Send + 'a>> {
    Box::pin(async move {
        let mut all_keys = Vec::new();
        let entries = storage.list(prefix).await?;

        for entry in entries {
            let full_path = format!("{prefix}{entry}");
            if entry.ends_with('/') {
                let sub_keys = list_all_storage_keys(storage, &full_path).await?;
                all_keys.extend(sub_keys);
            } else {
                all_keys.push(full_path);
            }
        }

        Ok(all_keys)
    })
}

/// Export secrets from the given storage (barrier-level, decrypted) under a prefix.
///
/// The storage must be the barrier (decrypted) view, not the raw backend.
/// Returns an `ExportData` struct that can be serialized to JSON.
pub async fn export_secrets(
    storage: &dyn Storage,
    mount: &str,
    prefix: &str,
) -> Result<ExportData, RvError> {
    let full_prefix = format!("{mount}{prefix}");
    let all_keys = list_all_storage_keys(storage, &full_prefix).await?;

    let mut entries = Vec::new();
    for key in &all_keys {
        if let Some(entry) = storage.get(key).await? {
            // Try to parse the value as JSON; if it fails, store as base64 string.
            let value = match serde_json::from_slice::<Value>(&entry.value) {
                Ok(v) => v,
                Err(_) => Value::String(base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &entry.value,
                )),
            };

            // Store key relative to the mount.
            let relative_key = key.strip_prefix(mount).unwrap_or(key).to_string();
            entries.push(ExportEntry { key: relative_key, value });
        }
    }

    Ok(ExportData {
        version: 1,
        created_at: chrono::Utc::now().to_rfc3339(),
        mount: mount.to_string(),
        prefix: prefix.to_string(),
        entries,
    })
}
