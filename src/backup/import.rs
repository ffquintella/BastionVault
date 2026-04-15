//! Import decrypted secrets from JSON into a vault.

use crate::{
    errors::RvError,
    storage::{Storage, StorageEntry},
};

use super::export::ExportData;

/// Result of an import operation.
pub struct ImportResult {
    pub imported: u64,
    pub skipped: u64,
}

/// Import secrets from an `ExportData` into the given storage (barrier-level).
///
/// The storage must be the barrier (decrypted) view. Entries are written under `mount`.
/// If `force` is true, existing entries are overwritten; otherwise they are skipped.
pub async fn import_secrets(
    storage: &dyn Storage,
    mount: &str,
    export: &ExportData,
    force: bool,
) -> Result<ImportResult, RvError> {
    let mut imported = 0u64;
    let mut skipped = 0u64;

    for entry in &export.entries {
        let full_key = format!("{mount}{}", entry.key);

        // Check if entry already exists when not forcing.
        if !force && storage.get(&full_key).await?.is_some() {
            skipped += 1;
            continue;
        }

        let value_bytes = serde_json::to_vec(&entry.value)?;
        let storage_entry = StorageEntry { key: full_key, value: value_bytes };
        storage.put(&storage_entry).await?;
        imported += 1;
    }

    Ok(ImportResult { imported, skipped })
}
