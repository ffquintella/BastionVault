//! Backend-to-backend migration utility.
//!
//! Copies all entries from a source storage backend to a destination backend.
//! Data is copied as-is (encrypted blobs), so the same unseal keys work after migration.

use std::sync::Arc;

use crate::errors::RvError;
use crate::storage::Backend;

/// Result of a migration operation.
pub struct MigrateResult {
    pub entries_copied: usize,
    pub entries_skipped: usize,
}

/// Recursively list all keys from a backend by walking prefixes.
pub fn list_all_keys<'a>(
    backend: &'a dyn Backend,
    prefix: &'a str,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<String>, RvError>> + Send + 'a>> {
    Box::pin(async move {
        let mut all_keys = Vec::new();
        let entries = backend.list(prefix).await?;

        for entry in entries {
            let full_path = format!("{prefix}{entry}");
            if entry.ends_with('/') {
                let sub_keys = list_all_keys(backend, &full_path).await?;
                all_keys.extend(sub_keys);
            } else {
                all_keys.push(full_path);
            }
        }

        Ok(all_keys)
    })
}

/// Copy all entries from source backend to destination backend.
///
/// Data is copied as raw encrypted bytes -- no decryption occurs.
/// The destination must be empty or the caller accepts overwrites.
#[maybe_async::maybe_async]
pub async fn migrate_backend(
    source: &Arc<dyn Backend>,
    destination: &Arc<dyn Backend>,
) -> Result<MigrateResult, RvError> {
    let all_keys = list_all_keys(source.as_ref(), "").await?;

    let mut copied = 0usize;
    let mut skipped = 0usize;

    for key in &all_keys {
        match source.get(key).await? {
            Some(entry) => {
                destination.put(&entry).await?;
                copied += 1;
            }
            None => {
                // Key existed in list but get returned None (race condition or directory marker)
                skipped += 1;
            }
        }
    }

    Ok(MigrateResult { entries_copied: copied, entries_skipped: skipped })
}
