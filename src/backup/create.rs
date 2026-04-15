//! Create full vault backups as encrypted blob archives with HMAC integrity.

use std::io::Write;

use hmac::Mac;

use crate::{
    errors::RvError,
    storage::Backend,
};

use super::format::{self, BackupHeader};

/// Create a backup of all data in the backend.
///
/// Data is copied as raw encrypted bytes -- no decryption occurs.
/// The HMAC is keyed with the barrier's HMAC key for integrity verification on restore.
pub async fn create_backup(
    backend: &dyn Backend,
    hmac_key: &[u8],
    writer: &mut dyn Write,
    compressed: bool,
) -> Result<u64, RvError> {
    // First pass: collect all keys and count entries.
    let all_keys = crate::storage::migrate::list_all_keys(backend, "").await?;
    let entry_count = all_keys.len() as u64;

    let header = BackupHeader {
        version: 1,
        created_at: chrono::Utc::now().to_rfc3339(),
        barrier_type: "chacha20-poly1305".to_string(),
        entry_count,
        compressed,
    };

    // We'll build the entire payload in memory so we can compute the HMAC over it.
    let mut payload = Vec::new();
    format::write_header(&mut payload, &header)?;

    // Second pass: read each entry and write frames.
    let mut actually_copied = 0u64;
    for key in &all_keys {
        if let Some(entry) = backend.get(key).await? {
            if compressed {
                let compressed_value = zstd::encode_all(entry.value.as_slice(), 3)
                    .map_err(|_| RvError::ErrBackupCorrupted)?;
                format::write_entry_frame(&mut payload, key, &compressed_value)?;
            } else {
                format::write_entry_frame(&mut payload, key, &entry.value)?;
            }
            actually_copied += 1;
        }
    }

    // Compute HMAC over the entire payload.
    let mut mac = format::new_hmac(hmac_key)?;
    mac.update(&payload);
    let digest = mac.finalize().into_bytes();

    // Write payload + HMAC to the output writer.
    writer.write_all(&payload)?;
    writer.write_all(&digest)?;
    writer.flush()?;

    Ok(actually_copied)
}
