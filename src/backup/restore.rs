//! Restore a vault from a backup file with HMAC verification.

use std::io::Read;

use crate::{
    errors::RvError,
    storage::{Backend, BackendEntry},
};

use super::format;

/// Restore a backup file into the given backend.
///
/// The HMAC is verified before any data is written to the backend.
/// Returns the number of entries restored.
pub async fn restore_backup(
    backend: &dyn Backend,
    hmac_key: &[u8],
    reader: &mut (dyn Read + Send),
) -> Result<u64, RvError> {
    // Read entire file into memory for HMAC verification.
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;

    if data.len() < 32 {
        return Err(RvError::ErrBackupCorrupted);
    }

    // Split payload and HMAC (last 32 bytes).
    let (payload, expected_hmac) = data.split_at(data.len() - 32);

    // Verify HMAC before touching the backend.
    format::verify_hmac(hmac_key, payload, expected_hmac)?;

    // Parse header.
    let mut cursor = std::io::Cursor::new(payload);
    let header = format::read_header(&mut cursor)?;

    // Read and restore entry frames.
    let mut restored = 0u64;
    while let Some((key, value)) = format::read_entry_frame(&mut cursor)? {
        let final_value = if header.compressed {
            zstd::decode_all(value.as_slice())
                .map_err(|_| RvError::ErrBackupCorrupted)?
        } else {
            value
        };

        let entry = BackendEntry { key, value: final_value };
        backend.put(&entry).await?;
        restored += 1;
    }

    Ok(restored)
}
