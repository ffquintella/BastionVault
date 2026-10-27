//! Restore a vault from a backup file with HMAC verification.

use std::io::Read;

use crate::{
    core::Core,
    errors::RvError,
    exchange::sql_gate::{self, SqlGate},
    storage::{Backend, BackendEntry},
};

use super::format;

/// How many frames of a verified payload hold policy documents. Keys are
/// plaintext in a BVBK, so no value is decompressed or decrypted.
fn policy_document_count(payload: &[u8]) -> Result<usize, RvError> {
    let mut cursor = std::io::Cursor::new(payload);
    format::read_header(&mut cursor)?;
    let mut count = 0;
    while let Some((key, _)) = format::read_entry_frame(&mut cursor)? {
        if sql_gate::is_policy_document_key(&key) {
            count += 1;
        }
    }
    Ok(count)
}

/// Restore a backup file into the given backend.
///
/// The HMAC is verified before any data is written to the backend.
/// Returns the number of entries restored. No vault is running here, so the
/// `sql_*` write gate cannot be consulted: [`restore_backup_live`] is the
/// restore for a running vault.
pub async fn restore_backup(
    backend: &dyn Backend,
    hmac_key: &[u8],
    reader: &mut (dyn Read + Send),
) -> Result<u64, RvError> {
    restore_with(backend, hmac_key, reader, None).await
}

/// Restore into a running vault (`sys/restore`, the desktop app). A backup
/// that carries policy documents is refused while the `sql_*` write gate is
/// closed (features/sql-browser.md §13): they are ciphertext here, so
/// whether one names `sql_*` cannot be known before it is written.
pub async fn restore_backup_live(core: &Core, reader: &mut (dyn Read + Send)) -> Result<u64, RvError> {
    let hmac_key = core.barrier.derive_hmac_key()?;
    restore_with(core.physical.as_ref(), &hmac_key, reader, Some(&SqlGate::of(core))).await
}

/// The restore itself; `gate` is consulted after the HMAC check and before
/// the first write.
pub(crate) async fn restore_with(
    backend: &dyn Backend,
    hmac_key: &[u8],
    reader: &mut (dyn Read + Send),
    gate: Option<&SqlGate>,
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

    if let Some(gate) = gate {
        let policies = policy_document_count(payload)?;
        if policies > 0 {
            gate.open_or_reason().await.map_err(|reason| sql_gate::restore_refused(policies, &reason))?;
        }
    }

    // Parse header.
    let mut cursor = std::io::Cursor::new(payload);
    let header = format::read_header(&mut cursor)?;

    // Read and restore entry frames.
    let mut restored = 0u64;
    while let Some((key, value)) = format::read_entry_frame(&mut cursor)? {
        let final_value = if header.compressed {
            zstd::decode_all(value.as_slice()).map_err(|_| RvError::ErrBackupCorrupted)?
        } else {
            value
        };

        let entry = BackendEntry { key, value: final_value };
        backend.put(&entry).await?;
        restored += 1;
    }

    Ok(restored)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::storage::{Backend, BackendEntry};

    /// A physical backend that records every write.
    #[derive(Default)]
    struct Recording {
        puts: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl Backend for Recording {
        async fn list(&self, _prefix: &str) -> Result<Vec<String>, RvError> {
            Ok(Vec::new())
        }
        async fn get(&self, _key: &str) -> Result<Option<BackendEntry>, RvError> {
            Ok(None)
        }
        async fn put(&self, entry: &BackendEntry) -> Result<(), RvError> {
            self.puts.lock().unwrap().push(entry.key.clone());
            Ok(())
        }
        async fn delete(&self, _key: &str) -> Result<(), RvError> {
            Ok(())
        }
    }

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn backup(keys: &[&str]) -> Vec<u8> {
        use hmac::Mac;
        let header = format::BackupHeader {
            version: 1,
            created_at: "2026-10-26T00:00:00Z".into(),
            barrier_type: "chacha20-poly1305".into(),
            entry_count: keys.len() as u64,
            compressed: false,
        };
        let mut payload = Vec::new();
        format::write_header(&mut payload, &header).unwrap();
        for k in keys {
            format::write_entry_frame(&mut payload, k, b"ciphertext").unwrap();
        }
        let mut mac = format::new_hmac(KEY).unwrap();
        mac.update(&payload);
        payload.extend_from_slice(&mac.finalize().into_bytes());
        payload
    }

    /// Regression (sql-browser subsystem 4's open gap): a restore wrote
    /// policy documents past the `sql_*` write gate. Closed, a backup that
    /// carries any is refused before the first write; one that carries none,
    /// and every backup once the gate is open, restores as before.
    #[tokio::test]
    async fn a_closed_gate_refuses_a_backup_carrying_policies_before_any_write() {
        let with_policy = backup(&["namespaces/u1/logical/kv/a", "namespaces/u1/sys/policy/analysts"]);
        let closed = SqlGate::Fixed(Err("node 2: no version record".into()));

        let backend = Arc::new(Recording::default());
        let mut reader = std::io::Cursor::new(with_policy.clone());
        let e = restore_with(backend.as_ref(), KEY, &mut reader, Some(&closed)).await.unwrap_err();
        let RvError::ErrResponseStatus(409, m) = e else { panic!("expected a 409") };
        assert!(m.contains("1 policy document") && m.contains("node 2: no version record"), "{m}");
        assert!(backend.puts.lock().unwrap().is_empty(), "nothing may be written");

        let no_policy = backup(&["namespaces/u1/logical/kv/a", "namespaces/u1/sys/policy-schema/nodes/standalone"]);
        let mut reader = std::io::Cursor::new(no_policy);
        assert_eq!(restore_with(backend.as_ref(), KEY, &mut reader, Some(&closed)).await.unwrap(), 2);

        let open = SqlGate::Fixed(Ok(()));
        let backend = Arc::new(Recording::default());
        let mut reader = std::io::Cursor::new(with_policy.clone());
        assert_eq!(restore_with(backend.as_ref(), KEY, &mut reader, Some(&open)).await.unwrap(), 2);
        assert_eq!(backend.puts.lock().unwrap().len(), 2);

        // A tampered backup is refused on its HMAC before the gate is asked.
        let mut tampered = with_policy;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let mut reader = std::io::Cursor::new(tampered);
        assert!(!matches!(
            restore_with(backend.as_ref(), KEY, &mut reader, Some(&closed)).await,
            Err(RvError::ErrResponseStatus(409, _))
        ));
    }
}
