//! Backup file format: magic, header, entry frames, and HMAC verification.

use std::io::{Read, Write};

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::errors::RvError;

/// Magic bytes identifying a BastionVault backup file.
pub const BACKUP_MAGIC: &[u8; 8] = b"BVBK\x00\x01\x00\x00";

type HmacSha256 = Hmac<Sha256>;

/// Backup file header, serialized as JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupHeader {
    pub version: u32,
    pub created_at: String,
    pub barrier_type: String,
    pub entry_count: u64,
    pub compressed: bool,
}

/// Write the backup file preamble (magic + header).
/// Returns the number of bytes written.
pub fn write_header(writer: &mut dyn Write, header: &BackupHeader) -> Result<usize, RvError> {
    let header_json = serde_json::to_vec(header)?;
    let header_len = (header_json.len() as u32).to_le_bytes();

    writer.write_all(BACKUP_MAGIC)?;
    writer.write_all(&header_len)?;
    writer.write_all(&header_json)?;

    Ok(8 + 4 + header_json.len())
}

/// Read and parse the backup file preamble (magic + header).
pub fn read_header(reader: &mut dyn Read) -> Result<BackupHeader, RvError> {
    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    if &magic != BACKUP_MAGIC {
        return Err(RvError::ErrBackupInvalidMagic);
    }

    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let header_len = u32::from_le_bytes(len_buf) as usize;

    let mut header_buf = vec![0u8; header_len];
    reader.read_exact(&mut header_buf)?;

    let header: BackupHeader = serde_json::from_slice(&header_buf)?;
    if header.version != 1 {
        return Err(RvError::ErrBackupUnsupportedVersion);
    }

    Ok(header)
}

/// Write a single entry frame: `[4B key_len][key][4B value_len][value]`.
pub fn write_entry_frame(writer: &mut dyn Write, key: &str, value: &[u8]) -> Result<(), RvError> {
    let key_bytes = key.as_bytes();
    writer.write_all(&(key_bytes.len() as u32).to_le_bytes())?;
    writer.write_all(key_bytes)?;
    writer.write_all(&(value.len() as u32).to_le_bytes())?;
    writer.write_all(value)?;
    Ok(())
}

/// Read a single entry frame. Returns `None` at EOF.
pub fn read_entry_frame(reader: &mut dyn Read) -> Result<Option<(String, Vec<u8>)>, RvError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let key_len = u32::from_le_bytes(len_buf) as usize;

    let mut key_buf = vec![0u8; key_len];
    reader.read_exact(&mut key_buf)?;
    let key = String::from_utf8(key_buf).map_err(|_| RvError::ErrBackupCorrupted)?;

    reader.read_exact(&mut len_buf)?;
    let value_len = u32::from_le_bytes(len_buf) as usize;

    let mut value_buf = vec![0u8; value_len];
    reader.read_exact(&mut value_buf)?;

    Ok(Some((key, value_buf)))
}

/// Create a new HMAC-SHA256 context from the given key.
pub fn new_hmac(key: &[u8]) -> Result<HmacSha256, RvError> {
    HmacSha256::new_from_slice(key).map_err(|_| RvError::ErrBackupHmacFailed)
}

/// Verify an HMAC-SHA256 digest.
pub fn verify_hmac(key: &[u8], data: &[u8], expected: &[u8]) -> Result<(), RvError> {
    let mut mac = new_hmac(key)?;
    mac.update(data);
    mac.verify_slice(expected).map_err(|_| RvError::ErrBackupHmacMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_round_trip() {
        let header = BackupHeader {
            version: 1,
            created_at: "2026-04-15T12:00:00Z".to_string(),
            barrier_type: "chacha20-poly1305".to_string(),
            entry_count: 42,
            compressed: false,
        };

        let mut buf = Vec::new();
        write_header(&mut buf, &header).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let parsed = read_header(&mut cursor).unwrap();

        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.entry_count, 42);
        assert_eq!(parsed.barrier_type, "chacha20-poly1305");
        assert!(!parsed.compressed);
    }

    #[test]
    fn test_entry_frame_round_trip() {
        let mut buf = Vec::new();
        write_entry_frame(&mut buf, "secret/myapp/db", b"encrypted_data_here").unwrap();
        write_entry_frame(&mut buf, "secret/myapp/api", b"more_encrypted").unwrap();

        let mut cursor = std::io::Cursor::new(&buf);

        let (key1, val1) = read_entry_frame(&mut cursor).unwrap().unwrap();
        assert_eq!(key1, "secret/myapp/db");
        assert_eq!(val1, b"encrypted_data_here");

        let (key2, val2) = read_entry_frame(&mut cursor).unwrap().unwrap();
        assert_eq!(key2, "secret/myapp/api");
        assert_eq!(val2, b"more_encrypted");

        assert!(read_entry_frame(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn test_invalid_magic() {
        let buf = b"NOTABACKUP";
        let mut cursor = std::io::Cursor::new(&buf[..]);
        let result = read_header(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_hmac_verify() {
        let key = b"test_hmac_key_for_backup";
        let data = b"some data to authenticate";

        let mut mac = new_hmac(key).unwrap();
        mac.update(data);
        let digest = mac.finalize().into_bytes();

        assert!(verify_hmac(key, data, &digest).is_ok());
        assert!(verify_hmac(key, b"tampered data", &digest).is_err());
    }
}
