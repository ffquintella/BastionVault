//! Append-only file audit device.
//!
//! Writes one JSON line per entry to a local file. Each write is
//! flushed before the call returns so a crash won't lose the most
//! recent entry. Concurrent writers are serialized by an async
//! mutex around the `File` handle.
//!
//! Config options (`AuditDeviceConfig::options`):
//!   `file_path`  — required. Path to the audit log file.
//!   `log_raw`    — optional bool. When `true`, sensitive fields
//!                  are not HMAC-redacted. Default `false`. Dev only.

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use tokio::{
    fs::{File, OpenOptions},
    io::AsyncWriteExt,
    sync::Mutex,
};

use super::{
    entry::{serialize_line, AuditEntry},
    AuditDevice,
};
use crate::{bv_error_string, errors::RvError};

pub struct FileAuditDevice {
    path: PathBuf,
    /// Whether this device persists raw (non-redacted) entries.
    /// Stored so operators can confirm via `list`; the broker uses
    /// it when calling `AuditEntry::from_request`.
    pub log_raw: bool,
    file: Mutex<File>,
}

impl FileAuditDevice {
    /// Parse an options map, open the file in append mode, and
    /// return a ready-to-use device. Creates the file (and parent
    /// directories) if they don't exist.
    pub async fn new(options: &HashMap<String, String>) -> Result<Arc<Self>, RvError> {
        let path_str = options
            .get("file_path")
            .cloned()
            .ok_or_else(|| bv_error_string!("file audit device requires `file_path`"))?;
        let log_raw = options
            .get("log_raw")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let path = PathBuf::from(&path_str);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| bv_error_string!(format!("audit: mkdir failed: {e}")))?;
            }
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .map_err(|e| bv_error_string!(format!("audit: open {} failed: {e}", path.display())))?;

        Ok(Arc::new(Self {
            path,
            log_raw,
            file: Mutex::new(file),
        }))
    }

    pub fn file_path(&self) -> &std::path::Path {
        &self.path
    }
}

#[maybe_async::maybe_async]
impl AuditDevice for FileAuditDevice {
    fn device_type(&self) -> &str {
        "file"
    }

    async fn log_entry(&self, entry: &AuditEntry) -> Result<(), RvError> {
        let line = serialize_line(entry)?;
        let mut f = self.file.lock().await;
        f.write_all(line.as_bytes())
            .await
            .map_err(|e| bv_error_string!(format!("audit: write failed: {e}")))?;
        f.write_all(b"\n")
            .await
            .map_err(|e| bv_error_string!(format!("audit: write failed: {e}")))?;
        f.flush()
            .await
            .map_err(|e| bv_error_string!(format!("audit: flush failed: {e}")))?;
        Ok(())
    }

    async fn flush(&self) -> Result<(), RvError> {
        let mut f = self.file.lock().await;
        f.flush()
            .await
            .map_err(|e| bv_error_string!(format!("audit: flush failed: {e}")))
    }

    /// Re-open the file handle (after logrotate). Swaps the inner
    /// File with a new append-mode handle at the same path.
    async fn reload(&self) -> Result<(), RvError> {
        let new_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .map_err(|e| bv_error_string!(format!("audit: reopen failed: {e}")))?;
        let mut guard = self.file.lock().await;
        *guard = new_file;
        Ok(())
    }
}
