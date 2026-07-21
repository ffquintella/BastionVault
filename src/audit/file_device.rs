//! Append-only file audit device.
//!
//! Writes one JSON line per entry to a local file. Each write is
//! flushed before the call returns so a crash won't lose the most
//! recent entry. Concurrent writers are serialized by an async
//! mutex around the `File` handle.
//!
//! Config options (`AuditDeviceConfig::options`):
//!   `file_path`        — required. Path to the audit log file.
//!   `log_raw`          — optional bool. When `true`, sensitive fields
//!                        are not HMAC-redacted. Default `false`. Dev only.
//!   `rotate_size_bytes` — optional u64. Size threshold for in-process
//!                        rotation. Default `0` (no size rotation; rely
//!                        on external logrotate + `reload()` via SIGHUP).
//!   `rotate_keep`       — optional u32. Number of historical copies to
//!                        keep when in-process rotation triggers.
//!                        Default `5`.

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
    /// `0` disables in-process rotation (operator runs logrotate
    /// externally and SIGHUPs us, which calls `reload`).
    rotate_size_bytes: u64,
    rotate_keep: u32,
    state: Mutex<FileState>,
}

struct FileState {
    file: File,
    size: u64,
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
        let rotate_size_bytes = options
            .get("rotate_size_bytes")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let rotate_keep = options
            .get("rotate_keep")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(5);

        let path = PathBuf::from(&path_str);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| bv_error_string!(format!("audit: mkdir failed: {e}")))?;
            }
        }

        let file = open_append(&path).await?;
        let size = file
            .metadata()
            .await
            .map(|m| m.len())
            .unwrap_or(0);

        Ok(Arc::new(Self {
            path,
            log_raw,
            rotate_size_bytes,
            rotate_keep,
            state: Mutex::new(FileState { file, size }),
        }))
    }

    pub fn file_path(&self) -> &std::path::Path {
        &self.path
    }

    /// Rotate `path` → `path.1` → `path.2` → ... → `path.{keep}`,
    /// dropping anything beyond `keep`. Best-effort: a failed shift
    /// returns the error to the caller, which keeps writing in
    /// place rather than dropping the entry.
    async fn rotate(&self, state: &mut FileState) -> Result<(), RvError> {
        if self.rotate_keep > 0 {
            let oldest = numbered_path(&self.path, self.rotate_keep);
            let _ = tokio::fs::remove_file(&oldest).await;
            for i in (1..self.rotate_keep).rev() {
                let src = numbered_path(&self.path, i);
                if tokio::fs::try_exists(&src).await.unwrap_or(false) {
                    let dst = numbered_path(&self.path, i + 1);
                    tokio::fs::rename(&src, &dst).await.map_err(|e| {
                        bv_error_string!(format!("audit: rotate rename failed: {e}"))
                    })?;
                }
            }
            tokio::fs::rename(&self.path, numbered_path(&self.path, 1))
                .await
                .map_err(|e| bv_error_string!(format!("audit: rotate rename failed: {e}")))?;
        } else {
            let _ = tokio::fs::remove_file(&self.path).await;
        }

        state.file = open_append(&self.path).await?;
        state.size = 0;
        Ok(())
    }
}

async fn open_append(path: &PathBuf) -> Result<File, RvError> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .map_err(|e| bv_error_string!(format!("audit: open {} failed: {e}", path.display())))
}

fn numbered_path(base: &PathBuf, n: u32) -> PathBuf {
    let mut s = base.as_os_str().to_owned();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

#[maybe_async::maybe_async]
impl AuditDevice for FileAuditDevice {
    fn device_type(&self) -> &str {
        "file"
    }

    async fn log_entry(&self, entry: &AuditEntry) -> Result<(), RvError> {
        let line = serialize_line(entry)?;
        let needed = line.len() as u64 + 1;
        let mut state = self.state.lock().await;

        if self.rotate_size_bytes > 0
            && state.size > 0
            && state.size + needed > self.rotate_size_bytes
        {
            if let Err(e) = self.rotate(&mut state).await {
                // Don't drop the entry — log to stderr (we *are* the
                // audit log; we can't recurse through the log macros
                // to ourselves) and keep writing in place.
                eprintln!(
                    "audit: rotate of {} failed: {e}. Continuing in place.",
                    self.path.display()
                );
            }
        }

        state
            .file
            .write_all(line.as_bytes())
            .await
            .map_err(|e| bv_error_string!(format!("audit: write failed: {e}")))?;
        state
            .file
            .write_all(b"\n")
            .await
            .map_err(|e| bv_error_string!(format!("audit: write failed: {e}")))?;
        state
            .file
            .flush()
            .await
            .map_err(|e| bv_error_string!(format!("audit: flush failed: {e}")))?;
        state.size += needed;
        Ok(())
    }

    async fn flush(&self) -> Result<(), RvError> {
        let mut state = self.state.lock().await;
        state
            .file
            .flush()
            .await
            .map_err(|e| bv_error_string!(format!("audit: flush failed: {e}")))
    }

    /// Re-open the file handle (after external logrotate). Swaps
    /// the inner File with a new append-mode handle at the same
    /// path and resets the running size to whatever's on disk.
    async fn reload(&self) -> Result<(), RvError> {
        let new_file = open_append(&self.path).await?;
        let size = new_file.metadata().await.map(|m| m.len()).unwrap_or(0);
        let mut state = self.state.lock().await;
        state.file = new_file;
        state.size = size;
        Ok(())
    }

    fn source_path(&self) -> Option<std::path::PathBuf> {
        Some(self.path.clone())
    }
}
