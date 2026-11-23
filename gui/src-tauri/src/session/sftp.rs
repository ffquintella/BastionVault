//! SFTP session driver (features/sftp-connect.md).
//!
//! Same SSH transport as `session::ssh` — the connection, host-key check and
//! authentication are [`super::ssh::connect_authenticated`] — but the channel
//! carries the `sftp` subsystem instead of a PTY. The live [`SftpSession`]
//! sits in `AppState::connect_sessions` as [`super::SessionState::Sftp`].

//! The dual-pane window drives it through the `sftp_*` commands
//! (`commands::connect_sftp`), each of which first checks that the calling
//! window holds the session. The listing rules, the transfer engine and the
//! local pane are shared with SMB in [`super::file_transfer`]; this module is
//! the SFTP side of its [`RemoteFs`] trait.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use russh::client;
use russh_sftp::client::SftpSession;
use serde::Serialize;
use tauri::AppHandle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::file_transfer::{
    is_safe_entry_name, remote_join, remote_parent, Entry, EntryKind, Listing, RemoteFs, RemoteReader, RemoteWriter,
    SourceKind,
};
use super::ssh::{connect_authenticated, new_token, ClosedPayload, HostKeyHandler, SshCredential};
use super::{SessionCleanup, SessionState};

pub struct SftpOpenArgs {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub credential: SshCredential,
    /// `SHA256:<base64>`; empty = trust on first use (logged).
    pub host_key_fingerprint: String,
    pub label: String,
    pub on_close: Option<SessionCleanup>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SftpOpenOutcome {
    pub token: String,
    pub closed_event: String,
    /// The remote folder the session starts in (`realpath(".")`).
    pub remote_home: String,
}

/// One live SFTP session.
pub struct SftpSessionState {
    pub sftp: Arc<SftpSession>,
    handle: Arc<client::Handle<HostKeyHandler>>,
    pub on_close: Option<SessionCleanup>,
    /// Cancel flags of the transfers in flight, by transfer id.
    pub transfers: Arc<std::sync::Mutex<HashMap<String, Arc<AtomicBool>>>>,
}

impl SftpSessionState {
    /// Cancel every transfer and close the SSH connection. Called once, by
    /// the drop path, after the entry left the registry.
    pub fn shut_down(self) {
        if let Ok(map) = self.transfers.lock() {
            for flag in map.values() {
                flag.store(true, Ordering::SeqCst);
            }
        }
        let handle = self.handle;
        let sftp = self.sftp;
        tokio::spawn(async move {
            let _ = sftp.close().await;
            let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "").await;
        });
    }
}

pub fn closed_event_name(token: &str) -> String {
    super::ssh::closed_event_name(token)
}

/// Dial, authenticate, start the `sftp` subsystem and register the session.
pub async fn open_sftp_session(
    app: AppHandle,
    state: &crate::state::AppState,
    args: SftpOpenArgs,
) -> Result<SftpOpenOutcome, String> {
    let (handle, _disconnect) = connect_authenticated(
        &args.host,
        args.port,
        &args.username,
        args.credential,
        &args.host_key_fingerprint,
        "resource-connect/sftp",
    )
    .await?;
    let channel = handle.channel_open_session().await.map_err(|e| format!("channel_open_session: {e}"))?;
    channel.request_subsystem(true, "sftp").await.map_err(|e| format!("sftp: subsystem request failed: {e}"))?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| format!("sftp: the server did not start an SFTP session: {e}"))?;
    let remote_home = sftp.canonicalize(".").await.unwrap_or_else(|_| "/".to_string());

    let token = new_token();
    let closed_event = closed_event_name(&token);
    let handle = Arc::new(handle);
    {
        let mut sessions = state.connect_sessions.lock().await;
        sessions.insert(
            token.clone(),
            SessionState::Sftp(SftpSessionState {
                sftp: Arc::new(sftp),
                handle: Arc::clone(&handle),
                on_close: args.on_close.clone(),
                transfers: Arc::default(),
            }),
        );
    }
    spawn_disconnect_watch(app, token.clone(), closed_event.clone(), handle);
    log::info!(
        "resource-connect/sftp: opened session token={token} label={} ({}:{})",
        args.label,
        args.host,
        args.port
    );
    Ok(SftpOpenOutcome { token, closed_event, remote_home })
}

/// Tell the window when the connection drops underneath it. Ends quietly
/// once the session left the registry (an operator close).
fn spawn_disconnect_watch(
    app: AppHandle,
    token: String,
    closed_event: String,
    handle: Arc<client::Handle<HostKeyHandler>>,
) {
    use tauri::Manager;
    tokio::spawn(async move {
        let events = super::routing::SessionEvents::new(app.clone(), token.clone());
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let Some(state) = app.try_state::<crate::state::AppState>() else { return };
            if !state.connect_sessions.lock().await.contains_key(&token) {
                return;
            }
            if handle.is_closed() {
                log::info!("resource-connect/sftp: transport closed for token={token}");
                let payload = ClosedPayload { reason: "ssh transport closed".into() };
                events.emit(&closed_event, payload).await;
                return;
            }
        }
    });
}

// ── The SFTP side of the dual-pane window ────────────────────────────

/// A remote path as sent by the window: any string without NUL.
fn check_remote_path(path: &str) -> Result<(), String> {
    if path.is_empty() || path.contains('\0') {
        return Err("sftp: invalid remote path".into());
    }
    Ok(())
}

fn remote_kind(meta: &russh_sftp::client::fs::Metadata) -> EntryKind {
    if meta.is_symlink() {
        EntryKind::Symlink
    } else if meta.is_dir() {
        EntryKind::Dir
    } else if meta.is_regular() {
        EntryKind::File
    } else {
        EntryKind::Other
    }
}

#[async_trait::async_trait]
impl RemoteFs for SftpSession {
    fn protocol(&self) -> &'static str {
        "sftp"
    }

    fn normalize(&self, path: &str) -> Result<String, String> {
        check_remote_path(path)?;
        Ok(path.to_string())
    }

    fn is_valid_name(&self, name: &str) -> bool {
        is_safe_entry_name(name)
    }

    async fn home(&self) -> Result<String, String> {
        self.canonicalize(".").await.map_err(|e| format!("sftp: {e}"))
    }

    async fn list(&self, path: &str) -> Result<Listing, String> {
        check_remote_path(path)?;
        let canonical = self.canonicalize(path).await.map_err(|e| format!("sftp: {path}: {e}"))?;
        let dir = self.read_dir(canonical.clone()).await.map_err(|e| format!("sftp: list {canonical}: {e}"))?;
        let mut entries = Vec::new();
        let mut skipped_unsafe = 0;
        for item in dir {
            let name = item.file_name();
            if name == "." || name == ".." {
                continue;
            }
            if !is_safe_entry_name(&name) {
                skipped_unsafe += 1;
                continue;
            }
            let meta = item.metadata();
            let kind = remote_kind(&meta);
            let target_kind = if kind == EntryKind::Symlink {
                match self.metadata(remote_join(&canonical, &name)).await {
                    Ok(t) => remote_kind(&t),
                    Err(_) => EntryKind::Other,
                }
            } else {
                kind
            };
            entries.push(Entry {
                name,
                kind,
                target_kind,
                size: meta.size.unwrap_or(0),
                mtime: meta.mtime.map(u64::from),
                permissions: meta.permissions,
            });
        }
        if skipped_unsafe > 0 {
            log::warn!("resource-connect/sftp: {canonical}: {skipped_unsafe} entries with unsafe names hidden");
        }
        Ok(Listing { path: canonical, entries, skipped_unsafe })
    }

    async fn mkdir(&self, parent: &str, name: &str) -> Result<String, String> {
        check_remote_path(parent)?;
        if !is_safe_entry_name(name) {
            return Err(format!("sftp: `{}` is not a valid folder name", name.escape_debug()));
        }
        let path = remote_join(parent, name);
        self.create_dir(path.clone()).await.map_err(|e| format!("sftp: create {path}: {e}"))?;
        Ok(path)
    }

    async fn rename(&self, path: &str, new_name: &str) -> Result<String, String> {
        check_remote_path(path)?;
        if !is_safe_entry_name(new_name) {
            return Err(format!("sftp: `{}` is not a valid name", new_name.escape_debug()));
        }
        let target = remote_join(remote_parent(path), new_name);
        if self.try_exists(target.clone()).await.unwrap_or(false) {
            return Err(format!("sftp: {target} already exists"));
        }
        SftpSession::rename(self, path, target.clone()).await.map_err(|e| format!("sftp: rename {path}: {e}"))?;
        Ok(target)
    }

    /// Never recursive: a folder with content is refused by the server, and
    /// that refusal is reported.
    async fn remove(&self, path: &str) -> Result<(), String> {
        check_remote_path(path)?;
        let meta = self.symlink_metadata(path).await.map_err(|e| format!("sftp: {path}: {e}"))?;
        if meta.is_dir() {
            self.remove_dir(path)
                .await
                .map_err(|e| format!("sftp: remove folder {path}: {e} (only empty folders can be removed)"))
        } else {
            SftpSession::remove_file(self, path).await.map_err(|e| format!("sftp: remove {path}: {e}"))
        }
    }

    async fn exists(&self, path: &str) -> Result<bool, String> {
        Ok(self.try_exists(path.to_string()).await.unwrap_or(false))
    }

    async fn source_kind(&self, path: &str) -> Result<SourceKind, String> {
        let lmeta = self.symlink_metadata(path).await.map_err(|e| format!("sftp: {path}: {e}"))?;
        let meta = if lmeta.is_symlink() {
            self.metadata(path).await.map_err(|e| format!("sftp: {path}: dangling symlink ({e})"))?
        } else {
            lmeta.clone()
        };
        Ok(if meta.is_dir() {
            if lmeta.is_symlink() {
                SourceKind::Skip("symlinked folder")
            } else {
                SourceKind::Dir
            }
        } else if meta.is_regular() {
            SourceKind::File(meta.size.unwrap_or(0))
        } else {
            SourceKind::Skip("not a regular file")
        })
    }

    /// Names only: each child's kind is read (without following a symlinked
    /// folder) when the planner reaches it, after its name was validated.
    async fn children(&self, dir: &str) -> Result<Vec<(String, Option<SourceKind>)>, String> {
        let rd = self.read_dir(dir.to_string()).await.map_err(|e| format!("sftp: list {dir}: {e}"))?;
        Ok(rd.map(|item| (item.file_name(), None)).collect())
    }

    async fn ensure_dir(&self, path: &str) -> Result<(), String> {
        match self.symlink_metadata(path.to_string()).await {
            Ok(m) if m.is_dir() => Ok(()),
            Ok(_) => Err(format!("sftp: {path} exists and is not a folder")),
            Err(_) => self.create_dir(path.to_string()).await.map_err(|e| format!("sftp: create {path}: {e}")),
        }
    }

    async fn open_read(&self, path: &str) -> Result<Box<dyn RemoteReader>, String> {
        let file = self.open(path.to_string()).await.map_err(|e| format!("sftp: open {path}: {e}"))?;
        Ok(Box::new(SftpFile { file, path: path.to_string() }))
    }

    async fn create_write(&self, path: &str) -> Result<Box<dyn RemoteWriter>, String> {
        let file = self.create(path.to_string()).await.map_err(|e| format!("sftp: create {path}: {e}"))?;
        Ok(Box::new(SftpFile { file, path: path.to_string() }))
    }

    async fn remove_file(&self, path: &str) -> Result<(), String> {
        SftpSession::remove_file(self, path.to_string()).await.map_err(|e| format!("sftp: remove {path}: {e}"))
    }

    /// SFTPv3 rename refuses an existing target, so a file there is removed
    /// first; a folder there is never replaced.
    async fn commit(&self, partial: &str, dst: &str) -> Result<(), String> {
        if let Ok(m) = self.symlink_metadata(dst.to_string()).await {
            if m.is_dir() {
                return Err(format!("sftp: {dst} is a folder; not replacing it with a file"));
            }
            SftpSession::remove_file(self, dst.to_string()).await.map_err(|e| format!("sftp: replace {dst}: {e}"))?;
        }
        SftpSession::rename(self, partial.to_string(), dst.to_string())
            .await
            .map_err(|e| format!("sftp: rename onto {dst}: {e}"))
    }
}

/// An open SFTP file, read or written by the transfer engine.
struct SftpFile {
    file: russh_sftp::client::fs::File,
    path: String,
}

#[async_trait::async_trait]
impl RemoteReader for SftpFile {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, String> {
        self.file.read(buf).await.map_err(|e| format!("sftp: read {}: {e}", self.path))
    }

    async fn close(mut self: Box<Self>) {
        let _ = self.file.shutdown().await;
    }
}

#[async_trait::async_trait]
impl RemoteWriter for SftpFile {
    async fn write_all(&mut self, data: &[u8]) -> Result<(), String> {
        self.file.write_all(data).await.map_err(|e| format!("sftp: write {}: {e}", self.path))
    }

    async fn finish(mut self: Box<Self>) -> Result<(), String> {
        self.file.flush().await.map_err(|e| format!("sftp: write {}: {e}", self.path))?;
        self.file.shutdown().await.map_err(|e| format!("sftp: close {}: {e}", self.path))
    }

    async fn abort(mut self: Box<Self>) {
        let _ = self.file.shutdown().await;
    }
}
