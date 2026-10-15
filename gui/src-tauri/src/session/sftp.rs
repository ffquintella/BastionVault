//! SFTP session driver (features/sftp-connect.md).
//!
//! Same SSH transport as `session::ssh` — the connection, host-key check and
//! authentication are [`super::ssh::connect_authenticated`] — but the channel
//! carries the `sftp` subsystem instead of a PTY. The live [`SftpSession`]
//! sits in `AppState::connect_sessions` as [`super::SessionState::Sftp`]; the
//! dual-pane window drives it through the `sftp_*` commands
//! (`commands::connect_sftp`), each of which first checks that the calling
//! window holds the session.
//!
//! Two rules carry the security weight here:
//!
//! * **Names from the remote side are untrusted.** A hostile server can list
//!   an entry called `..` or `a/../../b`. [`is_safe_entry_name`] drops such
//!   entries from listings and refuses them as transfer sources or
//!   destinations, so a download can never write outside the folder the
//!   operator picked.
//! * **Recursion never follows a symlinked folder**, on either side, so a
//!   link loop cannot make a transfer unbounded. A symlink to a file is
//!   copied as the file's content.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::client;
use russh_sftp::client::SftpSession;
use serde::{Deserialize, Serialize};
use tauri::AppHandle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::ssh::{connect_authenticated, new_token, ClosedPayload, HostKeyHandler, SshCredential};
use super::{SessionCleanup, SessionState};

/// Suffix of a file being written by a transfer. Renamed onto the real name
/// only once the copy completed, so an interrupted transfer never leaves a
/// truncated file under the name of a complete one.
pub const PARTIAL_SUFFIX: &str = ".bvpart";

/// Copy buffer. Large enough to keep russh-sftp's pipelined writes busy.
const COPY_CHUNK: usize = 256 * 1024;

/// Upper bound on the entries one transfer may plan. A folder tree beyond
/// this is refused up front rather than copied half-way.
const MAX_PLANNED_ENTRIES: usize = 100_000;

/// Folder depth a transfer may descend. Symlinked folders are not followed,
/// so this only bounds genuinely deep trees.
const MAX_DEPTH: usize = 64;

/// Minimum spacing of progress events for one transfer.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(150);

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
    pub label: String,
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

pub fn progress_event_name(token: &str) -> String {
    format!("sftp-progress-{token}")
}

/// Dial, authenticate, start the `sftp` subsystem and register the session.
pub async fn open_sftp_session(
    app: AppHandle,
    state: &crate::state::AppState,
    args: SftpOpenArgs,
) -> Result<SftpOpenOutcome, String> {
    let handle = connect_authenticated(
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
                label: args.label.clone(),
                on_close: args.on_close.clone(),
                transfers: Arc::default(),
            }),
        );
    }
    spawn_disconnect_watch(app, token.clone(), closed_event.clone(), handle);
    log::info!("resource-connect/sftp: opened session token={token} label={} ({}:{})", args.label, args.host, args.port);
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

// ── Names and paths ──────────────────────────────────────────────────

/// A single path component that is safe to create on either side: not
/// empty, not `.` / `..`, no separator of either platform, no NUL.
pub fn is_safe_entry_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', '\0'])
}

/// Whether `name` is a valid Windows file name that names a file: none of
/// `< > : " | ? *` or a control character, no trailing dot or space (Windows
/// strips them, so `a.` would write `a`), and not a reserved device name
/// (`CON`, `NUL`, `COM1`, … with or without an extension).
///
/// A remote name is checked against this before it becomes a local path on
/// Windows: `Path::join` with a drive-qualified name (`D:x`) *replaces* the
/// destination folder instead of extending it, `a:b` writes an NTFS
/// alternate data stream of `a`, and `NUL` opens a device.
pub fn is_windows_file_name(name: &str) -> bool {
    const RESERVED: [&str; 4] = ["CON", "PRN", "AUX", "NUL"];
    if name.chars().any(|c| matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*') || (c as u32) < 0x20) {
        return false;
    }
    if name.ends_with(['.', ' ']) {
        return false;
    }
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ').to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        return false;
    }
    // COM0–COM9 / LPT0–LPT9, and the superscript-digit forms Windows also
    // reserves.
    if let Some(n) = stem.strip_prefix("COM").or_else(|| stem.strip_prefix("LPT")) {
        let mut chars = n.chars();
        if let (Some(d), None) = (chars.next(), chars.next()) {
            if d.is_ascii_digit() || matches!(d, '\u{00B9}' | '\u{00B2}' | '\u{00B3}') {
                return false;
            }
        }
    }
    true
}

/// A name that may be created on this computer: [`is_safe_entry_name`], and
/// on Windows also [`is_windows_file_name`].
pub fn is_safe_local_name(name: &str) -> bool {
    is_safe_entry_name(name) && (!cfg!(windows) || is_windows_file_name(name))
}

/// Join a remote (POSIX) folder and an entry name.
pub fn remote_join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// Last component of a remote path, ignoring trailing slashes.
pub fn remote_basename(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

/// A remote path as sent by the window: any string without NUL.
fn check_remote_path(path: &str) -> Result<(), String> {
    if path.is_empty() || path.contains('\0') {
        return Err("sftp: invalid remote path".into());
    }
    Ok(())
}

fn check_local_path(path: &str) -> Result<PathBuf, String> {
    if path.is_empty() || path.contains('\0') {
        return Err("sftp: invalid local path".into());
    }
    let p = PathBuf::from(path);
    if !p.is_absolute() {
        return Err("sftp: local paths must be absolute".into());
    }
    Ok(p)
}

// ── Listings ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub name: String,
    pub kind: EntryKind,
    /// For a symlink, what it points at (`dir` makes it navigable); for
    /// anything else, the same as `kind`. `other` when it dangles.
    pub target_kind: EntryKind,
    pub size: u64,
    /// Seconds since the Unix epoch.
    pub mtime: Option<u64>,
    /// Unix mode bits, when the side reports them.
    pub permissions: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Listing {
    /// The folder listed, canonical where the side could resolve it.
    pub path: String,
    pub entries: Vec<Entry>,
    /// Entries left out because their name was unsafe (see module docs).
    pub skipped_unsafe: usize,
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

pub async fn remote_list(sftp: &SftpSession, path: &str) -> Result<Listing, String> {
    check_remote_path(path)?;
    let canonical = sftp.canonicalize(path).await.map_err(|e| format!("sftp: {path}: {e}"))?;
    let dir = sftp.read_dir(canonical.clone()).await.map_err(|e| format!("sftp: list {canonical}: {e}"))?;
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
            match sftp.metadata(remote_join(&canonical, &name)).await {
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

fn local_kind(ft: &std::fs::FileType) -> EntryKind {
    if ft.is_symlink() {
        EntryKind::Symlink
    } else if ft.is_dir() {
        EntryKind::Dir
    } else if ft.is_file() {
        EntryKind::File
    } else {
        EntryKind::Other
    }
}

/// A local path as the window shows it and sends it back. On Windows,
/// `canonicalize` returns the verbatim form (`\\?\C:\...`); a drive path
/// is shown without that prefix.
fn display_local(p: &Path) -> String {
    let s = p.display().to_string();
    #[cfg(windows)]
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        if rest.as_bytes().get(1) == Some(&b':') {
            return rest.to_string();
        }
    }
    s
}

fn unix_mode(meta: &std::fs::Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Some(meta.permissions().mode())
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        None
    }
}

pub async fn local_list(path: &str) -> Result<Listing, String> {
    let dir = check_local_path(path)?;
    let canonical = tokio::fs::canonicalize(&dir).await.map_err(|e| format!("{path}: {e}"))?;
    let mut rd = tokio::fs::read_dir(&canonical).await.map_err(|e| format!("{}: {e}", canonical.display()))?;
    let mut entries = Vec::new();
    let mut skipped_unsafe = 0;
    while let Some(item) = rd.next_entry().await.map_err(|e| format!("{}: {e}", canonical.display()))? {
        let Some(name) = item.file_name().to_str().map(str::to_string) else {
            // Not valid UTF-8: cannot be named over SFTP or shown faithfully.
            skipped_unsafe += 1;
            continue;
        };
        if !is_safe_entry_name(&name) {
            skipped_unsafe += 1;
            continue;
        }
        let Ok(meta) = tokio::fs::symlink_metadata(item.path()).await else { continue };
        let kind = local_kind(&meta.file_type());
        let target_kind = if kind == EntryKind::Symlink {
            match tokio::fs::metadata(item.path()).await {
                Ok(t) => local_kind(&t.file_type()),
                Err(_) => EntryKind::Other,
            }
        } else {
            kind
        };
        let mtime = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs());
        entries.push(Entry { name, kind, target_kind, size: meta.len(), mtime, permissions: unix_mode(&meta) });
    }
    Ok(Listing { path: display_local(&canonical), entries, skipped_unsafe })
}

// ── Single operations ────────────────────────────────────────────────

pub async fn remote_mkdir(sftp: &SftpSession, parent: &str, name: &str) -> Result<String, String> {
    check_remote_path(parent)?;
    if !is_safe_entry_name(name) {
        return Err(format!("sftp: `{}` is not a valid folder name", name.escape_debug()));
    }
    let path = remote_join(parent, name);
    sftp.create_dir(path.clone()).await.map_err(|e| format!("sftp: create {path}: {e}"))?;
    Ok(path)
}

pub async fn remote_rename(sftp: &SftpSession, path: &str, new_name: &str) -> Result<String, String> {
    check_remote_path(path)?;
    if !is_safe_entry_name(new_name) {
        return Err(format!("sftp: `{}` is not a valid name", new_name.escape_debug()));
    }
    let trimmed = path.trim_end_matches('/');
    let parent = match trimmed.rfind('/') {
        Some(0) => "/",
        Some(i) => &trimmed[..i],
        None => "",
    };
    let target = remote_join(parent, new_name);
    if sftp.try_exists(target.clone()).await.unwrap_or(false) {
        return Err(format!("sftp: {target} already exists"));
    }
    sftp.rename(path, target.clone()).await.map_err(|e| format!("sftp: rename {path}: {e}"))?;
    Ok(target)
}

/// Delete a file, a symlink, or an empty folder. Never recursive: a folder
/// with content is refused by the server, and that refusal is reported.
pub async fn remote_remove(sftp: &SftpSession, path: &str) -> Result<(), String> {
    check_remote_path(path)?;
    let meta = sftp.symlink_metadata(path).await.map_err(|e| format!("sftp: {path}: {e}"))?;
    if meta.is_dir() {
        sftp.remove_dir(path).await.map_err(|e| format!("sftp: remove folder {path}: {e} (only empty folders can be removed)"))
    } else {
        sftp.remove_file(path).await.map_err(|e| format!("sftp: remove {path}: {e}"))
    }
}

pub async fn local_mkdir(parent: &str, name: &str) -> Result<String, String> {
    let parent = check_local_path(parent)?;
    if !is_safe_local_name(name) {
        return Err(format!("`{}` is not a valid folder name", name.escape_debug()));
    }
    let path = parent.join(name);
    tokio::fs::create_dir(&path).await.map_err(|e| format!("create {}: {e}", path.display()))?;
    Ok(path.display().to_string())
}

// ── Transfers ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Local → remote.
    Upload,
    /// Remote → local.
    Download,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
        }
    }
}

/// One step of a planned transfer, in execution order (a folder before its
/// content).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    Dir { dst: String },
    File { src: String, dst: String, size: u64 },
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferProgress {
    pub transfer_id: String,
    pub state: &'static str,
    pub current: String,
    pub files_done: u64,
    pub files_total: u64,
    pub bytes_done: u64,
    pub bytes_total: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferOutcome {
    pub transfer_id: String,
    /// `completed` | `cancelled` | `failed`.
    pub outcome: &'static str,
    pub files: u64,
    pub bytes: u64,
    /// Sources left out: symlinked folders and anything that is neither a
    /// file nor a folder (named in the host log).
    pub skipped: u64,
    pub error: Option<String>,
}

pub struct TransferRequest {
    pub transfer_id: String,
    pub direction: Direction,
    pub sources: Vec<String>,
    pub dest_dir: String,
    pub overwrite: bool,
}

/// Plans, then runs, one transfer. Holds no lock while copying.
pub async fn run_transfer(
    sftp: Arc<SftpSession>,
    cancel: Arc<AtomicBool>,
    events: super::routing::SessionEvents,
    progress_event: String,
    req: TransferRequest,
) -> TransferOutcome {
    let mut progress = TransferProgress {
        transfer_id: req.transfer_id.clone(),
        state: "planning",
        current: String::new(),
        files_done: 0,
        files_total: 0,
        bytes_done: 0,
        bytes_total: 0,
    };
    events.emit(&progress_event, progress.clone()).await;

    let (plan, skipped) = match plan_transfer(&sftp, &req).await {
        Ok(p) => p,
        Err(e) => return finish(&events, &progress_event, progress, 0, "failed", Some(e)).await,
    };
    progress.files_total = plan.iter().filter(|s| matches!(s, Step::File { .. })).count() as u64;
    progress.bytes_total = plan.iter().map(|s| if let Step::File { size, .. } = s { *size } else { 0 }).sum();
    progress.state = "running";
    events.emit(&progress_event, progress.clone()).await;

    let mut last_emit = Instant::now();
    for step in plan {
        if cancel.load(Ordering::SeqCst) {
            return finish(&events, &progress_event, progress, skipped, "cancelled", None).await;
        }
        let result = match &step {
            Step::Dir { dst } => {
                progress.current = dst.clone();
                make_dir(&sftp, req.direction, dst).await
            }
            Step::File { src, dst, .. } => {
                progress.current = src.clone();
                copy_file(&sftp, req.direction, src, dst, &cancel, &mut progress, &events, &progress_event, &mut last_emit)
                    .await
            }
        };
        match result {
            Ok(()) => {
                if matches!(step, Step::File { .. }) {
                    progress.files_done += 1;
                }
            }
            Err(CopyError::Cancelled) => {
                return finish(&events, &progress_event, progress, skipped, "cancelled", None).await;
            }
            Err(CopyError::Failed(e)) => {
                return finish(&events, &progress_event, progress, skipped, "failed", Some(e)).await;
            }
        }
    }
    finish(&events, &progress_event, progress, skipped, "completed", None).await
}

async fn finish(
    events: &super::routing::SessionEvents,
    progress_event: &str,
    mut progress: TransferProgress,
    skipped: u64,
    outcome: &'static str,
    error: Option<String>,
) -> TransferOutcome {
    progress.state = outcome;
    events.emit(progress_event, progress.clone()).await;
    TransferOutcome {
        transfer_id: progress.transfer_id,
        outcome,
        files: progress.files_done,
        bytes: progress.bytes_done,
        skipped,
        error,
    }
}

/// Destination name for a source path, validated.
fn source_name(direction: Direction, src: &str) -> Result<String, String> {
    let name = match direction {
        Direction::Download => remote_basename(src).to_string(),
        Direction::Upload => {
            Path::new(src).file_name().and_then(|n| n.to_str()).map(str::to_string).unwrap_or_default()
        }
    };
    if !is_safe_entry_name(&name) {
        return Err(format!("`{}` cannot be transferred: unsafe name", src.escape_debug()));
    }
    if direction == Direction::Download && !is_safe_local_name(&name) {
        return Err(format!("`{}` cannot be transferred: the name is not valid on this computer", src.escape_debug()));
    }
    Ok(name)
}

fn dest_join(direction: Direction, dir: &str, name: &str) -> String {
    match direction {
        Direction::Upload => remote_join(dir, name),
        Direction::Download => Path::new(dir).join(name).display().to_string(),
    }
}

async fn dest_exists(sftp: &SftpSession, direction: Direction, path: &str) -> bool {
    match direction {
        Direction::Upload => sftp.try_exists(path.to_string()).await.unwrap_or(false),
        Direction::Download => tokio::fs::symlink_metadata(path).await.is_ok(),
    }
}

/// What a source is, without following a symlink.
enum SourceKind {
    File(u64),
    Dir,
    /// A symlinked folder, or something that is neither file nor folder.
    Skip(&'static str),
}

async fn source_kind(sftp: &SftpSession, direction: Direction, path: &str) -> Result<SourceKind, String> {
    match direction {
        Direction::Download => {
            let lmeta = sftp.symlink_metadata(path).await.map_err(|e| format!("sftp: {path}: {e}"))?;
            let meta = if lmeta.is_symlink() {
                sftp.metadata(path).await.map_err(|e| format!("sftp: {path}: dangling symlink ({e})"))?
            } else {
                lmeta.clone()
            };
            Ok(if meta.is_dir() {
                if lmeta.is_symlink() { SourceKind::Skip("symlinked folder") } else { SourceKind::Dir }
            } else if meta.is_regular() {
                SourceKind::File(meta.size.unwrap_or(0))
            } else {
                SourceKind::Skip("not a regular file")
            })
        }
        Direction::Upload => {
            let lmeta = tokio::fs::symlink_metadata(path).await.map_err(|e| format!("{path}: {e}"))?;
            let meta = if lmeta.file_type().is_symlink() {
                tokio::fs::metadata(path).await.map_err(|e| format!("{path}: dangling symlink ({e})"))?
            } else {
                lmeta.clone()
            };
            Ok(if meta.is_dir() {
                if lmeta.file_type().is_symlink() { SourceKind::Skip("symlinked folder") } else { SourceKind::Dir }
            } else if meta.is_file() {
                SourceKind::File(meta.len())
            } else {
                SourceKind::Skip("not a regular file")
            })
        }
    }
}

/// Child names of a source folder, unsafe names refused.
async fn source_children(sftp: &SftpSession, direction: Direction, dir: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    match direction {
        Direction::Download => {
            let rd = sftp.read_dir(dir.to_string()).await.map_err(|e| format!("sftp: list {dir}: {e}"))?;
            for item in rd {
                let n = item.file_name();
                if n == "." || n == ".." {
                    continue;
                }
                if !is_safe_entry_name(&n) {
                    return Err(format!("sftp: {dir} contains an entry with an unsafe name; refusing to copy it"));
                }
                if !is_safe_local_name(&n) {
                    return Err(format!(
                        "sftp: {dir} contains an entry whose name is not valid on this computer; refusing to copy it"
                    ));
                }
                names.push(n);
            }
        }
        Direction::Upload => {
            let mut rd = tokio::fs::read_dir(dir).await.map_err(|e| format!("{dir}: {e}"))?;
            while let Some(item) = rd.next_entry().await.map_err(|e| format!("{dir}: {e}"))? {
                let n = item
                    .file_name()
                    .to_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("{dir} contains a name that is not valid UTF-8"))?;
                if !is_safe_entry_name(&n) {
                    return Err(format!("{dir} contains an entry with an unsafe name"));
                }
                names.push(n);
            }
        }
    }
    names.sort();
    Ok(names)
}

fn source_join(direction: Direction, dir: &str, name: &str) -> String {
    match direction {
        Direction::Download => remote_join(dir, name),
        Direction::Upload => Path::new(dir).join(name).display().to_string(),
    }
}

async fn plan_transfer(sftp: &SftpSession, req: &TransferRequest) -> Result<(Vec<Step>, u64), String> {
    if req.sources.is_empty() {
        return Err("nothing to transfer".into());
    }
    match req.direction {
        Direction::Upload => {
            check_remote_path(&req.dest_dir)?;
            for s in &req.sources {
                check_local_path(s)?;
            }
        }
        Direction::Download => {
            check_local_path(&req.dest_dir)?;
            for s in &req.sources {
                check_remote_path(s)?;
            }
        }
    }
    // Top level: names and conflicts are checked for every source before
    // anything is written.
    let mut roots = Vec::with_capacity(req.sources.len());
    for src in &req.sources {
        let name = source_name(req.direction, src)?;
        let dst = dest_join(req.direction, &req.dest_dir, &name);
        if !req.overwrite && dest_exists(sftp, req.direction, &dst).await {
            return Err(format!("exists: {name}"));
        }
        roots.push((src.clone(), dst));
    }
    let mut plan = Vec::new();
    let mut skipped = 0u64;
    let mut stack: Vec<(String, String, usize)> = roots.into_iter().rev().map(|(s, d)| (s, d, 0)).collect();
    while let Some((src, dst, depth)) = stack.pop() {
        if plan.len() >= MAX_PLANNED_ENTRIES {
            return Err(format!("the selection has more than {MAX_PLANNED_ENTRIES} entries; transfer it in parts"));
        }
        match source_kind(sftp, req.direction, &src).await? {
            SourceKind::File(size) => plan.push(Step::File { src, dst, size }),
            SourceKind::Dir => {
                if depth >= MAX_DEPTH {
                    return Err(format!("{src}: folders nested deeper than {MAX_DEPTH} levels"));
                }
                plan.push(Step::Dir { dst: dst.clone() });
                let children = source_children(sftp, req.direction, &src).await?;
                for name in children.into_iter().rev() {
                    stack.push((
                        source_join(req.direction, &src, &name),
                        dest_join(req.direction, &dst, &name),
                        depth + 1,
                    ));
                }
            }
            SourceKind::Skip(why) => {
                log::info!("resource-connect/sftp: skipping {src} ({why})");
                skipped += 1;
            }
        }
    }
    Ok((plan, skipped))
}

enum CopyError {
    Cancelled,
    Failed(String),
}

async fn make_dir(sftp: &SftpSession, direction: Direction, dst: &str) -> Result<(), CopyError> {
    match direction {
        Direction::Upload => match sftp.symlink_metadata(dst.to_string()).await {
            Ok(m) if m.is_dir() => Ok(()),
            Ok(_) => Err(CopyError::Failed(format!("sftp: {dst} exists and is not a folder"))),
            Err(_) => {
                sftp.create_dir(dst.to_string()).await.map_err(|e| CopyError::Failed(format!("sftp: create {dst}: {e}")))
            }
        },
        Direction::Download => match tokio::fs::symlink_metadata(dst).await {
            Ok(m) if m.is_dir() => Ok(()),
            Ok(_) => Err(CopyError::Failed(format!("{dst} exists and is not a folder"))),
            Err(_) => tokio::fs::create_dir(dst).await.map_err(|e| CopyError::Failed(format!("create {dst}: {e}"))),
        },
    }
}

#[allow(clippy::too_many_arguments)]
async fn copy_file(
    sftp: &SftpSession,
    direction: Direction,
    src: &str,
    dst: &str,
    cancel: &AtomicBool,
    progress: &mut TransferProgress,
    events: &super::routing::SessionEvents,
    progress_event: &str,
    last_emit: &mut Instant,
) -> Result<(), CopyError> {
    let partial = format!("{dst}{PARTIAL_SUFFIX}");
    let result = match direction {
        Direction::Download => {
            download_file(sftp, src, &partial, cancel, progress, events, progress_event, last_emit).await
        }
        Direction::Upload => upload_file(sftp, src, &partial, cancel, progress, events, progress_event, last_emit).await,
    };
    if let Err(e) = result {
        // Never leave the partial file behind.
        match direction {
            Direction::Download => {
                let _ = tokio::fs::remove_file(&partial).await;
            }
            Direction::Upload => {
                let _ = sftp.remove_file(partial.clone()).await;
            }
        }
        return Err(e);
    }
    // Move the complete file onto its name.
    let renamed = match direction {
        Direction::Download => {
            // `rename` replaces on Unix but not on Windows.
            if tokio::fs::symlink_metadata(dst).await.is_ok() {
                if let Err(e) = tokio::fs::remove_file(dst).await {
                    let _ = tokio::fs::remove_file(&partial).await;
                    return Err(CopyError::Failed(format!("replace {dst}: {e}")));
                }
            }
            tokio::fs::rename(&partial, dst).await.map_err(|e| format!("rename onto {dst}: {e}"))
        }
        Direction::Upload => {
            // SFTPv3 rename refuses an existing target.
            if let Ok(m) = sftp.symlink_metadata(dst.to_string()).await {
                if m.is_dir() {
                    let _ = sftp.remove_file(partial.clone()).await;
                    return Err(CopyError::Failed(format!("sftp: {dst} is a folder; not replacing it with a file")));
                }
                if let Err(e) = sftp.remove_file(dst.to_string()).await {
                    let _ = sftp.remove_file(partial.clone()).await;
                    return Err(CopyError::Failed(format!("sftp: replace {dst}: {e}")));
                }
            }
            sftp.rename(partial.clone(), dst.to_string()).await.map_err(|e| format!("sftp: rename onto {dst}: {e}"))
        }
    };
    if let Err(e) = renamed {
        match direction {
            Direction::Download => {
                let _ = tokio::fs::remove_file(&partial).await;
            }
            Direction::Upload => {
                let _ = sftp.remove_file(partial.clone()).await;
            }
        }
        return Err(CopyError::Failed(e));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn download_file(
    sftp: &SftpSession,
    src: &str,
    partial: &str,
    cancel: &AtomicBool,
    progress: &mut TransferProgress,
    events: &super::routing::SessionEvents,
    progress_event: &str,
    last_emit: &mut Instant,
) -> Result<(), CopyError> {
    let mut remote = sftp.open(src.to_string()).await.map_err(|e| CopyError::Failed(format!("sftp: open {src}: {e}")))?;
    // `create_new`: a stale partial from a crashed run is not silently reused.
    let mut local = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(partial)
        .await
        .map_err(|e| CopyError::Failed(format!("create {partial}: {e}")))?;
    let mut buf = vec![0u8; COPY_CHUNK];
    loop {
        if cancel.load(Ordering::SeqCst) {
            return Err(CopyError::Cancelled);
        }
        let n = remote.read(&mut buf).await.map_err(|e| CopyError::Failed(format!("sftp: read {src}: {e}")))?;
        if n == 0 {
            break;
        }
        local.write_all(&buf[..n]).await.map_err(|e| CopyError::Failed(format!("write {partial}: {e}")))?;
        progress.bytes_done += n as u64;
        tick(progress, events, progress_event, last_emit).await;
    }
    local.flush().await.map_err(|e| CopyError::Failed(format!("write {partial}: {e}")))?;
    local.sync_all().await.map_err(|e| CopyError::Failed(format!("sync {partial}: {e}")))?;
    let _ = remote.shutdown().await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn upload_file(
    sftp: &SftpSession,
    src: &str,
    partial: &str,
    cancel: &AtomicBool,
    progress: &mut TransferProgress,
    events: &super::routing::SessionEvents,
    progress_event: &str,
    last_emit: &mut Instant,
) -> Result<(), CopyError> {
    let mut local = tokio::fs::File::open(src).await.map_err(|e| CopyError::Failed(format!("open {src}: {e}")))?;
    let mut remote =
        sftp.create(partial.to_string()).await.map_err(|e| CopyError::Failed(format!("sftp: create {partial}: {e}")))?;
    let mut buf = vec![0u8; COPY_CHUNK];
    loop {
        if cancel.load(Ordering::SeqCst) {
            let _ = remote.shutdown().await;
            return Err(CopyError::Cancelled);
        }
        let n = local.read(&mut buf).await.map_err(|e| CopyError::Failed(format!("read {src}: {e}")))?;
        if n == 0 {
            break;
        }
        remote.write_all(&buf[..n]).await.map_err(|e| CopyError::Failed(format!("sftp: write {partial}: {e}")))?;
        progress.bytes_done += n as u64;
        tick(progress, events, progress_event, last_emit).await;
    }
    remote.flush().await.map_err(|e| CopyError::Failed(format!("sftp: write {partial}: {e}")))?;
    remote.shutdown().await.map_err(|e| CopyError::Failed(format!("sftp: close {partial}: {e}")))?;
    Ok(())
}

async fn tick(
    progress: &TransferProgress,
    events: &super::routing::SessionEvents,
    progress_event: &str,
    last_emit: &mut Instant,
) {
    if last_emit.elapsed() >= PROGRESS_INTERVAL {
        *last_emit = Instant::now();
        events.emit(progress_event, progress.clone()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_names_are_refused() {
        for bad in ["", ".", "..", "a/b", "../x", "a\\b", "x\0y", "/"] {
            assert!(!is_safe_entry_name(bad), "{bad:?} accepted");
        }
        for ok in ["a", ".hidden", "..x", "x..", "file name.txt", "ação", "a:b"] {
            assert!(is_safe_entry_name(ok), "{ok:?} refused");
        }
    }

    #[test]
    fn windows_file_names_exclude_streams_drives_and_devices() {
        for bad in [
            "a:b", "D:evil", "C:", "x<y", "x>y", "a\"b", "a|b", "a?", "a*", "tab\tname", "dot.", "space ", "CON",
            "con", "Nul.txt", "aux.tar.gz", "COM1", "lpt9.log", "COM\u{00B9}", "PRN ",
        ] {
            assert!(!is_windows_file_name(bad), "{bad:?} accepted");
        }
        for ok in ["a", ".hidden", "report.pdf", "ação", "CONSOLE", "COM10", "LPT", "nul_x", "CONx.txt"] {
            assert!(is_windows_file_name(ok), "{ok:?} refused");
        }
        // Off Windows a `:` is an ordinary character.
        assert_eq!(is_safe_local_name("a:b"), !cfg!(windows));
        assert!(!is_safe_local_name(".."));
    }

    #[test]
    fn remote_paths_join_and_split_posix_style() {
        assert_eq!(remote_join("/home/op", "f"), "/home/op/f");
        assert_eq!(remote_join("/", "f"), "/f");
        assert_eq!(remote_join("", "f"), "f");
        assert_eq!(remote_basename("/home/op/f.txt"), "f.txt");
        assert_eq!(remote_basename("/home/op/dir/"), "dir");
        assert_eq!(remote_basename("f"), "f");
    }

    /// A source whose last component is `..` or empty would name the
    /// destination folder's parent (or the folder itself): refused.
    #[test]
    fn a_source_without_a_safe_name_is_refused() {
        assert!(source_name(Direction::Download, "/srv/..").is_err());
        assert!(source_name(Direction::Download, "/").is_err());
        assert!(source_name(Direction::Upload, "/tmp/..").is_err());
        assert_eq!(source_name(Direction::Download, "/srv/data/").unwrap(), "data");
        assert_eq!(source_name(Direction::Upload, "/tmp/report.pdf").unwrap(), "report.pdf");
    }

    #[test]
    fn transfer_destinations_stay_under_the_destination_folder() {
        assert_eq!(dest_join(Direction::Upload, "/home/op", "a"), "/home/op/a");
        let local = dest_join(Direction::Download, "/Users/op/Downloads", "a");
        assert_eq!(Path::new(&local), Path::new("/Users/op/Downloads").join("a"));
    }

    #[test]
    fn local_paths_must_be_absolute() {
        assert!(check_local_path("relative/dir").is_err());
        assert!(check_local_path("").is_err());
        #[cfg(unix)]
        assert!(check_local_path("/tmp").is_ok());
    }

    #[tokio::test]
    async fn local_listing_hides_nothing_safe_and_reports_kinds() {
        let dir = std::env::temp_dir().join(format!("bv-sftp-test-{}", new_token()));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("f.txt"), b"hello").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.join("sub"), dir.join("link")).unwrap();
        let listing = local_list(dir.to_str().unwrap()).await.unwrap();
        let by_name: HashMap<_, _> = listing.entries.iter().map(|e| (e.name.as_str(), e)).collect();
        assert_eq!(by_name["f.txt"].kind, EntryKind::File);
        assert_eq!(by_name["f.txt"].size, 5);
        assert_eq!(by_name["sub"].kind, EntryKind::Dir);
        #[cfg(unix)]
        {
            assert_eq!(by_name["link"].kind, EntryKind::Symlink);
            assert_eq!(by_name["link"].target_kind, EntryKind::Dir);
        }
        assert_eq!(listing.skipped_unsafe, 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
