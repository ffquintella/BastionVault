//! The dual-pane file window's engine, shared by the SFTP and SMB sessions
//! (features/sftp-connect.md, features/smb-connect.md). The remote side is
//! a [`RemoteFs`] — an SFTP session (`session::sftp`) or an SMB share
//! (`session::smb`) — and the local pane, the transfer planner and the copy
//! loop are written once against it, so these rules hold for both:

//! * **Remote names are untrusted.** [`is_safe_entry_name`] drops `..`,
//!   `a/b` and the like from listings and refuses them as transfer sources
//!   or destinations: a download never writes outside the chosen folder.
//! * **Recursion never follows a symlinked folder** the side reports as
//!   one; [`MAX_DEPTH`] and [`MAX_PLANNED_ENTRIES`] bound what it does not.
//! * **No silent overwrite, no partial file under a complete name**: see
//!   [`PARTIAL_SUFFIX`] and the `exists:` refusal in [`run_transfer`].

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Suffix of a file being written by a transfer. Renamed onto the real name
/// only once the copy completed, so an interrupted transfer never leaves a
/// truncated file under the name of a complete one.
pub const PARTIAL_SUFFIX: &str = ".bvpart";

/// Copy buffer. Large enough to keep russh-sftp's pipelined writes busy.
const COPY_CHUNK: usize = 256 * 1024;

/// Upper bound on the entries one transfer may plan. A folder tree beyond
/// this is refused up front rather than copied half-way.
pub const MAX_PLANNED_ENTRIES: usize = 100_000;

/// Folder depth a transfer may descend. Symlinked folders are not followed,
/// so this only bounds genuinely deep trees.
pub const MAX_DEPTH: usize = 64;

/// Minimum spacing of progress events for one transfer.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(150);

/// The event a session's transfer progress arrives on; one name for both
/// protocols, keyed by token.
pub fn progress_event_name(token: &str) -> String {
    format!("sftp-progress-{token}")
}

// ── The remote side ──────────────────────────────────────────────────

/// One remote side of the dual-pane window. Paths are POSIX-style on both
/// protocols (an SMB share's root is `/`). Every message an implementation
/// returns is operator-facing, starts with [`RemoteFs::protocol`] and never
/// carries a credential.
#[async_trait::async_trait]
pub trait RemoteFs: Send + Sync {
    /// `sftp` | `smb`: the prefix of messages and log lines.
    fn protocol(&self) -> &'static str;
    /// A path the window sent, refused or put in the side's canonical
    /// spelling before anything uses it.
    fn normalize(&self, path: &str) -> Result<String, String>;
    /// Whether `name` may be created on this side (new folder, rename,
    /// upload destination). Always at least [`is_safe_entry_name`].
    fn is_valid_name(&self, name: &str) -> bool;

    /// Where the remote pane starts.
    async fn home(&self) -> Result<String, String>;
    /// A folder's entries, unsafe names left out and counted.
    async fn list(&self, path: &str) -> Result<Listing, String>;
    async fn mkdir(&self, parent: &str, name: &str) -> Result<String, String>;
    async fn rename(&self, path: &str, new_name: &str) -> Result<String, String>;
    /// A file, a symlink or an empty folder; never recursive.
    async fn remove(&self, path: &str) -> Result<(), String>;

    // Transfer primitives, on normalized paths.

    async fn exists(&self, path: &str) -> Result<bool, String>;
    /// What `path` is, without following a symlinked folder.
    async fn source_kind(&self, path: &str) -> Result<SourceKind, String>;
    /// A folder's raw child names (`.` and `..` excluded), each with its
    /// kind when the listing already said it; the engine validates names.
    async fn children(&self, dir: &str) -> Result<Vec<(String, Option<SourceKind>)>, String>;
    /// `Ok` when `path` is a folder (created if missing); an error when
    /// something else is there.
    async fn ensure_dir(&self, path: &str) -> Result<(), String>;
    async fn open_read(&self, path: &str) -> Result<Box<dyn RemoteReader>, String>;
    /// Create (or truncate) the partial file of an upload.
    async fn create_write(&self, path: &str) -> Result<Box<dyn RemoteWriter>, String>;
    /// Best-effort removal of a partial file.
    async fn remove_file(&self, path: &str) -> Result<(), String>;
    /// Move a complete partial file onto `dst`, replacing a file there but
    /// never a folder.
    async fn commit(&self, partial: &str, dst: &str) -> Result<(), String>;
}

/// A remote file open for reading.
#[async_trait::async_trait]
pub trait RemoteReader: Send {
    /// Up to `buf.len()` bytes; `0` at the end of the file.
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, String>;
    async fn close(self: Box<Self>);
}

/// A remote file open for writing.
#[async_trait::async_trait]
pub trait RemoteWriter: Send {
    async fn write_all(&mut self, data: &[u8]) -> Result<(), String>;
    /// Flush and close: the file is complete only when this succeeds.
    async fn finish(self: Box<Self>) -> Result<(), String>;
    /// Close after a failure or a cancel; best effort.
    async fn abort(self: Box<Self>);
}

// ── Names and paths ──────────────────────────────────────────────────

/// A single path component that is safe to create on either side: not
/// empty, not `.` / `..`, no separator of either platform, no NUL.
pub fn is_safe_entry_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', '\0'])
}

/// Whether `name` is a valid Windows file name: none of `< > : " | ? *` or a
/// control character, no trailing dot or space, not a reserved device name
/// (`CON`, `NUL`, `COM1`, … with or without an extension). Checked before a
/// remote name becomes a local path on Windows (`D:x` replaces the folder on
/// `join`, `a:b` is an NTFS stream, `NUL` a device) and for every name sent
/// to an SMB share, which applies the same rules.
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

/// The folder holding a remote path: `/` for a top-level entry, `""` for a
/// relative single component.
pub fn remote_parent(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(0) => "/",
        Some(i) => &trimmed[..i],
        None => "",
    }
}

pub fn check_local_path(path: &str) -> Result<PathBuf, String> {
    if path.is_empty() || path.contains('\0') {
        return Err("invalid local path".into());
    }
    let p = PathBuf::from(path);
    if !p.is_absolute() {
        return Err("local paths must be absolute".into());
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
    /// anything else, the same as `kind`. `other` when it dangles or is not
    /// followed.
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
            // Not valid UTF-8: cannot be named remotely or shown faithfully.
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
        let mtime =
            meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs());
        entries.push(Entry { name, kind, target_kind, size: meta.len(), mtime, permissions: unix_mode(&meta) });
    }
    Ok(Listing { path: display_local(&canonical), entries, skipped_unsafe })
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

/// What a source is, without following a symlinked folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    File(u64),
    Dir,
    /// A symlinked folder, or something that is neither file nor folder.
    Skip(&'static str),
}

/// Plans, then runs, one transfer. Holds no lock while copying.
pub async fn run_transfer(
    fs: Arc<dyn RemoteFs>,
    cancel: Arc<AtomicBool>,
    events: super::routing::SessionEvents,
    progress_event: String,
    req: TransferRequest,
) -> TransferOutcome {
    let fs = fs.as_ref();
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

    let (plan, skipped) = match plan_transfer(fs, &req).await {
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
                make_dir(fs, req.direction, dst).await
            }
            Step::File { src, dst, .. } => {
                progress.current = src.clone();
                let mut ticker = Ticker { events: &events, event: &progress_event, last_emit: &mut last_emit };
                copy_file(fs, req.direction, src, dst, &cancel, &mut progress, &mut ticker).await
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

/// Destination name for a source path, validated: safe on both sides, and
/// creatable where it is going.
fn source_name(fs: &dyn RemoteFs, direction: Direction, src: &str) -> Result<String, String> {
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
    if direction == Direction::Upload && !fs.is_valid_name(&name) {
        return Err(format!(
            "`{}` cannot be transferred: the name is not valid on the {} server",
            src.escape_debug(),
            fs.protocol().to_ascii_uppercase()
        ));
    }
    Ok(name)
}

fn dest_join(direction: Direction, dir: &str, name: &str) -> String {
    match direction {
        Direction::Upload => remote_join(dir, name),
        Direction::Download => Path::new(dir).join(name).display().to_string(),
    }
}

async fn dest_exists(fs: &dyn RemoteFs, direction: Direction, path: &str) -> Result<bool, String> {
    match direction {
        Direction::Upload => fs.exists(path).await,
        Direction::Download => Ok(tokio::fs::symlink_metadata(path).await.is_ok()),
    }
}

async fn local_source_kind(path: &str) -> Result<SourceKind, String> {
    let lmeta = tokio::fs::symlink_metadata(path).await.map_err(|e| format!("{path}: {e}"))?;
    let meta = if lmeta.file_type().is_symlink() {
        tokio::fs::metadata(path).await.map_err(|e| format!("{path}: dangling symlink ({e})"))?
    } else {
        lmeta.clone()
    };
    Ok(if meta.is_dir() {
        if lmeta.file_type().is_symlink() {
            SourceKind::Skip("symlinked folder")
        } else {
            SourceKind::Dir
        }
    } else if meta.is_file() {
        SourceKind::File(meta.len())
    } else {
        SourceKind::Skip("not a regular file")
    })
}

async fn source_kind(fs: &dyn RemoteFs, direction: Direction, path: &str) -> Result<SourceKind, String> {
    match direction {
        Direction::Download => fs.source_kind(path).await,
        Direction::Upload => local_source_kind(path).await,
    }
}

/// Child names of a source folder, unsafe names refused, sorted.
async fn source_children(
    fs: &dyn RemoteFs,
    direction: Direction,
    dir: &str,
) -> Result<Vec<(String, Option<SourceKind>)>, String> {
    let mut names = Vec::new();
    match direction {
        Direction::Download => {
            let proto = fs.protocol();
            for (n, kind) in fs.children(dir).await? {
                if n == "." || n == ".." {
                    continue;
                }
                if !is_safe_entry_name(&n) {
                    return Err(format!("{proto}: {dir} contains an entry with an unsafe name; refusing to copy it"));
                }
                if !is_safe_local_name(&n) {
                    return Err(format!(
                        "{proto}: {dir} contains an entry whose name is not valid on this computer; refusing to copy it"
                    ));
                }
                names.push((n, kind));
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
                if !fs.is_valid_name(&n) {
                    return Err(format!(
                        "{dir} contains an entry whose name is not valid on the {} server",
                        fs.protocol().to_ascii_uppercase()
                    ));
                }
                names.push((n, None));
            }
        }
    }
    names.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(names)
}

fn source_join(direction: Direction, dir: &str, name: &str) -> String {
    match direction {
        Direction::Download => remote_join(dir, name),
        Direction::Upload => Path::new(dir).join(name).display().to_string(),
    }
}

async fn plan_transfer(fs: &dyn RemoteFs, req: &TransferRequest) -> Result<(Vec<Step>, u64), String> {
    if req.sources.is_empty() {
        return Err("nothing to transfer".into());
    }
    let proto = fs.protocol();
    // Remote paths in the side's canonical spelling from here on.
    let (sources, dest_dir) = match req.direction {
        Direction::Upload => {
            let dest = fs.normalize(&req.dest_dir)?;
            for s in &req.sources {
                check_local_path(s).map_err(|e| format!("{proto}: {e}"))?;
            }
            (req.sources.clone(), dest)
        }
        Direction::Download => {
            check_local_path(&req.dest_dir).map_err(|e| format!("{proto}: {e}"))?;
            let sources = req.sources.iter().map(|s| fs.normalize(s)).collect::<Result<Vec<_>, _>>()?;
            (sources, req.dest_dir.clone())
        }
    };
    // Top level: names and conflicts are checked for every source before
    // anything is written.
    let mut roots = Vec::with_capacity(sources.len());
    for src in &sources {
        let name = source_name(fs, req.direction, src)?;
        let dst = dest_join(req.direction, &dest_dir, &name);
        if !req.overwrite && dest_exists(fs, req.direction, &dst).await? {
            return Err(format!("exists: {name}"));
        }
        roots.push((src.clone(), dst));
    }
    let mut plan = Vec::new();
    let mut skipped = 0u64;
    // `None`: the kind is read when the entry is reached; a folder listing
    // that already told it hands it down.
    let mut stack: Vec<(String, String, usize, Option<SourceKind>)> =
        roots.into_iter().rev().map(|(s, d)| (s, d, 0, None)).collect();
    while let Some((src, dst, depth, known)) = stack.pop() {
        if plan.len() >= MAX_PLANNED_ENTRIES {
            return Err(format!("the selection has more than {MAX_PLANNED_ENTRIES} entries; transfer it in parts"));
        }
        let kind = match known {
            Some(k) => k,
            None => source_kind(fs, req.direction, &src).await?,
        };
        match kind {
            SourceKind::File(size) => plan.push(Step::File { src, dst, size }),
            SourceKind::Dir => {
                if depth >= MAX_DEPTH {
                    return Err(format!("{src}: folders nested deeper than {MAX_DEPTH} levels"));
                }
                plan.push(Step::Dir { dst: dst.clone() });
                let children = source_children(fs, req.direction, &src).await?;
                for (name, kind) in children.into_iter().rev() {
                    stack.push((
                        source_join(req.direction, &src, &name),
                        dest_join(req.direction, &dst, &name),
                        depth + 1,
                        kind,
                    ));
                }
            }
            SourceKind::Skip(why) => {
                log::info!("resource-connect/{proto}: skipping {src} ({why})");
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

async fn make_dir(fs: &dyn RemoteFs, direction: Direction, dst: &str) -> Result<(), CopyError> {
    match direction {
        Direction::Upload => fs.ensure_dir(dst).await.map_err(CopyError::Failed),
        Direction::Download => match tokio::fs::symlink_metadata(dst).await {
            Ok(m) if m.is_dir() => Ok(()),
            Ok(_) => Err(CopyError::Failed(format!("{dst} exists and is not a folder"))),
            Err(_) => tokio::fs::create_dir(dst).await.map_err(|e| CopyError::Failed(format!("create {dst}: {e}"))),
        },
    }
}

/// Rate-limited progress events for one transfer.
struct Ticker<'a> {
    events: &'a super::routing::SessionEvents,
    event: &'a str,
    last_emit: &'a mut Instant,
}

impl Ticker<'_> {
    async fn tick(&mut self, progress: &TransferProgress) {
        if self.last_emit.elapsed() >= PROGRESS_INTERVAL {
            *self.last_emit = Instant::now();
            self.events.emit(self.event, progress.clone()).await;
        }
    }
}

async fn copy_file(
    fs: &dyn RemoteFs,
    direction: Direction,
    src: &str,
    dst: &str,
    cancel: &AtomicBool,
    progress: &mut TransferProgress,
    ticker: &mut Ticker<'_>,
) -> Result<(), CopyError> {
    let partial = format!("{dst}{PARTIAL_SUFFIX}");
    let result = match direction {
        Direction::Download => download_file(fs, src, &partial, cancel, progress, ticker).await,
        Direction::Upload => upload_file(fs, src, &partial, cancel, progress, ticker).await,
    };
    if let Err(e) = result {
        // Never leave the partial file behind.
        match direction {
            Direction::Download => {
                let _ = tokio::fs::remove_file(&partial).await;
            }
            Direction::Upload => {
                let _ = fs.remove_file(&partial).await;
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
        // The side's own replace rule (never a folder).
        Direction::Upload => fs.commit(&partial, dst).await,
    };
    if let Err(e) = renamed {
        match direction {
            Direction::Download => {
                let _ = tokio::fs::remove_file(&partial).await;
            }
            Direction::Upload => {
                let _ = fs.remove_file(&partial).await;
            }
        }
        return Err(CopyError::Failed(e));
    }
    Ok(())
}

async fn download_file(
    fs: &dyn RemoteFs,
    src: &str,
    partial: &str,
    cancel: &AtomicBool,
    progress: &mut TransferProgress,
    ticker: &mut Ticker<'_>,
) -> Result<(), CopyError> {
    let mut remote = fs.open_read(src).await.map_err(CopyError::Failed)?;
    // `create_new`: a stale partial from a crashed run is not silently reused.
    let mut local = match tokio::fs::OpenOptions::new().write(true).create_new(true).open(partial).await {
        Ok(f) => f,
        Err(e) => {
            remote.close().await;
            return Err(CopyError::Failed(format!("create {partial}: {e}")));
        }
    };
    let mut buf = vec![0u8; COPY_CHUNK];
    let copied: Result<(), CopyError> = async {
        loop {
            if cancel.load(Ordering::SeqCst) {
                return Err(CopyError::Cancelled);
            }
            let n = remote.read(&mut buf).await.map_err(CopyError::Failed)?;
            if n == 0 {
                break;
            }
            local.write_all(&buf[..n]).await.map_err(|e| CopyError::Failed(format!("write {partial}: {e}")))?;
            progress.bytes_done += n as u64;
            ticker.tick(progress).await;
        }
        local.flush().await.map_err(|e| CopyError::Failed(format!("write {partial}: {e}")))?;
        local.sync_all().await.map_err(|e| CopyError::Failed(format!("sync {partial}: {e}")))?;
        Ok(())
    }
    .await;
    remote.close().await;
    copied
}

async fn upload_file(
    fs: &dyn RemoteFs,
    src: &str,
    partial: &str,
    cancel: &AtomicBool,
    progress: &mut TransferProgress,
    ticker: &mut Ticker<'_>,
) -> Result<(), CopyError> {
    let mut local = tokio::fs::File::open(src).await.map_err(|e| CopyError::Failed(format!("open {src}: {e}")))?;
    let mut remote = fs.create_write(partial).await.map_err(CopyError::Failed)?;
    let mut buf = vec![0u8; COPY_CHUNK];
    loop {
        if cancel.load(Ordering::SeqCst) {
            remote.abort().await;
            return Err(CopyError::Cancelled);
        }
        let n = match local.read(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                remote.abort().await;
                return Err(CopyError::Failed(format!("read {src}: {e}")));
            }
        };
        if n == 0 {
            break;
        }
        if let Err(e) = remote.write_all(&buf[..n]).await {
            remote.abort().await;
            return Err(CopyError::Failed(e));
        }
        progress.bytes_done += n as u64;
        ticker.tick(progress).await;
    }
    remote.finish().await.map_err(CopyError::Failed)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

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
            "a:b",
            "D:evil",
            "C:",
            "x<y",
            "x>y",
            "a\"b",
            "a|b",
            "a?",
            "a*",
            "tab\tname",
            "dot.",
            "space ",
            "CON",
            "con",
            "Nul.txt",
            "aux.tar.gz",
            "COM1",
            "lpt9.log",
            "COM\u{00B9}",
            "PRN ",
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
        assert_eq!(remote_parent("/home/op/f"), "/home/op");
        assert_eq!(remote_parent("/f"), "/");
        assert_eq!(remote_parent("f"), "");
    }

    /// A remote side with nothing behind it, carrying the name rules of
    /// SFTP (`windows_names` off) or SMB (on). Only what the planner's
    /// local-only paths reach is implemented.
    struct NameRules {
        windows_names: bool,
    }

    #[async_trait::async_trait]
    impl RemoteFs for NameRules {
        fn protocol(&self) -> &'static str {
            if self.windows_names {
                "smb"
            } else {
                "sftp"
            }
        }
        fn normalize(&self, path: &str) -> Result<String, String> {
            Ok(path.to_string())
        }
        fn is_valid_name(&self, name: &str) -> bool {
            is_safe_entry_name(name) && (!self.windows_names || is_windows_file_name(name))
        }
        async fn home(&self) -> Result<String, String> {
            Err("unused".into())
        }
        async fn list(&self, _: &str) -> Result<Listing, String> {
            Err("unused".into())
        }
        async fn mkdir(&self, _: &str, _: &str) -> Result<String, String> {
            Err("unused".into())
        }
        async fn rename(&self, _: &str, _: &str) -> Result<String, String> {
            Err("unused".into())
        }
        async fn remove(&self, _: &str) -> Result<(), String> {
            Err("unused".into())
        }
        async fn exists(&self, _: &str) -> Result<bool, String> {
            Ok(false)
        }
        async fn source_kind(&self, _: &str) -> Result<SourceKind, String> {
            Err("unused".into())
        }
        async fn children(&self, _: &str) -> Result<Vec<(String, Option<SourceKind>)>, String> {
            Err("unused".into())
        }
        async fn ensure_dir(&self, _: &str) -> Result<(), String> {
            Err("unused".into())
        }
        async fn open_read(&self, _: &str) -> Result<Box<dyn RemoteReader>, String> {
            Err("unused".into())
        }
        async fn create_write(&self, _: &str) -> Result<Box<dyn RemoteWriter>, String> {
            Err("unused".into())
        }
        async fn remove_file(&self, _: &str) -> Result<(), String> {
            Err("unused".into())
        }
        async fn commit(&self, _: &str, _: &str) -> Result<(), String> {
            Err("unused".into())
        }
    }

    const SFTP: NameRules = NameRules { windows_names: false };
    const SMB: NameRules = NameRules { windows_names: true };

    /// A source whose last component is `..` or empty would name the
    /// destination folder's parent (or the folder itself): refused.
    #[test]
    fn a_source_without_a_safe_name_is_refused() {
        assert!(source_name(&SFTP, Direction::Download, "/srv/..").is_err());
        assert!(source_name(&SFTP, Direction::Download, "/").is_err());
        assert!(source_name(&SFTP, Direction::Upload, "/tmp/..").is_err());
        assert_eq!(source_name(&SFTP, Direction::Download, "/srv/data/").unwrap(), "data");
        assert_eq!(source_name(&SFTP, Direction::Upload, "/tmp/report.pdf").unwrap(), "report.pdf");
    }

    /// An SMB share applies Windows naming: an upload named like an NTFS
    /// stream (`a:b`) or a device (`NUL`) is refused before anything is
    /// written. SFTP keeps its POSIX rule.
    #[cfg(unix)]
    #[test]
    fn an_upload_name_must_be_valid_on_the_destination_server() {
        for bad in ["/tmp/a:b", "/tmp/NUL", "/tmp/trailing."] {
            let err = source_name(&SMB, Direction::Upload, bad).unwrap_err();
            assert!(err.contains("not valid on the SMB server"), "{err}");
            assert!(source_name(&SFTP, Direction::Upload, bad).is_ok(), "{bad}");
        }
        assert_eq!(source_name(&SMB, Direction::Upload, "/tmp/report.pdf").unwrap(), "report.pdf");
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
        let dir = std::env::temp_dir().join(format!("bv-sftp-test-{}", super::super::ssh::new_token()));
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

    /// Upload planning walks the local tree: a symlinked folder is skipped,
    /// never descended, and the plan lists a folder before its content.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_upload_plan_skips_symlinked_folders_and_orders_folders_first() {
        let dir = std::env::temp_dir().join(format!("bv-sftp-plan-{}", super::super::ssh::new_token()));
        std::fs::create_dir_all(dir.join("tree/sub")).unwrap();
        std::fs::write(dir.join("tree/sub/f.txt"), b"abc").unwrap();
        std::os::unix::fs::symlink(&dir, dir.join("tree/loop")).unwrap();
        for side in [&SFTP, &SMB] {
            let req = TransferRequest {
                transfer_id: "t".into(),
                direction: Direction::Upload,
                sources: vec![dir.join("tree").display().to_string()],
                dest_dir: "/srv".into(),
                overwrite: false,
            };
            let (plan, skipped) = plan_transfer(side, &req).await.unwrap();
            assert_eq!(skipped, 1, "the symlinked folder is skipped");
            let file = dir.join("tree/sub/f.txt").display().to_string();
            assert_eq!(
                plan,
                vec![
                    Step::Dir { dst: "/srv/tree".into() },
                    Step::Dir { dst: "/srv/tree/sub".into() },
                    Step::File { src: file, dst: "/srv/tree/sub/f.txt".into(), size: 3 },
                ]
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A local folder holding a name the SMB server cannot store refuses
    /// the whole upload at planning, before anything is written.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_smb_upload_plan_refuses_a_nested_windows_invalid_name() {
        let dir = std::env::temp_dir().join(format!("bv-smb-plan-{}", super::super::ssh::new_token()));
        std::fs::create_dir_all(dir.join("tree")).unwrap();
        std::fs::write(dir.join("tree/a:b"), b"x").unwrap();
        let req = TransferRequest {
            transfer_id: "t".into(),
            direction: Direction::Upload,
            sources: vec![dir.join("tree").display().to_string()],
            dest_dir: "/".into(),
            overwrite: false,
        };
        let err = plan_transfer(&SMB, &req).await.unwrap_err();
        assert!(err.contains("not valid on the SMB server"), "{err}");
        assert!(plan_transfer(&SFTP, &req).await.is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
