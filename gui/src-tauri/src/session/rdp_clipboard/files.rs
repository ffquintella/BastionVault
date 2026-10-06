//! File copy over `CLIPRDR` (T35 Phase 3): `FileGroupDescriptorW` lists and
//! `FileContents` streams, both directions.
//!
//! Everything here is a refusal path first. A file list is accepted whole or
//! refused whole — never trimmed to the part that fit, for the same reason
//! a text payload is dropped rather than truncated — and every refusal has a
//! [`FileRefusal`] reason the caller counts and audits.
//!
//! **Never logged:** file names, paths and contents, at any level. Reasons,
//! counts and byte totals only. (`ironrdp-cliprdr` itself logs remote file
//! names at `warn` while it sanitises them; `crate::run` caps that target at
//! `error` for exactly this reason.)
//!
//! - **Outbound** (host → session): the host clipboard's file list is
//!   validated against the caps, every name must be one a Windows target can
//!   create, and only the *basename* goes on the wire
//!   (`FILECLIP_NO_FILE_PATHS`) — never a host path. Contents are served
//!   from the snapshot that was advertised, re-checked against the size we
//!   advertised before every read.
//! - **Inbound** (session → host): the remote's list is validated again on
//!   top of `ironrdp`'s own sanitisation (separators stripped to the last
//!   component, traversal and absolute forms impossible, folders and nested
//!   paths refused, names the host filesystem could misread refused), sizes
//!   must be declared and within the caps, and files are written with
//!   `create_new` into a private per-session staging directory that is
//!   removed when the session ends.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ironrdp::cliprdr::pdu::{ClipboardFileAttributes, FileContentsFlags, FileContentsRequest, FileDescriptor};
use zeroize::Zeroizing;

use super::audit::TransferOutcome;

/// Largest single file, either direction.
pub const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
/// Largest total for one file list, either direction.
pub const MAX_TOTAL_FILE_BYTES: u64 = 1024 * 1024 * 1024;
/// Most files in one list.
pub const MAX_FILE_COUNT: usize = 128;
/// Bytes asked for per `FileContents` RANGE request, and the most we serve
/// to one. Small enough that a slow link still reports progress, large
/// enough that a 256 MiB file is 256 round trips.
pub const FILE_CHUNK_BYTES: u32 = 1024 * 1024;
/// How long one RANGE request may stay unanswered before the transfer is
/// abandoned. A stalled remote must not pin a half-written file forever.
pub const CHUNK_TIMEOUT: Duration = Duration::from_secs(30);
/// `cFileName` is 260 UTF-16 units including the terminator.
const MAX_NAME_UTF16: usize = 259;
/// The common per-component limit of host filesystems, in UTF-8 bytes.
const MAX_NAME_BYTES: usize = 255;
/// Removed by a later session if its owner died without cleaning up.
const STAGING_LOCK_FILE: &str = ".lock";

/// Why a file list was refused. The variant is the whole of what is logged
/// and audited about it — no name, no path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRefusal {
    Empty,
    TooMany,
    FileTooLarge,
    TotalTooLarge,
    /// A host clipboard entry that is not a regular file (a folder, a
    /// device, a dangling link).
    NotAFile,
    /// A remote folder entry. Folders are not carried in this phase.
    Folder,
    /// A remote entry inside a folder (a relative path).
    NestedPath,
    /// A name that cannot be created safely on the receiving side.
    BadName,
    DuplicateName,
    /// A remote descriptor without `FD_FILESIZE`: a size we cannot cap.
    UnknownSize,
    /// A host file whose metadata could not be read.
    Unreadable,
}

impl FileRefusal {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::TooMany => "too_many_files",
            Self::FileTooLarge => "file_too_large",
            Self::TotalTooLarge => "total_too_large",
            Self::NotAFile => "not_a_file",
            Self::Folder => "folder",
            Self::NestedPath => "nested_path",
            Self::BadName => "bad_name",
            Self::DuplicateName => "duplicate_name",
            Self::UnknownSize => "unknown_size",
            Self::Unreadable => "unreadable",
        }
    }

    pub fn outcome(self) -> TransferOutcome {
        match self {
            Self::TooMany | Self::FileTooLarge | Self::TotalTooLarge => TransferOutcome::Oversize,
            Self::Folder | Self::NestedPath => TransferOutcome::Refused,
            Self::Empty | Self::BadName | Self::DuplicateName | Self::UnknownSize => TransferOutcome::Malformed,
            Self::NotAFile | Self::Unreadable => TransferOutcome::Error,
        }
    }
}

/// A refused list, with the sizes the caller audits (one entry per file,
/// the advertised size where known, else 0). Sizes are metadata about the
/// attempt — never content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub reason: FileRefusal,
    pub sizes: Vec<u64>,
}

/// Characters no name may carry in either direction: the Windows-reserved
/// set (the remote is a Windows target, or the host may be one) plus the
/// Unicode look-alikes of the two path separators, which some filesystems
/// normalise to the real thing.
fn is_forbidden_char(c: char) -> bool {
    matches!(
        c,
        '<' | '>'
            | ':'
            | '"'
            | '/'
            | '\\'
            | '|'
            | '?'
            | '*'
            | '\u{2215}'
            | '\u{2044}'
            | '\u{29F8}'
            | '\u{FF0F}'
            | '\u{FF3C}'
    ) || c.is_control()
}

/// The checks both directions share: non-empty, bounded, no forbidden or
/// control characters, not `.`/`..`, no trailing dot or space and no
/// leading space (Windows silently strips those, so two different names
/// would collide), not a Windows device name.
fn is_acceptable_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.len() <= MAX_NAME_BYTES
        && name.encode_utf16().count() <= MAX_NAME_UTF16
        && !name.chars().any(is_forbidden_char)
        && !name.ends_with('.')
        && !name.ends_with(' ')
        && !name.starts_with(' ')
        && !ironrdp::cliprdr::is_windows_device_name(name)
}

/// Sanitise a file name received from the remote.
///
/// Separators are *stripped*: only the last `/`- or `\`-separated component
/// survives, so no traversal or absolute form can reach the filesystem even
/// if a name arrives that `ironrdp` did not split. The survivor must then
/// pass [`is_acceptable_name`]; anything else is `None`.
pub fn sanitize_inbound_name(raw: &str) -> Option<String> {
    let raw = raw.trim_end_matches('\0');
    if raw.contains('\0') {
        return None;
    }
    let last = raw.rsplit(['/', '\\']).next().unwrap_or("");
    is_acceptable_name(last).then(|| last.to_string())
}

// ─── Outbound (host → session) ───────────────────────────────────────

/// One host file we advertised. `size` is what we told the remote; the
/// file is re-checked against it before every read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundFile {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
}

/// A host file list as advertised. `generation` distinguishes one copy from
/// the next, so a range served for an old list is never attributed to a new
/// one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundList {
    pub generation: u64,
    pub files: Vec<OutboundFile>,
}

/// What `build_outbound` needs to know about a path. A trait object so the
/// tests can describe files without a filesystem.
pub trait Stat {
    /// `Ok(Some(len))` for a regular file, `Ok(None)` for anything else.
    fn regular_file_len(&self, path: &Path) -> io::Result<Option<u64>>;
}

/// The real filesystem. Follows symlinks: the operator chose the entry in
/// their file manager, and what they mean is the file it shows.
pub struct Fs;

impl Stat for Fs {
    fn regular_file_len(&self, path: &Path) -> io::Result<Option<u64>> {
        let m = std::fs::metadata(path)?;
        Ok(m.is_file().then_some(m.len()))
    }
}

/// Validate the host clipboard's file list for advertising.
///
/// Every rule here is at least as strict as the filter
/// `Cliprdr::initiate_file_copy` applies on its own (non-empty, at most 259
/// characters, not absolute) — it counts characters, this counts UTF-16
/// units — so `ironrdp` never drops an entry we kept. That matters: the
/// remote addresses files by *index*, and a list `ironrdp` had thinned would
/// put a different file behind the same index here.
pub fn build_outbound(paths: &[PathBuf], generation: u64, stat: &dyn Stat) -> Result<OutboundList, Refused> {
    let mut sizes = Vec::with_capacity(paths.len().min(MAX_FILE_COUNT + 1));
    let refuse = |reason, sizes: &Vec<u64>, extra: usize| Refused {
        reason,
        sizes: sizes.iter().copied().chain(std::iter::repeat_n(0, extra)).collect(),
    };
    if paths.is_empty() {
        return Err(Refused { reason: FileRefusal::Empty, sizes });
    }
    if paths.len() > MAX_FILE_COUNT {
        return Err(Refused { reason: FileRefusal::TooMany, sizes: vec![0; paths.len()] });
    }
    let mut files = Vec::with_capacity(paths.len());
    let mut seen: HashSet<String> = HashSet::new();
    let mut total: u64 = 0;
    for (i, path) in paths.iter().enumerate() {
        let remaining = paths.len() - i - 1;
        let len = match stat.regular_file_len(path) {
            Ok(Some(len)) => len,
            Ok(None) => return Err(refuse(FileRefusal::NotAFile, &sizes, remaining + 1)),
            Err(_) => return Err(refuse(FileRefusal::Unreadable, &sizes, remaining + 1)),
        };
        sizes.push(len);
        let Some(name) = path.file_name().and_then(|n| n.to_str()).filter(|n| is_acceptable_name(n)) else {
            return Err(refuse(FileRefusal::BadName, &sizes, remaining));
        };
        if !seen.insert(name.to_lowercase()) {
            return Err(refuse(FileRefusal::DuplicateName, &sizes, remaining));
        }
        if len > MAX_FILE_BYTES {
            return Err(refuse(FileRefusal::FileTooLarge, &sizes, remaining));
        }
        total = total.saturating_add(len);
        if total > MAX_TOTAL_FILE_BYTES {
            return Err(refuse(FileRefusal::TotalTooLarge, &sizes, remaining));
        }
        files.push(OutboundFile { path: path.clone(), name: name.to_string(), size: len });
    }
    Ok(OutboundList { generation, files })
}

/// The wire descriptors for an advertised list: basename, size, `NORMAL`.
/// No host path, no timestamps.
pub fn descriptors(list: &OutboundList) -> Vec<FileDescriptor> {
    list.files
        .iter()
        .map(|f| {
            FileDescriptor::new(f.name.clone()).with_file_size(f.size).with_attributes(ClipboardFileAttributes::NORMAL)
        })
        .collect()
}

/// One served `FileContents` request.
#[derive(Debug)]
pub enum Served {
    Size(u64),
    Data(Zeroizing<Vec<u8>>),
}

/// Why a `FileContents` request was answered with `CB_RESPONSE_FAIL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeRefusal {
    BadIndex,
    /// More than [`FILE_CHUNK_BYTES`] in one request, or a range past EOF.
    BadRange,
    /// The file is no longer the one we advertised (size changed, gone,
    /// replaced by something that is not a regular file).
    Changed,
    Io,
}

/// Answer one request against the list it refers to.
pub fn serve(list: &OutboundList, req: &FileContentsRequest) -> Result<Served, ServeRefusal> {
    let index = usize::try_from(req.index).map_err(|_| ServeRefusal::BadIndex)?;
    let file = list.files.get(index).ok_or(ServeRefusal::BadIndex)?;
    if req.flags.contains(FileContentsFlags::SIZE) {
        return Ok(Served::Size(file.size));
    }
    if !req.flags.contains(FileContentsFlags::RANGE) {
        return Err(ServeRefusal::BadRange);
    }
    if req.requested_size > FILE_CHUNK_BYTES || req.position > file.size {
        return Err(ServeRefusal::BadRange);
    }
    let len = u64::from(req.requested_size).min(file.size - req.position);
    // Re-check before reading: a file swapped or resized since we advertised
    // it is refused, never read under the old size.
    match Fs.regular_file_len(&file.path) {
        Ok(Some(n)) if n == file.size => {}
        Ok(_) => return Err(ServeRefusal::Changed),
        Err(_) => return Err(ServeRefusal::Changed),
    }
    let mut f = File::open(&file.path).map_err(|_| ServeRefusal::Io)?;
    f.seek(SeekFrom::Start(req.position)).map_err(|_| ServeRefusal::Io)?;
    let mut buf = Zeroizing::new(vec![0u8; len as usize]);
    f.read_exact(&mut buf).map_err(|_| ServeRefusal::Changed)?;
    Ok(Served::Data(buf))
}

// ─── Inbound (session → host) ────────────────────────────────────────

/// One remote file we accepted, under its sanitised name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundFile {
    pub name: String,
    pub size: u64,
}

/// Validate the remote's file list (after `ironrdp`'s own sanitisation).
pub fn validate_inbound(files: &[FileDescriptor]) -> Result<Vec<InboundFile>, Refused> {
    let advertised: Vec<u64> = files.iter().map(|f| f.file_size.unwrap_or(0)).collect();
    let refuse = |reason| Refused { reason, sizes: advertised.clone() };
    if files.is_empty() {
        return Err(refuse(FileRefusal::Empty));
    }
    if files.len() > MAX_FILE_COUNT {
        return Err(refuse(FileRefusal::TooMany));
    }
    let mut out = Vec::with_capacity(files.len());
    let mut seen: HashSet<String> = HashSet::new();
    let mut total: u64 = 0;
    for f in files {
        if f.attributes.is_some_and(|a| a.contains(ClipboardFileAttributes::DIRECTORY)) {
            return Err(refuse(FileRefusal::Folder));
        }
        if f.relative_path.as_deref().is_some_and(|p| !p.is_empty()) {
            return Err(refuse(FileRefusal::NestedPath));
        }
        let Some(size) = f.file_size else {
            return Err(refuse(FileRefusal::UnknownSize));
        };
        let Some(name) = sanitize_inbound_name(&f.name) else {
            return Err(refuse(FileRefusal::BadName));
        };
        // Case-insensitive: the host filesystem very likely is.
        if !seen.insert(name.to_lowercase()) {
            return Err(refuse(FileRefusal::DuplicateName));
        }
        if size > MAX_FILE_BYTES {
            return Err(refuse(FileRefusal::FileTooLarge));
        }
        total = total.saturating_add(size);
        if total > MAX_TOTAL_FILE_BYTES {
            return Err(refuse(FileRefusal::TotalTooLarge));
        }
        out.push(InboundFile { name, size });
    }
    Ok(out)
}

#[cfg(unix)]
fn restrict_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn restrict_dir(_dir: &Path) -> io::Result<()> {
    // Under the per-user application cache directory, which is already
    // private to the account on Windows.
    Ok(())
}

/// Create a file that must not exist yet, private to the user. `create_new`
/// refuses an existing entry *including a symlink*, so nothing planted in
/// the staging directory can be written through.
fn create_private_file(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// The session's private directory for received files:
/// `<app cache>/rdp-clipboard/<session token>/`, mode 0700, holding a
/// `.lock` for as long as the session lives so a later session can tell a
/// dead owner's leftovers from a live one's. Removed on drop.
#[derive(Debug)]
pub struct StagingDir {
    root: PathBuf,
    _lock: File,
    next_transfer: u64,
    current: Option<PathBuf>,
}

impl StagingDir {
    pub fn create(base: &Path, token: &str) -> io::Result<Self> {
        std::fs::create_dir_all(base)?;
        restrict_dir(base)?;
        sweep_dead(base, token);
        let root = base.join(token);
        std::fs::create_dir(&root)?;
        restrict_dir(&root)?;
        let lock = OpenOptions::new().read(true).write(true).create_new(true).open(root.join(STAGING_LOCK_FILE))?;
        lock.try_lock().map_err(|e| io::Error::other(format!("lock staging dir: {e}")))?;
        Ok(Self { root, _lock: lock, next_transfer: 0, current: None })
    }

    /// A fresh directory for one received list. The previous one is
    /// removed: the host clipboard now points at the new list, and a
    /// privileged file should not outlive its use on the operator's disk.
    pub fn new_transfer_dir(&mut self) -> io::Result<PathBuf> {
        if let Some(old) = self.current.take() {
            let _ = std::fs::remove_dir_all(old);
        }
        let dir = self.root.join(format!("t{}", self.next_transfer));
        self.next_transfer += 1;
        std::fs::create_dir(&dir)?;
        restrict_dir(&dir)?;
        self.current = Some(dir.clone());
        Ok(dir)
    }

    /// Remove a transfer directory that failed part-way.
    pub fn discard(&mut self, dir: &Path) {
        if self.current.as_deref() == Some(dir) {
            self.current = None;
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(test)]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.root) {
            if e.kind() != io::ErrorKind::NotFound {
                log::warn!("rdp clipboard: could not remove the session's received-files directory: {e}");
            }
        }
    }
}

/// Remove sibling session directories whose owner is gone (its `.lock` can
/// be taken here). A live session's lock is held, so it is never touched.
fn sweep_dead(base: &Path, own: &str) {
    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy() == own || !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let path = entry.path();
        if let Ok(lock) = OpenOptions::new().read(true).write(true).open(path.join(STAGING_LOCK_FILE)) {
            if lock.try_lock().is_ok() {
                drop(lock);
                let _ = std::fs::remove_dir_all(&path);
            }
        }
    }
}

/// Why an inbound transfer was abandoned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferFailure {
    /// `CB_RESPONSE_FAIL` from the remote.
    RemoteError,
    /// A response for a stream we are not waiting on.
    UnexpectedStream,
    /// More bytes than requested, or past the declared size.
    Overlong,
    /// An empty response before the declared size was reached.
    Truncated,
    TimedOut,
    Io,
}

impl TransferFailure {
    pub fn reason(self) -> &'static str {
        match self {
            Self::RemoteError => "remote_error",
            Self::UnexpectedStream => "unexpected_stream",
            Self::Overlong => "overlong",
            Self::Truncated => "truncated",
            Self::TimedOut => "timed_out",
            Self::Io => "io",
        }
    }

    pub fn outcome(self) -> TransferOutcome {
        match self {
            Self::Overlong | Self::Truncated | Self::UnexpectedStream => TransferOutcome::Malformed,
            Self::RemoteError | Self::TimedOut | Self::Io => TransferOutcome::Error,
        }
    }
}

/// What the bridge does next for an inbound transfer.
#[derive(Debug)]
pub enum Step {
    Request(FileContentsRequest),
    /// Every file is on disk, in list order.
    Complete(Vec<PathBuf>),
}

#[derive(Debug)]
struct Pending {
    stream_id: u32,
    requested: u32,
    deadline: Instant,
}

/// One remote file list being downloaded, a file at a time, a chunk at a
/// time. Sequential on purpose: one outstanding request makes every
/// response attributable and bounds memory to one chunk.
#[derive(Debug)]
pub struct InboundTransfer {
    dir: PathBuf,
    files: Vec<InboundFile>,
    clip_data_id: Option<u32>,
    current: usize,
    position: u64,
    handle: Option<File>,
    pending: Option<Pending>,
    written: Vec<PathBuf>,
}

fn next_stream_id(counter: &mut u32) -> u32 {
    *counter = counter.wrapping_add(1).max(1);
    *counter
}

impl InboundTransfer {
    /// Start writing `files` into `dir`. Zero-length files are created and
    /// closed immediately; the first non-empty one gets a request.
    pub fn start(
        dir: PathBuf,
        files: Vec<InboundFile>,
        clip_data_id: Option<u32>,
        stream_ids: &mut u32,
        now: Instant,
    ) -> Result<(Self, Step), TransferFailure> {
        let mut t = Self {
            dir,
            files,
            clip_data_id,
            current: 0,
            position: 0,
            handle: None,
            pending: None,
            written: Vec::new(),
        };
        let step = t.advance(stream_ids, now)?;
        Ok((t, step))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn sizes(&self) -> Vec<u64> {
        self.files.iter().map(|f| f.size).collect()
    }

    /// Open files and issue the next request, skipping empty files.
    fn advance(&mut self, stream_ids: &mut u32, now: Instant) -> Result<Step, TransferFailure> {
        loop {
            let Some(file) = self.files.get(self.current) else {
                return Ok(Step::Complete(std::mem::take(&mut self.written)));
            };
            if self.handle.is_none() {
                let path = self.dir.join(&file.name);
                // `name` passed `sanitize_inbound_name`: a single
                // component, so the join cannot leave `dir`.
                debug_assert_eq!(path.parent(), Some(self.dir.as_path()));
                self.handle = Some(create_private_file(&path).map_err(|_| TransferFailure::Io)?);
                self.written.push(path);
                self.position = 0;
            }
            if self.position == file.size {
                if let Some(h) = self.handle.take() {
                    h.sync_all().map_err(|_| TransferFailure::Io)?;
                }
                self.current += 1;
                continue;
            }
            let requested =
                u32::try_from((file.size - self.position).min(u64::from(FILE_CHUNK_BYTES))).unwrap_or(FILE_CHUNK_BYTES);
            let stream_id = next_stream_id(stream_ids);
            self.pending = Some(Pending { stream_id, requested, deadline: now + CHUNK_TIMEOUT });
            return Ok(Step::Request(FileContentsRequest {
                stream_id,
                index: i32::try_from(self.current).map_err(|_| TransferFailure::Io)?,
                flags: FileContentsFlags::RANGE,
                position: self.position,
                requested_size: requested,
                data_id: self.clip_data_id,
            }));
        }
    }

    /// Apply one response.
    pub fn on_chunk(
        &mut self,
        stream_id: u32,
        is_error: bool,
        data: &[u8],
        stream_ids: &mut u32,
        now: Instant,
    ) -> Result<Step, TransferFailure> {
        let pending = self.pending.take().ok_or(TransferFailure::UnexpectedStream)?;
        if pending.stream_id != stream_id {
            return Err(TransferFailure::UnexpectedStream);
        }
        if is_error {
            return Err(TransferFailure::RemoteError);
        }
        if data.len() > pending.requested as usize {
            return Err(TransferFailure::Overlong);
        }
        if data.is_empty() {
            return Err(TransferFailure::Truncated);
        }
        let size = self.files[self.current].size;
        let end = self.position.checked_add(data.len() as u64).ok_or(TransferFailure::Overlong)?;
        if end > size {
            return Err(TransferFailure::Overlong);
        }
        let h = self.handle.as_mut().ok_or(TransferFailure::Io)?;
        h.write_all(data).map_err(|_| TransferFailure::Io)?;
        self.position = end;
        self.advance(stream_ids, now)
    }

    pub fn timed_out(&self, now: Instant) -> bool {
        self.pending.as_ref().is_some_and(|p| now >= p.deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bv-clip-test-{name}-{}", crate::session::rdp::new_token()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    struct FakeStat(Vec<(&'static str, Option<u64>)>);
    impl Stat for FakeStat {
        fn regular_file_len(&self, path: &Path) -> io::Result<Option<u64>> {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            self.0
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, len)| *len)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing"))
        }
    }

    fn desc(name: &str, size: Option<u64>) -> FileDescriptor {
        let d = FileDescriptor::new(name);
        match size {
            Some(s) => d.with_file_size(s),
            None => d,
        }
    }

    #[test]
    fn inbound_names_lose_their_separators_and_never_traverse() {
        assert_eq!(sanitize_inbound_name("report.txt").as_deref(), Some("report.txt"));
        assert_eq!(sanitize_inbound_name("..\\..\\Windows\\evil.dll").as_deref(), Some("evil.dll"));
        assert_eq!(sanitize_inbound_name("C:\\Users\\x\\a.txt").as_deref(), Some("a.txt"));
        assert_eq!(sanitize_inbound_name("/etc/cron.d/job").as_deref(), Some("job"));
        assert_eq!(sanitize_inbound_name("\\\\server\\share\\b.txt").as_deref(), Some("b.txt"));
        assert_eq!(sanitize_inbound_name("name.txt\0\0").as_deref(), Some("name.txt"));
        for bad in [
            "",
            ".",
            "..",
            "../",
            "a\\..",
            "dir/",
            "with\0nul",
            "CON",
            "nul.txt",
            "LPT1.log",
            "trail.",
            "trail ",
            " lead",
            "a:b",
            "a|b",
            "a?b",
            "a*b",
            "a\"b",
            "a<b",
            "a>b",
            "tab\there",
            "nl\nhere",
            "esc\u{1b}",
            "fake\u{2215}slash",
            "full\u{FF0F}width",
            "full\u{FF3C}back",
        ] {
            assert_eq!(sanitize_inbound_name(bad), None, "{bad:?} must be refused");
        }
        assert_eq!(sanitize_inbound_name(&"a".repeat(MAX_NAME_BYTES + 1)), None);
        // 200 three-byte characters is 600 UTF-8 bytes: over the byte limit.
        assert_eq!(sanitize_inbound_name(&"日".repeat(200)), None);
    }

    #[test]
    fn an_inbound_list_is_accepted_whole_or_refused_whole() {
        let ok = validate_inbound(&[desc("a.txt", Some(3)), desc("b.bin", Some(0))]).unwrap();
        assert_eq!(
            ok,
            vec![InboundFile { name: "a.txt".into(), size: 3 }, InboundFile { name: "b.bin".into(), size: 0 }]
        );

        let folder = desc("dir", Some(0)).with_attributes(ClipboardFileAttributes::DIRECTORY);
        let nested = desc("x.txt", Some(1)).with_relative_path("dir");
        let cases: Vec<(Vec<FileDescriptor>, FileRefusal)> = vec![
            (vec![], FileRefusal::Empty),
            (vec![desc("a", Some(1)), folder], FileRefusal::Folder),
            (vec![nested], FileRefusal::NestedPath),
            (vec![desc("a", None)], FileRefusal::UnknownSize),
            (vec![desc("CON", Some(1))], FileRefusal::BadName),
            (vec![desc("A.txt", Some(1)), desc("a.TXT", Some(1))], FileRefusal::DuplicateName),
            (vec![desc("big", Some(MAX_FILE_BYTES + 1))], FileRefusal::FileTooLarge),
            ((0..5).map(|i| desc(&format!("f{i}"), Some(MAX_FILE_BYTES))).collect(), FileRefusal::TotalTooLarge),
            ((0..=MAX_FILE_COUNT).map(|i| desc(&format!("f{i}"), Some(1))).collect(), FileRefusal::TooMany),
        ];
        for (files, want) in cases {
            let err = validate_inbound(&files).unwrap_err();
            assert_eq!(err.reason, want);
            assert_eq!(err.sizes.len(), files.len(), "one audit entry per advertised file");
        }
    }

    #[test]
    fn an_outbound_list_sends_basenames_only_and_respects_the_caps() {
        let stat = FakeStat(vec![
            ("a.txt", Some(5)),
            ("b.log", Some(0)),
            ("dir", None),
            ("huge.iso", Some(MAX_FILE_BYTES + 1)),
        ]);
        let list =
            build_outbound(&[PathBuf::from("/home/op/secret/a.txt"), PathBuf::from("/tmp/b.log")], 7, &stat).unwrap();
        assert_eq!(list.generation, 7);
        let d = descriptors(&list);
        assert_eq!(d.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), vec!["a.txt", "b.log"]);
        assert!(d.iter().all(|f| f.relative_path.is_none()), "no host path may reach the wire");
        assert_eq!(d[0].file_size, Some(5));

        let refused = |paths: &[&str]| {
            build_outbound(&paths.iter().map(PathBuf::from).collect::<Vec<_>>(), 0, &stat).unwrap_err()
        };
        assert_eq!(refused(&["/x/dir"]).reason, FileRefusal::NotAFile);
        assert_eq!(refused(&["/x/missing"]).reason, FileRefusal::Unreadable);
        assert_eq!(refused(&["/x/huge.iso"]).reason, FileRefusal::FileTooLarge);
        assert_eq!(refused(&["/x/a.txt", "/y/a.txt"]).reason, FileRefusal::DuplicateName);
        let r = refused(&["/x/a.txt", "/x/huge.iso", "/x/b.log"]);
        assert_eq!(r.sizes.len(), 3, "every advertised file is accounted for");
        assert_eq!(build_outbound(&[], 0, &stat).unwrap_err().reason, FileRefusal::Empty);
    }

    #[test]
    fn serve_reads_the_advertised_range_and_refuses_a_changed_file() {
        let dir = tmp("serve");
        let path = dir.join("data.bin");
        std::fs::write(&path, b"0123456789").unwrap();
        let list = OutboundList {
            generation: 1,
            files: vec![OutboundFile { path: path.clone(), name: "data.bin".into(), size: 10 }],
        };
        let req = |flags, position, size| FileContentsRequest {
            stream_id: 1,
            index: 0,
            flags,
            position,
            requested_size: size,
            data_id: None,
        };

        assert!(matches!(serve(&list, &req(FileContentsFlags::SIZE, 0, 8)), Ok(Served::Size(10))));
        match serve(&list, &req(FileContentsFlags::RANGE, 2, 4)) {
            Ok(Served::Data(d)) => assert_eq!(&d[..], b"2345"),
            other => panic!("{other:?}"),
        }
        // The final short chunk is served short, not padded.
        match serve(&list, &req(FileContentsFlags::RANGE, 8, 1024)) {
            Ok(Served::Data(d)) => assert_eq!(&d[..], b"89"),
            other => panic!("{other:?}"),
        }
        assert_eq!(serve(&list, &req(FileContentsFlags::RANGE, 11, 1)).unwrap_err(), ServeRefusal::BadRange);
        assert_eq!(
            serve(&list, &req(FileContentsFlags::RANGE, 0, FILE_CHUNK_BYTES + 1)).unwrap_err(),
            ServeRefusal::BadRange
        );
        let mut bad_index = req(FileContentsFlags::RANGE, 0, 1);
        bad_index.index = 1;
        assert_eq!(serve(&list, &bad_index).unwrap_err(), ServeRefusal::BadIndex);

        // Resized after it was advertised: refused, not read under the old size.
        std::fs::write(&path, b"0123").unwrap();
        assert_eq!(serve(&list, &req(FileContentsFlags::RANGE, 0, 4)).unwrap_err(), ServeRefusal::Changed);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_inbound_transfer_writes_every_file_in_order() {
        let dir = tmp("inbound");
        let mut ids = 0u32;
        let now = Instant::now();
        let files = vec![
            InboundFile { name: "empty".into(), size: 0 },
            InboundFile { name: "a.txt".into(), size: 5 },
            InboundFile { name: "b.txt".into(), size: 2 },
        ];
        let (mut t, step) = InboundTransfer::start(dir.clone(), files, Some(9), &mut ids, now).unwrap();
        let Step::Request(r) = step else { panic!("expected a request") };
        assert_eq!((r.index, r.position, r.requested_size, r.data_id), (1, 0, 5, Some(9)));
        let step = t.on_chunk(r.stream_id, false, b"hel", &mut ids, now).unwrap();
        let Step::Request(r) = step else { panic!("expected the rest of a.txt") };
        assert_eq!((r.index, r.position, r.requested_size), (1, 3, 2));
        let step = t.on_chunk(r.stream_id, false, b"lo", &mut ids, now).unwrap();
        let Step::Request(r) = step else { panic!("expected b.txt") };
        assert_eq!(r.index, 2);
        let Step::Complete(paths) = t.on_chunk(r.stream_id, false, b"ok", &mut ids, now).unwrap() else {
            panic!("expected completion")
        };
        assert_eq!(paths.len(), 3);
        assert_eq!(std::fs::read(&paths[0]).unwrap(), b"");
        assert_eq!(std::fs::read(&paths[1]).unwrap(), b"hello");
        assert_eq!(std::fs::read(&paths[2]).unwrap(), b"ok");
        assert!(paths.iter().all(|p| p.parent() == Some(dir.as_path())));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_misbehaving_remote_aborts_the_transfer() {
        let now = Instant::now();
        let files = || vec![InboundFile { name: "a.txt".into(), size: 4 }];
        let cases: Vec<(&str, Box<dyn Fn(u32) -> (u32, bool, Vec<u8>)>, TransferFailure)> = vec![
            ("error response", Box::new(|id| (id, true, vec![])), TransferFailure::RemoteError),
            ("wrong stream", Box::new(|id| (id + 1, false, b"abcd".to_vec())), TransferFailure::UnexpectedStream),
            ("more than asked", Box::new(|id| (id, false, b"abcde".to_vec())), TransferFailure::Overlong),
            ("empty before eof", Box::new(|id| (id, false, vec![])), TransferFailure::Truncated),
        ];
        for (what, reply, want) in cases {
            let dir = tmp("abort");
            let mut ids = 0u32;
            let (mut t, Step::Request(r)) = InboundTransfer::start(dir.clone(), files(), None, &mut ids, now).unwrap()
            else {
                panic!("expected a request")
            };
            let (id, err, data) = reply(r.stream_id);
            assert_eq!(t.on_chunk(id, err, &data, &mut ids, now).unwrap_err(), want, "{what}");
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn a_stalled_request_times_out() {
        let dir = tmp("timeout");
        let mut ids = 0u32;
        let now = Instant::now();
        let (t, _) =
            InboundTransfer::start(dir.clone(), vec![InboundFile { name: "a".into(), size: 1 }], None, &mut ids, now)
                .unwrap();
        assert!(!t.timed_out(now));
        assert!(t.timed_out(now + CHUNK_TIMEOUT));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_planted_file_is_never_written_through() {
        // `create_new` refuses an existing entry, including a symlink planted
        // where a received file is about to land.
        let dir = tmp("planted");
        std::fs::write(dir.join("a.txt"), b"planted").unwrap();
        let mut ids = 0u32;
        let err = InboundTransfer::start(
            dir.clone(),
            vec![InboundFile { name: "a.txt".into(), size: 1 }],
            None,
            &mut ids,
            Instant::now(),
        )
        .unwrap_err();
        assert_eq!(err, TransferFailure::Io);
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"planted");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_staging_dir_is_private_and_removed_with_the_session() {
        let base = tmp("staging");
        let root;
        {
            let mut s = StagingDir::create(&base, "rdp_test").unwrap();
            root = s.root().to_path_buf();
            let t1 = s.new_transfer_dir().unwrap();
            std::fs::write(t1.join("x"), b"1").unwrap();
            let t2 = s.new_transfer_dir().unwrap();
            assert!(!t1.exists(), "the previous transfer is removed when a new one lands");
            assert!(t2.exists());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(std::fs::metadata(&root).unwrap().permissions().mode() & 0o777, 0o700);
            }
        }
        assert!(!root.exists(), "dropping the session removes everything it received");
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn a_dead_sessions_leftovers_are_swept_and_a_live_one_is_not() {
        let base = tmp("sweep");
        let live = StagingDir::create(&base, "rdp_live").unwrap();
        // A dead owner: its lock file exists but nobody holds it.
        let dead = base.join("rdp_dead");
        std::fs::create_dir(&dead).unwrap();
        std::fs::write(dead.join(STAGING_LOCK_FILE), b"").unwrap();
        let _next = StagingDir::create(&base, "rdp_next").unwrap();
        assert!(!dead.exists(), "a dead session's directory is swept");
        assert!(live.root().exists(), "a live session's directory survives");
        drop(live);
        drop(_next);
        std::fs::remove_dir_all(base).unwrap();
    }
}
