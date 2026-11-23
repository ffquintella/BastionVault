//! SMB session driver (features/smb-connect.md).
//!
//! An `smb` connection profile opens the same dual-pane window as `sftp`,
//! with an SMB2/3 share on the right. The client is `smolder-smb-core`
//! (pure Rust): NTLM authentication, SMB 2.1 / 3.0.2 / 3.1.1, and message
//! signing *required* — a guest or anonymous session, or one that is
//! neither signed nor encrypted, is refused at open.

//! The session holds the tree connection and drives its typed requests
//! directly, so a transfer streams in [`IO_CHUNK`] pieces with progress and
//! cancel. Paths are POSIX-style (`/` is the share root, `\` is normalised
//! to `/`) and every component must be a valid Windows name: `a:b` would
//! address an NTFS stream. There is no host key — the server is identified
//! by NTLM and the signed session only (spec "Security considerations").

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use smolder_core::auth::NtlmCredentials;
use smolder_core::client::{Connection, TreeConnected};
use smolder_core::error::CoreError;
use smolder_core::facade::Client;
use smolder_core::pipe::connect_tree_with_transport;
use smolder_core::transport::TokioTcpTransport;
use smolder_proto::smb::smb2::{
    CloseRequest, CreateDisposition, CreateOptions, CreateRequest, CreateResponse, DispositionInformation,
    FileAttributes, FileId, FileInfoClass, FlushRequest, QueryDirectoryFlags, QueryDirectoryRequest, ReadRequest,
    RenameInformation, SessionFlags, SetInfoRequest, ShareAccess, SigningMode, WriteRequest,
};
use tauri::AppHandle;
use zeroize::Zeroizing;

use super::file_transfer::{
    is_safe_entry_name, is_windows_file_name, remote_join, remote_parent, Entry, EntryKind, Listing, RemoteFs,
    RemoteReader, RemoteWriter, SourceKind, MAX_PLANNED_ENTRIES,
};
use super::ssh::{new_token, ClosedPayload};
use super::{SessionCleanup, SessionState};

type Conn = Connection<TokioTcpTransport, TreeConnected>;

/// Largest READ / WRITE sent: one credit's worth, as the library's own
/// facade does (larger requests need multi-credit charges).
const IO_CHUNK: usize = u16::MAX as usize;

/// One request's budget. A request that overruns it leaves the connection
/// in an unknown state, so the connection is dropped, not reused.
const OP_TIMEOUT: Duration = Duration::from_secs(60);

/// Idle keepalive: an ECHO this often notices a dead connection and keeps
/// an idle one open.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Longest path sent (characters); far below the protocol's own limit.
const MAX_PATH_CHARS: usize = 4096;

// Access-mask and attribute bits (MS-SMB2 2.2.13.1, MS-FSCC 2.6).
const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const DELETE: u32 = 0x0001_0000;
const READ_CONTROL: u32 = 0x0002_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const ATTR_DIRECTORY: u32 = 0x0000_0010;
const ATTR_REPARSE_POINT: u32 = 0x0000_0400;

// NTSTATUS values the messages name (MS-ERREF 2.3.1).
const STATUS_NO_SUCH_FILE: u32 = 0xC000_000F;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
const STATUS_SHARING_VIOLATION: u32 = 0xC000_0043;
const STATUS_DELETE_PENDING: u32 = 0xC000_0056;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_LOGON_FAILURE: u32 = 0xC000_006D;
const STATUS_ACCOUNT_RESTRICTION: u32 = 0xC000_006E;
const STATUS_PASSWORD_EXPIRED: u32 = 0xC000_0071;
const STATUS_ACCOUNT_DISABLED: u32 = 0xC000_0072;
const STATUS_DISK_FULL: u32 = 0xC000_007F;
const STATUS_FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
const STATUS_NETWORK_NAME_DELETED: u32 = 0xC000_00C9;
const STATUS_BAD_NETWORK_NAME: u32 = 0xC000_00CC;
const STATUS_DIRECTORY_NOT_EMPTY: u32 = 0xC000_0101;
const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
const STATUS_LOGON_TYPE_NOT_GRANTED: u32 = 0xC000_015B;
const STATUS_USER_SESSION_DELETED: u32 = 0xC000_0203;
const STATUS_PASSWORD_MUST_CHANGE: u32 = 0xC000_0224;
const STATUS_ACCOUNT_LOCKED_OUT: u32 = 0xC000_0234;
const STATUS_STOPPED_ON_SYMLINK: u32 = 0x8000_002D;

// ── Profile ──────────────────────────────────────────────────────────

/// The SMB-only fields of a connection profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbProfile {
    /// The share name alone (`files`, not `\\host\files`).
    pub share: String,
    /// NTLM domain for a bare username; `None` when unset or empty.
    pub domain: Option<String>,
}

/// Characters no share or NetBIOS domain name may hold.
fn has_forbidden_name_chars(s: &str) -> bool {
    s.chars().any(|c| matches!(c, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|') || c.is_control())
}

/// A share name as `\\host\<share>` takes it: 1–80 characters, no
/// separator, wildcard or control character, no surrounding space.
pub fn is_valid_share_name(s: &str) -> bool {
    !s.is_empty() && s.chars().count() <= 80 && s.trim() == s && s != "." && s != ".." && !has_forbidden_name_chars(s)
}

/// Read `share` (required) and `domain` (optional) off an `smb` profile.
/// Strict: a missing or malformed share is an error, never a default.
pub fn parse_smb_profile(profile: &Value) -> Result<SmbProfile, String> {
    let share = match profile.get("share") {
        Some(Value::String(s)) => s.clone(),
        Some(_) => return Err("SMB profile `share` is not a string".into()),
        None => return Err("SMB profile has no `share`; set the share name (for example `files`)".into()),
    };
    if !is_valid_share_name(&share) {
        return Err(format!(
            "SMB profile share `{}` is not a valid share name (1-80 characters, no \\ / : * ? \" < > | or control \
             characters, no surrounding spaces)",
            share.escape_debug()
        ));
    }
    let domain = match profile.get("domain") {
        None | Some(Value::Null) => None,
        Some(Value::String(d)) if d.trim().is_empty() => None,
        Some(Value::String(d)) => {
            let d = d.trim();
            if d.chars().count() > 255 || has_forbidden_name_chars(d) {
                return Err(format!("SMB profile domain `{}` is not a valid domain name", d.escape_debug()));
            }
            Some(d.to_string())
        }
        Some(_) => return Err("SMB profile `domain` is not a string".into()),
    };
    Ok(SmbProfile { share, domain })
}

/// The NTLM user and domain for a resolved login. A domain carried by the
/// login itself (`CORP\user`, `user@corp.example`, or the credential
/// source's own) wins; the profile's `domain` applies to a bare user.
pub fn ntlm_identity(
    username: &str,
    resolved_domain: Option<String>,
    profile_domain: Option<&str>,
) -> (String, Option<String>) {
    if let Some(d) = resolved_domain.filter(|d| !d.is_empty()) {
        return (username.to_string(), Some(d));
    }
    let (user, split) = split_login(username);
    match split {
        Some(d) => (user, Some(d)),
        None => (user, profile_domain.map(str::to_string)),
    }
}

/// `DOMAIN\user` or `user@realm` into `(user, Some(domain))`.
fn split_login(input: &str) -> (String, Option<String>) {
    if let Some((domain, user)) = input.split_once('\\') {
        if !domain.is_empty() && !user.is_empty() {
            return (user.to_string(), Some(domain.to_string()));
        }
    }
    if let Some((user, realm)) = input.rsplit_once('@') {
        if !user.is_empty() && !realm.is_empty() {
            return (user.to_string(), Some(realm.to_string()));
        }
    }
    (input.to_string(), None)
}

// ── Paths ────────────────────────────────────────────────────────────

/// A share path from the window in canonical form: `\` read as `/`,
/// empty components dropped, `/` for the root. Refuses NUL, `.` / `..`
/// and any component that is not a valid Windows name (`a:b` would open
/// an NTFS stream, `CON` a device).
pub fn normalize_smb_path(path: &str) -> Result<String, String> {
    let invalid = || format!("smb: `{}` is not a valid path on an SMB share", path.escape_debug());
    if path.is_empty() || path.contains('\0') || path.chars().count() > MAX_PATH_CHARS {
        return Err(invalid());
    }
    let parts: Vec<&str> = path.split(['/', '\\']).filter(|s| !s.is_empty()).collect();
    if parts.iter().any(|p| !is_safe_entry_name(p) || !is_windows_file_name(p)) {
        return Err(invalid());
    }
    Ok(if parts.is_empty() { "/".to_string() } else { format!("/{}", parts.join("/")) })
}

/// The CREATE name of a normalized path: relative to the share root,
/// `\`-separated; the root is the empty name.
fn wire_name(normalized: &str) -> String {
    normalized.trim_start_matches('/').replace('/', "\\")
}

/// A name a new entry on the share may have.
fn is_valid_smb_name(name: &str) -> bool {
    is_safe_entry_name(name) && is_windows_file_name(name)
}

// ── Directory records ────────────────────────────────────────────────

/// One `FILE_DIRECTORY_INFORMATION` record (MS-FSCC 2.4.10). Parsed here
/// rather than by the library, whose decoder refuses a whole listing when
/// any entry carries an attribute it does not model — a reparse point
/// among them, which this side must see to avoid following it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DirRecord {
    name: String,
    attributes: u32,
    size: u64,
    last_write: u64,
}

const DIR_RECORD_HEADER: usize = 64;

fn le_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn le_u64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

/// Parse a QUERY_DIRECTORY output buffer. Returns the records and the
/// number whose name was not valid UTF-16 (left out). A malformed buffer
/// is an error: every length is checked before it is used.
fn parse_directory_records(buf: &[u8]) -> Result<(Vec<DirRecord>, usize), String> {
    let malformed = |why: &str| format!("smb: malformed directory listing from the server ({why})");
    let mut out = Vec::new();
    let mut undecodable = 0;
    let mut rest = buf;
    while !rest.is_empty() {
        if rest.len() < DIR_RECORD_HEADER {
            return Err(malformed("truncated record"));
        }
        let next = le_u32(rest, 0) as usize;
        let entry_len = if next == 0 { rest.len() } else { next };
        if entry_len < DIR_RECORD_HEADER || entry_len > rest.len() {
            return Err(malformed("record length out of bounds"));
        }
        let name_len = le_u32(rest, 60) as usize;
        if name_len > entry_len - DIR_RECORD_HEADER || !name_len.is_multiple_of(2) {
            return Err(malformed("name length out of bounds"));
        }
        let (pairs, _) = rest[DIR_RECORD_HEADER..DIR_RECORD_HEADER + name_len].as_chunks::<2>();
        let units: Vec<u16> = pairs.iter().map(|c| u16::from_le_bytes(*c)).collect();
        match String::from_utf16(&units) {
            Ok(name) => out.push(DirRecord {
                name,
                attributes: le_u32(rest, 56),
                size: le_u64(rest, 40),
                last_write: le_u64(rest, 24),
            }),
            Err(_) => undecodable += 1,
        }
        if next == 0 {
            break;
        }
        rest = &rest[entry_len..];
    }
    Ok((out, undecodable))
}

/// Seconds since the Unix epoch of a Windows FILETIME; `None` for 0 or a
/// time before 1970.
fn filetime_to_unix(ticks: u64) -> Option<u64> {
    const EPOCH_DIFF_SECS: u64 = 11_644_473_600;
    (ticks / 10_000_000).checked_sub(EPOCH_DIFF_SECS).filter(|_| ticks != 0)
}

/// A reparse point (symlink, junction, mount point) is shown as a link
/// that is not followed: never navigable, never descended, skipped by a
/// transfer.
fn record_kinds(attributes: u32, size: u64) -> (EntryKind, EntryKind, SourceKind) {
    if attributes & ATTR_REPARSE_POINT != 0 {
        (EntryKind::Symlink, EntryKind::Other, SourceKind::Skip("reparse point (symlink or junction)"))
    } else if attributes & ATTR_DIRECTORY != 0 {
        (EntryKind::Dir, EntryKind::Dir, SourceKind::Dir)
    } else {
        (EntryKind::File, EntryKind::File, SourceKind::File(size))
    }
}

/// Why an authenticated session may not be used: a guest or anonymous
/// login proves nothing about the credential and is never signed, and an
/// unsigned, unencrypted session would let the network rewrite files.
fn session_security_refusal(flags: SessionFlags, signed: bool, encrypted: bool) -> Option<&'static str> {
    if flags.intersects(SessionFlags::IS_GUEST | SessionFlags::IS_NULL) {
        return Some(
            "smb: the server admitted this login as a guest or anonymous session; refusing (the credential was not \
             verified and the session cannot be signed)",
        );
    }
    if !signed && !encrypted {
        return Some("smb: the session is neither signed nor encrypted; refusing to use it");
    }
    None
}

// ── Errors ───────────────────────────────────────────────────────────

enum SmbError {
    /// The connection is gone (dropped after a transport failure or a
    /// timeout, or the session closed).
    Closed(&'static str),
    Core(CoreError),
}

impl SmbError {
    fn status(&self) -> Option<u32> {
        match self {
            Self::Core(CoreError::UnexpectedStatus { status, .. }) => Some(*status),
            _ => None,
        }
    }

    fn is_not_found(&self) -> bool {
        matches!(self.status(), Some(STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND | STATUS_NO_SUCH_FILE))
    }

    /// The library refused to decode attributes it does not model: the
    /// object exists, but is a reparse point or similar.
    fn is_unreadable_attributes(&self) -> bool {
        matches!(self, Self::Core(CoreError::Protocol(p)) if p.to_string().contains("file attribute"))
    }

    fn is_symlink_stop(&self) -> bool {
        self.status() == Some(STATUS_STOPPED_ON_SYMLINK)
    }

    /// Operator-facing text. Never includes a credential: library errors
    /// carry statuses and static descriptions only.
    fn describe(&self) -> String {
        if self.is_unreadable_attributes() {
            return "the server reported file attributes this client cannot read (a reparse point, or a \
                    compressed, sparse, offline or encrypted object); refusing it"
                .to_string();
        }
        match self {
            Self::Closed(why) => (*why).to_string(),
            Self::Core(CoreError::UnexpectedStatus { status, .. }) => status_text(*status),
            Self::Core(CoreError::Protocol(p)) => format!("protocol error: {p}"),
            Self::Core(CoreError::Auth(a)) => format!("authentication error: {a}"),
            Self::Core(CoreError::Io(e)) => format!("connection error: {e}"),
            Self::Core(e) => e.to_string(),
        }
    }
}

fn status_text(status: u32) -> String {
    let text = match status {
        STATUS_NO_SUCH_FILE | STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND => "not found",
        STATUS_OBJECT_NAME_COLLISION => "already exists",
        STATUS_OBJECT_NAME_INVALID => "the name is not valid on this share",
        STATUS_ACCESS_DENIED => "access denied",
        STATUS_SHARING_VIOLATION => "in use by another process (sharing violation)",
        STATUS_DELETE_PENDING => "is being deleted",
        STATUS_DIRECTORY_NOT_EMPTY => "the folder is not empty (only empty folders can be removed)",
        STATUS_FILE_IS_A_DIRECTORY => "is a folder",
        STATUS_NOT_A_DIRECTORY => "is not a folder",
        STATUS_DISK_FULL => "the share is full",
        STATUS_BAD_NETWORK_NAME => "no such share on the server",
        STATUS_LOGON_FAILURE => "logon failure (wrong username or password)",
        STATUS_ACCOUNT_RESTRICTION => "the account is restricted",
        STATUS_PASSWORD_EXPIRED => "the password has expired",
        STATUS_PASSWORD_MUST_CHANGE => "the password must be changed",
        STATUS_ACCOUNT_DISABLED => "the account is disabled",
        STATUS_ACCOUNT_LOCKED_OUT => "the account is locked out",
        STATUS_LOGON_TYPE_NOT_GRANTED => "the account may not log on over the network",
        STATUS_STOPPED_ON_SYMLINK => "is a symbolic link; links on the share are not followed",
        STATUS_NETWORK_NAME_DELETED | STATUS_USER_SESSION_DELETED => "the server ended the session",
        _ => return format!("NTSTATUS 0x{status:08x}"),
    };
    text.to_string()
}

/// A failure after which the connection cannot be trusted to be in step
/// with the server.
fn is_connection_fatal(e: &CoreError) -> bool {
    match e {
        CoreError::Io(_) | CoreError::Timeout(_) => true,
        CoreError::UnexpectedStatus { status, .. } => {
            matches!(*status, STATUS_NETWORK_NAME_DELETED | STATUS_USER_SESSION_DELETED)
        }
        _ => false,
    }
}

// ── The connection ───────────────────────────────────────────────────

type CallFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, CoreError>> + Send + 'a>>;

/// The tree connection, one request at a time. `None` once it was lost or
/// closed: every later request fails with "connection closed".
struct SmbLink {
    conn: tokio::sync::Mutex<Option<Conn>>,
}

impl SmbLink {
    async fn call<T, F>(&self, f: F) -> Result<T, SmbError>
    where
        F: for<'a> FnOnce(&'a mut Conn) -> CallFuture<'a, T>,
    {
        let mut guard = self.conn.lock().await;
        let conn = guard.as_mut().ok_or(SmbError::Closed("the connection to the server is closed"))?;
        match tokio::time::timeout(OP_TIMEOUT, f(conn)).await {
            Err(_) => {
                *guard = None;
                Err(SmbError::Closed("the server did not answer in time; the connection was closed"))
            }
            Ok(Err(e)) => {
                if is_connection_fatal(&e) {
                    *guard = None;
                }
                Err(SmbError::Core(e))
            }
            Ok(Ok(v)) => Ok(v),
        }
    }

    async fn create(
        &self,
        path: &str,
        access: u32,
        disposition: CreateDisposition,
        options: CreateOptions,
        attributes: FileAttributes,
    ) -> Result<CreateResponse, SmbError> {
        let mut req = CreateRequest::from_path(&wire_name(path));
        req.desired_access = access;
        req.share_access = ShareAccess::READ | ShareAccess::WRITE | ShareAccess::DELETE;
        req.create_disposition = disposition;
        req.create_options = options;
        req.file_attributes = attributes;
        self.call(move |c| Box::pin(async move { c.create(&req).await })).await
    }

    /// Open an existing object for its attributes only, file or folder.
    async fn stat(&self, path: &str) -> Result<CreateResponse, SmbError> {
        let r = self
            .create(
                path,
                FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                CreateDisposition::Open,
                CreateOptions::empty(),
                FileAttributes::empty(),
            )
            .await?;
        self.close(r.file_id).await;
        Ok(r)
    }

    async fn close(&self, file_id: FileId) {
        let req = CloseRequest { flags: 0, file_id };
        let _ = self.call(move |c| Box::pin(async move { c.close(&req).await.map(|_| ()) })).await;
    }

    async fn set_disposition_delete(&self, file_id: FileId) -> Result<(), SmbError> {
        let req = SetInfoRequest::for_file_info(
            file_id,
            FileInfoClass::DispositionInformation,
            DispositionInformation { delete_pending: true }.encode(),
        );
        self.call(move |c| Box::pin(async move { c.set_info(&req).await.map(|_| ()) })).await
    }

    async fn set_rename(&self, file_id: FileId, target: &str, replace: bool) -> Result<(), SmbError> {
        let req = SetInfoRequest::for_file_info(
            file_id,
            FileInfoClass::RenameInformation,
            RenameInformation::from_path(&wire_name(target), replace).encode(),
        );
        self.call(move |c| Box::pin(async move { c.set_info(&req).await.map(|_| ()) })).await
    }

    /// Every record of a folder, bounded by [`MAX_PLANNED_ENTRIES`].
    async fn list_records(&self, path: &str) -> Result<(Vec<DirRecord>, usize), SmbError> {
        let dir = self
            .create(
                path,
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                CreateDisposition::Open,
                CreateOptions::DIRECTORY_FILE,
                FileAttributes::empty(),
            )
            .await?;
        let result = self.query_all(dir.file_id).await;
        self.close(dir.file_id).await;
        result
    }

    async fn query_all(&self, dir: FileId) -> Result<(Vec<DirRecord>, usize), SmbError> {
        let mut request = QueryDirectoryRequest::for_pattern(dir, "*", 64 * 1024);
        let mut records = Vec::new();
        let mut undecodable = 0;
        loop {
            let req = request.clone();
            let resp = self.call(move |c| Box::pin(async move { c.query_directory(&req).await })).await?;
            if resp.output_buffer.is_empty() {
                break;
            }
            let (batch, bad) = parse_directory_records(&resp.output_buffer)
                .map_err(|_| SmbError::Closed("the server sent a malformed directory listing"))?;
            if batch.is_empty() && bad == 0 {
                break;
            }
            records.extend(batch.into_iter().filter(|r| r.name != "." && r.name != ".."));
            undecodable += bad;
            if records.len() + undecodable > MAX_PLANNED_ENTRIES {
                return Err(SmbError::Closed("the folder has too many entries to list"));
            }
            request.flags = QueryDirectoryFlags::empty();
            request.file_name.clear();
        }
        Ok((records, undecodable))
    }
}

// ── The session ──────────────────────────────────────────────────────

pub struct SmbOpenArgs {
    pub host: String,
    pub port: u16,
    pub share: String,
    pub username: String,
    pub domain: Option<String>,
    pub password: Zeroizing<String>,
    pub label: String,
    pub on_close: Option<SessionCleanup>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SmbOpenOutcome {
    pub token: String,
    pub closed_event: String,
}

/// The SMB side of the dual-pane window.
pub struct SmbFs {
    link: Arc<SmbLink>,
    /// `\\host\share`, for log lines.
    unc: String,
}

/// One live SMB session.
pub struct SmbSessionState {
    pub fs: Arc<SmbFs>,
    pub on_close: Option<SessionCleanup>,
    /// Cancel flags of the transfers in flight, by transfer id.
    pub transfers: Arc<std::sync::Mutex<HashMap<String, Arc<AtomicBool>>>>,
}

impl SmbSessionState {
    /// Cancel every transfer, then disconnect the tree and log off. Called
    /// once, by the drop path, after the entry left the registry.
    pub fn shut_down(self) {
        if let Ok(map) = self.transfers.lock() {
            for flag in map.values() {
                flag.store(true, Ordering::SeqCst);
            }
        }
        let link = Arc::clone(&self.fs.link);
        tokio::spawn(async move {
            let conn = link.conn.lock().await.take();
            if let Some(conn) = conn {
                let _ = tokio::time::timeout(Duration::from_secs(5), async move {
                    if let Ok(session) = conn.tree_disconnect().await {
                        let _ = session.logoff().await;
                    }
                })
                .await;
            }
        });
    }
}

pub fn closed_event_name(token: &str) -> String {
    super::ssh::closed_event_name(token)
}

/// TCP connect, negotiate (signing required), NTLM session setup and tree
/// connect. A TCP failure says `tcp connect` so the dialler tries the next
/// host candidate; an authentication refusal stops it.
async fn connect_share(args: &SmbOpenArgs) -> Result<Conn, String> {
    let mut credentials = NtlmCredentials::new(args.username.clone(), args.password.as_str());
    if let Some(domain) = &args.domain {
        credentials = credentials.with_domain(domain.clone());
    }
    let client = Client::builder(args.host.clone())
        .with_port(args.port)
        .with_signing_mode(SigningMode::ENABLED | SigningMode::REQUIRED)
        .with_ntlm_credentials(credentials)
        .build()
        .map_err(|e| format!("smb: {e}"))?;
    let transport = TokioTcpTransport::connect((args.host.as_str(), args.port))
        .await
        .map_err(|e| format!("smb: tcp connect to {}:{} failed: {e}", args.host, args.port))?;
    let conn = connect_tree_with_transport(transport, client.session_config(), &args.share).await.map_err(|e| {
        let err = SmbError::Core(e);
        match err.status() {
            Some(STATUS_BAD_NETWORK_NAME) => format!("smb: share `{}` not found on {}", args.share, args.host),
            _ => format!("smb: login to \\\\{}\\{} failed: {}", args.host, args.share, err.describe()),
        }
    })?;
    // The credentials go with the builder; only the authenticated tree
    // connection is kept.
    drop(client);
    let state = conn.state();
    let signed = state.signing_required && state.signing.is_some();
    let encrypted = state.encryption_required && state.encryption.is_some();
    if let Some(refusal) = session_security_refusal(state.session.session_flags, signed, encrypted) {
        return Err(refusal.to_string());
    }
    Ok(conn)
}

/// Dial, authenticate, connect the share and register the session.
pub async fn open_smb_session(
    app: AppHandle,
    state: &crate::state::AppState,
    args: SmbOpenArgs,
) -> Result<SmbOpenOutcome, String> {
    let conn = connect_share(&args).await?;
    let link = Arc::new(SmbLink { conn: tokio::sync::Mutex::new(Some(conn)) });
    let unc = format!("\\\\{}\\{}", args.host, args.share);
    let token = new_token();
    let closed_event = closed_event_name(&token);
    {
        let mut sessions = state.connect_sessions.lock().await;
        sessions.insert(
            token.clone(),
            SessionState::Smb(SmbSessionState {
                fs: Arc::new(SmbFs { link: Arc::clone(&link), unc: unc.clone() }),
                on_close: args.on_close.clone(),
                transfers: Arc::default(),
            }),
        );
    }
    spawn_link_watch(app, token.clone(), closed_event.clone(), link);
    log::info!("resource-connect/smb: opened session token={token} label={} ({unc}, port {})", args.label, args.port);
    Ok(SmbOpenOutcome { token, closed_event })
}

/// Tell the window when the connection is lost, and keep an idle one alive
/// with ECHO. Ends quietly once the session left the registry.
fn spawn_link_watch(app: AppHandle, token: String, closed_event: String, link: Arc<SmbLink>) {
    use tauri::Manager;
    tokio::spawn(async move {
        let events = super::routing::SessionEvents::new(app.clone(), token.clone());
        let mut idle = Duration::ZERO;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let Some(state) = app.try_state::<crate::state::AppState>() else { return };
            if !state.connect_sessions.lock().await.contains_key(&token) {
                return;
            }
            idle += Duration::from_secs(1);
            // A request in flight holds the lock; it reports its own failure.
            let Ok(mut guard) = link.conn.try_lock() else { continue };
            let lost = match guard.as_mut() {
                None => true,
                Some(_) if idle < KEEPALIVE_INTERVAL => false,
                Some(conn) => {
                    idle = Duration::ZERO;
                    !matches!(tokio::time::timeout(Duration::from_secs(10), conn.echo()).await, Ok(Ok(_)))
                }
            };
            if lost {
                *guard = None;
                drop(guard);
                log::info!("resource-connect/smb: connection lost for token={token}");
                events.emit(&closed_event, ClosedPayload { reason: "smb connection closed".into() }).await;
                return;
            }
        }
    });
}

impl SmbFs {
    fn fail(&self, what: &str, path: &str, e: SmbError) -> String {
        format!("smb: {what} {path}: {}", e.describe())
    }
}

#[async_trait::async_trait]
impl RemoteFs for SmbFs {
    fn protocol(&self) -> &'static str {
        "smb"
    }

    fn normalize(&self, path: &str) -> Result<String, String> {
        normalize_smb_path(path)
    }

    fn is_valid_name(&self, name: &str) -> bool {
        is_valid_smb_name(name)
    }

    async fn home(&self) -> Result<String, String> {
        Ok("/".to_string())
    }

    async fn list(&self, path: &str) -> Result<Listing, String> {
        let p = normalize_smb_path(path)?;
        let (records, undecodable) = self.link.list_records(&p).await.map_err(|e| self.fail("list", &p, e))?;
        let mut entries = Vec::with_capacity(records.len());
        let mut skipped_unsafe = undecodable;
        for r in records {
            if !is_valid_smb_name(&r.name) {
                skipped_unsafe += 1;
                continue;
            }
            let (kind, target_kind, _) = record_kinds(r.attributes, r.size);
            let size = if kind == EntryKind::File { r.size } else { 0 };
            entries.push(Entry {
                name: r.name,
                kind,
                target_kind,
                size,
                mtime: filetime_to_unix(r.last_write),
                permissions: None,
            });
        }
        if skipped_unsafe > 0 {
            log::warn!("resource-connect/smb: {}{p}: {skipped_unsafe} entries with unsafe names hidden", self.unc);
        }
        Ok(Listing { path: p, entries, skipped_unsafe })
    }

    async fn mkdir(&self, parent: &str, name: &str) -> Result<String, String> {
        let parent = normalize_smb_path(parent)?;
        if !is_valid_smb_name(name) {
            return Err(format!("smb: `{}` is not a valid folder name", name.escape_debug()));
        }
        let path = remote_join(&parent, name);
        let r = self
            .link
            .create(
                &path,
                FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                CreateDisposition::Create,
                CreateOptions::DIRECTORY_FILE,
                FileAttributes::DIRECTORY,
            )
            .await
            .map_err(|e| self.fail("create", &path, e))?;
        self.link.close(r.file_id).await;
        Ok(path)
    }

    async fn rename(&self, path: &str, new_name: &str) -> Result<String, String> {
        let p = normalize_smb_path(path)?;
        if p == "/" {
            return Err("smb: the share root cannot be renamed".into());
        }
        if !is_valid_smb_name(new_name) {
            return Err(format!("smb: `{}` is not a valid name", new_name.escape_debug()));
        }
        let target = remote_join(remote_parent(&p), new_name);
        if self.exists(&target).await? {
            return Err(format!("smb: {target} already exists"));
        }
        let r = self
            .link
            .create(
                &p,
                DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                CreateDisposition::Open,
                CreateOptions::empty(),
                FileAttributes::empty(),
            )
            .await
            .map_err(|e| self.fail("rename", &p, e))?;
        let renamed = self.link.set_rename(r.file_id, &target, false).await;
        self.link.close(r.file_id).await;
        renamed.map_err(|e| self.fail("rename", &p, e))?;
        Ok(target)
    }

    async fn remove(&self, path: &str) -> Result<(), String> {
        let p = normalize_smb_path(path)?;
        if p == "/" {
            return Err("smb: the share root cannot be removed".into());
        }
        let r = self
            .link
            .create(
                &p,
                DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                CreateDisposition::Open,
                CreateOptions::empty(),
                FileAttributes::empty(),
            )
            .await
            .map_err(|e| self.fail("remove", &p, e))?;
        // A non-empty folder refuses the disposition; nothing recurses.
        let removed = self.link.set_disposition_delete(r.file_id).await;
        self.link.close(r.file_id).await;
        removed.map_err(|e| self.fail("remove", &p, e))
    }

    async fn exists(&self, path: &str) -> Result<bool, String> {
        let p = normalize_smb_path(path)?;
        match self.link.stat(&p).await {
            Ok(_) => Ok(true),
            Err(e) if e.is_not_found() => Ok(false),
            // Present, but a link or an object the library cannot describe.
            Err(e) if e.is_symlink_stop() || e.is_unreadable_attributes() => Ok(true),
            Err(e) => Err(self.fail("check", &p, e)),
        }
    }

    async fn source_kind(&self, path: &str) -> Result<SourceKind, String> {
        let p = normalize_smb_path(path)?;
        if p == "/" {
            return Ok(SourceKind::Dir);
        }
        match self.link.stat(&p).await {
            Ok(r) => Ok(record_kinds(r.file_attributes.bits(), r.end_of_file).2),
            Err(e) if e.is_symlink_stop() || e.is_unreadable_attributes() => {
                Ok(SourceKind::Skip("reparse point or an object this client cannot read"))
            }
            Err(e) => Err(self.fail("open", &p, e)),
        }
    }

    async fn children(&self, dir: &str) -> Result<Vec<(String, Option<SourceKind>)>, String> {
        let p = normalize_smb_path(dir)?;
        let (records, undecodable) = self.link.list_records(&p).await.map_err(|e| self.fail("list", &p, e))?;
        if undecodable > 0 {
            return Err(format!("smb: {p} contains an entry whose name is not valid UTF-16; refusing to copy it"));
        }
        Ok(records
            .into_iter()
            .map(|r| {
                let kind = record_kinds(r.attributes, r.size).2;
                (r.name, Some(kind))
            })
            .collect())
    }

    async fn ensure_dir(&self, path: &str) -> Result<(), String> {
        let p = normalize_smb_path(path)?;
        match self.link.stat(&p).await {
            Ok(r) if r.file_attributes.bits() & ATTR_DIRECTORY != 0 => Ok(()),
            Ok(_) => Err(format!("smb: {p} exists and is not a folder")),
            Err(e) if e.is_not_found() => {
                let r = self
                    .link
                    .create(
                        &p,
                        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                        CreateDisposition::Create,
                        CreateOptions::DIRECTORY_FILE,
                        FileAttributes::DIRECTORY,
                    )
                    .await
                    .map_err(|e| self.fail("create", &p, e))?;
                self.link.close(r.file_id).await;
                Ok(())
            }
            Err(e) => Err(self.fail("create", &p, e)),
        }
    }

    async fn open_read(&self, path: &str) -> Result<Box<dyn RemoteReader>, String> {
        let p = normalize_smb_path(path)?;
        let r = self
            .link
            .create(
                &p,
                FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                CreateDisposition::Open,
                CreateOptions::NON_DIRECTORY_FILE,
                FileAttributes::empty(),
            )
            .await
            .map_err(|e| self.fail("open", &p, e))?;
        Ok(Box::new(SmbFile {
            link: Arc::clone(&self.link),
            file_id: r.file_id,
            offset: 0,
            size: r.end_of_file,
            path: p,
        }))
    }

    async fn create_write(&self, path: &str) -> Result<Box<dyn RemoteWriter>, String> {
        let p = normalize_smb_path(path)?;
        let r = self
            .link
            .create(
                &p,
                FILE_WRITE_DATA
                    | FILE_APPEND_DATA
                    | FILE_READ_ATTRIBUTES
                    | FILE_WRITE_ATTRIBUTES
                    | READ_CONTROL
                    | SYNCHRONIZE,
                CreateDisposition::OverwriteIf,
                CreateOptions::NON_DIRECTORY_FILE,
                FileAttributes::NORMAL,
            )
            .await
            .map_err(|e| self.fail("create", &p, e))?;
        Ok(Box::new(SmbFile { link: Arc::clone(&self.link), file_id: r.file_id, offset: 0, size: 0, path: p }))
    }

    async fn remove_file(&self, path: &str) -> Result<(), String> {
        let p = normalize_smb_path(path)?;
        let r = self
            .link
            .create(
                &p,
                DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                CreateDisposition::Open,
                CreateOptions::NON_DIRECTORY_FILE,
                FileAttributes::empty(),
            )
            .await
            .map_err(|e| self.fail("remove", &p, e))?;
        let removed = self.link.set_disposition_delete(r.file_id).await;
        self.link.close(r.file_id).await;
        removed.map_err(|e| self.fail("remove", &p, e))
    }

    /// Renamed onto `dst` with replace-if-exists, so a file there is swapped
    /// in one step; a folder there is refused first.
    async fn commit(&self, partial: &str, dst: &str) -> Result<(), String> {
        let partial = normalize_smb_path(partial)?;
        let dst = normalize_smb_path(dst)?;
        match self.link.stat(&dst).await {
            Ok(r) if r.file_attributes.bits() & ATTR_DIRECTORY != 0 => {
                return Err(format!("smb: {dst} is a folder; not replacing it with a file"));
            }
            Ok(_) => {}
            Err(e) if e.is_not_found() => {}
            Err(e) => return Err(self.fail("replace", &dst, e)),
        }
        let r = self
            .link
            .create(
                &partial,
                DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                CreateDisposition::Open,
                CreateOptions::NON_DIRECTORY_FILE,
                FileAttributes::empty(),
            )
            .await
            .map_err(|e| self.fail("rename onto", &dst, e))?;
        let renamed = self.link.set_rename(r.file_id, &dst, true).await;
        self.link.close(r.file_id).await;
        renamed.map_err(|e| self.fail("rename onto", &dst, e))
    }
}

/// An open file on the share, read or written by the transfer engine.
struct SmbFile {
    link: Arc<SmbLink>,
    file_id: FileId,
    offset: u64,
    /// End of file when opened for reading; reads stop there.
    size: u64,
    path: String,
}

#[async_trait::async_trait]
impl RemoteReader for SmbFile {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, String> {
        if self.offset >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let want = buf.len().min(IO_CHUNK).min(usize::try_from(self.size - self.offset).unwrap_or(IO_CHUNK));
        let req = ReadRequest::for_file(self.file_id, self.offset, want as u32);
        let resp = self
            .link
            .call(move |c| Box::pin(async move { c.read(&req).await }))
            .await
            .map_err(|e| format!("smb: read {}: {}", self.path, e.describe()))?;
        // Never more than was asked for, whatever the server sent.
        let n = resp.data.len().min(want);
        buf[..n].copy_from_slice(&resp.data[..n]);
        self.offset += n as u64;
        Ok(n)
    }

    async fn close(self: Box<Self>) {
        self.link.close(self.file_id).await;
    }
}

#[async_trait::async_trait]
impl RemoteWriter for SmbFile {
    async fn write_all(&mut self, data: &[u8]) -> Result<(), String> {
        for chunk in data.chunks(IO_CHUNK) {
            let req = WriteRequest::for_file(self.file_id, self.offset, chunk.to_vec());
            let resp = self
                .link
                .call(move |c| Box::pin(async move { c.write(&req).await }))
                .await
                .map_err(|e| format!("smb: write {}: {}", self.path, e.describe()))?;
            if resp.count as usize != chunk.len() {
                return Err(format!(
                    "smb: write {}: the server wrote {} of {} bytes",
                    self.path,
                    resp.count,
                    chunk.len()
                ));
            }
            self.offset += chunk.len() as u64;
        }
        Ok(())
    }

    async fn finish(self: Box<Self>) -> Result<(), String> {
        let req = FlushRequest::for_file(self.file_id);
        let flushed = self.link.call(move |c| Box::pin(async move { c.flush(&req).await.map(|_| ()) })).await;
        self.link.close(self.file_id).await;
        flushed.map_err(|e| format!("smb: write {}: {}", self.path, e.describe()))
    }

    async fn abort(self: Box<Self>) {
        self.link.close(self.file_id).await;
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_profile_needs_a_valid_share_and_may_name_a_domain() {
        let p = parse_smb_profile(&json!({ "protocol": "smb", "share": "files" })).unwrap();
        assert_eq!(p, SmbProfile { share: "files".into(), domain: None });
        let p = parse_smb_profile(&json!({ "share": "Dept Data$", "domain": " CORP " })).unwrap();
        assert_eq!(p.share, "Dept Data$");
        assert_eq!(p.domain.as_deref(), Some("CORP"));
        assert_eq!(parse_smb_profile(&json!({ "share": "f", "domain": "" })).unwrap().domain, None);
        for bad in [
            json!({}),
            json!({ "share": "" }),
            json!({ "share": 7 }),
            json!({ "share": "a/b" }),
            json!({ "share": "\\\\host\\files" }),
            json!({ "share": ".." }),
            json!({ "share": " files" }),
            json!({ "share": "x".repeat(81) }),
            json!({ "share": "files", "domain": "CORP\\x" }),
            json!({ "share": "files", "domain": 1 }),
        ] {
            assert!(parse_smb_profile(&bad).is_err(), "{bad}");
        }
    }

    /// A domain carried by the login wins; the profile's applies to a bare
    /// user only.
    #[test]
    fn the_ntlm_domain_comes_from_the_login_first() {
        assert_eq!(ntlm_identity("op", None, Some("CORP")), ("op".into(), Some("CORP".into())));
        assert_eq!(ntlm_identity("OTHER\\op", None, Some("CORP")), ("op".into(), Some("OTHER".into())));
        assert_eq!(ntlm_identity("op@corp.example", None, None), ("op".into(), Some("corp.example".into())));
        assert_eq!(ntlm_identity("op", Some("LDAPDOM".into()), Some("CORP")), ("op".into(), Some("LDAPDOM".into())));
        assert_eq!(ntlm_identity("op", None, None), ("op".into(), None));
    }

    #[test]
    fn share_paths_normalise_to_posix_from_the_root() {
        assert_eq!(normalize_smb_path("/").unwrap(), "/");
        assert_eq!(normalize_smb_path("\\").unwrap(), "/");
        assert_eq!(normalize_smb_path("dir\\sub\\").unwrap(), "/dir/sub");
        assert_eq!(normalize_smb_path("//dir///f.txt").unwrap(), "/dir/f.txt");
        assert_eq!(wire_name("/"), "");
        assert_eq!(wire_name("/dir/f.txt"), "dir\\f.txt");
    }

    /// No component may climb, address an NTFS stream or a device, or
    /// smuggle a NUL: the whole path is refused, nothing is trimmed away.
    #[test]
    fn share_paths_refuse_traversal_streams_and_devices() {
        for bad in
            ["", "/dir/../etc", "..\\x", "/./a", "/a:b", "/f.txt:$DATA", "/NUL", "/con.txt", "/a\0b", "/x/trail."]
        {
            assert!(normalize_smb_path(bad).is_err(), "{bad:?}");
        }
        assert!(normalize_smb_path(&format!("/{}", "a".repeat(MAX_PATH_CHARS))).is_err());
        assert!(!is_valid_smb_name("a:b") && !is_valid_smb_name("..") && is_valid_smb_name("report.pdf"));
    }

    fn record(name: &str, attributes: u32, size: u64, next: Option<u32>) -> Vec<u8> {
        let units: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut b = vec![0u8; DIR_RECORD_HEADER];
        b[24..32].copy_from_slice(&(133_000_000_000_000_000u64).to_le_bytes());
        b[40..48].copy_from_slice(&size.to_le_bytes());
        b[56..60].copy_from_slice(&attributes.to_le_bytes());
        b[60..64].copy_from_slice(&(units.len() as u32).to_le_bytes());
        b.extend_from_slice(&units);
        if let Some(n) = next {
            b.resize(n as usize, 0);
            b[0..4].copy_from_slice(&n.to_le_bytes());
        }
        b
    }

    /// Unknown attribute bits are kept, not refused: a reparse point is
    /// recognised as a link that is not followed.
    #[test]
    fn directory_records_keep_every_attribute_bit() {
        let mut buf = record("dir", ATTR_DIRECTORY | 0x2000, 0, Some(88));
        buf.extend(record("junction", ATTR_DIRECTORY | ATTR_REPARSE_POINT, 0, Some(96)));
        buf.extend(record("f.txt", 0x20 | 0x0200, 42, None));
        let (records, bad) = parse_directory_records(&buf).unwrap();
        assert_eq!(bad, 0);
        let names: Vec<_> = records.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["dir", "junction", "f.txt"]);
        assert_eq!(record_kinds(records[0].attributes, 0).2, SourceKind::Dir);
        let (kind, target, source) = record_kinds(records[1].attributes, 0);
        assert_eq!((kind, target), (EntryKind::Symlink, EntryKind::Other));
        assert!(matches!(source, SourceKind::Skip(_)));
        assert_eq!(record_kinds(records[2].attributes, records[2].size).2, SourceKind::File(42));
        assert!(filetime_to_unix(records[2].last_write).is_some());
        assert_eq!(filetime_to_unix(0), None);
    }

    /// A hostile listing cannot make the parser read out of bounds or loop.
    #[test]
    fn malformed_directory_records_are_refused() {
        let good = record("a", 0x20, 1, None);
        assert!(parse_directory_records(&good[..40]).is_err(), "truncated header");
        let mut long_name = good.clone();
        long_name[60..64].copy_from_slice(&1000u32.to_le_bytes());
        assert!(parse_directory_records(&long_name).is_err(), "name past the record");
        let mut odd = good.clone();
        odd[60..64].copy_from_slice(&1u32.to_le_bytes());
        assert!(parse_directory_records(&odd).is_err(), "odd UTF-16 length");
        let mut short_next = good.clone();
        short_next[0..4].copy_from_slice(&8u32.to_le_bytes());
        assert!(parse_directory_records(&short_next).is_err(), "next offset inside the header");
        let mut past_end = good.clone();
        past_end[0..4].copy_from_slice(&4096u32.to_le_bytes());
        assert!(parse_directory_records(&past_end).is_err(), "next offset past the buffer");
        // A lone surrogate is not a name: left out and counted.
        let mut bad_utf16 = record("ab", 0x20, 1, None);
        bad_utf16[64..66].copy_from_slice(&0xD800u16.to_le_bytes());
        assert_eq!(parse_directory_records(&bad_utf16).unwrap(), (vec![], 1));
        assert_eq!(parse_directory_records(&[]).unwrap(), (vec![], 0));
    }

    /// Signing is required: a guest or anonymous session, or one neither
    /// signed nor encrypted, is never used.
    #[test]
    fn unsigned_guest_and_anonymous_sessions_are_refused() {
        assert!(session_security_refusal(SessionFlags::empty(), true, false).is_none());
        assert!(session_security_refusal(SessionFlags::ENCRYPT_DATA, false, true).is_none());
        assert!(session_security_refusal(SessionFlags::empty(), false, false).is_some());
        assert!(session_security_refusal(SessionFlags::IS_GUEST, true, false).is_some());
        assert!(session_security_refusal(SessionFlags::IS_NULL, false, true).is_some());
    }

    #[test]
    fn statuses_read_as_operator_messages() {
        assert_eq!(status_text(STATUS_LOGON_FAILURE), "logon failure (wrong username or password)");
        assert!(status_text(STATUS_DIRECTORY_NOT_EMPTY).contains("only empty folders"));
        assert_eq!(status_text(0xC000_9999), "NTSTATUS 0xc0009999");
        let not_found = SmbError::Core(CoreError::UnexpectedStatus {
            command: smolder_proto::smb::smb2::Command::Create,
            status: STATUS_OBJECT_PATH_NOT_FOUND,
        });
        assert!(not_found.is_not_found());
        assert!(!is_connection_fatal(&CoreError::InvalidInput("x")));
        assert!(is_connection_fatal(&CoreError::Io(std::io::Error::other("reset"))));
    }
}
