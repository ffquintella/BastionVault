//! MS-RDPECLIP (`CLIPRDR`) clipboard redirection for the in-app RDP
//! session — see [`features/rdp-clipboard-redirection.md`].
//!
//! Copy in the remote desktop, paste on the host, and the reverse:
//! text (`CF_UNICODETEXT`, Phase 1), images (`CF_DIB` / `CF_DIBV5`,
//! Phase 2, [`dib`]) and — behind a switch of its own — files
//! (`FileGroupDescriptorW` + `FileContents`, Phase 3, [`files`]). Every
//! transfer is audited (Phase 4, [`audit`]) and every knob is capped by a
//! four-tier lockable policy resolved on the vault (Phase 4,
//! [`PolicyCeiling`]).
//!
//! ## The switches
//!
//! The clipboard is a bidirectional data channel into and out of a
//! privileged session: egress for whatever the operator can see on the
//! target, and ingress into a production host. So:
//!
//! - **`rdp_clipboard`** sets the direction for text and images. On in both
//!   directions unless the resource narrows it ([`PROFILE_DEFAULT_DIRECTION`]);
//!   `off` means the channel is **not attached at all** rather than
//!   attached-but-inert — a capability we do not intend to honour should
//!   not be advertised to the server.
//! - **`rdp_clipboard_files`** sets the direction for file copy, **off**
//!   unless the resource opts in ([`PROFILE_DEFAULT_FILES_DIRECTION`]). It is
//!   never folded into `rdp_clipboard`: a file channel is a materially
//!   larger control question than text. File copy can only travel where the
//!   clipboard itself may, so it is intersected with `rdp_clipboard`.
//! - **The policy ceiling** (`rustion/policy/effective`'s `clipboard` and
//!   `clipboard_files`) is intersected with both. An administrator pins the
//!   clipboard off for a resource type, an asset group or globally there,
//!   and no profile value can widen it ([`resolve_settings`]).
//!
//! This does not weaken the "credentials never reach the clipboard"
//! property: the resource's stored secret still goes straight into the
//! protocol and never onto any clipboard. What moves here is
//! operator-initiated content, and only when profile and policy allow it.
//!
//! ## Shape
//!
//! ```text
//!  host OS clipboard                              remote desktop
//!         │                                              ▲
//!         │ arboard (own thread)                         │
//!         ▼                                              │
//!  Bridge ─────────ClipboardMessage──────▶ pump ──▶ CliprdrClient ──▶ SVC
//!    (poll, read/write,  (unbounded mpsc)  (rdp.rs)
//!     file staging)                                      │
//!         ▲                                              │
//!         └──────────────── BridgeBackend ◀──────────────┘
//!                              │
//!                              └──TransferEvent──▶ audit task ──▶ vault
//! ```
//!
//! Two things are deliberate:
//!
//! - **The `arboard` handle and all file I/O live on their own thread.** An
//!   X11 or Wayland clipboard read can block for as long as the *owning*
//!   application takes to answer, a disk can be slow, and a blocked pump is
//!   a frozen session. Platform clipboard handles also carry thread affinity
//!   a `tokio` worker cannot promise.
//! - **Host-side changes are polled**, because no cross-platform clipboard
//!   change notification exists (Windows has one; X11 and macOS do not).
//!   [`HOST_POLL_INTERVAL`] is well under human copy→paste latency.
//!
//! Nothing here ever logs clipboard content or file names, at any level, in
//! either direction. The logs carry direction, byte counts, format ids,
//! reasons and outcomes only.

pub mod audit;
pub mod dib;
pub mod files;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ironrdp::cliprdr::backend::{ClipboardMessage, ClipboardMessageProxy, CliprdrBackend};
use ironrdp::cliprdr::loop_detector::{ClipboardSource, LoopDetector};
use ironrdp::cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardFormatName, ClipboardGeneralCapabilityFlags, FileContentsRequest,
    FileContentsResponse, FileDescriptor, FormatDataRequest, FormatDataResponse, LockDataId,
};
use ironrdp_core::{impl_as_any, IntoOwned as _};
use serde_json::{Map, Value};
use tokio::sync::mpsc as tokio_mpsc;
use zeroize::Zeroizing;

use self::audit::{AuditSink, TransferDirection, TransferEvent, TransferKind, TransferOutcome};

/// Largest text payload transferred in either direction.
///
/// A payload over the cap is **dropped and counted, never truncated**:
/// a half-pasted credential or config file is worse than a failed
/// paste. The cap applies to the wire payload, which is the
/// attacker-influenced side. Images and files have their own caps
/// ([`dib::MAX_IMAGE_BYTES`], [`files::MAX_FILE_BYTES`]).
pub const MAX_CLIPBOARD_BYTES: usize = 1024 * 1024;

/// How often the bridge re-reads the host clipboard looking for a
/// local copy to advertise.
const HOST_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Images are polled on every Nth tick, and only while the host clipboard
/// holds no text: reading an image decodes it, which is not free.
const IMAGE_POLL_EVERY: u64 = 4;

/// A host image of the same size seen this soon after we wrote a remote
/// image is our own paste coming back. Pasteboards re-encode images, so the
/// bytes rarely survive the round trip exactly enough to hash-match.
const IMAGE_ECHO_WINDOW: Duration = Duration::from_secs(10);

/// Most clipboard-lock snapshots of our file list held at once — the same
/// bound `ironrdp-cliprdr` puts on its own.
const MAX_LOCK_SNAPSHOTS: usize = 100;

/// `CF_TEXT` / `CF_OEMTEXT` are deliberately not offered: every
/// Windows target since NT converts from `CF_UNICODETEXT`, and
/// offering a code-page format invites mojibake.
const TEXT_FORMAT: ClipboardFormatId = ClipboardFormatId::CF_UNICODETEXT;

/// Which way clipboard content may travel. Ingress and egress are
/// separately expressible because they are different risks.
///
/// Deliberately no `Default` impl: the value an RDP profile gets when
/// it says nothing is [`PROFILE_DEFAULT_DIRECTION`] (or, for files,
/// [`PROFILE_DEFAULT_FILES_DIRECTION`]), and a second, differently-valued
/// `default()` sitting next to them is how a caller ends up silently
/// opening or closing a clipboard channel it did not mean to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClipboardDirection {
    /// The `CLIPRDR` channel is not attached (or, for files, no file
    /// capability is advertised).
    Off,
    /// Host clipboard → session only. The remote may request ours;
    /// remote copies never touch the host clipboard.
    HostToSession,
    /// Session clipboard → host only. Ours is never advertised or
    /// served to the remote.
    SessionToHost,
    Bidirectional,
}

impl ClipboardDirection {
    pub fn enabled(self) -> bool {
        !matches!(self, Self::Off)
    }

    /// May the host's clipboard be advertised and served to the remote?
    pub fn allows_host_to_session(self) -> bool {
        matches!(self, Self::HostToSession | Self::Bidirectional)
    }

    /// May remote clipboard content be written to the host clipboard?
    pub fn allows_session_to_host(self) -> bool {
        matches!(self, Self::SessionToHost | Self::Bidirectional)
    }

    fn from_directions(host_to_session: bool, session_to_host: bool) -> Self {
        match (host_to_session, session_to_host) {
            (true, true) => Self::Bidirectional,
            (true, false) => Self::HostToSession,
            (false, true) => Self::SessionToHost,
            (false, false) => Self::Off,
        }
    }

    /// The most restrictive combination: a direction survives only if
    /// both sides allow it. `host-to-session` ∩ `session-to-host` is `off`.
    pub fn meet(a: Self, b: Self) -> Self {
        Self::from_directions(
            a.allows_host_to_session() && b.allows_host_to_session(),
            a.allows_session_to_host() && b.allows_session_to_host(),
        )
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::HostToSession => "host-to-session",
            Self::SessionToHost => "session-to-host",
            Self::Bidirectional => "bidirectional",
        }
    }
}

/// What a profile with no `rdp_clipboard` key gets.
///
/// Copy and paste between the operator's machine and the target works
/// unless the resource turns it off — an operator who cannot paste a
/// command or carry an error message back out routes around the
/// bastion, and that is the worse outcome. Set `rdp_clipboard` to
/// `off` on the resource to withhold the channel entirely, or to one
/// of the single directions to allow only ingress or only egress.
///
/// This is a *posture*, not an oversight: everything the channel
/// carries is capped, never logged, audited per transfer, and subject to
/// the policy ceiling.
pub const PROFILE_DEFAULT_DIRECTION: ClipboardDirection = ClipboardDirection::Bidirectional;

/// What a profile with no `rdp_clipboard_files` key gets: no file copy.
/// The opposite posture to text on purpose — files are a far larger
/// egress and ingress path, and an operator who needs them can ask for
/// them on the one resource that warrants it.
pub const PROFILE_DEFAULT_FILES_DIRECTION: ClipboardDirection = ClipboardDirection::Off;

fn parse_direction_for(key: &str, value: &str) -> Result<ClipboardDirection, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" | "none" | "disabled" | "" => Ok(ClipboardDirection::Off),
        "host-to-session" | "host_to_session" | "in" => Ok(ClipboardDirection::HostToSession),
        "session-to-host" | "session_to_host" | "out" => Ok(ClipboardDirection::SessionToHost),
        "bidirectional" | "both" | "on" => Ok(ClipboardDirection::Bidirectional),
        other => Err(format!(
            "rdp: unknown {key} `{other}` (expected one of: off, \
             host-to-session, session-to-host, bidirectional)"
        )),
    }
}

/// Parse the `rdp_clipboard` profile value.
///
/// Rejects anything unrecognised rather than falling back to a
/// default: a typo in a profile must not silently change whether a
/// privileged session has a clipboard channel (AGENTS.md §7 — no
/// implicit fallbacks on paths an operator configured deliberately).
/// Mirrors [`super::rdp::parse_bulk_compression`].
pub fn parse_clipboard_direction(value: &str) -> Result<ClipboardDirection, String> {
    parse_direction_for("rdp_clipboard", value)
}

/// Resolve the session's clipboard direction from the profile's
/// `rdp_clipboard` value, absent or not.
///
/// The two cases are deliberately different: *absent* means the
/// resource never said anything and gets [`PROFILE_DEFAULT_DIRECTION`];
/// *present but unrecognised* is a misconfiguration and fails the
/// connect rather than resolving to anything in either direction.
pub fn direction_from_profile(value: Option<&str>) -> Result<ClipboardDirection, String> {
    match value {
        None => Ok(PROFILE_DEFAULT_DIRECTION),
        Some(raw) => parse_clipboard_direction(raw),
    }
}

/// [`direction_from_profile`] for `rdp_clipboard_files`: same vocabulary,
/// same strictness, default [`PROFILE_DEFAULT_FILES_DIRECTION`].
pub fn files_direction_from_profile(value: Option<&str>) -> Result<ClipboardDirection, String> {
    match value {
        None => Ok(PROFILE_DEFAULT_FILES_DIRECTION),
        Some(raw) => parse_direction_for("rdp_clipboard_files", raw),
    }
}

/// The server's spelling only — the four canonical words, no aliases. A
/// policy value is machine-written, so anything else is a fault.
fn parse_canonical(value: &str) -> Option<ClipboardDirection> {
    match value {
        "off" => Some(ClipboardDirection::Off),
        "host-to-session" => Some(ClipboardDirection::HostToSession),
        "session-to-host" => Some(ClipboardDirection::SessionToHost),
        "bidirectional" => Some(ClipboardDirection::Bidirectional),
        _ => None,
    }
}

/// The clipboard ceiling the vault's policy tiers impose on this
/// resource, from `rustion/policy/effective`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyCeiling {
    pub clipboard: ClipboardDirection,
    pub clipboard_source: String,
    pub files: ClipboardDirection,
    pub files_source: String,
    pub locked_by: Vec<String>,
    /// The server knows the clipboard knobs at all (T35 or later). Also
    /// what decides whether `resources/v2/connect/clipboard/audit` exists
    /// to write to — detected here, never inferred from a failed write.
    pub server_supports: bool,
    /// The answer could not be read; the ceiling is then `off`/`off`.
    pub unreadable: Option<String>,
}

impl PolicyCeiling {
    /// Read the clipboard half of a `policy/effective` response.
    ///
    /// - No `clipboard` key: a server that predates the knobs. No tier can
    ///   have set one, so nothing is constrained — that is the accurate
    ///   reading, not a fallback — and there is no vault endpoint to audit
    ///   to, which the caller says once.
    /// - A value outside the canonical four, or a missing companion key:
    ///   **fail closed**, both knobs `off`, with the reason kept for the
    ///   log. A policy we cannot read must not be read as "allowed".
    pub fn from_effective(data: &Map<String, Value>) -> Self {
        let Some(raw) = data.get("clipboard") else {
            return Self {
                clipboard: ClipboardDirection::Bidirectional,
                clipboard_source: "default".into(),
                files: ClipboardDirection::Bidirectional,
                files_source: "default".into(),
                locked_by: Vec::new(),
                server_supports: false,
                unreadable: None,
            };
        };
        let s = |k: &str| data.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let clipboard = raw.as_str().and_then(parse_canonical);
        let files = data.get("clipboard_files").and_then(|v| v.as_str()).and_then(parse_canonical);
        let locked_by = data
            .get("clipboard_locked_by")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        match (clipboard, files) {
            (Some(clipboard), Some(files)) => Self {
                clipboard,
                clipboard_source: s("clipboard_source"),
                files,
                files_source: s("clipboard_files_source"),
                locked_by,
                server_supports: true,
                unreadable: None,
            },
            _ => Self {
                clipboard: ClipboardDirection::Off,
                clipboard_source: "unreadable".into(),
                files: ClipboardDirection::Off,
                files_source: "unreadable".into(),
                locked_by,
                server_supports: true,
                unreadable: Some(
                    "the policy resolver returned a clipboard value this client does not recognise".into(),
                ),
            },
        }
    }
}

/// What a session's clipboard may do, after profile and policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClipboardSettings {
    /// Text and images.
    pub direction: ClipboardDirection,
    /// File copy. Always within `direction`.
    pub files: ClipboardDirection,
}

impl ClipboardSettings {
    #[cfg(test)]
    pub fn off() -> Self {
        Self { direction: ClipboardDirection::Off, files: ClipboardDirection::Off }
    }
}

/// [`ClipboardSettings`] plus a line per knob the policy narrowed, for
/// the connect-time log. Narrowing is never silent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolution {
    pub settings: ClipboardSettings,
    pub narrowed: Vec<String>,
}

/// Intersect the profile's two values with the policy ceiling.
pub fn resolve_settings(
    profile_direction: ClipboardDirection,
    profile_files: ClipboardDirection,
    ceiling: &PolicyCeiling,
) -> Resolution {
    let mut narrowed = Vec::new();
    let direction = ClipboardDirection::meet(profile_direction, ceiling.clipboard);
    if direction != profile_direction {
        narrowed.push(format!(
            "rdp_clipboard narrowed from {} to {} by policy tier `{}`",
            profile_direction.label(),
            direction.label(),
            ceiling.clipboard_source
        ));
    }
    let by_policy = ClipboardDirection::meet(profile_files, ceiling.files);
    if by_policy != profile_files {
        narrowed.push(format!(
            "rdp_clipboard_files narrowed from {} to {} by policy tier `{}`",
            profile_files.label(),
            by_policy.label(),
            ceiling.files_source
        ));
    }
    let files = ClipboardDirection::meet(by_policy, direction);
    if files != by_policy {
        narrowed.push(format!(
            "rdp_clipboard_files narrowed from {} to {}: file copy cannot travel where the clipboard may not",
            by_policy.label(),
            files.label()
        ));
    }
    Resolution { settings: ClipboardSettings { direction, files }, narrowed }
}

/// Per-session clipboard counters, surfaced on the session's stats
/// line. Byte counts and outcomes only — never content.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClipboardStats {
    /// `CLIPRDR` finished capability negotiation. A brokered session
    /// that never gets the channel forwarded stays `false`, which is
    /// how an operator tells "enabled" from "working".
    pub ready: bool,
    pub in_transfers: u64,
    pub in_bytes: u64,
    pub out_transfers: u64,
    pub out_bytes: u64,
    /// Of the transfers above: images and files, each way.
    pub images_in: u64,
    pub images_out: u64,
    pub files_in: u64,
    pub files_out: u64,
    /// Payloads refused for exceeding a size or count cap.
    pub dropped_oversize: u64,
    /// Local "changes" that were really our own paste echoing back.
    pub suppressed_loop: u64,
    /// Refused because the profile's or the policy's direction does not
    /// allow it.
    pub refused_direction: u64,
    /// Payloads that failed validation (UTF-16, DIB, file lists, names).
    pub malformed: u64,
    /// File lists refused whole (caps, names, folders).
    pub refused_files: u64,
    /// Host clipboard, disk and protocol failures.
    pub errors: u64,
    /// The vault could not record a transfer and the clipboard was
    /// withdrawn for the rest of the session (fail closed).
    pub withdrawn: bool,
}

pub type SharedClipboardStats = Arc<Mutex<ClipboardStats>>;

fn bump(stats: &SharedClipboardStats, f: impl FnOnce(&mut ClipboardStats)) {
    if let Ok(mut s) = stats.lock() {
        f(&mut s);
    }
}

/// Sends [`ClipboardMessage`]s from the bridge thread and the backend
/// into the session pump.
///
/// Unbounded, and separate from the bounded input channel, for the
/// reason `ironrdp-client` documents: backpressure meant for keyboard
/// and pointer input would desynchronize the clipboard protocol state
/// machine.
#[derive(Clone, Debug)]
pub struct PumpProxy {
    tx: tokio_mpsc::UnboundedSender<ClipboardMessage>,
}

impl ClipboardMessageProxy for PumpProxy {
    fn send_clipboard_message(&self, message: ClipboardMessage) {
        if self.tx.send(message).is_err() {
            log::debug!("rdp clipboard: pump closed, dropping message");
        }
    }
}

/// What the backend asks the bridge thread to do. The backend's trait
/// methods are synchronous and must never block, so each one either
/// answers from memory or posts one of these.
enum BridgeCommand {
    /// The server's Monitor Ready: send the initial (empty) format list
    /// that completes `CLIPRDR` initialisation.
    Initialize,
    /// The server accepted that list: the channel is Ready, and host
    /// copies may be advertised from now on.
    Ready,
    /// Whether the server agreed to stream-based file copy.
    Negotiated {
        files: bool,
    },
    /// The remote asked for our clipboard in `CF_UNICODETEXT`.
    ProvideHostText,
    /// The remote asked for our clipboard image in `CF_DIB` / `CF_DIBV5`.
    ProvideHostImage(ClipboardFormatId),
    /// The remote sent us text; put it on the host clipboard.
    StoreRemoteText(Zeroizing<String>),
    /// The remote sent us a DIB; validate it and put it on the host
    /// clipboard.
    StoreRemoteImage(Zeroizing<Vec<u8>>),
    /// The remote asked for a size or a range of one of our files.
    ProvideFileContents(FileContentsRequest),
    /// The remote's file list, already sanitised by `ironrdp`.
    RemoteFileList {
        files: Vec<FileDescriptor>,
        clip_data_id: Option<u32>,
    },
    /// One response to a request of ours. `data` is `None` when the
    /// backend already found it larger than any request we make.
    RemoteFileChunk {
        stream_id: u32,
        is_error: bool,
        data: Option<Zeroizing<Vec<u8>>>,
    },
    Lock(u32),
    Unlock(u32),
}

/// Handle the backend uses to talk to the bridge thread. Dropping it
/// (with the backend) ends the thread.
#[derive(Debug)]
struct BridgeHandle {
    tx: std_mpsc::Sender<BridgeCommand>,
}

impl BridgeHandle {
    fn send(&self, cmd: BridgeCommand) {
        if self.tx.send(cmd).is_err() {
            log::debug!("rdp clipboard: bridge thread gone, dropping command");
        }
    }
}

/// UTF-8 → the wire form of `CF_UNICODETEXT` (MS-RDPECLIP 2.2.5.2):
/// UTF-16LE, CRLF line endings, NUL-terminated.
fn encode_unicode_text(text: &str) -> Vec<u8> {
    let normalized = normalize_to_crlf(text);
    let mut out = Vec::with_capacity(normalized.len() * 2 + 2);
    for unit in normalized.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.extend_from_slice(&0u16.to_le_bytes()); // NUL terminator
    out
}

/// `\n` → `\r\n`, leaving existing CRLF alone.
fn normalize_to_crlf(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    let mut prev_cr = false;
    for ch in text.chars() {
        if ch == '\n' && !prev_cr {
            out.push('\r');
        }
        prev_cr = ch == '\r';
        out.push(ch);
    }
    out
}

/// Wire form → what the host clipboard should hold.
///
/// CRLF is folded to LF on a non-Windows host, because that is what
/// its own applications expect; a Windows host keeps CRLF for the same
/// reason.
fn host_line_endings(text: &str) -> String {
    if cfg!(windows) {
        text.to_string()
    } else {
        text.replace("\r\n", "\n")
    }
}

fn is_image_format(id: ClipboardFormatId) -> bool {
    id == ClipboardFormatId::CF_DIB || id == ClipboardFormatId::CF_DIBV5
}

fn kind_of(id: ClipboardFormatId) -> TransferKind {
    if is_image_format(id) {
        TransferKind::Image
    } else {
        TransferKind::Text
    }
}

/// Everything a session's clipboard needs besides the channel itself.
pub struct SpawnConfig {
    pub settings: ClipboardSettings,
    pub proxy: PumpProxy,
    pub stats: SharedClipboardStats,
    pub label: String,
    pub audit: AuditSink,
    /// Set by the audit task when the vault cannot record a transfer.
    pub withdrawn: Arc<AtomicBool>,
    /// `<app cache>/rdp-clipboard`, for received files. `None` when the
    /// cache directory could not be resolved; received files then fail
    /// explicitly.
    pub staging_base: Option<PathBuf>,
    /// The session token, naming the staging directory.
    pub token: String,
}

/// Start the bridge thread. Returns the backend to hand to
/// [`ironrdp::cliprdr::Cliprdr::new`].
///
/// The thread owns the process's only `arboard::Clipboard` handle for
/// this session and exits when the returned backend is dropped.
pub fn spawn(cfg: SpawnConfig) -> BridgeBackend {
    let (tx, rx) = std_mpsc::channel::<BridgeCommand>();
    let backend = BridgeBackend {
        bridge: BridgeHandle { tx },
        proxy: cfg.proxy.clone(),
        settings: cfg.settings,
        stats: Arc::clone(&cfg.stats),
        audit: cfg.audit.clone(),
        withdrawn: Arc::clone(&cfg.withdrawn),
        label: cfg.label.clone(),
        files_negotiated: false,
        pending_paste: None,
    };
    let label = cfg.label.clone();
    let stats = Arc::clone(&cfg.stats);
    // A plain OS thread, not a tokio task: see the module docs on
    // blocking clipboard reads and thread affinity.
    if let Err(e) = std::thread::Builder::new().name("rdp-clipboard".into()).spawn(move || bridge_main(cfg, rx)) {
        log::warn!("rdp clipboard [{label}]: could not start bridge thread: {e}");
        bump(&stats, |s| s.errors += 1);
    }
    backend
}

fn bridge_main(cfg: SpawnConfig, rx: std_mpsc::Receiver<BridgeCommand>) {
    let clipboard = match arboard::Clipboard::new() {
        Ok(c) => c,
        Err(e) => {
            // No host clipboard (a headless session, a locked
            // pasteboard). Say so once and stop: pretending the
            // channel works would be the silent downgrade.
            log::warn!("rdp clipboard [{}]: host clipboard unavailable: {e}", cfg.label);
            bump(&cfg.stats, |s| s.errors += 1);
            return;
        }
    };
    let mut bridge = Bridge::new(cfg, clipboard);
    bridge.seed();
    let mut last_poll = Instant::now();
    loop {
        match rx.recv_timeout(HOST_POLL_INTERVAL) {
            Ok(cmd) => bridge.handle(cmd),
            Err(std_mpsc::RecvTimeoutError::Timeout) => {}
            Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
        }
        // Polled on elapsed time rather than only on a quiet channel, so
        // a busy file transfer cannot starve change detection or the
        // stalled-transfer check.
        if last_poll.elapsed() >= HOST_POLL_INTERVAL {
            last_poll = Instant::now();
            bridge.poll_host();
            bridge.check_inbound_timeout();
        }
    }
    bridge.abandon_inbound();
    log::debug!("rdp clipboard [{}]: bridge thread exiting", bridge.label);
}

/// A cheap identity for a host image: dimensions plus a content hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ImageFingerprint {
    width: u32,
    height: u32,
    hash: u64,
}

impl ImageFingerprint {
    fn of(width: u32, height: u32, rgba: &[u8]) -> Self {
        Self { width, height, hash: LoopDetector::compute_hash(rgba) }
    }
}

/// The bridge thread's state. Owns the host clipboard handle, the
/// advertised file list and its lock snapshots, and any download in
/// progress.
struct Bridge {
    clipboard: arboard::Clipboard,
    proxy: PumpProxy,
    settings: ClipboardSettings,
    stats: SharedClipboardStats,
    audit: AuditSink,
    withdrawn: Arc<AtomicBool>,
    label: String,
    epoch: Instant,
    detector: LoopDetector,
    /// The initial format list has gone out.
    initialized: bool,
    /// The channel reached Ready. Nothing is advertised before it: in the
    /// Initialization state `ironrdp` bundles a copy with a second
    /// capabilities PDU, and a file copy is refused outright.
    ready: bool,
    files_negotiated: bool,
    last_text: Option<Zeroizing<String>>,
    last_image: Option<ImageFingerprint>,
    last_files: Option<Vec<PathBuf>>,
    /// Dimensions and time of the last remote image we wrote.
    image_echo: Option<(u32, u32, Instant)>,
    tick: u64,
    generation: u64,
    outbound: Option<Arc<files::OutboundList>>,
    locked: HashMap<u32, Arc<files::OutboundList>>,
    served: HashMap<(u64, usize), u64>,
    audited_out: HashSet<(u64, usize)>,
    staging_base: Option<PathBuf>,
    token: String,
    staging: Option<files::StagingDir>,
    inbound: Option<files::InboundTransfer>,
    stream_ids: u32,
}

impl Bridge {
    fn new(cfg: SpawnConfig, clipboard: arboard::Clipboard) -> Self {
        Self {
            clipboard,
            proxy: cfg.proxy,
            settings: cfg.settings,
            stats: cfg.stats,
            audit: cfg.audit,
            withdrawn: cfg.withdrawn,
            label: cfg.label,
            epoch: Instant::now(),
            detector: LoopDetector::new(),
            initialized: false,
            ready: false,
            files_negotiated: false,
            last_text: None,
            last_image: None,
            last_files: None,
            image_echo: None,
            tick: 0,
            generation: 0,
            outbound: None,
            locked: HashMap::new(),
            served: HashMap::new(),
            audited_out: HashSet::new(),
            staging_base: cfg.staging_base,
            token: cfg.token,
            staging: None,
            inbound: None,
            stream_ids: 0,
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn withdrawn(&self) -> bool {
        self.withdrawn.load(Ordering::SeqCst)
    }

    fn record(&self, direction: TransferDirection, kind: TransferKind, outcome: TransferOutcome, bytes: u64) {
        self.audit.record(TransferEvent::new(direction, kind, outcome, bytes));
    }

    /// Seed the caches without advertising: whatever was on the host
    /// clipboard *before* the session opened is not a copy the operator
    /// made during it, and offering it to the remote on connect would
    /// leak pre-session content into a privileged desktop.
    fn seed(&mut self) {
        if let Ok(text) = self.clipboard.get_text() {
            self.last_text = Some(Zeroizing::new(text));
        }
        if self.settings.files.allows_host_to_session() {
            self.last_files = self.clipboard.get().file_list().ok().filter(|p| !p.is_empty());
        }
        if self.last_text.is_none() && self.settings.direction.allows_host_to_session() {
            if let Ok(img) = self.clipboard.get_image() {
                let bytes = Zeroizing::new(img.bytes.into_owned());
                self.last_image = u32::try_from(img.width)
                    .ok()
                    .zip(u32::try_from(img.height).ok())
                    .map(|(w, h)| ImageFingerprint::of(w, h, &bytes));
            }
        }
    }

    fn handle(&mut self, cmd: BridgeCommand) {
        match cmd {
            BridgeCommand::Initialize => self.initialize(),
            BridgeCommand::Ready => self.ready = true,
            BridgeCommand::Negotiated { files } => self.files_negotiated = files,
            BridgeCommand::ProvideHostText => self.provide_host_text(),
            BridgeCommand::ProvideHostImage(format) => self.provide_host_image(format),
            BridgeCommand::StoreRemoteText(text) => self.store_remote_text(text),
            BridgeCommand::StoreRemoteImage(dib) => self.store_remote_image(dib),
            BridgeCommand::ProvideFileContents(req) => self.provide_file_contents(req),
            BridgeCommand::RemoteFileList { files, clip_data_id } => self.receive_file_list(files, clip_data_id),
            BridgeCommand::RemoteFileChunk { stream_id, is_error, data } => {
                self.receive_file_chunk(stream_id, is_error, data)
            }
            BridgeCommand::Lock(id) => {
                if let Some(list) = &self.outbound {
                    if self.locked.len() < MAX_LOCK_SNAPSHOTS {
                        self.locked.insert(id, Arc::clone(list));
                    }
                }
            }
            BridgeCommand::Unlock(id) => {
                self.locked.remove(&id);
            }
        }
    }

    /// `CLIPRDR` initialisation completes only once the client has sent a
    /// format list, so one goes out whatever the direction — and it is
    /// empty, for the pre-session reason in [`Self::seed`]. A session that
    /// never answered here never reached Ready at all.
    fn initialize(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;
        self.proxy.send_clipboard_message(ClipboardMessage::SendInitiateCopy(Vec::new()));
    }

    fn poll_host(&mut self) {
        self.tick = self.tick.wrapping_add(1);
        if !self.ready || self.withdrawn() || !self.settings.direction.allows_host_to_session() {
            return;
        }

        if self.settings.files.allows_host_to_session() && self.files_negotiated {
            match self.clipboard.get().file_list() {
                Ok(paths) if !paths.is_empty() => {
                    if self.last_files.as_ref() != Some(&paths) {
                        self.last_files = Some(paths.clone());
                        self.advertise_host_files(&paths);
                    }
                    // A file copy also puts the names on the clipboard as
                    // text on some hosts; the files are what was copied.
                    return;
                }
                _ => self.last_files = None,
            }
        }

        match self.clipboard.get_text() {
            Ok(text) => {
                self.last_image = None;
                if self.last_text.as_deref().map(String::as_str) == Some(text.as_str()) || text.is_empty() {
                    return;
                }
                let text = Zeroizing::new(text);
                if self.detector.would_cause_content_loop(text.as_bytes(), ClipboardSource::Local, self.now_ms()) {
                    self.last_text = Some(text);
                    bump(&self.stats, |s| s.suppressed_loop += 1);
                    log::trace!("rdp clipboard [{}]: local change is our own paste; skipped", self.label);
                    return;
                }
                self.last_text = Some(text);
                self.proxy.send_clipboard_message(ClipboardMessage::SendInitiateCopy(vec![ClipboardFormat::new(
                    TEXT_FORMAT,
                )]));
            }
            Err(_) => {
                // A clipboard holding a non-text format reads as an error
                // here. Not worth a counter every 500 ms.
                self.last_text = None;
                if !self.tick.is_multiple_of(IMAGE_POLL_EVERY) {
                    return;
                }
                let Ok(img) = self.clipboard.get_image() else {
                    self.last_image = None;
                    return;
                };
                let (Ok(w), Ok(h)) = (u32::try_from(img.width), u32::try_from(img.height)) else {
                    return;
                };
                let bytes = Zeroizing::new(img.bytes.into_owned());
                let fp = ImageFingerprint::of(w, h, &bytes);
                if self.last_image == Some(fp) {
                    return;
                }
                self.last_image = Some(fp);
                if let Some((ew, eh, at)) = self.image_echo {
                    if (ew, eh) == (w, h) && at.elapsed() < IMAGE_ECHO_WINDOW {
                        self.image_echo = None;
                        bump(&self.stats, |s| s.suppressed_loop += 1);
                        return;
                    }
                }
                // Advertise both; the remote application picks. Delayed
                // rendering: the pixels are only read again, and encoded,
                // if the remote actually pastes.
                self.proxy.send_clipboard_message(ClipboardMessage::SendInitiateCopy(vec![
                    ClipboardFormat::new(ClipboardFormatId::CF_DIBV5),
                    ClipboardFormat::new(ClipboardFormatId::CF_DIB),
                ]));
            }
        }
    }

    /// Validate the host's file list and advertise it, or refuse it whole.
    ///
    /// A refusal here is counted and logged but not audited: nothing has
    /// crossed the channel, and a file copied on the operator's own machine
    /// while a session window happens to be open is not a transfer.
    fn advertise_host_files(&mut self, paths: &[PathBuf]) {
        self.generation += 1;
        match files::build_outbound(paths, self.generation, &files::Fs) {
            Ok(list) => {
                let total: u64 = list.files.iter().map(|f| f.size).sum();
                log::debug!(
                    "rdp clipboard [{}]: host→session file list advertised ({} files, {total} bytes)",
                    self.label,
                    list.files.len()
                );
                let descriptors = files::descriptors(&list);
                self.outbound = Some(Arc::new(list));
                self.proxy.send_clipboard_message(ClipboardMessage::SendInitiateFileCopy(descriptors));
            }
            Err(refused) => {
                bump(&self.stats, |s| s.refused_files += 1);
                log::info!(
                    "rdp clipboard [{}]: host file list of {} entries not offered to the session ({})",
                    self.label,
                    refused.sizes.len(),
                    refused.reason.reason()
                );
            }
        }
    }

    fn respond_error(&self) {
        self.proxy
            .send_clipboard_message(ClipboardMessage::SendFormatData(FormatDataResponse::new_error().into_owned()));
    }

    fn provide_host_text(&mut self) {
        if self.withdrawn() {
            self.record(TransferDirection::HostToSession, TransferKind::Text, TransferOutcome::Refused, 0);
            return self.respond_error();
        }
        let response = match self.clipboard.get_text() {
            Ok(text) => {
                let text = Zeroizing::new(text);
                let encoded = encode_unicode_text(&text);
                self.last_text = Some(text);
                if encoded.len() > MAX_CLIPBOARD_BYTES {
                    log::warn!(
                        "rdp clipboard [{}]: host→session payload of {} bytes \
                         exceeds the {MAX_CLIPBOARD_BYTES}-byte cap; refused",
                        self.label,
                        encoded.len()
                    );
                    bump(&self.stats, |s| s.dropped_oversize += 1);
                    self.record(
                        TransferDirection::HostToSession,
                        TransferKind::Text,
                        TransferOutcome::Oversize,
                        encoded.len() as u64,
                    );
                    FormatDataResponse::new_error()
                } else {
                    let len = encoded.len();
                    let now = self.now_ms();
                    self.detector.record_content(&encoded, ClipboardSource::Local, now);
                    bump(&self.stats, |s| {
                        s.out_transfers += 1;
                        s.out_bytes += len as u64;
                    });
                    self.record(TransferDirection::HostToSession, TransferKind::Text, TransferOutcome::Ok, len as u64);
                    log::debug!("rdp clipboard [{}]: host→session {len} bytes", self.label);
                    FormatDataResponse::new_data(encoded)
                }
            }
            Err(e) => {
                log::warn!("rdp clipboard [{}]: host clipboard read failed: {e}", self.label);
                bump(&self.stats, |s| s.errors += 1);
                self.record(TransferDirection::HostToSession, TransferKind::Text, TransferOutcome::Error, 0);
                FormatDataResponse::new_error()
            }
        };
        self.proxy.send_clipboard_message(ClipboardMessage::SendFormatData(response.into_owned()));
    }

    fn provide_host_image(&mut self, format: ClipboardFormatId) {
        if self.withdrawn() {
            self.record(TransferDirection::HostToSession, TransferKind::Image, TransferOutcome::Refused, 0);
            return self.respond_error();
        }
        let img = match self.clipboard.get_image() {
            Ok(img) => img,
            Err(e) => {
                log::warn!("rdp clipboard [{}]: host clipboard image read failed: {e}", self.label);
                bump(&self.stats, |s| s.errors += 1);
                self.record(TransferDirection::HostToSession, TransferKind::Image, TransferOutcome::Error, 0);
                return self.respond_error();
            }
        };
        let rgba = Zeroizing::new(img.bytes.into_owned());
        let encoded = match (u32::try_from(img.width), u32::try_from(img.height)) {
            (Ok(w), Ok(h)) if format == ClipboardFormatId::CF_DIBV5 => dib::encode_dibv5(w, h, &rgba),
            (Ok(w), Ok(h)) => dib::encode_dib(w, h, &rgba),
            _ => Err(dib::DibError::BadDimensions),
        };
        match encoded {
            Ok(wire) => {
                let len = wire.len() as u64;
                bump(&self.stats, |s| {
                    s.out_transfers += 1;
                    s.out_bytes += len;
                    s.images_out += 1;
                });
                self.record(TransferDirection::HostToSession, TransferKind::Image, TransferOutcome::Ok, len);
                log::debug!("rdp clipboard [{}]: host→session image {len} bytes", self.label);
                self.proxy.send_clipboard_message(ClipboardMessage::SendFormatData(
                    FormatDataResponse::new_data(wire).into_owned(),
                ));
            }
            Err(e) => {
                let attempted = (img.width as u64).saturating_mul(img.height as u64).saturating_mul(4);
                if e.is_oversize() {
                    bump(&self.stats, |s| s.dropped_oversize += 1);
                    self.record(
                        TransferDirection::HostToSession,
                        TransferKind::Image,
                        TransferOutcome::Oversize,
                        attempted,
                    );
                } else {
                    bump(&self.stats, |s| s.malformed += 1);
                    self.record(
                        TransferDirection::HostToSession,
                        TransferKind::Image,
                        TransferOutcome::Malformed,
                        attempted,
                    );
                }
                log::warn!("rdp clipboard [{}]: host→session image refused: {e}", self.label);
                self.respond_error();
            }
        }
    }

    fn store_remote_text(&mut self, text: Zeroizing<String>) {
        if self.withdrawn() {
            return self.record(TransferDirection::SessionToHost, TransferKind::Text, TransferOutcome::Refused, 0);
        }
        let text = Zeroizing::new(host_line_endings(&text));
        // Record before writing: the poll will see this very content as a
        // "local change" and must recognise it as our own paste rather than
        // advertising it back.
        let now = self.now_ms();
        self.detector.record_content(text.as_bytes(), ClipboardSource::Remote, now);
        match self.clipboard.set_text(text.as_str()) {
            Ok(()) => {
                self.record(
                    TransferDirection::SessionToHost,
                    TransferKind::Text,
                    TransferOutcome::Ok,
                    text.len() as u64,
                );
                self.last_text = Some(text);
            }
            Err(e) => {
                log::warn!("rdp clipboard [{}]: host clipboard write failed: {e}", self.label);
                bump(&self.stats, |s| s.errors += 1);
                self.record(
                    TransferDirection::SessionToHost,
                    TransferKind::Text,
                    TransferOutcome::Error,
                    text.len() as u64,
                );
            }
        }
    }

    fn store_remote_image(&mut self, payload: Zeroizing<Vec<u8>>) {
        let len = payload.len() as u64;
        if self.withdrawn() {
            return self.record(TransferDirection::SessionToHost, TransferKind::Image, TransferOutcome::Refused, len);
        }
        let img = match dib::decode(&payload) {
            Ok(img) => img,
            Err(e) => {
                if e.is_oversize() {
                    bump(&self.stats, |s| s.dropped_oversize += 1);
                    self.record(TransferDirection::SessionToHost, TransferKind::Image, TransferOutcome::Oversize, len);
                } else {
                    bump(&self.stats, |s| s.malformed += 1);
                    self.record(TransferDirection::SessionToHost, TransferKind::Image, TransferOutcome::Malformed, len);
                }
                log::warn!("rdp clipboard [{}]: session→host image of {len} bytes refused: {e}", self.label);
                return;
            }
        };
        let (w, h) = (img.width, img.height);
        let fp = ImageFingerprint::of(w, h, &img.rgba);
        let data = arboard::ImageData {
            width: w as usize,
            height: h as usize,
            bytes: std::borrow::Cow::Borrowed(&img.rgba[..]),
        };
        match self.clipboard.set_image(data) {
            Ok(()) => {
                self.last_image = Some(fp);
                self.last_text = None;
                self.image_echo = Some((w, h, Instant::now()));
                bump(&self.stats, |s| {
                    s.in_transfers += 1;
                    s.in_bytes += len;
                    s.images_in += 1;
                });
                self.record(TransferDirection::SessionToHost, TransferKind::Image, TransferOutcome::Ok, len);
                log::debug!("rdp clipboard [{}]: session→host image {w}x{h}, {len} bytes", self.label);
            }
            Err(e) => {
                log::warn!("rdp clipboard [{}]: host clipboard image write failed: {e}", self.label);
                bump(&self.stats, |s| s.errors += 1);
                self.record(TransferDirection::SessionToHost, TransferKind::Image, TransferOutcome::Error, len);
            }
        }
    }

    fn respond_file_error(&self, stream_id: u32) {
        self.proxy.send_clipboard_message(ClipboardMessage::SendFileContentsResponse(
            FileContentsResponse::new_error(stream_id).into_owned(),
        ));
    }

    fn provide_file_contents(&mut self, req: FileContentsRequest) {
        if self.withdrawn() {
            self.record(TransferDirection::HostToSession, TransferKind::File, TransferOutcome::Refused, 0);
            return self.respond_file_error(req.stream_id);
        }
        // A request that carries a lock id is served from the snapshot taken
        // when that lock arrived — the same list `ironrdp` validated the
        // index against. No snapshot for the id is an explicit failure, not
        // a fall-back to whatever list is current: a different list would
        // put a different file behind the same index.
        let list = match req.data_id {
            Some(id) => self.locked.get(&id).cloned(),
            None => self.outbound.clone(),
        };
        let Some(list) = list else {
            bump(&self.stats, |s| s.errors += 1);
            self.record(TransferDirection::HostToSession, TransferKind::File, TransferOutcome::Error, 0);
            return self.respond_file_error(req.stream_id);
        };
        let index = usize::try_from(req.index).unwrap_or(usize::MAX);
        match files::serve(&list, &req) {
            Ok(files::Served::Size(size)) => {
                self.proxy.send_clipboard_message(ClipboardMessage::SendFileContentsResponse(
                    FileContentsResponse::new_size_response(req.stream_id, size),
                ));
                self.note_served(&list, index, 0);
            }
            Ok(files::Served::Data(mut data)) => {
                let n = data.len() as u64;
                bump(&self.stats, |s| s.out_bytes += n);
                let owned = std::mem::take(&mut *data);
                self.proxy.send_clipboard_message(ClipboardMessage::SendFileContentsResponse(
                    FileContentsResponse::new_data_response(req.stream_id, owned),
                ));
                self.note_served(&list, index, n);
            }
            Err(refusal) => {
                let outcome = match refusal {
                    files::ServeRefusal::BadIndex | files::ServeRefusal::BadRange => {
                        bump(&self.stats, |s| s.malformed += 1);
                        TransferOutcome::Malformed
                    }
                    files::ServeRefusal::Changed | files::ServeRefusal::Io => {
                        bump(&self.stats, |s| s.errors += 1);
                        TransferOutcome::Error
                    }
                };
                log::info!("rdp clipboard [{}]: file contents request refused ({refusal:?})", self.label);
                self.record(
                    TransferDirection::HostToSession,
                    TransferKind::File,
                    outcome,
                    u64::from(req.requested_size),
                );
                self.respond_file_error(req.stream_id);
            }
        }
    }

    /// One audit record per file, the first time the remote has been
    /// served at least the whole of it.
    fn note_served(&mut self, list: &files::OutboundList, index: usize, bytes: u64) {
        let Some(file) = list.files.get(index) else {
            return;
        };
        let key = (list.generation, index);
        let served = self.served.entry(key).or_default();
        *served = served.saturating_add(bytes);
        if *served >= file.size && self.audited_out.insert(key) {
            bump(&self.stats, |s| {
                s.out_transfers += 1;
                s.files_out += 1;
            });
            self.record(TransferDirection::HostToSession, TransferKind::File, TransferOutcome::Ok, file.size);
        }
    }

    fn receive_file_list(&mut self, descriptors: Vec<FileDescriptor>, clip_data_id: Option<u32>) {
        let advertised: Vec<u64> = descriptors.iter().map(|f| f.file_size.unwrap_or(0)).collect();
        if self.withdrawn() {
            for size in advertised {
                self.record(TransferDirection::SessionToHost, TransferKind::File, TransferOutcome::Refused, size);
            }
            return;
        }
        if self.inbound.is_some() {
            // A new remote copy supersedes a download still running.
            self.fail_inbound(files::TransferFailure::RemoteError);
        }
        let accepted = match files::validate_inbound(&descriptors) {
            Ok(files) => files,
            Err(refused) => {
                bump(&self.stats, |s| s.refused_files += 1);
                log::info!(
                    "rdp clipboard [{}]: session→host file list of {} entries refused ({})",
                    self.label,
                    refused.sizes.len(),
                    refused.reason.reason()
                );
                for size in refused.sizes {
                    self.record(TransferDirection::SessionToHost, TransferKind::File, refused.reason.outcome(), size);
                }
                return;
            }
        };
        let dir = match self.transfer_dir() {
            Ok(dir) => dir,
            Err(e) => {
                log::warn!("rdp clipboard [{}]: cannot stage received files: {e}", self.label);
                bump(&self.stats, |s| s.errors += 1);
                for f in &accepted {
                    self.record(TransferDirection::SessionToHost, TransferKind::File, TransferOutcome::Error, f.size);
                }
                return;
            }
        };
        let sizes: Vec<u64> = accepted.iter().map(|f| f.size).collect();
        match files::InboundTransfer::start(dir.clone(), accepted, clip_data_id, &mut self.stream_ids, Instant::now()) {
            Ok((transfer, step)) => {
                self.inbound = Some(transfer);
                self.handle_step(step);
            }
            Err(failure) => {
                if let Some(staging) = self.staging.as_mut() {
                    staging.discard(&dir);
                }
                self.account_failure(failure, &sizes);
            }
        }
    }

    fn transfer_dir(&mut self) -> std::io::Result<PathBuf> {
        if self.staging.is_none() {
            let base =
                self.staging_base.as_deref().ok_or_else(|| std::io::Error::other("no application cache directory"))?;
            self.staging = Some(files::StagingDir::create(base, &self.token)?);
        }
        match self.staging.as_mut() {
            Some(staging) => staging.new_transfer_dir(),
            None => Err(std::io::Error::other("staging directory unavailable")),
        }
    }

    fn handle_step(&mut self, step: files::Step) {
        match step {
            files::Step::Request(req) => {
                self.proxy.send_clipboard_message(ClipboardMessage::SendFileContentsRequest(req));
            }
            files::Step::Complete(paths) => {
                let Some(transfer) = self.inbound.take() else {
                    return;
                };
                let sizes = transfer.sizes();
                let total: u64 = sizes.iter().sum();
                match self.clipboard.set().file_list(&paths) {
                    Ok(()) => {
                        // Our own paste must not come back as a host copy.
                        self.last_files = Some(paths);
                        bump(&self.stats, |s| {
                            s.in_transfers += sizes.len() as u64;
                            s.files_in += sizes.len() as u64;
                            s.in_bytes += total;
                        });
                        for size in sizes {
                            self.record(
                                TransferDirection::SessionToHost,
                                TransferKind::File,
                                TransferOutcome::Ok,
                                size,
                            );
                        }
                        log::debug!("rdp clipboard [{}]: session→host file list received ({total} bytes)", self.label);
                    }
                    Err(e) => {
                        log::warn!("rdp clipboard [{}]: host clipboard file-list write failed: {e}", self.label);
                        if let Some(staging) = self.staging.as_mut() {
                            staging.discard(transfer.dir());
                        }
                        bump(&self.stats, |s| s.errors += 1);
                        for size in sizes {
                            self.record(
                                TransferDirection::SessionToHost,
                                TransferKind::File,
                                TransferOutcome::Error,
                                size,
                            );
                        }
                    }
                }
            }
        }
    }

    fn receive_file_chunk(&mut self, stream_id: u32, is_error: bool, data: Option<Zeroizing<Vec<u8>>>) {
        let Some(transfer) = self.inbound.as_mut() else {
            log::debug!("rdp clipboard [{}]: file contents response with no transfer running", self.label);
            return;
        };
        if self.withdrawn.load(Ordering::SeqCst) {
            return self.fail_inbound(files::TransferFailure::RemoteError);
        }
        let Some(data) = data else {
            return self.fail_inbound(files::TransferFailure::Overlong);
        };
        match transfer.on_chunk(stream_id, is_error, &data, &mut self.stream_ids, Instant::now()) {
            Ok(step) => self.handle_step(step),
            Err(failure) => self.fail_inbound(failure),
        }
    }

    fn check_inbound_timeout(&mut self) {
        if self.inbound.as_ref().is_some_and(|t| t.timed_out(Instant::now())) {
            self.fail_inbound(files::TransferFailure::TimedOut);
        }
    }

    fn fail_inbound(&mut self, failure: files::TransferFailure) {
        let Some(transfer) = self.inbound.take() else {
            return;
        };
        if let Some(staging) = self.staging.as_mut() {
            staging.discard(transfer.dir());
        }
        self.account_failure(failure, &transfer.sizes());
    }

    fn account_failure(&self, failure: files::TransferFailure, sizes: &[u64]) {
        log::info!(
            "rdp clipboard [{}]: session→host file transfer of {} files abandoned ({})",
            self.label,
            sizes.len(),
            failure.reason()
        );
        let outcome = failure.outcome();
        bump(&self.stats, |s| match outcome {
            TransferOutcome::Malformed => s.malformed += 1,
            _ => s.errors += 1,
        });
        for size in sizes {
            self.record(TransferDirection::SessionToHost, TransferKind::File, outcome, *size);
        }
    }

    /// The session is ending with a download half done.
    fn abandon_inbound(&mut self) {
        if self.inbound.is_some() {
            self.fail_inbound(files::TransferFailure::RemoteError);
        }
    }
}

/// What the backend is waiting for from its last paste request, so the
/// response is read as what it is — and an unsolicited one is not read at
/// all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingPaste {
    Text,
    Image(ClipboardFormatId),
    FileList,
}

/// The [`CliprdrBackend`] the session's `CLIPRDR` channel drives.
///
/// Every method either answers from memory or posts one command; none
/// of them blocks or touches the OS clipboard or the disk directly.
/// Clipboard locks only snapshot our own advertised file list.
#[derive(Debug)]
pub struct BridgeBackend {
    bridge: BridgeHandle,
    proxy: PumpProxy,
    settings: ClipboardSettings,
    stats: SharedClipboardStats,
    audit: AuditSink,
    withdrawn: Arc<AtomicBool>,
    label: String,
    files_negotiated: bool,
    pending_paste: Option<PendingPaste>,
}

impl_as_any!(BridgeBackend);

impl BridgeBackend {
    fn withdrawn(&self) -> bool {
        self.withdrawn.load(Ordering::SeqCst)
    }

    fn record(&self, direction: TransferDirection, kind: TransferKind, outcome: TransferOutcome, bytes: u64) {
        self.audit.record(TransferEvent::new(direction, kind, outcome, bytes));
    }

    fn paste(&mut self, pending: PendingPaste, format: ClipboardFormatId) {
        self.pending_paste = Some(pending);
        self.proxy.send_clipboard_message(ClipboardMessage::SendInitiatePaste(format));
    }
}

impl CliprdrBackend for BridgeBackend {
    fn temporary_directory(&self) -> &str {
        // Sent to the server in the init sequence. Never a real host path:
        // with stream-based file copy the server has no use for one, and a
        // path would tell it about the operator's machine.
        "."
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        // Long format names always — `FileGroupDescriptorW` does not fit a
        // short one. The file capabilities only when the profile and the
        // policy allow file copy: advertising one we would refuse is worse
        // than not advertising it. `FILECLIP_NO_FILE_PATHS`: descriptors
        // carry basenames only. No `HUGE_FILE_SUPPORT`: the per-file cap is
        // far below 4 GiB.
        let mut caps = ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES;
        if self.settings.files.enabled() {
            caps |= ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED
                | ClipboardGeneralCapabilityFlags::FILECLIP_NO_FILE_PATHS
                | ClipboardGeneralCapabilityFlags::CAN_LOCK_CLIPDATA;
        }
        caps
    }

    fn on_ready(&mut self) {
        bump(&self.stats, |s| s.ready = true);
        self.bridge.send(BridgeCommand::Ready);
        log::info!(
            "rdp clipboard [{}]: channel ready, direction {}, files {}{}",
            self.label,
            self.settings.direction.label(),
            self.settings.files.label(),
            if self.settings.files.enabled() && !self.files_negotiated {
                " (not negotiated by the server)"
            } else {
                ""
            }
        );
    }

    fn on_request_format_list(&mut self) {
        self.bridge.send(BridgeCommand::Initialize);
    }

    fn on_process_negotiated_capabilities(&mut self, capabilities: ClipboardGeneralCapabilityFlags) {
        self.files_negotiated = self.settings.files.enabled()
            && capabilities.contains(ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED);
        self.bridge.send(BridgeCommand::Negotiated { files: self.files_negotiated });
        log::debug!("rdp clipboard [{}]: negotiated capabilities {capabilities:?}", self.label);
    }

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        if self.withdrawn() || !self.settings.direction.allows_session_to_host() {
            // The remote copied something; this session does not carry it
            // out. Counted so "why did my paste not arrive?" has an answer
            // that is not silence. Not audited: nothing was fetched, and a
            // copy *inside* the remote desktop is not a transfer.
            bump(&self.stats, |s| s.refused_direction += 1);
            return;
        }
        let file_list = available_formats
            .iter()
            .find(|f| f.name().map(|n| n.value() == ClipboardFormatName::FILE_LIST.value()).unwrap_or(false));
        if let Some(f) = file_list {
            if self.settings.files.allows_session_to_host() && self.files_negotiated {
                let id = f.id();
                return self.paste(PendingPaste::FileList, id);
            }
        }
        if available_formats.iter().any(|f| f.id() == TEXT_FORMAT) {
            return self.paste(PendingPaste::Text, TEXT_FORMAT);
        }
        // `CF_DIB` first: every Windows target synthesises it for any
        // bitmap, and it is the simpler of the two shapes to validate.
        for format in [ClipboardFormatId::CF_DIB, ClipboardFormatId::CF_DIBV5] {
            if available_formats.iter().any(|f| f.id() == format) {
                return self.paste(PendingPaste::Image(format), format);
            }
        }
        if file_list.is_some() {
            // Files offered, file copy withheld for this session.
            bump(&self.stats, |s| s.refused_direction += 1);
            return;
        }
        log::debug!(
            "rdp clipboard [{}]: remote offered no supported format ({} offered)",
            self.label,
            available_formats.len()
        );
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        let supported = request.format == TEXT_FORMAT || is_image_format(request.format);
        if self.withdrawn() || !self.settings.direction.allows_host_to_session() {
            bump(&self.stats, |s| s.refused_direction += 1);
            if supported {
                // The remote asked for our clipboard and was told no: an
                // attempted ingress, audited as such.
                self.record(TransferDirection::HostToSession, kind_of(request.format), TransferOutcome::Refused, 0);
            }
        } else if request.format == TEXT_FORMAT {
            return self.bridge.send(BridgeCommand::ProvideHostText);
        } else if is_image_format(request.format) {
            return self.bridge.send(BridgeCommand::ProvideHostImage(request.format));
        }
        // An explicit failure response, not silence: the remote is
        // waiting on this and MS-RDPECLIP has a slot for "no".
        self.proxy
            .send_clipboard_message(ClipboardMessage::SendFormatData(FormatDataResponse::new_error().into_owned()));
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        let pending = self.pending_paste.take();
        let len = response.data().len();
        let kind = match pending {
            Some(PendingPaste::Image(_)) => TransferKind::Image,
            Some(PendingPaste::FileList) => TransferKind::File,
            _ => TransferKind::Text,
        };
        if self.withdrawn() || !self.settings.direction.allows_session_to_host() {
            bump(&self.stats, |s| s.refused_direction += 1);
            if pending.is_some() && !response.is_error() {
                self.record(TransferDirection::SessionToHost, kind, TransferOutcome::Refused, len as u64);
            }
            return;
        }
        if response.is_error() {
            log::debug!("rdp clipboard [{}]: remote refused the format data request", self.label);
            if pending == Some(PendingPaste::FileList) {
                bump(&self.stats, |s| s.errors += 1);
                self.record(TransferDirection::SessionToHost, TransferKind::File, TransferOutcome::Error, 0);
            }
            return;
        }
        match pending {
            None => {
                // Nothing was asked for. Writing it to the host clipboard
                // would let the server place content there unprompted.
                log::warn!("rdp clipboard [{}]: unsolicited format data ({len} bytes) dropped", self.label);
                bump(&self.stats, |s| s.malformed += 1);
            }
            Some(PendingPaste::FileList) => {
                // `ironrdp` hands a file-list response here only when it
                // could not parse it.
                log::warn!("rdp clipboard [{}]: malformed remote file list ({len} bytes)", self.label);
                bump(&self.stats, |s| s.malformed += 1);
                self.record(
                    TransferDirection::SessionToHost,
                    TransferKind::File,
                    TransferOutcome::Malformed,
                    len as u64,
                );
            }
            Some(PendingPaste::Image(_)) => {
                if len > dib::MAX_IMAGE_BYTES {
                    log::warn!(
                        "rdp clipboard [{}]: session→host image of {len} bytes exceeds the {}-byte cap; dropped",
                        self.label,
                        dib::MAX_IMAGE_BYTES
                    );
                    bump(&self.stats, |s| s.dropped_oversize += 1);
                    return self.record(
                        TransferDirection::SessionToHost,
                        TransferKind::Image,
                        TransferOutcome::Oversize,
                        len as u64,
                    );
                }
                self.bridge.send(BridgeCommand::StoreRemoteImage(Zeroizing::new(response.data().to_vec())));
            }
            Some(PendingPaste::Text) => {
                if len > MAX_CLIPBOARD_BYTES {
                    log::warn!(
                        "rdp clipboard [{}]: session→host payload of {len} bytes exceeds the \
                         {MAX_CLIPBOARD_BYTES}-byte cap; dropped",
                        self.label
                    );
                    bump(&self.stats, |s| s.dropped_oversize += 1);
                    return self.record(
                        TransferDirection::SessionToHost,
                        TransferKind::Text,
                        TransferOutcome::Oversize,
                        len as u64,
                    );
                }
                match response.to_unicode_string() {
                    Ok(text) => {
                        bump(&self.stats, |s| {
                            s.in_transfers += 1;
                            s.in_bytes += len as u64;
                        });
                        log::debug!("rdp clipboard [{}]: session→host {len} bytes", self.label);
                        self.bridge.send(BridgeCommand::StoreRemoteText(Zeroizing::new(text)));
                    }
                    Err(e) => {
                        log::warn!(
                            "rdp clipboard [{}]: malformed CF_UNICODETEXT payload ({len} bytes): {e}",
                            self.label
                        );
                        bump(&self.stats, |s| s.malformed += 1);
                        self.record(
                            TransferDirection::SessionToHost,
                            TransferKind::Text,
                            TransferOutcome::Malformed,
                            len as u64,
                        );
                    }
                }
            }
        }
    }

    fn on_file_contents_request(&mut self, request: FileContentsRequest) {
        if self.withdrawn() || !self.settings.files.allows_host_to_session() {
            bump(&self.stats, |s| s.refused_direction += 1);
            self.record(TransferDirection::HostToSession, TransferKind::File, TransferOutcome::Refused, 0);
            return self.proxy.send_clipboard_message(ClipboardMessage::SendFileContentsResponse(
                FileContentsResponse::new_error(request.stream_id).into_owned(),
            ));
        }
        self.bridge.send(BridgeCommand::ProvideFileContents(request));
    }

    fn on_file_contents_response(&mut self, response: FileContentsResponse<'_>) {
        if !self.settings.files.allows_session_to_host() {
            bump(&self.stats, |s| s.refused_direction += 1);
            return;
        }
        // We never ask for more than a chunk; anything larger is refused
        // before it is copied.
        let data = (response.data().len() <= files::FILE_CHUNK_BYTES as usize)
            .then(|| Zeroizing::new(response.data().to_vec()));
        self.bridge.send(BridgeCommand::RemoteFileChunk {
            stream_id: response.stream_id(),
            is_error: response.is_error(),
            data,
        });
    }

    fn on_lock(&mut self, data_id: LockDataId) {
        self.bridge.send(BridgeCommand::Lock(data_id.0));
    }

    fn on_unlock(&mut self, data_id: LockDataId) {
        self.bridge.send(BridgeCommand::Unlock(data_id.0));
    }

    fn on_remote_file_list(&mut self, files: &[FileDescriptor], clip_data_id: Option<u32>) {
        // `ironrdp` consumed the response we were waiting for.
        self.pending_paste = None;
        if self.withdrawn() || !self.settings.files.allows_session_to_host() {
            bump(&self.stats, |s| s.refused_direction += 1);
            for f in files {
                self.record(
                    TransferDirection::SessionToHost,
                    TransferKind::File,
                    TransferOutcome::Refused,
                    f.file_size.unwrap_or(0),
                );
            }
            return;
        }
        if files.len() > files::MAX_FILE_COUNT {
            // Refused here rather than on the bridge so an oversized list —
            // `ironrdp` admits up to 100,000 entries — is never copied.
            log::info!(
                "rdp clipboard [{}]: session→host file list of {} entries refused ({})",
                self.label,
                files.len(),
                files::FileRefusal::TooMany.reason()
            );
            bump(&self.stats, |s| s.refused_files += 1);
            for f in files {
                self.record(
                    TransferDirection::SessionToHost,
                    TransferKind::File,
                    TransferOutcome::Oversize,
                    f.file_size.unwrap_or(0),
                );
            }
            return;
        }
        self.bridge.send(BridgeCommand::RemoteFileList { files: files.to_vec(), clip_data_id });
    }
}

/// Create the pump-side receiver and the proxy the bridge and backend
/// send through.
pub fn channel() -> (PumpProxy, tokio_mpsc::UnboundedReceiver<ClipboardMessage>) {
    let (tx, rx) = tokio_mpsc::unbounded_channel();
    (PumpProxy { tx }, rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend_with(
        settings: ClipboardSettings,
    ) -> (
        BridgeBackend,
        tokio_mpsc::UnboundedReceiver<ClipboardMessage>,
        std_mpsc::Receiver<BridgeCommand>,
        SharedClipboardStats,
        tokio_mpsc::UnboundedReceiver<TransferEvent>,
    ) {
        let (proxy, rx) = channel();
        let stats: SharedClipboardStats = Arc::new(Mutex::new(ClipboardStats::default()));
        let (tx, bridge_rx) = std_mpsc::channel();
        let (audit, audit_rx) = AuditSink::for_test();
        let backend = BridgeBackend {
            bridge: BridgeHandle { tx },
            proxy,
            settings,
            stats: Arc::clone(&stats),
            audit,
            withdrawn: Arc::new(AtomicBool::new(false)),
            label: "test".into(),
            files_negotiated: false,
            pending_paste: None,
        };
        (backend, rx, bridge_rx, stats, audit_rx)
    }

    fn text_only(direction: ClipboardDirection) -> ClipboardSettings {
        ClipboardSettings { direction, files: ClipboardDirection::Off }
    }

    fn all(direction: ClipboardDirection) -> ClipboardSettings {
        ClipboardSettings { direction, files: direction }
    }

    fn file_list_format() -> ClipboardFormat {
        ClipboardFormat::new(ClipboardFormatId::new(0xC0FE)).with_name(ClipboardFormatName::FILE_LIST)
    }

    // ─── Profile parsing (Phase 1) ───────────────────────────────

    #[test]
    fn a_resource_that_says_nothing_gets_a_working_clipboard() {
        let dir = direction_from_profile(None).expect("absent is not an error");
        assert_eq!(dir, PROFILE_DEFAULT_DIRECTION);
        assert!(dir.allows_host_to_session(), "the operator must be able to paste into the target");
        assert!(dir.allows_session_to_host(), "and to carry content back out");
    }

    #[test]
    fn a_resource_can_withhold_the_clipboard_entirely() {
        assert_eq!(direction_from_profile(Some("off")), Ok(ClipboardDirection::Off));
        assert!(!ClipboardDirection::Off.enabled(), "`off` attaches no CLIPRDR channel");
        // And each direction can be withheld on its own.
        let ingress = direction_from_profile(Some("host-to-session")).unwrap();
        assert!(ingress.allows_host_to_session() && !ingress.allows_session_to_host());
        let egress = direction_from_profile(Some("session-to-host")).unwrap();
        assert!(egress.allows_session_to_host() && !egress.allows_host_to_session());
    }

    #[test]
    fn a_typo_fails_the_connect_instead_of_defaulting_to_on() {
        let err = direction_from_profile(Some("bidrectional")).expect_err("a typo must not resolve");
        assert!(err.contains("unknown rdp_clipboard"), "{err}");
    }

    #[test]
    fn direction_parsing_is_strict() {
        assert_eq!(parse_clipboard_direction("off"), Ok(ClipboardDirection::Off));
        assert_eq!(parse_clipboard_direction(""), Ok(ClipboardDirection::Off));
        assert_eq!(parse_clipboard_direction("  NONE "), Ok(ClipboardDirection::Off));
        assert_eq!(parse_clipboard_direction("host-to-session"), Ok(ClipboardDirection::HostToSession));
        assert_eq!(parse_clipboard_direction("in"), Ok(ClipboardDirection::HostToSession));
        assert_eq!(parse_clipboard_direction("session_to_host"), Ok(ClipboardDirection::SessionToHost));
        assert_eq!(parse_clipboard_direction("both"), Ok(ClipboardDirection::Bidirectional));
        // A typo must not silently become a default — in either
        // direction. `bidirectionnal` enabling nothing is as wrong as
        // it enabling everything.
        let err = parse_clipboard_direction("bidirectionnal").unwrap_err();
        assert!(err.contains("unknown rdp_clipboard"), "{err}");
        assert!(parse_clipboard_direction("yes").is_err());
    }

    #[test]
    fn direction_gates_are_not_symmetric() {
        assert!(!ClipboardDirection::Off.enabled());
        assert!(!ClipboardDirection::Off.allows_host_to_session());
        assert!(!ClipboardDirection::Off.allows_session_to_host());

        let h2s = ClipboardDirection::HostToSession;
        assert!(h2s.allows_host_to_session());
        assert!(!h2s.allows_session_to_host());

        let s2h = ClipboardDirection::SessionToHost;
        assert!(!s2h.allows_host_to_session());
        assert!(s2h.allows_session_to_host());

        let both = ClipboardDirection::Bidirectional;
        assert!(both.allows_host_to_session());
        assert!(both.allows_session_to_host());
    }

    // ─── File switch (Phase 3) ───────────────────────────────────

    #[test]
    fn file_copy_is_off_unless_the_resource_asks_for_it() {
        assert_eq!(files_direction_from_profile(None), Ok(ClipboardDirection::Off));
        assert_eq!(files_direction_from_profile(Some("session-to-host")), Ok(ClipboardDirection::SessionToHost));
        let err = files_direction_from_profile(Some("yes please")).unwrap_err();
        assert!(err.contains("unknown rdp_clipboard_files"), "{err}");
    }

    #[test]
    fn file_copy_is_not_folded_into_a_bidirectional_clipboard() {
        // Regression guard: `rdp_clipboard: bidirectional` (the default)
        // must not imply file copy.
        let r = resolve_settings(
            direction_from_profile(Some("bidirectional")).unwrap(),
            files_direction_from_profile(None).unwrap(),
            &PolicyCeiling::from_effective(&Map::new()),
        );
        assert_eq!(r.settings.files, ClipboardDirection::Off);
    }

    #[test]
    fn file_copy_never_travels_where_the_clipboard_may_not() {
        let r = resolve_settings(
            ClipboardDirection::HostToSession,
            ClipboardDirection::Bidirectional,
            &PolicyCeiling::from_effective(&Map::new()),
        );
        assert_eq!(r.settings.files, ClipboardDirection::HostToSession);
        assert_eq!(r.narrowed.len(), 1, "{:?}", r.narrowed);
    }

    // ─── Policy ceiling (Phase 4) ────────────────────────────────

    fn effective(clipboard: &str, files: &str) -> Map<String, Value> {
        serde_json::json!({
            "transport": "direct",
            "clipboard": clipboard,
            "clipboard_source": "type",
            "clipboard_files": files,
            "clipboard_files_source": "global",
            "clipboard_locked_by": ["global"],
        })
        .as_object()
        .cloned()
        .unwrap()
    }

    #[test]
    fn a_locked_policy_overrides_the_profile_value() {
        let ceiling = PolicyCeiling::from_effective(&effective("off", "off"));
        assert!(ceiling.server_supports);
        let r = resolve_settings(ClipboardDirection::Bidirectional, ClipboardDirection::Bidirectional, &ceiling);
        assert_eq!(r.settings, ClipboardSettings::off());
        assert!(r.narrowed.iter().any(|l| l.contains("by policy tier `type`")), "{:?}", r.narrowed);
    }

    #[test]
    fn the_policy_narrows_but_never_widens() {
        let ceiling = PolicyCeiling::from_effective(&effective("bidirectional", "bidirectional"));
        let r = resolve_settings(ClipboardDirection::SessionToHost, ClipboardDirection::Off, &ceiling);
        assert_eq!(r.settings.direction, ClipboardDirection::SessionToHost);
        assert_eq!(r.settings.files, ClipboardDirection::Off);
        assert!(r.narrowed.is_empty());

        let ceiling = PolicyCeiling::from_effective(&effective("host-to-session", "bidirectional"));
        let r = resolve_settings(ClipboardDirection::SessionToHost, ClipboardDirection::Off, &ceiling);
        assert_eq!(r.settings.direction, ClipboardDirection::Off, "one direction each way intersects to nothing");
    }

    #[test]
    fn an_unreadable_policy_fails_closed() {
        for data in [effective("sideways", "off"), effective("bidirectional", "BIDIRECTIONAL"), {
            let mut m = effective("bidirectional", "off");
            m.remove("clipboard_files");
            m
        }] {
            let ceiling = PolicyCeiling::from_effective(&data);
            assert!(ceiling.unreadable.is_some());
            let r = resolve_settings(ClipboardDirection::Bidirectional, ClipboardDirection::Bidirectional, &ceiling);
            assert_eq!(r.settings, ClipboardSettings::off());
        }
        // A non-string value too.
        let mut m = effective("off", "off");
        m.insert("clipboard".into(), Value::Bool(true));
        assert_eq!(PolicyCeiling::from_effective(&m).clipboard, ClipboardDirection::Off);
    }

    #[test]
    fn a_server_without_the_knobs_constrains_nothing_and_has_no_vault_audit() {
        let ceiling =
            PolicyCeiling::from_effective(&serde_json::json!({ "transport": "direct" }).as_object().cloned().unwrap());
        assert!(!ceiling.server_supports);
        assert!(ceiling.unreadable.is_none());
        let r = resolve_settings(ClipboardDirection::Bidirectional, ClipboardDirection::Off, &ceiling);
        assert_eq!(r.settings.direction, ClipboardDirection::Bidirectional);
    }

    // ─── Wire form (Phase 1) ─────────────────────────────────────

    #[test]
    fn unicode_text_round_trips_through_the_wire_form() {
        // UTF-16LE, CRLF, NUL-terminated (MS-RDPECLIP 2.2.5.2).
        let encoded = encode_unicode_text("a\nb");
        assert_eq!(
            encoded,
            vec![b'a', 0, b'\r', 0, b'\n', 0, b'b', 0, 0, 0],
            "expected UTF-16LE with CRLF and a NUL terminator"
        );
        let decoded = FormatDataResponse::new_data(encoded).to_unicode_string().unwrap();
        assert_eq!(decoded, "a\r\nb");
        assert_eq!(host_line_endings(&decoded), if cfg!(windows) { "a\r\nb" } else { "a\nb" });
    }

    #[test]
    fn non_ascii_survives_the_wire_form() {
        // Two-byte, three-byte and astral-plane characters: a
        // latin1/UTF-8 confusion or a lost surrogate pair shows here.
        for text in ["café", "日本語", "emoji 🔐 ok", "Ω≈ç√∫"] {
            let decoded = FormatDataResponse::new_data(encode_unicode_text(text)).to_unicode_string().unwrap();
            assert_eq!(decoded, *text, "round trip failed for {text:?}");
        }
    }

    #[test]
    fn crlf_normalisation_does_not_double_up() {
        assert_eq!(normalize_to_crlf("a\r\nb"), "a\r\nb");
        assert_eq!(normalize_to_crlf("a\nb"), "a\r\nb");
        assert_eq!(normalize_to_crlf("a\r\n\nb"), "a\r\n\r\nb");
        assert_eq!(normalize_to_crlf("plain"), "plain");
    }

    #[test]
    fn the_size_cap_counts_the_wire_payload() {
        // A string just under the cap in UTF-8 is over it once it is
        // UTF-16LE with a terminator — which is the length that
        // matters, and the one the cap is applied to.
        let text = "x".repeat(MAX_CLIPBOARD_BYTES - 1);
        assert!(text.len() < MAX_CLIPBOARD_BYTES);
        assert!(encode_unicode_text(&text).len() > MAX_CLIPBOARD_BYTES);
    }

    // ─── Backend: text (Phase 1) ─────────────────────────────────

    #[test]
    fn an_oversize_inbound_payload_is_dropped_not_truncated() {
        let (mut backend, _rx, bridge_rx, stats, mut audit) =
            backend_with(text_only(ClipboardDirection::Bidirectional));
        backend.on_remote_copy(&[ClipboardFormat::new(TEXT_FORMAT)]);
        let oversize = vec![b'a'; MAX_CLIPBOARD_BYTES + 1];
        backend.on_format_data_response(FormatDataResponse::new_data(oversize));
        let s = *stats.lock().unwrap();
        assert_eq!(s.dropped_oversize, 1);
        assert_eq!(s.in_transfers, 0);
        // Nothing reached the bridge, so nothing reached the host
        // clipboard — not even a prefix.
        assert!(bridge_rx.try_recv().is_err());
        let ev = audit.try_recv().unwrap();
        assert_eq!(
            (ev.direction, ev.kind, ev.outcome),
            (TransferDirection::SessionToHost, TransferKind::Text, TransferOutcome::Oversize)
        );
        assert_eq!(ev.bytes, (MAX_CLIPBOARD_BYTES + 1) as u64);
    }

    #[test]
    fn a_remote_copy_is_ignored_when_the_direction_forbids_it() {
        let (mut backend, mut rx, _bridge_rx, stats, mut audit) =
            backend_with(text_only(ClipboardDirection::HostToSession));
        backend.on_remote_copy(&[ClipboardFormat::new(TEXT_FORMAT)]);
        assert_eq!(stats.lock().unwrap().refused_direction, 1);
        // No paste initiated: the remote's copy stays on the remote.
        assert!(rx.try_recv().is_err());
        // A copy inside the remote desktop is not a transfer: not audited.
        assert!(audit.try_recv().is_err());

        // And the inbound data path refuses too, even if a response
        // arrives anyway.
        backend.on_format_data_response(FormatDataResponse::new_data(encode_unicode_text("x")));
        let s = *stats.lock().unwrap();
        assert_eq!(s.in_transfers, 0);
        assert_eq!(s.refused_direction, 2);
    }

    #[test]
    fn a_format_data_request_is_refused_explicitly_when_the_direction_forbids_it() {
        let (mut backend, mut rx, bridge_rx, stats, mut audit) =
            backend_with(text_only(ClipboardDirection::SessionToHost));
        backend.on_format_data_request(FormatDataRequest { format: TEXT_FORMAT });
        // An explicit CB_RESPONSE_FAIL, not silence — the remote is
        // blocked on an answer.
        match rx.try_recv() {
            Ok(ClipboardMessage::SendFormatData(resp)) => assert!(resp.is_error()),
            other => panic!("expected an error format-data response, got {other:?}"),
        }
        assert_eq!(stats.lock().unwrap().refused_direction, 1);
        // The host clipboard was never read.
        assert!(bridge_rx.try_recv().is_err());
        assert_eq!(audit.try_recv().unwrap().outcome, TransferOutcome::Refused);
    }

    #[test]
    fn an_unsupported_format_request_is_refused_without_touching_the_clipboard() {
        let (mut backend, mut rx, bridge_rx, stats, _audit) =
            backend_with(text_only(ClipboardDirection::Bidirectional));
        backend.on_format_data_request(FormatDataRequest { format: ClipboardFormatId::CF_ENHMETAFILE });
        match rx.try_recv() {
            Ok(ClipboardMessage::SendFormatData(resp)) => assert!(resp.is_error()),
            other => panic!("expected an error format-data response, got {other:?}"),
        }
        // Not a direction refusal — the direction was fine, the format
        // is simply not carried.
        assert_eq!(stats.lock().unwrap().refused_direction, 0);
        assert!(bridge_rx.try_recv().is_err());
    }

    #[test]
    fn a_text_request_reaches_the_bridge_when_allowed() {
        let (mut backend, _rx, bridge_rx, _stats, _audit) = backend_with(text_only(ClipboardDirection::Bidirectional));
        backend.on_format_data_request(FormatDataRequest { format: TEXT_FORMAT });
        assert!(matches!(bridge_rx.try_recv(), Ok(BridgeCommand::ProvideHostText)));
    }

    #[test]
    fn a_well_formed_inbound_payload_is_counted_and_forwarded() {
        let (mut backend, mut rx, bridge_rx, stats, _audit) =
            backend_with(text_only(ClipboardDirection::Bidirectional));
        backend.on_remote_copy(&[ClipboardFormat::new(TEXT_FORMAT)]);
        assert!(matches!(rx.try_recv(), Ok(ClipboardMessage::SendInitiatePaste(f)) if f == TEXT_FORMAT));
        let payload = encode_unicode_text("hello\nworld");
        let len = payload.len();
        backend.on_format_data_response(FormatDataResponse::new_data(payload));
        let s = *stats.lock().unwrap();
        assert_eq!(s.in_transfers, 1);
        assert_eq!(s.in_bytes, len as u64);
        match bridge_rx.try_recv() {
            Ok(BridgeCommand::StoreRemoteText(text)) => assert_eq!(text.as_str(), "hello\r\nworld"),
            other => panic!("expected StoreRemoteText, got {}", other.is_ok()),
        }
    }

    #[test]
    fn an_error_response_is_not_counted_as_a_transfer() {
        let (mut backend, _rx, bridge_rx, stats, _audit) = backend_with(text_only(ClipboardDirection::Bidirectional));
        backend.on_remote_copy(&[ClipboardFormat::new(TEXT_FORMAT)]);
        backend.on_format_data_response(FormatDataResponse::new_error());
        let s = *stats.lock().unwrap();
        assert_eq!(s.in_transfers, 0);
        assert_eq!(s.errors, 0);
        assert!(bridge_rx.try_recv().is_err());
    }

    #[test]
    fn an_unsolicited_payload_never_reaches_the_host_clipboard() {
        // Regression guard: the server must not be able to place content on
        // the host clipboard by sending data nobody asked for.
        let (mut backend, _rx, bridge_rx, stats, _audit) = backend_with(text_only(ClipboardDirection::Bidirectional));
        backend.on_format_data_response(FormatDataResponse::new_data(encode_unicode_text("planted")));
        assert!(bridge_rx.try_recv().is_err());
        assert_eq!(stats.lock().unwrap().malformed, 1);
    }

    #[test]
    fn malformed_utf16_is_counted_and_audited_not_forwarded() {
        let (mut backend, _rx, bridge_rx, stats, mut audit) =
            backend_with(text_only(ClipboardDirection::Bidirectional));
        backend.on_remote_copy(&[ClipboardFormat::new(TEXT_FORMAT)]);
        // An odd byte count is not UTF-16.
        backend.on_format_data_response(FormatDataResponse::new_data(vec![b'a', 0, b'b']));
        if stats.lock().unwrap().malformed == 1 {
            assert!(bridge_rx.try_recv().is_err());
            assert_eq!(audit.try_recv().unwrap().outcome, TransferOutcome::Malformed);
        } else {
            // `ironrdp` reads an odd tail leniently; then it is ordinary
            // text and must still be capped and forwarded like any other.
            assert!(matches!(bridge_rx.try_recv(), Ok(BridgeCommand::StoreRemoteText(_))));
        }
    }

    #[test]
    fn the_loop_detector_suppresses_our_own_paste_coming_back() {
        // The feedback loop this exists to break: remote copy → host
        // clipboard → the poller sees a "local change" → advertise it
        // back → remote copies again, forever.
        let mut detector = LoopDetector::new();
        let text = "round and round";
        detector.record_content(text.as_bytes(), ClipboardSource::Remote, 0);
        assert!(detector.would_cause_content_loop(text.as_bytes(), ClipboardSource::Local, 10));
        // An unrelated later copy is not suppressed.
        assert!(!detector.would_cause_content_loop(b"something else", ClipboardSource::Local, 10));
    }

    #[test]
    fn initialisation_is_requested_whatever_the_direction() {
        // Regression guard: `CLIPRDR` reaches Ready only after the client
        // sends a format list. Phase 1 sent one only when the host had text
        // to offer and the direction allowed it, so a `session-to-host`
        // session never initialised at all.
        for dir in
            [ClipboardDirection::SessionToHost, ClipboardDirection::HostToSession, ClipboardDirection::Bidirectional]
        {
            let (mut backend, _rx, bridge_rx, _stats, _audit) = backend_with(text_only(dir));
            backend.on_request_format_list();
            assert!(matches!(bridge_rx.try_recv(), Ok(BridgeCommand::Initialize)), "{dir:?}");
        }
    }

    #[test]
    fn host_copies_wait_for_the_channel_to_be_ready() {
        // The bridge advertises nothing until the backend relays Ready: in
        // the Initialization state a copy would re-send capabilities.
        let (mut backend, _rx, bridge_rx, stats, _audit) = backend_with(text_only(ClipboardDirection::Bidirectional));
        backend.on_ready();
        assert!(matches!(bridge_rx.try_recv(), Ok(BridgeCommand::Ready)));
        assert!(stats.lock().unwrap().ready);
    }

    // ─── Backend: images (Phase 2) ───────────────────────────────

    #[test]
    fn an_image_copy_is_fetched_as_cf_dib_and_validated_on_the_bridge() {
        let (mut backend, mut rx, bridge_rx, _stats, _audit) =
            backend_with(text_only(ClipboardDirection::Bidirectional));
        backend.on_remote_copy(&[
            ClipboardFormat::new(ClipboardFormatId::CF_DIBV5),
            ClipboardFormat::new(ClipboardFormatId::CF_DIB),
        ]);
        assert!(matches!(rx.try_recv(), Ok(ClipboardMessage::SendInitiatePaste(f)) if f == ClipboardFormatId::CF_DIB));
        let dib = dib::encode_dib(1, 1, &[1, 2, 3, 255]).unwrap();
        backend.on_format_data_response(FormatDataResponse::new_data(dib.clone()));
        match bridge_rx.try_recv() {
            Ok(BridgeCommand::StoreRemoteImage(p)) => assert_eq!(&p[..], &dib[..]),
            other => panic!("expected StoreRemoteImage, got {}", other.is_ok()),
        }
    }

    #[test]
    fn text_wins_over_an_image_offered_alongside_it() {
        let (mut backend, mut rx, _bridge_rx, _stats, _audit) =
            backend_with(text_only(ClipboardDirection::Bidirectional));
        backend.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_DIB), ClipboardFormat::new(TEXT_FORMAT)]);
        assert!(matches!(rx.try_recv(), Ok(ClipboardMessage::SendInitiatePaste(f)) if f == TEXT_FORMAT));
    }

    #[test]
    fn an_oversize_image_is_dropped_before_it_is_copied() {
        let (mut backend, _rx, bridge_rx, stats, mut audit) =
            backend_with(text_only(ClipboardDirection::Bidirectional));
        backend.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_DIB)]);
        backend.on_format_data_response(FormatDataResponse::new_data(vec![0u8; dib::MAX_IMAGE_BYTES + 1]));
        assert!(bridge_rx.try_recv().is_err());
        assert_eq!(stats.lock().unwrap().dropped_oversize, 1);
        let ev = audit.try_recv().unwrap();
        assert_eq!((ev.kind, ev.outcome), (TransferKind::Image, TransferOutcome::Oversize));
    }

    #[test]
    fn image_requests_follow_the_text_direction() {
        let (mut backend, mut rx, bridge_rx, _stats, _audit) =
            backend_with(text_only(ClipboardDirection::SessionToHost));
        backend.on_format_data_request(FormatDataRequest { format: ClipboardFormatId::CF_DIB });
        assert!(bridge_rx.try_recv().is_err());
        assert!(matches!(rx.try_recv(), Ok(ClipboardMessage::SendFormatData(r)) if r.is_error()));

        let (mut backend, _rx, bridge_rx, _stats, _audit) = backend_with(text_only(ClipboardDirection::HostToSession));
        backend.on_format_data_request(FormatDataRequest { format: ClipboardFormatId::CF_DIBV5 });
        assert!(
            matches!(bridge_rx.try_recv(), Ok(BridgeCommand::ProvideHostImage(f)) if f == ClipboardFormatId::CF_DIBV5)
        );
    }

    // ─── Backend: files (Phase 3) ────────────────────────────────

    #[test]
    fn no_file_capability_is_advertised_unless_file_copy_is_on() {
        let (backend, ..) = backend_with(text_only(ClipboardDirection::Bidirectional));
        let caps = backend.client_capabilities();
        assert!(caps.contains(ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES));
        assert!(!caps.contains(ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED));
        assert!(!caps.contains(ClipboardGeneralCapabilityFlags::CAN_LOCK_CLIPDATA));

        let (backend, ..) = backend_with(all(ClipboardDirection::SessionToHost));
        let caps = backend.client_capabilities();
        assert!(caps.contains(ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED));
        assert!(caps.contains(ClipboardGeneralCapabilityFlags::FILECLIP_NO_FILE_PATHS));
        assert!(!caps.contains(ClipboardGeneralCapabilityFlags::HUGE_FILE_SUPPORT_ENABLED));
        assert_eq!(backend.temporary_directory(), ".", "no host path in the init sequence");
    }

    #[test]
    fn a_remote_file_copy_is_fetched_only_when_file_copy_is_on_and_negotiated() {
        // Off: offered files are refused, and with nothing else on offer no
        // paste is started.
        let (mut backend, mut rx, _b, stats, _a) = backend_with(text_only(ClipboardDirection::Bidirectional));
        backend.on_remote_copy(&[file_list_format()]);
        assert!(rx.try_recv().is_err());
        assert_eq!(stats.lock().unwrap().refused_direction, 1);

        // On, but the server never agreed to stream file copy.
        let (mut backend, mut rx, _b, _s, _a) = backend_with(all(ClipboardDirection::Bidirectional));
        backend.on_process_negotiated_capabilities(ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES);
        backend.on_remote_copy(&[file_list_format()]);
        assert!(rx.try_recv().is_err());

        // On and negotiated: the list is requested.
        let (mut backend, mut rx, _b, _s, _a) = backend_with(all(ClipboardDirection::Bidirectional));
        backend.on_process_negotiated_capabilities(ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED);
        backend.on_remote_copy(&[ClipboardFormat::new(TEXT_FORMAT), file_list_format()]);
        assert!(
            matches!(rx.try_recv(), Ok(ClipboardMessage::SendInitiatePaste(f)) if f == ClipboardFormatId::new(0xC0FE))
        );
    }

    #[test]
    fn a_file_contents_request_is_refused_explicitly_when_file_copy_is_off() {
        let (mut backend, mut rx, bridge_rx, _stats, mut audit) =
            backend_with(text_only(ClipboardDirection::Bidirectional));
        backend.on_file_contents_request(FileContentsRequest {
            stream_id: 7,
            index: 0,
            flags: ironrdp::cliprdr::pdu::FileContentsFlags::RANGE,
            position: 0,
            requested_size: 10,
            data_id: None,
        });
        assert!(bridge_rx.try_recv().is_err(), "no host file is opened");
        match rx.try_recv() {
            Ok(ClipboardMessage::SendFileContentsResponse(r)) => {
                assert!(r.is_error());
                assert_eq!(r.stream_id(), 7);
            }
            other => panic!("expected an error file-contents response, got {other:?}"),
        }
        let ev = audit.try_recv().unwrap();
        assert_eq!(
            (ev.direction, ev.kind, ev.outcome),
            (TransferDirection::HostToSession, TransferKind::File, TransferOutcome::Refused)
        );
    }

    #[test]
    fn an_overlong_file_chunk_is_not_copied() {
        let (mut backend, _rx, bridge_rx, _stats, _audit) = backend_with(all(ClipboardDirection::Bidirectional));
        let big = vec![0u8; files::FILE_CHUNK_BYTES as usize + 1];
        backend.on_file_contents_response(FileContentsResponse::new_data_response(3, big));
        match bridge_rx.try_recv() {
            Ok(BridgeCommand::RemoteFileChunk { stream_id, data, .. }) => {
                assert_eq!(stream_id, 3);
                assert!(data.is_none(), "an over-chunk response is refused before it is copied");
            }
            other => panic!("expected RemoteFileChunk, got {}", other.is_ok()),
        }
    }

    #[test]
    fn an_oversized_remote_file_list_is_refused_before_it_is_copied() {
        let (mut backend, _rx, bridge_rx, stats, mut audit) = backend_with(all(ClipboardDirection::Bidirectional));
        let list: Vec<FileDescriptor> =
            (0..=files::MAX_FILE_COUNT).map(|i| FileDescriptor::new(format!("f{i}")).with_file_size(1)).collect();
        backend.on_remote_file_list(&list, None);
        assert!(bridge_rx.try_recv().is_err(), "nothing reaches the bridge or the disk");
        assert_eq!(stats.lock().unwrap().refused_files, 1);
        let ev = audit.try_recv().unwrap();
        assert_eq!((ev.kind, ev.outcome), (TransferKind::File, TransferOutcome::Oversize));

        // At the cap it is the bridge's to validate in full.
        let (mut backend, _rx, bridge_rx, ..) = backend_with(all(ClipboardDirection::Bidirectional));
        backend.on_remote_file_list(&list[..files::MAX_FILE_COUNT], Some(4));
        assert!(matches!(
            bridge_rx.try_recv(),
            Ok(BridgeCommand::RemoteFileList { files, clip_data_id: Some(4) }) if files.len() == files::MAX_FILE_COUNT
        ));
    }

    // ─── Withdrawal (Phase 4, fail closed) ───────────────────────

    #[test]
    fn a_withdrawn_clipboard_refuses_everything() {
        let (mut backend, mut rx, bridge_rx, stats, _audit) = backend_with(all(ClipboardDirection::Bidirectional));
        backend.withdrawn.store(true, Ordering::SeqCst);
        backend.on_remote_copy(&[ClipboardFormat::new(TEXT_FORMAT)]);
        assert!(rx.try_recv().is_err(), "no paste after withdrawal");
        backend.on_format_data_request(FormatDataRequest { format: TEXT_FORMAT });
        assert!(matches!(rx.try_recv(), Ok(ClipboardMessage::SendFormatData(r)) if r.is_error()));
        backend.on_file_contents_request(FileContentsRequest {
            stream_id: 1,
            index: 0,
            flags: ironrdp::cliprdr::pdu::FileContentsFlags::SIZE,
            position: 0,
            requested_size: 8,
            data_id: None,
        });
        assert!(matches!(rx.try_recv(), Ok(ClipboardMessage::SendFileContentsResponse(r)) if r.is_error()));
        assert!(bridge_rx.try_recv().is_err(), "nothing reaches the host clipboard or disk");
        assert!(stats.lock().unwrap().refused_direction >= 3);
    }
}
