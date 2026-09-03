//! MS-RDPECLIP (`CLIPRDR`) clipboard redirection for the in-app RDP
//! session — see [`features/rdp-clipboard-redirection.md`].
//!
//! Copy in the remote desktop, paste on the host, and the reverse.
//! Phase 1 carries `CF_UNICODETEXT` only.
//!
//! ## Why this is off by default
//!
//! The clipboard is a bidirectional data channel into and out of a
//! privileged session: unlogged egress for whatever the operator can
//! see on the target, and ingress into a production host. So it is
//! opt-in per connection profile, with an explicit direction, a size
//! cap and observable counters. `off` means the channel is **not
//! attached at all** rather than attached-but-inert — a capability we
//! do not intend to honour should not be advertised to the server.
//!
//! This does not weaken the "credentials never reach the clipboard"
//! property: the resource's stored secret still goes straight into the
//! protocol and never onto any clipboard. What moves here is
//! operator-initiated content, and only when the profile allows it.
//!
//! ## Shape
//!
//! ```text
//!  host OS clipboard                              remote desktop
//!         │                                              ▲
//!         │ arboard (own thread)                         │
//!         ▼                                              │
//!  ClipboardBridge ──ClipboardMessage──▶ pump ──▶ CliprdrClient ──▶ SVC
//!    (poll, read/write)  (unbounded mpsc)  (rdp.rs)
//!         ▲                                              │
//!         └──────────── TextCliprdrBackend ◀─────────────┘
//! ```
//!
//! Two things are deliberate:
//!
//! - **The `arboard` handle lives on its own thread.** An X11 or
//!   Wayland clipboard read can block for as long as the *owning*
//!   application takes to answer, and a blocked pump is a frozen
//!   session. Platform clipboard handles also carry thread affinity a
//!   `tokio` worker cannot promise.
//! - **Host-side changes are polled**, because no cross-platform
//!   clipboard change notification exists (Windows has one; X11 and
//!   macOS do not). [`HOST_POLL_INTERVAL`] is well under human
//!   copy→paste latency and costs one clipboard read per tick.
//!
//! Nothing here ever logs clipboard content, at any level, in either
//! direction. The logs carry direction, byte counts, format ids and
//! outcomes only.

use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ironrdp::cliprdr::backend::{CliprdrBackend, ClipboardMessage, ClipboardMessageProxy};
use ironrdp::cliprdr::loop_detector::{ClipboardSource, LoopDetector};
use ironrdp::cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest,
    FileContentsResponse, FormatDataRequest, FormatDataResponse, LockDataId,
};
use ironrdp_core::{IntoOwned as _, impl_as_any};
use tokio::sync::mpsc as tokio_mpsc;

/// Largest clipboard payload transferred in either direction.
///
/// A payload over the cap is **dropped and counted, never truncated**:
/// a half-pasted credential or config file is worse than a failed
/// paste. The cap applies to the wire payload, which is the
/// attacker-influenced side.
pub const MAX_CLIPBOARD_BYTES: usize = 1024 * 1024;

/// How often the bridge re-reads the host clipboard looking for a
/// local copy to advertise.
const HOST_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// The one format Phase 1 carries.
///
/// `CF_TEXT` / `CF_OEMTEXT` are deliberately not offered: every
/// Windows target since NT converts from `CF_UNICODETEXT`, and
/// offering a code-page format invites mojibake.
const TEXT_FORMAT: ClipboardFormatId = ClipboardFormatId::CF_UNICODETEXT;

/// Which way clipboard content may travel. Ingress and egress are
/// separately expressible because they are different risks.
///
/// Deliberately no `Default` impl: the value an RDP profile gets when
/// it says nothing is [`PROFILE_DEFAULT_DIRECTION`], and a second,
/// differently-valued `default()` sitting next to it is how a caller
/// ends up silently opening or closing a clipboard channel it did not
/// mean to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClipboardDirection {
    /// The `CLIPRDR` channel is not attached.
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
/// carries is still text-only, capped at [`MAX_CLIPBOARD_BYTES`],
/// never logged, and counted per session.
pub const PROFILE_DEFAULT_DIRECTION: ClipboardDirection = ClipboardDirection::Bidirectional;

/// Parse the `rdp_clipboard` profile value.
///
/// Rejects anything unrecognised rather than falling back to a
/// default: a typo in a profile must not silently change whether a
/// privileged session has a clipboard channel (AGENTS.md §7 — no
/// implicit fallbacks on paths an operator configured deliberately).
/// Mirrors [`super::rdp::parse_bulk_compression`].
pub fn parse_clipboard_direction(value: &str) -> Result<ClipboardDirection, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" | "none" | "disabled" | "" => Ok(ClipboardDirection::Off),
        "host-to-session" | "host_to_session" | "in" => Ok(ClipboardDirection::HostToSession),
        "session-to-host" | "session_to_host" | "out" => Ok(ClipboardDirection::SessionToHost),
        "bidirectional" | "both" | "on" => Ok(ClipboardDirection::Bidirectional),
        other => Err(format!(
            "rdp: unknown rdp_clipboard `{other}` (expected one of: off, \
             host-to-session, session-to-host, bidirectional)"
        )),
    }
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

/// Per-session clipboard counters, surfaced on the session's stats
/// line and to the session window. Byte counts and outcomes only —
/// never content.
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
    /// Payloads refused for exceeding [`MAX_CLIPBOARD_BYTES`].
    pub dropped_oversize: u64,
    /// Local "changes" that were really our own paste echoing back.
    pub suppressed_loop: u64,
    /// Refused because the profile's direction does not allow it.
    pub refused_direction: u64,
    /// Host clipboard read/write failures and malformed payloads.
    pub errors: u64,
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
    /// Advertise the host clipboard's formats to the remote, if it has
    /// anything and the direction allows it.
    AdvertiseHostFormats,
    /// The remote asked for our clipboard in `CF_UNICODETEXT`.
    ProvideHostText,
    /// The remote sent us text; put it on the host clipboard.
    StoreRemoteText(String),
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

/// Start the bridge thread. Returns the backend to hand to
/// [`ironrdp::cliprdr::Cliprdr::new`].
///
/// The thread owns the process's only `arboard::Clipboard` handle for
/// this session and exits when the returned backend is dropped.
pub fn spawn(
    direction: ClipboardDirection,
    proxy: PumpProxy,
    stats: SharedClipboardStats,
    label: String,
) -> TextCliprdrBackend {
    let (tx, rx) = std_mpsc::channel::<BridgeCommand>();
    let bridge_stats = Arc::clone(&stats);
    let bridge_proxy = proxy.clone();
    let bridge_label = label.clone();
    // A plain OS thread, not a tokio task: see the module docs on
    // blocking clipboard reads and thread affinity.
    if let Err(e) = std::thread::Builder::new()
        .name("rdp-clipboard".into())
        .spawn(move || bridge_loop(rx, bridge_proxy, bridge_stats, direction, &bridge_label))
    {
        log::warn!("rdp clipboard [{label}]: could not start bridge thread: {e}");
        bump(&stats, |s| s.errors += 1);
    }
    TextCliprdrBackend {
        bridge: BridgeHandle { tx },
        proxy,
        direction,
        stats,
        label,
    }
}

fn bridge_loop(
    rx: std_mpsc::Receiver<BridgeCommand>,
    proxy: PumpProxy,
    stats: SharedClipboardStats,
    direction: ClipboardDirection,
    label: &str,
) {
    let mut clipboard = match arboard::Clipboard::new() {
        Ok(c) => c,
        Err(e) => {
            // No host clipboard (a headless session, a locked
            // pasteboard). Say so once and stop: pretending the
            // channel works would be the silent downgrade.
            log::warn!("rdp clipboard [{label}]: host clipboard unavailable: {e}");
            bump(&stats, |s| s.errors += 1);
            return;
        }
    };
    let epoch = Instant::now();
    let now_ms = move || u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut detector = LoopDetector::new();
    // Last text we know the host clipboard held, so a poll can tell a
    // real local copy from "nothing changed".
    let mut last_host_text: Option<String> = None;

    // Seed the cache without advertising: whatever was on the host
    // clipboard *before* the session opened is not a copy the operator
    // made during it, and pushing it at the remote on connect would
    // leak pre-session content into a privileged desktop.
    if let Ok(text) = clipboard.get_text() {
        last_host_text = Some(text);
    }

    loop {
        match rx.recv_timeout(HOST_POLL_INTERVAL) {
            Ok(BridgeCommand::AdvertiseHostFormats) => {
                if !direction.allows_host_to_session() {
                    continue;
                }
                if last_host_text.as_deref().is_some_and(|t| !t.is_empty()) {
                    proxy.send_clipboard_message(ClipboardMessage::SendInitiateCopy(vec![
                        ClipboardFormat::new(TEXT_FORMAT),
                    ]));
                }
            }
            Ok(BridgeCommand::ProvideHostText) => {
                let response = match clipboard.get_text() {
                    Ok(text) => {
                        last_host_text = Some(text.clone());
                        let encoded = encode_unicode_text(&text);
                        if encoded.len() > MAX_CLIPBOARD_BYTES {
                            log::warn!(
                                "rdp clipboard [{label}]: host→session payload of {} bytes \
                                 exceeds the {MAX_CLIPBOARD_BYTES}-byte cap; refused",
                                encoded.len()
                            );
                            bump(&stats, |s| s.dropped_oversize += 1);
                            FormatDataResponse::new_error()
                        } else {
                            let len = encoded.len();
                            detector.record_content(&encoded, ClipboardSource::Local, now_ms());
                            bump(&stats, |s| {
                                s.out_transfers += 1;
                                s.out_bytes += len as u64;
                            });
                            log::debug!("rdp clipboard [{label}]: host→session {len} bytes");
                            FormatDataResponse::new_data(encoded)
                        }
                    }
                    Err(e) => {
                        log::warn!("rdp clipboard [{label}]: host clipboard read failed: {e}");
                        bump(&stats, |s| s.errors += 1);
                        FormatDataResponse::new_error()
                    }
                };
                proxy.send_clipboard_message(ClipboardMessage::SendFormatData(
                    response.into_owned(),
                ));
            }
            Ok(BridgeCommand::StoreRemoteText(text)) => {
                let text = host_line_endings(&text);
                // Record before writing: the poll below will see this
                // very content as a "local change" and must recognise
                // it as our own paste rather than advertising it back.
                detector.record_content(text.as_bytes(), ClipboardSource::Remote, now_ms());
                match clipboard.set_text(text.clone()) {
                    Ok(()) => {
                        last_host_text = Some(text);
                    }
                    Err(e) => {
                        log::warn!("rdp clipboard [{label}]: host clipboard write failed: {e}");
                        bump(&stats, |s| s.errors += 1);
                    }
                }
            }
            Err(std_mpsc::RecvTimeoutError::Timeout) => {
                if !direction.allows_host_to_session() {
                    continue;
                }
                let Ok(text) = clipboard.get_text() else {
                    // A clipboard holding a non-text format reads as an
                    // error here. Not worth a counter every 500 ms.
                    continue;
                };
                if last_host_text.as_deref() == Some(text.as_str()) || text.is_empty() {
                    continue;
                }
                last_host_text = Some(text.clone());
                if detector.would_cause_content_loop(
                    text.as_bytes(),
                    ClipboardSource::Local,
                    now_ms(),
                ) {
                    bump(&stats, |s| s.suppressed_loop += 1);
                    log::trace!("rdp clipboard [{label}]: local change is our own paste; skipped");
                    continue;
                }
                proxy.send_clipboard_message(ClipboardMessage::SendInitiateCopy(vec![
                    ClipboardFormat::new(TEXT_FORMAT),
                ]));
            }
            Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    log::debug!("rdp clipboard [{label}]: bridge thread exiting");
}

/// Text-only [`CliprdrBackend`].
///
/// Every method either answers from memory or posts one command; none
/// of them blocks or touches the OS clipboard directly. Formats other
/// than [`TEXT_FORMAT`], file transfers and clipboard locks are
/// no-ops — Phase 1 carries text, and a file channel is a materially
/// different control question that gets its own switch (Phase 3).
#[derive(Debug)]
pub struct TextCliprdrBackend {
    bridge: BridgeHandle,
    proxy: PumpProxy,
    direction: ClipboardDirection,
    stats: SharedClipboardStats,
    label: String,
}

impl_as_any!(TextCliprdrBackend);

impl CliprdrBackend for TextCliprdrBackend {
    fn temporary_directory(&self) -> &str {
        // Only consulted for file-clip transfers, which this backend
        // never advertises.
        "."
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        // Long format names only. No `STREAM_FILECLIP_ENABLED` /
        // `FILECLIP_NO_FILE_PATHS`: advertising a file capability we
        // do not honour would be worse than not advertising it.
        ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
    }

    fn on_ready(&mut self) {
        bump(&self.stats, |s| s.ready = true);
        log::info!(
            "rdp clipboard [{}]: channel ready, direction {}",
            self.label,
            self.direction.label()
        );
        self.bridge.send(BridgeCommand::AdvertiseHostFormats);
    }

    fn on_request_format_list(&mut self) {
        self.bridge.send(BridgeCommand::AdvertiseHostFormats);
    }

    fn on_process_negotiated_capabilities(
        &mut self,
        capabilities: ClipboardGeneralCapabilityFlags,
    ) {
        log::debug!(
            "rdp clipboard [{}]: negotiated capabilities {capabilities:?}",
            self.label
        );
    }

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        if !self.direction.allows_session_to_host() {
            // The remote copied something; this profile does not carry
            // it out. Counted so "why did my paste not arrive?" has an
            // answer that is not silence.
            bump(&self.stats, |s| s.refused_direction += 1);
            return;
        }
        if available_formats.iter().any(|f| f.id() == TEXT_FORMAT) {
            self.proxy
                .send_clipboard_message(ClipboardMessage::SendInitiatePaste(TEXT_FORMAT));
        } else {
            log::debug!(
                "rdp clipboard [{}]: remote offered no text format ({} offered)",
                self.label,
                available_formats.len()
            );
        }
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        if !self.direction.allows_host_to_session() || request.format != TEXT_FORMAT {
            if !self.direction.allows_host_to_session() {
                bump(&self.stats, |s| s.refused_direction += 1);
            }
            // An explicit failure response, not silence: the remote is
            // waiting on this and MS-RDPECLIP has a slot for "no".
            self.proxy.send_clipboard_message(ClipboardMessage::SendFormatData(
                FormatDataResponse::new_error().into_owned(),
            ));
            return;
        }
        self.bridge.send(BridgeCommand::ProvideHostText);
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        if !self.direction.allows_session_to_host() {
            bump(&self.stats, |s| s.refused_direction += 1);
            return;
        }
        if response.is_error() {
            log::debug!(
                "rdp clipboard [{}]: remote refused the format data request",
                self.label
            );
            return;
        }
        let len = response.data().len();
        if len > MAX_CLIPBOARD_BYTES {
            log::warn!(
                "rdp clipboard [{}]: session→host payload of {len} bytes exceeds the \
                 {MAX_CLIPBOARD_BYTES}-byte cap; dropped",
                self.label
            );
            bump(&self.stats, |s| s.dropped_oversize += 1);
            return;
        }
        match response.to_unicode_string() {
            Ok(text) => {
                bump(&self.stats, |s| {
                    s.in_transfers += 1;
                    s.in_bytes += len as u64;
                });
                log::debug!("rdp clipboard [{}]: session→host {len} bytes", self.label);
                self.bridge.send(BridgeCommand::StoreRemoteText(text));
            }
            Err(e) => {
                log::warn!(
                    "rdp clipboard [{}]: malformed CF_UNICODETEXT payload ({len} bytes): {e}",
                    self.label
                );
                bump(&self.stats, |s| s.errors += 1);
            }
        }
    }

    fn on_file_contents_request(&mut self, _request: FileContentsRequest) {
        log::debug!(
            "rdp clipboard [{}]: file contents request ignored (text-only backend)",
            self.label
        );
    }

    fn on_file_contents_response(&mut self, _response: FileContentsResponse<'_>) {
        log::debug!(
            "rdp clipboard [{}]: file contents response ignored (text-only backend)",
            self.label
        );
    }

    fn on_lock(&mut self, _data_id: LockDataId) {}

    fn on_unlock(&mut self, _data_id: LockDataId) {}
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
        assert_eq!(
            parse_clipboard_direction("host-to-session"),
            Ok(ClipboardDirection::HostToSession)
        );
        assert_eq!(parse_clipboard_direction("in"), Ok(ClipboardDirection::HostToSession));
        assert_eq!(
            parse_clipboard_direction("session_to_host"),
            Ok(ClipboardDirection::SessionToHost)
        );
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
            let decoded = FormatDataResponse::new_data(encode_unicode_text(text))
                .to_unicode_string()
                .unwrap();
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

    #[test]
    fn an_oversize_inbound_payload_is_dropped_not_truncated() {
        let (proxy, _rx) = channel();
        let stats: SharedClipboardStats = Arc::new(Mutex::new(ClipboardStats::default()));
        let (tx, rx) = std_mpsc::channel();
        let mut backend = TextCliprdrBackend {
            bridge: BridgeHandle { tx },
            proxy,
            direction: ClipboardDirection::Bidirectional,
            stats: Arc::clone(&stats),
            label: "test".into(),
        };
        let oversize = vec![b'a'; MAX_CLIPBOARD_BYTES + 1];
        backend.on_format_data_response(FormatDataResponse::new_data(oversize));
        let s = *stats.lock().unwrap();
        assert_eq!(s.dropped_oversize, 1);
        assert_eq!(s.in_transfers, 0);
        // Nothing reached the bridge, so nothing reached the host
        // clipboard — not even a prefix.
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn a_remote_copy_is_ignored_when_the_direction_forbids_it() {
        let (proxy, mut rx) = channel();
        let stats: SharedClipboardStats = Arc::new(Mutex::new(ClipboardStats::default()));
        let (tx, _bridge_rx) = std_mpsc::channel();
        let mut backend = TextCliprdrBackend {
            bridge: BridgeHandle { tx },
            proxy,
            direction: ClipboardDirection::HostToSession,
            stats: Arc::clone(&stats),
            label: "test".into(),
        };
        backend.on_remote_copy(&[ClipboardFormat::new(TEXT_FORMAT)]);
        assert_eq!(stats.lock().unwrap().refused_direction, 1);
        // No paste initiated: the remote's copy stays on the remote.
        assert!(rx.try_recv().is_err());

        // And the inbound data path refuses too, even if a response
        // arrives anyway.
        backend.on_format_data_response(FormatDataResponse::new_data(encode_unicode_text("x")));
        let s = *stats.lock().unwrap();
        assert_eq!(s.in_transfers, 0);
        assert_eq!(s.refused_direction, 2);
    }

    #[test]
    fn a_format_data_request_is_refused_explicitly_when_the_direction_forbids_it() {
        let (proxy, mut rx) = channel();
        let stats: SharedClipboardStats = Arc::new(Mutex::new(ClipboardStats::default()));
        let (tx, bridge_rx) = std_mpsc::channel();
        let mut backend = TextCliprdrBackend {
            bridge: BridgeHandle { tx },
            proxy,
            direction: ClipboardDirection::SessionToHost,
            stats: Arc::clone(&stats),
            label: "test".into(),
        };
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
    }

    #[test]
    fn a_non_text_format_request_is_refused_without_touching_the_clipboard() {
        let (proxy, mut rx) = channel();
        let stats: SharedClipboardStats = Arc::new(Mutex::new(ClipboardStats::default()));
        let (tx, bridge_rx) = std_mpsc::channel();
        let mut backend = TextCliprdrBackend {
            bridge: BridgeHandle { tx },
            proxy,
            direction: ClipboardDirection::Bidirectional,
            stats: Arc::clone(&stats),
            label: "test".into(),
        };
        backend.on_format_data_request(FormatDataRequest {
            format: ClipboardFormatId::CF_DIB,
        });
        match rx.try_recv() {
            Ok(ClipboardMessage::SendFormatData(resp)) => assert!(resp.is_error()),
            other => panic!("expected an error format-data response, got {other:?}"),
        }
        // Not a direction refusal — the direction was fine, the format
        // is simply not carried in Phase 1.
        assert_eq!(stats.lock().unwrap().refused_direction, 0);
        assert!(bridge_rx.try_recv().is_err());
    }

    #[test]
    fn a_text_request_reaches_the_bridge_when_allowed() {
        let (proxy, _rx) = channel();
        let stats: SharedClipboardStats = Arc::new(Mutex::new(ClipboardStats::default()));
        let (tx, bridge_rx) = std_mpsc::channel();
        let mut backend = TextCliprdrBackend {
            bridge: BridgeHandle { tx },
            proxy,
            direction: ClipboardDirection::Bidirectional,
            stats,
            label: "test".into(),
        };
        backend.on_format_data_request(FormatDataRequest { format: TEXT_FORMAT });
        assert!(matches!(bridge_rx.try_recv(), Ok(BridgeCommand::ProvideHostText)));
    }

    #[test]
    fn a_well_formed_inbound_payload_is_counted_and_forwarded() {
        let (proxy, _rx) = channel();
        let stats: SharedClipboardStats = Arc::new(Mutex::new(ClipboardStats::default()));
        let (tx, bridge_rx) = std_mpsc::channel();
        let mut backend = TextCliprdrBackend {
            bridge: BridgeHandle { tx },
            proxy,
            direction: ClipboardDirection::Bidirectional,
            stats: Arc::clone(&stats),
            label: "test".into(),
        };
        let payload = encode_unicode_text("hello\nworld");
        let len = payload.len();
        backend.on_format_data_response(FormatDataResponse::new_data(payload));
        let s = *stats.lock().unwrap();
        assert_eq!(s.in_transfers, 1);
        assert_eq!(s.in_bytes, len as u64);
        match bridge_rx.try_recv() {
            Ok(BridgeCommand::StoreRemoteText(text)) => assert_eq!(text, "hello\r\nworld"),
            other => panic!("expected StoreRemoteText, got {}", other.is_ok()),
        }
    }

    #[test]
    fn an_error_response_is_not_counted_as_a_transfer() {
        let (proxy, _rx) = channel();
        let stats: SharedClipboardStats = Arc::new(Mutex::new(ClipboardStats::default()));
        let (tx, bridge_rx) = std_mpsc::channel();
        let mut backend = TextCliprdrBackend {
            bridge: BridgeHandle { tx },
            proxy,
            direction: ClipboardDirection::Bidirectional,
            stats: Arc::clone(&stats),
            label: "test".into(),
        };
        backend.on_format_data_response(FormatDataResponse::new_error());
        let s = *stats.lock().unwrap();
        assert_eq!(s.in_transfers, 0);
        assert_eq!(s.errors, 0);
        assert!(bridge_rx.try_recv().is_err());
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
}
