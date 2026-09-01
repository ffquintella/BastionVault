//! RDP session driver — Phase 4 implementation.
//!
//! Drives `ironrdp` over a tokio TCP+TLS framed stream. The
//! `IronRDP/` git submodule on its `fix-deps` branch carries the
//! picky-rc.23 + sspi-main patches needed for `crypto-common 0.2.1`
//! to resolve cleanly alongside the host crate's `digest 0.11`
//! stack. See `IronRDP/Cargo.toml` for the patched workspace
//! deps and `gui/src-tauri/Cargo.toml` for the git pin.
//!
//! Pump shape (mirrors `session::ssh`):
//!   - tokio task drives the active-stage loop: read PDU →
//!     `ActiveStage::process(...)` → accumulate damage → flush a
//!     packed binary frame down the session's IPC channel at most
//!     once per [`FRAME_INTERVAL`], send response frames back to
//!     the server.
//!   - input control flows from the SessionRdpWindow via
//!     `session_input_rdp_*` Tauri commands → mpsc → fast-path
//!     input PDUs sent through the same framed stream.
//!
//! Frame transport: a [`tauri::ipc::Channel`] carrying
//! [`InvokeResponseBody::Raw`], installed by the window itself via
//! `session_attach_rdp_frames` once its canvas is mounted. Tauri
//! routes a raw body over the `ipc://` custom protocol as a real
//! binary response, so the pixels never become a JavaScript string.
//! This replaced a per-PDU `app.emit` of base64-in-JSON, which had
//! the webview parsing (and the Rust side formatting) a ~3 MB
//! string literal for every full-desktop repaint.
//!
//! Phase 4 limitations (each deferred to a follow-up phase):
//!   - **No CredSSP / NLA**: connects in standard RDP-Security
//!     mode. Modern Windows servers refuse this by default;
//!     operators with NLA-enforcing servers see an explicit error
//!     pointing at the sspi/picky integration follow-up.
//!   - **No EGFX / Graphics Pipeline**: server-side H.264 and
//!     RFX Progressive are not negotiated, so the server falls back
//!     to RemoteFX (advertised by default) or interleaved bitmap
//!     updates. See `roadmaps/rdp-performance.md`.
//!   - **Fast-path keyboard scancode mapping is conservative**:
//!     the JS-side `KeyboardEvent.code` → PS/2 set 1 scancode
//!     table covers the printable ASCII set + the common
//!     modifiers; full international + media-key support is a
//!     follow-up.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ironrdp::connector::connection_activation::ConnectionActivationState;
use ironrdp::connector::{
    ClientConnector, Config as ConnectorConfig, ConnectionResult, Credentials, DesktopSize, SmartCardIdentity,
};
use ironrdp::displaycontrol::client::DisplayControlClient;
use ironrdp::displaycontrol::pdu::MonitorLayoutEntry;
use ironrdp::dvc::DrdynvcClient;
use ironrdp::pdu::gcc::{ConnectionType, KeyboardType};
use ironrdp::pdu::geometry::InclusiveRectangle;
use ironrdp::pdu::input::fast_path::{FastPathInput, FastPathInputEvent, KeyboardFlags};
use ironrdp::pdu::input::mouse::{MousePdu, PointerFlags};
use ironrdp::pdu::nego::NegoRequestData;
use ironrdp::pdu::rdp::capability_sets::{MajorPlatformType, RailSupportLevel};
use ironrdp::pdu::rdp::client_info::{CompressionType, PerformanceFlags, TimezoneInfo};
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use ironrdp_async::{single_sequence_step_read, FramedWrite, NetworkClient};
use ironrdp_core::{encode_buf, WriteBuf};
use ironrdp_tokio::TokioFramed;
use serde::Serialize;
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{AppHandle, Emitter};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::{RdpSessionState, SessionCleanup, SessionState};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Floor on the spacing between frame flushes. A server repainting
/// a busy screen emits a burst of small fast-path update PDUs; the
/// pump used to turn each one into its own IPC round trip. We now
/// accumulate damage and flush at most this often, which collapses
/// a burst into a single message without adding perceptible latency
/// (16 ms ≈ 60 Hz, below the point where a human notices).
const FRAME_INTERVAL: Duration = Duration::from_millis(16);

/// How many disjoint damage rectangles we carry before collapsing
/// them. A single bounding box over scattered updates degenerates
/// to the whole desktop (cursor top-left, clock bottom-right), so a
/// short list beats one union; but the per-rect header and the
/// row-by-row pack both cost, so the list has to stay short.
const MAX_DIRTY_RECTS: usize = 8;

/// Cadence of the per-session throughput log line. Only emitted
/// when something actually moved in the window.
const STATS_INTERVAL: Duration = Duration::from_secs(10);

/// Frame wire-format version, byte 0 of every frame message. Bump
/// on any layout change so a stale webview fails loudly instead of
/// painting garbage.
const FRAME_WIRE_VERSION: u8 = 1;

/// Frame header flag: this message repaints the whole desktop and
/// the frontend may discard anything it had.
const FRAME_FLAG_FULL: u8 = 0x01;

/// Bytes of frame header before the rect table.
const FRAME_HEADER_LEN: usize = 8;

/// Bytes per entry in the frame rect table.
const FRAME_RECT_LEN: usize = 8;

/// Bulk compression (MS-RDPBCGR 3.1.8) advertised in the Client Info
/// PDU by default.
///
/// MPPC with a 64K history buffer: universally supported by Windows
/// (it is the RDP 5.0 baseline), eight times the history of the
/// 8K variant, and the decompressor `ironrdp-bulk` has the most
/// coverage for. `Rdp6`/`Rdp61` (NCRUSH / XCRUSH) compress harder
/// but are far more intricate on the decode side; they can be
/// selected per profile if a link ever justifies the risk.
///
/// This is a negotiated capability, not a unilateral one — the
/// server echoes what it will actually use, and `ActiveStage`
/// builds a decompressor only for what came back. Set the profile
/// key `rdp_bulk_compression` to `off` to advertise none.
pub const DEFAULT_BULK_COMPRESSION: Option<CompressionType> = Some(CompressionType::K64);

/// Whether the pinned `ironrdp-connector` can advertise the Graphics
/// Pipeline in the Client Core Data.
///
/// A Windows server only opens the
/// `Microsoft::Windows::RDS::Graphics` DVC when the client sets
/// `RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL` (0x0100) in the early
/// capability flags. Registering the EGFX channel is necessary but
/// not sufficient without it.
///
/// As of the IronRDP 0.17 pin the connector exposes this as
/// `Config::support_dyn_vc_gfx_protocol`, so the path is live and
/// this constant is `true`.
///
/// The flag is *not* set from the profile's `enable_egfx` directly.
/// [`build_connector_config`] leaves it `false` and the single branch
/// that registers the graphics DVC turns it on, so advertising the
/// capability and having an H.264 decoder are the same decision.
/// Advertising without a decoder is worse than not advertising: the
/// server may drop Bitmap Updates for a pipeline we cannot decode.
///
/// Kept as a constant rather than deleted so the warning below it
/// stays a single source of truth: if a future pin ever loses the
/// connector option again, flip this to `false` and the `rdp_egfx`
/// path says out loud that it cannot work instead of silently doing
/// nothing. See `roadmaps/rdp-performance.md`.
///
/// Only read on the `rdp_egfx` path, so a default build sees it as
/// dead.
#[cfg_attr(not(feature = "rdp_egfx"), allow(dead_code))]
const EGFX_EARLY_CAPABILITY_AVAILABLE: bool = true;

/// Parse the `rdp_bulk_compression` profile value.
///
/// Rejects anything unrecognised rather than falling back to the
/// default: a typo in a profile must not silently change the wire
/// behaviour of a session (AGENTS.md §7 — no implicit fallbacks on
/// paths an operator configured deliberately).
pub fn parse_bulk_compression(value: &str) -> Result<Option<CompressionType>, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" | "none" | "" => Ok(None),
        "default" => Ok(DEFAULT_BULK_COMPRESSION),
        "mppc8k" | "k8" => Ok(Some(CompressionType::K8)),
        "mppc64k" | "k64" => Ok(Some(CompressionType::K64)),
        "rdp6" => Ok(Some(CompressionType::Rdp6)),
        "rdp61" | "rdp6.1" => Ok(Some(CompressionType::Rdp61)),
        other => Err(format!(
            "rdp: unknown rdp_bulk_compression `{other}` \
             (expected one of: off, default, mppc8k, mppc64k, rdp6, rdp61)"
        )),
    }
}

pub struct RdpOpenArgs {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub credential: RdpCredential,
    pub domain: Option<String>,
    pub label: String,
    /// Mirror of `SshOpenArgs::on_close` — runs when the session
    /// closes. Only LDAP library check-in uses it today.
    pub on_close: Option<SessionCleanup>,
    /// Opt-in aggressive perf-flag set (disable wallpaper / theming /
    /// cursor shadow / cursor settings on top of the ironrdp default).
    /// `false` keeps the visual fidelity defaults; `true` trades a
    /// blander desktop for less repaint bandwidth.
    pub aggressive_performance: bool,
    /// Optional X.224 ticket cookie — the bare `tkt_<32 hex>` value,
    /// with no `mstshash=` prefix. Set when the session is being routed
    /// through a Rustion bastion: the bastion looks the ticket up at
    /// the X.224 stage and skips local auth + client-side CredSSP.
    /// When `None`, ironrdp's default (a cookie with the username) is
    /// used. Phase 7.4 of the Rustion integration.
    ///
    /// This goes in the **cookie** slot (`Cookie: mstshash=`), not the
    /// routing-token slot (`Cookie: msts=`). MS-RDPBCGR allows either
    /// in the Connection Request and Rustion's
    /// `extract_username_from_cookie` parses only the former, so a
    /// `msts=` token is silently invisible to it — see
    /// [`super::rdp::describe_finalize_error`].
    pub ticket_cookie: Option<String>,
    /// Opt in to the Graphics Pipeline (MS-RDPEGFX) for this
    /// session. Only has an effect in a build with the `rdp_egfx`
    /// feature and a loadable OpenH264 library; see
    /// [`build_h264_decoder`].
    ///
    /// Kept in the struct unconditionally rather than behind the
    /// feature so the callers in `commands::connect` do not need
    /// their own `#[cfg]`; a build without `rdp_egfx` therefore
    /// carries a field nothing reads.
    #[cfg_attr(not(feature = "rdp_egfx"), allow(dead_code))]
    pub enable_egfx: bool,
    /// Bulk compression to advertise in the Client Info PDU, or
    /// `None` to advertise none. Defaults to
    /// [`DEFAULT_BULK_COMPRESSION`]; the profile key
    /// `rdp_bulk_compression` overrides it.
    pub bulk_compression: Option<CompressionType>,
    /// Optional pinned SHA-256 of the server's TLS leaf certificate
    /// (`sha256:<hex>`). Set when dialling a Rustion bastion whose TLS
    /// fingerprint was discovered via `GET /v1/listeners`. The RDP TLS
    /// layer does **not** verify the cert against any CA (it's a
    /// self-signed leaf with no chain), so when this is `Some` the pin
    /// is the *only* authentication of the peer's TLS identity: a
    /// mismatch aborts the connect (fail-closed). `None` keeps the
    /// prior unpinned behaviour (direct dials, or a bastion that
    /// advertised no fingerprint).
    pub tls_pin_sha256: Option<String>,
}

/// What kind of credential the operator picked for this session.
/// Phase 4 ships `Password` (RDP Standard Security or NLA with
/// password). The CredSSP smartcard wiring (Phase 6) adds
/// `SmartCard`, which feeds a synthetic PIV credential built from
/// a vault-issued PKI cert + PKCS#8 private key.
#[derive(Clone)]
pub enum RdpCredential {
    Password(Zeroizing<String>),
    SmartCard(SmartCardCredential),
}

#[derive(Clone)]
pub struct SmartCardCredential {
    /// DER-encoded X509 cert (PEM-decoded body).
    pub certificate_der: Vec<u8>,
    /// DER-encoded PKCS#8 private key (PEM-decoded body).
    pub private_key_der: Vec<u8>,
    /// Synthetic PIN. The PIV emulator inside sspi-rs accepts any
    /// non-empty PIN since there's no hardware to enforce it; we
    /// pass a fixed value for log clarity.
    pub pin: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct RdpOpenOutcome {
    pub token: String,
    pub closed_event: String,
    /// Per-session event name the frontend listens on to learn the
    /// new desktop dimensions after a DisplayControl-driven resize
    /// completes its deactivation-reactivation sequence.
    pub resize_event: String,
    /// Initial desktop size advertised to the server. The frontend
    /// sizes its canvas to match.
    pub width: u16,
    pub height: u16,
}

pub fn new_token() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes[..]);
    let mut hex = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{b:02x}");
    }
    format!("rdp_{hex}")
}

pub fn closed_event_name(token: &str) -> String {
    format!("session-closed-{token}")
}

pub fn resize_event_name(token: &str) -> String {
    format!("session-resize-{token}")
}

#[derive(Debug, Clone)]
pub enum RdpControl {
    /// Pointer movement in canvas-relative coords.
    PointerMove { x: u16, y: u16 },
    /// Mouse-button press/release. `button_index` is the JS
    /// `MouseEvent.button` value: 0=left, 1=middle, 2=right.
    PointerButton { button_index: u8, pressed: bool, x: u16, y: u16 },
    /// Keyboard key down/up. `js_code` is the JS
    /// `KeyboardEvent.code` string (e.g. `"KeyA"`, `"Enter"`).
    Key { js_code: String, pressed: bool },
    /// Window resize from the local canvas. Forwarded to the server
    /// over the DisplayControl DVC; the server replies with a
    /// DeactivateAll → reactivation sequence that completes with the
    /// new desktop size, which is then emitted on
    /// [`resize_event_name`].
    Resize { width: u16, height: u16 },
    /// The session window attached (or re-attached) its frame
    /// channel and needs a full-desktop paint. Sent by
    /// `session_attach_rdp_frames`, not by any input event.
    Repaint,
    /// Operator clicked Disconnect or x'd the window.
    Close,
}

/// Where packed canvas frames go once the session window has
/// mounted and handed us its IPC channel.
///
/// The pump starts inside `open_rdp_session`, before the
/// `WebviewWindow` exists, so for the first few hundred ms there is
/// nowhere to send frames. Rather than buffer them we keep painting
/// into the `DecodedImage` and leave [`Self::needs_full`] set, so
/// the first flush after the window attaches carries the whole
/// desktop. The same mechanism covers a window reload and the
/// repaint after a DisplayControl resize.
pub struct FrameSink {
    channel: Option<Channel<InvokeResponseBody>>,
    needs_full: bool,
}

impl FrameSink {
    fn new() -> Self {
        Self { channel: None, needs_full: true }
    }

    /// Install the window's channel, replacing any predecessor (a
    /// reloaded window creates a fresh one) and arming a full
    /// repaint so the new canvas starts from a complete frame.
    pub fn attach(&mut self, channel: Channel<InvokeResponseBody>) {
        self.channel = Some(channel);
        self.needs_full = true;
    }
}

/// Accumulated damage between two flushes.
///
/// Rects are stored clamped to the desktop and deduplicated by
/// containment, which is what actually happens on a real session:
/// a caret, a spinner or a hovered button repaints the same few
/// pixels over and over between flushes.
#[derive(Default)]
struct Dirty {
    rects: Vec<InclusiveRectangle>,
    /// The whole desktop is dirty. Set on (re)activation, on
    /// attach, and when the rect list collapses to something that
    /// covers most of the screen anyway.
    full: bool,
}

impl Dirty {
    fn is_empty(&self) -> bool {
        !self.full && self.rects.is_empty()
    }

    fn clear(&mut self) {
        self.rects.clear();
        self.full = false;
    }

    fn mark_full(&mut self) {
        self.rects.clear();
        self.full = true;
    }

    /// Record one damaged region, keeping the list short.
    ///
    /// Clamps to the desktop first — some servers report rects
    /// outside the negotiated `DesktopSize` for cursor sprites, and
    /// an unclamped rect would read past the framebuffer in
    /// [`pack_subrect`].
    fn add(&mut self, rect: InclusiveRectangle, width: u16, height: u16) {
        if self.full || width == 0 || height == 0 {
            return;
        }
        let (max_x, max_y) = (width - 1, height - 1);
        if rect.left > max_x || rect.top > max_y {
            return;
        }
        let rect = InclusiveRectangle {
            left: rect.left,
            top: rect.top,
            right: rect.right.min(max_x),
            bottom: rect.bottom.min(max_y),
        };
        if rect.right < rect.left || rect.bottom < rect.top {
            return;
        }
        if self.rects.iter().any(|held| contains(held, &rect)) {
            return;
        }
        self.rects.retain(|held| !contains(&rect, held));
        self.rects.push(rect);
        if self.rects.len() <= MAX_DIRTY_RECTS {
            return;
        }
        // Over budget: collapse to the bounding union. If that union
        // covers most of the desktop there is nothing left to save by
        // tracking it as a rect, so promote to a full repaint and
        // stop doing the bookkeeping.
        let union = self.rects.iter().skip(1).fold(self.rects[0].clone(), |acc, r| InclusiveRectangle {
            left: acc.left.min(r.left),
            top: acc.top.min(r.top),
            right: acc.right.max(r.right),
            bottom: acc.bottom.max(r.bottom),
        });
        let union_area = u64::from(union.right - union.left + 1) * u64::from(union.bottom - union.top + 1);
        let desktop_area = u64::from(width) * u64::from(height);
        if union_area * 10 >= desktop_area * 9 {
            self.mark_full();
        } else {
            self.rects.clear();
            self.rects.push(union);
        }
    }
}

/// Inclusive-rectangle containment: does `outer` cover all of `inner`?
fn contains(outer: &InclusiveRectangle, inner: &InclusiveRectangle) -> bool {
    outer.left <= inner.left
        && outer.top <= inner.top
        && outer.right >= inner.right
        && outer.bottom >= inner.bottom
}

/// Per-session throughput counters.
///
/// These exist to answer one question that is otherwise invisible:
/// *is the server actually using a bitmap codec?* We advertise
/// RemoteFX (ironrdp's `client_codecs_capabilities` default), but
/// whether the server picks it depends on its own configuration,
/// and nothing on the wire tells the operator either way.
/// [`Self::log_delta`] prints the ratio that does.
#[derive(Default, Clone)]
struct PumpStats {
    /// Server PDUs read.
    pdus: u64,
    /// Bytes of PDU payload read from the server.
    wire_bytes_in: u64,
    /// `GraphicsUpdate` outputs seen, before coalescing.
    graphics_updates: u64,
    /// RGBA bytes those updates covered, before coalescing. The
    /// honest denominator for the compression ratio.
    graphics_pixel_bytes: u64,
    /// Frame messages actually pushed down the IPC channel.
    frames_sent: u64,
    /// Rects across those messages.
    rects_sent: u64,
    /// RGBA bytes across those messages.
    pixel_bytes_sent: u64,
    /// Flushes discarded because no window was attached.
    frames_dropped_no_sink: u64,
    /// `Channel::send` failures (webview gone, usually).
    send_errors: u64,
}

impl PumpStats {
    /// Log the delta since `prev` and re-baseline it.
    ///
    /// `codec` is the interesting field. It is server wire bytes
    /// divided by the RGBA bytes those updates painted, so it
    /// measures how well whatever the server chose is compressing:
    ///
    ///   - **~1.0 or higher** — essentially raw bitmaps. No bitmap
    ///     codec is in use. Confirm with
    ///     `RUST_LOG=ironrdp_connector=debug`, which logs the
    ///     server's `ServerDemandActive` PDU including its
    ///     `BitmapCodecs` capability set: that is the authoritative
    ///     record of what was negotiated.
    ///   - **~0.05–0.20** — RemoteFX or bulk compression is working.
    ///
    /// `saved` is what the coalescing in [`Dirty`] bought: the share
    /// of painted pixels we did *not* forward to the webview because
    /// a later update superseded them inside the same flush window.
    fn log_delta(&self, prev: &mut Self, label: &str, secs: f64) {
        let pdus = self.pdus - prev.pdus;
        if pdus == 0 {
            return;
        }
        let wire_in = self.wire_bytes_in - prev.wire_bytes_in;
        let updates = self.graphics_updates - prev.graphics_updates;
        let painted = self.graphics_pixel_bytes - prev.graphics_pixel_bytes;
        let frames = self.frames_sent - prev.frames_sent;
        let rects = self.rects_sent - prev.rects_sent;
        let sent = self.pixel_bytes_sent - prev.pixel_bytes_sent;
        let codec = if painted > 0 { wire_in as f64 / painted as f64 } else { f64::NAN };
        let saved = if painted > 0 { 1.0 - (sent as f64 / painted as f64) } else { 0.0 };
        log::info!(
            "resource-connect/rdp: {label} {secs:.0}s — in {in_kib:.0} KiB ({pdus} pdus), \
             painted {painted_kib:.0} KiB in {updates} updates (codec {codec:.3}), \
             sent {frames} frames / {rects} rects / {sent_kib:.0} KiB (coalesced away {saved:.0}%), \
             {fps:.1} fps",
            in_kib = wire_in as f64 / 1024.0,
            painted_kib = painted as f64 / 1024.0,
            sent_kib = sent as f64 / 1024.0,
            saved = saved * 100.0,
            fps = frames as f64 / secs.max(0.001),
        );
        if self.frames_dropped_no_sink != prev.frames_dropped_no_sink || self.send_errors != prev.send_errors {
            log::debug!(
                "resource-connect/rdp: {label} dropped {} flush(es) with no window attached, {} send error(s)",
                self.frames_dropped_no_sink - prev.frames_dropped_no_sink,
                self.send_errors - prev.send_errors,
            );
        }
        *prev = self.clone();
    }

    /// One closing line covering the whole session.
    ///
    /// Deliberately not a `log_delta` against a zeroed baseline: that
    /// would divide the session's totals by whatever interval was
    /// passed, and reporting a session's frame rate over a made-up
    /// window is worse than not reporting one.
    fn log_session_total(&self, label: &str, started: tokio::time::Instant) {
        let secs = (tokio::time::Instant::now() - started).as_secs_f64();
        let codec = if self.graphics_pixel_bytes > 0 {
            self.wire_bytes_in as f64 / self.graphics_pixel_bytes as f64
        } else {
            f64::NAN
        };
        log::info!(
            "resource-connect/rdp: {label} closed after {secs:.0}s — {pdus} pdus, in {in_kib:.0} KiB, \
             painted {painted_kib:.0} KiB (codec {codec:.3}), sent {frames} frames / {sent_kib:.0} KiB, \
             {dropped} flush(es) with no window, {errs} send error(s)",
            pdus = self.pdus,
            in_kib = self.wire_bytes_in as f64 / 1024.0,
            painted_kib = self.graphics_pixel_bytes as f64 / 1024.0,
            frames = self.frames_sent,
            sent_kib = self.pixel_bytes_sent as f64 / 1024.0,
            dropped = self.frames_dropped_no_sink,
            errs = self.send_errors,
        );
    }
}

/// Resolve the Phase 4 transport. Connects via TCP, runs the
/// ironrdp connector handshake (no CredSSP — standard RDP
/// security; NLA support is a follow-up), starts the active-stage
/// pump task, and registers the session on `AppState`.
pub async fn open_rdp_session(
    app: AppHandle,
    state: &crate::state::AppState,
    args: RdpOpenArgs,
) -> Result<RdpOpenOutcome, String> {
    let token = new_token();
    let closed_event = closed_event_name(&token);
    let resize_event = resize_event_name(&token);

    // Stage 1: resolve + TCP connect. We need a concrete `SocketAddr`
    // for the ironrdp connector (it stamps the local addr into the
    // PDU stream), so resolve here rather than letting `TcpStream`
    // do it implicitly.
    let host_port = format!("{}:{}", args.host, args.port);
    let target: SocketAddr = if let Ok(sa) = host_port.parse::<SocketAddr>() {
        sa
    } else {
        // Real async DNS — earlier code used `now_or_never()` which
        // returned `None` for every non-trivial lookup and surfaced
        // as a spurious "dns lookup returned no addresses".
        let resolved = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::lookup_host(host_port.clone()))
            .await
            .map_err(|_| format!("rdp: DNS lookup for {} timed out", args.host))?
            .map_err(|e| format!("rdp: parse/resolve {}: {e}", host_port))?;
        resolved.into_iter().next().ok_or_else(|| format!("rdp: DNS lookup for {} returned no addresses", args.host))?
    };
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target))
        .await
        .map_err(|_| format!("rdp: TCP connect to {target} timed out"))?
        .map_err(|e| format!("rdp: TCP connect {target}: {e}"))?;
    let local = tcp.local_addr().map_err(|e| format!("rdp: local_addr: {e}"))?;

    // Stage 2: ironrdp connector — phase one (pre-TLS).
    //
    // `mut` only so the EGFX branch below can turn
    // `support_dyn_vc_gfx_protocol` on once it knows the graphics
    // channel was really registered; nothing mutates it in a build
    // without the `rdp_egfx` feature.
    #[cfg_attr(not(feature = "rdp_egfx"), allow(unused_mut))]
    let mut cfg = build_connector_config(&args);
    let (width, height) = (cfg.desktop_size.width, cfg.desktop_size.height);
    let mut framed = TokioFramed::new(tcp);
    // Register the DisplayControl dynamic virtual channel so the
    // server advertises support during capability exchange. The
    // capability-set callback is invoked when the server announces
    // its supported monitor count / scaling — we don't need anything
    // from it today, so reply with an empty SVC message vector.
    let drdynvc = DrdynvcClient::new().with_dynamic_channel(DisplayControlClient::new(|_caps| Ok(Vec::new())));

    // Graphics Pipeline (MS-RDPEGFX). Registered only when the
    // `rdp_egfx` feature is compiled in AND an OpenH264 library was
    // loaded — see `build_h264_decoder` for why a decoder is a hard
    // requirement rather than an enhancement.
    //
    // NOTE: registering the DVC is necessary but not sufficient. A
    // Windows server only opens the graphics channel when the client
    // sets `RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL` (0x0100) in the
    // Client Core Data early-capability flags. As of the IronRDP 0.17
    // pin the connector can set it, and this is the only place that
    // asks it to — the flag and the channel are turned on by the same
    // branch, so the client can never advertise a pipeline it has no
    // decoder for. Tracked in `roadmaps/rdp-performance.md`.
    #[cfg(feature = "rdp_egfx")]
    let (drdynvc, egfx_rx) = match (args.enable_egfx, build_h264_decoder()) {
        (true, Some(decoder)) => {
            if EGFX_EARLY_CAPABILITY_AVAILABLE {
                cfg.support_dyn_vc_gfx_protocol = true;
            } else {
                log::warn!(
                    "rdp/egfx: the graphics channel is being advertised, but this build's ironrdp pin \
                     does not set RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL in the Client Core Data, so the \
                     server will never open it and the session will use the RemoteFX / bitmap path. \
                     See roadmaps/rdp-performance.md § Graphics Pipeline for the one-line connector \
                     change and how to switch this constant on."
                );
            }
            let (tx, rx) = mpsc::unbounded_channel();
            let client = ironrdp_egfx::client::GraphicsPipelineClient::new(Box::new(EgfxHandler::new(tx)), Some(decoder));
            (drdynvc.with_dynamic_channel(client), Some(rx))
        }
        _ => (drdynvc, None),
    };

    let mut connector = ClientConnector::new(cfg, local).with_static_channel(drdynvc);
    let should_upgrade = ironrdp_async::connect_begin(&mut framed, &mut connector)
        .await
        .map_err(|e| format!("rdp: connect_begin: {}", e.report()))?;

    // Stage 3: TLS upgrade. ironrdp-tls returns the server cert
    // as `x509_cert::Certificate`; extract the SubjectPublicKeyInfo
    // bytes for the connector's CredSSP / TLS-binding requirements.
    let initial = framed.into_inner_no_leftover();
    let (upgraded, server_cert) =
        ironrdp_tls::upgrade(initial, args.host.as_str()).await.map_err(|e| format!("rdp: TLS upgrade: {e}"))?;

    // Bastion TLS pinning. The RDP TLS handshake above trusts any cert
    // (self-signed leaf, no chain to a CA), so when a pin is supplied it
    // is the sole authentication of the peer's TLS identity. Verify the
    // leaf's DER SHA-256 against the pin discovered from the bastion's
    // `/v1/listeners`; a mismatch is fail-closed — abort before any
    // session bytes flow. Non-bastion (direct) dials pass `None` and
    // keep the prior behaviour.
    if let Some(pin) = args.tls_pin_sha256.as_deref() {
        verify_tls_pin(&server_cert, pin)?;
        log::info!("resource-connect/rdp: bastion TLS leaf cert matched pin {pin}");
    }

    let server_pubkey = ironrdp_tls::extract_tls_server_public_key(&server_cert)
        .ok_or_else(|| "rdp: server cert missing SubjectPublicKeyInfo".to_string())?
        .to_vec();
    let upgraded_marker = ironrdp_async::mark_as_upgraded(should_upgrade, &mut connector);
    let mut framed = TokioFramed::new(upgraded);

    // Stage 4: ironrdp connector — phase two. CredSSP is OFF in
    // build_connector_config so the network client is never invoked
    // (we still pass a stub to satisfy the trait bound).
    let mut net = CredSspNetworkClient::new();
    let connection_result = ironrdp_async::connect_finalize(
        upgraded_marker,
        connector,
        &mut framed,
        &mut net,
        args.host.as_str().into(),
        server_pubkey,
        None,
    )
    .await
    .map_err(|e| describe_finalize_error(&args, &e))?;

    // What the server actually agreed to. The bitmap codec is not
    // in `ConnectionResult` — ironrdp keeps the server's capability
    // sets internal — so the runtime counters in [`PumpStats`] and
    // `RUST_LOG=ironrdp_connector=debug` are how you find that out.
    log::info!(
        "resource-connect/rdp: negotiated desktop {}x{}, bulk compression {}, server pointer {}, \
         advertised bitmap codecs [remotefx] — set RUST_LOG=ironrdp_connector=debug to see the \
         server's own BitmapCodecs capability set",
        connection_result.desktop_size.width,
        connection_result.desktop_size.height,
        match connection_result.compression_type {
            Some(ct) => format!("{ct:?}"),
            None => "none".to_owned(),
        },
        connection_result.enable_server_pointer,
    );
    if args.bulk_compression.is_some() && connection_result.compression_type.is_none() {
        log::warn!(
            "resource-connect/rdp: advertised bulk compression {:?} but the server declined it; \
             graphics will be uncompressed at the bulk layer",
            args.bulk_compression
        );
    }

    // Stage 5: spawn the active-stage pump.
    let (tx, rx) = mpsc::channel::<RdpControl>(64);
    let frames = Arc::new(Mutex::new(FrameSink::new()));
    let app_for_task = app.clone();
    let closed_event_for_task = closed_event.clone();
    let resize_event_for_task = resize_event.clone();
    let frames_for_task = Arc::clone(&frames);
    let label_for_task = args.label.clone();
    #[cfg(not(feature = "rdp_egfx"))]
    let egfx_rx: Option<mpsc::UnboundedReceiver<EgfxEvent>> = None;
    tokio::spawn(active_stage_loop(
        app_for_task,
        framed,
        connection_result,
        rx,
        frames_for_task,
        closed_event_for_task,
        resize_event_for_task,
        width,
        height,
        label_for_task,
        egfx_rx,
    ));

    {
        let mut sessions = state.connect_sessions.lock().await;
        sessions.insert(
            token.clone(),
            SessionState::Rdp(RdpSessionState {
                input_tx: tx,
                frames,
                label: args.label.clone(),
                on_close: args.on_close.clone(),
            }),
        );
    }
    log::info!("resource-connect/rdp: opened session token={token} label={} ({}:{})", args.label, args.host, args.port);

    Ok(RdpOpenOutcome { token, closed_event, resize_event, width, height })
}

fn build_connector_config(args: &RdpOpenArgs) -> ConnectorConfig {
    // Smartcard auth requires CredSSP — there's no Standard
    // Security analogue. Password auth still uses Standard
    // Security so the Phase-4 flow against NLA-disabled hosts
    // keeps working unchanged.
    let (credentials, enable_credssp) = match &args.credential {
        RdpCredential::Password(pw) => {
            (Credentials::UsernamePassword { username: args.username.clone(), password: pw.as_str().to_owned() }, false)
        }
        RdpCredential::SmartCard(sc) => (
            Credentials::SmartCard {
                pin: sc.pin.clone(),
                config: Some(SmartCardIdentity {
                    certificate: sc.certificate_der.clone(),
                    // Synthetic reader / container / CSP names —
                    // the AD-side checks the cert itself, not the
                    // reader, so any plausible label works. We
                    // surface "BastionVault" so server-side audit
                    // logs name what minted the credential.
                    reader_name: "BastionVault Virtual SmartCard".to_owned(),
                    container_name: "bv-rdp".to_owned(),
                    csp_name: "Microsoft Base Smart Card Crypto Provider".to_owned(),
                    private_key: sc.private_key_der.clone(),
                }),
            },
            true,
        ),
    };
    ConnectorConfig {
        credentials,
        domain: args.domain.clone(),
        enable_tls: true,
        enable_credssp,
        keyboard_type: KeyboardType::IBM_ENHANCED,
        keyboard_subtype: 0,
        keyboard_layout: 0,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: DesktopSize { width: 1024, height: 600 },
        // Single logical monitor: `desktop_size` above already
        // describes it, and the DisplayControl resize path sends its
        // own monitor layout per activation.
        monitor_layout: None,
        // Standard RDP Security (`PROTOCOL_RDP`, no enhanced flags)
        // stays off. It only takes effect when both `enable_tls` and
        // `enable_credssp` are false; `enable_tls` is unconditionally
        // true above, so this is belt-and-braces. ironrdp only
        // implements the ENCRYPTION_LEVEL_NONE variant, which has no
        // business on a TCP session to a bastion-reached host.
        enable_standard_rdp_security: false,
        // LAN profile. The GUI's own transport is either a local
        // socket or a Rustion-brokered tunnel, and this only tunes
        // the server's bandwidth heuristics; `Autodetect` would let
        // the server run its own probe and pick worse defaults on a
        // brokered link that looks lossy.
        connection_type: ConnectionType::Lan,
        // No microphone redirection. `enable_audio_playback` is
        // already false below; capture is the one that would push
        // client-side audio *to* the server, so it stays off
        // explicitly rather than by omission.
        enable_audio_capture: false,
        // No RemoteApp/RAIL: this is a full-desktop session. The
        // support level must stay empty while the mode is off — the
        // connector requires SUPPORTED only when it is on.
        remote_application_mode: false,
        rail_support_level: RailSupportLevel::empty(),
        bitmap: None,
        client_build: 0,
        client_name: "BastionVault".to_owned(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        // Bulk compression (MS-RDPBCGR 3.1.8). Advertised, not
        // imposed: the server echoes what it will use in the
        // Demand Active exchange and `ActiveStage` builds a
        // decompressor only for that. See
        // [`DEFAULT_BULK_COMPRESSION`].
        compression_type: args.bulk_compression,
        multitransport_flags: None,
        #[cfg(target_os = "macos")]
        platform: MajorPlatformType::MACINTOSH,
        #[cfg(target_os = "linux")]
        platform: MajorPlatformType::UNIX,
        #[cfg(target_os = "windows")]
        platform: MajorPlatformType::WINDOWS,
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        platform: MajorPlatformType::UNIX,
        enable_server_pointer: false,
        // Phase 7.4: Rustion-routed sessions carry the ticket in the
        // X.224 cookie slot; the bastion consumes it at the Connection
        // Request stage and skips local auth. None on the direct path
        // keeps ironrdp's default behaviour (username cookie).
        //
        // `cookie`, not `routing_token`: the two write different
        // prefixes — `Cookie: mstshash=` vs `Cookie: msts=` — and
        // Rustion's gateway only scans for `mstshash=`. Sending the
        // ticket as a routing token made every bastion-routed RDP
        // session fail with `user=unknown, method=rdp-cookie,
        // reason=invalid username or password`, observable only in the
        // bastion's log because it drops the socket without an RDP
        // error PDU.
        request_data: args.ticket_cookie.as_ref().map(|t| NegoRequestData::cookie(t.clone())),
        autologon: false,
        enable_audio_playback: false,
        pointer_software_rendering: true,
        // Default off: ironrdp's default already disables full-
        // window-drag + menu animations and enables font smoothing.
        // Operators can opt in per-profile to *also* disable
        // wallpaper / theming / cursor shadow / cursor settings,
        // trading a blander desktop for less repaint bandwidth.
        performance_flags: if args.aggressive_performance {
            PerformanceFlags::DISABLE_WALLPAPER
                | PerformanceFlags::DISABLE_FULLWINDOWDRAG
                | PerformanceFlags::DISABLE_MENUANIMATIONS
                | PerformanceFlags::DISABLE_THEMING
                | PerformanceFlags::DISABLE_CURSOR_SHADOW
                | PerformanceFlags::DISABLE_CURSORSETTINGS
                | PerformanceFlags::ENABLE_FONT_SMOOTHING
        } else {
            PerformanceFlags::default()
        },
        // EGFX ACTIVATION SITE — the connector carries the flag as of
        // IronRDP 0.17. Deliberately `false` here and turned on by the
        // caller *only* in the branch that actually registers the
        // graphics channel, which additionally requires the
        // `rdp_egfx` feature and a loaded OpenH264 decoder.
        //
        // Advertising `RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL` from
        // `args.enable_egfx` alone would be a trap: a Windows server
        // that sees it may abandon Bitmap Updates and send H.264 we
        // cannot decode, which is a frozen desktop rather than a
        // degraded one. See `build_h264_decoder` and
        // [`EGFX_EARLY_CAPABILITY_AVAILABLE`].
        support_dyn_vc_gfx_protocol: false,
        desktop_scale_factor: 0,
        hardware_id: None,
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
    }
}

/// Async `NetworkClient` wrapper over sspi's blocking
/// `ReqwestNetworkClient`. CredSSP smartcard auth (Kerberos
/// PKINIT) suspends the connector to discover the realm's KDC
/// over the network; that's when this trait gets invoked. Each
/// call delegates to sspi's blocking client via
/// `tokio::task::spawn_blocking` so we don't park the runtime —
/// the network round-trip is short, but blocking on it from the
/// pump task would still freeze the spawned WebviewWindow.
struct CredSspNetworkClient {
    inner: sspi::network_client::reqwest_network_client::ReqwestNetworkClient,
}

impl CredSspNetworkClient {
    fn new() -> Self {
        Self { inner: sspi::network_client::reqwest_network_client::ReqwestNetworkClient }
    }
}

impl NetworkClient for CredSspNetworkClient {
    fn send(
        &mut self,
        request: &ironrdp::connector::sspi::generator::NetworkRequest,
    ) -> impl std::future::Future<Output = ironrdp::connector::ConnectorResult<Vec<u8>>> {
        // Clone the request so the task closure owns it; the
        // borrow lives only as long as `send`.
        let req = request.clone();
        let client = self.inner.clone();
        async move {
            let result = tokio::task::spawn_blocking(move || sspi::network_client::NetworkClient::send(&client, &req))
                .await
                .map_err(|e| {
                    let msg = format!("rdp: network task: {e}");
                    log::error!("{msg}");
                    ironrdp::connector::general_err!("rdp: network task")
                })?;
            result.map_err(|e| {
                let msg = format!("rdp: network: {e}");
                log::error!("{msg}");
                ironrdp::connector::general_err!("rdp: network")
            })
        }
    }
}

/// The active-stage pump.
///
/// One tokio task per session. Three things race in the `select!`:
/// operator input (highest priority — a keystroke must not wait
/// behind a screen repaint), the frame-flush deadline, and the next
/// server PDU. `Framed::read_pdu` documents itself as cancel safe,
/// which is what makes the flush timer legal here: dropping the
/// read future leaves any partial data in the `Framed` buffer.
#[allow(clippy::too_many_arguments)]
async fn active_stage_loop<S>(
    app: AppHandle,
    mut framed: TokioFramed<S>,
    connection_result: ConnectionResult,
    mut rx: mpsc::Receiver<RdpControl>,
    frames: Arc<Mutex<FrameSink>>,
    closed_event: String,
    resize_event: String,
    mut width: u16,
    mut height: u16,
    label: String,
    mut egfx_rx: Option<mpsc::UnboundedReceiver<EgfxEvent>>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    let mut image = DecodedImage::new(ironrdp::graphics::image_processing::PixelFormat::RgbA32, width, height);
    // Captured before the builder consumes the rest of the result:
    // the reactivation sequence is now minted from a factory the
    // connection result carries, rather than being handed to us
    // inside the `DeactivateAll` output.
    let activation_factory = connection_result.activation_factory;
    let mut active_stage = ActiveStageBuilder {
        static_channels: connection_result.static_channels,
        user_channel_id: connection_result.user_channel_id,
        io_channel_id: connection_result.io_channel_id,
        message_channel_id: connection_result.message_channel_id,
        share_id: connection_result.share_id,
        // ironrdp now owns the bulk decompressor and builds it from
        // this, keeping its history across a reactivation. That is
        // why this crate no longer depends on `ironrdp-bulk`: there
        // is nothing left for us to construct by hand.
        compression_type: connection_result.compression_type,
        enable_server_pointer: connection_result.enable_server_pointer,
        pointer_software_rendering: connection_result.pointer_software_rendering,
    }
    .build();

    // EGFX compositing target. Allocated regardless so
    // `current_surface` always has something to point at; it stays
    // inert — and the packer keeps reading the `DecodedImage` —
    // until the first Graphics Pipeline update actually composites
    // into it. See `apply_egfx_event`.
    let mut egfx_fb = EgfxFramebuffer::new(width, height);

    let mut dirty = Dirty::default();
    // Deadline for the next flush, armed the moment damage first
    // arrives and disarmed by the flush itself. `None` means "no
    // pending damage", so an idle session parks on `read_pdu` with
    // no timer churn at all.
    let mut flush_at: Option<tokio::time::Instant> = None;

    let mut stats = PumpStats::default();
    let mut stats_baseline = PumpStats::default();
    let session_start = tokio::time::Instant::now();
    // Actual wall time covered by the pending window, not the
    // nominal interval: the timer branch can be late when the pump
    // is busy, and a late tick would otherwise inflate the reported
    // frame rate.
    let mut stats_since = session_start;
    let mut stats_at = session_start + STATS_INTERVAL;

    loop {
        // Copied out so the `select!` branches below can reassign
        // `flush_at` without holding a borrow across the await.
        let deadline = flush_at;
        tokio::select! {
            biased;
            ctl = rx.recv() => {
                match ctl {
                    Some(RdpControl::Close) | None => break,
                    Some(RdpControl::Repaint) => {
                        // Window attached or reloaded. Paint everything,
                        // now rather than on the next server update —
                        // an idle desktop produces no PDUs and the
                        // canvas would stay blank.
                        dirty.mark_full();
                        flush_at = Some(tokio::time::Instant::now());
                    }
                    Some(RdpControl::Resize { width: rw, height: rh }) => {
                        // Clamp to the DisplayControl-permitted range
                        // before asking ironrdp to encode the monitor
                        // layout PDU. The server replies with a
                        // DeactivateAll, which the pdu-read branch
                        // below converts into a reactivation sequence
                        // + framebuffer resize.
                        let (cw, ch) = MonitorLayoutEntry::adjust_display_size(
                            u32::from(rw),
                            u32::from(rh),
                        );
                        match active_stage.encode_resize(cw, ch, None, None) {
                            Some(Ok(frame)) => {
                                if let Err(e) = framed.write_all(&frame).await {
                                    log::warn!("rdp: write resize pdu: {e:?}");
                                    break;
                                }
                            }
                            Some(Err(e)) => {
                                log::warn!("rdp: encode_resize: {e:?}");
                            }
                            None => {
                                // Server didn't advertise DisplayControl
                                // support, or the DVC isn't open yet.
                                // Drop silently — the canvas stays at
                                // the negotiated resolution and the
                                // frontend continues to letterbox it.
                                log::debug!(
                                    "rdp: resize {rw}x{rh} ignored (DisplayControl unavailable)"
                                );
                            }
                        }
                    }
                    Some(other) => {
                        if let Some(pdu) = control_to_fastpath(other) {
                            let mut buf = WriteBuf::new();
                            if let Err(e) = encode_buf(&pdu, &mut buf) {
                                log::warn!("rdp: encode fast-path input: {e:?}");
                                continue;
                            }
                            if let Err(e) = framed.write_all(buf.filled()).await {
                                log::warn!("rdp: write fast-path input: {e:?}");
                                break;
                            }
                        }
                    }
                }
            }
            () = async move {
                match deadline {
                    Some(at) => tokio::time::sleep_until(at).await,
                    // Unreachable — the branch is disabled when
                    // `deadline` is None — but `select!` still needs a
                    // future of the same type here.
                    None => std::future::pending().await,
                }
            }, if deadline.is_some() => {
                flush_frame(&frames, current_surface(&image, &egfx_fb), &mut dirty, width, height, &mut stats);
                flush_at = None;
            }
            _ = tokio::time::sleep_until(stats_at) => {
                let now = tokio::time::Instant::now();
                stats.log_delta(&mut stats_baseline, &label, (now - stats_since).as_secs_f64());
                stats_since = now;
                stats_at = now + STATS_INTERVAL;
            }
            pdu = framed.read_pdu() => {
                let (action, payload) = match pdu {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn!("rdp: read_pdu: {e:?}");
                        break;
                    }
                };
                stats.pdus += 1;
                stats.wire_bytes_in += payload.len() as u64;
                let outputs = match active_stage.process(&mut image, action, &payload) {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn!("rdp: active_stage.process: {e:?}");
                        break;
                    }
                };
                let mut response_frames: Vec<Vec<u8>> = Vec::new();
                let mut reactivation: Option<
                    Box<ironrdp::connector::connection_activation::ConnectionActivationSequence>,
                > = None;
                for out in outputs {
                    match out {
                        ActiveStageOutput::GraphicsUpdate(rect) => {
                            stats.graphics_updates += 1;
                            stats.graphics_pixel_bytes += rect_pixel_bytes(&rect, width, height);
                            dirty.add(rect, width, height);
                        }
                        ActiveStageOutput::ResponseFrame(frame) => response_frames.push(frame),
                        ActiveStageOutput::DeactivateAll => {
                            // The server replies with DeactivateAll
                            // after every successful resize request.
                            // The variant no longer carries the
                            // sequence, so mint one from the factory;
                            // after we've flushed any pending response
                            // frames we drive it to Finalized, swap in
                            // the new framebuffer and tell the frontend
                            // the new size.
                            reactivation = Some(Box::new(activation_factory.create()));
                        }
                        ActiveStageOutput::Terminate(_) => {
                            log::info!("rdp: server initiated disconnect");
                            for frame in response_frames {
                                let _ = framed.write_all(&frame).await;
                            }
                            let _ = app.emit(&closed_event, ());
                            stats.log_session_total(&label, session_start);
                            return;
                        }
                        _ => {}
                    }
                }
                for frame in response_frames {
                    if let Err(e) = framed.write_all(&frame).await {
                        log::warn!("rdp: write response frame: {e:?}");
                        break;
                    }
                }
                // Drive the deactivation-reactivation sequence to
                // completion *before* the next read_pdu() — the next
                // server PDU is the first capabilities-exchange step,
                // which `single_sequence_step_read` consumes on our
                // behalf. On completion we swap in the new
                // framebuffer + fastpath processor and tell the
                // frontend the new size; any damage accumulated in
                // this round targets the old framebuffer and is
                // replaced by a full repaint.
                if let Some(mut seq) = reactivation {
                    match run_reactivation(&mut framed, &mut active_stage, &mut seq).await {
                        Ok(new_size) => {
                            width = new_size.width;
                            height = new_size.height;
                            image = DecodedImage::new(
                                ironrdp::graphics::image_processing::PixelFormat::RgbA32,
                                width,
                                height,
                            );
                            egfx_fb.resize(width, height);
                            let _ = app.emit(
                                &resize_event,
                                ResizePayload { width, height },
                            );
                            // The frame header carries the desktop size
                            // too, so the canvas can resize itself off
                            // the next frame even if this event loses
                            // the race. Repaint in full: the new
                            // framebuffer is blank.
                            dirty.mark_full();
                            flush_at = Some(tokio::time::Instant::now());
                            log::info!(
                                "rdp: reactivated at {width}x{height} after DisplayControl resize"
                            );
                        }
                        Err(e) => {
                            log::warn!("rdp: reactivation failed: {e:?}");
                            break;
                        }
                    }
                    continue;
                }
                // Drain whatever the EGFX handler produced while
                // `process` was routing this PDU through the DVC.
                if let Some(rx) = egfx_rx.as_mut() {
                    while let Ok(event) = rx.try_recv() {
                        if let Some(size) = apply_egfx_event(event, &mut egfx_fb, &mut dirty, &mut width, &mut height) {
                            let _ = app.emit(&resize_event, size);
                        }
                    }
                }
                if !dirty.is_empty() && flush_at.is_none() {
                    flush_at = Some(tokio::time::Instant::now() + FRAME_INTERVAL);
                }
            }
        }
    }
    stats.log_session_total(&label, session_start);
    let _ = app.emit(&closed_event, ());
}

/// RGBA byte count a damage rect covers, clamped to the desktop.
/// Used only for the compression-ratio denominator in [`PumpStats`].
fn rect_pixel_bytes(rect: &InclusiveRectangle, width: u16, height: u16) -> u64 {
    if width == 0 || height == 0 || rect.left >= width || rect.top >= height {
        return 0;
    }
    let right = rect.right.min(width - 1);
    let bottom = rect.bottom.min(height - 1);
    if right < rect.left || bottom < rect.top {
        return 0;
    }
    u64::from(right - rect.left + 1) * u64::from(bottom - rect.top + 1) * 4
}

/// Pack the accumulated damage into one binary message and push it
/// down the session's IPC channel.
///
/// Wire format, little-endian, one message per flush:
///
/// ```text
///   0      u8    version (FRAME_WIRE_VERSION)
///   1      u8    flags   (bit 0: full-desktop repaint)
///   2..4   u16   rect count
///   4..6   u16   desktop width
///   6..8   u16   desktop height
///   8..    rect count × { u16 x, u16 y, u16 w, u16 h }
///   ...          row-packed RGBA for each rect, in rect order
/// ```
///
/// The desktop size travels in every frame on purpose. The `resize`
/// Tauri event and this channel are separate transports, so the
/// event can lose the race against the first post-reactivation
/// frame; a header the frontend can size its canvas from cannot.
///
/// All rects are packed from the same `DecodedImage` at the same
/// instant, so overlapping rects carry identical pixels and the
/// order they are applied in does not matter.
fn flush_frame(
    frames: &Mutex<FrameSink>,
    surface: SurfaceView<'_>,
    dirty: &mut Dirty,
    width: u16,
    height: u16,
    stats: &mut PumpStats,
) {
    // Poison here would mean a previous holder panicked while doing
    // nothing but a channel send; the guarded state is two plain
    // fields with no invariant to violate, so recovering beats
    // killing the session.
    let mut sink = match frames.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let Some(channel) = sink.channel.as_ref() else {
        // No window attached yet. Drop the damage rather than grow a
        // backlog — `needs_full` is still set, so whatever the
        // desktop looks like when the window does attach is painted
        // whole.
        stats.frames_dropped_no_sink += 1;
        dirty.clear();
        return;
    };

    let full = sink.needs_full || dirty.full;
    let full_rect = InclusiveRectangle { left: 0, top: 0, right: width.saturating_sub(1), bottom: height.saturating_sub(1) };
    let rects: &[InclusiveRectangle] = if full { std::slice::from_ref(&full_rect) } else { &dirty.rects };
    if rects.is_empty() || width == 0 || height == 0 {
        dirty.clear();
        return;
    }

    let pixel_bytes: usize =
        rects.iter().map(rect_dims).map(|(w, h)| usize::from(w) * usize::from(h) * 4).sum();
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + rects.len() * FRAME_RECT_LEN + pixel_bytes);
    out.push(FRAME_WIRE_VERSION);
    out.push(if full { FRAME_FLAG_FULL } else { 0 });
    // `rects` is at most MAX_DIRTY_RECTS + 1, so the u16 cast cannot
    // truncate.
    out.extend_from_slice(&(rects.len() as u16).to_le_bytes());
    out.extend_from_slice(&width.to_le_bytes());
    out.extend_from_slice(&height.to_le_bytes());
    for rect in rects {
        let (w, h) = rect_dims(rect);
        out.extend_from_slice(&rect.left.to_le_bytes());
        out.extend_from_slice(&rect.top.to_le_bytes());
        out.extend_from_slice(&w.to_le_bytes());
        out.extend_from_slice(&h.to_le_bytes());
    }
    for rect in rects {
        let (w, h) = rect_dims(rect);
        pack_subrect(surface, rect.left, rect.top, w, h, &mut out);
    }

    stats.frames_sent += 1;
    stats.rects_sent += rects.len() as u64;
    stats.pixel_bytes_sent += pixel_bytes as u64;

    if let Err(e) = channel.send(InvokeResponseBody::Raw(out)) {
        // The window went away between attach and now. Drop the
        // channel so subsequent flushes take the no-sink path
        // instead of erroring once per frame.
        stats.send_errors += 1;
        log::debug!("rdp: frame channel send failed ({e}); detaching sink");
        sink.channel = None;
        sink.needs_full = true;
        dirty.clear();
        return;
    }
    sink.needs_full = false;
    dirty.clear();
}

/// Inclusive rect → (width, height).
fn rect_dims(rect: &InclusiveRectangle) -> (u16, u16) {
    (rect.right - rect.left + 1, rect.bottom - rect.top + 1)
}

/// Drive the connection-activation state machine to `Finalized`
/// after a DeactivateAll, then return the new desktop size and
/// hand the renegotiated channel/pointer settings to
/// `ActiveStage::reactivate`. Mirrors the reference client's
/// reactivation handler in `ironrdp-client/src/rdp.rs`.
///
/// The bulk decompressor is no longer our problem. `reactivate`
/// rebuilds the fast-path processor internally from the
/// compression type the original connect negotiated, and *retains*
/// the decompression history rather than starting a fresh one —
/// the server signals any reset per update with `PACKET_FLUSHED` /
/// `PACKET_AT_FRONT`. Before IronRDP 0.17 this function had to
/// build a `BulkCompressor` by hand and pass it to
/// `set_fastpath_processor`, which is what the `ironrdp-bulk`
/// dependency existed for; both are gone.
///
/// `reactivate` also re-validates the server's negotiated static
/// virtual channel chunk size and returns `false` rather than
/// installing a processor built on a bad one.
async fn run_reactivation<S>(
    framed: &mut TokioFramed<S>,
    active_stage: &mut ActiveStage,
    seq: &mut ironrdp::connector::connection_activation::ConnectionActivationSequence,
) -> Result<DesktopSize, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    let mut buf = WriteBuf::new();
    loop {
        buf.clear();
        let written =
            single_sequence_step_read(framed, seq, &mut buf).await.map_err(|e| format!("reactivation step: {e:?}"))?;
        if written.size().is_some() {
            framed.write_all(buf.filled()).await.map_err(|e| format!("reactivation write: {e:?}"))?;
        }
        if let ConnectionActivationState::Finalized {
            desktop_size,
            share_id,
            enable_server_pointer,
            pointer_software_rendering,
            static_channel_chunk_size,
            window_support_level,
            ..
        } = seq.connection_activation_state()
        {
            // The channel ids come off the sequence now rather than
            // out of the `Finalized` payload, which no longer carries
            // them. `reactivate` rebuilds the fast-path processor,
            // re-applies the share id and the pointer setting, and
            // keeps the bulk decompression history.
            if !active_stage.reactivate(
                seq.io_channel_id(),
                seq.user_channel_id(),
                share_id,
                enable_server_pointer,
                pointer_software_rendering,
                static_channel_chunk_size,
            ) {
                // Refuse the resize rather than run on a processor
                // built from a chunk size the server mis-declared:
                // every subsequent static-channel PDU would be framed
                // wrongly. AGENTS.md §7 — fail explicitly.
                return Err(format!(
                    "reactivation: server negotiated an invalid static channel chunk size \
                     ({static_channel_chunk_size})"
                ));
            }
            // Renegotiated per activation, and not covered by
            // `reactivate`: a server may change Window List support
            // across a Deactivation-Reactivation.
            active_stage.set_window_support_level(window_support_level);
            return Ok(desktop_size);
        }
    }
}

// ============================================================================
// Graphics Pipeline (MS-RDPEGFX)
// ============================================================================

/// Compositing framebuffer for the Graphics Pipeline.
///
/// EGFX does not paint into ironrdp's `DecodedImage` — that type is
/// read-only from outside `ironrdp-session` — so surfaces decoded
/// from the graphics DVC are composited here instead, and
/// [`current_surface`] decides which of the two the frame packer
/// reads from.
struct EgfxFramebuffer {
    data: Vec<u8>,
    width: u16,
    height: u16,
    /// Set once the server has confirmed EGFX capabilities and this
    /// buffer, not the `DecodedImage`, is what the operator should
    /// be looking at.
    active: bool,
}

impl EgfxFramebuffer {
    fn new(width: u16, height: u16) -> Self {
        Self { data: vec![0; usize::from(width) * usize::from(height) * 4], width, height, active: false }
    }

    fn resize(&mut self, width: u16, height: u16) {
        self.width = width;
        self.height = height;
        self.data.clear();
        self.data.resize(usize::from(width) * usize::from(height) * 4, 0);
    }

    fn stride(&self) -> usize {
        usize::from(self.width) * 4
    }

    /// Composite one decoded RGBA rectangle at output coordinates,
    /// returning the region actually written so the caller can mark
    /// it dirty. `None` when the rectangle lies entirely outside the
    /// framebuffer or the payload is the wrong length.
    ///
    /// Clipping rather than rejecting: a surface mapped near the
    /// right or bottom edge legitimately produces updates that hang
    /// over, and dropping the whole rect would leave stale pixels on
    /// screen.
    fn blit(&mut self, x: u32, y: u32, w: u16, h: u16, rgba: &[u8]) -> Option<InclusiveRectangle> {
        let expected = usize::from(w) * usize::from(h) * 4;
        if rgba.len() != expected {
            log::warn!("rdp/egfx: bitmap update is {} bytes, expected {expected} for {w}x{h}; dropping", rgba.len());
            return None;
        }
        if w == 0 || h == 0 || x >= u32::from(self.width) || y >= u32::from(self.height) {
            return None;
        }
        let dst_x = x as usize;
        let dst_y = y as usize;
        let copy_w = usize::from(w).min(usize::from(self.width) - dst_x);
        let copy_h = usize::from(h).min(usize::from(self.height) - dst_y);
        let src_stride = usize::from(w) * 4;
        let dst_stride = self.stride();
        for row in 0..copy_h {
            let src = (row * src_stride)..(row * src_stride + copy_w * 4);
            let dst_off = (dst_y + row) * dst_stride + dst_x * 4;
            self.data[dst_off..dst_off + copy_w * 4].copy_from_slice(&rgba[src]);
        }
        Some(InclusiveRectangle {
            left: dst_x as u16,
            top: dst_y as u16,
            right: (dst_x + copy_w - 1) as u16,
            bottom: (dst_y + copy_h - 1) as u16,
        })
    }
}

/// Fold one EGFX event into the compositing framebuffer and the
/// damage set.
///
/// Kept out of the `select!` arm so the pump body stays readable,
/// and free of `AppHandle` so it is unit-testable without a Tauri
/// runtime: a size change is *returned* for the caller to emit
/// rather than emitted here.
fn apply_egfx_event(
    event: EgfxEvent,
    fb: &mut EgfxFramebuffer,
    dirty: &mut Dirty,
    width: &mut u16,
    height: &mut u16,
) -> Option<ResizePayload> {
    match event {
        EgfxEvent::Reset { width: rw, height: rh } => {
            // ResetGraphics carries the new output size. Clamp into
            // u16 — the DisplayControl ceiling is 8192, so anything
            // beyond that is a malformed PDU, not a real desktop.
            let (nw, nh) = (rw.min(8192) as u16, rh.min(8192) as u16);
            if nw == 0 || nh == 0 {
                log::warn!("rdp/egfx: ResetGraphics to {rw}x{rh} ignored");
                return None;
            }
            let resized = (nw, nh) != (*width, *height);
            if resized {
                *width = nw;
                *height = nh;
                log::info!("rdp/egfx: output reset to {nw}x{nh}");
            }
            fb.resize(nw, nh);
            dirty.mark_full();
            return resized.then_some(ResizePayload { width: nw, height: nh });
        }
        EgfxEvent::Blit { x, y, width: w, height: h, rgba } => {
            let rect = fb.blit(x, y, w, h, &rgba)?;
            if !fb.active {
                // Switch the frame source on the first blit that
                // actually landed, not on CapabilitiesConfirm.
                // Confirming capabilities only means the server *may*
                // use the pipeline; if it then sends nothing but a
                // codec we cannot decode, flipping early would blank
                // the desktop. Waiting for real pixels means we only
                // ever switch to a buffer that has some.
                fb.active = true;
                // The desktop painted so far lives in the
                // `DecodedImage` we are about to stop reading, so
                // repaint whole rather than leaving a torn frame.
                dirty.mark_full();
                log::info!("rdp/egfx: first surface update composited; the graphics pipeline is now the frame source");
            }
            dirty.add(rect, *width, *height);
        }
        EgfxEvent::Undecodable(what) => {
            log::error!(
                "rdp/egfx: the server is sending {what}. The desktop will not update. Set the \
                 profile key `rdp_egfx` to false for this target, or configure the server to \
                 prefer H.264 (AVC420) in the Graphics Pipeline."
            );
        }
    }
    None
}

/// Which framebuffer the frame packer should read.
///
/// Flips to the EGFX buffer exactly once, when the server confirms
/// Graphics Pipeline capabilities — from that point on a Windows
/// server sends graphics over the DVC and stops sending bitmap
/// updates, so the `DecodedImage` stops being updated and would
/// freeze the desktop if we kept reading it.
fn current_surface<'a>(image: &'a DecodedImage, egfx: &'a EgfxFramebuffer) -> SurfaceView<'a> {
    if egfx.active {
        SurfaceView { data: &egfx.data, stride: egfx.stride(), bpp: 4 }
    } else {
        SurfaceView::from_decoded(image)
    }
}

/// What the EGFX handler reports back to the pump.
///
/// The handler is owned by `GraphicsPipelineClient`, which is owned
/// by `DrdynvcClient` inside the connector's static-channel set, so
/// it has no path to the pump's framebuffer. It sends these instead
/// and the pump drains them after each `ActiveStage::process`.
#[cfg_attr(not(feature = "rdp_egfx"), allow(dead_code))]
enum EgfxEvent {
    /// Server reset the graphics output buffer.
    Reset { width: u32, height: u32 },
    /// Decoded RGBA for a rectangle in output coordinates.
    Blit { x: u32, y: u32, width: u16, height: u16, rgba: Vec<u8> },
    /// A codec arrived that we cannot decode. Reported so the
    /// operator gets an explanation instead of a frozen desktop.
    Undecodable(&'static str),
}

/// EGFX handler: tracks surface→output mapping and forwards decoded
/// bitmaps to the pump.
///
/// Surface origins matter: `BitmapUpdate::destination_rectangle` is
/// in *surface* coordinates, and a surface is placed on the output
/// by `MapSurfaceToOutput`. Compositing without applying the origin
/// draws every surface at the top-left corner.
#[cfg(feature = "rdp_egfx")]
struct EgfxHandler {
    tx: mpsc::UnboundedSender<EgfxEvent>,
    origins: std::collections::HashMap<u16, (u32, u32)>,
    /// Whether an undecodable-codec warning has already been sent;
    /// the server would otherwise generate one per frame.
    warned_undecodable: bool,
}

#[cfg(feature = "rdp_egfx")]
impl EgfxHandler {
    fn new(tx: mpsc::UnboundedSender<EgfxEvent>) -> Self {
        Self { tx, origins: std::collections::HashMap::new(), warned_undecodable: false }
    }

    fn warn_once(&mut self, what: &'static str) {
        if !self.warned_undecodable {
            self.warned_undecodable = true;
            let _ = self.tx.send(EgfxEvent::Undecodable(what));
        }
    }
}

#[cfg(feature = "rdp_egfx")]
impl ironrdp_egfx::client::GraphicsPipelineHandler for EgfxHandler {
    fn on_capabilities_confirmed(&mut self, caps: &ironrdp_egfx::pdu::CapabilitySet) {
        log::info!("rdp/egfx: server confirmed {caps:?}");
    }

    fn on_reset_graphics(&mut self, width: u32, height: u32) {
        self.origins.clear();
        let _ = self.tx.send(EgfxEvent::Reset { width, height });
    }

    fn on_surface_created(&mut self, surface: &ironrdp_egfx::client::Surface) {
        // Origin defaults to (0,0) until MapSurfaceToOutput arrives.
        self.origins.insert(surface.id, (surface.output_origin_x, surface.output_origin_y));
    }

    fn on_surface_deleted(&mut self, surface_id: u16) {
        self.origins.remove(&surface_id);
    }

    fn on_surface_mapped(&mut self, surface_id: u16, origin_x: u32, origin_y: u32) {
        self.origins.insert(surface_id, (origin_x, origin_y));
    }

    fn on_bitmap_updated(&mut self, update: &ironrdp_egfx::client::BitmapUpdate) {
        if update.data.is_empty() {
            // The client skipped decode (no decoder for this codec).
            self.warn_once("a codec with no decoder configured");
            return;
        }
        let Some(&(ox, oy)) = self.origins.get(&update.surface_id) else {
            log::warn!("rdp/egfx: bitmap update for unmapped surface {}; dropping", update.surface_id);
            return;
        };
        let _ = self.tx.send(EgfxEvent::Blit {
            x: ox.saturating_add(u32::from(update.destination_rectangle.left)),
            y: oy.saturating_add(u32::from(update.destination_rectangle.top)),
            width: update.width,
            height: update.height,
            rgba: update.data.clone(),
        });
    }

    fn on_wire_to_surface2(&mut self, _pdu: &ironrdp_egfx::pdu::WireToSurface2Pdu) {
        // RFX Progressive. `ironrdp-graphics` has the transform
        // primitives but no tile-level decoder, so there is nothing
        // to decode this with. Report it rather than silently
        // freezing: the fix is to make the server prefer H.264, or
        // to turn EGFX off for this target.
        self.warn_once("RFX Progressive (WireToSurface2), which this client cannot decode");
    }

    fn on_unhandled_pdu(&mut self, pdu: &ironrdp_egfx::pdu::GfxPdu) {
        log::debug!("rdp/egfx: unhandled pdu {pdu:?}");
    }

    fn on_close(&mut self) {
        log::info!("rdp/egfx: graphics channel closed");
    }
}

/// Build the H.264 decoder for the Graphics Pipeline, or explain why
/// there isn't one.
///
/// The decoder is Cisco's OpenH264, loaded at run time from a path
/// the operator supplies in `BASTION_RDP_OPENH264`. Deliberately
/// *not* compiled into the binary:
///
///   - An H.264 decoder parses server-controlled bitstreams. Keeping
///     it out of the default build keeps that attack surface out of
///     every BastionVault install (AGENTS.md §7 — minimize the
///     trusted computing base).
///   - `openh264-libloading` verifies the library against known
///     Cisco release hashes before loading it, so the thing being
///     loaded is a Cisco build and not an arbitrary shared object.
///   - Cisco's patent grant covers their prebuilt binaries, not a
///     source build.
///
/// Returning `None` disables EGFX entirely rather than negotiating
/// it without a decoder: a V8-only EGFX session gets RFX Progressive
/// from Windows, which we cannot decode, and the operator would see
/// a frozen desktop instead of falling back to the RemoteFX path
/// that works.
#[cfg(feature = "rdp_egfx")]
fn build_h264_decoder() -> Option<Box<dyn ironrdp_egfx::decode::H264Decoder>> {
    let path = match std::env::var_os("BASTION_RDP_OPENH264") {
        Some(p) if !p.is_empty() => std::path::PathBuf::from(p),
        _ => {
            log::info!(
                "rdp/egfx: BASTION_RDP_OPENH264 is not set, so no H.264 decoder is available and the \
                 Graphics Pipeline stays off; the session uses the RemoteFX / bitmap path. Point that \
                 variable at a Cisco OpenH264 release binary to enable it."
            );
            return None;
        }
    };
    match ironrdp_egfx::decode::OpenH264Decoder::from_library_path(&path) {
        Ok(d) => {
            log::info!("rdp/egfx: loaded OpenH264 from {}", path.display());
            Some(Box::new(d))
        }
        Err(e) => {
            // Fail closed onto the working path, loudly. A hash
            // mismatch here means the library is not a recognised
            // Cisco release.
            log::error!(
                "rdp/egfx: could not load OpenH264 from {} ({e}); the Graphics Pipeline stays off and \
                 the session falls back to the RemoteFX / bitmap path",
                path.display()
            );
            None
        }
    }
}

/// A read-only view of whatever framebuffer is currently
/// authoritative for the session.
///
/// Two exist. Fast-path and slow-path bitmap updates are decoded by
/// ironrdp into a [`DecodedImage`], which exposes no mutation API —
/// so the Graphics Pipeline, whose decoded surfaces we composite
/// ourselves, has to keep its own buffer. Packing reads through
/// this so it does not care which.
#[derive(Copy, Clone)]
struct SurfaceView<'a> {
    data: &'a [u8],
    stride: usize,
    bpp: usize,
}

impl<'a> SurfaceView<'a> {
    fn from_decoded(image: &'a DecodedImage) -> Self {
        Self { data: image.data(), stride: image.stride(), bpp: image.bytes_per_pixel() }
    }
}

/// Append a sub-rectangle of `surface` to `out` as row-packed RGBA,
/// ready for `new ImageData(bytes, w, h)` on the JS side.
///
/// Appends — it does not clear. A frame message carries a header,
/// a rect table and then several rects back to back, all in one
/// buffer.
///
/// The rect is assumed already clamped to the surface by
/// [`Dirty::add`]; rows that would still read out of bounds are
/// skipped and zero-filled rather than panicking, because a panic
/// here kills the session pump and takes the operator's desktop
/// with it.
fn pack_subrect(surface: SurfaceView<'_>, x: u16, y: u16, w: u16, h: u16, out: &mut Vec<u8>) {
    let row_bytes = usize::from(w) * surface.bpp;
    out.reserve(row_bytes * usize::from(h));
    let col_start = usize::from(x) * surface.bpp;
    let col_end = col_start + row_bytes;
    for row in usize::from(y)..usize::from(y) + usize::from(h) {
        let row_off = row * surface.stride;
        match surface.data.get(row_off + col_start..row_off + col_end) {
            Some(slice) => out.extend_from_slice(slice),
            None => {
                log::warn!(
                    "rdp: frame rect {w}x{h} at ({x},{y}) reaches past the framebuffer at row {row}; \
                     packing black"
                );
                out.resize(out.len() + row_bytes, 0);
            }
        }
    }
}

#[derive(Serialize, Clone)]
struct ResizePayload {
    width: u16,
    height: u16,
}

fn control_to_fastpath(ctl: RdpControl) -> Option<FastPathInput> {
    let event = match ctl {
        RdpControl::PointerMove { x, y } => FastPathInputEvent::MouseEvent(MousePdu {
            flags: PointerFlags::MOVE,
            number_of_wheel_rotation_units: 0,
            x_position: x,
            y_position: y,
        }),
        RdpControl::PointerButton { button_index, pressed, x, y } => {
            // JS MouseEvent.button: 0=left, 1=middle, 2=right.
            let button = match button_index {
                0 => PointerFlags::LEFT_BUTTON,
                1 => PointerFlags::MIDDLE_BUTTON_OR_WHEEL,
                _ => PointerFlags::RIGHT_BUTTON,
            };
            let mut flags = button;
            if pressed {
                flags |= PointerFlags::DOWN;
            }
            FastPathInputEvent::MouseEvent(MousePdu {
                flags,
                number_of_wheel_rotation_units: 0,
                x_position: x,
                y_position: y,
            })
        }
        RdpControl::Key { js_code, pressed } => {
            let scancode = js_code_to_ps2_scancode(&js_code)?;
            let mut flags = KeyboardFlags::empty();
            if !pressed {
                flags |= KeyboardFlags::RELEASE;
            }
            FastPathInputEvent::KeyboardEvent(flags, scancode)
        }
        RdpControl::Resize { .. } | RdpControl::Repaint | RdpControl::Close => return None,
    };
    FastPathInput::new(vec![event]).ok()
}

/// Conservative JS `KeyboardEvent.code` → PS/2 scancode set 1 map.
/// Covers the printable ASCII set + common modifiers / arrows /
/// function keys / Enter / Escape / Backspace / Tab. Anything else
/// drops on the floor — operator sees the keystroke land in xterm
/// for SSH but get ignored in RDP. International keys + media keys
/// are tracked as follow-up work alongside the broader Phase 7
/// polish slice.
fn js_code_to_ps2_scancode(code: &str) -> Option<u8> {
    Some(match code {
        "Escape" => 0x01,
        "Digit1" => 0x02,
        "Digit2" => 0x03,
        "Digit3" => 0x04,
        "Digit4" => 0x05,
        "Digit5" => 0x06,
        "Digit6" => 0x07,
        "Digit7" => 0x08,
        "Digit8" => 0x09,
        "Digit9" => 0x0a,
        "Digit0" => 0x0b,
        "Minus" => 0x0c,
        "Equal" => 0x0d,
        "Backspace" => 0x0e,
        "Tab" => 0x0f,
        "KeyQ" => 0x10,
        "KeyW" => 0x11,
        "KeyE" => 0x12,
        "KeyR" => 0x13,
        "KeyT" => 0x14,
        "KeyY" => 0x15,
        "KeyU" => 0x16,
        "KeyI" => 0x17,
        "KeyO" => 0x18,
        "KeyP" => 0x19,
        "BracketLeft" => 0x1a,
        "BracketRight" => 0x1b,
        "Enter" => 0x1c,
        "ControlLeft" | "ControlRight" => 0x1d,
        "KeyA" => 0x1e,
        "KeyS" => 0x1f,
        "KeyD" => 0x20,
        "KeyF" => 0x21,
        "KeyG" => 0x22,
        "KeyH" => 0x23,
        "KeyJ" => 0x24,
        "KeyK" => 0x25,
        "KeyL" => 0x26,
        "Semicolon" => 0x27,
        "Quote" => 0x28,
        "Backquote" => 0x29,
        "ShiftLeft" => 0x2a,
        "Backslash" => 0x2b,
        "KeyZ" => 0x2c,
        "KeyX" => 0x2d,
        "KeyC" => 0x2e,
        "KeyV" => 0x2f,
        "KeyB" => 0x30,
        "KeyN" => 0x31,
        "KeyM" => 0x32,
        "Comma" => 0x33,
        "Period" => 0x34,
        "Slash" => 0x35,
        "ShiftRight" => 0x36,
        "AltLeft" | "AltRight" => 0x38,
        "Space" => 0x39,
        "CapsLock" => 0x3a,
        "F1" => 0x3b,
        "F2" => 0x3c,
        "F3" => 0x3d,
        "F4" => 0x3e,
        "F5" => 0x3f,
        "F6" => 0x40,
        "F7" => 0x41,
        "F8" => 0x42,
        "F9" => 0x43,
        "F10" => 0x44,
        "F11" => 0x57,
        "F12" => 0x58,
        "ArrowUp" => 0x48,
        "ArrowDown" => 0x50,
        "ArrowLeft" => 0x4b,
        "ArrowRight" => 0x4d,
        "Home" => 0x47,
        "End" => 0x4f,
        "PageUp" => 0x49,
        "PageDown" => 0x51,
        "Delete" => 0x53,
        "Insert" => 0x52,
        _ => return None,
    })
}

pub async fn send_control(state: &crate::state::AppState, token: &str, ctl: RdpControl) -> Result<(), String> {
    let sessions = state.connect_sessions.lock().await;
    match sessions.get(token) {
        Some(SessionState::Rdp(s)) => s.input_tx.send(ctl).await.map_err(|_| "rdp control channel closed".to_string()),
        Some(_) => Err(format!("session `{token}` is not an RDP session (cannot route RDP control)")),
        None => Err(format!("session token `{token}` not found")),
    }
}

pub async fn drop_session(state: &crate::state::AppState, token: &str) -> Option<SessionCleanup> {
    let mut sessions = state.connect_sessions.lock().await;
    let removed = sessions.remove(token);
    drop(sessions);
    state.rustion_session_bundles.lock().await.remove(token);
    match removed {
        Some(SessionState::Rdp(s)) => {
            log::info!("resource-connect/rdp: closed session token={token}");
            s.on_close
        }
        Some(SessionState::Ssh(s)) => {
            log::info!("resource-connect/rdp: dropped (was SSH) token={token}");
            s.on_close
        }
        None => None,
    }
}

/// `sha256:<hex>` of a DER blob, lowercase hex — the canonical pin
/// shape Rustion advertises and BV stores.
fn cert_der_sha256(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(der);
    let mut out = String::with_capacity(7 + digest.len() * 2);
    out.push_str("sha256:");
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// Render a `connect_finalize` failure with its full cause chain, plus
/// a bastion-specific hint when the peer hung up.
///
/// ironrdp's `Display` prints only `[context @ file:line] kind` — the
/// real cause (an `io::Error`, a decode failure) hangs off the `source`
/// chain and is dropped by a plain `{e}`. That's why a bastion that
/// closed the socket surfaced as the uninformative
/// `[read frame by hint @ ironrdp-connector/src/lib.rs:416] custom
/// error`. `report()` walks the chain.
///
/// The extra hint matters because of how the Rustion RDP gateway
/// fails: every error path in `handle_rdp_connection` after the TLS
/// accept returns `Err` and drops the socket without writing an
/// RDP-level error PDU, so the operator's client can only ever observe
/// EOF. When we're on a ticketed dial and the chain bottoms out in a
/// closed connection, say so and point at the hop that actually broke.
fn describe_finalize_error(args: &RdpOpenArgs, e: &ironrdp::connector::ConnectorError) -> String {
    let report = format!("rdp: connect_finalize: {}", e.report());
    if args.ticket_cookie.is_some() && peer_hung_up(e) {
        format!(
            "{report} — the Rustion bastion at {}:{} closed the connection without \
             answering the RDP exchange. The bastion never reports why on the wire, so \
             the reason is only in its log: look for the `AUTH_FAILURE` / `RDP session \
             error` pair for this peer address. A rejected ticket (`user=unknown`, \
             `reason=invalid username or password`) and a failed bastion→target dial \
             both surface here as a bare EOF.",
            args.host, args.port
        )
    } else {
        report
    }
}

/// Walk an error's source chain looking for an `io::Error` that means
/// the remote end went away.
fn peer_hung_up(e: &ironrdp::connector::ConnectorError) -> bool {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = cur {
        if let Some(io) = err.downcast_ref::<std::io::Error>() {
            if matches!(
                io.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            ) {
                return true;
            }
        }
        cur = err.source();
    }
    false
}

/// Compare the observed TLS leaf certificate against a pinned
/// `sha256:<hex>` digest. Returns `Ok(())` on match, an error string on
/// mismatch or if the cert can't be re-encoded. The comparison tolerates
/// an optional `sha256:` prefix and is case-insensitive on the hex so an
/// operator-pasted pin in either form still matches.
// `x509_cert_v03`, not the crate's default `x509_cert` (0.2): this is
// the certificate `ironrdp_tls::upgrade` handed back, and ironrdp-tls
// is built on x509-cert 0.3. See the dependency comment in Cargo.toml.
fn verify_tls_pin(server_cert: &x509_cert_v03::Certificate, pin: &str) -> Result<(), String> {
    use x509_cert_v03::der::Encode as _;
    let der = server_cert.to_der().map_err(|e| format!("rdp: re-encode server cert for pin check: {e}"))?;
    let observed = cert_der_sha256(&der);
    if tls_pin_matches(&observed, pin) {
        Ok(())
    } else {
        Err(format!(
            "rdp: bastion TLS certificate does not match the pinned fingerprint \
             (expected {pin}, observed {observed}). Refusing to connect. If the \
             bastion's TLS certificate was rotated, re-run listener discovery on \
             the Rustion target to update the pin."
        ))
    }
}

/// Normalise + compare two fingerprints. Both sides are lowercased and
/// any leading `sha256:` is stripped so `sha256:AB…` and `ab…` match.
fn tls_pin_matches(observed: &str, expected: &str) -> bool {
    fn norm(s: &str) -> String {
        let lower = s.trim().to_ascii_lowercase();
        lower.strip_prefix("sha256:").unwrap_or(&lower).to_string()
    }
    let e = norm(expected);
    !e.is_empty() && norm(observed) == e
}

#[cfg(test)]
mod pin_tests {
    use super::{cert_der_sha256, tls_pin_matches};

    #[test]
    fn sha256_shape_is_lowercase_hex_with_prefix() {
        assert_eq!(
            cert_der_sha256(&[0xde, 0xad, 0xbe, 0xef]),
            "sha256:5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953"
        );
    }

    #[test]
    fn pin_match_tolerates_prefix_and_case() {
        let obs = "sha256:5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953";
        // exact
        assert!(tls_pin_matches(obs, obs));
        // no prefix on expected
        assert!(tls_pin_matches(obs, "5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953"));
        // uppercase expected
        assert!(tls_pin_matches(obs, "SHA256:5F78C33274E43FA9DE5659265C1D917E25C03722DCB0B8D27DB8D5FEAA813953"));
    }

    #[test]
    fn pin_mismatch_and_empty_are_rejected() {
        let obs = "sha256:5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953";
        assert!(!tls_pin_matches(obs, "sha256:0000"));
        // An empty expected pin must never be treated as a match — that
        // would silently disable pinning.
        assert!(!tls_pin_matches(obs, ""));
        assert!(!tls_pin_matches(obs, "sha256:"));
    }
}

/// The X.224 Connection Request is the only place a Rustion-routed
/// session identifies itself, and getting the slot wrong is invisible
/// from this side: the bastion drops the socket without an RDP error
/// PDU, so the client sees nothing but EOF. These tests assert the
/// bytes on the wire.
#[cfg(test)]
mod nego_cookie_tests {
    use super::{build_connector_config, RdpCredential, RdpOpenArgs, DEFAULT_BULK_COMPRESSION};
    use ironrdp::pdu::nego::{ConnectionRequest, RequestFlags, SecurityProtocol};
    use ironrdp::pdu::x224::X224;
    use ironrdp_core::{encode_buf, WriteBuf};
    use zeroize::Zeroizing;

    const TICKET: &str = "tkt_0123456789abcdef0123456789abcdef";

    fn args(ticket_cookie: Option<String>) -> RdpOpenArgs {
        RdpOpenArgs {
            host: "apldc1vhm0069.fgv.br".to_owned(),
            port: 3389,
            username: "rustion-operator".to_owned(),
            credential: RdpCredential::Password(Zeroizing::new(String::new())),
            domain: None,
            label: "test".to_owned(),
            on_close: None,
            aggressive_performance: false,
            enable_egfx: false,
            bulk_compression: DEFAULT_BULK_COMPRESSION,
            ticket_cookie,
            tls_pin_sha256: None,
        }
    }

    /// Encode the Connection Request the connector would send for
    /// these args and return it as a lossy string.
    fn connection_request(args: &RdpOpenArgs) -> String {
        let config = build_connector_config(args);
        let request = ConnectionRequest {
            nego_data: config.request_data.clone(),
            flags: RequestFlags::empty(),
            protocol: SecurityProtocol::SSL,
            // None keeps the encoding byte-identical to what this
            // test asserted before IronRDP 0.17 added the field:
            // `Some(..)` would set CORRELATION_INFO_PRESENT and append
            // a payload, changing the bytes the cookie assertions read.
            correlation_info: None,
        };
        let mut buf = WriteBuf::new();
        encode_buf(&X224(request), &mut buf).expect("encode connection request");
        String::from_utf8_lossy(buf.filled()).into_owned()
    }

    #[test]
    fn ticket_goes_in_the_mstshash_cookie() {
        let pdu = connection_request(&args(Some(TICKET.to_owned())));
        assert!(
            pdu.contains(&format!("Cookie: mstshash={TICKET}\r\n")),
            "ticket must ride in the cookie slot Rustion parses; got {pdu:?}"
        );
    }

    #[test]
    fn ticket_is_not_sent_as_a_routing_token() {
        let pdu = connection_request(&args(Some(TICKET.to_owned())));
        // `Cookie: msts=` is the routing-token slot. It is equally
        // legal per MS-RDPBCGR and equally invisible to Rustion's
        // `extract_username_from_cookie`, which scans only for
        // `Cookie: mstshash=`.
        assert!(
            !pdu.contains("Cookie: msts="),
            "routing-token slot is not read by the bastion; got {pdu:?}"
        );
        // The bare ticket must not be double-prefixed either.
        assert!(!pdu.contains("mstshash=mstshash="), "double prefix; got {pdu:?}");
    }

    #[test]
    fn direct_sessions_leave_the_slot_to_ironrdp() {
        let mut a = args(None);
        a.username = "alice".to_owned();
        // `request_data: None` is what hands the slot back to the
        // connector, which fills it with `Cookie: mstshash=<username>`.
        // Setting it here would override that default.
        assert!(build_connector_config(&a).request_data.is_none());
    }
}

/// Coalescing is what keeps a burst of small server updates from
/// becoming a burst of IPC round trips, and the wire format is the
/// contract `gui/src/lib/rdpFrames.ts` parses. Both are pure
/// functions of their inputs, so both are tested directly.
#[cfg(test)]
mod frame_tests {
    use super::{
        contains, parse_bulk_compression, rect_dims, rect_pixel_bytes, Dirty, CompressionType,
        DEFAULT_BULK_COMPRESSION, MAX_DIRTY_RECTS,
    };
    use ironrdp::pdu::geometry::InclusiveRectangle;

    fn rect(left: u16, top: u16, right: u16, bottom: u16) -> InclusiveRectangle {
        InclusiveRectangle { left, top, right, bottom }
    }

    #[test]
    fn dirty_starts_empty_and_clears() {
        let mut d = Dirty::default();
        assert!(d.is_empty());
        d.add(rect(0, 0, 9, 9), 100, 100);
        assert!(!d.is_empty());
        d.clear();
        assert!(d.is_empty());
    }

    #[test]
    fn repeated_damage_to_the_same_region_collapses() {
        // A blinking caret: the same rect over and over. This is the
        // case that used to cost one IPC message per repaint.
        let mut d = Dirty::default();
        for _ in 0..50 {
            d.add(rect(10, 10, 19, 29), 800, 600);
        }
        assert_eq!(d.rects.len(), 1);
        assert!(!d.full);
    }

    #[test]
    fn a_containing_rect_replaces_the_ones_it_covers() {
        let mut d = Dirty::default();
        d.add(rect(10, 10, 19, 19), 800, 600);
        d.add(rect(30, 30, 39, 39), 800, 600);
        assert_eq!(d.rects.len(), 2);
        // One rect covering both must leave exactly itself behind, or
        // the same pixels get packed and shipped more than once.
        d.add(rect(0, 0, 99, 99), 800, 600);
        assert_eq!(d.rects.len(), 1);
        assert_eq!(d.rects[0], rect(0, 0, 99, 99));
    }

    #[test]
    fn a_contained_rect_is_dropped() {
        let mut d = Dirty::default();
        d.add(rect(0, 0, 99, 99), 800, 600);
        d.add(rect(10, 10, 19, 19), 800, 600);
        assert_eq!(d.rects.len(), 1);
        assert_eq!(d.rects[0], rect(0, 0, 99, 99));
    }

    #[test]
    fn scattered_damage_collapses_to_a_union_not_a_full_repaint() {
        // One rect past the budget, all clustered in a corner of a
        // large desktop. The union is still far cheaper than a full
        // repaint, so it must be kept as a rect.
        let mut d = Dirty::default();
        for i in 0..=(MAX_DIRTY_RECTS as u16) {
            let x = i * 4;
            d.add(rect(x, 0, x + 1, 1), 4000, 4000);
        }
        assert!(!d.full, "a corner cluster must not trigger a full-desktop repaint");
        assert_eq!(d.rects.len(), 1, "over budget collapses to exactly one union");
        assert_eq!(d.rects[0], rect(0, 0, MAX_DIRTY_RECTS as u16 * 4 + 1, 1));
    }

    #[test]
    fn damage_spread_across_the_desktop_becomes_a_full_repaint() {
        // Same over-budget trigger, but the damage touches opposite
        // corners so the union *is* the desktop. Tracking that as a
        // rect buys nothing over saying "repaint everything".
        let mut d = Dirty::default();
        let spread = [
            rect(0, 0, 1, 1),
            rect(98, 98, 99, 99),
            rect(10, 10, 11, 11),
            rect(20, 20, 21, 21),
            rect(30, 30, 31, 31),
            rect(40, 40, 41, 41),
            rect(50, 50, 51, 51),
            rect(60, 60, 61, 61),
            rect(70, 70, 71, 71),
        ];
        assert!(spread.len() > MAX_DIRTY_RECTS, "the fixture must exceed the rect budget");
        for r in spread {
            d.add(r, 100, 100);
        }
        assert!(d.full);
        assert!(d.rects.is_empty(), "a full repaint carries no rect list");
    }

    #[test]
    fn full_absorbs_further_damage() {
        let mut d = Dirty::default();
        d.mark_full();
        d.add(rect(1, 1, 2, 2), 100, 100);
        assert!(d.full);
        assert!(d.rects.is_empty());
    }

    #[test]
    fn rects_are_clamped_to_the_desktop() {
        // Some servers report rects past the negotiated DesktopSize
        // for cursor sprites. An unclamped rect would read past the
        // framebuffer in pack_subrect.
        let mut d = Dirty::default();
        d.add(rect(90, 90, 200, 200), 100, 100);
        assert_eq!(d.rects.len(), 1);
        assert_eq!(d.rects[0], rect(90, 90, 99, 99));
    }

    #[test]
    fn rects_entirely_outside_the_desktop_are_dropped() {
        let mut d = Dirty::default();
        d.add(rect(200, 200, 300, 300), 100, 100);
        assert!(d.is_empty());
    }

    #[test]
    fn zero_sized_desktop_is_not_a_panic() {
        let mut d = Dirty::default();
        d.add(rect(0, 0, 0, 0), 0, 0);
        assert!(d.is_empty());
    }

    #[test]
    fn containment_is_inclusive() {
        assert!(contains(&rect(0, 0, 9, 9), &rect(0, 0, 9, 9)));
        assert!(contains(&rect(0, 0, 9, 9), &rect(1, 1, 8, 8)));
        assert!(!contains(&rect(1, 1, 8, 8), &rect(0, 0, 9, 9)));
        assert!(!contains(&rect(0, 0, 9, 9), &rect(0, 0, 10, 9)));
    }

    #[test]
    fn rect_dims_are_inclusive() {
        assert_eq!(rect_dims(&rect(0, 0, 0, 0)), (1, 1));
        assert_eq!(rect_dims(&rect(10, 20, 19, 29)), (10, 10));
    }

    #[test]
    fn pixel_bytes_clamp_and_never_underflow() {
        assert_eq!(rect_pixel_bytes(&rect(0, 0, 1, 1), 100, 100), 2 * 2 * 4);
        // Clamped: 90..=99 is 10 wide, not 111.
        assert_eq!(rect_pixel_bytes(&rect(90, 90, 200, 200), 100, 100), 10 * 10 * 4);
        assert_eq!(rect_pixel_bytes(&rect(200, 0, 300, 1), 100, 100), 0);
        assert_eq!(rect_pixel_bytes(&rect(0, 0, 1, 1), 0, 0), 0);
    }

    #[test]
    fn bulk_compression_default_is_mppc_64k() {
        assert_eq!(DEFAULT_BULK_COMPRESSION, Some(CompressionType::K64));
        assert_eq!(parse_bulk_compression("default"), Ok(DEFAULT_BULK_COMPRESSION));
    }

    #[test]
    fn bulk_compression_accepts_the_documented_spellings() {
        assert_eq!(parse_bulk_compression("off"), Ok(None));
        assert_eq!(parse_bulk_compression("none"), Ok(None));
        assert_eq!(parse_bulk_compression("mppc8k"), Ok(Some(CompressionType::K8)));
        assert_eq!(parse_bulk_compression("k8"), Ok(Some(CompressionType::K8)));
        assert_eq!(parse_bulk_compression("mppc64k"), Ok(Some(CompressionType::K64)));
        assert_eq!(parse_bulk_compression("rdp6"), Ok(Some(CompressionType::Rdp6)));
        assert_eq!(parse_bulk_compression("rdp61"), Ok(Some(CompressionType::Rdp61)));
        assert_eq!(parse_bulk_compression("rdp6.1"), Ok(Some(CompressionType::Rdp61)));
        // Case and surrounding whitespace are tolerated.
        assert_eq!(parse_bulk_compression("  MPPC64K "), Ok(Some(CompressionType::K64)));
    }

    #[test]
    fn an_unknown_bulk_compression_is_an_error_not_a_fallback() {
        // Silently defaulting a typo would change a session's wire
        // behaviour without telling anyone (AGENTS.md §7).
        let err = parse_bulk_compression("mppc32k").expect_err("must reject");
        assert!(err.contains("mppc32k"), "{err}");
        assert!(err.contains("mppc64k"), "the error must list the valid values: {err}");
    }
}

/// The Graphics Pipeline composites into a framebuffer we own,
/// applies surface origins itself, and decides when to become the
/// authoritative frame source. All three are places where a quiet
/// mistake shows up as a black or misplaced desktop, so they are
/// tested directly.
#[cfg(test)]
mod egfx_tests {
    use super::{apply_egfx_event, current_surface, Dirty, EgfxEvent, EgfxFramebuffer};
    use ironrdp::graphics::image_processing::PixelFormat;
    use ironrdp::session::image::DecodedImage;

    fn rgba(w: u16, h: u16, fill: u8) -> Vec<u8> {
        vec![fill; usize::from(w) * usize::from(h) * 4]
    }

    #[test]
    fn a_new_framebuffer_is_inert_and_the_decoded_image_is_authoritative() {
        let image = DecodedImage::new(PixelFormat::RgbA32, 16, 8);
        let fb = EgfxFramebuffer::new(16, 8);
        assert!(!fb.active);
        let view = current_surface(&image, &fb);
        assert_eq!(view.stride, image.stride());
        assert!(std::ptr::eq(view.data.as_ptr(), image.data().as_ptr()));
    }

    #[test]
    fn blit_writes_at_the_output_origin_and_reports_the_region() {
        let mut fb = EgfxFramebuffer::new(8, 4);
        let rect = fb.blit(2, 1, 2, 2, &rgba(2, 2, 0xab)).expect("blit lands");
        assert_eq!((rect.left, rect.top, rect.right, rect.bottom), (2, 1, 3, 2));
        // Row 1, column 2 is the first written pixel.
        let off = (1 * 8 + 2) * 4;
        assert_eq!(&fb.data[off..off + 8], &[0xab; 8]);
        // Column 1 of the same row is untouched.
        assert_eq!(&fb.data[off - 4..off], &[0; 4]);
    }

    #[test]
    fn blit_clips_at_the_right_and_bottom_edges() {
        // A surface mapped near the edge legitimately overhangs.
        // Clipping keeps the visible part; rejecting would leave
        // stale pixels on screen.
        let mut fb = EgfxFramebuffer::new(4, 4);
        let rect = fb.blit(3, 3, 4, 4, &rgba(4, 4, 0x11)).expect("clipped blit still lands");
        assert_eq!((rect.left, rect.top, rect.right, rect.bottom), (3, 3, 3, 3));
        let off = (3 * 4 + 3) * 4;
        assert_eq!(&fb.data[off..off + 4], &[0x11; 4]);
    }

    #[test]
    fn blit_outside_the_framebuffer_is_dropped() {
        let mut fb = EgfxFramebuffer::new(4, 4);
        assert!(fb.blit(4, 0, 1, 1, &rgba(1, 1, 1)).is_none());
        assert!(fb.blit(0, 4, 1, 1, &rgba(1, 1, 1)).is_none());
        assert!(fb.blit(0, 0, 0, 0, &[]).is_none());
    }

    #[test]
    fn a_payload_of_the_wrong_length_is_rejected_not_truncated() {
        // A short payload from a malformed PDU must not be padded
        // into the framebuffer, and must not panic the pump.
        let mut fb = EgfxFramebuffer::new(4, 4);
        assert!(fb.blit(0, 0, 2, 2, &rgba(2, 2, 7)[..8]).is_none());
        assert!(fb.blit(0, 0, 2, 2, &rgba(4, 4, 7)).is_none());
        assert!(fb.data.iter().all(|&b| b == 0), "nothing may have been written");
    }

    #[test]
    fn the_first_landed_blit_takes_over_as_the_frame_source() {
        let image = DecodedImage::new(PixelFormat::RgbA32, 8, 4);
        let mut fb = EgfxFramebuffer::new(8, 4);
        let mut dirty = Dirty::default();
        let (mut w, mut h) = (8u16, 4u16);

        assert!(!fb.active);
        let resize =
            apply_egfx_event(EgfxEvent::Blit { x: 0, y: 0, width: 2, height: 2, rgba: rgba(2, 2, 5) },
                &mut fb, &mut dirty, &mut w, &mut h);
        assert!(resize.is_none());
        assert!(fb.active);
        // Taking over must repaint whole — the old desktop lives in
        // the DecodedImage we just stopped reading.
        assert!(dirty.full);
        assert!(std::ptr::eq(current_surface(&image, &fb).data.as_ptr(), fb.data.as_ptr()));
    }

    #[test]
    fn a_dropped_blit_does_not_take_over_the_frame_source() {
        // The regression that matters: if we switched on *any* blit
        // event rather than one that landed, a stream of malformed
        // updates would blank the operator's desktop.
        let mut fb = EgfxFramebuffer::new(8, 4);
        let mut dirty = Dirty::default();
        let (mut w, mut h) = (8u16, 4u16);
        apply_egfx_event(
            EgfxEvent::Blit { x: 99, y: 99, width: 2, height: 2, rgba: rgba(2, 2, 5) },
            &mut fb, &mut dirty, &mut w, &mut h,
        );
        assert!(!fb.active);
        assert!(dirty.is_empty());
    }

    #[test]
    fn reset_graphics_resizes_and_reports_the_new_size() {
        let mut fb = EgfxFramebuffer::new(8, 4);
        let mut dirty = Dirty::default();
        let (mut w, mut h) = (8u16, 4u16);
        let resize = apply_egfx_event(
            EgfxEvent::Reset { width: 16, height: 9 },
            &mut fb, &mut dirty, &mut w, &mut h,
        )
        .expect("a size change is reported so the caller can emit it");
        assert_eq!((resize.width, resize.height), (16, 9));
        assert_eq!((w, h), (16, 9));
        assert_eq!(fb.data.len(), 16 * 9 * 4);
        assert!(dirty.full, "a reset framebuffer is blank and must be repainted whole");
    }

    #[test]
    fn reset_graphics_to_the_same_size_reports_nothing() {
        let mut fb = EgfxFramebuffer::new(8, 4);
        let mut dirty = Dirty::default();
        let (mut w, mut h) = (8u16, 4u16);
        assert!(apply_egfx_event(
            EgfxEvent::Reset { width: 8, height: 4 },
            &mut fb, &mut dirty, &mut w, &mut h,
        )
        .is_none());
        assert_eq!((w, h), (8, 4));
    }

    #[test]
    fn a_degenerate_reset_is_ignored_rather_than_resizing_to_nothing() {
        let mut fb = EgfxFramebuffer::new(8, 4);
        let mut dirty = Dirty::default();
        let (mut w, mut h) = (8u16, 4u16);
        assert!(apply_egfx_event(
            EgfxEvent::Reset { width: 0, height: 0 },
            &mut fb, &mut dirty, &mut w, &mut h,
        )
        .is_none());
        assert_eq!((w, h), (8, 4), "the desktop size must survive a malformed ResetGraphics");
        assert!(dirty.is_empty());
    }
}
