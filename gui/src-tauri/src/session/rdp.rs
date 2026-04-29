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
//!     `ActiveStage::process(...)` → forward graphics updates as
//!     full-image RGBA snapshots over a per-session Tauri event,
//!     send response frames back to the server.
//!   - input control flows from the SessionRdpWindow via
//!     `session_input_rdp_*` Tauri commands → mpsc → fast-path
//!     input PDUs sent through the same framed stream.
//!
//! Phase 4 limitations (each deferred to a follow-up phase):
//!   - **No CredSSP / NLA**: connects in standard RDP-Security
//!     mode. Modern Windows servers refuse this by default;
//!     operators with NLA-enforcing servers see an explicit error
//!     pointing at the sspi/picky integration follow-up.
//!   - **Full-frame snapshots, not dirty-rect deltas**: every
//!     batch of graphics updates emits the full DecodedImage as
//!     RGBA-b64 to the WebviewWindow. Bandwidth-heavy on slow
//!     LAN links; the dirty-rect coordinates are already in the
//!     `ActiveStageOutput::GraphicsUpdate(InclusiveRectangle)`
//!     payload for the future incremental wiring.
//!   - **Fast-path keyboard scancode mapping is conservative**:
//!     the JS-side `KeyboardEvent.code` → PS/2 set 1 scancode
//!     table covers the printable ASCII set + the common
//!     modifiers; full international + media-key support is a
//!     follow-up.

use std::net::SocketAddr;
use std::time::Duration;

use ironrdp::connector::{
    ClientConnector, Config as ConnectorConfig, ConnectionResult, Credentials, DesktopSize,
    SmartCardIdentity,
};
use ironrdp::pdu::gcc::KeyboardType;
use ironrdp::pdu::input::fast_path::{FastPathInput, FastPathInputEvent, KeyboardFlags};
use ironrdp::pdu::input::mouse::{MousePdu, PointerFlags};
use ironrdp::pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp::pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{ActiveStage, ActiveStageOutput};
use ironrdp_core::{encode_buf, WriteBuf};
use ironrdp_async::{FramedWrite, NetworkClient};
use ironrdp_tokio::TokioFramed;
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::{RdpSessionState, SessionCleanup, SessionState};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

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
}

/// What kind of credential the operator picked for this session.
/// Phase 4 ships `Password` (RDP Standard Security or NLA with
/// password). The CredSSP smartcard wiring (Phase 6) adds
/// `SmartCard`, which feeds a synthetic PIV credential built from
/// a vault-issued PKI cert + PKCS#8 private key.
pub enum RdpCredential {
    Password(Zeroizing<String>),
    SmartCard(SmartCardCredential),
}

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
    pub frame_event: String,
    pub closed_event: String,
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

pub fn frame_event_name(token: &str) -> String {
    format!("session-frame-{token}")
}

pub fn closed_event_name(token: &str) -> String {
    format!("session-closed-{token}")
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
    /// Window resize from the local canvas. Reserved — Phase 4
    /// drops it on the floor; DisplayControl-channel forwarding
    /// lands alongside the dirty-rect optimization.
    #[allow(dead_code)]
    Resize { width: u16, height: u16 },
    /// Operator clicked Disconnect or x'd the window.
    Close,
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
    let frame_event = frame_event_name(&token);
    let closed_event = closed_event_name(&token);

    // Stage 1: TCP connect.
    let target: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .or_else(|_| {
            // Fall back to DNS resolution.
            tokio::net::lookup_host(format!("{}:{}", args.host, args.port))
                .now_or_never()
                .and_then(|r| r.ok())
                .and_then(|mut iter| iter.next())
                .ok_or_else(|| "dns lookup returned no addresses".to_string())
        })
        .map_err(|e: String| format!("rdp: parse/resolve {}:{}: {e}", args.host, args.port))?;
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target))
        .await
        .map_err(|_| format!("rdp: TCP connect to {target} timed out"))?
        .map_err(|e| format!("rdp: TCP connect {target}: {e}"))?;
    let local = tcp.local_addr().map_err(|e| format!("rdp: local_addr: {e}"))?;

    // Stage 2: ironrdp connector — phase one (pre-TLS).
    let cfg = build_connector_config(&args);
    let (width, height) = (cfg.desktop_size.width, cfg.desktop_size.height);
    let mut framed = TokioFramed::new(tcp);
    let mut connector = ClientConnector::new(cfg, local);
    let should_upgrade = ironrdp_async::connect_begin(&mut framed, &mut connector)
        .await
        .map_err(|e| format!("rdp: connect_begin: {e}"))?;

    // Stage 3: TLS upgrade. ironrdp-tls returns the server cert
    // as `x509_cert::Certificate`; extract the SubjectPublicKeyInfo
    // bytes for the connector's CredSSP / TLS-binding requirements.
    let initial = framed.into_inner_no_leftover();
    let (upgraded, server_cert) = ironrdp_tls::upgrade(initial, args.host.as_str())
        .await
        .map_err(|e| format!("rdp: TLS upgrade: {e}"))?;
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
    .map_err(|e| format!("rdp: connect_finalize: {e}"))?;

    // Stage 5: spawn the active-stage pump.
    let (tx, rx) = mpsc::channel::<RdpControl>(64);
    let app_for_task = app.clone();
    let frame_event_for_task = frame_event.clone();
    let closed_event_for_task = closed_event.clone();
    tokio::spawn(active_stage_loop(
        app_for_task,
        framed,
        connection_result,
        rx,
        frame_event_for_task,
        closed_event_for_task,
        width,
        height,
    ));

    {
        let mut sessions = state.connect_sessions.lock().await;
        sessions.insert(
            token.clone(),
            SessionState::Rdp(RdpSessionState {
                input_tx: tx,
                label: args.label.clone(),
                on_close: args.on_close.clone(),
            }),
        );
    }
    log::info!(
        "resource-connect/rdp: opened session token={token} label={} ({}:{})",
        args.label, args.host, args.port
    );

    Ok(RdpOpenOutcome {
        token,
        frame_event,
        closed_event,
        width,
        height,
    })
}

fn build_connector_config(args: &RdpOpenArgs) -> ConnectorConfig {
    // Smartcard auth requires CredSSP — there's no Standard
    // Security analogue. Password auth still uses Standard
    // Security so the Phase-4 flow against NLA-disabled hosts
    // keeps working unchanged.
    let (credentials, enable_credssp) = match &args.credential {
        RdpCredential::Password(pw) => (
            Credentials::UsernamePassword {
                username: args.username.clone(),
                password: pw.as_str().to_owned(),
            },
            false,
        ),
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
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_layout: 0,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: DesktopSize {
            width: 1024,
            height: 600,
        },
        bitmap: None,
        client_build: 0,
        client_name: "BastionVault".to_owned(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        compression_type: None,
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
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        pointer_software_rendering: true,
        performance_flags: PerformanceFlags::default(),
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
        Self {
            inner: sspi::network_client::reqwest_network_client::ReqwestNetworkClient,
        }
    }
}

impl NetworkClient for CredSspNetworkClient {
    fn send(
        &mut self,
        request: &ironrdp::connector::sspi::generator::NetworkRequest,
    ) -> impl std::future::Future<Output = ironrdp::connector::ConnectorResult<Vec<u8>>>
    {
        // Clone the request so the task closure owns it; the
        // borrow lives only as long as `send`.
        let req = request.clone();
        let client = self.inner.clone();
        async move {
            let result = tokio::task::spawn_blocking(move || {
                sspi::network_client::NetworkClient::send(&client, &req)
            })
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

#[allow(clippy::too_many_arguments)]
async fn active_stage_loop<S>(
    app: AppHandle,
    mut framed: TokioFramed<S>,
    connection_result: ConnectionResult,
    mut rx: mpsc::Receiver<RdpControl>,
    frame_event: String,
    closed_event: String,
    width: u16,
    height: u16,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    let mut image = DecodedImage::new(
        ironrdp::graphics::image_processing::PixelFormat::RgbA32,
        width,
        height,
    );
    let mut active_stage = ActiveStage::new(connection_result);
    let mut emit_buf = Vec::new();

    loop {
        tokio::select! {
            biased;
            ctl = rx.recv() => {
                match ctl {
                    Some(RdpControl::Close) | None => break,
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
            pdu = framed.read_pdu() => {
                let (action, payload) = match pdu {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn!("rdp: read_pdu: {e:?}");
                        break;
                    }
                };
                let outputs = match active_stage.process(&mut image, action, &payload) {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn!("rdp: active_stage.process: {e:?}");
                        break;
                    }
                };
                let mut updated = false;
                let mut response_frames: Vec<Vec<u8>> = Vec::new();
                for out in outputs {
                    match out {
                        ActiveStageOutput::GraphicsUpdate(_rect) => {
                            updated = true;
                        }
                        ActiveStageOutput::ResponseFrame(frame) => response_frames.push(frame),
                        ActiveStageOutput::Terminate(_) => {
                            log::info!("rdp: server initiated disconnect");
                            for frame in response_frames {
                                let _ = framed.write_all(&frame).await;
                            }
                            let _ = app.emit(&closed_event, ());
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
                if updated {
                    encode_full_frame(&image, width, height, &mut emit_buf);
                    let _ = app.emit(
                        &frame_event,
                        FramePayload {
                            x: 0,
                            y: 0,
                            width,
                            height,
                            bytes_b64: encode_b64(&emit_buf),
                        },
                    );
                }
            }
        }
    }
    let _ = app.emit(&closed_event, ());
}

/// Pack the full DecodedImage as RGBA bytes. Skips the alpha
/// channel? No — keeps RGBA so the canvas's `ImageData` constructor
/// doesn't need an alpha-fill pass.
fn encode_full_frame(image: &DecodedImage, width: u16, height: u16, out: &mut Vec<u8>) {
    let _ = (width, height);
    out.clear();
    out.extend_from_slice(image.data());
}

fn encode_b64(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(bytes)
}

#[derive(Serialize, Clone)]
struct FramePayload {
    x: u16,
    y: u16,
    width: u16,
    height: u16,
    bytes_b64: String,
}

fn control_to_fastpath(ctl: RdpControl) -> Option<FastPathInput> {
    let event = match ctl {
        RdpControl::PointerMove { x, y } => FastPathInputEvent::MouseEvent(MousePdu {
            flags: PointerFlags::MOVE,
            number_of_wheel_rotation_units: 0,
            x_position: x,
            y_position: y,
        }),
        RdpControl::PointerButton {
            button_index,
            pressed,
            x,
            y,
        } => {
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
        RdpControl::Resize { .. } | RdpControl::Close => return None,
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

pub async fn send_control(
    state: &crate::state::AppState,
    token: &str,
    ctl: RdpControl,
) -> Result<(), String> {
    let sessions = state.connect_sessions.lock().await;
    match sessions.get(token) {
        Some(SessionState::Rdp(s)) => s
            .input_tx
            .send(ctl)
            .await
            .map_err(|_| "rdp control channel closed".to_string()),
        Some(_) => Err(format!(
            "session `{token}` is not an RDP session (cannot route RDP control)"
        )),
        None => Err(format!("session token `{token}` not found")),
    }
}

pub async fn drop_session(
    state: &crate::state::AppState,
    token: &str,
) -> Option<SessionCleanup> {
    let mut sessions = state.connect_sessions.lock().await;
    let removed = sessions.remove(token);
    drop(sessions);
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

// `now_or_never` would be nice but we don't depend on `futures` as
// a direct dep. Inline what we need.
trait FutureExt: std::future::Future + Sized {
    fn now_or_never(self) -> Option<Self::Output>;
}
impl<F: std::future::Future + Sized> FutureExt for F {
    fn now_or_never(self) -> Option<Self::Output> {
        use std::future::Future;
        use std::pin::Pin;
        use std::task::{Context, Poll, Waker};
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut pinned = Box::pin(self);
        match Pin::new(&mut pinned).poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }
}
