//! SSH session driver — `russh` + a tokio task per session.
//!
//! Lifecycle:
//!   1. The frontend calls `session_open_ssh` with a credential
//!      bundle pre-resolved on the Rust side (the credential bytes
//!      never travel through the JS layer — the Tauri command
//!      reads them out of barrier-encrypted storage, then hands
//!      this resolver the plaintext for the duration of the
//!      session).
//!   2. We open a russh connection, request a PTY, and spawn a
//!      background task that pumps bytes both directions: data
//!      from the remote PTY → emitted on a per-session Tauri
//!      event the WebviewWindow subscribes to; keystrokes from
//!      the WebviewWindow → pushed through an mpsc channel into
//!      the russh data writer.
//!   3. The session lives until any of: the operator closes the
//!      window (frontend calls `session_close`), the remote PTY
//!      sends EOF, the russh connection drops, or the host
//!      receives a panic in the worker task.

use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, Config, Handler};
use russh::keys::{decode_secret_key, PrivateKeyWithHashAlg, PublicKey};
use russh::ChannelMsg;
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::{SessionCleanup, SessionState, SshControl, SshSessionState};

/// What the caller needs to give us to drive a Phase-3 SSH
/// session. The credential bytes are wrapped in `Zeroizing` so
/// they're cleared on drop; they only survive long enough for
/// `russh::authenticate_*` to consume them.
pub struct SshOpenArgs {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub credential: SshCredential,
    /// Pinned host-key fingerprint (`SHA256:<base64>`); empty
    /// accepts any key on first connect (TOFU-without-pinning).
    pub host_key_fingerprint: String,
    /// The label rendered in the Tauri WebviewWindow title bar +
    /// emitted on the audit event. Format: `ssh user@host:port`.
    pub label: String,
    /// Optional cleanup task to run when the session closes
    /// (LDAP library check-in is the only kind today). Stored on
    /// the session record so `session_close` + the
    /// WindowEvent::CloseRequested hook can both fire it.
    pub on_close: Option<SessionCleanup>,
}

#[derive(Clone)]
pub enum SshCredential {
    Password(Zeroizing<String>),
    PrivateKey {
        pem: Zeroizing<String>,
        passphrase: Option<Zeroizing<String>>,
    },
}

#[derive(Debug, Serialize, Clone)]
pub struct SshOpenOutcome {
    /// Per-session token the spawned WebviewWindow uses to claim
    /// its session via `session_input` / `session_resize` /
    /// `session_close`.
    pub token: String,
    /// Tauri event channel name the spawned WebviewWindow
    /// subscribes to for stdout bytes. One event per chunk; the
    /// payload is the raw bytes (base64 to keep JSON honest).
    pub stdout_event: String,
    /// Tauri event the host emits when the remote PTY closes or
    /// the connection drops, so the WebviewWindow can show
    /// "disconnected" rather than wait forever.
    pub closed_event: String,
}

/// Mint a fresh per-session token. Also drives the event channel
/// names so they're scoped to the session and don't bleed across
/// concurrent windows.
pub fn new_token() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes[..]);
    let mut hex = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{b:02x}");
    }
    format!("sess_{hex}")
}

pub fn stdout_event_name(token: &str) -> String {
    format!("session-stdout-{token}")
}

pub fn closed_event_name(token: &str) -> String {
    format!("session-closed-{token}")
}

/// Open the russh connection, request a PTY + interactive shell,
/// spawn the per-session pump task, and register the session on
/// `AppState`. Returns the metadata the spawned WebviewWindow
/// needs to claim the session.
pub async fn open_ssh_session(
    app: AppHandle,
    state: &crate::state::AppState,
    args: SshOpenArgs,
) -> Result<SshOpenOutcome, String> {
    let token = new_token();
    let stdout_event = stdout_event_name(&token);
    let closed_event = closed_event_name(&token);

    // Connect + auth.
    let cfg = Arc::new(Config::default());
    let observed = Arc::new(std::sync::Mutex::new(String::new()));
    let handler = HostKeyHandler {
        expected_fp: args.host_key_fingerprint.clone(),
        observed: observed.clone(),
    };
    let mut session =
        client::connect(cfg, (args.host.as_str(), args.port), handler)
            .await
            .map_err(|e| format!("connect {}:{}: {e}", args.host, args.port))?;

    // Auth — caller already picked one; we just dispatch.
    // russh ≥ 0.51 returns `AuthResult` (carrying success +
    // remaining-method hints) instead of a plain bool, and
    // `authenticate_publickey` takes a `PrivateKeyWithHashAlg`.
    let auth_result = match args.credential {
        SshCredential::Password(pw) => session
            .authenticate_password(&args.username, pw.as_str())
            .await
            .map_err(|e| format!("password auth: {e}"))?,
        SshCredential::PrivateKey { pem, passphrase } => {
            let key = decode_secret_key(pem.as_str(), passphrase.as_deref().map(|p| p.as_str()))
                .map_err(|e| format!("parse private key: {e}"))?;
            let key_arg = PrivateKeyWithHashAlg::new(Arc::new(key), None);
            session
                .authenticate_publickey(&args.username, key_arg)
                .await
                .map_err(|e| format!("publickey auth: {e}"))?
        }
    };
    if !auth_result.success() {
        return Err("ssh: authentication rejected".into());
    }

    // TOFU log if no pin was supplied.
    {
        let fp = observed.lock().map(|g| g.clone()).unwrap_or_default();
        if args.host_key_fingerprint.is_empty() && !fp.is_empty() {
            log::warn!(
                "resource-connect/ssh: accepted unpinned host key for {}:{} — pin {fp} on the profile to lock",
                args.host, args.port
            );
        }
    }

    // Open a channel + request a PTY + start an interactive shell.
    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|e| format!("channel_open_session: {e}"))?;

    // OpenSSH's client sends `no-more-sessions@openssh.com` AFTER
    // the session channel is open as a hardening hint ("I won't
    // open any more sessions on this connection — if you see one,
    // it's a hijack"). Sending it before the channel-open is
    // explicitly treated as an attack by sshd (it disconnects with
    // "Possible attack: attempt to open a session after additional
    // sessions disabled"). want_reply=false so servers that don't
    // recognise the extension just ignore it.
    if let Err(e) = session.no_more_sessions(false).await {
        log::warn!(
            "resource-connect/ssh: no-more-sessions hint failed (continuing): {e:?}"
        );
    }
    // Populated terminal modes blob, mirroring what OpenSSH's
    // client sends. IMPORTANT: do NOT include Pty::TTY_OP_END in
    // this slice — russh's pty-req encoder (client/session.rs)
    // computes the modes-string length prefix as `1 + 5 * len`
    // *before* iterating, but then skips any TTY_OP_END entries
    // and auto-appends a single TTY_OP_END byte. Including
    // TTY_OP_END here therefore makes the declared length 5 bytes
    // longer than the actual modes payload, so sshd reads past
    // the end of the modes string into padding/garbage, sees an
    // invalid mode opcode, and the session child dies — no
    // SSH_MSG_DISCONNECT, just a silent TCP teardown. This is the
    // root cause of the "early eof" we were chasing.
    let modes: &[(russh::Pty, u32)] = &[
        (russh::Pty::VINTR, 3),     // ^C
        (russh::Pty::VQUIT, 28),    // ^\
        (russh::Pty::VERASE, 127),  // DEL
        (russh::Pty::VKILL, 21),    // ^U
        (russh::Pty::VEOF, 4),      // ^D
        (russh::Pty::VEOL, 0),
        (russh::Pty::VSTART, 17),   // ^Q
        (russh::Pty::VSTOP, 19),    // ^S
        (russh::Pty::VSUSP, 26),    // ^Z
        (russh::Pty::VREPRINT, 18), // ^R
        (russh::Pty::VWERASE, 23),  // ^W
        (russh::Pty::VLNEXT, 22),   // ^V
        (russh::Pty::ICRNL, 1),
        (russh::Pty::IXON, 1),
        (russh::Pty::IXANY, 0),
        (russh::Pty::IXOFF, 0),
        (russh::Pty::IMAXBEL, 1),
        (russh::Pty::ISIG, 1),
        (russh::Pty::ICANON, 1),
        (russh::Pty::ECHO, 1),
        (russh::Pty::ECHOE, 1),
        (russh::Pty::ECHOK, 1),
        (russh::Pty::ECHONL, 0),
        (russh::Pty::NOFLSH, 0),
        (russh::Pty::TOSTOP, 0),
        (russh::Pty::IEXTEN, 1),
        (russh::Pty::ECHOCTL, 1),
        (russh::Pty::ECHOKE, 1),
        (russh::Pty::PENDIN, 0),
        (russh::Pty::OPOST, 1),
        (russh::Pty::ONLCR, 1),
        (russh::Pty::TTY_OP_ISPEED, 38400),
        (russh::Pty::TTY_OP_OSPEED, 38400),
        // NOTE: no TTY_OP_END here — russh appends it for us.
    ];
    channel
        .request_pty(true, "xterm-256color", 80, 24, 0, 0, modes)
        .await
        .map_err(|e| format!("request_pty: {e}"))?;
    // russh's request_pty / request_shell are fire-and-forget — they
    // call send_msg and return without awaiting the server's
    // CHANNEL_SUCCESS reply, even when want_reply=true. Most sshd
    // builds tolerate back-to-back channel requests, but some
    // (observed on RHEL/CentOS 8.x sshd 8.7) tear down the TCP
    // connection if shell-req arrives before they've finished
    // replying to pty-req. OpenSSH's client waits for the reply
    // between requests; mirror that here by draining the next
    // ChannelMsg before issuing the shell request. Anything other
    // than Success/Failure is forwarded into a small buffer so the
    // worker loop below picks it up on its first poll.
    let mut pre_shell_buf: Vec<u8> = Vec::new();
    match channel.wait().await {
        Some(ChannelMsg::Success) => {}
        Some(ChannelMsg::Failure) => {
            return Err("ssh: server refused pty-req".into());
        }
        Some(ChannelMsg::Data { data }) => pre_shell_buf.extend_from_slice(&data),
        Some(ChannelMsg::ExtendedData { data, .. }) => {
            pre_shell_buf.extend_from_slice(&data)
        }
        Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
            return Err(
                "ssh: server closed the channel before pty-req completed".into(),
            );
        }
        _ => {}
    }
    channel
        .request_shell(true)
        .await
        .map_err(|e| format!("request_shell: {e}"))?;
    // Drain the shell-req reply the same way so the worker loop
    // starts on the first real PTY byte.
    match channel.wait().await {
        Some(ChannelMsg::Success) => {}
        Some(ChannelMsg::Failure) => {
            return Err("ssh: server refused shell request".into());
        }
        Some(ChannelMsg::Data { data }) => pre_shell_buf.extend_from_slice(&data),
        Some(ChannelMsg::ExtendedData { data, .. }) => {
            pre_shell_buf.extend_from_slice(&data)
        }
        Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
            return Err(
                "ssh: server closed the channel before shell request completed"
                    .into(),
            );
        }
        _ => {}
    }

    // Control channel — the per-session task pumps from here.
    let (tx, mut rx) = mpsc::channel::<SshControl>(64);
    let app_for_task = app.clone();
    let stdout_event_for_task = stdout_event.clone();
    let closed_event_for_task = closed_event.clone();

    tokio::spawn(async move {
        // The WebviewWindow takes a non-trivial amount of wall-time
        // to load + register its `listen()` handler for stdout
        // events — by the time the React effect runs, the remote
        // shell may have already printed its prompt + MOTD into a
        // void. We buffer all PTY bytes that arrive before the
        // window signals readiness, then flush them once the first
        // Resize control message arrives (the React effect always
        // fires a resize immediately after registering the
        // listener, which makes it a reliable "ready" handshake).
        let mut early_buf: Vec<u8> = pre_shell_buf;
        let mut ready = false;
        #[allow(unused_assignments)]
        let mut close_reason: String = "remote host closed the connection".into();

        // Pump loop: select between (1) bytes from russh (forward
        // to the WebviewWindow as a Tauri event) and (2) control
        // messages from the frontend (write to russh / resize / close).
        loop {
            tokio::select! {
                msg = channel.wait() => {
                    match msg {
                        Some(ChannelMsg::Data { data }) => {
                            if ready {
                                let _ = app_for_task.emit(
                                    &stdout_event_for_task,
                                    ChunkPayload { bytes_b64: encode_b64(&data) },
                                );
                            } else {
                                early_buf.extend_from_slice(&data);
                            }
                        }
                        Some(ChannelMsg::ExtendedData { data, .. }) => {
                            // stderr — surface it on the same channel.
                            if ready {
                                let _ = app_for_task.emit(
                                    &stdout_event_for_task,
                                    ChunkPayload { bytes_b64: encode_b64(&data) },
                                );
                            } else {
                                early_buf.extend_from_slice(&data);
                            }
                        }
                        Some(ChannelMsg::Eof) => {
                            close_reason = "remote sent EOF".into();
                            break;
                        }
                        Some(ChannelMsg::Close) => {
                            close_reason = "remote closed the channel".into();
                            break;
                        }
                        None => {
                            close_reason = "ssh transport closed (TCP EOF / disconnect before shell was ready)".into();
                            break;
                        }
                        Some(ChannelMsg::ExitStatus { exit_status }) => {
                            // Status arrives before Eof/Close; the
                            // following message in the stream will
                            // break the loop with the right reason.
                            log::info!(
                                "resource-connect/ssh: remote exit status {exit_status}"
                            );
                        }
                        Some(ChannelMsg::ExitSignal { signal_name, error_message, .. }) => {
                            log::info!(
                                "resource-connect/ssh: remote exit signal {signal_name:?} ({error_message})"
                            );
                        }
                        _ => {}
                    }
                }
                ctl = rx.recv() => {
                    match ctl {
                        Some(SshControl::Data(bytes)) => {
                            if let Err(e) = channel.data(&bytes[..]).await {
                                log::warn!(
                                    "resource-connect/ssh: write to channel failed: {e:?}"
                                );
                                close_reason = format!("write to ssh channel failed: {e}");
                                break;
                            }
                        }
                        Some(SshControl::Resize { cols, rows }) => {
                            if let Err(e) = channel
                                .window_change(cols as u32, rows as u32, 0, 0)
                                .await
                            {
                                log::warn!(
                                    "resource-connect/ssh: window_change failed: {e:?}"
                                );
                            }
                            // First Resize doubles as the "frontend
                            // listener is live" signal: drain the
                            // early-bytes buffer in one emit and
                            // flip to live mode.
                            if !ready {
                                ready = true;
                                if !early_buf.is_empty() {
                                    let _ = app_for_task.emit(
                                        &stdout_event_for_task,
                                        ChunkPayload {
                                            bytes_b64: encode_b64(&early_buf),
                                        },
                                    );
                                    early_buf.clear();
                                    early_buf.shrink_to_fit();
                                }
                            }
                        }
                        Some(SshControl::Close) => {
                            close_reason = "operator closed the session".into();
                            let _ = channel.eof().await;
                            break;
                        }
                        None => {
                            close_reason = "session control channel dropped".into();
                            let _ = channel.eof().await;
                            break;
                        }
                    }
                }
            }
        }
        log::info!(
            "resource-connect/ssh: worker exiting — reason: {close_reason}"
        );
        // Fire the closed event so the WebviewWindow shows
        // "disconnected" instead of waiting forever. The worker can
        // exit before the React listener has subscribed (a server
        // that drops the connection right after the shell request
        // is the worst case: pty-req + shell-req succeed, the
        // window spawns, but by the time React mounts the worker is
        // already gone). Re-emit a couple of times on a short delay
        // so the frontend picks it up no matter when its listener
        // came online.
        let payload = ClosedPayload { reason: close_reason };
        let _ = app_for_task.emit(&closed_event_for_task, payload.clone());
        let app_for_replay = app_for_task.clone();
        let evt_for_replay = closed_event_for_task.clone();
        let payload_for_replay = payload.clone();
        tokio::spawn(async move {
            for delay in [200u64, 800, 2500] {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                let _ = app_for_replay.emit(&evt_for_replay, payload_for_replay.clone());
            }
        });
        let _ = session
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await;
    });

    // Register the session on AppState so subsequent commands
    // (input/resize/close) can find the control tx.
    {
        let mut sessions = state.connect_sessions.lock().await;
        sessions.insert(
            token.clone(),
            SessionState::Ssh(SshSessionState {
                input_tx: tx,
                label: args.label.clone(),
                on_close: args.on_close.clone(),
            }),
        );
    }

    log::info!(
        "resource-connect/ssh: opened session token={token} label={} ({}:{})",
        args.label, args.host, args.port
    );

    Ok(SshOpenOutcome {
        token,
        stdout_event,
        closed_event,
    })
}

#[derive(Serialize, Clone)]
struct ClosedPayload {
    /// Human-readable reason the session ended. Surfaced in the
    /// session window's status bar so the operator can tell apart
    /// "I clicked Disconnect" from "the server killed it during
    /// PAM" without having to dig into logs.
    reason: String,
}

#[derive(Serialize, Clone)]
struct ChunkPayload {
    /// Base64 — the raw PTY bytes, including escape sequences.
    /// xterm.js's `terminal.write` accepts UTF-8 strings, so the
    /// frontend decodes from b64 → Uint8Array → TextDecoder before
    /// passing the result in.
    bytes_b64: String,
}

fn encode_b64(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(bytes)
}

/// Decode the base64 the frontend sent on `session_input`. Mirrors
/// the encoding direction we use for stdout.
pub fn decode_b64(b64: &str) -> Result<Vec<u8>, String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| format!("base64 decode: {e}"))
}

struct HostKeyHandler {
    expected_fp: String,
    observed: Arc<std::sync::Mutex<String>>,
}

// russh ≥ 0.59 dropped `#[async_trait]` on `Handler` in favour of
// return-position `impl Future`. The async-fn-in-trait sugar makes the
// implementation read identically to the previous version.
impl Handler for HostKeyHandler {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let fp = openssh_sha256_fingerprint(server_public_key);
        if let Ok(mut g) = self.observed.lock() {
            *g = fp.clone();
        }
        if self.expected_fp.is_empty() {
            return Ok(true);
        }
        Ok(fp == self.expected_fp)
    }
}

fn openssh_sha256_fingerprint(key: &PublicKey) -> String {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use russh::keys::PublicKeyBase64;
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(&key.public_key_bytes());
    format!("SHA256:{}", STANDARD_NO_PAD.encode(h.finalize()))
}

/// Push a control message into a session's control channel. Used by
/// the `session_input` / `session_resize` / `session_close` Tauri
/// commands.
pub async fn send_control(
    state: &crate::state::AppState,
    token: &str,
    ctl: SshControl,
) -> Result<(), String> {
    let sessions = state.connect_sessions.lock().await;
    match sessions.get(token) {
        Some(SessionState::Ssh(s)) => s
            .input_tx
            .send(ctl)
            .await
            .map_err(|_| "session control channel closed".to_string()),
        Some(_) => Err(format!(
            "session `{token}` is not an SSH session (cannot route SSH control message)"
        )),
        None => Err(format!("session token `{token}` not found")),
    }
}

/// Drop a session from AppState. Called on `session_close` and on
/// the `session-closed` event the worker emits when the remote
/// PTY hangs up.
/// Drop a session from `connect_sessions` and fire any cleanup
/// hook captured at open time. Returns the captured hook (if any)
/// so the caller can run it through the appropriate context (the
/// LDAP library check-in needs the AppHandle + token).
pub async fn drop_session(
    state: &crate::state::AppState,
    token: &str,
) -> Option<SessionCleanup> {
    let mut sessions = state.connect_sessions.lock().await;
    let removed = sessions.remove(token);
    drop(sessions);
    match removed {
        Some(SessionState::Ssh(s)) => {
            log::info!("resource-connect/ssh: closed session token={token}");
            s.on_close
        }
        Some(SessionState::Rdp(s)) => {
            log::info!("resource-connect/ssh: dropped (was RDP) token={token}");
            s.on_close
        }
        None => None,
    }
}

/// Time budget for the whole connect+auth phase. Beyond this we
/// give up and report a clear timeout to the operator. 30s lines
/// up with the SMB transport's posture.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
