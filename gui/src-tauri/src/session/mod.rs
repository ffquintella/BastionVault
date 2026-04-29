//! Resource Connect session module.
//!
//! Per-session state lives on `AppState::connect_sessions`, keyed by
//! a one-shot token handed to the spawned WebviewWindow. The
//! window's React route ([`SessionSshWindow.tsx`]) claims its
//! session via that token and drives the PTY through the Tauri
//! `session_input` / `session_resize` / `session_close` commands.
//!
//! Phase 3 implements the SSH side (`secret` credential source).
//! RDP (`ironrdp` + `<canvas>`) is Phase 4; LDAP / SSH-engine / PKI
//! credential sources land in Phases 5–6.

pub mod rdp;
pub mod ssh;

use tokio::sync::mpsc;

/// One live Resource-Connect session. Drops when the
/// WebviewWindow closes (the `session_close` command removes the
/// entry from `AppState::connect_sessions`).
pub enum SessionState {
    /// SSH session — owns the russh client handle (kept alive by
    /// the spawned task) and a tx channel the per-keystroke
    /// `session_input` command pumps into.
    Ssh(SshSessionState),
    /// RDP session — owns the active-stage pump task's tx side.
    /// The pump translates control messages into fast-path PDUs
    /// and forwards bitmap updates back to the WebviewWindow as
    /// per-session Tauri events.
    Rdp(RdpSessionState),
}

pub struct RdpSessionState {
    /// Tx side of the input channel. Frontend `session_input_rdp_*`
    /// commands push control messages here; the spawned task awaits
    /// on the rx side and translates to fast-path PDUs.
    pub input_tx: tokio::sync::mpsc::Sender<rdp::RdpControl>,
    /// Operator-visible window title + future audit close-event
    /// payload.
    #[allow(dead_code)]
    pub label: String,
}

pub struct SshSessionState {
    /// Tx side of the input channel. Frontend `session_input`
    /// pushes a Vec<u8> here; the spawned task awaits on the rx
    /// side and writes into the russh channel.
    pub input_tx: mpsc::Sender<SshControl>,
    /// For the `Disconnect` button + the future audit close
    /// event. Read by Phase 7's session-history surface; allow
    /// dead_code until that lands.
    #[allow(dead_code)]
    pub label: String,
}

#[derive(Debug, Clone)]
pub enum SshControl {
    /// Bytes from the local terminal heading to the remote PTY.
    Data(Vec<u8>),
    /// Window resize from the local terminal.
    Resize { cols: u16, rows: u16 },
    /// Operator clicked Disconnect or closed the WebviewWindow.
    Close,
}
