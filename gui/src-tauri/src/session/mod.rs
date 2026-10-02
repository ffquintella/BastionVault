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
pub mod rdp_clipboard;
pub mod sk_signer;
pub mod ssh;
pub mod web;

use tokio::sync::mpsc;

/// A connection profile's `protocol`, parsed strictly.
///
/// Profiles are opaque JSON on the resource record, so a value this build
/// doesn't know (a profile written by a newer GUI, or by hand) is possible.
/// It is an error, never a default: a `web` profile read by code that
/// assumed `ssh` would dial its URL's host over SSH with whatever credential
/// source the profile names. See features/web-application-connect.md §1,
/// "Strict parsing / old clients".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileProtocol {
    Ssh,
    Rdp,
    Web,
}

impl ProfileProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
            Self::Web => "web",
        }
    }

    /// Parse `profile.protocol`. Missing, non-string and unknown values are
    /// all errors.
    pub fn of_profile(profile: &serde_json::Value) -> Result<Self, String> {
        match profile.get("protocol") {
            Some(serde_json::Value::String(s)) => match s.as_str() {
                "ssh" => Ok(Self::Ssh),
                "rdp" => Ok(Self::Rdp),
                "web" => Ok(Self::Web),
                other => Err(format!(
                    "connection profile has unknown protocol `{other}`; refusing to guess (this client \
                     supports ssh, rdp and web)"
                )),
            },
            Some(_) => Err("connection profile `protocol` is not a string".to_string()),
            None => Err("connection profile has no `protocol`".to_string()),
        }
    }

    /// Require `profile.protocol == expected`. Each `session_open_*`
    /// command calls this first, so a profile id handed to the wrong
    /// command is refused before anything is resolved or dialled.
    pub fn require(profile: &serde_json::Value, expected: Self) -> Result<(), String> {
        let actual = Self::of_profile(profile)?;
        if actual != expected {
            return Err(format!(
                "connection profile is a `{}` profile, not `{}`; refusing to open it as {}",
                actual.as_str(),
                expected.as_str(),
                expected.as_str(),
            ));
        }
        Ok(())
    }
}

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
    /// and forwards bitmap updates back to the WebviewWindow over
    /// a binary IPC channel the window installs on mount.
    Rdp(RdpSessionState),
    /// Web application session (T96) — an external-URL window with no IPC
    /// grant. Nothing to pump; the entry exists so teardown (data-dir
    /// removal, the close audit line) runs through the same registry.
    Web(web::WebSessionState),
}

pub struct RdpSessionState {
    /// Tx side of the input channel. Frontend `session_input_rdp_*`
    /// commands push control messages here; the spawned task awaits
    /// on the rx side and translates to fast-path PDUs.
    pub input_tx: tokio::sync::mpsc::Sender<rdp::RdpControl>,
    /// Where the pump sends packed canvas frames. Empty until the
    /// session window calls `session_attach_rdp_frames` with the IPC
    /// channel it created; see [`rdp::FrameSink`].
    pub frames: std::sync::Arc<std::sync::Mutex<rdp::FrameSink>>,
    /// Operator-visible window title + future audit close-event
    /// payload.
    #[allow(dead_code)]
    pub label: String,
    /// Mirror of `SshSessionState::on_close` — see that field for
    /// the full rationale.
    pub on_close: Option<SessionCleanup>,
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
    /// Optional cleanup task to run on session-close. Used by
    /// the LDAP library credential source to check the account
    /// back into its set so the next operator can claim it.
    pub on_close: Option<SessionCleanup>,
}

/// Library check-in payload — captured at connect time, executed
/// from `session_close` (or the WebviewWindow close hook). Keeps
/// the `(mount, set, lease_id)` tuple needed to call
/// `<mount>/library/<set>/check-in`.
#[derive(Clone, Debug)]
pub struct SessionCleanup {
    pub kind: SessionCleanupKind,
}

#[derive(Clone, Debug)]
pub enum SessionCleanupKind {
    LdapLibraryCheckIn {
        ldap_mount: String,
        library_set: String,
        lease_id: String,
    },
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

#[cfg(test)]
mod profile_protocol_tests {
    use super::ProfileProtocol;
    use serde_json::json;

    #[test]
    fn known_protocols_parse() {
        assert_eq!(ProfileProtocol::of_profile(&json!({ "protocol": "ssh" })), Ok(ProfileProtocol::Ssh));
        assert_eq!(ProfileProtocol::of_profile(&json!({ "protocol": "rdp" })), Ok(ProfileProtocol::Rdp));
        assert_eq!(ProfileProtocol::of_profile(&json!({ "protocol": "web" })), Ok(ProfileProtocol::Web));
    }

    /// Pins the fail-closed rule: an unknown, missing or mistyped protocol
    /// is an error. Nothing may fall back to `ssh`.
    #[test]
    fn unknown_missing_or_mistyped_protocol_fails_closed() {
        for p in [
            json!({ "protocol": "telnet" }),
            json!({ "protocol": "SSH" }),
            json!({ "protocol": "" }),
            json!({ "protocol": 22 }),
            json!({ "protocol": null }),
            json!({}),
        ] {
            assert!(ProfileProtocol::of_profile(&p).is_err(), "{p}");
            assert!(ProfileProtocol::require(&p, ProfileProtocol::Ssh).is_err(), "{p}");
        }
    }

    #[test]
    fn require_refuses_a_profile_of_another_protocol() {
        let web = json!({ "protocol": "web" });
        let err = ProfileProtocol::require(&web, ProfileProtocol::Ssh).unwrap_err();
        assert!(err.contains("`web` profile"), "{err}");
        assert!(ProfileProtocol::require(&web, ProfileProtocol::Rdp).is_err());
        assert!(ProfileProtocol::require(&web, ProfileProtocol::Web).is_ok());
        assert!(ProfileProtocol::require(&json!({ "protocol": "rdp" }), ProfileProtocol::Ssh).is_err());
    }
}
