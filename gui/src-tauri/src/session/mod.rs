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

pub mod attachments;
pub mod close_guard;
pub mod layouts;
pub mod output;
pub mod rdp;
pub mod rdp_clipboard;
pub mod routing;
pub mod sk_signer;
pub mod ssh;
pub mod web;
pub mod web_chrome;
pub mod web_engine;
pub mod web_http_auth;
pub mod web_launch;
pub mod web_recipe;
pub mod web_script;
pub mod web_tls_pin;
pub mod workspace;

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
    /// grant. Nothing to pump; the entry exists so teardown (the form-mode
    /// launch's `result` / `close`, data-dir removal, the close audit line)
    /// runs through the same registry. A `web_recipe_test` dry-run window is
    /// one too, so it counts for the web/RDP exclusion.
    Web(web::WebSessionState),
}

impl SessionState {
    /// Which protocol this registry entry belongs to.
    pub fn protocol(&self) -> ProfileProtocol {
        match self {
            Self::Ssh(_) => ProfileProtocol::Ssh,
            Self::Rdp(_) => ProfileProtocol::Rdp,
            Self::Web(_) => ProfileProtocol::Web,
        }
    }
}

/// Why a session of one kind may not start while a session of the other is
/// live (see [`web_rdp_conflict`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebRdpConflict {
    /// Stable `reason=` token for the host audit line.
    pub audit_reason: &'static str,
    /// Operator-facing refusal.
    pub message: String,
}

/// Web / RDP mutual exclusion.
///
/// Tauri 2.11.5 exempts `plugin:__TAURI_CHANNEL__|fetch` from the
/// remote-origin ACL, so a hostile page in a `web-*` window could poll
/// sequential channel ids and read payloads queued for another session's
/// `tauri::ipc::Channel`. The only channel users are the RDP frame path
/// (`session_attach_rdp_frames`, `session::rdp::FrameSink`), so a web
/// session and an RDP session are never allowed to be live together. This
/// is the pure predicate; callers evaluate it while holding the
/// `connect_sessions` lock at the point of registration so two concurrent
/// opens cannot both pass. Remove this once upstream drops the exemption.
/// See features/web-application-connect.md, Security Considerations.
///
/// `opening` is the kind of session about to start; `live` are the kinds
/// already registered. SSH sessions never conflict.
pub fn web_rdp_conflict(
    opening: ProfileProtocol,
    live: impl IntoIterator<Item = ProfileProtocol>,
) -> Option<WebRdpConflict> {
    let other = match opening {
        ProfileProtocol::Web => ProfileProtocol::Rdp,
        ProfileProtocol::Rdp => ProfileProtocol::Web,
        ProfileProtocol::Ssh => return None,
    };
    if !live.into_iter().any(|p| p == other) {
        return None;
    }
    Some(match opening {
        ProfileProtocol::Web => WebRdpConflict {
            audit_reason: "rdp_session_live",
            message: "an RDP session is open; close it before opening a web application session. Web and RDP \
                 sessions cannot run at the same time because the webview's IPC channel transport cannot yet \
                 isolate the RDP desktop stream from web content"
                .to_string(),
        },
        _ => WebRdpConflict {
            audit_reason: "web_session_live",
            message: "a web application session is open; close it before opening an RDP session. Web and RDP \
                 sessions cannot run at the same time because the webview's IPC channel transport cannot yet \
                 isolate the RDP desktop stream from web content"
                .to_string(),
        },
    })
}

/// [`web_rdp_conflict`] over a `connect_sessions` map. Call with the lock held.
pub fn registry_web_rdp_conflict(
    opening: ProfileProtocol,
    sessions: &std::collections::HashMap<String, SessionState>,
) -> Option<WebRdpConflict> {
    web_rdp_conflict(opening, sessions.values().map(SessionState::protocol))
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
/// the `(mount, set, account)` tuple needed to call
/// `<mount>/library/<set>/check-in` (the engine keys check-in on
/// `account`; `lease_id` is kept for log correlation only).
#[derive(Clone, Debug)]
pub struct SessionCleanup {
    pub kind: SessionCleanupKind,
}

#[derive(Clone, Debug)]
pub enum SessionCleanupKind {
    LdapLibraryCheckIn { ldap_mount: String, library_set: String, account: String, lease_id: String },
}

#[derive(Debug, Clone)]
pub enum SshControl {
    /// Bytes from the local terminal heading to the remote PTY.
    Data(Vec<u8>),
    /// Window resize from the local terminal. `epoch` is the holder epoch
    /// the resize was authorised at (`attachments::AttachmentRegistry::
    /// route_epoch`); the first resize a holder sends at an epoch is its
    /// listener handshake (`session::output`).
    Resize { cols: u16, rows: u16, epoch: u64 },
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

#[cfg(test)]
mod web_rdp_exclusion_tests {
    use super::{web_rdp_conflict, ProfileProtocol::*};

    #[test]
    fn web_is_refused_while_rdp_is_live() {
        let c = web_rdp_conflict(Web, [Ssh, Rdp]).unwrap();
        assert_eq!(c.audit_reason, "rdp_session_live");
        assert!(c.message.contains("RDP session is open"), "{}", c.message);
    }

    #[test]
    fn rdp_is_refused_while_web_is_live() {
        let c = web_rdp_conflict(Rdp, [Web]).unwrap();
        assert_eq!(c.audit_reason, "web_session_live");
        assert!(c.message.contains("web application session is open"), "{}", c.message);
    }

    #[test]
    fn same_kind_ssh_and_empty_registries_do_not_conflict() {
        assert_eq!(web_rdp_conflict(Web, [Web, Ssh]), None);
        assert_eq!(web_rdp_conflict(Rdp, [Rdp, Ssh]), None);
        assert_eq!(web_rdp_conflict(Web, []), None);
        assert_eq!(web_rdp_conflict(Rdp, []), None);
        // SSH never conflicts, whatever is live.
        assert_eq!(web_rdp_conflict(Ssh, [Web, Rdp]), None);
    }
}
