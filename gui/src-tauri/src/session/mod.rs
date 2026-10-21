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
pub mod replays;
pub mod routing;
pub mod sftp;
pub mod sk_signer;
pub mod ssh;
pub mod web;
pub mod web_chrome;
pub mod web_engine;
pub mod web_http_auth;
pub mod web_launch;
pub mod web_load;
pub mod web_nav_bar;
pub mod web_proxy;
pub mod web_proxy_ca;
pub mod web_proxy_listener;
pub mod web_proxy_upstream;
pub mod web_proxy_webview;
pub mod web_recipe;
pub mod web_script;
pub mod web_tls_pin;
pub mod web_tls_prompt;
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
    /// SSH transport with the `sftp` subsystem: the dual-pane file
    /// transfer window (features/sftp-connect.md).
    Sftp,
}

impl ProfileProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
            Self::Web => "web",
            Self::Sftp => "sftp",
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
                "sftp" => Ok(Self::Sftp),
                other => Err(format!(
                    "connection profile has unknown protocol `{other}`; refusing to guess (this client \
                     supports ssh, sftp, rdp and web)"
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
    /// SFTP session (features/sftp-connect.md) — the live `SftpSession`
    /// the dual-pane window's `sftp_*` commands drive, and the SSH
    /// connection under it.
    Sftp(sftp::SftpSessionState),
}

impl SessionState {
    /// Which protocol this registry entry belongs to.
    pub fn protocol(&self) -> ProfileProtocol {
        match self {
            Self::Ssh(_) => ProfileProtocol::Ssh,
            Self::Rdp(_) => ProfileProtocol::Rdp,
            Self::Web(_) => ProfileProtocol::Web,
            Self::Sftp(_) => ProfileProtocol::Sftp,
        }
    }
}

/// Why a session of one kind may not start while a session of the other is
/// live (see [`web_channel_conflict`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebChannelConflict {
    /// Stable `reason=` token for the host audit line.
    pub audit_reason: &'static str,
    /// Operator-facing refusal.
    pub message: String,
}

/// Back-compat alias for [`WebChannelConflict`] — the type was called
/// `WebRdpConflict` before T111 extended it to SSH. New code uses the
/// new name.
pub type WebRdpConflict = WebChannelConflict;

/// Web / `Channel`-using-session mutual exclusion.
///
/// Tauri 2.11.5 exempts `plugin:__TAURI_CHANNEL__|fetch` from the
/// remote-origin ACL, so a hostile page in a `web-*` window could poll
/// sequential channel ids and read payloads queued for another session's
/// `tauri::ipc::Channel`. Before T111 the only channel user was the RDP
/// frame path (`session_attach_rdp_frames`, `session::rdp::FrameSink`),
/// so only RDP and web had to be mutually exclusive. T111 moves SSH
/// output onto a per-webview channel too (`session_attach_ssh_output`,
/// `session::output::SshOutputSink`), so SSH joins the exclusion: web
/// cannot run while SSH or RDP is live, and vice versa. The predicate
/// is pure; callers evaluate it while holding the `connect_sessions`
/// lock at the point of registration so two concurrent opens cannot
/// both pass. Remove this once upstream drops the exemption. See
/// features/web-application-connect.md and features/session-workspace.md
/// (§"T111").
///
/// `opening` is the kind of session about to start; `live` are the kinds
/// already registered. SFTP sessions never conflict — their transport is
/// SSH but no `tauri::ipc::Channel` carries any of their data.
pub fn web_channel_conflict(
    opening: ProfileProtocol,
    live: impl IntoIterator<Item = ProfileProtocol>,
) -> Option<WebChannelConflict> {
    let live: Vec<ProfileProtocol> = live.into_iter().collect();
    match opening {
        // Opening a web session is refused while any Channel-using session
        // (RDP or SSH) is live, because that live session's channel ids
        // would be reachable from the new web window.
        ProfileProtocol::Web => {
            let rdp_live = live.iter().any(|p| *p == ProfileProtocol::Rdp);
            let ssh_live = live.iter().any(|p| *p == ProfileProtocol::Ssh);
            if !rdp_live && !ssh_live {
                return None;
            }
            Some(WebChannelConflict {
                audit_reason: if rdp_live { "rdp_session_live" } else { "ssh_session_live" },
                message: if rdp_live {
                    "an RDP session is open; close it before opening a web application session. Web and RDP \
                     sessions cannot run at the same time because the webview's IPC channel transport cannot yet \
                     isolate the RDP desktop stream from web content"
                        .to_string()
                } else {
                    "an SSH session is open; close it before opening a web application session. Web and SSH \
                     sessions cannot run at the same time because the webview's IPC channel transport cannot yet \
                     isolate SSH output from web content"
                        .to_string()
                },
            })
        }
        // Opening an RDP or SSH session is refused while a web session is
        // live, same reason in the other direction.
        ProfileProtocol::Rdp | ProfileProtocol::Ssh => {
            if !live.iter().any(|p| *p == ProfileProtocol::Web) {
                return None;
            }
            Some(WebChannelConflict {
                audit_reason: "web_session_live",
                message: match opening {
                    ProfileProtocol::Rdp => "a web application session is open; close it before opening an RDP \
                                             session. Web and RDP sessions cannot run at the same time because \
                                             the webview's IPC channel transport cannot yet isolate the RDP \
                                             desktop stream from web content"
                        .to_string(),
                    _ => "a web application session is open; close it before opening an SSH session. Web and \
                          SSH sessions cannot run at the same time because the webview's IPC channel transport \
                          cannot yet isolate SSH output from web content"
                        .to_string(),
                },
            })
        }
        ProfileProtocol::Sftp => None,
    }
}

/// Back-compat alias for [`web_channel_conflict`].
#[allow(dead_code)]
pub fn web_rdp_conflict(
    opening: ProfileProtocol,
    live: impl IntoIterator<Item = ProfileProtocol>,
) -> Option<WebChannelConflict> {
    web_channel_conflict(opening, live)
}

/// [`web_channel_conflict`] over a `connect_sessions` map. Call with
/// the lock held.
pub fn registry_web_channel_conflict(
    opening: ProfileProtocol,
    sessions: &std::collections::HashMap<String, SessionState>,
) -> Option<WebChannelConflict> {
    web_channel_conflict(opening, sessions.values().map(SessionState::protocol))
}

/// Back-compat alias for [`registry_web_channel_conflict`].
pub fn registry_web_rdp_conflict(
    opening: ProfileProtocol,
    sessions: &std::collections::HashMap<String, SessionState>,
) -> Option<WebChannelConflict> {
    registry_web_channel_conflict(opening, sessions)
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
    /// Where the pump sends terminal output chunks. Empty until the
    /// holding window calls `session_attach_ssh_output` with the IPC
    /// channel it created (T111). See [`output::SshOutputSink`].
    pub output_sink: std::sync::Arc<std::sync::Mutex<output::SshOutputSink>>,
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
        assert_eq!(ProfileProtocol::of_profile(&json!({ "protocol": "sftp" })), Ok(ProfileProtocol::Sftp));
    }

    /// An `sftp` profile is never opened as an SSH shell, nor the reverse:
    /// each `session_open_*` command requires its own protocol.
    #[test]
    fn sftp_and_ssh_profiles_are_not_interchangeable() {
        let sftp = json!({ "protocol": "sftp" });
        assert!(ProfileProtocol::require(&sftp, ProfileProtocol::Ssh).is_err());
        assert!(ProfileProtocol::require(&sftp, ProfileProtocol::Sftp).is_ok());
        assert!(ProfileProtocol::require(&json!({ "protocol": "ssh" }), ProfileProtocol::Sftp).is_err());
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
mod web_channel_exclusion_tests {
    use super::{web_channel_conflict, ProfileProtocol::*};

    #[test]
    fn web_is_refused_while_rdp_is_live() {
        let c = web_channel_conflict(Web, [Sftp, Rdp]).unwrap();
        assert_eq!(c.audit_reason, "rdp_session_live");
        assert!(c.message.contains("RDP session is open"), "{}", c.message);
    }

    #[test]
    fn web_is_refused_while_ssh_is_live() {
        // T111: SSH joined the exclusion because its output moved onto a
        // per-webview Channel too.
        let c = web_channel_conflict(Web, [Ssh]).unwrap();
        assert_eq!(c.audit_reason, "ssh_session_live");
        assert!(c.message.contains("SSH session is open"), "{}", c.message);
    }

    #[test]
    fn rdp_is_refused_while_web_is_live() {
        let c = web_channel_conflict(Rdp, [Web]).unwrap();
        assert_eq!(c.audit_reason, "web_session_live");
        assert!(c.message.contains("web application session is open"), "{}", c.message);
        assert!(c.message.contains("RDP"), "{}", c.message);
    }

    #[test]
    fn ssh_is_refused_while_web_is_live() {
        // T111: SSH + web is now also mutually exclusive.
        let c = web_channel_conflict(Ssh, [Web]).unwrap();
        assert_eq!(c.audit_reason, "web_session_live");
        assert!(c.message.contains("web application session is open"), "{}", c.message);
        assert!(c.message.contains("SSH"), "{}", c.message);
    }

    #[test]
    fn rdp_prevails_over_ssh_in_the_refusal_reason_when_both_are_live() {
        // Deterministic reason: when a new web open sees both an RDP and an
        // SSH session, we name RDP (the longer-standing exclusion).
        let c = web_channel_conflict(Web, [Ssh, Rdp]).unwrap();
        assert_eq!(c.audit_reason, "rdp_session_live");
    }

    #[test]
    fn same_kind_sftp_and_empty_registries_do_not_conflict() {
        assert_eq!(web_channel_conflict(Web, [Web, Sftp]), None);
        assert_eq!(web_channel_conflict(Rdp, [Rdp, Sftp]), None);
        assert_eq!(web_channel_conflict(Ssh, [Ssh, Sftp]), None);
        assert_eq!(web_channel_conflict(Web, []), None);
        assert_eq!(web_channel_conflict(Rdp, []), None);
        assert_eq!(web_channel_conflict(Ssh, []), None);
        // SFTP has no Channel; nothing it does conflicts.
        assert_eq!(web_channel_conflict(Sftp, [Web, Rdp, Ssh]), None);
    }
}
