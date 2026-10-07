//! Session attachment registry: which window renders which live session
//! (features/session-workspace.md §3, T38 Phase 2).
//!
//! Teardown is keyed on this registry rather than on the window that
//! happened to spawn a session. Every exit converges on the same stop path
//! (`stop_session`: control-channel `Close` → `drop_session` → the
//! session's cleanup hook):
//!
//! * pane / Disconnect → `session_close`;
//! * a window closing → every session attached to its label;
//! * a renderer that dies without a close event → the watchdog
//!   (`commands::session_workspace::spawn_watchdog`) or, on macOS, the
//!   web-content-process-terminated hook.
//!
//! A missing `session.close` is an audit signal and, for the LDAP library
//! credential source, an account never checked back in, so the registry is
//! written to make "stopped exactly once" structural: every removal is a
//! `take` under the lock, and only the caller that took an entry stops it.
//! A second path racing the first finds nothing to take.
//!
//! The registry is a plain struct with no Tauri types so the policy —
//! who may attach, when a session counts as orphaned — is unit-tested
//! without a runtime.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::Serialize;

use super::workspace::{Placement, WORKSPACE_WINDOW_LABEL};
use super::{ProfileProtocol, SessionCleanup, SshControl};

/// How often the watchdog looks for orphans.
pub const WATCHDOG_TICK: Duration = Duration::from_secs(30);

/// A shown window that has not heartbeated for this long is treated as
/// having lost its renderer. Windows heartbeat every 15 s, one call per
/// window rather than per pane (`gui/src/lib/sessionHeartbeat.ts`).
///
/// Deliberately not the spec's 60 s: a hidden Chromium page (WebView2) is
/// held to one timer wake-up a minute, so a 60 s threshold would reap a
/// live session whose window had merely been covered. Twelve missed
/// heartbeats is past any throttling cadence while still bounding a leak
/// to minutes, not "until the app exits" as before.
pub const HEARTBEAT_STALE_AFTER: Duration = Duration::from_secs(180);

/// A window that has disappeared is reaped only once its attachment is
/// this old, so the watchdog cannot race a window that is being built
/// right after its session was registered.
pub const WINDOW_GONE_GRACE: Duration = Duration::from_secs(10);

/// A session detached from every window (`session_detach`) is stopped if
/// nothing re-attaches it within this long. Moving a session between
/// windows takes seconds; a detach that never lands must not leave a PTY
/// running with no window.
pub const UNATTACHED_GRACE: Duration = Duration::from_secs(60);

/// What `session_list_open` reports for one live SSH/RDP session.
///
/// Identity and routing only: the token and event names a window needs to
/// drive the session, and the resource/profile it was opened from. No
/// credential, no session output, nothing the connect path resolved.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SessionDescriptor {
    pub token: String,
    /// `ssh` or `rdp` on the wire.
    #[serde(serialize_with = "serialize_protocol")]
    pub protocol: ProfileProtocol,
    pub label: String,
    pub resource_name: String,
    pub profile_id: String,
    /// SSH only.
    pub stdout_event: Option<String>,
    pub closed_event: String,
    /// RDP only.
    pub resize_event: Option<String>,
    /// RDP only.
    pub cursor_event: Option<String>,
    /// RDP only: the desktop size negotiated at open. A later
    /// DisplayControl resize is not tracked here; the frame header is
    /// authoritative for the current size.
    pub width: Option<u16>,
    pub height: Option<u16>,
    /// RFC 3339, UTC.
    pub opened_at: String,
    /// Where the open request asked for the session to render. The
    /// workspace reads it from the listing to decide between a new tab and
    /// a split, because `session://placed` carries no payload.
    pub placement: Placement,
    /// The restore placeholder this session fills (Phase 5), echoed from
    /// the open request's `restore.pane_ref`. An opaque layout id, never a
    /// credential; `None` for an ordinary open.
    pub pane_ref: Option<String>,
    /// The namespace that was active when the session was opened (`""` =
    /// root). Recorded so a saved layout can refuse a restore into another
    /// namespace (Phase 5). Host-side only: not part of the listing.
    #[serde(skip)]
    pub namespace: String,
    /// The vault profile id the session was opened against — the id the
    /// host already treats as the open vault (`last_used_id`, as the local
    /// keystore does). Host-side only.
    #[serde(skip)]
    pub vault_id: String,
}

fn serialize_protocol<S: serde::Serializer>(p: &ProfileProtocol, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(p.as_str())
}

/// One row of `session_list_open`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SessionListing {
    #[serde(flatten)]
    pub descriptor: SessionDescriptor,
    /// Label of the window currently rendering the session; `None` while
    /// it is detached.
    pub attached_to: Option<String>,
    /// Bumped on every change of holder (Phase 6). A window that gave a
    /// session up and later receives it back sees a new epoch, which is
    /// how the workspace tells a session moved back to it from a stale
    /// listing of the pane it already closed.
    pub attach_epoch: u64,
}

#[derive(Debug, Clone)]
pub struct Attachment {
    pub window_label: String,
    pub attached_at: Instant,
    /// Last heartbeat from the rendering window (or the attach itself).
    pub last_seen: Instant,
    /// True once the window has heartbeated at least once. Staleness is
    /// judged only on an armed attachment: a window that has never
    /// heartbeated has never shown it can, and reaping it would turn a
    /// frontend that skipped the heartbeat into a session killer.
    pub heartbeat_armed: bool,
}

#[derive(Debug, Clone)]
struct Entry {
    descriptor: SessionDescriptor,
    attachment: Option<Attachment>,
    /// Set while the entry has no attachment.
    unattached_since: Option<Instant>,
    /// Holder generation: 1 at registration, bumped on every change of
    /// holder (attach to another window, detach, transfer). The SSH pump
    /// delivers output only to the holder of the epoch that completed the
    /// listener handshake (`session::output`), so a window that has just
    /// been handed a session never has output addressed to it before it
    /// is listening.
    epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachOutcome {
    /// The session had no window.
    Attached,
    /// Already attached to this window; the attachment was refreshed.
    /// Idempotent so a remount (React StrictMode) is harmless.
    Refreshed,
    /// The previous holder's window no longer exists.
    TookOver { previous: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachError {
    NotFound,
    /// The caller is not a window that may render this session.
    NotAllowed {
        caller: String,
    },
    /// Another window that still exists holds the session.
    HeldBy {
        holder: String,
    },
    /// The caller asked to hand on a session no window holds.
    NotHeld {
        caller: String,
    },
}

impl AttachError {
    pub fn message(&self, token: &str) -> String {
        match self {
            Self::NotFound => format!("session token `{token}` not found"),
            Self::NotAllowed { caller } => format!(
                "window `{caller}` may not render session `{token}`: a session renders only in its own window or \
                 in the Session Workspace"
            ),
            Self::HeldBy { holder } => {
                format!("session `{token}` is attached to window `{holder}`; detach it there first")
            }
            Self::NotHeld { caller } => {
                format!("window `{caller}` does not hold session `{token}`; no window does")
            }
        }
    }
}

/// Whether `label` may render the session: its own window or the
/// workspace, never `main`, a plugin, a web window or another session's
/// window. The one rule `attach` and `transfer` share.
fn may_render(protocol: ProfileProtocol, token: &str, label: &str) -> bool {
    label == WORKSPACE_WINDOW_LABEL || label == own_window_label(protocol, token)
}

/// What the watchdog knows about one window at the start of a tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowState {
    /// No window with this label exists any more.
    Missing,
    /// Visible and not minimised: its timers run, so a missing heartbeat
    /// means a dead renderer.
    Shown,
    /// Minimised or hidden: the OS may throttle or suspend the page, so a
    /// missing heartbeat proves nothing.
    Hidden,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReapReason {
    WindowGone,
    HeartbeatStale,
    Unattached,
}

impl ReapReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WindowGone => "window_gone",
            Self::HeartbeatStale => "heartbeat_stale",
            Self::Unattached => "unattached",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ReapPolicy {
    pub heartbeat_stale_after: Duration,
    pub window_gone_grace: Duration,
    pub unattached_grace: Duration,
    /// Whether a stale heartbeat on a shown window reaps. Off on macOS,
    /// where WebKit can suspend an occluded window's page with no signal
    /// to the host; there a dead renderer is caught by the
    /// web-content-process-terminated hook instead, which is exact.
    pub judge_heartbeats: bool,
}

impl ReapPolicy {
    pub fn for_this_platform() -> Self {
        Self {
            heartbeat_stale_after: HEARTBEAT_STALE_AFTER,
            window_gone_grace: WINDOW_GONE_GRACE,
            unattached_grace: UNATTACHED_GRACE,
            judge_heartbeats: cfg!(not(target_os = "macos")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reaped {
    pub token: String,
    pub window_label: Option<String>,
    pub reason: ReapReason,
    /// Time since the last sign of life the reason is judged on.
    pub idle: Duration,
}

/// Where a session's host→window traffic goes, and whose input it takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// No registry entry: never registered, or already stopped.
    Unknown,
    /// Registered, but no window holds it (in transit between windows).
    Detached,
    /// Held by this window label.
    Attached(String),
}

/// Whether `caller` may drive the session on `route` — keystrokes, paste,
/// resize, pointer, the RDP frame channel. Only the window that holds the
/// session: a token is enough to drive a session, and with a shared
/// workspace realm and plugin windows that have IPC, knowing one must not
/// be enough. Fails closed on a session the registry does not know.
pub fn authorize_input(route: &Route, caller: &str, token: &str) -> Result<(), String> {
    match route {
        Route::Attached(holder) if holder == caller => Ok(()),
        Route::Attached(holder) => {
            Err(format!("session `{token}` is rendered by window `{holder}`; input from window `{caller}` is refused"))
        }
        Route::Detached => Err(format!("session `{token}` is not attached to any window; input is refused")),
        Route::Unknown => Err(format!("session token `{token}` not found")),
    }
}

/// Whether `caller` may stop the session on `route` with `session_close`.
/// Looser than input, because stopping is the safe direction: refused
/// only when *another* window holds the session, so no window can tear
/// down a session rendered elsewhere. An unknown token stays a no-op
/// success (closing twice is not an error) and a detached one may be
/// stopped by whoever still knows its token.
pub fn authorize_close(route: &Route, caller: &str, token: &str) -> Result<(), String> {
    match route {
        Route::Attached(holder) if holder != caller => {
            Err(format!("session `{token}` is rendered by window `{holder}`; window `{caller}` may not close it"))
        }
        _ => Ok(()),
    }
}

/// The label of a session's own (pre-workspace) window: `ssh-<token>` /
/// `rdp-<token>`. The single place the convention is spelled.
pub fn own_window_label(protocol: ProfileProtocol, token: &str) -> String {
    format!("{}-{token}", protocol.as_str())
}

/// Windows that may enumerate live sessions. `main` opens every session
/// and already receives each token from `session_open_*`; the workspace
/// needs the list to (re)claim them. Per-session windows, plugin windows
/// and web windows get nothing: a token is enough to drive a session, and
/// today none of them can learn another session's token.
pub fn may_list_sessions(caller_label: &str) -> bool {
    caller_label == "main" || caller_label == WORKSPACE_WINDOW_LABEL
}

#[derive(Debug, Default)]
pub struct AttachmentRegistry {
    entries: HashMap<String, Entry>,
}

impl AttachmentRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a newly opened session, attached to `window_label` when the
    /// host already knows which window renders it.
    pub fn register(
        &mut self,
        descriptor: SessionDescriptor,
        window_label: Option<&str>,
        now: Instant,
    ) -> Result<(), String> {
        let token = descriptor.token.clone();
        if self.entries.contains_key(&token) {
            return Err(format!("session token `{token}` is already registered"));
        }
        let attachment = window_label.map(|label| Attachment {
            window_label: label.to_string(),
            attached_at: now,
            last_seen: now,
            heartbeat_armed: false,
        });
        let unattached_since = if attachment.is_none() { Some(now) } else { None };
        self.entries.insert(token, Entry { descriptor, attachment, unattached_since, epoch: 1 });
        Ok(())
    }

    /// Claim `token` for `caller_label`.
    ///
    /// The caller must be the session's own window or the workspace. A
    /// session held by another window is refused while that window
    /// exists (`window_open`); a holder whose window is gone is replaced.
    pub fn attach(
        &mut self,
        token: &str,
        caller_label: &str,
        now: Instant,
        window_open: impl Fn(&str) -> bool,
    ) -> Result<AttachOutcome, AttachError> {
        let entry = self.entries.get_mut(token).ok_or(AttachError::NotFound)?;
        if !may_render(entry.descriptor.protocol, token, caller_label) {
            return Err(AttachError::NotAllowed { caller: caller_label.to_string() });
        }
        let outcome = match &mut entry.attachment {
            Some(current) if current.window_label == caller_label => {
                current.last_seen = now;
                return Ok(AttachOutcome::Refreshed);
            }
            Some(current) if window_open(&current.window_label) => {
                return Err(AttachError::HeldBy { holder: current.window_label.clone() });
            }
            Some(current) => AttachOutcome::TookOver { previous: current.window_label.clone() },
            None => AttachOutcome::Attached,
        };
        entry.attachment = Some(Attachment {
            window_label: caller_label.to_string(),
            attached_at: now,
            last_seen: now,
            heartbeat_armed: false,
        });
        entry.unattached_since = None;
        entry.epoch += 1;
        Ok(outcome)
    }

    /// Release `token` from `caller_label` without stopping it. Only the
    /// holder may detach; detaching an unattached session is a no-op.
    pub fn detach(&mut self, token: &str, caller_label: &str, now: Instant) -> Result<(), AttachError> {
        let entry = self.entries.get_mut(token).ok_or(AttachError::NotFound)?;
        match &entry.attachment {
            None => Ok(()),
            Some(current) if current.window_label == caller_label => {
                entry.attachment = None;
                entry.unattached_since = Some(now);
                entry.epoch += 1;
                Ok(())
            }
            Some(current) => Err(AttachError::HeldBy { holder: current.window_label.clone() }),
        }
    }

    /// Hand `token` from its holder `from` straight to `to` — the host's
    /// half of moving a live session between windows (Phase 6). There is
    /// no detached gap: the session is always held by exactly one window,
    /// so input stays narrowed to one window throughout and the watchdog
    /// never sees it unattached.
    ///
    /// Only the holder may hand a session on, and only to a window
    /// `attach` would accept. `attached_at` restarts, so the watchdog's
    /// `WINDOW_GONE_GRACE` covers a destination window still being built.
    /// Returns the new epoch.
    pub fn transfer(&mut self, token: &str, from: &str, to: &str, now: Instant) -> Result<u64, AttachError> {
        let entry = self.entries.get_mut(token).ok_or(AttachError::NotFound)?;
        if !may_render(entry.descriptor.protocol, token, to) {
            return Err(AttachError::NotAllowed { caller: to.to_string() });
        }
        match &entry.attachment {
            Some(current) if current.window_label == from => {}
            Some(current) => return Err(AttachError::HeldBy { holder: current.window_label.clone() }),
            None => return Err(AttachError::NotHeld { caller: from.to_string() }),
        }
        entry.attachment =
            Some(Attachment { window_label: to.to_string(), attached_at: now, last_seen: now, heartbeat_armed: false });
        entry.unattached_since = None;
        entry.epoch += 1;
        Ok(entry.epoch)
    }

    /// The descriptor recorded for `token` at open.
    pub fn descriptor(&self, token: &str) -> Option<&SessionDescriptor> {
        self.entries.get(token).map(|e| &e.descriptor)
    }

    /// Liveness from `window_label`; refreshes and arms every attachment
    /// it holds. Returns how many it holds.
    pub fn heartbeat(&mut self, window_label: &str, now: Instant) -> usize {
        let mut held = 0;
        for entry in self.entries.values_mut() {
            if let Some(att) = &mut entry.attachment {
                if att.window_label == window_label {
                    att.last_seen = now;
                    att.heartbeat_armed = true;
                    held += 1;
                }
            }
        }
        held
    }

    /// Remove and return every session attached to `window_label` — the
    /// window-close fan-out. A token is returned to exactly one caller.
    pub fn take_window(&mut self, window_label: &str) -> Vec<String> {
        let mut tokens: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| e.attachment.as_ref().is_some_and(|a| a.window_label == window_label))
            .map(|(t, _)| t.clone())
            .collect();
        tokens.sort();
        for t in &tokens {
            self.entries.remove(t);
        }
        tokens
    }

    /// Forget `token` (it is being dropped). Returns its descriptor.
    pub fn remove(&mut self, token: &str) -> Option<SessionDescriptor> {
        self.entries.remove(token).map(|e| e.descriptor)
    }

    #[cfg(test)]
    pub fn holder(&self, token: &str) -> Option<&str> {
        self.entries.get(token).and_then(|e| e.attachment.as_ref()).map(|a| a.window_label.as_str())
    }

    pub fn contains(&self, token: &str) -> bool {
        self.entries.contains_key(token)
    }

    /// Where `token`'s traffic goes right now.
    pub fn route(&self, token: &str) -> Route {
        self.route_epoch(token).0
    }

    /// [`Self::route`] and the holder epoch, read together. `0` for an
    /// unknown token (epochs start at 1).
    pub fn route_epoch(&self, token: &str) -> (Route, u64) {
        match self.entries.get(token) {
            None => (Route::Unknown, 0),
            Some(Entry { attachment: None, epoch, .. }) => (Route::Detached, *epoch),
            Some(Entry { attachment: Some(a), epoch, .. }) => (Route::Attached(a.window_label.clone()), *epoch),
        }
    }

    /// Every registered session, ordered by token for a stable output.
    pub fn list(&self) -> Vec<SessionListing> {
        let mut out: Vec<SessionListing> = self
            .entries
            .values()
            .map(|e| SessionListing {
                descriptor: e.descriptor.clone(),
                attached_to: e.attachment.as_ref().map(|a| a.window_label.clone()),
                attach_epoch: e.epoch,
            })
            .collect();
        out.sort_by(|a, b| a.descriptor.token.cmp(&b.descriptor.token));
        out
    }

    /// Distinct labels that currently hold a session — what the watchdog
    /// has to look up before a tick.
    pub fn window_labels(&self) -> Vec<String> {
        let mut labels: Vec<String> =
            self.entries.values().filter_map(|e| e.attachment.as_ref().map(|a| a.window_label.clone())).collect();
        labels.sort();
        labels.dedup();
        labels
    }

    /// Remove and return every orphan under `policy`, judged against the
    /// window snapshot taken for this tick. A window absent from the
    /// snapshot (attached after it was taken) is not judged this tick.
    pub fn reap(&mut self, now: Instant, windows: &HashMap<String, WindowState>, policy: ReapPolicy) -> Vec<Reaped> {
        let mut reaped: Vec<Reaped> = self
            .entries
            .iter()
            .filter_map(|(token, entry)| {
                reap_reason(entry, now, windows, policy).map(|(reason, idle)| Reaped {
                    token: token.clone(),
                    window_label: entry.attachment.as_ref().map(|a| a.window_label.clone()),
                    reason,
                    idle,
                })
            })
            .collect();
        reaped.sort_by(|a, b| a.token.cmp(&b.token));
        for r in &reaped {
            self.entries.remove(&r.token);
        }
        reaped
    }
}

fn reap_reason(
    entry: &Entry,
    now: Instant,
    windows: &HashMap<String, WindowState>,
    policy: ReapPolicy,
) -> Option<(ReapReason, Duration)> {
    let Some(att) = &entry.attachment else {
        let idle = now.duration_since(entry.unattached_since?);
        return (idle >= policy.unattached_grace).then_some((ReapReason::Unattached, idle));
    };
    match windows.get(&att.window_label)? {
        WindowState::Missing => {
            let idle = now.duration_since(att.attached_at);
            (idle >= policy.window_gone_grace).then_some((ReapReason::WindowGone, idle))
        }
        WindowState::Hidden => None,
        WindowState::Shown => {
            if !policy.judge_heartbeats || !att.heartbeat_armed {
                return None;
            }
            let idle = now.duration_since(att.last_seen);
            (idle > policy.heartbeat_stale_after).then_some((ReapReason::HeartbeatStale, idle))
        }
    }
}

/// Stop one SSH/RDP session: signal its control channel, drop it from
/// every registry, and hand back its cleanup hook for the caller to run.
///
/// The session's kind is not known here, so both control channels are
/// tried; the mismatched one fails and is ignored. `drop_session` is the
/// atomic take: a second call for the same token yields no hook, so the
/// cleanup runs at most once however many paths race to stop it.
pub async fn stop_session(state: &crate::state::AppState, token: &str) -> Option<SessionCleanup> {
    let _ = super::ssh::send_control(state, token, SshControl::Close).await;
    let _ = super::rdp::send_control(state, token, super::rdp::RdpControl::Close).await;
    let cleanup_ssh = super::ssh::drop_session(state, token).await;
    let cleanup_rdp = super::rdp::drop_session(state, token).await;
    cleanup_ssh.or(cleanup_rdp)
}

/// Stop every session attached to `window_label`.
///
/// `own_token` is the session an own window was built for. It is the
/// fail-safe for a registry that has lost track of a live session: if the
/// registry does not know the token at all but the session is still live,
/// the window it was born in stops it. A token the registry *does* know
/// and that is not attached here — moved to another window, or detached
/// and in transit — is left alone.
///
/// Returns `(token, cleanup)` per stopped session; the caller runs the
/// cleanups, which need a request context this module does not have.
pub async fn stop_window_sessions(
    state: &crate::state::AppState,
    window_label: &str,
    own_token: Option<&str>,
) -> Vec<(String, Option<SessionCleanup>)> {
    let (mut tokens, unregistered_own) = {
        let mut registry = state.session_attachments.lock().await;
        let tokens = registry.take_window(window_label);
        let unregistered_own =
            own_token.filter(|own| !tokens.iter().any(|t| t == own) && !registry.contains(own)).map(str::to_string);
        (tokens, unregistered_own)
    };
    if let Some(own) = unregistered_own {
        if state.connect_sessions.lock().await.contains_key(&own) {
            log::warn!("resource-connect: window {window_label} closed with live session {own} missing from the attachment registry; stopping it");
            tokens.push(own);
        }
    }
    let mut stopped = Vec::with_capacity(tokens.len());
    for token in tokens {
        let cleanup = stop_session(state, &token).await;
        stopped.push((token, cleanup));
    }
    stopped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(token: &str, protocol: &'static str) -> SessionDescriptor {
        SessionDescriptor {
            token: token.to_string(),
            protocol: if protocol == "rdp" { ProfileProtocol::Rdp } else { ProfileProtocol::Ssh },
            label: format!("{protocol} op@host:22"),
            resource_name: "web01".into(),
            profile_id: "cp_1".into(),
            stdout_event: (protocol == "ssh").then(|| format!("session-stdout-{token}")),
            closed_event: format!("session-closed-{token}"),
            resize_event: None,
            cursor_event: None,
            width: None,
            height: None,
            opened_at: "2026-10-06T12:00:00Z".into(),
            placement: Placement::OwnWindow,
            pane_ref: None,
            namespace: String::new(),
            vault_id: "v1".into(),
        }
    }

    fn policy(judge_heartbeats: bool) -> ReapPolicy {
        ReapPolicy {
            heartbeat_stale_after: HEARTBEAT_STALE_AFTER,
            window_gone_grace: WINDOW_GONE_GRACE,
            unattached_grace: UNATTACHED_GRACE,
            judge_heartbeats,
        }
    }

    fn snapshot(entries: &[(&str, WindowState)]) -> HashMap<String, WindowState> {
        entries.iter().map(|(l, s)| (l.to_string(), *s)).collect()
    }

    const T: &str = "sess_aa";
    const OWN: &str = "ssh-sess_aa";

    #[test]
    fn attach_detach_reattach() {
        let t0 = Instant::now();
        let mut reg = AttachmentRegistry::new();
        reg.register(descriptor(T, "ssh"), Some(OWN), t0).unwrap();
        assert_eq!(reg.holder(T), Some(OWN));

        // Re-attach from the same window is idempotent (StrictMode remount).
        assert_eq!(reg.attach(T, OWN, t0, |_| true), Ok(AttachOutcome::Refreshed));

        reg.detach(T, OWN, t0).unwrap();
        assert_eq!(reg.holder(T), None);
        assert_eq!(reg.list()[0].attached_to, None);
        // Detaching an unattached session is a no-op, not an error.
        reg.detach(T, OWN, t0).unwrap();

        assert_eq!(reg.attach(T, WORKSPACE_WINDOW_LABEL, t0, |_| true), Ok(AttachOutcome::Attached));
        assert_eq!(reg.holder(T), Some(WORKSPACE_WINDOW_LABEL));
        assert_eq!(reg.list()[0].attached_to.as_deref(), Some(WORKSPACE_WINDOW_LABEL));
    }

    /// The spec's rule: a second attach while a live window holds the
    /// token is refused, naming the holder.
    #[test]
    fn second_attach_while_a_live_window_holds_it_is_refused() {
        let t0 = Instant::now();
        let mut reg = AttachmentRegistry::new();
        reg.register(descriptor(T, "ssh"), Some(OWN), t0).unwrap();
        let err = reg.attach(T, WORKSPACE_WINDOW_LABEL, t0, |_| true).unwrap_err();
        assert_eq!(err, AttachError::HeldBy { holder: OWN.into() });
        assert!(err.message(T).contains(OWN));
        assert_eq!(reg.holder(T), Some(OWN));
    }

    #[test]
    fn a_holder_whose_window_is_gone_is_replaced() {
        let t0 = Instant::now();
        let mut reg = AttachmentRegistry::new();
        reg.register(descriptor(T, "ssh"), Some(OWN), t0).unwrap();
        let out = reg.attach(T, WORKSPACE_WINDOW_LABEL, t0, |label| label != OWN).unwrap();
        assert_eq!(out, AttachOutcome::TookOver { previous: OWN.into() });
        assert_eq!(reg.holder(T), Some(WORKSPACE_WINDOW_LABEL));
    }

    /// Sessions never render in the admin window, a plugin window, a web
    /// window, or another session's own window.
    #[test]
    fn only_the_own_window_or_the_workspace_may_attach() {
        let t0 = Instant::now();
        let mut reg = AttachmentRegistry::new();
        reg.register(descriptor(T, "ssh"), None, t0).unwrap();
        for caller in ["main", "plugin-x", "web-sess_aa", "ssh-sess_bb", "rdp-sess_aa", "session-workspace-2"] {
            assert_eq!(
                reg.attach(T, caller, t0, |_| true),
                Err(AttachError::NotAllowed { caller: caller.into() }),
                "{caller}"
            );
        }
        assert_eq!(reg.attach(T, OWN, t0, |_| true), Ok(AttachOutcome::Attached));

        reg.register(descriptor("rdp_cc", "rdp"), None, t0).unwrap();
        assert!(reg.attach("rdp_cc", "ssh-rdp_cc", t0, |_| true).is_err());
        assert_eq!(reg.attach("rdp_cc", "rdp-rdp_cc", t0, |_| true), Ok(AttachOutcome::Attached));
    }

    #[test]
    fn only_the_holder_may_detach_and_unknown_tokens_are_named() {
        let t0 = Instant::now();
        let mut reg = AttachmentRegistry::new();
        reg.register(descriptor(T, "ssh"), Some(OWN), t0).unwrap();
        assert_eq!(reg.detach(T, WORKSPACE_WINDOW_LABEL, t0), Err(AttachError::HeldBy { holder: OWN.into() }));
        assert_eq!(reg.holder(T), Some(OWN));
        assert_eq!(reg.detach("sess_zz", OWN, t0), Err(AttachError::NotFound));
        assert_eq!(reg.attach("sess_zz", OWN, t0, |_| true), Err(AttachError::NotFound));
    }

    #[test]
    fn duplicate_registration_is_refused() {
        let t0 = Instant::now();
        let mut reg = AttachmentRegistry::new();
        reg.register(descriptor(T, "ssh"), Some(OWN), t0).unwrap();
        assert!(reg.register(descriptor(T, "ssh"), None, t0).is_err());
    }

    #[test]
    fn take_window_returns_each_token_exactly_once() {
        let t0 = Instant::now();
        let mut reg = AttachmentRegistry::new();
        for t in ["sess_1", "sess_2", "rdp_3"] {
            let proto = if t.starts_with("rdp") { "rdp" } else { "ssh" };
            reg.register(descriptor(t, proto), Some(WORKSPACE_WINDOW_LABEL), t0).unwrap();
        }
        reg.register(descriptor("sess_other", "ssh"), Some("ssh-sess_other"), t0).unwrap();
        assert_eq!(reg.take_window(WORKSPACE_WINDOW_LABEL), vec!["rdp_3", "sess_1", "sess_2"]);
        assert!(reg.take_window(WORKSPACE_WINDOW_LABEL).is_empty());
        assert_eq!(reg.holder("sess_other"), Some("ssh-sess_other"));
    }

    #[test]
    fn heartbeat_refreshes_and_arms_only_the_callers_attachments() {
        let t0 = Instant::now();
        let mut reg = AttachmentRegistry::new();
        reg.register(descriptor("sess_1", "ssh"), Some(WORKSPACE_WINDOW_LABEL), t0).unwrap();
        reg.register(descriptor("sess_2", "ssh"), Some(WORKSPACE_WINDOW_LABEL), t0).unwrap();
        reg.register(descriptor("sess_3", "ssh"), Some("ssh-sess_3"), t0).unwrap();
        assert_eq!(reg.heartbeat(WORKSPACE_WINDOW_LABEL, t0), 2);
        assert_eq!(reg.heartbeat("plugin-x", t0), 0);
        let armed: Vec<bool> = ["sess_1", "sess_2", "sess_3"]
            .iter()
            .map(|t| reg.entries[*t].attachment.as_ref().unwrap().heartbeat_armed)
            .collect();
        assert_eq!(armed, vec![true, true, false]);
    }

    /// Starved past the threshold on a shown window: reaped. One that
    /// keeps heartbeating: kept.
    #[test]
    fn watchdog_reaps_a_starved_attachment_and_keeps_a_live_one() {
        let t0 = Instant::now();
        let mut reg = AttachmentRegistry::new();
        reg.register(descriptor("sess_dead", "ssh"), Some("ssh-sess_dead"), t0).unwrap();
        reg.register(descriptor("sess_live", "ssh"), Some("ssh-sess_live"), t0).unwrap();
        reg.heartbeat("ssh-sess_dead", t0);
        reg.heartbeat("ssh-sess_live", t0);

        let later = t0 + HEARTBEAT_STALE_AFTER + Duration::from_secs(1);
        reg.heartbeat("ssh-sess_live", later - Duration::from_secs(15));
        let windows = snapshot(&[("ssh-sess_dead", WindowState::Shown), ("ssh-sess_live", WindowState::Shown)]);

        let reaped = reg.reap(later, &windows, policy(true));
        assert_eq!(reaped.len(), 1);
        assert_eq!(reaped[0].token, "sess_dead");
        assert_eq!(reaped[0].reason, ReapReason::HeartbeatStale);
        assert_eq!(reaped[0].window_label.as_deref(), Some("ssh-sess_dead"));
        assert!(reg.contains("sess_live"));
        assert!(!reg.contains("sess_dead"));
        // Taken: a second tick does not report it again.
        assert!(reg.reap(later, &windows, policy(true)).is_empty());
    }

    #[test]
    fn exactly_at_the_threshold_is_not_stale() {
        let t0 = Instant::now();
        let mut reg = AttachmentRegistry::new();
        reg.register(descriptor(T, "ssh"), Some(OWN), t0).unwrap();
        reg.heartbeat(OWN, t0);
        let windows = snapshot(&[(OWN, WindowState::Shown)]);
        assert!(reg.reap(t0 + HEARTBEAT_STALE_AFTER, &windows, policy(true)).is_empty());
    }

    /// The false positives the policy exists to prevent: a minimised or
    /// hidden window may be throttled or suspended by the OS; a window
    /// that never heartbeated has not shown it can; and on macOS
    /// staleness is not judged at all.
    #[test]
    fn watchdog_does_not_reap_what_it_cannot_judge() {
        let t0 = Instant::now();
        let much_later = t0 + Duration::from_secs(3600);

        let mut reg = AttachmentRegistry::new();
        reg.register(descriptor(T, "ssh"), Some(OWN), t0).unwrap();
        reg.heartbeat(OWN, t0);
        assert!(reg.reap(much_later, &snapshot(&[(OWN, WindowState::Hidden)]), policy(true)).is_empty());
        assert!(reg.reap(much_later, &snapshot(&[(OWN, WindowState::Shown)]), policy(false)).is_empty());
        // Not in this tick's snapshot (attached after it was taken).
        assert!(reg.reap(much_later, &snapshot(&[]), policy(true)).is_empty());

        let mut never = AttachmentRegistry::new();
        never.register(descriptor(T, "ssh"), Some(OWN), t0).unwrap();
        assert!(never.reap(much_later, &snapshot(&[(OWN, WindowState::Shown)]), policy(true)).is_empty());
    }

    /// A window that vanished without a close event is reaped on every
    /// platform, heartbeat or not — but not while it may still be being
    /// built.
    #[test]
    fn watchdog_reaps_a_vanished_window_after_the_grace() {
        let t0 = Instant::now();
        let mut reg = AttachmentRegistry::new();
        reg.register(descriptor(T, "ssh"), Some(OWN), t0).unwrap();
        let gone = snapshot(&[(OWN, WindowState::Missing)]);
        assert!(reg.reap(t0 + Duration::from_secs(1), &gone, policy(false)).is_empty());
        let reaped = reg.reap(t0 + WINDOW_GONE_GRACE, &gone, policy(false));
        assert_eq!(reaped.len(), 1);
        assert_eq!(reaped[0].reason, ReapReason::WindowGone);
    }

    #[test]
    fn watchdog_reaps_a_session_left_detached() {
        let t0 = Instant::now();
        let mut reg = AttachmentRegistry::new();
        reg.register(descriptor(T, "ssh"), Some(OWN), t0).unwrap();
        reg.detach(T, OWN, t0).unwrap();
        assert!(reg.reap(t0 + Duration::from_secs(5), &snapshot(&[]), policy(true)).is_empty());
        let reaped = reg.reap(t0 + UNATTACHED_GRACE, &snapshot(&[]), policy(true));
        assert_eq!(reaped.len(), 1);
        assert_eq!(reaped[0].reason, ReapReason::Unattached);
        assert_eq!(reaped[0].window_label, None);

        // Re-attached in time: not reaped.
        let mut moved = AttachmentRegistry::new();
        moved.register(descriptor(T, "ssh"), Some(OWN), t0).unwrap();
        moved.detach(T, OWN, t0).unwrap();
        moved.attach(T, WORKSPACE_WINDOW_LABEL, t0 + Duration::from_secs(2), |_| true).unwrap();
        assert!(moved
            .reap(t0 + UNATTACHED_GRACE, &snapshot(&[(WORKSPACE_WINDOW_LABEL, WindowState::Shown)]), policy(true))
            .is_empty());
    }

    #[test]
    fn listing_carries_identity_and_holder_only() {
        let t0 = Instant::now();
        let mut reg = AttachmentRegistry::new();
        reg.register(descriptor(T, "ssh"), Some(OWN), t0).unwrap();
        let json = serde_json::to_value(reg.list()).unwrap();
        let row = &json[0];
        assert_eq!(row["token"], T);
        assert_eq!(row["protocol"], "ssh");
        assert_eq!(row["attached_to"], OWN);
        assert_eq!(row["resource_name"], "web01");
        let keys: Vec<&str> = row.as_object().unwrap().keys().map(String::as_str).collect();
        for k in &keys {
            assert!(!k.contains("credential") && !k.contains("password") && !k.contains("secret"), "{k}");
        }
    }

    #[test]
    fn list_permission_is_main_and_workspace_only() {
        assert!(may_list_sessions("main"));
        assert!(may_list_sessions(WORKSPACE_WINDOW_LABEL));
        for l in ["ssh-sess_aa", "rdp-rdp_aa", "plugin-x", "web-sess_aa", "webchrome-sess_aa", ""] {
            assert!(!may_list_sessions(l), "{l}");
        }
    }

    #[test]
    fn route_follows_attach_detach_and_removal() {
        let t0 = Instant::now();
        let mut reg = AttachmentRegistry::new();
        assert_eq!(reg.route(T), Route::Unknown);
        reg.register(descriptor(T, "ssh"), Some(OWN), t0).unwrap();
        assert_eq!(reg.route(T), Route::Attached(OWN.into()));
        reg.detach(T, OWN, t0).unwrap();
        assert_eq!(reg.route(T), Route::Detached);
        reg.attach(T, WORKSPACE_WINDOW_LABEL, t0, |_| true).unwrap();
        assert_eq!(reg.route(T), Route::Attached(WORKSPACE_WINDOW_LABEL.into()));
        reg.remove(T);
        assert_eq!(reg.route(T), Route::Unknown);
    }

    /// Only the holding window drives a session. A plugin window, the
    /// main window, another session's window — or the session's own
    /// window once the workspace holds it — is refused, as is any input
    /// to a detached or unknown session.
    #[test]
    fn input_is_authorised_for_the_holder_only() {
        let held = Route::Attached(WORKSPACE_WINDOW_LABEL.into());
        assert_eq!(authorize_input(&held, WORKSPACE_WINDOW_LABEL, T), Ok(()));
        for caller in ["main", "plugin-x", "ssh-sess_aa", "ssh-sess_bb", "web-sess_aa", ""] {
            let err = authorize_input(&held, caller, T).unwrap_err();
            assert!(err.contains(WORKSPACE_WINDOW_LABEL) && err.contains("refused"), "{caller}: {err}");
        }
        assert!(authorize_input(&Route::Detached, OWN, T).is_err());
        assert!(authorize_input(&Route::Unknown, OWN, T).unwrap_err().contains("not found"));
        assert_eq!(authorize_input(&Route::Attached(OWN.into()), OWN, T), Ok(()));
    }

    /// Close is refused only when another window holds the session; a
    /// second close of a stopped session stays a no-op success.
    #[test]
    fn close_is_refused_only_for_a_session_another_window_holds() {
        let held = Route::Attached(WORKSPACE_WINDOW_LABEL.into());
        assert_eq!(authorize_close(&held, WORKSPACE_WINDOW_LABEL, T), Ok(()));
        assert!(authorize_close(&held, "plugin-x", T).unwrap_err().contains(WORKSPACE_WINDOW_LABEL));
        assert!(authorize_close(&held, "main", T).is_err());
        assert_eq!(authorize_close(&Route::Unknown, "plugin-x", T), Ok(()));
        assert_eq!(authorize_close(&Route::Detached, OWN, T), Ok(()));
    }

    #[test]
    fn listing_reports_the_requested_placement() {
        let t0 = Instant::now();
        let mut reg = AttachmentRegistry::new();
        let mut d = descriptor(T, "ssh");
        d.placement = Placement::WorkspaceSplitDown;
        reg.register(d, Some(WORKSPACE_WINDOW_LABEL), t0).unwrap();
        let json = serde_json::to_value(reg.list()).unwrap();
        assert_eq!(json[0]["placement"], "workspace-split-down");
        assert_eq!(json[0]["attached_to"], WORKSPACE_WINDOW_LABEL);
    }

    /// Phase 6: the holder hands a session straight to another window it
    /// may render in; there is no detached gap, and the epoch moves.
    #[test]
    fn transfer_hands_a_session_on_without_a_detached_gap() {
        let t0 = Instant::now();
        let mut reg = AttachmentRegistry::new();
        reg.register(descriptor(T, "ssh"), Some(WORKSPACE_WINDOW_LABEL), t0).unwrap();
        let (_, e0) = reg.route_epoch(T);
        assert_eq!(e0, 1);

        let e1 = reg.transfer(T, WORKSPACE_WINDOW_LABEL, OWN, t0).unwrap();
        assert!(e1 > e0);
        assert_eq!(reg.route_epoch(T), (Route::Attached(OWN.into()), e1));
        assert_eq!(reg.list()[0].attach_epoch, e1);

        // And back again: a new epoch, not the one the workspace last held.
        let e2 = reg.transfer(T, OWN, WORKSPACE_WINDOW_LABEL, t0).unwrap();
        assert!(e2 > e1);
        assert_eq!(reg.holder(T), Some(WORKSPACE_WINDOW_LABEL));
    }

    /// Only the holder may hand a session on, only to a window that may
    /// render it, and never one no window holds.
    #[test]
    fn transfer_is_refused_for_non_holders_and_foreign_destinations() {
        let t0 = Instant::now();
        let mut reg = AttachmentRegistry::new();
        reg.register(descriptor(T, "ssh"), Some(WORKSPACE_WINDOW_LABEL), t0).unwrap();
        assert_eq!(
            reg.transfer(T, "plugin-x", OWN, t0),
            Err(AttachError::HeldBy { holder: WORKSPACE_WINDOW_LABEL.into() })
        );
        for to in ["main", "plugin-x", "web-sess_aa", "ssh-sess_bb", "rdp-sess_aa"] {
            assert_eq!(
                reg.transfer(T, WORKSPACE_WINDOW_LABEL, to, t0),
                Err(AttachError::NotAllowed { caller: to.into() }),
                "{to}"
            );
        }
        assert_eq!(reg.holder(T), Some(WORKSPACE_WINDOW_LABEL));
        assert_eq!(reg.route_epoch(T).1, 1, "a refused transfer does not move the epoch");

        reg.detach(T, WORKSPACE_WINDOW_LABEL, t0).unwrap();
        let err = reg.transfer(T, WORKSPACE_WINDOW_LABEL, OWN, t0).unwrap_err();
        assert_eq!(err, AttachError::NotHeld { caller: WORKSPACE_WINDOW_LABEL.into() });
        assert!(err.message(T).contains("no window does"));
        assert_eq!(reg.transfer("sess_zz", OWN, WORKSPACE_WINDOW_LABEL, t0), Err(AttachError::NotFound));
    }

    /// Every change of holder moves the epoch; a refresh from the same
    /// window does not.
    #[test]
    fn the_epoch_moves_with_the_holder_only() {
        let t0 = Instant::now();
        let mut reg = AttachmentRegistry::new();
        reg.register(descriptor(T, "ssh"), Some(OWN), t0).unwrap();
        let epoch = |reg: &AttachmentRegistry| reg.route_epoch(T).1;
        assert_eq!(epoch(&reg), 1);
        reg.attach(T, OWN, t0, |_| true).unwrap();
        reg.heartbeat(OWN, t0);
        assert_eq!(epoch(&reg), 1);
        reg.detach(T, OWN, t0).unwrap();
        assert_eq!(epoch(&reg), 2);
        reg.attach(T, WORKSPACE_WINDOW_LABEL, t0, |_| true).unwrap();
        assert_eq!(epoch(&reg), 3);
        assert_eq!(reg.route_epoch("sess_zz"), (Route::Unknown, 0));
    }

    /// The namespace and vault id recorded at open stay host-side; the
    /// restore placeholder ref is listed.
    #[test]
    fn listing_omits_namespace_and_vault_but_carries_the_pane_ref() {
        let t0 = Instant::now();
        let mut reg = AttachmentRegistry::new();
        let mut d = descriptor(T, "ssh");
        d.namespace = "tenant-a".into();
        d.pane_ref = Some("r3".into());
        reg.register(d, Some(WORKSPACE_WINDOW_LABEL), t0).unwrap();
        let json = serde_json::to_value(reg.list()).unwrap();
        let row = json[0].as_object().unwrap();
        assert_eq!(row["pane_ref"], "r3");
        assert_eq!(row["attach_epoch"], 1);
        assert!(!row.contains_key("namespace") && !row.contains_key("vault_id"), "{row:?}");
        assert_eq!(reg.descriptor(T).unwrap().namespace, "tenant-a");
    }

    #[test]
    fn own_window_labels_match_the_existing_convention() {
        assert_eq!(own_window_label(ProfileProtocol::Ssh, "sess_ab"), "ssh-sess_ab");
        assert_eq!(own_window_label(ProfileProtocol::Rdp, "rdp_ab"), "rdp-rdp_ab");
    }
}

/// Teardown fan-out against a real `AppState`: the registries and the
/// cleanup hand-off, without a Tauri runtime.
#[cfg(test)]
mod teardown_tests {
    use super::*;
    use crate::session::{SessionCleanupKind, SessionState, SshSessionState};
    use crate::state::AppState;

    fn cleanup(account: &str) -> SessionCleanup {
        SessionCleanup {
            kind: SessionCleanupKind::LdapLibraryCheckIn {
                ldap_mount: "ldap".into(),
                library_set: "ops".into(),
                account: account.into(),
                lease_id: format!("lease-{account}"),
            },
        }
    }

    /// Insert a fake SSH session (no russh behind it) and register it.
    /// The receiver is returned so the control channel stays open.
    async fn fake_session(
        state: &AppState,
        token: &str,
        window: &str,
        on_close: Option<SessionCleanup>,
    ) -> tokio::sync::mpsc::Receiver<SshControl> {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        state.connect_sessions.lock().await.insert(
            token.to_string(),
            SessionState::Ssh(SshSessionState { input_tx: tx, label: token.into(), on_close }),
        );
        let d = SessionDescriptor {
            token: token.into(),
            protocol: ProfileProtocol::Ssh,
            label: token.into(),
            resource_name: "web01".into(),
            profile_id: "cp_1".into(),
            stdout_event: None,
            closed_event: format!("session-closed-{token}"),
            resize_event: None,
            cursor_event: None,
            width: None,
            height: None,
            opened_at: String::new(),
            placement: Placement::WorkspaceTab,
            pane_ref: None,
            namespace: String::new(),
            vault_id: "v1".into(),
        };
        state.session_attachments.lock().await.register(d, Some(window), Instant::now()).unwrap();
        rx
    }

    fn account(c: &Option<SessionCleanup>) -> Option<String> {
        c.as_ref().map(|c| match &c.kind {
            SessionCleanupKind::LdapLibraryCheckIn { account, .. } => account.clone(),
        })
    }

    /// The spec's fan-out case: three sessions attached to one window,
    /// the window closes, all three stop and each cleanup is handed out
    /// exactly once — a racing second close gets nothing.
    #[tokio::test]
    async fn closing_a_window_stops_every_attached_session_once() {
        let state = AppState::new();
        let mut rxs = Vec::new();
        for (t, acct) in [("sess_1", "a1"), ("sess_2", "a2"), ("sess_3", "a3")] {
            rxs.push(fake_session(&state, t, WORKSPACE_WINDOW_LABEL, Some(cleanup(acct))).await);
        }
        let _other = fake_session(&state, "sess_9", "ssh-sess_9", Some(cleanup("a9"))).await;

        let stopped = stop_window_sessions(&state, WORKSPACE_WINDOW_LABEL, None).await;
        let accounts: Vec<Option<String>> = stopped.iter().map(|(_, c)| account(c)).collect();
        assert_eq!(accounts, vec![Some("a1".into()), Some("a2".into()), Some("a3".into())]);

        // Each control channel saw the Close.
        for rx in &mut rxs {
            assert!(matches!(rx.try_recv(), Ok(SshControl::Close)));
        }
        assert!(stop_window_sessions(&state, WORKSPACE_WINDOW_LABEL, None).await.is_empty());

        let sessions = state.connect_sessions.lock().await;
        assert_eq!(sessions.len(), 1);
        assert!(sessions.contains_key("sess_9"));
        drop(sessions);
        assert!(state.session_attachments.lock().await.contains("sess_9"));
    }

    /// `drop_session` clears the attachment, so the explicit
    /// `session_close` path and a later window close cannot both run the
    /// cleanup.
    #[tokio::test]
    async fn drop_session_clears_the_attachment() {
        let state = AppState::new();
        let _rx = fake_session(&state, "sess_1", "ssh-sess_1", Some(cleanup("a1"))).await;
        let first = stop_session(&state, "sess_1").await;
        assert_eq!(account(&first), Some("a1".into()));
        assert!(!state.session_attachments.lock().await.contains("sess_1"));
        // Disconnect, then the window closes: nothing left to stop.
        assert!(stop_window_sessions(&state, "ssh-sess_1", Some("sess_1")).await.is_empty());
        assert!(stop_session(&state, "sess_1").await.is_none());
    }

    /// The own-window fail-safe stops the window's own session even when
    /// the registry does not know it, and leaves it when the session now
    /// lives in another window or is in transit between windows.
    #[tokio::test]
    async fn own_window_close_is_fail_safe_but_respects_a_move() {
        let state = AppState::new();
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        state.connect_sessions.lock().await.insert(
            "sess_1".into(),
            SessionState::Ssh(SshSessionState { input_tx: tx, label: "x".into(), on_close: Some(cleanup("a1")) }),
        );
        let stopped = stop_window_sessions(&state, "ssh-sess_1", Some("sess_1")).await;
        assert_eq!(stopped.len(), 1);
        assert_eq!(account(&stopped[0].1), Some("a1".into()));

        let _rx2 = fake_session(&state, "sess_2", WORKSPACE_WINDOW_LABEL, None).await;
        assert!(stop_window_sessions(&state, "ssh-sess_2", Some("sess_2")).await.is_empty());
        assert!(state.connect_sessions.lock().await.contains_key("sess_2"));

        let _rx3 = fake_session(&state, "sess_3", "ssh-sess_3", None).await;
        state.session_attachments.lock().await.detach("sess_3", "ssh-sess_3", Instant::now()).unwrap();
        assert!(stop_window_sessions(&state, "ssh-sess_3", Some("sess_3")).await.is_empty());
        assert!(state.connect_sessions.lock().await.contains_key("sess_3"));
    }

    /// A reap runs the same stop path as a clean close.
    #[tokio::test]
    async fn a_reap_hands_out_the_same_cleanup_as_a_close() {
        let state = AppState::new();
        let mut rx = fake_session(&state, "sess_1", "ssh-sess_1", Some(cleanup("a1"))).await;
        let t0 = Instant::now();
        let reaped = state.session_attachments.lock().await.reap(
            t0 + Duration::from_secs(60),
            &[("ssh-sess_1".to_string(), WindowState::Missing)].into_iter().collect(),
            ReapPolicy::for_this_platform(),
        );
        assert_eq!(reaped.len(), 1);
        let c = stop_session(&state, &reaped[0].token).await;
        assert_eq!(account(&c), Some("a1".into()));
        assert!(matches!(rx.try_recv(), Ok(SshControl::Close)));
        assert!(state.connect_sessions.lock().await.is_empty());
    }
}
