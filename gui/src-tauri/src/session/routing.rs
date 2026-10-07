//! Host → window event routing for SSH/RDP sessions
//! (features/session-workspace.md, Security: "Event scoping", T38 Phase 3).
//!
//! The session pumps used to `app.emit` their per-session events (SSH
//! output, the closed notice, RDP resize and cursor) to every webview.
//! They now `emit_to` the window the attachment registry says holds the
//! session, looked up per event so a session that moves between windows
//! follows its holder.
//!
//! What this narrows, and what it does not: Tauri 2.11 delivers an
//! `emit_to(label)` event to listeners *in that webview*, **and** to any
//! listener in any webview registered with the default `Any` target
//! (`listen()` from `@tauri-apps/api/event`; see `match_any_or_filter` in
//! tauri's `event/listener.rs`). So this is not a confidentiality boundary
//! against a webview that already knows a session's event names. That
//! boundary is still the token: it reaches only `main` (the
//! `session_open_*` reply), the rendering window, and — through
//! `session_list_open` — the workspace; `session://placed` carries no
//! payload for exactly this reason. What the routing does guarantee is
//! that the host never *addresses* a session's traffic to a window that
//! does not hold it.

use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};

use super::attachments::Route;

/// Which window label a session event goes to.
///
/// * Attached → the holder, remembered as the last known holder.
/// * Detached → nowhere: nothing renders the session. (A Phase 6 move does
///   not detach — it hands the session straight to the next window — and
///   SSH output waiting for that window's handshake is held by
///   `session::output`, delivered through [`SessionEvents::emit_if_epoch`].)
/// * Unknown → the last known holder, if any. A session is removed from
///   the registry as it is stopped, before its pump emits the closed
///   notice; that notice still belongs to the window that rendered it.
///   With no last holder (an event before registration) → nowhere; the
///   SSH pump buffers output until the window's handshake, and the closed
///   notice is re-sent for 3.5 s.
pub fn emit_target(route: &Route, last_holder: &mut Option<String>) -> Option<String> {
    match route {
        Route::Attached(label) => {
            if last_holder.as_deref() != Some(label.as_str()) {
                *last_holder = Some(label.clone());
            }
            Some(label.clone())
        }
        Route::Detached => None,
        Route::Unknown => last_holder.clone(),
    }
}

/// Where an epoch-gated delivery goes: the holder, only if it holds the
/// session at exactly `expected` (Phase 6). A session moved since, or
/// detached, or unknown, gets nothing — its output stays buffered for the
/// next holder's handshake.
pub fn gated_target(route: &Route, current_epoch: u64, expected: u64) -> Option<&str> {
    match route {
        Route::Attached(label) if current_epoch == expected => Some(label.as_str()),
        _ => None,
    }
}

/// Emits one session's events to its holding window. Cheap to clone.
#[derive(Clone)]
pub struct SessionEvents {
    app: AppHandle,
    token: String,
    last_holder: Arc<Mutex<Option<String>>>,
}

impl SessionEvents {
    pub fn new(app: AppHandle, token: String) -> Self {
        Self { app, token, last_holder: Arc::new(Mutex::new(None)) }
    }

    /// Emit `event` to the window holding the session, if any.
    pub async fn emit<S: Serialize + Clone>(&self, event: &str, payload: S) {
        let route = match self.app.try_state::<crate::state::AppState>() {
            Some(state) => state.session_attachments.lock().await.route(&self.token),
            None => Route::Unknown,
        };
        let target = {
            let mut last = match self.last_holder.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            emit_target(&route, &mut last)
        };
        match target {
            Some(label) => {
                if let Err(e) = self.app.emit_to(label.as_str(), event, payload) {
                    log::debug!("resource-connect: emit {event} to window {label} failed: {e}");
                }
            }
            None => log::debug!("resource-connect: session {} has no window; {event} not delivered", self.token),
        }
    }

    /// Emit `event` to the holder only if it holds the session at
    /// `epoch`; returns whether it was handed to the webview. The registry
    /// lock is held across the check *and* the `emit_to` (which does not
    /// await), so no transfer can slip between them: a chunk is either
    /// delivered to the window that completed the handshake at `epoch` or
    /// kept by the caller for the next one — never addressed to a window
    /// that gave the session up or is not listening yet.
    pub async fn emit_if_epoch<S: Serialize + Clone>(&self, event: &str, payload: S, epoch: u64) -> bool {
        let Some(state) = self.app.try_state::<crate::state::AppState>() else {
            return false;
        };
        let registry = state.session_attachments.lock().await;
        let (route, current) = registry.route_epoch(&self.token);
        let Some(label) = gated_target(&route, current, epoch) else {
            return false;
        };
        {
            let mut last = match self.last_holder.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            emit_target(&route, &mut last);
        }
        match self.app.emit_to(label, event, payload) {
            Ok(()) => true,
            Err(e) => {
                log::debug!("resource-connect: emit {event} to window {label} failed: {e}");
                false
            }
        }
    }

    /// Whether the session's holder is at `epoch` right now.
    pub async fn holder_epoch_is(&self, epoch: u64) -> bool {
        let Some(state) = self.app.try_state::<crate::state::AppState>() else {
            return false;
        };
        let (route, current) = state.session_attachments.lock().await.route_epoch(&self.token);
        gated_target(&route, current, epoch).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attached_sessions_go_to_their_holder_and_are_remembered() {
        let mut last = None;
        assert_eq!(
            emit_target(&Route::Attached("session-workspace".into()), &mut last).as_deref(),
            Some("session-workspace")
        );
        assert_eq!(last.as_deref(), Some("session-workspace"));
        // A move follows the new holder.
        assert_eq!(emit_target(&Route::Attached("ssh-sess_a".into()), &mut last).as_deref(), Some("ssh-sess_a"));
        assert_eq!(last.as_deref(), Some("ssh-sess_a"));
    }

    /// The closed notice of a session already dropped from the registry
    /// still reaches the window that rendered it.
    #[test]
    fn a_stopped_session_falls_back_to_its_last_holder() {
        let mut last = Some("session-workspace".to_string());
        assert_eq!(emit_target(&Route::Unknown, &mut last).as_deref(), Some("session-workspace"));
    }

    /// Phase 6: gated output reaches the holder only at the epoch whose
    /// handshake it completed.
    #[test]
    fn gated_delivery_needs_the_holder_at_the_expected_epoch() {
        let held = Route::Attached("session-workspace".into());
        assert_eq!(gated_target(&held, 3, 3), Some("session-workspace"));
        assert_eq!(gated_target(&held, 4, 3), None, "moved since the handshake");
        assert_eq!(gated_target(&Route::Detached, 3, 3), None);
        assert_eq!(gated_target(&Route::Unknown, 0, 0), None);
    }

    #[test]
    fn nothing_is_addressed_without_a_holder() {
        let mut last = None;
        assert_eq!(emit_target(&Route::Unknown, &mut last), None);
        // Detached: not even the last holder, which gave the session up.
        let mut last = Some("ssh-sess_a".to_string());
        assert_eq!(emit_target(&Route::Detached, &mut last), None);
    }
}
