//! The native-close protocol for windows that render live sessions
//! (features/session-workspace.md §8, T108).
//!
//! A session's own window (`ssh-<token>` / `rdp-<token>`) and the Session
//! Workspace no longer stop their sessions when the operator asks to close
//! them (`WindowEvent::CloseRequested`). The session page listens for the
//! close request; while such a listener is registered, Tauri vetoes the
//! native close and hands the request to the page, which asks the operator
//! before it closes the window. Teardown runs when the window is actually
//! gone (`WindowEvent::Destroyed`), through the same stop path as every
//! other exit (`attachments::stop_window_sessions`).
//!
//! A veto handed to a page that cannot answer would trap the window — and
//! keep its sessions running — for good: Tauri 2.11 keeps a dead
//! renderer's listener registered, so every later close is vetoed too.
//! This guard is the escape hatch. Every close request is recorded, and the
//! page must answer it (`session_window_closing`, or closing the window)
//! within [`CLOSE_ANSWER_TIMEOUT`]; otherwise the host stops the window's
//! sessions and destroys it. A window whose renderer is known to be dead
//! (the macOS web-content-process hook) is not asked at all.
//!
//! The answer is bound to the window that sends it — the host takes the
//! label from the calling webview — so no other webview can keep a window
//! it does not own from being force-closed.
//!
//! Plain data with no Tauri types, so the policy is unit-tested without a
//! runtime.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::workspace::WORKSPACE_WINDOW_LABEL;

/// How long the page has to answer a close request before the host forces
/// the close. The page answers as soon as its confirmation is on screen —
/// one IPC round trip — so this only has to cover a busy renderer, not the
/// operator's decision. Erring short costs the confirmation (the window
/// closes as it did before T108); erring long leaves a hung window
/// unclosable for longer.
pub const CLOSE_ANSWER_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether `label` is a window that renders live sessions and so takes
/// part in this protocol: a session's own window or the workspace. Never
/// `main`, a plugin, a replay or a web window.
pub fn renders_sessions(label: &str) -> bool {
    label == WORKSPACE_WINDOW_LABEL
        || label.strip_prefix("ssh-").is_some_and(|t| !t.is_empty())
        || label.strip_prefix("rdp-").is_some_and(|t| !t.is_empty())
}

/// What the host does with one close request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseRequest {
    /// Let the page answer; force the close if request `id` is still
    /// unanswered after [`CLOSE_ANSWER_TIMEOUT`].
    AwaitAnswer { id: u64 },
    /// The window's renderer is known to be dead: nothing can answer, so
    /// close it now.
    ForceNow,
}

#[derive(Debug, Default)]
struct WindowClose {
    /// The oldest unanswered request and when it was made. A second click
    /// while one is pending joins it rather than restarting the clock, so
    /// clicking close repeatedly on a hung window cannot postpone the
    /// forced close.
    pending: Option<(u64, Instant)>,
    renderer_gone: bool,
}

#[derive(Debug, Default)]
pub struct CloseGuard {
    windows: HashMap<String, WindowClose>,
    /// Request ids are unique across windows and window lifetimes, so a
    /// timer armed for a window that has since been destroyed and rebuilt
    /// under the same label can never match the new window's request.
    next_id: u64,
}

impl CloseGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// The operator asked to close `label` (`WindowEvent::CloseRequested`).
    pub fn requested(&mut self, label: &str, now: Instant) -> CloseRequest {
        let window = self.windows.entry(label.to_string()).or_default();
        if window.renderer_gone {
            return CloseRequest::ForceNow;
        }
        if let Some((id, _)) = window.pending {
            return CloseRequest::AwaitAnswer { id };
        }
        self.next_id += 1;
        let id = self.next_id;
        window.pending = Some((id, now));
        CloseRequest::AwaitAnswer { id }
    }

    /// The page in `label` answered: its confirmation is on screen, or it is
    /// closing the window. Returns whether a request was pending.
    pub fn answered(&mut self, label: &str) -> bool {
        self.windows.get_mut(label).and_then(|w| w.pending.take()).is_some()
    }

    /// The timer for request `id` fired. When that request is still
    /// unanswered it is taken — so the close is forced once however many
    /// timers fire — and the time it waited is returned.
    pub fn take_unanswered(&mut self, label: &str, id: u64, now: Instant) -> Option<Duration> {
        let window = self.windows.get_mut(label)?;
        match window.pending {
            Some((pending, at)) if pending == id => {
                window.pending = None;
                Some(now.duration_since(at))
            }
            _ => None,
        }
    }

    /// The window's renderer died (the macOS web-content-process hook).
    /// Its next close request is forced at once.
    // Only the macOS hook calls this: Tauri 2.11 reports a dead renderer on
    // no other platform, where the timeout covers it instead.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn renderer_gone(&mut self, label: &str) {
        self.windows.entry(label.to_string()).or_default().renderer_gone = true;
    }

    /// The window is destroyed. Forget it: a pending timer finds nothing,
    /// and a later window under the same label starts clean.
    pub fn forget(&mut self, label: &str) {
        self.windows.remove(label);
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.windows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: &str = "ssh-sess_aa";

    #[test]
    fn only_session_windows_take_part() {
        for label in [WORKSPACE_WINDOW_LABEL, "ssh-sess_aa", "rdp-rdp_bb"] {
            assert!(renders_sessions(label), "{label}");
        }
        for label in ["main", "plugin-x", "replay-rec_1", "web-sess_aa", "webchrome-sess_aa", "ssh-", "rdp-", ""] {
            assert!(!renders_sessions(label), "{label}");
        }
    }

    /// The page answers in time: no forced close, whenever the timer fires.
    #[test]
    fn an_answered_request_is_never_forced() {
        let t0 = Instant::now();
        let mut g = CloseGuard::new();
        let CloseRequest::AwaitAnswer { id } = g.requested(W, t0) else { panic!("forced") };
        assert!(g.answered(W));
        assert_eq!(g.take_unanswered(W, id, t0 + CLOSE_ANSWER_TIMEOUT), None);
        // A second answer has nothing left to answer.
        assert!(!g.answered(W));
    }

    /// The hung renderer: nothing answers, the timer forces the close —
    /// once, however many timers fire for it.
    #[test]
    fn an_unanswered_request_is_forced_exactly_once() {
        let t0 = Instant::now();
        let mut g = CloseGuard::new();
        let CloseRequest::AwaitAnswer { id } = g.requested(W, t0) else { panic!("forced") };
        let later = t0 + CLOSE_ANSWER_TIMEOUT;
        assert_eq!(g.take_unanswered(W, id, later), Some(CLOSE_ANSWER_TIMEOUT));
        assert_eq!(g.take_unanswered(W, id, later), None);
        // An answer arriving after the close was forced changes nothing.
        assert!(!g.answered(W));
    }

    /// Clicking close again on a window that has not answered joins the
    /// first request; it does not restart the clock.
    #[test]
    fn repeated_requests_do_not_postpone_the_forced_close() {
        let t0 = Instant::now();
        let mut g = CloseGuard::new();
        let first = g.requested(W, t0);
        let second = g.requested(W, t0 + Duration::from_secs(3));
        assert_eq!(first, second);
        let CloseRequest::AwaitAnswer { id } = first else { panic!("forced") };
        assert_eq!(g.take_unanswered(W, id, t0 + CLOSE_ANSWER_TIMEOUT), Some(CLOSE_ANSWER_TIMEOUT));
    }

    /// Answered, then asked again (the operator cancelled and clicked
    /// close later): a fresh request with its own clock.
    #[test]
    fn a_request_after_an_answer_is_new() {
        let t0 = Instant::now();
        let mut g = CloseGuard::new();
        let CloseRequest::AwaitAnswer { id: first } = g.requested(W, t0) else { panic!() };
        g.answered(W);
        let CloseRequest::AwaitAnswer { id: second } = g.requested(W, t0 + Duration::from_secs(60)) else { panic!() };
        assert_ne!(first, second);
        // The first timer, firing late, does not force the second request.
        assert_eq!(g.take_unanswered(W, first, t0 + Duration::from_secs(61)), None);
        assert!(g.take_unanswered(W, second, t0 + Duration::from_secs(65)).is_some());
    }

    /// A destroyed window is forgotten: its timer finds nothing, and a
    /// window rebuilt under the same label is not confused with it.
    #[test]
    fn a_destroyed_window_is_forgotten() {
        let t0 = Instant::now();
        let mut g = CloseGuard::new();
        let CloseRequest::AwaitAnswer { id: old } = g.requested(W, t0) else { panic!() };
        g.forget(W);
        assert_eq!(g.tracked(), 0);
        assert_eq!(g.take_unanswered(W, old, t0 + CLOSE_ANSWER_TIMEOUT), None);

        let CloseRequest::AwaitAnswer { id: new } = g.requested(W, t0 + Duration::from_secs(1)) else { panic!() };
        assert_ne!(old, new);
        assert_eq!(g.take_unanswered(W, old, t0 + CLOSE_ANSWER_TIMEOUT), None, "the old timer must not fire");
        assert!(g.take_unanswered(W, new, t0 + Duration::from_secs(6)).is_some());
        g.forget(W);
        assert_eq!(g.tracked(), 0);
    }

    /// A renderer known dead cannot answer: its close is forced at once,
    /// and the flag dies with the window.
    #[test]
    fn a_dead_renderer_is_closed_at_once() {
        let t0 = Instant::now();
        let mut g = CloseGuard::new();
        g.renderer_gone(W);
        assert_eq!(g.requested(W, t0), CloseRequest::ForceNow);
        assert_eq!(g.requested(W, t0), CloseRequest::ForceNow);
        g.forget(W);
        assert!(matches!(g.requested(W, t0), CloseRequest::AwaitAnswer { .. }));
    }

    /// One window's answer never answers another's request.
    #[test]
    fn answers_are_per_window() {
        let t0 = Instant::now();
        let mut g = CloseGuard::new();
        let CloseRequest::AwaitAnswer { id: ws } = g.requested(WORKSPACE_WINDOW_LABEL, t0) else { panic!() };
        let CloseRequest::AwaitAnswer { id: own } = g.requested(W, t0) else { panic!() };
        assert!(g.answered(W));
        assert!(!g.answered("ssh-sess_bb"));
        assert_eq!(g.take_unanswered(W, own, t0 + CLOSE_ANSWER_TIMEOUT), None);
        assert!(g.take_unanswered(WORKSPACE_WINDOW_LABEL, ws, t0 + CLOSE_ANSWER_TIMEOUT).is_some());
        // An id from one window cannot take another window's request.
        let CloseRequest::AwaitAnswer { id: again } = g.requested(W, t0) else { panic!() };
        assert_eq!(g.take_unanswered(WORKSPACE_WINDOW_LABEL, again, t0 + CLOSE_ANSWER_TIMEOUT), None);
    }
}
