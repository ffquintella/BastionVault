//! Recording replays handed to the Session Workspace (T109,
//! features/session-workspace.md §9).
//!
//! A replay is not a session: it has no token, no attachment and nothing to
//! tear down. It is identified by its recording id, which names an object
//! the vault's own policy gates (`rustion_recording_*` read it). The main
//! window queues a request here and sends the workspace the payload-less
//! `session://placed` wake-up; the workspace drains the queue with
//! `session_replay_take`. The id never travels in an event payload, for the
//! same reason a session token does not (see `workspace::PLACED_EVENT`).

use std::collections::VecDeque;

use serde::Serialize;

/// Most requests held for a workspace that has not drained them yet (it is
/// still loading). Past it the oldest is dropped, so a stuck window cannot
/// grow the queue without bound.
pub const MAX_PENDING: usize = 32;
/// Longest recording id accepted.
pub const MAX_RECORDING_ID: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReplayRequest {
    pub recording_id: String,
    /// Seek offset in ms from a keystroke-search hit; a number only.
    pub at_ms: Option<u64>,
}

#[derive(Debug, Default)]
pub struct ReplayQueue {
    pending: VecDeque<ReplayRequest>,
}

/// A recording id is an opaque server-assigned name: non-empty, bounded,
/// printable. Anything else is not one the GUI could have listed.
pub fn recording_id_ok(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("recording_id is required".into());
    }
    if id.len() > MAX_RECORDING_ID || id.chars().any(char::is_control) {
        return Err("recording_id is empty, over-long or not printable".into());
    }
    Ok(())
}

impl ReplayQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a request. A recording already waiting is not queued twice (the
    /// later seek offset wins).
    pub fn push(&mut self, req: ReplayRequest) -> Result<(), String> {
        recording_id_ok(&req.recording_id)?;
        if let Some(existing) = self.pending.iter_mut().find(|r| r.recording_id == req.recording_id) {
            existing.at_ms = req.at_ms;
            return Ok(());
        }
        if self.pending.len() >= MAX_PENDING {
            self.pending.pop_front();
        }
        self.pending.push_back(req);
        Ok(())
    }

    /// Hand everything queued to the workspace, oldest first.
    pub fn take(&mut self) -> Vec<ReplayRequest> {
        self.pending.drain(..).collect()
    }
}

/// Only the Session Workspace places panes, so only it may drain the queue.
pub fn may_take_replays(window_label: &str) -> bool {
    window_label == super::workspace::WORKSPACE_WINDOW_LABEL
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(id: &str, at: Option<u64>) -> ReplayRequest {
        ReplayRequest { recording_id: id.into(), at_ms: at }
    }

    #[test]
    fn take_drains_in_order_and_empties_the_queue() {
        let mut q = ReplayQueue::new();
        q.push(req("a", None)).unwrap();
        q.push(req("b", Some(5))).unwrap();
        assert_eq!(q.take(), vec![req("a", None), req("b", Some(5))]);
        assert!(q.take().is_empty());
    }

    #[test]
    fn a_waiting_recording_is_not_queued_twice() {
        let mut q = ReplayQueue::new();
        q.push(req("a", None)).unwrap();
        q.push(req("a", Some(9))).unwrap();
        assert_eq!(q.take(), vec![req("a", Some(9))]);
    }

    #[test]
    fn the_queue_is_bounded_and_drops_the_oldest() {
        let mut q = ReplayQueue::new();
        for i in 0..(MAX_PENDING + 3) {
            q.push(req(&format!("r{i}"), None)).unwrap();
        }
        let got = q.take();
        assert_eq!(got.len(), MAX_PENDING);
        assert_eq!(got[0].recording_id, "r3");
    }

    #[test]
    fn malformed_ids_are_refused() {
        let mut q = ReplayQueue::new();
        assert!(q.push(req("", None)).is_err());
        assert!(q.push(req("a\nb", None)).is_err());
        assert!(q.push(req(&"x".repeat(MAX_RECORDING_ID + 1), None)).is_err());
        assert!(q.take().is_empty());
    }

    #[test]
    fn only_the_workspace_may_take() {
        assert!(may_take_replays("session-workspace"));
        for w in ["main", "replay-rec_01", "ssh-tok", "plugin-x", "session-workspace2"] {
            assert!(!may_take_replays(w), "{w}");
        }
    }
}
