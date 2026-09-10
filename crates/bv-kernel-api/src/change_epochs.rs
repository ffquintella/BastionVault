//! Per-topic change epochs — the signal a client watches to learn that
//! *another* client wrote something.
//!
//! A client can invalidate its own cache when it writes. It cannot know that a
//! second operator, or the same operator's CLI, changed something behind its
//! back; without a signal it serves stale listings until a TTL expires. This
//! registry is that signal: every successful mutating request bumps a counter
//! for its **topic** (namespace + mount), and `sys/cache/version` lets a client
//! long-poll the counters it cares about. See
//! `features/client-request-efficiency.md`.
//!
//! # Deliberate limitations
//!
//! **Process-local, exactly like [`crate::dos::guard::DosGuard`].** Epochs are
//! in-memory and per node. Persisting a counter would mean a barrier write on
//! every mutation — doubling the write cost of the vault to accelerate a cache
//! — so it is not done. `bv-client` pins a session to one node, so a client
//! sees a coherent view of everything routed through its own node; two clients
//! pinned to different nodes of an HA cluster will not invalidate each other.
//! **The client TTL remains the correctness backstop**, and a cache must stay
//! correct — merely less fresh — with no signal at all.
//!
//! **Counters reset on restart.** A restarted node starts every topic at zero,
//! so a client can observe an epoch going *down*. A client must treat only an
//! increase as evidence of a write; acting on a decrease would turn every
//! failover into a cache-clear storm.
//!
//! **Bounded.** The topic map is capped ([`MAX_TOPICS`]). A vault with more
//! live topics than that stops itemizing and reports `coarse`, which tells a
//! client to treat a version bump as "something changed, I cannot say what"
//! and drop everything. Unbounded growth in a process-global map reachable
//! from the request path is not an option.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

/// Separator between the namespace and the mount in a topic key.
///
/// An ASCII unit separator, which cannot appear in either half: a namespace
/// path and a mount path are both slash-delimited printable text, so a
/// printable separator could be forged into one of them to make two distinct
/// topics collide.
pub const TOPIC_SEP: char = '\u{1f}';

/// Most topics tracked before the registry stops itemizing. Each entry is a
/// short string and a `u64`, so this bound is about refusing unbounded growth
/// rather than about memory pressure.
pub const MAX_TOPICS: usize = 4096;

/// A snapshot of the registry, filtered and rendered by the endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochSnapshot {
    /// Monotonic counter bumped on **every** change, whatever its topic.
    ///
    /// One comparison tells a client whether anything at all has moved, which
    /// is what makes the long-poll cheap and what the endpoint's ETag is built
    /// from.
    pub version: u64,
    /// `topic -> epoch` for the topics that were asked about.
    pub topics: BTreeMap<String, u64>,
    /// True when the topic map hit [`MAX_TOPICS`] and some changes are no
    /// longer itemized. A client seeing this must treat a `version` bump as
    /// global and drop its whole cache rather than trusting `topics`.
    pub coarse: bool,
}

/// Process-wide change-epoch registry. Held on `Core` beside the DoS guard.
pub struct ChangeEpochs {
    /// `topic -> epoch`.
    topics: Mutex<HashMap<String, u64>>,
    /// Bumped on every change; the aggregate a watcher compares.
    version: AtomicU64,
    /// True once the topic map has been full and a change went unitemized.
    /// Never cleared: a client that missed an itemization cannot be told
    /// later which topic it was.
    coarse: std::sync::atomic::AtomicBool,
    /// Wakes long-polling watchers. A `Notify` rather than a polling loop, so
    /// an invalidation reaches a waiting client in about as long as it takes
    /// to schedule the task.
    notify: Notify,
}

impl Default for ChangeEpochs {
    fn default() -> Self {
        Self::new()
    }
}

impl ChangeEpochs {
    pub fn new() -> Self {
        Self {
            topics: Mutex::new(HashMap::new()),
            version: AtomicU64::new(0),
            coarse: std::sync::atomic::AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    /// Build a topic key from a namespace path and a mount path.
    ///
    /// The namespace is part of the key so the registry can be filtered to the
    /// caller's own namespace: without it, a snapshot would tell a tenant
    /// which mounts exist in someone else's.
    pub fn topic(namespace: &str, mount: &str) -> String {
        format!("{}{TOPIC_SEP}{}", namespace.trim_end_matches('/'), mount)
    }

    /// Record a change to `topic` and wake every watcher.
    ///
    /// Called from the request path, so it takes one uncontended mutex and no
    /// allocation in the common case. Never fails: a poisoned lock (only
    /// reachable if a previous holder panicked) degrades to bumping the
    /// aggregate version and marking the snapshot coarse, because failing a
    /// caller's *write* over a cache-invalidation hint would be the wrong
    /// trade.
    pub fn bump(&self, topic: &str) {
        match self.topics.lock() {
            Ok(mut map) => match map.get_mut(topic) {
                Some(epoch) => *epoch = epoch.saturating_add(1),
                None => {
                    if map.len() < MAX_TOPICS {
                        map.insert(topic.to_string(), 1);
                    } else {
                        // Full: the change is real but no longer itemized.
                        self.coarse.store(true, Ordering::Relaxed);
                    }
                }
            },
            Err(_) => self.coarse.store(true, Ordering::Relaxed),
        }
        self.version.fetch_add(1, Ordering::Release);
        self.notify.notify_waiters();
    }

    /// The aggregate version, for a cheap "has anything changed?" comparison.
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// Snapshot the epochs for `wanted`, in the caller's namespace.
    ///
    /// Only the requested topics are returned, and a topic that has never been
    /// written is reported as `0` rather than omitted — a client needs a
    /// baseline for it, or its first real bump would look like the first
    /// snapshot and be ignored.
    ///
    /// The endpoint decides what the caller may ask about; this function does
    /// no authorization.
    pub fn snapshot_for(&self, namespace: &str, wanted: &[String]) -> EpochSnapshot {
        let map = self.topics.lock().ok();
        let mut topics = BTreeMap::new();
        for mount in wanted {
            let key = Self::topic(namespace, mount);
            let epoch = map.as_ref().and_then(|m| m.get(&key).copied()).unwrap_or(0);
            topics.insert(mount.clone(), epoch);
        }
        EpochSnapshot {
            version: self.version(),
            topics,
            coarse: self.coarse.load(Ordering::Relaxed),
        }
    }

    /// Wait until the aggregate version differs from `since`, or `timeout`
    /// elapses. Returns `true` if something changed.
    ///
    /// Registering the notified future *before* re-checking the version is
    /// what closes the lost-wakeup race: a bump landing between the check and
    /// the wait would otherwise leave the watcher asleep for the whole
    /// timeout.
    pub async fn wait_for_change(&self, since: u64, timeout: Duration) -> bool {
        if self.version() != since {
            return true;
        }
        let notified = self.notify.notified();
        if self.version() != since {
            return true;
        }
        match tokio::time::timeout(timeout, notified).await {
            Ok(()) => self.version() != since,
            Err(_) => false,
        }
    }

    /// Number of tracked topics. For tests and diagnostics.
    pub fn tracked(&self) -> usize {
        self.topics.lock().map(|m| m.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bump_moves_both_the_topic_and_the_aggregate() {
        let e = ChangeEpochs::new();
        let snap = e.snapshot_for("", &["pki/".to_string()]);
        assert_eq!(snap.version, 0);
        // A never-written topic reports 0 rather than being omitted: the
        // client needs a baseline, or its first real bump looks like a first
        // snapshot and is ignored.
        assert_eq!(snap.topics.get("pki/"), Some(&0));

        e.bump(&ChangeEpochs::topic("", "pki/"));
        let snap = e.snapshot_for("", &["pki/".to_string()]);
        assert_eq!(snap.version, 1);
        assert_eq!(snap.topics.get("pki/"), Some(&1));
    }

    #[test]
    fn a_bump_in_one_namespace_is_invisible_in_another() {
        // Without the namespace in the key, a snapshot would tell a tenant
        // which mounts exist in someone else's.
        let e = ChangeEpochs::new();
        e.bump(&ChangeEpochs::topic("acme", "pki/"));
        assert_eq!(
            e.snapshot_for("", &["pki/".to_string()]).topics.get("pki/"),
            Some(&0),
            "root's `pki/` must not move because `acme/pki/` did"
        );
        assert_eq!(
            e.snapshot_for("acme", &["pki/".to_string()]).topics.get("pki/"),
            Some(&1)
        );
    }

    #[test]
    fn only_requested_topics_are_reported() {
        // The endpoint must not enumerate: a caller learns about mounts it
        // already knew the names of, and nothing else.
        let e = ChangeEpochs::new();
        e.bump(&ChangeEpochs::topic("", "secret-payroll/"));
        let snap = e.snapshot_for("", &["pki/".to_string()]);
        assert_eq!(snap.topics.len(), 1);
        assert!(snap.topics.contains_key("pki/"));
        assert!(!snap.topics.contains_key("secret-payroll/"));
        // The aggregate still moved — that is what a watcher wakes on.
        assert_eq!(snap.version, 1);
    }

    #[test]
    fn the_topic_separator_cannot_be_forged_from_either_half() {
        // Both halves are slash-delimited printable text; a printable
        // separator could be smuggled into one to collide two topics.
        assert!(TOPIC_SEP.is_control());
        let a = ChangeEpochs::topic("acme", "pki/");
        let b = ChangeEpochs::topic("acme/pki", "");
        assert_ne!(a, b);
    }

    #[test]
    fn trailing_namespace_slash_does_not_fork_the_topic() {
        assert_eq!(ChangeEpochs::topic("acme/", "pki/"), ChangeEpochs::topic("acme", "pki/"));
    }

    #[test]
    fn the_map_is_bounded_and_says_so_when_it_stops_itemizing() {
        let e = ChangeEpochs::new();
        for i in 0..MAX_TOPICS {
            e.bump(&ChangeEpochs::topic("", &format!("mount-{i}/")));
        }
        assert_eq!(e.tracked(), MAX_TOPICS);
        assert!(!e.snapshot_for("", &[]).coarse);

        e.bump(&ChangeEpochs::topic("", "one-too-many/"));
        assert_eq!(e.tracked(), MAX_TOPICS, "the map does not grow past the cap");
        let snap = e.snapshot_for("", &["one-too-many/".to_string()]);
        assert!(snap.coarse, "an unitemized change must be advertised");
        // The change is still visible in the aggregate, so a watcher wakes
        // and — seeing `coarse` — drops everything.
        assert_eq!(snap.version as usize, MAX_TOPICS + 1);
    }

    #[tokio::test]
    async fn a_watcher_wakes_on_a_bump() {
        let e = std::sync::Arc::new(ChangeEpochs::new());
        let since = e.version();
        let waiter = {
            let e = e.clone();
            tokio::spawn(async move { e.wait_for_change(since, Duration::from_secs(5)).await })
        };
        // Give the waiter a chance to register before bumping.
        tokio::task::yield_now().await;
        e.bump(&ChangeEpochs::topic("", "pki/"));
        assert!(waiter.await.unwrap(), "the watcher must observe the bump");
    }

    #[tokio::test]
    async fn a_watcher_returns_immediately_when_it_is_already_behind() {
        let e = ChangeEpochs::new();
        let since = e.version();
        e.bump(&ChangeEpochs::topic("", "pki/"));
        // No wakeup is pending — the bump happened before the wait — so this
        // can only pass because `wait_for_change` re-checks the version
        // first. Without that check a client that missed a notification
        // would block for the whole timeout on every poll.
        assert!(e.wait_for_change(since, Duration::from_secs(5)).await);
    }

    #[tokio::test]
    async fn a_quiet_watch_times_out_rather_than_hanging() {
        let e = ChangeEpochs::new();
        let since = e.version();
        assert!(!e.wait_for_change(since, Duration::from_millis(50)).await);
    }
}
