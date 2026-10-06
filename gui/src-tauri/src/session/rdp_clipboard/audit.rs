//! Per-transfer audit for RDP clipboard redirection (T35 Phase 4).
//!
//! Every transfer — text, image, file; either direction; accepted or not —
//! becomes one [`TransferEvent`]: direction, kind, outcome and a byte count.
//! Nothing else exists to be recorded: no content, no file names, no paths.
//!
//! Events are **batched** ([`FLUSH_INTERVAL`], [`MAX_ENTRIES_PER_BATCH`]) and
//! **rate-limited** ([`MAX_FLUSHES_PER_WINDOW`] per [`RATE_WINDOW`]). A
//! transfer that arrives while its batch is full is not dropped: it is folded
//! into the batch's `overflow` count and byte total, so a flood costs a
//! bounded number of audit records and still accounts for every transfer.
//!
//! Each batch goes two places:
//!
//! 1. a host audit line (`target: "audit"`, `connect.rdp.clipboard`), like
//!    the host's `session.open` / `session.close` lines, and
//! 2. the vault, `POST resources/v2/connect/clipboard/audit`, where the
//!    request pipeline writes it to every audit device. This is the record
//!    an auditor actually reads.
//!
//! **Fail closed.** If the vault refuses or cannot take a batch (after one
//! retry), the session's clipboard is *withdrawn*: the backend refuses every
//! further transfer for the rest of the session and says so. A clipboard
//! that keeps moving data it can no longer account for is the silent
//! downgrade AGENTS.md §7 forbids. The one exception is a vault that has no
//! such endpoint at all — a server predating T35, detected from its policy
//! resolver before the session opens, not guessed from an error — where the
//! host line is the only record and the connect path logs that once.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use tokio::sync::mpsc as tokio_mpsc;

use super::SharedClipboardStats;

/// Longest a transfer waits before its batch is sent.
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(10);
/// A batch is sent early once it holds this many transfers. Well under the
/// server's own cap (256).
pub const MAX_ENTRIES_PER_BATCH: usize = 64;
/// Rate-limit window and the most batches sent in one. The session's final
/// batch is exempt, so the close is always recorded.
pub const RATE_WINDOW: Duration = Duration::from_secs(60);
pub const MAX_FLUSHES_PER_WINDOW: u32 = 12;
/// The vault endpoint the batches go to.
pub const AUDIT_PATH: &str = "resources/v2/connect/clipboard/audit";
/// Pause before the one retry of a refused batch.
const RETRY_DELAY: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransferDirection {
    HostToSession,
    SessionToHost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransferKind {
    Text,
    Image,
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransferOutcome {
    Ok,
    /// Over a size or count cap: dropped whole.
    Oversize,
    /// Withheld by the direction switch, the policy ceiling, or a withdrawn
    /// clipboard.
    Refused,
    /// Failed validation (a bad DIB, bad UTF-16, a bad file list or name).
    Malformed,
    /// A local failure: host clipboard, disk, timeout, remote error.
    Error,
}

impl TransferDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HostToSession => "host-to-session",
            Self::SessionToHost => "session-to-host",
        }
    }
}

impl TransferKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Image => "image",
            Self::File => "file",
        }
    }
}

impl TransferOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Oversize => "oversize",
            Self::Refused => "refused",
            Self::Malformed => "malformed",
            Self::Error => "error",
        }
    }
}

/// One transfer. `bytes` is the wire size moved, or for a refusal the size
/// that was attempted (where known) — a size, never content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferEvent {
    pub direction: TransferDirection,
    pub kind: TransferKind,
    pub outcome: TransferOutcome,
    pub bytes: u64,
}

impl TransferEvent {
    pub fn new(direction: TransferDirection, kind: TransferKind, outcome: TransferOutcome, bytes: u64) -> Self {
        Self { direction, kind, outcome, bytes }
    }

    fn key(&self) -> String {
        format!("{}.{}.{}", self.direction.as_str(), self.kind.as_str(), self.outcome.as_str())
    }
}

/// One batch, ready to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditBatch {
    pub seq: u64,
    pub is_final: bool,
    /// key → per-transfer byte counts.
    pub transfers: BTreeMap<String, Vec<u64>>,
    /// key → (count, bytes) for transfers folded in past the batch cap.
    pub overflow: BTreeMap<String, (u64, u64)>,
}

impl AuditBatch {
    pub fn transfer_count(&self) -> u64 {
        self.transfers.values().map(|v| v.len() as u64).sum::<u64>()
            + self.overflow.values().map(|(c, _)| *c).sum::<u64>()
    }

    pub fn byte_count(&self) -> u64 {
        self.transfers.values().flatten().sum::<u64>() + self.overflow.values().map(|(_, b)| *b).sum::<u64>()
    }

    /// The vault request body. Metadata words are keys, every value is a
    /// number — the audit device HMACs strings but not keys or numbers, so
    /// the row stays readable, and there is no string slot for a name.
    pub fn to_body(&self, resource: &str, profile_id: &str, session: &str) -> Map<String, Value> {
        let mut body = Map::new();
        body.insert("resource".into(), Value::String(resource.to_string()));
        body.insert("profile_id".into(), Value::String(profile_id.to_string()));
        body.insert("session".into(), Value::String(session.to_string()));
        body.insert("seq".into(), Value::from(self.seq));
        body.insert("final".into(), Value::Bool(self.is_final));
        let transfers: Map<String, Value> = self
            .transfers
            .iter()
            .map(|(k, v)| (k.clone(), Value::Array(v.iter().map(|n| Value::from(*n)).collect())))
            .collect();
        body.insert("transfers".into(), Value::Object(transfers));
        if !self.overflow.is_empty() {
            let overflow: Map<String, Value> = self
                .overflow
                .iter()
                .map(|(k, (c, b))| {
                    let mut m = Map::new();
                    m.insert("count".into(), Value::from(*c));
                    m.insert("bytes".into(), Value::from(*b));
                    (k.clone(), Value::Object(m))
                })
                .collect();
            body.insert("overflow".into(), Value::Object(overflow));
        }
        body
    }

    /// `key=count` pairs for the host audit line.
    pub fn summary(&self) -> String {
        let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
        for (k, v) in &self.transfers {
            *counts.entry(k).or_default() += v.len() as u64;
        }
        for (k, (c, _)) in &self.overflow {
            *counts.entry(k).or_default() += c;
        }
        counts.iter().map(|(k, n)| format!("{k}={n}")).collect::<Vec<_>>().join(",")
    }
}

/// The batching and rate-limiting decisions, with no I/O and an injected
/// clock, so every rule is unit-testable.
#[derive(Debug)]
pub struct AuditBatcher {
    transfers: BTreeMap<String, Vec<u64>>,
    entries: usize,
    overflow: BTreeMap<String, (u64, u64)>,
    first_pending_at: Option<Instant>,
    window_start: Instant,
    flushes_in_window: u32,
    seq: u64,
}

impl AuditBatcher {
    pub fn new(now: Instant) -> Self {
        Self {
            transfers: BTreeMap::new(),
            entries: 0,
            overflow: BTreeMap::new(),
            first_pending_at: None,
            window_start: now,
            flushes_in_window: 0,
            seq: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.entries == 0 && self.overflow.is_empty()
    }

    pub fn record(&mut self, event: TransferEvent, now: Instant) {
        self.first_pending_at.get_or_insert(now);
        let key = event.key();
        if self.entries < MAX_ENTRIES_PER_BATCH {
            self.transfers.entry(key).or_default().push(event.bytes);
            self.entries += 1;
        } else {
            let slot = self.overflow.entry(key).or_insert((0, 0));
            slot.0 += 1;
            slot.1 = slot.1.saturating_add(event.bytes);
        }
    }

    fn roll_window(&mut self, now: Instant) {
        if now.duration_since(self.window_start) >= RATE_WINDOW {
            self.window_start = now;
            self.flushes_in_window = 0;
        }
    }

    /// Whether a batch should be sent now.
    pub fn due(&mut self, now: Instant) -> bool {
        if self.is_empty() {
            return false;
        }
        self.roll_window(now);
        if self.flushes_in_window >= MAX_FLUSHES_PER_WINDOW {
            return false;
        }
        self.entries >= MAX_ENTRIES_PER_BATCH
            || self.first_pending_at.is_some_and(|t| now.duration_since(t) >= FLUSH_INTERVAL)
    }

    /// Take the pending batch. `is_final` marks the session's last one: it
    /// ignores the rate limit, and is produced even when empty provided an
    /// earlier batch was sent (so an auditor sees the close); a session that
    /// never moved anything produces no record at all.
    pub fn take(&mut self, now: Instant, is_final: bool) -> Option<AuditBatch> {
        if self.is_empty() && !(is_final && self.seq > 0) {
            return None;
        }
        if !is_final {
            self.roll_window(now);
            self.flushes_in_window += 1;
        }
        let batch = AuditBatch {
            seq: self.seq,
            is_final,
            transfers: std::mem::take(&mut self.transfers),
            overflow: std::mem::take(&mut self.overflow),
        };
        self.seq += 1;
        self.entries = 0;
        self.first_pending_at = None;
        Some(batch)
    }
}

/// Who a session's batches are about.
#[derive(Debug, Clone)]
pub struct AuditContext {
    pub resource: String,
    pub profile_id: String,
    /// False only for a vault that predates the endpoint (see the module
    /// docs); the host line is then the only record.
    pub vault_audit: bool,
}

/// Where the backend and the bridge thread report transfers. Cheap to
/// clone; a send never blocks.
#[derive(Debug, Clone)]
pub struct AuditSink {
    tx: Option<tokio_mpsc::UnboundedSender<TransferEvent>>,
}

impl AuditSink {
    #[cfg(test)]
    pub fn for_test() -> (Self, tokio_mpsc::UnboundedReceiver<TransferEvent>) {
        let (tx, rx) = tokio_mpsc::unbounded_channel();
        (Self { tx: Some(tx) }, rx)
    }

    pub fn record(&self, event: TransferEvent) {
        if let Some(tx) = &self.tx {
            // A closed receiver means the session's audit task has finished;
            // the session is closing and nothing more can move.
            let _ = tx.send(event);
        }
    }
}

/// Withdrawing a session's clipboard: raise the flag the backend and the
/// bridge check before every transfer, and show it on the session's
/// counters. Done once; later failures change nothing.
#[derive(Debug, Clone)]
pub struct Withdraw {
    flag: Arc<AtomicBool>,
    stats: SharedClipboardStats,
}

impl Withdraw {
    pub fn new(stats: SharedClipboardStats) -> Self {
        Self { flag: Arc::new(AtomicBool::new(false)), stats }
    }

    /// The flag to hand the backend and the bridge.
    pub fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.flag)
    }

    /// Withdraw; true the first time.
    fn trigger(&self) -> bool {
        let first = !self.flag.swap(true, Ordering::SeqCst);
        if first {
            if let Ok(mut s) = self.stats.lock() {
                s.withdrawn = true;
            }
        }
        first
    }

    #[cfg(test)]
    fn is_set(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

/// How a batch is delivered. A trait so the flush loop can be exercised
/// without a vault.
pub trait AuditDelivery: Send + Sync + 'static {
    fn deliver(
        &self,
        body: Map<String, Value>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>>;
}

/// Start the session's audit task. Returns the sink to hand the backend and
/// the bridge; the task ends (after a final flush) once every sink clone is
/// dropped.
pub fn spawn(
    ctx: AuditContext,
    session: String,
    label: String,
    withdrawn: Withdraw,
    delivery: Arc<dyn AuditDelivery>,
) -> AuditSink {
    let (tx, rx) = tokio_mpsc::unbounded_channel();
    tokio::spawn(run(ctx, session, label, withdrawn, delivery, rx, RETRY_DELAY));
    AuditSink { tx: Some(tx) }
}

async fn run(
    ctx: AuditContext,
    session: String,
    label: String,
    withdrawn: Withdraw,
    delivery: Arc<dyn AuditDelivery>,
    mut rx: tokio_mpsc::UnboundedReceiver<TransferEvent>,
    retry_delay: Duration,
) {
    let mut batcher = AuditBatcher::new(Instant::now());
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Some(ev) => batcher.record(ev, Instant::now()),
                None => break,
            },
            _ = tick.tick() => {}
        }
        let now = Instant::now();
        if batcher.due(now) {
            if let Some(batch) = batcher.take(now, false) {
                flush(&ctx, &session, &label, &withdrawn, delivery.as_ref(), batch, retry_delay).await;
            }
        }
    }
    if let Some(batch) = batcher.take(Instant::now(), true) {
        flush(&ctx, &session, &label, &withdrawn, delivery.as_ref(), batch, retry_delay).await;
    }
}

async fn flush(
    ctx: &AuditContext,
    session: &str,
    label: &str,
    withdrawn: &Withdraw,
    delivery: &dyn AuditDelivery,
    batch: AuditBatch,
    retry_delay: Duration,
) {
    // Host line first, so the record exists locally even if the vault
    // write below fails. Counts and outcomes only.
    log::info!(
        target: "audit",
        "connect.rdp.clipboard: resource={} profile={} token={session} seq={} final={} transfers={} bytes={} [{}]",
        ctx.resource,
        ctx.profile_id,
        batch.seq,
        batch.is_final,
        batch.transfer_count(),
        batch.byte_count(),
        batch.summary(),
    );
    if !ctx.vault_audit {
        return;
    }
    let body = batch.to_body(&ctx.resource, &ctx.profile_id, session);
    let first = delivery.deliver(body.clone()).await;
    let outcome = match first {
        Ok(()) => Ok(()),
        Err(_) => {
            tokio::time::sleep(retry_delay).await;
            delivery.deliver(body).await
        }
    };
    if let Err(e) = outcome {
        // Fail closed: stop moving data we can no longer account for.
        if withdrawn.trigger() {
            log::warn!(
                "rdp clipboard [{label}]: the vault refused the clipboard audit batch ({e}); \
                 clipboard redirection is withdrawn for the rest of this session"
            );
            log::warn!(
                target: "audit",
                "connect.rdp.clipboard.withdrawn: resource={} profile={} token={session} reason=audit_unavailable seq={}",
                ctx.resource,
                ctx.profile_id,
                batch.seq,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn ev(outcome: TransferOutcome, bytes: u64) -> TransferEvent {
        TransferEvent::new(TransferDirection::SessionToHost, TransferKind::Text, outcome, bytes)
    }

    #[test]
    fn nothing_is_sent_for_a_session_that_moved_nothing() {
        let t0 = Instant::now();
        let mut b = AuditBatcher::new(t0);
        assert!(!b.due(t0 + FLUSH_INTERVAL * 10));
        assert!(b.take(t0, true).is_none(), "no final record for an idle session");
    }

    #[test]
    fn a_batch_waits_for_the_interval_or_the_cap() {
        let t0 = Instant::now();
        let mut b = AuditBatcher::new(t0);
        b.record(ev(TransferOutcome::Ok, 10), t0);
        assert!(!b.due(t0 + Duration::from_secs(1)));
        assert!(b.due(t0 + FLUSH_INTERVAL));

        let mut b = AuditBatcher::new(t0);
        for _ in 0..MAX_ENTRIES_PER_BATCH {
            b.record(ev(TransferOutcome::Ok, 1), t0);
        }
        assert!(b.due(t0), "a full batch goes immediately");
    }

    #[test]
    fn a_flood_is_folded_into_overflow_not_dropped() {
        let t0 = Instant::now();
        let mut b = AuditBatcher::new(t0);
        let flood = MAX_ENTRIES_PER_BATCH as u64 + 500;
        for i in 0..flood {
            b.record(ev(TransferOutcome::Ok, i), t0);
        }
        let batch = b.take(t0, false).unwrap();
        assert_eq!(batch.transfer_count(), flood, "every transfer is accounted for");
        assert_eq!(batch.byte_count(), (0..flood).sum::<u64>());
        assert_eq!(batch.transfers.values().map(Vec::len).sum::<usize>(), MAX_ENTRIES_PER_BATCH);
        assert_eq!(batch.overflow["session-to-host.text.ok"].0, 500);
    }

    #[test]
    fn the_rate_limit_holds_batches_back_until_the_window_rolls() {
        let t0 = Instant::now();
        let mut b = AuditBatcher::new(t0);
        for _ in 0..MAX_FLUSHES_PER_WINDOW {
            b.record(ev(TransferOutcome::Ok, 1), t0);
            assert!(b.due(t0 + FLUSH_INTERVAL));
            b.take(t0 + FLUSH_INTERVAL, false).unwrap();
        }
        b.record(ev(TransferOutcome::Ok, 1), t0);
        assert!(!b.due(t0 + FLUSH_INTERVAL * 2), "the window's budget is spent");
        assert!(b.due(t0 + RATE_WINDOW + FLUSH_INTERVAL), "a new window has budget again");
    }

    #[test]
    fn the_final_batch_ignores_the_rate_limit_and_marks_the_close() {
        let t0 = Instant::now();
        let mut b = AuditBatcher::new(t0);
        for _ in 0..MAX_FLUSHES_PER_WINDOW {
            b.record(ev(TransferOutcome::Ok, 1), t0);
            b.take(t0, false).unwrap();
        }
        b.record(ev(TransferOutcome::Error, 0), t0);
        let last = b.take(t0, true).expect("the close is always recorded");
        assert!(last.is_final);
        assert_eq!(last.seq, u64::from(MAX_FLUSHES_PER_WINDOW));
        // After earlier batches, an empty final batch still marks the close.
        let mut b = AuditBatcher::new(t0);
        b.record(ev(TransferOutcome::Ok, 1), t0);
        b.take(t0, false).unwrap();
        let close = b.take(t0, true).unwrap();
        assert!(close.is_final && close.transfer_count() == 0);
    }

    #[test]
    fn the_body_carries_metadata_words_as_keys_and_numbers_only() {
        let t0 = Instant::now();
        let mut b = AuditBatcher::new(t0);
        b.record(ev(TransferOutcome::Ok, 120), t0);
        b.record(
            TransferEvent::new(TransferDirection::HostToSession, TransferKind::File, TransferOutcome::Oversize, 9),
            t0,
        );
        let body = b.take(t0, false).unwrap().to_body("srv1", "p_1", "rdp_ab");
        let transfers = body["transfers"].as_object().unwrap();
        assert_eq!(transfers["session-to-host.text.ok"], serde_json::json!([120]));
        assert_eq!(transfers["host-to-session.file.oversize"], serde_json::json!([9]));
        // The only strings are the three identifiers the endpoint requires.
        let strings: Vec<&str> = body.iter().filter(|(_, v)| v.is_string()).map(|(k, _)| k.as_str()).collect();
        assert_eq!(strings, vec!["profile_id", "resource", "session"]);
        assert!(transfers.values().flat_map(|v| v.as_array().unwrap()).all(Value::is_u64));
    }

    /// The vocabulary the host emits must be exactly what the server's
    /// validator accepts (`bv-engine-resource` `connect_clipboard.rs`);
    /// a drift would refuse every batch and withdraw every clipboard.
    #[test]
    fn every_key_the_host_can_emit_is_in_the_server_vocabulary() {
        const DIRECTIONS: [&str; 2] = ["host-to-session", "session-to-host"];
        const KINDS: [&str; 3] = ["text", "image", "file"];
        const OUTCOMES: [&str; 5] = ["ok", "oversize", "refused", "malformed", "error"];
        for d in [TransferDirection::HostToSession, TransferDirection::SessionToHost] {
            assert!(DIRECTIONS.contains(&d.as_str()));
        }
        for k in [TransferKind::Text, TransferKind::Image, TransferKind::File] {
            assert!(KINDS.contains(&k.as_str()));
        }
        for o in [
            TransferOutcome::Ok,
            TransferOutcome::Oversize,
            TransferOutcome::Refused,
            TransferOutcome::Malformed,
            TransferOutcome::Error,
        ] {
            assert!(OUTCOMES.contains(&o.as_str()));
        }
    }

    struct Recorder {
        fail: bool,
        calls: Mutex<Vec<Map<String, Value>>>,
    }

    impl AuditDelivery for Recorder {
        fn deliver(
            &self,
            body: Map<String, Value>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
            self.calls.lock().unwrap().push(body);
            let fail = self.fail;
            Box::pin(async move {
                if fail {
                    Err("HTTP 403: permission denied".into())
                } else {
                    Ok(())
                }
            })
        }
    }

    fn ctx() -> AuditContext {
        AuditContext { resource: "srv1".into(), profile_id: "p_1".into(), vault_audit: true }
    }

    #[tokio::test]
    async fn a_refused_batch_is_retried_once_then_withdraws_the_clipboard() {
        let withdrawn = Withdraw::new(Arc::new(Mutex::new(super::super::ClipboardStats::default())));
        let rec = Arc::new(Recorder { fail: true, calls: Mutex::new(Vec::new()) });
        let mut b = AuditBatcher::new(Instant::now());
        b.record(ev(TransferOutcome::Ok, 5), Instant::now());
        let batch = b.take(Instant::now(), false).unwrap();
        flush(&ctx(), "rdp_ab", "test", &withdrawn, rec.as_ref(), batch, Duration::ZERO).await;
        assert_eq!(rec.calls.lock().unwrap().len(), 2, "one retry, then give up");
        assert!(withdrawn.is_set(), "an unrecordable clipboard fails closed");
        assert!(withdrawn.stats.lock().unwrap().withdrawn, "and the session's counters say so");
    }

    #[tokio::test]
    async fn a_delivered_batch_leaves_the_clipboard_alone() {
        let withdrawn = Withdraw::new(Arc::new(Mutex::new(super::super::ClipboardStats::default())));
        let rec = Arc::new(Recorder { fail: false, calls: Mutex::new(Vec::new()) });
        let mut b = AuditBatcher::new(Instant::now());
        b.record(ev(TransferOutcome::Ok, 5), Instant::now());
        flush(
            &ctx(),
            "rdp_ab",
            "test",
            &withdrawn,
            rec.as_ref(),
            b.take(Instant::now(), false).unwrap(),
            Duration::ZERO,
        )
        .await;
        assert_eq!(rec.calls.lock().unwrap().len(), 1);
        assert!(!withdrawn.is_set());
    }

    #[tokio::test]
    async fn a_vault_without_the_endpoint_gets_the_host_line_only() {
        let withdrawn = Withdraw::new(Arc::new(Mutex::new(super::super::ClipboardStats::default())));
        let rec = Arc::new(Recorder { fail: true, calls: Mutex::new(Vec::new()) });
        let mut b = AuditBatcher::new(Instant::now());
        b.record(ev(TransferOutcome::Ok, 5), Instant::now());
        let old_vault = AuditContext { vault_audit: false, ..ctx() };
        flush(
            &old_vault,
            "rdp_ab",
            "test",
            &withdrawn,
            rec.as_ref(),
            b.take(Instant::now(), false).unwrap(),
            Duration::ZERO,
        )
        .await;
        assert!(rec.calls.lock().unwrap().is_empty());
        assert!(!withdrawn.is_set(), "capability was detected up front, not inferred from an error");
    }

    #[tokio::test]
    async fn the_task_flushes_on_close() {
        let withdrawn = Withdraw::new(Arc::new(Mutex::new(super::super::ClipboardStats::default())));
        let rec = Arc::new(Recorder { fail: false, calls: Mutex::new(Vec::new()) });
        let delivery: Arc<dyn AuditDelivery> = rec.clone();
        let (tx, rx) = tokio_mpsc::unbounded_channel();
        let task = tokio::spawn(run(ctx(), "rdp_ab".into(), "test".into(), withdrawn, delivery, rx, Duration::ZERO));
        tx.send(ev(TransferOutcome::Ok, 7)).unwrap();
        drop(tx);
        task.await.unwrap();
        let calls = rec.calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "the pending transfer goes out with the close");
        assert_eq!(calls[0]["final"], Value::Bool(true));
        assert_eq!(calls[0]["transfers"]["session-to-host.text.ok"], serde_json::json!([7]));
    }
}
