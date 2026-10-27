//! Multiplexed long-lived process invocations (ABI 1.4, `concurrent = true`,
//! features/sql-browser.md §9.4). One reader task routes the child's lines to
//! per-invocation channels and one writer sits behind a lock. A timed-out
//! invocation is cancelled; the child is torn down only for a protocol
//! violation or a missed heartbeat.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock, Weak};
use std::time::{Duration, Instant};

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::{mpsc, oneshot, watch, Mutex, Semaphore};
use zeroize::Zeroizing;

use super::invocation::InvocationCaller;
use super::manifest::PluginManifest;
use super::process_runtime::{handle_host_call, scrub};
use super::runtime::{InvokeOutcome, InvokeOutput};
use crate::kernel_api::VaultCtx;

/// Longest line the host reads from a multiplexed child (Phase 0 item 8):
/// the 4 MiB of the host HTTP and WASM payload caps. Longer fails the
/// invocation it belongs to, not the child.
pub const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;
/// Bytes kept from each end of an oversized line to attribute it.
const HEADER_PREFIX_BYTES: usize = 1024;
/// Host calls one invocation may have queued before further ones are refused.
const PENDING_HOST_CALLS: usize = 64;
/// How long a child has to acknowledge a lifecycle message (§6.7).
pub const LIFECYCLE_DEADLINE: Duration = Duration::from_secs(10);
/// How long the spawn handshake may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// Heartbeat cadence. A child that answers nothing (not even a `ping`) for
/// `heartbeat_timeout` is wedged and is torn down.
#[derive(Debug, Clone, Copy)]
pub struct MuxTimings {
    pub heartbeat_interval: Duration,
    pub heartbeat_timeout: Duration,
}

impl Default for MuxTimings {
    fn default() -> Self {
        Self { heartbeat_interval: Duration::from_secs(10), heartbeat_timeout: Duration::from_secs(30) }
    }
}

static TIMINGS: RwLock<Option<MuxTimings>> = RwLock::new(None);

fn timings() -> MuxTimings {
    TIMINGS.read().ok().and_then(|t| *t).unwrap_or_default()
}

/// Override the heartbeat cadence for workers spawned afterwards (tests).
#[doc(hidden)]
pub fn set_timings_for_tests(t: MuxTimings) {
    if let Ok(mut g) = TIMINGS.write() {
        *g = Some(t);
    }
}

/// Host → plugin lifecycle events (§6.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleEvent {
    /// The vault is sealing: close every session, zeroize every released
    /// credential, drop every run buffer.
    Seal,
    /// The plugin is being reloaded or deregistered.
    Reload,
    /// The node is shutting down.
    Shutdown,
}

/// Why a worker stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeathCause {
    /// stdout closed: the child exited or crashed.
    Eof,
    /// The child broke the protocol.
    ProtocolViolation(&'static str),
    /// The child stopped answering, `ping` included.
    MissedHeartbeat,
    /// The host tore it down (reload, seal without acknowledgement).
    Teardown,
}

impl DeathCause {
    /// Counts toward the crash breaker. A host-initiated teardown does not.
    pub fn is_crash(&self) -> bool {
        !matches!(self, DeathCause::Teardown)
    }
}

impl std::fmt::Display for DeathCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeathCause::Eof => f.write_str("child exited"),
            DeathCause::ProtocolViolation(m) => write!(f, "protocol violation: {m}"),
            DeathCause::MissedHeartbeat => f.write_str("missed heartbeat"),
            DeathCause::Teardown => f.write_str("torn down by the host"),
        }
    }
}

/// How a multiplexed invocation failed.
#[derive(Debug, thiserror::Error)]
pub enum MuxError {
    #[error("multiplexed plugin io: {0}")]
    Io(String),
    #[error("multiplexed plugin invocation timed out after {0:?} and was cancelled")]
    Timeout(Duration),
    #[error("multiplexed plugin has {0} invocations in flight; none freed up before the deadline")]
    Busy(u32),
    #[error("multiplexed plugin invocation failed: {0}")]
    InvocationFailed(String),
    #[error("multiplexed plugin stopped: {0}")]
    Died(String),
    #[error("multiplexed plugin handshake failed: {0}")]
    Handshake(String),
}

// ── wire messages ───────────────────────────────────────────────────────

/// Host → plugin, one JSON object per line. `init` and `invoke` keep the
/// long-lived shapes; `host_reply` carries `result` or `error` and names
/// its invocation; `cancel`, `ping` and `lifecycle` are new in ABI 1.4.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HostMsg<'a> {
    Init { plugin_name: &'a str, protocol: &'static str, max_concurrent: u32 },
    Invoke { id: u64, input: String },
    HostReply {
        id: u64,
        invocation: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        result: Option<&'a Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<&'a str>,
    },
    Cancel { id: u64 },
    Ping { nonce: u64 },
    Lifecycle { event: LifecycleEvent, deadline_ms: u64 },
}

/// Plugin → host. Anything else is a protocol violation.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PluginMsg {
    Hello {
        token: String,
    },
    HostCall {
        id: u64,
        invocation: u64,
        method: String,
        #[serde(default)]
        params: Value,
    },
    Done {
        id: u64,
        status: i32,
        #[serde(default)]
        data_b64: String,
    },
    Pong {
        #[allow(dead_code)]
        nonce: u64,
    },
    LifecycleAck {
        event: LifecycleEvent,
    },
}

// ── bounded line reader ─────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Line {
    /// A complete line is in the buffer (without the newline).
    Complete,
    /// Longer than the limit: the buffer holds its first and last
    /// [`HEADER_PREFIX_BYTES`] joined by a newline; the rest was discarded.
    TooLong,
    /// End of stream (a partial last line is discarded).
    Eof,
}

/// Read one line of at most `max` bytes. An oversized line is consumed to
/// its newline without being kept, so a child cannot make the host buffer
/// more than `max` bytes of one line.
pub(super) async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<Line> {
    buf.clear();
    let mut overflow = false;
    let mut tail: Vec<u8> = Vec::new();
    loop {
        let available = r.fill_buf().await?;
        if available.is_empty() {
            return Ok(Line::Eof);
        }
        let (chunk, found) = match available.iter().position(|b| *b == b'\n') {
            Some(i) => (&available[..i], Some(i)),
            None => (available, None),
        };
        if !overflow && buf.len() + chunk.len() > max {
            overflow = true;
            tail.extend_from_slice(&buf[HEADER_PREFIX_BYTES.min(buf.len())..]);
            buf.truncate(HEADER_PREFIX_BYTES);
        }
        if overflow {
            let head_room = HEADER_PREFIX_BYTES.saturating_sub(buf.len()).min(chunk.len());
            buf.extend_from_slice(&chunk[..head_room]);
            tail.extend_from_slice(&chunk[head_room..]);
            if tail.len() > HEADER_PREFIX_BYTES {
                tail.drain(..tail.len() - HEADER_PREFIX_BYTES);
            }
        } else {
            buf.extend_from_slice(chunk);
        }
        let used = found.map(|i| i + 1).unwrap_or(available.len());
        r.consume(used);
        if found.is_some() {
            if overflow {
                buf.push(b'\n');
                buf.extend_from_slice(&tail);
                return Ok(Line::TooLong);
            }
            return Ok(Line::Complete);
        }
    }
}

/// `"key": <u64>` at the first occurrence of `key` (whitespace tolerated).
fn header_u64(text: &str, key: &str) -> Option<u64> {
    let at = text.find(&format!("\"{key}\""))? + key.len() + 2;
    value_u64(&text[at..])
}

/// As [`header_u64`], at the last occurrence: the tail of an oversized line.
fn trailer_u64(text: &str, key: &str) -> Option<u64> {
    let at = text.rfind(&format!("\"{key}\""))? + key.len() + 2;
    value_u64(&text[at..])
}

fn value_u64(rest: &str) -> Option<u64> {
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// `"key": "<value>"` at the first occurrence of `key`.
fn header_str<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let at = text.find(&format!("\"{key}\""))? + key.len() + 2;
    let rest = text[at..].trim_start().strip_prefix(':')?.trim_start().strip_prefix('"')?;
    rest.split('"').next()
}

/// Which message an oversized line is, from its head and tail: `(type,
/// id, invocation)`. Keys may come in any order, so each is looked for at
/// the head first and at the tail second.
fn attribute(head: &str, tail: &str) -> Option<(String, u64, u64)> {
    let kind = header_str(head, "type").or_else(|| header_str(tail, "type"))?.to_string();
    let id = header_u64(head, "id").or_else(|| trailer_u64(tail, "id"))?;
    let invocation = header_u64(head, "invocation").or_else(|| trailer_u64(tail, "invocation")).unwrap_or(0);
    Some((kind, id, invocation))
}

// ── the worker ──────────────────────────────────────────────────────────

/// The result of one invocation, routed by the reader.
enum DoneEvent {
    Done { status: i32, response: Vec<u8> },
    Failed(String),
    Died(String),
}

struct HostCallReq {
    id: u64,
    method: String,
    params: Value,
}

struct Inflight {
    calls: mpsc::Sender<HostCallReq>,
    done: oneshot::Sender<DoneEvent>,
}

/// One multiplexed child.
pub struct MuxWorker {
    plugin: String,
    max_concurrent: u32,
    writer: Mutex<ChildStdin>,
    child: Mutex<Option<Child>>,
    pid: Option<u32>,
    inflight: StdMutex<HashMap<u64, Inflight>>,
    next_id: AtomicU64,
    slots: Arc<Semaphore>,
    dead: AtomicBool,
    cause: StdMutex<Option<DeathCause>>,
    dead_tx: watch::Sender<bool>,
    last_seen: StdMutex<Instant>,
    lifecycle_waiters: StdMutex<Vec<(LifecycleEvent, oneshot::Sender<()>)>>,
    lifecycle_acks: AtomicU64,
}

impl MuxWorker {
    /// Handshake with a freshly spawned child, then start its reader and
    /// heartbeat tasks.
    pub async fn start(
        manifest: &PluginManifest,
        mut child: Child,
        stdin: ChildStdin,
        stdout: ChildStdout,
        bootstrap: &str,
    ) -> Result<Arc<Self>, MuxError> {
        let mut reader = BufReader::new(stdout);
        let max_concurrent = manifest.capabilities.effective_max_concurrent();
        let pid = child.id();
        let worker = Arc::new(Self {
            plugin: manifest.name.clone(),
            max_concurrent,
            writer: Mutex::new(stdin),
            child: Mutex::new(None),
            pid,
            inflight: StdMutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            slots: Arc::new(Semaphore::new(max_concurrent as usize)),
            dead: AtomicBool::new(false),
            cause: StdMutex::new(None),
            dead_tx: watch::channel(false).0,
            last_seen: StdMutex::new(Instant::now()),
            lifecycle_waiters: StdMutex::new(Vec::new()),
            lifecycle_acks: AtomicU64::new(0),
        });
        let init = HostMsg::Init { plugin_name: &manifest.name, protocol: "multiplexed", max_concurrent };
        if let Err(e) = worker.write(&init).await {
            let _ = child.start_kill();
            return Err(MuxError::Handshake(e.to_string()));
        }
        let hello = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            let mut buf = Vec::new();
            loop {
                match read_bounded_line(&mut reader, &mut buf, MAX_LINE_BYTES).await {
                    Ok(Line::Complete) if buf.iter().all(u8::is_ascii_whitespace) => continue,
                    Ok(Line::Complete) => return serde_json::from_slice::<PluginMsg>(&buf).ok(),
                    _ => return None,
                }
            }
        })
        .await;
        match hello {
            Ok(Some(PluginMsg::Hello { token })) if token == bootstrap => {}
            other => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                let why = match other {
                    Ok(Some(PluginMsg::Hello { .. })) => "bootstrap token mismatch",
                    Ok(_) => "expected hello as the first message",
                    Err(_) => "no hello before the handshake deadline",
                };
                return Err(MuxError::Handshake(why.to_string()));
            }
        }
        *worker.child.lock().await = Some(child);
        tokio::spawn(read_loop(worker.clone(), reader));
        tokio::spawn(heartbeat_loop(Arc::downgrade(&worker), timings()));
        Ok(worker)
    }

    pub fn plugin(&self) -> &str {
        &self.plugin
    }

    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    pub fn max_concurrent(&self) -> u32 {
        self.max_concurrent
    }

    /// Lifecycle acknowledgements received so far.
    pub fn lifecycle_acks(&self) -> u64 {
        self.lifecycle_acks.load(Ordering::SeqCst)
    }

    fn cause_text(&self) -> String {
        self.cause.lock().ok().and_then(|c| c.clone()).unwrap_or(DeathCause::Eof).to_string()
    }

    /// Resolves once the worker has stopped, with the cause.
    pub async fn wait_dead(&self) -> DeathCause {
        let mut rx = self.dead_tx.subscribe();
        while !*rx.borrow() {
            if rx.changed().await.is_err() {
                break;
            }
        }
        self.cause.lock().ok().and_then(|c| c.clone()).unwrap_or(DeathCause::Eof)
    }

    async fn write(&self, msg: &HostMsg<'_>) -> Result<(), MuxError> {
        // Zeroized once written: a host reply can carry a released credential.
        let mut line = Zeroizing::new(serde_json::to_vec(msg).map_err(|e| MuxError::Io(e.to_string()))?);
        line.push(b'\n');
        let mut w = self.writer.lock().await;
        w.write_all(&line).await.map_err(|e| MuxError::Io(e.to_string()))?;
        w.flush().await.map_err(|e| MuxError::Io(e.to_string()))
    }

    /// Stop the worker: record the cause (first one wins), fail every
    /// invocation in flight, and kill the child.
    pub async fn die(&self, cause: DeathCause) {
        if let Ok(mut c) = self.cause.lock() {
            if c.is_none() {
                *c = Some(cause.clone());
            }
        }
        if self.dead.swap(true, Ordering::SeqCst) {
            return;
        }
        let drained: Vec<Inflight> = match self.inflight.lock() {
            Ok(mut m) => m.drain().map(|(_, v)| v).collect(),
            Err(_) => Vec::new(),
        };
        for f in drained {
            let _ = f.done.send(DoneEvent::Died(cause.to_string()));
        }
        if let Some(mut child) = self.child.lock().await.take() {
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
        let _ = self.dead_tx.send(true);
    }

    fn remove_inflight(&self, id: u64) -> Option<Inflight> {
        self.inflight.lock().ok().and_then(|mut m| m.remove(&id))
    }

    /// Send `event` and wait up to `deadline` for its acknowledgement.
    pub async fn lifecycle(&self, event: LifecycleEvent, deadline: Duration) -> bool {
        if self.is_dead() {
            return false;
        }
        let (tx, rx) = oneshot::channel();
        if let Ok(mut w) = self.lifecycle_waiters.lock() {
            w.push((event, tx));
        }
        let msg = HostMsg::Lifecycle { event, deadline_ms: deadline.as_millis() as u64 };
        if self.write(&msg).await.is_err() {
            return false;
        }
        matches!(tokio::time::timeout(deadline, rx).await, Ok(Ok(())))
    }

    /// Run one invocation. Its host calls are answered in this task against
    /// `caller`, and refused once it has finished.
    pub async fn invoke(
        self: &Arc<Self>,
        manifest: &PluginManifest,
        core: Option<Arc<dyn VaultCtx>>,
        config: &std::collections::BTreeMap<String, String>,
        caller: Option<&InvocationCaller>,
        input: &[u8],
        timeout: Duration,
    ) -> Result<InvokeOutput, MuxError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let _permit = match tokio::time::timeout_at(deadline, self.slots.clone().acquire_owned()).await {
            Ok(Ok(p)) => p,
            Ok(Err(_)) => return Err(MuxError::Died("worker closed".into())),
            Err(_) => return Err(MuxError::Busy(self.max_concurrent)),
        };
        if self.is_dead() {
            return Err(MuxError::Died(self.cause_text()));
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (calls_tx, mut calls_rx) = mpsc::channel(PENDING_HOST_CALLS);
        let (done_tx, mut done_rx) = oneshot::channel();
        if let Ok(mut m) = self.inflight.lock() {
            m.insert(id, Inflight { calls: calls_tx, done: done_tx });
        }
        let mut guard = InflightGuard { worker: self.clone(), id, finished: false };
        let input = base64::engine::general_purpose::STANDARD.encode(input);
        self.write(&HostMsg::Invoke { id, input }).await?;

        let run = async {
            loop {
                tokio::select! {
                    biased;
                    done = &mut done_rx => {
                        return match done {
                            Ok(DoneEvent::Done { status, response }) => {
                                let outcome = if status == 0 { InvokeOutcome::Success } else { InvokeOutcome::PluginError(status) };
                                Ok(InvokeOutput { outcome, response, fuel_consumed: 0 })
                            }
                            Ok(DoneEvent::Failed(m)) => Err(MuxError::InvocationFailed(m)),
                            Ok(DoneEvent::Died(m)) => Err(MuxError::Died(m)),
                            Err(_) => Err(MuxError::Died("worker closed".into())),
                        };
                    }
                    Some(call) = calls_rx.recv() => {
                        let result = handle_host_call(manifest, core.as_ref(), config, &call.method, &call.params, caller).await;
                        let (mut ok, error) = match result {
                            Ok(v) => (Some(v), None),
                            Err(e) => (None, Some(e)),
                        };
                        let reply = HostMsg::HostReply { id: call.id, invocation: id, result: ok.as_ref(), error: error.as_deref() };
                        let written = self.write(&reply).await;
                        if let Some(v) = ok.as_mut() {
                            scrub(v);
                        }
                        written?;
                    }
                }
            }
        };
        let outcome = tokio::time::timeout_at(deadline, run).await;
        guard.finished = true;
        match outcome {
            Ok(r) => r,
            Err(_) => {
                // Cancel, not kill: one slow handler must not drop every
                // other caller's sessions.
                self.remove_inflight(id);
                let _ = self.write(&HostMsg::Cancel { id }).await;
                Err(MuxError::Timeout(timeout))
            }
        }
    }
}

/// Removes an invocation from the routing table when its future ends, and
/// cancels it in the child when the caller went away mid-flight.
struct InflightGuard {
    worker: Arc<MuxWorker>,
    id: u64,
    finished: bool,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        let was_inflight = self.worker.remove_inflight(self.id).is_some();
        if !self.finished && was_inflight {
            let worker = self.worker.clone();
            let id = self.id;
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    let _ = worker.write(&HostMsg::Cancel { id }).await;
                });
            }
        }
    }
}

async fn reply_error(worker: &MuxWorker, id: u64, invocation: u64, error: &str) {
    let _ = worker.write(&HostMsg::HostReply { id, invocation, result: None, error: Some(error) }).await;
}

/// The single reader: routes every line, and stops the worker when the
/// stream ends or the child breaks the protocol.
async fn read_loop(worker: Arc<MuxWorker>, mut reader: BufReader<ChildStdout>) {
    let mut buf = Vec::new();
    let cause = loop {
        let line = match read_bounded_line(&mut reader, &mut buf, MAX_LINE_BYTES).await {
            Ok(l) => l,
            Err(_) => break DeathCause::Eof,
        };
        if let Ok(mut t) = worker.last_seen.lock() {
            *t = Instant::now();
        }
        match line {
            Line::Eof => break DeathCause::Eof,
            Line::TooLong => {
                if let Err(c) = route_oversized(&worker, &buf).await {
                    break c;
                }
            }
            Line::Complete => {
                if buf.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                let msg = match serde_json::from_slice::<PluginMsg>(&buf) {
                    Ok(m) => m,
                    Err(_) => break DeathCause::ProtocolViolation("plugin message is not a known JSON message"),
                };
                if let Err(c) = route(&worker, msg).await {
                    break c;
                }
            }
        }
    };
    if cause.is_crash() && !worker.is_dead() {
        log::warn!(target: "plugin", "[{}] multiplexed child stopped: {cause}", worker.plugin);
    }
    worker.die(cause).await;
}

async fn route(worker: &Arc<MuxWorker>, msg: PluginMsg) -> Result<(), DeathCause> {
    match msg {
        PluginMsg::Hello { .. } => return Err(DeathCause::ProtocolViolation("unexpected hello after the handshake")),
        PluginMsg::Pong { .. } => {}
        PluginMsg::LifecycleAck { event } => {
            worker.lifecycle_acks.fetch_add(1, Ordering::SeqCst);
            let ready: Vec<oneshot::Sender<()>> = match worker.lifecycle_waiters.lock() {
                Ok(mut w) => {
                    let (hit, keep): (Vec<_>, Vec<_>) = w.drain(..).partition(|(e, _)| *e == event);
                    *w = keep;
                    hit.into_iter().map(|(_, tx)| tx).collect()
                }
                Err(_) => Vec::new(),
            };
            for tx in ready {
                let _ = tx.send(());
            }
        }
        PluginMsg::HostCall { id, invocation, method, params } => {
            let sender = worker.inflight.lock().ok().and_then(|m| m.get(&invocation).map(|f| f.calls.clone()));
            match sender {
                // Outside an invocation in flight a host call is refused,
                // never answered with someone else's authority.
                None => reply_error(worker, id, invocation, "no_invocation").await,
                Some(tx) => match tx.try_send(HostCallReq { id, method, params }) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        reply_error(worker, id, invocation, "too_many_pending_host_calls").await
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        reply_error(worker, id, invocation, "no_invocation").await
                    }
                },
            }
        }
        PluginMsg::Done { id, status, data_b64 } => {
            if id == 0 || id >= worker.next_id.load(Ordering::SeqCst) {
                return Err(DeathCause::ProtocolViolation("done for an invocation that was never sent"));
            }
            // A done for a cancelled invocation arrives late by design.
            let Some(f) = worker.remove_inflight(id) else { return Ok(()) };
            let event = match base64::engine::general_purpose::STANDARD.decode(data_b64.as_bytes()) {
                Ok(response) => DoneEvent::Done { status, response },
                Err(_) => DoneEvent::Failed("response data is not base64".into()),
            };
            let _ = f.done.send(event);
        }
    }
    Ok(())
}

/// Fail what an oversized line belongs to: a `done` fails its invocation,
/// a `host_call` is refused. A line that cannot be attributed is dropped
/// and logged; its invocation then times out and is cancelled. The child is
/// never killed for size: one large result must not end every session.
async fn route_oversized(worker: &Arc<MuxWorker>, ends: &[u8]) -> Result<(), DeathCause> {
    let ends = String::from_utf8_lossy(ends);
    let (head, tail) = ends.split_once('\n').unwrap_or((&ends, ""));
    match attribute(head, tail) {
        Some((kind, id, _)) if kind == "done" => {
            if let Some(f) = worker.remove_inflight(id) {
                let _ = f.done.send(DoneEvent::Failed(format!("a plugin message exceeded {MAX_LINE_BYTES} bytes")));
            }
        }
        Some((kind, id, invocation)) if kind == "host_call" => reply_error(worker, id, invocation, "too_large").await,
        _ => log::warn!(target: "plugin", "[{}] dropped an unattributable message over {MAX_LINE_BYTES} bytes", worker.plugin),
    }
    Ok(())
}

/// Ping the child while it lives; tear it down when it stops answering.
async fn heartbeat_loop(worker: Weak<MuxWorker>, t: MuxTimings) {
    let mut nonce = 0u64;
    loop {
        tokio::time::sleep(t.heartbeat_interval).await;
        let Some(w) = worker.upgrade() else { return };
        if w.is_dead() {
            return;
        }
        let silent = w.last_seen.lock().map(|s| s.elapsed()).unwrap_or_default();
        if silent > t.heartbeat_timeout {
            log::warn!(target: "plugin", "[{}] multiplexed child missed its heartbeat ({silent:?})", w.plugin);
            w.die(DeathCause::MissedHeartbeat).await;
            return;
        }
        nonce = nonce.wrapping_add(1);
        let _ = w.write(&HostMsg::Ping { nonce }).await;
    }
}

// ── test child ──────────────────────────────────────────────────────────

/// The in-tree long-lived test plugin: the test binary re-run with
/// `BV_PLUGIN_LONG_LIVED=1` (ctor in `src/lib.rs`). Behaviour comes from the
/// plugin name (`serial`, `nopong`, `noack`) and from each invocation input.
#[doc(hidden)]
#[cfg(test)]
pub fn run_test_long_lived_plugin() -> ! {
    use std::io::{BufRead, Write};

    // Runs from a ctor: never panic, always exit explicitly.
    let stdout = Arc::new(StdMutex::new(std::io::stdout()));
    let send = {
        let stdout = stdout.clone();
        move |v: &Value| {
            if let Ok(mut o) = stdout.lock() {
                let _ = writeln!(o, "{v}");
                let _ = o.flush();
            }
        }
    };
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    let init: Value = match lines.next() {
        Some(Ok(l)) => serde_json::from_str(&l).unwrap_or(Value::Null),
        _ => std::process::exit(90),
    };
    let name = init.get("plugin_name").and_then(Value::as_str).unwrap_or("").to_string();
    let token = std::env::var("BV_PLUGIN_BOOTSTRAP_TOKEN").unwrap_or_default();
    send(&serde_json::json!({"type": "hello", "token": token}));
    let b64 = base64::engine::general_purpose::STANDARD;

    if name.contains("serial") {
        for line in lines.map_while(Result::ok) {
            let v: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
            if v["type"] == "invoke" {
                send(&serde_json::json!({"type": "invoke_done", "id": v["id"], "status": 0, "data_b64": v["input"]}));
            }
        }
        std::process::exit(0);
    }

    let replies: Arc<StdMutex<HashMap<u64, std::sync::mpsc::Sender<Value>>>> = Arc::default();
    let cancelled: Arc<StdMutex<std::collections::HashSet<u64>>> = Arc::default();
    let next_call = Arc::new(AtomicU64::new(1));
    for line in lines.map_while(Result::ok) {
        let v: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
        match v["type"].as_str().unwrap_or("") {
            "ping" if !name.contains("nopong") => send(&serde_json::json!({"type": "pong", "nonce": v["nonce"]})),
            "lifecycle" if !name.contains("noack") => {
                send(&serde_json::json!({"type": "lifecycle_ack", "event": v["event"]}))
            }
            "cancel" => {
                if let (Some(id), Ok(mut c)) = (v["id"].as_u64(), cancelled.lock()) {
                    c.insert(id);
                }
            }
            "host_reply" => {
                let tx = v["id"].as_u64().and_then(|id| replies.lock().ok().and_then(|mut r| r.remove(&id)));
                if let Some(tx) = tx {
                    let _ = tx.send(v);
                }
            }
            "invoke" => {
                let id = v["id"].as_u64().unwrap_or(0);
                let input: Value = b64
                    .decode(v["input"].as_str().unwrap_or(""))
                    .ok()
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .unwrap_or(Value::Null);
                let (send, replies, cancelled, next_call) =
                    (send.clone(), replies.clone(), cancelled.clone(), next_call.clone());
                std::thread::spawn(move || {
                    let b64 = base64::engine::general_purpose::STANDARD;
                    if let Some(code) = input["exit"].as_i64() {
                        std::process::exit(code as i32);
                    }
                    if input["violate"] == true {
                        send(&Value::String("not a protocol message".into()));
                        return;
                    }
                    let mut reply = Value::Null;
                    if let Some(call) = input.get("host_call") {
                        let call_id = next_call.fetch_add(1, Ordering::SeqCst);
                        let (tx, rx) = std::sync::mpsc::channel();
                        if let Ok(mut r) = replies.lock() {
                            r.insert(call_id, tx);
                        }
                        let invocation = input["invocation_override"].as_u64().unwrap_or(id);
                        send(&serde_json::json!({"type": "host_call", "id": call_id, "invocation": invocation,
                            "method": call["method"], "params": call["params"]}));
                        reply = rx.recv_timeout(Duration::from_secs(30)).unwrap_or(Value::Null);
                    }
                    let mut was_cancelled = false;
                    let sleep_ms = input["sleep_ms"].as_u64().unwrap_or(0);
                    let start = Instant::now();
                    while start.elapsed() < Duration::from_millis(sleep_ms) {
                        if input["ignore_cancel"] != true && cancelled.lock().map(|c| c.contains(&id)).unwrap_or(false) {
                            was_cancelled = true;
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    let data = if input["oversize"] == true {
                        "A".repeat(MAX_LINE_BYTES + 16)
                    } else {
                        b64.encode(
                            serde_json::json!({"echo": input["echo"], "reply": reply, "cancelled": was_cancelled})
                                .to_string(),
                        )
                    };
                    send(&serde_json::json!({"type": "done", "id": id, "status": 0, "data_b64": data}));
                });
            }
            _ => {}
        }
    }
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn lines_of(input: &[u8], max: usize) -> Vec<(Line, Vec<u8>)> {
        let mut r = BufReader::with_capacity(7, input);
        let mut out = Vec::new();
        let mut buf = Vec::new();
        loop {
            let l = read_bounded_line(&mut r, &mut buf, max).await.unwrap();
            if l == Line::Eof {
                return out;
            }
            out.push((l, buf.clone()));
        }
    }

    /// An oversized line is consumed whole, keeps only its two ends, and
    /// the next line reads normally.
    #[tokio::test]
    async fn bounded_reader_skips_an_oversized_line_and_recovers() {
        let big = "A".repeat(5000);
        let long = format!("{{\"data_b64\":\"{big}\",\"id\":7,\"status\":0,\"type\":\"done\"}}");
        let input = format!("short\n{long}\n{{\"x\":1}}\npartial-without-newline");
        let got = lines_of(input.as_bytes(), 64).await;
        assert_eq!(got.len(), 3);
        assert_eq!(got[0], (Line::Complete, b"short".to_vec()));
        assert_eq!(got[1].0, Line::TooLong);
        assert!(got[1].1.len() <= 2 * HEADER_PREFIX_BYTES + 1);
        let ends = String::from_utf8(got[1].1.clone()).unwrap();
        let (head, tail) = ends.split_once('\n').unwrap();
        assert_eq!(attribute(head, tail), Some(("done".to_string(), 7, 0)));
        assert_eq!(got[2], (Line::Complete, b"{\"x\":1}".to_vec()));
    }

    /// Either key order attributes: fields first, or a large field first.
    #[test]
    fn oversized_lines_are_attributed_from_either_end() {
        let head = r#"{"type": "host_call", "id" : 12, "invocation":3, "method":"x","params":{"id":99"#;
        assert_eq!(attribute(head, ""), Some(("host_call".to_string(), 12, 3)));
        let sorted_tail = r#"AAAA","id":5,"invocation":2,"status":0,"type":"done"}"#;
        assert_eq!(attribute(r#"{"data_b64":"AAAA"#, sorted_tail), Some(("done".to_string(), 5, 2)));
        assert_eq!(attribute(r#"{"data_b64":"AAAA"#, "AAAA\"}"), None);
        assert_eq!(header_u64(head, "missing"), None);
    }

    /// Unknown or malformed plugin messages do not parse: the reader treats
    /// them as protocol violations.
    #[test]
    fn plugin_messages_parse_strictly() {
        for bad in [
            r#"{"type":"set_response","data_b64":""}"#,
            r#"{"type":"done","id":"1","status":0}"#,
            r#"{"type":"host_call","id":1,"method":"log"}"#,
            r#"{"type":"lifecycle_ack","event":"reboot"}"#,
            r#""done""#,
        ] {
            assert!(serde_json::from_str::<PluginMsg>(bad).is_err(), "{bad}");
        }
        assert!(matches!(
            serde_json::from_str::<PluginMsg>(r#"{"type":"done","id":1,"status":0}"#),
            Ok(PluginMsg::Done { id: 1, status: 0, .. })
        ));
    }

    #[test]
    fn host_replies_carry_result_or_error() {
        let v = serde_json::json!({"k": 1});
        let ok =
            serde_json::to_value(HostMsg::HostReply { id: 2, invocation: 9, result: Some(&v), error: None }).unwrap();
        assert_eq!(ok, serde_json::json!({"type": "host_reply", "id": 2, "invocation": 9, "result": {"k": 1}}));
        let err =
            serde_json::to_value(HostMsg::HostReply { id: 2, invocation: 9, result: None, error: Some("forbidden") })
                .unwrap();
        assert_eq!(err, serde_json::json!({"type": "host_reply", "id": 2, "invocation": 9, "error": "forbidden"}));
        let lc = serde_json::to_value(HostMsg::Lifecycle { event: LifecycleEvent::Seal, deadline_ms: 10_000 }).unwrap();
        assert_eq!(lc, serde_json::json!({"type": "lifecycle", "event": "seal", "deadline_ms": 10000}));
    }

    #[test]
    fn only_host_teardown_spares_the_crash_breaker() {
        assert!(DeathCause::Eof.is_crash());
        assert!(DeathCause::MissedHeartbeat.is_crash());
        assert!(DeathCause::ProtocolViolation("x").is_crash());
        assert!(!DeathCause::Teardown.is_crash());
    }
}
