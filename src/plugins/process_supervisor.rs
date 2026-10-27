//! Long-lived supervised process runtime — Phase 5.3.
//!
//! Opt-in via `manifest.capabilities.long_lived = true`. Spawns one
//! persistent child per plugin name, reuses it across invocations,
//! restarts on crash with exponential backoff, and forwards stderr
//! into the host log tagged `[plugin=<name>]`. Single-shot
//! [`super::process_runtime::ProcessRuntime`] continues to handle
//! plugins where `long_lived = false` (the default), so the existing
//! SDK + reference plugins in `plugins-ext/` keep working unchanged.
//!
//! ## Wire protocol (extends the single-shot framing)
//!
//! Single-shot uses one `Init` then `set_response` / `done`. The
//! long-lived path adds two new message types so the same child can
//! handle many invocations:
//!
//! - Host → plugin: `{"type":"invoke","id":<n>,"input":"<base64>"}`
//! - Plugin → host: `{"type":"invoke_done","id":<n>,"status":<i32>,"data_b64":"<base64>"}`
//!
//! Host-call requests (`storage_get`, `crypto_sign`, …) flow over the
//! same socket as in single-shot — they are the plugin asking the
//! host to perform a capability-gated op while servicing an invoke.
//!
//! ## Restart policy
//!
//! - Initial spawn happens lazily on first invoke (so a misconfigured
//!   plugin doesn't crash the parent at unseal time).
//! - On stdout EOF or unexpected `done` after `Init`, the supervisor
//!   tears down the child, waits a backoff interval, and respawns.
//! - Backoff: `min(initial_backoff * 2^(failures-1), max_backoff)`.
//!   Defaults: 1s → 60s. The window is 5 minutes; `MAX_RESTARTS`
//!   crashes inside the window opens the breaker — subsequent
//!   invokes return `RestartBudgetExhausted` until the window slides
//!   forward. The breaker prevents a wedged plugin from burning
//!   inotify watchers / file descriptors.
//!
//! ## Bootstrap token
//!
//! One token per child *lifetime*, supplied via the
//! `BV_PLUGIN_BOOTSTRAP_TOKEN` env var on spawn. The plugin echoes
//! the token in its first message; mismatch tears down the child and
//! refuses the invoke. Restart issues a fresh token.
//!
//! ## Per-plugin singleton
//!
//! `tokio::sync::Mutex` per plugin name guards the in-memory child.
//! Concurrent invokes are serialised through it, unless the plugin opts
//! into the ABI 1.4 multiplexed protocol (`concurrent = true`,
//! [`super::process_mux`]).

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

use super::dynamic::DynamicSession;
use super::invocation::InvocationCaller;
use super::manifest::PluginManifest;
use super::process_mux::{DeathCause, LifecycleEvent, MuxError, MuxWorker, LIFECYCLE_DEADLINE};
use super::process_runtime::{
    generate_bootstrap_token, handle_host_call, scrub, write_temp_executable, ProcessRuntimeError,
};
use super::runtime::{InvokeOutcome, InvokeOutput};
use crate::kernel_api::VaultCtx;

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// Crashes inside this rolling window count toward the breaker.
const RESTART_WINDOW: Duration = Duration::from_secs(5 * 60);
/// Crashes inside `RESTART_WINDOW` after which the supervisor refuses
/// further invokes until the oldest crash ages out of the window.
const MAX_RESTARTS_IN_WINDOW: usize = 10;
/// Per-invoke wall-clock cap. Independent of restart backoff — this
/// is "how long do we wait for the plugin to respond before we
/// declare the child wedged and tear it down?".
pub const DEFAULT_INVOKE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    #[error("supervised plugin spawn failed: {0}")]
    Spawn(String),
    #[error("supervised plugin io: {0}")]
    Io(String),
    #[error("supervised plugin protocol: {0}")]
    Protocol(&'static str),
    #[error("supervised plugin response timed out after {0:?}")]
    Timeout(Duration),
    #[error("supervised plugin restart budget exhausted ({crashes} crashes in {window:?})")]
    RestartBudgetExhausted { crashes: usize, window: Duration },
    #[error("supervised plugin handshake failed (bootstrap token mismatch)")]
    HandshakeFailed,
    #[error("supervised plugin has {0} invocations in flight; none freed up before the deadline")]
    Busy(u32),
    #[error("supervised plugin invocation failed: {0}")]
    InvocationFailed(String),
}

impl From<MuxError> for SupervisorError {
    fn from(e: MuxError) -> Self {
        match e {
            MuxError::Io(s) | MuxError::Died(s) => SupervisorError::Io(s),
            MuxError::Timeout(d) => SupervisorError::Timeout(d),
            MuxError::Busy(n) => SupervisorError::Busy(n),
            MuxError::InvocationFailed(s) => SupervisorError::InvocationFailed(s),
            MuxError::Handshake(s) => SupervisorError::Spawn(format!("handshake: {s}")),
        }
    }
}

impl From<SupervisorError> for ProcessRuntimeError {
    fn from(e: SupervisorError) -> Self {
        match e {
            SupervisorError::Spawn(s) => ProcessRuntimeError::Spawn(s),
            SupervisorError::Io(s) => ProcessRuntimeError::Io(s),
            SupervisorError::Protocol(s) => ProcessRuntimeError::Protocol(s),
            SupervisorError::Timeout(d) => ProcessRuntimeError::Timeout(d),
            SupervisorError::Busy(n) => ProcessRuntimeError::Busy(n),
            SupervisorError::InvocationFailed(s) => ProcessRuntimeError::InvocationFailed(s),
            SupervisorError::RestartBudgetExhausted { .. } | SupervisorError::HandshakeFailed => {
                ProcessRuntimeError::Spawn(format!("{e}"))
            }
        }
    }
}

// ── Wire protocol (long-lived extension) ──────────────────────────

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PluginMessage {
    HostCall {
        id: u64,
        method: String,
        #[serde(default)]
        params: Value,
    },
    InvokeDone {
        id: u64,
        status: i32,
        #[serde(default)]
        data_b64: String,
    },
    /// Sent once after `Init`; carries the token the plugin received
    /// via `BV_PLUGIN_BOOTSTRAP_TOKEN`. Must match what the host
    /// supplied or the supervisor tears the child down.
    Hello { token: String },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HostMessage<'a> {
    Init { plugin_name: &'a str },
    Invoke { id: u64, input: String },
    HostReply { id: u64, result: Value },
    HostReplyError { id: u64, error: String },
}

// ── Per-plugin worker ─────────────────────────────────────────────

struct Worker {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    /// Monotonic invoke counter; the plugin echoes it back in
    /// `invoke_done.id` so we can detect protocol drift.
    next_id: u64,
}

#[derive(Default)]
struct Supervised {
    /// `None` until the first successful spawn.
    worker: Option<Worker>,
    /// The multiplexed child of a `concurrent` plugin (ABI 1.4).
    mux: Option<Arc<MuxWorker>>,
    /// Crash timestamps within the rolling window. Used by the
    /// breaker; entries older than `RESTART_WINDOW` are pruned on
    /// every spawn attempt.
    crashes: Vec<Instant>,
    /// Failed spawn attempts since the last successful spawn —
    /// drives the exponential backoff.
    consecutive_failures: u32,
    /// Last attempt timestamp — used to compute backoff sleep.
    last_attempt_at: Option<Instant>,
}

impl Supervised {
    fn prune_window(&mut self) {
        let cutoff = Instant::now() - RESTART_WINDOW;
        self.crashes.retain(|t| *t >= cutoff);
    }

    fn budget_exhausted(&self) -> Option<SupervisorError> {
        if self.crashes.len() >= MAX_RESTARTS_IN_WINDOW {
            Some(SupervisorError::RestartBudgetExhausted { crashes: self.crashes.len(), window: RESTART_WINDOW })
        } else {
            None
        }
    }

    fn backoff(&self) -> Duration {
        if self.consecutive_failures == 0 {
            return Duration::ZERO;
        }
        let exp = (self.consecutive_failures - 1).min(8);
        let raw = INITIAL_BACKOFF * 2u32.pow(exp);
        std::cmp::min(raw, MAX_BACKOFF)
    }

    fn record_crash(&mut self) {
        self.crashes.push(Instant::now());
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
    }
}

type SupervisedMap = DashMap<String, Arc<Mutex<Supervised>>>;
static SUPERVISED: OnceLock<SupervisedMap> = OnceLock::new();

fn supervised_for(name: &str) -> Arc<Mutex<Supervised>> {
    SUPERVISED
        .get_or_init(DashMap::new)
        .entry(name.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(Supervised::default())))
        .clone()
}

/// Tear down every supervised child. Called on plugin reload
/// (`POST /v1/sys/plugins/<name>/reload` after the drain) and on
/// catalog `delete` to make sure a re-registered plugin doesn't
/// inherit a wedged child from the previous version.
pub async fn shutdown_for(name: &str) {
    let map = SUPERVISED.get_or_init(DashMap::new);
    let entry = map.get(name).map(|e| e.value().clone());
    if let Some(entry) = entry {
        let mut sup = entry.lock().await;
        // A multiplexed child is told first, so it can close its sessions
        // and zeroize what it holds; it goes either way.
        if let Some(mux) = sup.mux.take() {
            mux.lifecycle(LifecycleEvent::Reload, LIFECYCLE_DEADLINE).await;
            mux.die(DeathCause::Teardown).await;
        }
        if let Some(mut worker) = sup.worker.take() {
            let _ = worker.child.start_kill();
            let _ = worker.child.wait().await;
        }
        sup.consecutive_failures = 0;
        // We intentionally keep `crashes` so the breaker still applies
        // — a plugin that's been thrashing should not be reset just
        // because the operator clicked Reload.
    }
}

// ── Public entrypoint ─────────────────────────────────────────────

/// Invoke a long-lived plugin. Spawns the child if needed, sends one
/// `Invoke` message, awaits `InvokeDone`, returns the response bytes.
/// Restarts the child on crash with exponential backoff.
pub async fn invoke_with_config(
    manifest: &PluginManifest,
    binary: &[u8],
    input: &[u8],
    core: Option<Arc<dyn VaultCtx>>,
    config: BTreeMap<String, String>,
) -> Result<InvokeOutput, ProcessRuntimeError> {
    invoke_bound(manifest, binary, input, core, config, None, None, DEFAULT_INVOKE_TIMEOUT).await
}

/// [`invoke_with_config`] on behalf of `caller` (ABI 1.4) and of a
/// dynamic-secret RPC `session` (ABI 1.5), with an explicit deadline. A
/// `concurrent` plugin runs on the multiplexed child; every other
/// long-lived plugin keeps the serialized protocol. A lease whose plugin
/// child is not running (never spawned on this node, shut down by a reload
/// or a delete) spawns it here: revocation never needs it resident.
pub async fn invoke_bound(
    manifest: &PluginManifest,
    binary: &[u8],
    input: &[u8],
    core: Option<Arc<dyn VaultCtx>>,
    config: BTreeMap<String, String>,
    caller: Option<InvocationCaller>,
    session: Option<Arc<DynamicSession>>,
    timeout: Duration,
) -> Result<InvokeOutput, ProcessRuntimeError> {
    if manifest.capabilities.concurrent {
        return invoke_mux(manifest, binary, input, core, config, caller, session, timeout).await;
    }
    let sup_arc = supervised_for(&manifest.name);
    let mut sup = sup_arc.lock().await;

    sup.prune_window();
    if let Some(err) = sup.budget_exhausted() {
        return Err(err.into());
    }

    // Lazy spawn / respawn after a previous crash.
    if sup.worker.is_none() {
        let backoff = sup.backoff();
        if backoff > Duration::ZERO {
            // Respect the spawn cooldown so we don't fork-bomb.
            tokio::time::sleep(backoff).await;
        }
        sup.last_attempt_at = Some(Instant::now());
        match spawn_worker(manifest, binary).await {
            Ok(w) => {
                sup.worker = Some(w);
                sup.record_success();
                log::info!(
                    target: "plugin",
                    "[{}] supervised child spawned", manifest.name
                );
            }
            Err(e) => {
                sup.record_crash();
                return Err(e.into());
            }
        }
    }

    // Drive one invoke. On any I/O / protocol error we tear the child
    // down and surface the error; the next call will respawn under
    // the breaker.
    let result =
        drive_invoke(&mut sup, manifest, &core, &config, input, caller.as_ref(), session.as_ref(), timeout).await;
    match result {
        Ok(out) => Ok(out),
        Err(e) => {
            // Bring the child down so we don't leave a half-broken
            // session in place.
            if let Some(mut w) = sup.worker.take() {
                let _ = w.child.start_kill();
                let _ = w.child.wait().await;
            }
            sup.record_crash();
            log::warn!(
                target: "plugin",
                "[{}] supervised invoke failed: {e}; child torn down (consecutive_failures={})",
                manifest.name, sup.consecutive_failures,
            );
            Err(e.into())
        }
    }
}

async fn drive_invoke(
    sup: &mut Supervised,
    manifest: &PluginManifest,
    core: &Option<Arc<dyn VaultCtx>>,
    config: &BTreeMap<String, String>,
    input: &[u8],
    caller: Option<&InvocationCaller>,
    session: Option<&Arc<DynamicSession>>,
    timeout: Duration,
) -> Result<InvokeOutput, SupervisorError> {
    let worker = sup.worker.as_mut().ok_or(SupervisorError::Protocol("worker missing"))?;
    let id = worker.next_id;
    worker.next_id = worker.next_id.wrapping_add(1);

    let invoke_msg = HostMessage::Invoke { id, input: base64::engine::general_purpose::STANDARD.encode(input) };
    write_msg(&mut worker.stdin, &invoke_msg).await?;

    let outcome = tokio::time::timeout(timeout, async {
        loop {
            // A host call's line can carry a credential (a connection's root secret).
            let mut buf = zeroize::Zeroizing::new(String::new());
            let read = worker.stdout.read_line(&mut buf).await.map_err(|e| SupervisorError::Io(format!("{e}")))?;
            if read == 0 {
                return Err(SupervisorError::Io("stdout closed before invoke_done".into()));
            }
            let trimmed = buf.trim_end();
            if trimmed.is_empty() {
                continue;
            }
            let msg: PluginMessage = serde_json::from_str(trimmed)
                .map_err(|_| SupervisorError::Protocol("plugin message not valid JSON"))?;
            match msg {
                PluginMessage::Hello { .. } => {
                    // Hello is the spawn-time handshake; receiving it
                    // mid-invoke means the plugin lost track of the
                    // protocol — force a teardown.
                    return Err(SupervisorError::Protocol("unexpected hello mid-invoke"));
                }
                PluginMessage::HostCall { id: hid, method, mut params } => {
                    let result =
                        handle_host_call(manifest, core.as_ref(), config, &method, &params, caller, session).await;
                    scrub(&mut params);
                    let mut reply = match result {
                        Ok(v) => HostMessage::HostReply { id: hid, result: v },
                        Err(e) => HostMessage::HostReplyError { id: hid, error: e },
                    };
                    let written = write_msg(&mut worker.stdin, &reply).await;
                    if let HostMessage::HostReply { result, .. } = &mut reply {
                        scrub(result);
                    }
                    written?;
                }
                PluginMessage::InvokeDone { id: did, status, data_b64 } => {
                    if did != id {
                        return Err(SupervisorError::Protocol("invoke_done id mismatch"));
                    }
                    let response = if data_b64.is_empty() {
                        Vec::new()
                    } else {
                        base64::engine::general_purpose::STANDARD
                            .decode(data_b64.as_bytes())
                            .map_err(|_| SupervisorError::Protocol("invoke_done data not base64"))?
                    };
                    let outcome = if status == 0 { InvokeOutcome::Success } else { InvokeOutcome::PluginError(status) };
                    return Ok(InvokeOutput { outcome, response, fuel_consumed: 0 });
                }
            }
        }
    })
    .await;

    match outcome {
        Ok(Ok(out)) => Ok(out),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(SupervisorError::Timeout(timeout)),
    }
}

// ── Multiplexed path (ABI 1.4) ───────────────────────────────────

/// Run one invocation on a `concurrent` plugin's multiplexed child. The
/// per-plugin lock is held only to find or (re)spawn the child, under the
/// same breaker and backoff as the serialized path.
async fn invoke_mux(
    manifest: &PluginManifest,
    binary: &[u8],
    input: &[u8],
    core: Option<Arc<dyn VaultCtx>>,
    config: BTreeMap<String, String>,
    caller: Option<InvocationCaller>,
    session: Option<Arc<DynamicSession>>,
    timeout: Duration,
) -> Result<InvokeOutput, ProcessRuntimeError> {
    let sup_arc = supervised_for(&manifest.name);
    let worker = {
        let mut sup = sup_arc.lock().await;
        sup.prune_window();
        if let Some(err) = sup.budget_exhausted() {
            return Err(err.into());
        }
        match &sup.mux {
            Some(w) if !w.is_dead() => w.clone(),
            _ => {
                sup.mux = None;
                let backoff = sup.backoff();
                if backoff > Duration::ZERO {
                    tokio::time::sleep(backoff).await;
                }
                sup.last_attempt_at = Some(Instant::now());
                let spawned = match spawn_child(manifest, binary) {
                    Ok((child, stdin, stdout, bootstrap)) => {
                        MuxWorker::start(manifest, child, stdin, stdout, &bootstrap).await.map_err(SupervisorError::from)
                    }
                    Err(e) => Err(e),
                };
                let w = match spawned {
                    Ok(w) => w,
                    Err(e) => {
                        sup.record_crash();
                        return Err(e.into());
                    }
                };
                sup.record_success();
                log::info!(target: "plugin", "[{}] multiplexed child spawned", manifest.name);
                watch_mux(Arc::downgrade(&sup_arc), w.clone());
                sup.mux = Some(w.clone());
                w
            }
        }
    };
    worker
        .invoke(manifest, core, &config, caller.as_ref(), session.as_ref(), input, timeout)
        .await
        .map_err(|e| SupervisorError::from(e).into())
}

/// When a multiplexed child stops, unhook it and, unless the host tore it
/// down itself, count the crash. The breaker is the serialized path's.
fn watch_mux(sup: std::sync::Weak<Mutex<Supervised>>, w: Arc<MuxWorker>) {
    tokio::spawn(async move {
        let cause = w.wait_dead().await;
        let Some(sup) = sup.upgrade() else { return };
        let mut sup = sup.lock().await;
        if sup.mux.as_ref().is_some_and(|m| Arc::ptr_eq(m, &w)) {
            sup.mux = None;
        }
        if cause.is_crash() {
            sup.record_crash();
            log::warn!(
                target: "plugin",
                "[{}] multiplexed child stopped ({cause}); consecutive_failures={}",
                w.plugin(), sup.consecutive_failures,
            );
        }
    });
}

/// Send `event` to every multiplexed child and wait up to `deadline` for
/// each acknowledgement. A child that does not acknowledge is killed; one
/// that does is kept for `Seal` and torn down for `Reload` / `Shutdown`.
/// Returns `(plugin, acknowledged)` per child.
pub async fn lifecycle_all(event: LifecycleEvent, deadline: Duration) -> Vec<(String, bool)> {
    let map = SUPERVISED.get_or_init(DashMap::new);
    let entries: Vec<(String, Arc<Mutex<Supervised>>)> =
        map.iter().map(|e| (e.key().clone(), e.value().clone())).collect();
    let mut tasks = Vec::new();
    for (name, sup) in entries {
        let Some(w) = sup.lock().await.mux.clone() else { continue };
        tasks.push(tokio::spawn(async move {
            let acked = w.lifecycle(event, deadline).await;
            if !acked || event != LifecycleEvent::Seal {
                if !acked {
                    log::warn!(target: "plugin", "[{name}] did not acknowledge {event:?} within {deadline:?}; killed");
                }
                w.die(DeathCause::Teardown).await;
            }
            (name, acked)
        }));
    }
    let mut out = Vec::new();
    for t in tasks {
        if let Ok(r) = t.await {
            out.push(r);
        }
    }
    out
}

/// The multiplexed child of `name`, for tests and diagnostics.
#[doc(hidden)]
pub async fn mux_worker(name: &str) -> Option<Arc<MuxWorker>> {
    let sup = SUPERVISED.get_or_init(DashMap::new).get(name).map(|e| e.value().clone())?;
    let w = sup.lock().await.mux.clone();
    w
}

/// Crashes inside the breaker window for `name`, for tests and diagnostics.
#[doc(hidden)]
pub async fn crash_count(name: &str) -> usize {
    let Some(sup) = SUPERVISED.get_or_init(DashMap::new).get(name).map(|e| e.value().clone()) else { return 0 };
    let mut s = sup.lock().await;
    s.prune_window();
    s.crashes.len()
}

// ── Spawn helpers ─────────────────────────────────────────────────

async fn spawn_worker(manifest: &PluginManifest, binary: &[u8]) -> Result<Worker, SupervisorError> {
    let (child, stdin, stdout, bootstrap) = spawn_child(manifest, binary)?;
    let mut worker = Worker { child, stdin, stdout: BufReader::new(stdout), next_id: 1 };

    // Send Init + receive Hello handshake. The handshake is bounded
    // by a 60s timeout — a plugin that fails to send Hello in that
    // window is killed and the spawn is retried.
    handshake(&mut worker, manifest, &bootstrap).await?;

    Ok(worker)
}

/// Spawn the plugin child with a cleared environment and forward its
/// stderr to the host log. Returns the child, its stdio and the bootstrap
/// token it was given.
fn spawn_child(
    manifest: &PluginManifest,
    binary: &[u8],
) -> Result<(Child, ChildStdin, ChildStdout, String), SupervisorError> {
    let exe_path =
        write_temp_executable(&manifest.name, binary).map_err(|e| SupervisorError::Spawn(format!("temp file: {e}")))?;
    // Note: the temp file persists across the worker's lifetime (the
    // process is exec'd from it; on Unix the inode stays valid until
    // the process exits even if the file is unlinked, but we don't
    // unlink eagerly because that breaks Windows). It's swept on
    // teardown via `shutdown_for`.

    let bootstrap = generate_bootstrap_token();

    let mut cmd = Command::new(&exe_path);
    cmd.env("BV_PLUGIN_BOOTSTRAP_TOKEN", &bootstrap);
    cmd.env("BV_PLUGIN_NAME", &manifest.name);
    cmd.env("BV_PLUGIN_LONG_LIVED", "1");
    cmd.env("BV_PLUGIN_MODE", "1");
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.env_clear();
    cmd.env("BV_PLUGIN_BOOTSTRAP_TOKEN", &bootstrap);
    cmd.env("BV_PLUGIN_NAME", &manifest.name);
    cmd.env("BV_PLUGIN_LONG_LIVED", "1");
    cmd.env("BV_PLUGIN_MODE", "1");
    if let Ok(p) = std::env::var("PATH") {
        cmd.env("PATH", p);
    }
    #[cfg(target_os = "windows")]
    for var in &[
        "SystemRoot",
        "SystemDrive",
        "windir",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
        "ProgramData",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "COMSPEC",
        "PATHEXT",
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
    ] {
        if let Ok(v) = std::env::var(var) {
            cmd.env(var, v);
        }
    }

    let mut child = cmd.spawn().map_err(|e| SupervisorError::Spawn(format!("{e}")))?;

    let stdin = child.stdin.take().ok_or(SupervisorError::Protocol("stdin"))?;
    let stdout = child.stdout.take().ok_or(SupervisorError::Protocol("stdout"))?;
    let stderr = child.stderr.take().ok_or(SupervisorError::Protocol("stderr"))?;

    // Stderr forwarding task. Lifetime tied to the child via the
    // pipe — when the child dies the pipe closes and the task ends.
    let plugin_name_for_stderr = manifest.name.clone();
    tokio::spawn(async move {
        let mut reader = BufReader::new(stderr);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    log::info!(
                        target: "plugin",
                        "[{plugin_name_for_stderr}] {}",
                        line.trim_end()
                    );
                }
                Err(_) => break,
            }
        }
    });

    Ok((child, stdin, stdout, bootstrap))
}

async fn handshake(worker: &mut Worker, manifest: &PluginManifest, bootstrap: &str) -> Result<(), SupervisorError> {
    let init = HostMessage::Init { plugin_name: &manifest.name };
    write_msg(&mut worker.stdin, &init).await?;

    let timeout = Duration::from_secs(60);
    let hello = tokio::time::timeout(timeout, async {
        let mut buf = String::new();
        loop {
            buf.clear();
            let read = worker.stdout.read_line(&mut buf).await.map_err(|e| SupervisorError::Io(format!("{e}")))?;
            if read == 0 {
                return Err(SupervisorError::Io("stdout closed before hello".into()));
            }
            let trimmed = buf.trim_end();
            if trimmed.is_empty() {
                continue;
            }
            let msg: PluginMessage =
                serde_json::from_str(trimmed).map_err(|_| SupervisorError::Protocol("hello not valid JSON"))?;
            return Ok(msg);
        }
    })
    .await
    .map_err(|_| SupervisorError::Timeout(timeout))??;

    match hello {
        PluginMessage::Hello { token } if token == bootstrap => Ok(()),
        PluginMessage::Hello { .. } => Err(SupervisorError::HandshakeFailed),
        _ => Err(SupervisorError::Protocol("expected hello as first message")),
    }
}

async fn write_msg<W>(writer: &mut W, msg: &HostMessage<'_>) -> Result<(), SupervisorError>
where
    W: AsyncWriteExt + Unpin,
{
    let mut line = serde_json::to_vec(msg).map_err(|_| SupervisorError::Protocol("host message serialise"))?;
    line.push(b'\n');
    writer.write_all(&line).await.map_err(|e| SupervisorError::Io(format!("{e}")))?;
    writer.flush().await.map_err(|e| SupervisorError::Io(format!("{e}")))?;
    Ok(())
}

// Suppress unused-warning when no test in this file consumes `json!`.
#[allow(dead_code)]
fn _unused_json() -> Value {
    json!(null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Backoff schedule sanity. Confirms exponential growth + the
    /// `MAX_BACKOFF` cap so a flapping plugin doesn't get respawned
    /// faster than we promise.
    #[test]
    fn backoff_grows_then_caps() {
        let mut s = Supervised::default();
        assert_eq!(s.backoff(), Duration::ZERO);
        s.consecutive_failures = 1;
        assert_eq!(s.backoff(), INITIAL_BACKOFF);
        s.consecutive_failures = 2;
        assert_eq!(s.backoff(), INITIAL_BACKOFF * 2);
        s.consecutive_failures = 3;
        assert_eq!(s.backoff(), INITIAL_BACKOFF * 4);
        s.consecutive_failures = 10;
        assert_eq!(s.backoff(), MAX_BACKOFF, "should cap at MAX_BACKOFF");
        s.consecutive_failures = 100;
        assert_eq!(s.backoff(), MAX_BACKOFF, "cap holds at the ceiling");
    }

    #[test]
    fn budget_breaker_trips_at_max_restarts_in_window() {
        let mut s = Supervised::default();
        for _ in 0..MAX_RESTARTS_IN_WINDOW {
            s.record_crash();
        }
        s.prune_window();
        assert!(matches!(s.budget_exhausted(), Some(SupervisorError::RestartBudgetExhausted { .. })));
    }

    // ── ABI 1.4 multiplexed children, driven against the test binary ──

    use crate::plugins::manifest::{Capabilities, PluginManifest, RuntimeKind};
    use crate::plugins::process_mux::{set_timings_for_tests, MuxTimings};
    use serde_json::json;

    fn mux_manifest(name: &str, max_concurrent: Option<u32>) -> PluginManifest {
        PluginManifest {
            name: name.to_string(),
            version: "0.1.0".to_string(),
            plugin_type: "test".to_string(),
            engine_type: None,
            runtime: RuntimeKind::Process,
            abi_version: "1.4".to_string(),
            sha256: "0".repeat(64),
            size: 0,
            capabilities: Capabilities {
                long_lived: true,
                concurrent: true,
                max_concurrent,
                caller_identity: true,
                sql_gate: true,
                ..Default::default()
            },
            description: String::new(),
            config_schema: vec![],
            signature: String::new(),
            signing_key: String::new(),
            surface: None,
            client_assets: vec![],
        }
    }

    fn test_binary() -> Vec<u8> {
        std::fs::read(std::env::current_exe().unwrap()).unwrap()
    }

    async fn call(
        m: &PluginManifest,
        bin: &[u8],
        input: serde_json::Value,
        caller: Option<InvocationCaller>,
        timeout: Duration,
    ) -> Result<serde_json::Value, ProcessRuntimeError> {
        let out =
            invoke_bound(m, bin, input.to_string().as_bytes(), None, BTreeMap::new(), caller, None, timeout).await?;
        assert!(matches!(out.outcome, InvokeOutcome::Success));
        Ok(serde_json::from_slice(&out.response).unwrap())
    }

    fn a_caller() -> InvocationCaller {
        let mut req = crate::logical::Request::new("dbms/v2/sessions");
        req.auth = Some(crate::logical::Auth::default());
        InvocationCaller::from_request(&req).unwrap()
    }

    const LONG: Duration = Duration::from_secs(20);

    /// Invocations run at once on one child, and each reply reaches its own
    /// caller.
    #[tokio::test]
    #[serial_test::serial]
    async fn multiplexed_invocations_run_concurrently() {
        let m = mux_manifest("test-mux-concurrent", None);
        let bin = test_binary();
        call(&m, &bin, json!({"echo": "warm"}), None, LONG).await.unwrap();
        let started = Instant::now();
        let mut tasks = Vec::new();
        for i in 0..8 {
            let (m, bin) = (m.clone(), bin.clone());
            tasks.push(tokio::spawn(async move {
                call(&m, &bin, json!({"echo": format!("n{i}"), "sleep_ms": 600}), None, LONG).await.unwrap()
            }));
        }
        for (i, t) in tasks.into_iter().enumerate() {
            assert_eq!(t.await.unwrap()["echo"], format!("n{i}"));
        }
        // Fully serial would take 8 * 600 ms; the bound sits below that with
        // headroom for a loaded CI runner (3.1 s observed against a 2.4 s limit).
        assert!(started.elapsed() < Duration::from_millis(8 * 600 * 3 / 4), "serialized: {:?}", started.elapsed());
        assert_eq!(crash_count(&m.name).await, 0);
        shutdown_for(&m.name).await;
    }

    /// A timeout cancels the invocation in the child and keeps the child:
    /// the next invocation runs on the same process and no crash counts.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_timeout_cancels_without_killing_the_child() {
        let m = mux_manifest("test-mux-cancel", None);
        let bin = test_binary();
        call(&m, &bin, json!({}), None, LONG).await.unwrap();
        let pid = mux_worker(&m.name).await.unwrap().pid();
        let err = call(&m, &bin, json!({"sleep_ms": 10_000}), None, Duration::from_millis(400)).await.unwrap_err();
        assert!(matches!(err, ProcessRuntimeError::Timeout(_)), "{err:?}");
        assert_eq!(call(&m, &bin, json!({"echo": "after"}), None, LONG).await.unwrap()["echo"], "after");
        assert_eq!(mux_worker(&m.name).await.unwrap().pid(), pid, "the child was replaced");
        assert_eq!(crash_count(&m.name).await, 0);
        shutdown_for(&m.name).await;
    }

    /// `max_concurrent` bounds what is in flight; a caller that cannot get a
    /// slot before its deadline is told so, and nothing is killed.
    #[tokio::test]
    #[serial_test::serial]
    async fn max_concurrent_bounds_the_invocations_in_flight() {
        let m = mux_manifest("test-mux-bounded", Some(1));
        let bin = test_binary();
        call(&m, &bin, json!({}), None, LONG).await.unwrap();
        let (m2, bin2) = (m.clone(), bin.clone());
        let slow = tokio::spawn(async move { call(&m2, &bin2, json!({"sleep_ms": 1500}), None, LONG).await });
        tokio::time::sleep(Duration::from_millis(200)).await;
        let err = call(&m, &bin, json!({}), None, Duration::from_millis(300)).await.unwrap_err();
        assert!(matches!(err, ProcessRuntimeError::Busy(1)), "{err:?}");
        slow.await.unwrap().unwrap();
        assert_eq!(crash_count(&m.name).await, 0);
        shutdown_for(&m.name).await;
    }

    /// Host calls are bound to the invocation in flight: one naming another
    /// invocation is refused, and the caller decides what the host sees.
    #[tokio::test]
    #[serial_test::serial]
    async fn host_calls_are_bound_to_their_invocation() {
        let m = mux_manifest("test-mux-binding", None);
        let bin = test_binary();
        let target = json!({"method": "resource_sql_target", "params": {"resource": "db"}});
        let stray = call(&m, &bin, json!({"host_call": target, "invocation_override": 999_999}), Some(a_caller()), LONG)
            .await
            .unwrap();
        assert_eq!(stray["reply"]["error"], "no_invocation");
        let uncalled = call(&m, &bin, json!({"host_call": target}), None, LONG).await.unwrap();
        assert_eq!(uncalled["reply"]["error"], "no_invocation");
        // With a caller the call gets past the invocation check (and stops at
        // the missing core, since this test runs without a vault).
        let bound = call(&m, &bin, json!({"host_call": target}), Some(a_caller()), LONG).await.unwrap();
        assert_eq!(bound["reply"]["error"], "no core");
        shutdown_for(&m.name).await;
    }

    /// ABI 1.5 on the multiplexed child: a `dynamic_*` host call acts on the
    /// session of the invocation it belongs to, and is `no_session` (not a
    /// violation) in an invocation without one.
    #[tokio::test]
    #[serial_test::serial]
    async fn dynamic_host_calls_reach_their_session_on_the_multiplexed_child() {
        use crate::plugins::dynamic::{DynamicSession, DynamicVerb};
        let mut m = mux_manifest("test-mux-dynamic", None);
        m.capabilities.dynamic_lease_register = true;
        let bin = test_binary();
        let lease = json!({"method": "dynamic_lease_register", "params": {"internal": {}, "ttl_secs": 60}});

        let without = call(&m, &bin, json!({"host_call": lease}), None, LONG).await.unwrap();
        assert_eq!(without["reply"]["error"], "no_session");

        let session = Arc::new(DynamicSession::new(DynamicVerb::Generate, "0a1b", None));
        let input = json!({"host_call": lease}).to_string();
        let out = invoke_bound(&m, &bin, input.as_bytes(), None, BTreeMap::new(), None, Some(session.clone()), LONG)
            .await
            .unwrap();
        let with: serde_json::Value = serde_json::from_slice(&out.response).unwrap();
        assert_eq!(with["reply"]["result"]["registered"], true, "{with}");
        assert!(session.take_lease_request().is_some());
        assert!(!session.violated());
        shutdown_for(&m.name).await;
    }

    /// T62 host connectors on the multiplexed child: a checkout in one
    /// invocation and `execute` on that slot in the next, on one session; the
    /// host runs the session's rendered statements through its connector.
    #[tokio::test]
    #[serial_test::serial]
    async fn host_execution_reaches_its_session_on_the_multiplexed_child() {
        use bv_dynamic::{connector::ExecPlan, records::ConnectionRecord};
        use zeroize::Zeroizing;

        use crate::plugins::dynamic::{test_support, DynamicSession, DynamicVerb};
        let target = test_support::fake_target("fake://mux-child");
        let mut m = mux_manifest("test-mux-host-exec", None);
        m.capabilities.dynamic_pool_checkout = true;
        let bin = test_binary();
        let storage = Arc::new(test_support::MemStorage::default());
        let record = ConnectionRecord {
            connection_url: Some("fake://mux-child".into()),
            username: Some("root".into()),
            ..Default::default()
        };
        let record = serde_json::to_vec(&record).unwrap();
        let entry = crate::storage::StorageEntry { key: "bv-dynamic/connections/prod".into(), value: record };
        crate::storage::Storage::put(storage.as_ref(), &entry).await.unwrap();
        let plan = ExecPlan::Create { statements: vec![Zeroizing::new("CREATE \"v-mux\"".to_string())] };
        let mut s = DynamicSession::new(DynamicVerb::Generate, "0a1c", Some(storage)).with_plan(plan);
        s.connection = Some("prod".into());
        let session = Arc::new(s);

        let run = |host_call: serde_json::Value| {
            let (m, bin, session) = (&m, &bin, session.clone());
            async move {
                let input = json!({ "host_call": host_call }).to_string();
                let out = invoke_bound(m, bin, input.as_bytes(), None, BTreeMap::new(), None, Some(session), LONG)
                    .await
                    .unwrap();
                serde_json::from_slice::<serde_json::Value>(&out.response).unwrap()
            }
        };
        let checkout = json!({"method": "dynamic_pool_checkout", "params": {"connection": "prod"}});
        let grant = run(checkout).await;
        let slot = grant["reply"]["result"]["slot"].clone();
        assert!(grant["reply"]["result"]["host_execute"].as_array().unwrap().contains(&json!("fake")), "{grant}");
        let connector =
            json!({"kind": "fake", "url": "fake://mux-child", "username": "root", "password": "mux-root-secret"});
        let execute = json!({"method": "dynamic_pool_checkout",
            "params": {"connection": "prod", "execute": {"slot": slot, "connector": connector}}});
        let done = run(execute).await;
        assert_eq!(done["reply"]["result"]["executed"], 1, "{done}");
        assert_eq!(*target.committed.lock().unwrap(), vec![vec!["CREATE \"v-mux\"".to_string()]]);
        assert!(!session.violated());
        shutdown_for(&m.name).await;
    }

    /// A response over the line cap fails that invocation; the child lives.
    #[tokio::test]
    #[serial_test::serial]
    async fn an_oversized_response_fails_the_invocation_not_the_child() {
        let m = mux_manifest("test-mux-oversize", None);
        let bin = test_binary();
        call(&m, &bin, json!({}), None, LONG).await.unwrap();
        let pid = mux_worker(&m.name).await.unwrap().pid();
        let err = call(&m, &bin, json!({"oversize": true}), None, LONG).await.unwrap_err();
        assert!(matches!(&err, ProcessRuntimeError::InvocationFailed(m) if m.contains("exceeded")), "{err:?}");
        assert_eq!(call(&m, &bin, json!({"echo": "ok"}), None, LONG).await.unwrap()["echo"], "ok");
        assert_eq!(mux_worker(&m.name).await.unwrap().pid(), pid);
        assert_eq!(crash_count(&m.name).await, 0);
        shutdown_for(&m.name).await;
    }

    /// A protocol violation tears the child down and counts one crash; the
    /// next invocation respawns it under the unchanged breaker.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_protocol_violation_kills_the_child_and_counts_a_crash() {
        let m = mux_manifest("test-mux-violation", None);
        let bin = test_binary();
        call(&m, &bin, json!({}), None, LONG).await.unwrap();
        let pid = mux_worker(&m.name).await.unwrap().pid();
        let err = call(&m, &bin, json!({"violate": true, "sleep_ms": 0}), None, LONG).await.unwrap_err();
        assert!(matches!(err, ProcessRuntimeError::Io(_)), "{err:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(crash_count(&m.name).await, 1);
        assert_eq!(call(&m, &bin, json!({"echo": "again"}), None, LONG).await.unwrap()["echo"], "again");
        assert_ne!(mux_worker(&m.name).await.unwrap().pid(), pid);
        shutdown_for(&m.name).await;
    }

    /// A child that stops answering pings is torn down and counted.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_missed_heartbeat_kills_the_child() {
        set_timings_for_tests(MuxTimings {
            heartbeat_interval: Duration::from_millis(100),
            // The warm-up call below must finish inside this window or the
            // child is already declared dead mid-call; 400 ms was too tight
            // for a cold spawn on a loaded CI runner.
            heartbeat_timeout: Duration::from_millis(1500),
        });
        let m = mux_manifest("test-mux-nopong", None);
        let bin = test_binary();
        call(&m, &bin, json!({}), None, LONG).await.unwrap();
        let w = mux_worker(&m.name).await.unwrap();
        let cause = tokio::time::timeout(Duration::from_secs(15), w.wait_dead()).await.unwrap();
        set_timings_for_tests(MuxTimings::default());
        assert_eq!(cause, DeathCause::MissedHeartbeat);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(crash_count(&m.name).await, 1);
        assert!(mux_worker(&m.name).await.is_none());
    }

    /// Seal reaches every multiplexed child through the module hook; a
    /// child that acknowledges is kept, one that does not is killed within
    /// the deadline, and neither counts as a crash.
    #[tokio::test]
    #[serial_test::serial]
    async fn seal_tears_sessions_down_within_the_deadline() {
        use crate::modules::Module;
        // The vault first: setting it up seals once, which would reach the
        // children too.
        let (_bv, core, _root) = crate::test_utils::new_unseal_test_bastion_vault("plugin-seal-lifecycle").await;
        // Let the setup's own seal notification run (and find nothing).
        tokio::time::sleep(Duration::from_millis(200)).await;
        let acks = mux_manifest("test-mux-seal", None);
        let silent = mux_manifest("test-mux-noack", None);
        let bin = test_binary();
        call(&acks, &bin, json!({}), None, LONG).await.unwrap();
        call(&silent, &bin, json!({}), None, LONG).await.unwrap();
        let (good, bad) = (mux_worker(&acks.name).await.unwrap(), mux_worker(&silent.name).await.unwrap());

        let deadline = Duration::from_millis(500);
        let started = Instant::now();
        crate::plugins::lifecycle::PluginLifecycleModule::with_deadline(deadline).cleanup(core.as_ref()).unwrap();
        tokio::time::timeout(deadline + Duration::from_secs(2), bad.wait_dead()).await.expect("killed in time");
        assert!(started.elapsed() < deadline + Duration::from_secs(2));
        assert_eq!(good.lifecycle_acks(), 1);
        assert!(!good.is_dead(), "an acknowledging child is kept");
        assert_eq!(crash_count(&silent.name).await, 0);
        shutdown_for(&acks.name).await;
    }

    /// End to end on a vault: a host call made by the child is decided for
    /// the invocation's caller, and its audit event names that caller, not
    /// whatever the payload claims.
    #[tokio::test]
    #[serial_test::serial]
    async fn host_calls_reach_the_vault_as_the_invocation_caller() {
        let (_bv, core, root) = crate::test_utils::new_unseal_test_bastion_vault("plugin-mux-e2e").await;
        let write = |path: &'static str, body: serde_json::Value| {
            let (core, root) = (core.clone(), root.clone());
            async move {
                crate::test_utils::test_write_api(core.as_ref(), &root, path, true, body.as_object().cloned())
                    .await
                    .unwrap();
            }
        };
        write(
            "sys/policy/sql-reader",
            json!({"policy": "path \"resources/resources/db/sql/*\" {\n  capabilities = [\"sql_select\"]\n}\n"}),
        )
        .await;
        let log = std::env::temp_dir().join(format!("bv-mux-e2e-{}.log", std::process::id()));
        write("sys/audit/primary", json!({"type": "file", "options": {"file_path": log.display().to_string()}})).await;

        let mut m = mux_manifest("test-mux-e2e", None);
        m.capabilities.audit_emit = true;
        let vault: Arc<dyn VaultCtx> = core.clone();
        crate::plugins::sql_grants::put(
            vault.barrier().as_storage(),
            crate::plugins::sql_grants::SqlGrantKind::SqlGate,
            &m,
            "admin",
            "t".into(),
        )
        .await
        .unwrap();
        let mut req = crate::logical::Request::new("dbms/v2/sessions");
        let mut auth = crate::logical::Auth { policies: vec!["sql-reader".into()], ..Default::default() };
        auth.metadata.insert("entity_id".into(), "ent-ana".into());
        req.auth = Some(auth);
        req.client_token = "caller-token".into();
        let ana = InvocationCaller::from_request(&req).unwrap();

        let bin = test_binary();
        let run = |input: serde_json::Value| {
            let (m, bin, vault, ana) = (m.clone(), bin.clone(), vault.clone(), ana.clone());
            async move {
                let out = invoke_bound(
                    &m,
                    &bin,
                    input.to_string().as_bytes(),
                    Some(vault),
                    BTreeMap::new(),
                    Some(ana),
                    None,
                    LONG,
                )
                .await
                .unwrap();
                serde_json::from_slice::<serde_json::Value>(&out.response).unwrap()
            }
        };
        let authorize = json!({"method": "resource_sql_authorize", "params": {"resource": "db", "checks": [
            {"capability": "sql_select", "target": "server"}, {"capability": "sql_drop", "target": "server"}]}});
        let v = run(json!({"host_call": authorize})).await;
        assert_eq!(v["reply"]["result"]["verdicts"][0]["allowed"], true, "{v}");
        assert_eq!(v["reply"]["result"]["verdicts"][1]["allowed"], false, "{v}");

        let forged = json!({"method": "audit_emit", "params": {"payload": {"entity_id": "attacker", "event": "x"}}});
        let v = run(json!({"host_call": forged})).await;
        assert!(v["reply"].get("error").is_none(), "{v}");
        let text = tokio::fs::read_to_string(&log).await.unwrap();
        let event = text
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .find(|e| e["request"]["path"] == "sys/plugins/test-mux-e2e/event")
            .expect("the plugin event was audited");
        assert_eq!(event["auth"]["metadata"]["entity_id"], "ent-ana");
        assert!(event["auth"]["client_token"].as_str().unwrap().starts_with("hmac:"));
        assert!(!text.contains("attacker") && !text.contains("caller-token"));
        let _ = std::fs::remove_file(&log);
        shutdown_for(&m.name).await;
    }

    /// D5 on the real runtime (features/sql-browser.md Phase 0): 50 sessions
    /// × 20 invocations, 20–200 ms each, against one session alone. Prints
    /// the numbers; run with `--run-ignored only`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "measurement, not a regression gate"]
    async fn d5_fifty_session_latency_on_the_real_runtime() {
        let m = mux_manifest("test-mux-d5", None);
        let bin = test_binary();
        call(&m, &bin, json!({}), None, LONG).await.unwrap();
        async fn session(m: PluginManifest, bin: Vec<u8>, seed: u64) -> Vec<Duration> {
            let mut out = Vec::new();
            let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            for _ in 0..20 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let sleep_ms = 20 + x % 181;
                let t = Instant::now();
                call(&m, &bin, json!({"sleep_ms": sleep_ms}), None, LONG).await.unwrap();
                out.push(t.elapsed());
            }
            out
        }
        let pct = |mut v: Vec<Duration>, p: f64| {
            v.sort();
            v[((v.len() as f64 - 1.0) * p).round() as usize]
        };
        let single = session(m.clone(), bin.clone(), 1).await;
        let started = Instant::now();
        let tasks: Vec<_> = (0..50).map(|i| tokio::spawn(session(m.clone(), bin.clone(), i + 1))).collect();
        let mut all = Vec::new();
        for t in tasks {
            all.extend(t.await.unwrap());
        }
        let wall = started.elapsed();
        println!(
            "D5 real runtime: single p50={:?} p99={:?}; 50 sessions p50={:?} p99={:?} max={:?} wall={wall:?} (max_concurrent=32)",
            pct(single.clone(), 0.5),
            pct(single.clone(), 0.99),
            pct(all.clone(), 0.5),
            pct(all.clone(), 0.99),
            pct(all, 1.0),
        );
        shutdown_for(&m.name).await;
    }

    /// 1.0–1.3 long-lived plugins keep the serialized protocol unchanged.
    #[tokio::test]
    #[serial_test::serial]
    async fn serialized_long_lived_plugins_are_unchanged() {
        let mut m = mux_manifest("test-serial-echo", None);
        m.abi_version = "1.3".into();
        m.capabilities.concurrent = false;
        m.capabilities.sql_gate = false;
        let bin = test_binary();
        let out = invoke_with_config(&m, &bin, b"plain-bytes", None, BTreeMap::new()).await.unwrap();
        assert_eq!(out.response, b"plain-bytes");
        assert!(mux_worker(&m.name).await.is_none());
        shutdown_for(&m.name).await;
    }

    #[test]
    fn record_success_clears_consecutive_failures() {
        let mut s = Supervised::default();
        s.record_crash();
        s.record_crash();
        assert_eq!(s.consecutive_failures, 2);
        s.record_success();
        assert_eq!(s.consecutive_failures, 0);
        // But the crash window is preserved — the breaker uses the
        // crash count regardless of intervening successes so a
        // flapping plugin doesn't escape detection.
        assert_eq!(s.crashes.len(), 2);
    }
}
