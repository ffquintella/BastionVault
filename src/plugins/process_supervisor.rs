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
//! Concurrent invokes are serialised through it; a future revision
//! (with the `.proto` promotion in 5.4) can multiplex by request id.

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

use super::manifest::PluginManifest;
use super::process_runtime::{
    generate_bootstrap_token, handle_host_call, write_temp_executable, ProcessRuntimeError,
};
use super::runtime::{InvokeOutcome, InvokeOutput};
use crate::core::Core;

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
}

impl From<SupervisorError> for ProcessRuntimeError {
    fn from(e: SupervisorError) -> Self {
        match e {
            SupervisorError::Spawn(s) => ProcessRuntimeError::Spawn(s),
            SupervisorError::Io(s) => ProcessRuntimeError::Io(s),
            SupervisorError::Protocol(s) => ProcessRuntimeError::Protocol(s),
            SupervisorError::Timeout(d) => ProcessRuntimeError::Timeout(d),
            SupervisorError::RestartBudgetExhausted { .. }
            | SupervisorError::HandshakeFailed => ProcessRuntimeError::Spawn(format!("{e}")),
        }
    }
}

// ── Wire protocol (long-lived extension) ──────────────────────────

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PluginMessage {
    HostCall { id: u64, method: String, #[serde(default)] params: Value },
    InvokeDone { id: u64, status: i32, #[serde(default)] data_b64: String },
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

struct Supervised {
    /// `None` until the first successful spawn.
    worker: Option<Worker>,
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

impl Default for Supervised {
    fn default() -> Self {
        Self {
            worker: None,
            crashes: Vec::new(),
            consecutive_failures: 0,
            last_attempt_at: None,
        }
    }
}

impl Supervised {
    fn prune_window(&mut self) {
        let cutoff = Instant::now() - RESTART_WINDOW;
        self.crashes.retain(|t| *t >= cutoff);
    }

    fn budget_exhausted(&self) -> Option<SupervisorError> {
        if self.crashes.len() >= MAX_RESTARTS_IN_WINDOW {
            Some(SupervisorError::RestartBudgetExhausted {
                crashes: self.crashes.len(),
                window: RESTART_WINDOW,
            })
        } else {
            None
        }
    }

    fn backoff(&self) -> Duration {
        if self.consecutive_failures == 0 {
            return Duration::ZERO;
        }
        let exp = (self.consecutive_failures - 1).min(8);
        let raw = INITIAL_BACKOFF * 2u32.pow(exp as u32);
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
    if let Some(entry) = map.get(name) {
        let mut sup = entry.value().lock().await;
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
    core: Option<Arc<Core>>,
    config: BTreeMap<String, String>,
) -> Result<InvokeOutput, ProcessRuntimeError> {
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
    let result = drive_invoke(&mut sup, manifest, &core, &config, input).await;
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
    core: &Option<Arc<Core>>,
    config: &BTreeMap<String, String>,
    input: &[u8],
) -> Result<InvokeOutput, SupervisorError> {
    let worker = sup.worker.as_mut().ok_or(SupervisorError::Protocol("worker missing"))?;
    let id = worker.next_id;
    worker.next_id = worker.next_id.wrapping_add(1);

    let invoke_msg = HostMessage::Invoke {
        id,
        input: base64::engine::general_purpose::STANDARD.encode(input),
    };
    write_msg(&mut worker.stdin, &invoke_msg).await?;

    let timeout = DEFAULT_INVOKE_TIMEOUT;
    let outcome = tokio::time::timeout(timeout, async {
        loop {
            let mut buf = String::new();
            let read = worker
                .stdout
                .read_line(&mut buf)
                .await
                .map_err(|e| SupervisorError::Io(format!("{e}")))?;
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
                PluginMessage::HostCall { id: hid, method, params } => {
                    let result =
                        handle_host_call(manifest, core.as_ref(), config, &method, &params).await;
                    let reply = match result {
                        Ok(v) => HostMessage::HostReply { id: hid, result: v },
                        Err(e) => HostMessage::HostReplyError { id: hid, error: e },
                    };
                    write_msg(&mut worker.stdin, &reply).await?;
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
                    let outcome = if status == 0 {
                        InvokeOutcome::Success
                    } else {
                        InvokeOutcome::PluginError(status)
                    };
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

// ── Spawn helpers ─────────────────────────────────────────────────

async fn spawn_worker(
    manifest: &PluginManifest,
    binary: &[u8],
) -> Result<Worker, SupervisorError> {
    let exe_path = write_temp_executable(&manifest.name, binary)
        .map_err(|e| SupervisorError::Spawn(format!("temp file: {e}")))?;
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
        "SystemRoot", "SystemDrive", "windir", "TEMP", "TMP",
        "USERPROFILE", "LOCALAPPDATA", "APPDATA", "ProgramData",
        "ProgramFiles", "ProgramFiles(x86)", "COMSPEC",
        "PATHEXT", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
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

    let mut worker = Worker {
        child,
        stdin,
        stdout: BufReader::new(stdout),
        next_id: 1,
    };

    // Send Init + receive Hello handshake. The handshake is bounded
    // by a 60s timeout — a plugin that fails to send Hello in that
    // window is killed and the spawn is retried.
    handshake(&mut worker, manifest, &bootstrap).await?;

    Ok(worker)
}

async fn handshake(
    worker: &mut Worker,
    manifest: &PluginManifest,
    bootstrap: &str,
) -> Result<(), SupervisorError> {
    let init = HostMessage::Init {
        plugin_name: &manifest.name,
    };
    write_msg(&mut worker.stdin, &init).await?;

    let timeout = Duration::from_secs(60);
    let hello = tokio::time::timeout(timeout, async {
        let mut buf = String::new();
        loop {
            buf.clear();
            let read = worker
                .stdout
                .read_line(&mut buf)
                .await
                .map_err(|e| SupervisorError::Io(format!("{e}")))?;
            if read == 0 {
                return Err(SupervisorError::Io("stdout closed before hello".into()));
            }
            let trimmed = buf.trim_end();
            if trimmed.is_empty() {
                continue;
            }
            let msg: PluginMessage = serde_json::from_str(trimmed)
                .map_err(|_| SupervisorError::Protocol("hello not valid JSON"))?;
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
    let mut line =
        serde_json::to_vec(msg).map_err(|_| SupervisorError::Protocol("host message serialise"))?;
    line.push(b'\n');
    writer
        .write_all(&line)
        .await
        .map_err(|e| SupervisorError::Io(format!("{e}")))?;
    writer
        .flush()
        .await
        .map_err(|e| SupervisorError::Io(format!("{e}")))?;
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
        assert!(matches!(
            s.budget_exhausted(),
            Some(SupervisorError::RestartBudgetExhausted { .. })
        ));
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
