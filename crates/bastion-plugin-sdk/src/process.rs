//! Process-runtime plugin runner (`runtime = "process"`): read loop,
//! dispatch, host calls and lifecycle messages for the three host protocols
//! — single-shot, serialized long-lived, and the ABI 1.4 multiplexed one
//! (`concurrent = true`, features/sql-browser.md §9.4).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::{Zeroize, Zeroizing};

use crate::Response;

/// How long a host call waits for its reply on the multiplexed protocol.
pub const HOST_CALL_TIMEOUT: Duration = Duration::from_secs(60);

/// A process-runtime plugin. `handle` runs once per invocation; on the
/// multiplexed protocol several run at once, each on its own thread.
pub trait ProcessPlugin: Send + Sync + 'static {
    fn handle(&self, inv: &Invocation, input: &[u8]) -> Response;

    /// A host lifecycle event (ABI 1.4): close sessions, zeroize released
    /// credentials and drop buffers before returning. The host is told the
    /// event was handled on return. Also called with `Shutdown` at EOF.
    fn on_lifecycle(&self, _event: Lifecycle) {}
}

/// Host → plugin lifecycle events (ABI 1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Seal,
    Reload,
    Shutdown,
}

/// Why a host call failed: the host's error code and its detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCallError {
    /// `forbidden`, `no_invocation`, `not_granted`, `bad_request`,
    /// `no_sql_privilege`, `not_available`, `refused`, `not_found`, …
    pub code: String,
    pub detail: String,
}

impl HostCallError {
    fn from_reply(s: &str) -> Self {
        match s.split_once(": ") {
            Some((c, d)) => Self { code: c.to_string(), detail: d.to_string() },
            None => Self { code: s.to_string(), detail: String::new() },
        }
    }

    fn local(code: &str, detail: impl Into<String>) -> Self {
        Self { code: code.to_string(), detail: detail.into() }
    }
}

impl std::fmt::Display for HostCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.detail.is_empty() {
            f.write_str(&self.code)
        } else {
            write!(f, "{}: {}", self.code, self.detail)
        }
    }
}

impl std::error::Error for HostCallError {}

/// The runner could not speak to the host.
#[derive(Debug)]
pub enum RunnerError {
    Io(std::io::Error),
    Protocol(&'static str),
}

impl std::fmt::Display for RunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunnerError::Io(e) => write!(f, "plugin stdio: {e}"),
            RunnerError::Protocol(m) => write!(f, "plugin protocol: {m}"),
        }
    }
}

impl std::error::Error for RunnerError {}

impl From<std::io::Error> for RunnerError {
    fn from(e: std::io::Error) -> Self {
        RunnerError::Io(e)
    }
}

// ── shared state ────────────────────────────────────────────────────────

/// Boxed host → plugin stream.
pub type Reader = Box<dyn BufRead + Send>;
/// Boxed plugin → host stream.
pub type Writer = Box<dyn Write + Send>;
type Reply = Result<Value, HostCallError>;

enum Mode {
    /// Single-shot and serialized: a host call reads its reply inline.
    Direct(Mutex<Reader>),
    /// Multiplexed: the reader thread routes replies by call id.
    Mux(Mutex<HashMap<u64, mpsc::Sender<Reply>>>),
}

struct Shared {
    writer: Mutex<Writer>,
    next_call: AtomicU64,
    mode: Mode,
}

impl Shared {
    fn new(writer: Writer, mode: Mode) -> Arc<Self> {
        Arc::new(Self { writer: Mutex::new(writer), next_call: AtomicU64::new(1), mode })
    }

    fn send(&self, v: &Value) -> Result<(), RunnerError> {
        let mut line = Zeroizing::new(serde_json::to_vec(v).map_err(|_| RunnerError::Protocol("serialise"))?);
        line.push(b'\n');
        let mut w = self.writer.lock().map_err(|_| RunnerError::Protocol("writer poisoned"))?;
        w.write_all(&line)?;
        w.flush()?;
        Ok(())
    }
}

/// Parse a `host_reply` (or the serialized hosts' `host_reply_error`).
fn reply_of(v: &mut Value) -> Reply {
    if let Some(e) = v.get("error").and_then(Value::as_str) {
        return Err(HostCallError::from_reply(e));
    }
    Ok(v.get_mut("result").map(Value::take).unwrap_or(Value::Null))
}

/// One line, in a buffer zeroized on drop (a reply can carry a released
/// credential). `None` at end of stream.
fn read_line(r: &mut Reader) -> Result<Option<Zeroizing<String>>, RunnerError> {
    let mut line = Zeroizing::new(String::new());
    if r.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    Ok(Some(line))
}

fn scrub(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Object(m) => m.values_mut().for_each(scrub),
        Value::Array(a) => a.iter_mut().for_each(scrub),
        _ => {}
    }
}

// ── invocations and host calls ──────────────────────────────────────────

/// One invocation in flight, with its host handle.
pub struct Invocation {
    id: u64,
    cancelled: Arc<AtomicBool>,
    host: ProcessHost,
}

impl Invocation {
    /// The host's invocation id (0 on the single-shot protocol).
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The host cancelled this invocation (its deadline passed). Stop; the
    /// caller already has its answer, and host calls are now refused.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn host(&self) -> &ProcessHost {
        &self.host
    }
}

/// One check for [`ProcessHost::resource_sql_authorize`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SqlCheck {
    /// `sql_select` … `sql_script`.
    pub capability: String,
    /// `"server"`, or `{"catalog", "schema", "object"}`.
    pub target: Value,
}

impl SqlCheck {
    pub fn server(capability: &str) -> Self {
        Self { capability: capability.to_string(), target: json!("server") }
    }

    pub fn object(capability: &str, catalog: &str, schema: &str, object: &str) -> Self {
        Self {
            capability: capability.to_string(),
            target: json!({"catalog": catalog, "schema": schema, "object": object}),
        }
    }
}

/// The host's decision for one [`SqlCheck`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SqlVerdict {
    pub capability: String,
    pub target: Value,
    pub path: String,
    pub allowed: bool,
    pub denied_by_deny: bool,
}

/// A database login released by the host. The password is zeroized on drop
/// and redacted from `Debug`; keep it for the session's connection only.
pub struct SqlCredential {
    pub resource: String,
    pub profile: String,
    pub secret_id: String,
    /// The only endpoint the credential may be sent to, `host:port`.
    pub endpoint: String,
    pub username: String,
    pub password: Zeroizing<String>,
}

impl std::fmt::Debug for SqlCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlCredential")
            .field("resource", &self.resource)
            .field("profile", &self.profile)
            .field("secret_id", &self.secret_id)
            .field("endpoint", &self.endpoint)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Typed wrappers over the process runtime's host calls.
#[derive(Clone)]
pub struct ProcessHost {
    shared: Arc<Shared>,
    invocation: u64,
}

impl ProcessHost {
    /// Make one host call and wait for its reply.
    pub fn call(&self, method: &str, params: Value) -> Reply {
        let id = self.shared.next_call.fetch_add(1, Ordering::SeqCst);
        match &self.shared.mode {
            Mode::Direct(reader) => {
                let msg = json!({"type": "host_call", "id": id, "method": method, "params": params});
                self.shared.send(&msg).map_err(|e| HostCallError::local("io", e.to_string()))?;
                let mut r = reader.lock().map_err(|_| HostCallError::local("io", "reader poisoned"))?;
                loop {
                    let line = read_line(&mut r)
                        .map_err(|e| HostCallError::local("io", e.to_string()))?
                        .ok_or_else(|| HostCallError::local("io", "host closed stdin"))?;
                    let Ok(mut v) = serde_json::from_str::<Value>(line.trim()) else { continue };
                    let is_reply = matches!(v["type"].as_str(), Some("host_reply" | "host_reply_error"));
                    let reply = (is_reply && v["id"].as_u64() == Some(id)).then(|| reply_of(&mut v));
                    scrub(&mut v);
                    if let Some(reply) = reply {
                        return reply;
                    }
                }
            }
            Mode::Mux(pending) => {
                let (tx, rx) = mpsc::channel();
                if let Ok(mut p) = pending.lock() {
                    p.insert(id, tx);
                }
                let msg = json!({"type": "host_call", "id": id, "invocation": self.invocation,
                    "method": method, "params": params});
                let reply = match self.shared.send(&msg) {
                    Ok(()) => rx
                        .recv_timeout(HOST_CALL_TIMEOUT)
                        .unwrap_or_else(|_| Err(HostCallError::local("timeout", "no reply from the host"))),
                    Err(e) => Err(HostCallError::local("io", e.to_string())),
                };
                if let Ok(mut p) = pending.lock() {
                    p.remove(&id);
                }
                reply
            }
        }
    }

    pub fn config_get(&self, key: &str) -> Option<String> {
        let v = self.call("config_get", json!({"key": key})).ok()?;
        v.get("value").and_then(Value::as_str).map(str::to_string)
    }

    /// 1 = trace … 5 = error. Never log a credential or statement data.
    pub fn log(&self, level: i32, msg: &str) {
        let _ = self.call("log", json!({"level": level, "msg": msg}));
    }

    pub fn now_unix_ms(&self) -> Result<u64, HostCallError> {
        self.call("now_unix_ms", json!({}))?.as_u64().ok_or_else(|| HostCallError::local("bad_reply", "not a number"))
    }

    pub fn storage_get(&self, key: &str) -> Result<Vec<u8>, HostCallError> {
        let v = self.call("storage_get", json!({"key": key}))?;
        let b64 = v.get("value_b64").and_then(Value::as_str).unwrap_or("");
        B64.decode(b64).map_err(|_| HostCallError::local("bad_reply", "value not base64"))
    }

    pub fn storage_put(&self, key: &str, value: &[u8]) -> Result<(), HostCallError> {
        self.call("storage_put", json!({"key": key, "value_b64": B64.encode(value)})).map(|_| ())
    }

    pub fn storage_delete(&self, key: &str) -> Result<(), HostCallError> {
        self.call("storage_delete", json!({"key": key})).map(|_| ())
    }

    pub fn storage_list(&self, prefix: &str) -> Result<Vec<String>, HostCallError> {
        let v = self.call("storage_list", json!({"prefix": prefix}))?;
        Ok(v.get("keys")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|k| k.as_str().map(str::to_string)).collect())
            .unwrap_or_default())
    }

    /// Emit an audit event. On ABI 1.4 with `caller_identity` the host stamps
    /// the caller as the actor; nothing in `payload` can set it.
    pub fn audit_emit(&self, payload: Value) -> Result<(), HostCallError> {
        self.call("audit_emit", json!({"payload": payload})).map(|_| ())
    }

    /// The resource's engine, endpoint and `sql` profiles, when the caller
    /// holds any SQL privilege on it (`sql_gate`).
    pub fn resource_sql_target(&self, resource: &str) -> Reply {
        self.call("resource_sql_target", json!({"resource": resource}))
    }

    /// The caller's verdict per check (`sql_gate`); refusals reach the
    /// host's denial store.
    pub fn resource_sql_authorize(&self, resource: &str, checks: &[SqlCheck]) -> Result<Vec<SqlVerdict>, HostCallError> {
        let v = self.call("resource_sql_authorize", json!({"resource": resource, "checks": checks}))?;
        serde_json::from_value(v.get("verdicts").cloned().unwrap_or(Value::Null))
            .map_err(|_| HostCallError::local("bad_reply", "malformed verdicts"))
    }

    /// Release `profile`'s login for one session (`resource_credentials =
    /// ["sql"]`). The host enforces the endpoint binding and audits it.
    pub fn resource_sql_credential(
        &self,
        resource: &str,
        profile: &str,
        session_ref: &str,
    ) -> Result<SqlCredential, HostCallError> {
        let mut v = self.call(
            "resource_sql_credential",
            json!({"resource": resource, "profile": profile, "session_ref": session_ref}),
        )?;
        let text = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_string).unwrap_or_default();
        let cred = match v.get_mut("password").map(Value::take) {
            Some(Value::String(p)) => Ok(SqlCredential {
                resource: text(&v, "resource"),
                profile: text(&v, "profile"),
                secret_id: text(&v, "secret_id"),
                endpoint: text(&v, "endpoint"),
                username: text(&v, "username"),
                password: Zeroizing::new(p),
            }),
            Some(mut other) => {
                scrub(&mut other);
                Err(HostCallError::local("bad_reply", "release has no password"))
            }
            None => Err(HostCallError::local("bad_reply", "release has no password")),
        };
        scrub(&mut v);
        cred
    }

    /// Burn a connect-MFA ticket for `(resource, profile)` (`sql_gate`).
    /// `Ok(false)` when the profile is not gated (nothing is consumed).
    pub fn connect_ticket_redeem(&self, resource: &str, profile: &str, ticket: &str) -> Result<bool, HostCallError> {
        let v = self.call("connect_ticket_redeem", json!({"resource": resource, "profile": profile, "ticket": ticket}))?;
        Ok(v.get("redeemed").and_then(Value::as_bool).unwrap_or(false))
    }

    /// Burn a step-up ticket bound to `action` (features/sql-browser.md
    /// §8.3): one or more `sql_*` names, comma-separated. The host always
    /// demands a ticket minted for exactly that action; a connect ticket is
    /// refused. `Ok(true)` only when the host says it redeemed one, so a
    /// reply without `redeemed: true` reads as not redeemed (fail closed).
    pub fn connect_ticket_redeem_action(
        &self,
        resource: &str,
        profile: &str,
        ticket: &str,
        action: &str,
    ) -> Result<bool, HostCallError> {
        let v = self.call(
            "connect_ticket_redeem",
            json!({"resource": resource, "profile": profile, "ticket": ticket, "action": action}),
        )?;
        Ok(v.get("redeemed").and_then(Value::as_bool).unwrap_or(false))
    }
}

// ── the runner ──────────────────────────────────────────────────────────

/// Serve `plugin` on stdin/stdout and exit. The protocol follows from
/// `BV_PLUGIN_LONG_LIVED` and the host's `init`.
pub fn run<P: ProcessPlugin>(plugin: P) -> ! {
    let long_lived = std::env::var("BV_PLUGIN_LONG_LIVED").ok().as_deref() == Some("1");
    let token = std::env::var("BV_PLUGIN_BOOTSTRAP_TOKEN").unwrap_or_default();
    let input: Reader = Box::new(BufReader::new(std::io::stdin()));
    let output: Writer = Box::new(std::io::stdout());
    match serve(Arc::new(plugin), input, output, long_lived, &token) {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(70)
        }
    }
}

/// [`run`] over any reader and writer; returns at end of stream.
pub fn serve<P: ProcessPlugin>(
    plugin: Arc<P>,
    mut input: Reader,
    output: Writer,
    long_lived: bool,
    token: &str,
) -> Result<(), RunnerError> {
    let init_line = read_line(&mut input)?.ok_or(RunnerError::Protocol("stdin closed before init"))?;
    let init: Value = serde_json::from_str(init_line.trim()).map_err(|_| RunnerError::Protocol("init is not JSON"))?;
    if init["type"] != "init" {
        return Err(RunnerError::Protocol("expected init"));
    }
    if !long_lived {
        return single_shot(plugin, input, output, &init);
    }
    if init["protocol"] == "multiplexed" {
        let shared = Shared::new(output, Mode::Mux(Mutex::new(HashMap::new())));
        shared.send(&json!({"type": "hello", "token": token}))?;
        return multiplexed(plugin, input, shared);
    }
    let shared = Shared::new(output, Mode::Direct(Mutex::new(input)));
    shared.send(&json!({"type": "hello", "token": token}))?;
    serialized(plugin, shared)
}

fn single_shot<P: ProcessPlugin>(plugin: Arc<P>, input: Reader, output: Writer, init: &Value) -> Result<(), RunnerError> {
    let data = B64.decode(init["input"].as_str().unwrap_or("")).map_err(|_| RunnerError::Protocol("input not base64"))?;
    let shared = Shared::new(output, Mode::Direct(Mutex::new(input)));
    let host = ProcessHost { shared: shared.clone(), invocation: 0 };
    let resp = plugin.handle(&Invocation { id: 0, cancelled: Arc::default(), host }, &data);
    shared.send(&json!({"type": "set_response", "data_b64": B64.encode(&resp.bytes)}))?;
    shared.send(&json!({"type": "done", "status": resp.status}))
}

fn serialized<P: ProcessPlugin>(plugin: Arc<P>, shared: Arc<Shared>) -> Result<(), RunnerError> {
    let Mode::Direct(reader) = &shared.mode else { return Err(RunnerError::Protocol("mode")) };
    loop {
        let line = read_line(&mut *reader.lock().map_err(|_| RunnerError::Protocol("reader poisoned"))?)?;
        let Some(line) = line else {
            plugin.on_lifecycle(Lifecycle::Shutdown);
            return Ok(());
        };
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else { continue };
        if v["type"] != "invoke" {
            continue;
        }
        let id = v["id"].as_u64().unwrap_or(0);
        let data = B64.decode(v["input"].as_str().unwrap_or("")).unwrap_or_default();
        let host = ProcessHost { shared: shared.clone(), invocation: id };
        let resp = plugin.handle(&Invocation { id, cancelled: Arc::default(), host }, &data);
        let done = json!({"type": "invoke_done", "id": id, "status": resp.status, "data_b64": B64.encode(&resp.bytes)});
        shared.send(&done)?;
    }
}

/// The multiplexed loop: this thread only reads and routes. Invocations and
/// lifecycle events run on their own threads, so a slow handler never stops
/// replies, cancels or pings.
fn multiplexed<P: ProcessPlugin>(plugin: Arc<P>, mut input: Reader, shared: Arc<Shared>) -> Result<(), RunnerError> {
    let cancels: Arc<Mutex<HashMap<u64, Arc<AtomicBool>>>> = Arc::default();
    loop {
        let Some(line) = read_line(&mut input)? else {
            plugin.on_lifecycle(Lifecycle::Shutdown);
            return Ok(());
        };
        let Ok(mut v) = serde_json::from_str::<Value>(line.trim()) else { continue };
        match v["type"].as_str().unwrap_or("") {
            "host_reply" => {
                let id = v["id"].as_u64().unwrap_or(0);
                let tx = match &shared.mode {
                    Mode::Mux(p) => p.lock().ok().and_then(|mut p| p.remove(&id)),
                    Mode::Direct(_) => None,
                };
                if let Some(tx) = tx {
                    let _ = tx.send(reply_of(&mut v));
                }
            }
            "invoke" => {
                let id = v["id"].as_u64().unwrap_or(0);
                let data = B64.decode(v["input"].as_str().unwrap_or("")).unwrap_or_default();
                let cancelled = Arc::new(AtomicBool::new(false));
                if let Ok(mut c) = cancels.lock() {
                    c.insert(id, cancelled.clone());
                }
                let (plugin, shared, cancels) = (plugin.clone(), shared.clone(), cancels.clone());
                std::thread::spawn(move || {
                    let host = ProcessHost { shared: shared.clone(), invocation: id };
                    let resp = plugin.handle(&Invocation { id, cancelled, host }, &data);
                    if let Ok(mut c) = cancels.lock() {
                        c.remove(&id);
                    }
                    let done = json!({"type": "done", "id": id, "status": resp.status,
                        "data_b64": B64.encode(&resp.bytes)});
                    let _ = shared.send(&done);
                });
            }
            "cancel" => {
                let id = v["id"].as_u64().unwrap_or(0);
                if let Some(flag) = cancels.lock().ok().and_then(|c| c.get(&id).cloned()) {
                    flag.store(true, Ordering::SeqCst);
                }
            }
            "ping" => shared.send(&json!({"type": "pong", "nonce": v["nonce"]}))?,
            "lifecycle" => {
                if let Ok(event) = serde_json::from_value::<Lifecycle>(v["event"].clone()) {
                    let (plugin, shared) = (plugin.clone(), shared.clone());
                    std::thread::spawn(move || {
                        plugin.on_lifecycle(event);
                        let _ = shared.send(&json!({"type": "lifecycle_ack", "event": event}));
                    });
                }
            }
            _ => {}
        }
        scrub(&mut v);
    }
}

#[cfg(test)]
mod tests;
