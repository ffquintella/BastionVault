//! Harness for **process-runtime** plugins (`runtime = "process"`).
//!
//! Spawns the plugin executable exactly like
//! `src/plugins/process_runtime.rs` does — cleared environment plus
//! `BV_PLUGIN_BOOTSTRAP_TOKEN` / `BV_PLUGIN_NAME` / `BV_PLUGIN_MODE`,
//! piped stdio — and speaks the same line-delimited JSON protocol
//! (`init` → `host_call`/`host_reply` → `set_response` → `done`). Host
//! calls are answered from the **same** [`TestHost`] state the WASM
//! harness uses, so one builder configures either runtime and storage,
//! logs and audit events are asserted the same way.
//!
//! The process runtime's call set is a subset of the WASM one: it has
//! no `crypto_*` (they answer `unknown_method`), and `now_unix_ms` /
//! `storage_*` reply with JSON values instead of buffer return codes.
//! Error strings (`forbidden`, `not_found`, `internal`, `bad_b64`,
//! `unknown_method`) match the server's.
//!
//! ```no_run
//! use bastion_plugin_testkit::TestHost;
//! let host = TestHost::builder("my-proc").storage_prefix("").build();
//! let out = host
//!     .invoke_process("target/release/my-proc".as_ref(), "read", "k", serde_json::json!({}))
//!     .unwrap();
//! out.assert_success();
//! ```

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::{json, Value};

use crate::{data_key, envelope, InvokeOutcome, LogLine, TestClock, TestHost, TestInvocation, TestkitError};

/// Same default as `process_runtime::DEFAULT_INVOKE_TIMEOUT`.
pub const DEFAULT_PROCESS_TIMEOUT: Duration = Duration::from_secs(30);

impl TestHost {
    /// Run a process-runtime plugin executable through one invocation
    /// with the standard `{"op","path","data"}` envelope.
    pub fn invoke_process(
        &self,
        exe: &Path,
        op: &str,
        path: &str,
        data: Value,
    ) -> Result<TestInvocation, TestkitError> {
        self.invoke_process_raw(exe, &envelope(op, path, data), DEFAULT_PROCESS_TIMEOUT)
    }

    /// Like [`invoke_process`](Self::invoke_process) with raw input
    /// bytes and an explicit kill-on-timeout.
    pub fn invoke_process_raw(
        &self,
        exe: &Path,
        input: &[u8],
        timeout: Duration,
    ) -> Result<TestInvocation, TestkitError> {
        let (logs_before, audit_before) = {
            let st = self.state.lock().unwrap();
            (st.logs.len(), st.audit.len())
        };

        let mut cmd = Command::new(exe);
        cmd.env_clear()
            .env("BV_PLUGIN_BOOTSTRAP_TOKEN", "testkit-bootstrap-token")
            .env("BV_PLUGIN_NAME", &self.name)
            .env("BV_PLUGIN_MODE", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Ok(p) = std::env::var("PATH") {
            cmd.env("PATH", p);
        }
        let mut child = cmd.spawn().map_err(|e| TestkitError::Invoke(format!("spawn {}: {e}", exe.display())))?;
        let mut stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");

        // Drain stderr so a chatty plugin cannot block on a full pipe.
        let err_thread =
            std::thread::spawn(move || BufReader::new(stderr).lines().map_while(Result::ok).collect::<Vec<_>>());
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });

        let init = json!({
            "type": "init",
            "token": "testkit-bootstrap-token",
            "input": B64.encode(input),
            "plugin_name": self.name,
        });
        send(&mut stdin, &init)?;

        let deadline = Instant::now() + timeout;
        let mut response = Vec::new();
        let result: Result<i32, TestkitError> = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let line = match rx.recv_timeout(remaining) {
                Ok(l) => l,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    break Err(TestkitError::Invoke(format!("process plugin timed out after {timeout:?}")))
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    break Err(TestkitError::Invoke("process plugin exited before sending `done`".into()))
                }
            };
            if line.trim().is_empty() {
                continue;
            }
            let msg: Value = match serde_json::from_str(line.trim()) {
                Ok(v) => v,
                Err(_) => break Err(TestkitError::Invoke("plugin message not valid JSON".into())),
            };
            match msg.get("type").and_then(Value::as_str) {
                Some("host_call") => {
                    let id = msg.get("id").and_then(Value::as_u64).unwrap_or(0);
                    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
                    let params = msg.get("params").cloned().unwrap_or(Value::Null);
                    let reply = match self.handle_process_call(method, &params) {
                        Ok(v) => json!({"type": "host_reply", "id": id, "result": v}),
                        Err(e) => json!({"type": "host_reply", "id": id, "error": e}),
                    };
                    if let Err(e) = send(&mut stdin, &reply) {
                        break Err(e);
                    }
                }
                Some("set_response") => {
                    let b64 = msg.get("data_b64").and_then(Value::as_str).unwrap_or("");
                    match B64.decode(b64.as_bytes()) {
                        Ok(b) => response = b,
                        Err(_) => break Err(TestkitError::Invoke("set_response data not base64".into())),
                    }
                }
                Some("done") => break Ok(msg.get("status").and_then(Value::as_i64).unwrap_or(0) as i32),
                _ => break Err(TestkitError::Invoke("unrecognised plugin message type".into())),
            }
        };

        drop(stdin);
        if result.is_err() {
            let _ = child.kill();
        }
        let _ = child.wait();
        let stderr_lines = err_thread.join().unwrap_or_default();
        self.state.lock().unwrap().stderr.extend(stderr_lines);

        let status = result?;
        let st = self.state.lock().unwrap();
        Ok(TestInvocation {
            outcome: if status == 0 { InvokeOutcome::Success } else { InvokeOutcome::PluginError(status) },
            response,
            fuel_consumed: 0,
            logs: st.logs[logs_before..].to_vec(),
            audit_events: st.audit[audit_before..].to_vec(),
        })
    }

    /// Lines the process plugin wrote to stderr (the server forwards
    /// these to its log; they are never parsed).
    pub fn process_stderr(&self) -> Vec<String> {
        self.state.lock().unwrap().stderr.clone()
    }

    /// Mirror of `process_runtime::handle_host_call`.
    fn handle_process_call(&self, method: &str, params: &Value) -> Result<Value, String> {
        let s = |k: &str| params.get(k).and_then(Value::as_str).unwrap_or("");
        match method {
            "config_get" => match self.state.lock().unwrap().config.get(s("key")) {
                Some(v) => Ok(json!({"value": v})),
                None => Err("not_found".into()),
            },
            "log" => {
                if !self.log_emit {
                    return Err("forbidden".into());
                }
                let level = params.get("level").and_then(Value::as_i64).unwrap_or(3) as i32;
                self.state.lock().unwrap().logs.push(LogLine { level, line: s("msg").to_string() });
                Ok(Value::Null)
            }
            "now_unix_ms" => {
                let ms = match self.state.lock().unwrap().clock {
                    TestClock::Fixed(ms) => ms as u64,
                    TestClock::System => {
                        use std::time::{SystemTime, UNIX_EPOCH};
                        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
                    }
                };
                Ok(json!(ms))
            }
            "storage_get" => {
                let full = self.rebase(s("key")).ok_or("forbidden")?;
                match self.state.lock().unwrap().storage.get(&full) {
                    Some(v) => Ok(json!({"value_b64": B64.encode(v)})),
                    None => Err("not_found".into()),
                }
            }
            "storage_put" => {
                let full = self.rebase(s("key")).ok_or("forbidden")?;
                let value = B64.decode(s("value_b64").as_bytes()).map_err(|_| "bad_b64")?;
                self.state.lock().unwrap().storage.insert(full, value);
                Ok(Value::Null)
            }
            "storage_delete" => {
                let full = self.rebase(s("key")).ok_or("forbidden")?;
                self.state.lock().unwrap().storage.remove(&full);
                Ok(Value::Null)
            }
            "storage_list" => {
                let prefix = s("prefix");
                let granted = self.storage_prefix.as_deref().ok_or("forbidden")?;
                if prefix.contains("..") {
                    return Err("forbidden".into());
                }
                let mut full_prefix = data_key(&self.name, "");
                if !prefix.is_empty() {
                    let granted = granted.trim_end_matches('/');
                    let req = prefix.trim_start_matches('/').trim_end_matches('/');
                    if !granted.is_empty() && req != granted && !req.starts_with(&format!("{granted}/")) {
                        return Err("forbidden".into());
                    }
                    full_prefix.push_str(req);
                    full_prefix.push('/');
                }
                // Immediate children; directories carry a trailing `/`.
                let mut names = BTreeSet::new();
                for k in self.state.lock().unwrap().storage.keys() {
                    if let Some(rest) = k.strip_prefix(&full_prefix) {
                        match rest.split_once('/') {
                            Some((dir, _)) => names.insert(format!("{dir}/")),
                            None => names.insert(rest.to_string()),
                        };
                    }
                }
                Ok(json!({"keys": names.into_iter().collect::<Vec<_>>()}))
            }
            "audit_emit" => {
                if !self.audit_emit {
                    return Err("forbidden".into());
                }
                let payload = params.get("payload").cloned().unwrap_or(Value::Null);
                self.state.lock().unwrap().audit.push(json!({
                    "path": format!("sys/plugins/{}/event", self.name),
                    "data": {"plugin_event": payload},
                }));
                Ok(Value::Null)
            }
            _ => Err("unknown_method".into()),
        }
    }

    /// Same prefix/`..` rules as the server's `rebase_key`.
    fn rebase(&self, requested: &str) -> Option<String> {
        let prefix = self.storage_prefix.as_deref()?.trim_end_matches('/');
        let req = requested.trim_start_matches('/');
        if !prefix.is_empty() && req != prefix && !req.starts_with(&format!("{prefix}/")) {
            return None;
        }
        if req.contains("..") {
            return None;
        }
        Some(data_key(&self.name, req))
    }
}

fn send(stdin: &mut impl Write, msg: &Value) -> Result<(), TestkitError> {
    let mut line = serde_json::to_vec(msg).expect("serialisable");
    line.push(b'\n');
    stdin
        .write_all(&line)
        .and_then(|_| stdin.flush())
        .map_err(|e| TestkitError::Invoke(format!("write to plugin stdin: {e}")))
}
