//! Out-of-process plugin runtime.
//!
//! Runs plugins as separate OS subprocesses for cases that the WASM
//! sandbox can't serve — typically plugins that need real network
//! access (cloud SDKs, DB drivers, HSM bridges). Capability mediation
//! still goes through the host: every storage / audit / log call the
//! plugin wants to make is sent to the parent process as a JSON-RPC
//! message over stdin/stdout, and the host enforces capability gates
//! the same way `WasmRuntime` does.
//!
//! ## IPC: line-delimited JSON
//!
//! We deliberately do **not** use tonic + protobuf here. The substance
//! of "out-of-process" is the OS-level subprocess boundary, not the
//! wire format. A line-delimited JSON-RPC over stdio:
//!
//! - adds zero new crate dependencies (tokio + serde_json are already
//!   in the workspace),
//! - works identically on Windows + Linux + macOS without UDS / named-
//!   pipe gymnastics,
//! - is a well-known pattern (LSP, debug adapters, etc.),
//! - and matches the spec's intent (capability-gated host calls). Tonic
//!   is an implementation detail the spec mentions; the substance is
//!   what we keep.
//!
//! ## Lifecycle
//!
//! Single-shot per-invoke for v1: the host spawns the binary, sends
//! one init message, dispatches host-call requests until the plugin
//! signals `done`, then waits for exit (with a configurable kill-on-
//! timeout). Long-lived plugin processes with restart-with-backoff are
//! a follow-up — they only matter for plugins that hold cross-request
//! state, which is the same gap as plugin-as-mount on the WASM side.
//!
//! ## Net allowlist
//!
//! `manifest.capabilities.allowed_hosts` is **declarative-only** in v1.
//! The host has no way to enforce outbound network rules from inside
//! the parent process — Linux seccomp + network namespaces, Windows
//! AppContainer, macOS sandbox-exec are the right tools and they're
//! platform-specific. Operators who need hard egress filtering wrap
//! the BastionVault process under a runtime that can do it (systemd
//! `IPAddressAllow=`, k8s NetworkPolicy, Docker `--network=`). The
//! manifest still records the declared hosts so audit + GUI can
//! surface the intent.
//!
//! ## Wire protocol (line-delimited JSON, one object per line)
//!
//! Host → plugin (stdin):
//! - Init: `{"type":"init","token":"<bootstrap>","input":"<base64>","plugin_name":"..."}`
//! - Host reply: `{"type":"host_reply","id":<n>,"result":<value>}` or
//!   `{"type":"host_reply","id":<n>,"error":"<reason>"}`
//!
//! Plugin → host (stdout):
//! - Host call: `{"type":"host_call","id":<n>,"method":"<name>","params":<obj>}`
//! - Set response: `{"type":"set_response","data_b64":"..."}`
//! - Done: `{"type":"done","status":<i32>}`
//!
//! Plugin → host (stderr): forwarded to host log with `[plugin=<name>]`
//! prefix; not parsed.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::timeout;

use crate::{
    audit,
    core::Core,
    storage::StorageEntry,
};

use super::manifest::PluginManifest;
use super::runtime::{InvokeOutcome, InvokeOutput};

pub const DEFAULT_INVOKE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum ProcessRuntimeError {
    #[error("temp file write failed: {0}")]
    TempFile(String),
    #[error("subprocess spawn failed: {0}")]
    Spawn(String),
    #[error("subprocess io failed: {0}")]
    Io(String),
    #[error("subprocess exited before completing: status={0:?}")]
    UnexpectedExit(Option<i32>),
    #[error("subprocess sent malformed message: {0}")]
    Protocol(&'static str),
    #[error("subprocess timed out after {0:?}")]
    Timeout(Duration),
}

/// Execute a registered plugin as a subprocess. Mirrors `WasmRuntime`'s
/// `invoke` shape so the HTTP handler can dispatch on
/// `manifest.runtime` without thinking about the IPC mechanism.
pub struct ProcessRuntime {
    invoke_timeout: Duration,
}

impl ProcessRuntime {
    pub fn new() -> Self {
        Self { invoke_timeout: DEFAULT_INVOKE_TIMEOUT }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { invoke_timeout: timeout }
    }

    /// Single-shot invoke: write the binary to a temp file, spawn it,
    /// drive the JSON-RPC dispatch loop, return the response bytes.
    pub async fn invoke(
        &self,
        manifest: &PluginManifest,
        binary: &[u8],
        input: &[u8],
        core: Option<Arc<Core>>,
    ) -> Result<InvokeOutput, ProcessRuntimeError> {
        self.invoke_with_config(manifest, binary, input, core, Default::default())
            .await
    }

    /// Like `invoke`, but also exposes `config` to the plugin via the
    /// `config_get` JSON-RPC method.
    pub async fn invoke_with_config(
        &self,
        manifest: &PluginManifest,
        binary: &[u8],
        input: &[u8],
        core: Option<Arc<Core>>,
        config: std::collections::BTreeMap<String, String>,
    ) -> Result<InvokeOutput, ProcessRuntimeError> {
        // Write the binary to a uniquely-named temp file so concurrent
        // invocations don't clobber each other. Mark executable on Unix.
        let exe_path = write_temp_executable(&manifest.name, binary)?;

        // Bootstrap token: 256-bit random, single-use. The plugin echoes
        // it back in its first message; mismatch fails the invoke.
        let bootstrap = generate_bootstrap_token();

        let mut cmd = Command::new(&exe_path);
        cmd.env("BV_PLUGIN_BOOTSTRAP_TOKEN", &bootstrap);
        cmd.env("BV_PLUGIN_NAME", &manifest.name);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        // Don't leak parent env to the child — give it only the
        // bootstrap + name. Plugins that need extra env declare it via
        // a future capability; for v1 we keep the surface minimal.
        cmd.env_remove("RUST_LOG");
        cmd.env_clear();
        cmd.env("BV_PLUGIN_BOOTSTRAP_TOKEN", &bootstrap);
        cmd.env("BV_PLUGIN_NAME", &manifest.name);
        // Keep PATH so the plugin can find dynamic linker / deps;
        // operators who want airgapped plugins can null PATH via a
        // future manifest field.
        if let Ok(p) = std::env::var("PATH") {
            cmd.env("PATH", p);
        }
        // Windows requires `SystemRoot`, `SystemDrive`, `windir`, and
        // `TEMP`/`TMP` to be present in the child's environment for
        // DLL search, CRT initialisation, and the Win32 base services.
        // Stripping them via `env_clear()` causes the spawned process
        // to fast-fail during static init with
        // `STATUS_STACK_BUFFER_OVERRUN` (0xC0000409) before the
        // plugin handler even runs. Forward only this minimal set —
        // not arbitrary parent env.
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
        // Tests use the same binary as both runner and plugin; signal
        // plugin mode via env so the ctor in lib.rs picks it up.
        cmd.env("BV_PLUGIN_MODE", "1");

        let mut child = cmd
            .spawn()
            .map_err(|e| ProcessRuntimeError::Spawn(format!("{e}")))?;

        let result = match timeout(self.invoke_timeout, drive_invocation(
            &mut child,
            manifest,
            &bootstrap,
            input,
            core,
            config,
        ))
        .await
        {
            Ok(Ok(out)) => Ok(out),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                let _ = child.start_kill();
                Err(ProcessRuntimeError::Timeout(self.invoke_timeout))
            }
        };

        // Best-effort cleanup of the temp file (the directory is the
        // OS temp dir, which is rotated; this is just being tidy).
        let _ = std::fs::remove_file(&exe_path);

        result
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PluginMessage {
    HostCall { id: u64, method: String, #[serde(default)] params: Value },
    SetResponse { data_b64: String },
    Done { status: i32 },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HostMessage<'a> {
    Init { token: &'a str, input: String, plugin_name: &'a str },
    HostReply { id: u64, result: Value },
    HostReplyError { id: u64, error: String },
}

async fn drive_invocation(
    child: &mut Child,
    manifest: &PluginManifest,
    bootstrap: &str,
    input: &[u8],
    core: Option<Arc<Core>>,
    config: std::collections::BTreeMap<String, String>,
) -> Result<InvokeOutput, ProcessRuntimeError> {
    let mut stdin = child.stdin.take().ok_or(ProcessRuntimeError::Protocol("stdin"))?;
    let stdout = child.stdout.take().ok_or(ProcessRuntimeError::Protocol("stdout"))?;
    let stderr = child.stderr.take().ok_or(ProcessRuntimeError::Protocol("stderr"))?;
    let mut stdout = BufReader::new(stdout);
    let mut stderr = BufReader::new(stderr);

    // Send init.
    let init = HostMessage::Init {
        token: bootstrap,
        input: base64::engine::general_purpose::STANDARD.encode(input),
        plugin_name: &manifest.name,
    };
    write_msg(&mut stdin, &init).await?;

    // Forward stderr lines to log on a detached task. Lifetime tied to
    // the subprocess; when stderr closes the loop exits.
    let plugin_name_for_stderr = manifest.name.clone();
    tokio::spawn(async move {
        let mut line = String::new();
        loop {
            line.clear();
            match stderr.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    let trimmed = line.trim_end();
                    log::info!(target: "plugin", "[{plugin_name_for_stderr}] {trimmed}");
                }
                Err(_) => break,
            }
        }
    });

    // Dispatch loop: read plugin messages, handle host calls, exit on
    // `done` or stdout EOF.
    let mut response: Vec<u8> = Vec::new();
    let status: i32;
    let mut buf = String::new();

    loop {
        buf.clear();
        let read = stdout.read_line(&mut buf).await
            .map_err(|e| ProcessRuntimeError::Io(format!("{e}")))?;
        if read == 0 {
            // EOF before `done` — treat as crash.
            let exit = child.wait().await
                .map_err(|e| ProcessRuntimeError::Io(format!("{e}")))?;
            return Err(ProcessRuntimeError::UnexpectedExit(exit.code()));
        }
        let trimmed = buf.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        let msg: PluginMessage = serde_json::from_str(trimmed)
            .map_err(|_| ProcessRuntimeError::Protocol("plugin message not valid JSON"))?;

        match msg {
            PluginMessage::HostCall { id, method, params } => {
                let result =
                    handle_host_call(manifest, core.as_ref(), &config, &method, &params).await;
                let reply = match result {
                    Ok(v) => HostMessage::HostReply { id, result: v },
                    Err(e) => HostMessage::HostReplyError { id, error: e },
                };
                write_msg(&mut stdin, &reply).await?;
            }
            PluginMessage::SetResponse { data_b64 } => {
                response = base64::engine::general_purpose::STANDARD
                    .decode(data_b64.as_bytes())
                    .map_err(|_| ProcessRuntimeError::Protocol("set_response data not base64"))?;
            }
            PluginMessage::Done { status: s } => {
                status = s;
                break;
            }
        }
    }

    // Wait for the subprocess to actually exit so we don't return to
    // the caller while it's still running.
    let _ = child.wait().await;

    let outcome = if status == 0 {
        InvokeOutcome::Success
    } else {
        InvokeOutcome::PluginError(status)
    };
    Ok(InvokeOutput { outcome, response, fuel_consumed: 0 })
}

async fn write_msg<W>(writer: &mut W, msg: &HostMessage<'_>) -> Result<(), ProcessRuntimeError>
where
    W: AsyncWriteExt + Unpin,
{
    let mut line = serde_json::to_vec(msg)
        .map_err(|_| ProcessRuntimeError::Protocol("host message serialization"))?;
    line.push(b'\n');
    writer
        .write_all(&line)
        .await
        .map_err(|e| ProcessRuntimeError::Io(format!("{e}")))?;
    writer
        .flush()
        .await
        .map_err(|e| ProcessRuntimeError::Io(format!("{e}")))?;
    Ok(())
}

/// Capability-gated host-call dispatcher. Mirrors the function set the
/// WASM runtime exposes via `register_host_imports`. Returns either a
/// JSON value (the "result" payload) or a string error the host sends
/// back as `host_reply.error`.
pub(super) async fn handle_host_call(
    manifest: &PluginManifest,
    core: Option<&Arc<Core>>,
    config: &std::collections::BTreeMap<String, String>,
    method: &str,
    params: &Value,
) -> Result<Value, String> {
    match method {
        "config_get" => {
            let key = params.get("key").and_then(|v| v.as_str()).unwrap_or("");
            match config.get(key) {
                Some(v) => Ok(json!({ "value": v })),
                None => Err("not_found".to_string()),
            }
        }
        "log" => {
            if !manifest.capabilities.log_emit {
                return Err("forbidden".to_string());
            }
            let level = params.get("level").and_then(|v| v.as_i64()).unwrap_or(3) as i32;
            let msg = params.get("msg").and_then(|v| v.as_str()).unwrap_or("");
            let plugin = manifest.name.as_str();
            match level {
                1 => log::trace!(target: "plugin", "[{plugin}] {msg}"),
                2 => log::debug!(target: "plugin", "[{plugin}] {msg}"),
                3 => log::info!(target: "plugin", "[{plugin}] {msg}"),
                4 => log::warn!(target: "plugin", "[{plugin}] {msg}"),
                _ => log::error!(target: "plugin", "[{plugin}] {msg}"),
            }
            Ok(Value::Null)
        }
        "now_unix_ms" => {
            use std::time::{SystemTime, UNIX_EPOCH};
            let v = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            Ok(json!(v))
        }
        "storage_get" => {
            let key = params.get("key").and_then(|v| v.as_str()).unwrap_or("");
            let full = match rebase_key(manifest, key) {
                Some(v) => v,
                None => return Err("forbidden".to_string()),
            };
            let core = match core {
                Some(c) => c,
                None => return Err("no core".to_string()),
            };
            match core.barrier.as_storage().get(&full).await {
                Ok(Some(entry)) => Ok(json!({
                    "value_b64": base64::engine::general_purpose::STANDARD.encode(&entry.value),
                })),
                Ok(None) => Err("not_found".to_string()),
                Err(_) => Err("internal".to_string()),
            }
        }
        "storage_put" => {
            let key = params.get("key").and_then(|v| v.as_str()).unwrap_or("");
            let value_b64 = params.get("value_b64").and_then(|v| v.as_str()).unwrap_or("");
            let full = match rebase_key(manifest, key) {
                Some(v) => v,
                None => return Err("forbidden".to_string()),
            };
            let core = match core {
                Some(c) => c,
                None => return Err("no core".to_string()),
            };
            let value = base64::engine::general_purpose::STANDARD
                .decode(value_b64.as_bytes())
                .map_err(|_| "bad_b64".to_string())?;
            core.barrier
                .as_storage()
                .put(&StorageEntry { key: full, value })
                .await
                .map_err(|_| "internal".to_string())?;
            Ok(Value::Null)
        }
        "storage_delete" => {
            let key = params.get("key").and_then(|v| v.as_str()).unwrap_or("");
            let full = match rebase_key(manifest, key) {
                Some(v) => v,
                None => return Err("forbidden".to_string()),
            };
            let core = match core {
                Some(c) => c,
                None => return Err("no core".to_string()),
            };
            core.barrier
                .as_storage()
                .delete(&full)
                .await
                .map_err(|_| "internal".to_string())?;
            Ok(Value::Null)
        }
        "storage_list" => {
            let prefix = params.get("prefix").and_then(|v| v.as_str()).unwrap_or("");
            if manifest.capabilities.storage_prefix.is_none() {
                return Err("forbidden".to_string());
            }
            if prefix.contains("..") {
                return Err("forbidden".to_string());
            }
            let core = match core {
                Some(c) => c,
                None => return Err("no core".to_string()),
            };
            let mut full_prefix = format!("core/plugins/{}/data/", manifest.name);
            if !prefix.is_empty() {
                let prefix_norm = manifest
                    .capabilities
                    .storage_prefix
                    .as_deref()
                    .unwrap_or("")
                    .trim_end_matches('/');
                let req_norm = prefix.trim_start_matches('/').trim_end_matches('/');
                if !prefix_norm.is_empty()
                    && !(req_norm == prefix_norm || req_norm.starts_with(&format!("{prefix_norm}/")))
                {
                    return Err("forbidden".to_string());
                }
                full_prefix.push_str(req_norm);
                full_prefix.push('/');
            }
            let names = core
                .barrier
                .as_storage()
                .list(&full_prefix)
                .await
                .map_err(|_| "internal".to_string())?;
            Ok(json!({"keys": names}))
        }
        "audit_emit" => {
            if !manifest.capabilities.audit_emit {
                return Err("forbidden".to_string());
            }
            let core = match core {
                Some(c) => c,
                None => return Err("no core".to_string()),
            };
            let payload = params.get("payload").cloned().unwrap_or(Value::Null);
            let mut body = serde_json::Map::new();
            body.insert("plugin_event".to_string(), payload);
            audit::emit_sys_audit(
                core,
                "",
                &format!("sys/plugins/{}/event", manifest.name),
                crate::logical::Operation::Write,
                Some(body),
                None,
            )
            .await;
            Ok(Value::Null)
        }
        _ => Err("unknown_method".to_string()),
    }
}

/// Rebase a plugin-supplied key into the absolute barrier key while
/// enforcing the declared `storage_prefix`. Mirrors the WASM runtime's
/// `PluginCtx::rebase_key`.
fn rebase_key(manifest: &PluginManifest, requested: &str) -> Option<String> {
    let prefix = manifest.capabilities.storage_prefix.as_deref()?;
    let prefix_norm = prefix.trim_end_matches('/');
    let req_norm = requested.trim_start_matches('/');
    if !prefix_norm.is_empty()
        && !(req_norm == prefix_norm || req_norm.starts_with(&format!("{prefix_norm}/")))
    {
        return None;
    }
    if req_norm.contains("..") {
        return None;
    }
    Some(format!(
        "core/plugins/{name}/data/{rel}",
        name = manifest.name,
        rel = req_norm,
    ))
}

pub(super) fn write_temp_executable(name: &str, binary: &[u8]) -> Result<std::path::PathBuf, ProcessRuntimeError> {
    use std::io::Write;
    let mut path = std::env::temp_dir();
    let stem = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>();
    let unique = format!(
        "bv-plugin-{stem}-{ts}-{pid}{ext}",
        ts = chrono::Utc::now().format("%Y%m%dT%H%M%S%6f"),
        pid = std::process::id(),
        ext = if cfg!(windows) { ".exe" } else { "" },
    );
    path.push(unique);
    let mut f = std::fs::File::create(&path)
        .map_err(|e| ProcessRuntimeError::TempFile(format!("{e}")))?;
    f.write_all(binary)
        .map_err(|e| ProcessRuntimeError::TempFile(format!("{e}")))?;
    drop(f);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700));
    }
    Ok(path)
}

pub(super) fn generate_bootstrap_token() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Test-only helper: handler for the in-tree subprocess plugin used by
/// tests. The same test binary acts as both runner and plugin — we
/// dispatch via the `BV_PLUGIN_MODE` env var the runtime sets before
/// spawn. See the `ctor` hook in `src/lib.rs`.
#[doc(hidden)]
#[cfg(test)]
pub fn run_test_subprocess_plugin() -> ! {
    use std::io::{stdin, stdout, BufRead, Write};

    // Critical: this function runs from a `#[ctor::ctor]` (which is
    // `extern "C"` and `nounwind`). Any panic here aborts the
    // process via fast-fail (`STATUS_STACK_BUFFER_OVERRUN` on
    // Windows), and the panic message is **lost** because stderr
    // doesn't flush before the abort. So we use explicit
    // `eprintln!` + `process::exit(N)` for every failure path —
    // never `.expect()`, never `.unwrap()`.

    let stdin = stdin();
    let mut stdout = stdout();

    // Read init. EOF here = parent dropped stdin before writing,
    // which is itself a bug — surface it loudly with exit code 90 so
    // the parent's `UnexpectedExit` carries identifiable info.
    let mut init_line = String::new();
    let bytes_read = match stdin.lock().read_line(&mut init_line) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[bv-test-plugin] stdin read failed: {e}");
            std::process::exit(91);
        }
    };
    if bytes_read == 0 {
        eprintln!("[bv-test-plugin] stdin EOF before init — parent never wrote it");
        std::process::exit(90);
    }
    let init: Value = match serde_json::from_str(init_line.trim()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[bv-test-plugin] init parse failed: {e} (line: {init_line:?})");
            std::process::exit(92);
        }
    };
    let input_b64 = init.get("input").and_then(|v| v.as_str()).unwrap_or("");
    let plugin_name = init.get("plugin_name").and_then(|v| v.as_str()).unwrap_or("");
    let input = base64::engine::general_purpose::STANDARD
        .decode(input_b64)
        .unwrap_or_default();

    // Behaviour selector is the plugin_name suffix after `test-`. The
    // env-var path doesn't work because the runtime's `env_clear()`
    // wipes anything we set in the parent, but the init message goes
    // through stdin verbatim, so we route the behaviour via the name
    // field instead.
    let mode = plugin_name.strip_prefix("test-").unwrap_or("echo").to_string();

    match mode.as_str() {
        "echo" => {
            // set_response(input); done(0)
            let resp = json!({
                "type": "set_response",
                "data_b64": base64::engine::general_purpose::STANDARD.encode(&input),
            });
            writeln!(stdout, "{resp}").unwrap();
            writeln!(stdout, "{}", json!({"type": "done", "status": 0})).unwrap();
        }
        "fail" => {
            // No set_response; done(7)
            writeln!(stdout, "{}", json!({"type": "done", "status": 7})).unwrap();
        }
        "crash" => {
            // Exit without sending done.
            std::process::exit(0);
        }
        "storage_round_trip" => {
            // host_call storage_put("k", input); host_call storage_get("k");
            // set_response(received); done(0).
            //
            // Fails loudly (panics → non-zero exit before `done`) on
            // any host_reply that carries an `error` field — this is
            // what makes the `storage_forbidden_without_capability`
            // test see UnexpectedExit when no storage capability was
            // declared.
            let put = json!({
                "type": "host_call",
                "id": 1,
                "method": "storage_put",
                "params": {
                    "key": "k",
                    "value_b64": base64::engine::general_purpose::STANDARD.encode(&input),
                },
            });
            writeln!(stdout, "{put}").unwrap();
            stdout.flush().unwrap();
            let mut reply = String::new();
            stdin.lock().read_line(&mut reply).unwrap();
            let reply_v: Value = serde_json::from_str(reply.trim()).unwrap();
            if reply_v.get("error").is_some() {
                eprintln!("storage_put refused: {}", reply_v.get("error").unwrap());
                std::process::exit(11);
            }

            let get = json!({
                "type": "host_call",
                "id": 2,
                "method": "storage_get",
                "params": {"key": "k"},
            });
            writeln!(stdout, "{get}").unwrap();
            stdout.flush().unwrap();
            let mut reply2 = String::new();
            stdin.lock().read_line(&mut reply2).unwrap();
            let reply2_v: Value = serde_json::from_str(reply2.trim()).unwrap();
            if reply2_v.get("error").is_some() {
                eprintln!("storage_get refused: {}", reply2_v.get("error").unwrap());
                std::process::exit(12);
            }
            let value_b64 = reply2_v
                .get("result")
                .and_then(|r| r.get("value_b64"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            writeln!(stdout, "{}", json!({"type": "set_response", "data_b64": value_b64})).unwrap();
            writeln!(stdout, "{}", json!({"type": "done", "status": 0})).unwrap();
        }
        "now_ms" => {
            // host_call now_unix_ms; set_response(le_bytes(result)); done(0)
            writeln!(
                stdout,
                "{}",
                json!({"type": "host_call", "id": 1, "method": "now_unix_ms", "params": {}})
            )
            .unwrap();
            stdout.flush().unwrap();
            let mut reply = String::new();
            stdin.lock().read_line(&mut reply).unwrap();
            let v: Value = serde_json::from_str(reply.trim()).unwrap();
            let now = v.get("result").and_then(|r| r.as_u64()).unwrap_or(0);
            let bytes = (now as i64).to_le_bytes();
            let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
            writeln!(stdout, "{}", json!({"type": "set_response", "data_b64": b64})).unwrap();
            writeln!(stdout, "{}", json!({"type": "done", "status": 0})).unwrap();
        }
        other => {
            eprintln!("unknown BV_TEST_PLUGIN_BEHAVIOUR={other} for plugin={plugin_name}");
            std::process::exit(1);
        }
    }
    stdout.flush().unwrap();
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::manifest::{Capabilities, RuntimeKind};

    fn manifest_for(behaviour: &str, name: &str) -> PluginManifest {
        // The "binary" is a copy of the current test exe — see
        // `current_exe_bytes()` below. We don't actually rehash on
        // each test; we just plug a placeholder sha that matches what
        // the catalog would compute. The tests bypass catalog
        // verification by constructing the manifest manually.
        let _ = behaviour;
        PluginManifest {
            name: name.to_string(),
            version: "0.1.0".to_string(),
            plugin_type: "test".to_string(),
            runtime: RuntimeKind::Process,
            abi_version: "1.0".to_string(),
            sha256: "0".repeat(64),
            size: 0,
            capabilities: Capabilities { log_emit: true, ..Default::default() },
            description: String::new(),
            config_schema: vec![],
            signature: String::new(),
            signing_key: String::new(),
        }
    }

    fn current_exe_bytes() -> Vec<u8> {
        let exe = std::env::current_exe().expect("current_exe");
        std::fs::read(exe).expect("read current_exe")
    }

    /// Drive `ProcessRuntime::invoke` against a fresh copy of the test
    /// binary. The subprocess `run_test_subprocess_plugin` handler
    /// chooses its behaviour from `manifest.name` (suffix after the
    /// `test-` prefix) so each test caller controls the mode just by
    /// naming the plugin appropriately — no shared mutable env vars.
    async fn invoke_proc(
        manifest: PluginManifest,
        input: &[u8],
        core: Option<Arc<Core>>,
    ) -> Result<InvokeOutput, ProcessRuntimeError> {
        let bytes = current_exe_bytes();
        let runtime = ProcessRuntime::new();
        runtime.invoke(&manifest, &bytes, input, core).await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn echo_round_trip() {
        let m = manifest_for("echo", "test-echo");
        let out = invoke_proc(m, b"hello-process", None).await.unwrap();
        assert!(matches!(out.outcome, InvokeOutcome::Success));
        assert_eq!(out.response, b"hello-process");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn plugin_reported_error() {
        let m = manifest_for("fail", "test-fail");
        let out = invoke_proc(m, b"", None).await.unwrap();
        match out.outcome {
            InvokeOutcome::PluginError(7) => {}
            other => panic!("expected PluginError(7), got {other:?}"),
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn crash_before_done_is_unexpected_exit() {
        let m = manifest_for("crash", "test-crash");
        let err = invoke_proc(m, b"", None).await.unwrap_err();
        assert!(
            matches!(err, ProcessRuntimeError::UnexpectedExit(_)),
            "expected UnexpectedExit, got {err:?}",
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn now_unix_ms_round_trip() {
        let m = manifest_for("now_ms", "test-now_ms");
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let out = invoke_proc(m, b"", None).await.unwrap();
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        assert!(matches!(out.outcome, InvokeOutcome::Success));
        assert_eq!(out.response.len(), 8);
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&out.response);
        let plugin_now = i64::from_le_bytes(buf);
        // Process startup is slower than WASM; allow a generous window.
        assert!(
            plugin_now >= before - 1000 && plugin_now <= after + 1000,
            "plugin now {plugin_now} outside [{before}, {after}]"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn storage_round_trip_with_capability() {
        let mut m = manifest_for("storage_round_trip", "test-storage_round_trip");
        m.capabilities.storage_prefix = Some("".to_string());
        let core = crate::test_utils::new_unseal_test_bastion_vault("plugin-process-storage")
            .await
            .1;
        let out = invoke_proc(m, b"hello-process-storage", Some(core)).await.unwrap();
        assert!(matches!(out.outcome, InvokeOutcome::Success));
        assert_eq!(out.response, b"hello-process-storage");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn storage_forbidden_without_capability() {
        // No storage_prefix → host returns "forbidden" → plugin's
        // unwrap of the reply panics → child exits before sending
        // `done`. The runtime surfaces this as UnexpectedExit.
        let m = manifest_for("storage_round_trip", "test-storage_round_trip");
        let core = crate::test_utils::new_unseal_test_bastion_vault(
            "plugin-process-storage-forbidden",
        )
        .await
        .1;
        let result = invoke_proc(m, b"x", Some(core)).await;
        match result {
            Err(ProcessRuntimeError::UnexpectedExit(_))
            | Err(ProcessRuntimeError::Protocol(_)) => {}
            other => panic!("expected UnexpectedExit or Protocol, got {other:?}"),
        }
    }
}
