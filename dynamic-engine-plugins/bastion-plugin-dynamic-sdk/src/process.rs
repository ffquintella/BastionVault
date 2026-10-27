//! The process runtime's plugin side: line-delimited JSON over stdio, the
//! protocol `src/plugins/process_runtime.rs` (single-shot) and
//! `src/plugins/process_supervisor.rs` (long-lived) drive. The first line
//! tells them apart: a single-shot `init` carries `token` and `input`, a
//! long-lived one only `plugin_name` and is answered with `hello`.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use zeroize::Zeroizing;

use crate::{
    backend::DynamicCredentialBackend,
    dispatch::dispatch,
    host::{DynamicMethod, HostCalls},
    DynamicError,
};

/// The env var carrying the bootstrap token (cleared environment otherwise).
pub const BOOTSTRAP_TOKEN_ENV: &str = "BV_PLUGIN_BOOTSTRAP_TOKEN";

/// Why the loop stopped before answering.
#[derive(Debug)]
pub enum ProcessError {
    Io(std::io::Error),
    /// The host's first line did not carry the bootstrap token we were given.
    Bootstrap,
    Protocol(&'static str),
}

impl From<std::io::Error> for ProcessError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl ProcessError {
    /// The exit code `main` ends with (the host reports it on a crash).
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Io(_) => 91,
            Self::Bootstrap => 92,
            Self::Protocol(_) => 93,
        }
    }
}

async fn write_line<W: AsyncWrite + Unpin>(writer: &mut W, msg: &Value) -> std::io::Result<()> {
    let mut line = Zeroizing::new(serde_json::to_vec(msg)?);
    line.push(b'\n');
    writer.write_all(&line).await?;
    writer.flush().await
}

/// Read one non-empty line; `None` at end of input.
async fn read_message<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Option<Value>, ProcessError> {
    loop {
        let mut line = Zeroizing::new(String::new());
        if reader.read_line(&mut line).await? == 0 {
            return Ok(None);
        }
        if line.trim().is_empty() {
            continue;
        }
        return serde_json::from_str(line.trim())
            .map(Some)
            .map_err(|_| ProcessError::Protocol("host message is not JSON"));
    }
}

/// [`HostCalls`] over the stdio JSON-RPC: `host_call` out, the reply with
/// the same `id` back. The server tags errors `host_reply_error` (the
/// testkit `host_reply`); both are read by `id` and an `error` field.
pub struct StdioHost<'a, R, W> {
    reader: &'a mut R,
    writer: &'a mut W,
    next_id: &'a mut u64,
}

impl<'a, R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin> StdioHost<'a, R, W> {
    pub fn new(reader: &'a mut R, writer: &'a mut W, next_id: &'a mut u64) -> Self {
        Self { reader, writer, next_id }
    }

    async fn call(&mut self, method: &'static str, params: Value) -> Result<Value, DynamicError> {
        *self.next_id += 1;
        let id = *self.next_id;
        let msg = json!({ "type": "host_call", "id": id, "method": method, "params": params });
        write_line(self.writer, &msg).await.map_err(|e| DynamicError::Unavailable(format!("{method}: {e}")))?;
        loop {
            let reply = match read_message(self.reader).await {
                Ok(Some(v)) => v,
                Ok(None) => return Err(DynamicError::Unavailable(format!("{method}: the host closed stdin"))),
                Err(_) => return Err(DynamicError::Protocol(format!("{method}: unreadable host reply"))),
            };
            let kind = reply.get("type").and_then(Value::as_str).unwrap_or("");
            if !matches!(kind, "host_reply" | "host_reply_error") {
                return Err(DynamicError::Protocol(format!("{method}: expected a host reply, got `{kind}`")));
            }
            if reply.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(err) = reply.get("error").and_then(Value::as_str) {
                return Err(DynamicError::from_process_reply(method, err));
            }
            return Ok(reply.get("result").cloned().unwrap_or(Value::Null));
        }
    }
}

#[async_trait::async_trait(?Send)]
impl<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin> HostCalls for StdioHost<'_, R, W> {
    async fn dynamic_call(&mut self, method: DynamicMethod, params: Value) -> Result<Value, DynamicError> {
        self.call(method.name(), params).await
    }

    async fn storage_get(&mut self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, DynamicError> {
        match self.call("storage_get", json!({ "key": key })).await {
            Ok(v) => {
                let b64 = v.get("value_b64").and_then(Value::as_str).unwrap_or("");
                let bytes =
                    B64.decode(b64).map_err(|_| DynamicError::Protocol("storage_get: value not base64".into()))?;
                Ok(Some(Zeroizing::new(bytes)))
            }
            Err(DynamicError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn storage_put(&mut self, key: &str, value: &[u8]) -> Result<(), DynamicError> {
        let encoded = Zeroizing::new(B64.encode(value));
        self.call("storage_put", json!({ "key": key, "value_b64": encoded.as_str() })).await.map(|_| ())
    }

    async fn storage_delete(&mut self, key: &str) -> Result<(), DynamicError> {
        self.call("storage_delete", json!({ "key": key })).await.map(|_| ())
    }

    async fn storage_list(&mut self, prefix: &str) -> Result<Vec<String>, DynamicError> {
        let v = self.call("storage_list", json!({ "prefix": prefix })).await?;
        let keys = v.get("keys").and_then(Value::as_array).cloned().unwrap_or_default();
        Ok(keys.into_iter().filter_map(|k| k.as_str().map(str::to_string)).collect())
    }
}

fn decode_input(msg: &Value) -> Result<Zeroizing<Vec<u8>>, ProcessError> {
    let b64 = msg.get("input").and_then(Value::as_str).unwrap_or("");
    B64.decode(b64).map(Zeroizing::new).map_err(|_| ProcessError::Protocol("input is not base64"))
}

/// Serve the host on `reader`/`writer` until the call (single-shot) or the
/// stream (long-lived) ends. `token` is the bootstrap token from the env.
pub async fn serve<B, R, W>(
    backend: &B,
    reader: R,
    mut writer: W,
    token: &str,
    diag: &mut dyn FnMut(&str),
) -> Result<(), ProcessError>
where
    B: DynamicCredentialBackend + ?Sized,
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = reader;
    if token.is_empty() {
        return Err(ProcessError::Bootstrap);
    }
    let Some(mut init) = read_message(&mut reader).await? else {
        return Err(ProcessError::Protocol("stdin closed before init"));
    };
    if init.get("type").and_then(Value::as_str) != Some("init") {
        return Err(ProcessError::Protocol("first host message is not init"));
    }
    let mut next_id = 0u64;
    if init.get("input").is_some() {
        // Single-shot: the host echoes the token; refuse to act on a mismatch.
        let sent = init.get("token").and_then(Value::as_str).unwrap_or("");
        if !bool::from(sent.as_bytes().ct_eq(token.as_bytes())) {
            return Err(ProcessError::Bootstrap);
        }
        let input = decode_input(&init)?;
        crate::secret::wipe_value(&mut init);
        let reply = {
            let mut host = StdioHost::new(&mut reader, &mut writer, &mut next_id);
            dispatch(backend, &mut host, &input, diag).await
        };
        let data = Zeroizing::new(B64.encode(&reply.body));
        write_line(&mut writer, &json!({ "type": "set_response", "data_b64": data.as_str() })).await?;
        write_line(&mut writer, &json!({ "type": "done", "status": reply.status })).await?;
        return Ok(());
    }
    // Long-lived: prove we hold the token, then serve invokes until EOF.
    write_line(&mut writer, &json!({ "type": "hello", "token": token })).await?;
    while let Some(mut msg) = read_message(&mut reader).await? {
        if msg.get("type").and_then(Value::as_str) != Some("invoke") {
            return Err(ProcessError::Protocol("expected an invoke"));
        }
        let id = msg.get("id").and_then(Value::as_u64).ok_or(ProcessError::Protocol("invoke without id"))?;
        let input = decode_input(&msg)?;
        crate::secret::wipe_value(&mut msg);
        let reply = {
            let mut host = StdioHost::new(&mut reader, &mut writer, &mut next_id);
            dispatch(backend, &mut host, &input, diag).await
        };
        let data = Zeroizing::new(B64.encode(&reply.body));
        let done = json!({ "type": "invoke_done", "id": id, "status": reply.status, "data_b64": data.as_str() });
        write_line(&mut writer, &done).await?;
    }
    Ok(())
}

/// Entry point for a process plugin's `main`: serve stdin/stdout on a
/// single-threaded runtime and exit. Diagnostics go to stderr, which the
/// host forwards to its log.
pub fn run_main<B: DynamicCredentialBackend>(backend: B) -> ! {
    let token = Zeroizing::new(std::env::var(BOOTSTRAP_TOKEN_ENV).unwrap_or_default());
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(_) => {
            eprintln!("bv-dynamic: could not start the async runtime");
            std::process::exit(94);
        }
    };
    let mut diag = |line: &str| eprintln!("{line}");
    let result =
        runtime.block_on(serve(&backend, BufReader::new(tokio::io::stdin()), tokio::io::stdout(), &token, &mut diag));
    drop(runtime);
    match result {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            let what = match &e {
                ProcessError::Io(_) => "stdio failed",
                ProcessError::Bootstrap => "bootstrap token mismatch",
                ProcessError::Protocol(m) => *m,
            };
            eprintln!("bv-dynamic: {what}");
            std::process::exit(e.exit_code());
        }
    }
}
