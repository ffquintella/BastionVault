//! The WASM runtime's plugin side (`wasm32`, feature `wasm`): the
//! `bv.dynamic_*(in_ptr, in_len, out_ptr, out_max) -> i32` imports the host
//! registers (`src/plugins/runtime.rs`), storage through the base SDK, and
//! [`run`], which the [`crate::dynamic_module!`] macro calls from `bv_run`.

use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use bastion_plugin_sdk::{Host, HostError, LogLevel, Response};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::{
    backend::DynamicCredentialBackend,
    dispatch::{dispatch, Reply},
    host::{DynamicMethod, HostCalls},
    DynamicError,
};

mod raw {
    #[link(wasm_import_module = "bv")]
    extern "C" {
        pub fn dynamic_lease_register(in_ptr: i32, in_len: i32, out_ptr: i32, out_max: i32) -> i32;
        pub fn dynamic_audit_emit(in_ptr: i32, in_len: i32, out_ptr: i32, out_max: i32) -> i32;
        pub fn dynamic_pool_checkout(in_ptr: i32, in_len: i32, out_ptr: i32, out_max: i32) -> i32;
    }
}

/// Reply buffer per call. A call is never retried on "buffer too small"
/// (`-3`): the host acted before it wrote the reply, and a retry would
/// register a second lease or take a second pool slot. A pool grant can
/// carry an operator CA bundle, hence its larger buffer.
fn reply_capacity(method: DynamicMethod) -> usize {
    match method {
        DynamicMethod::PoolCheckout => 1 << 20,
        DynamicMethod::LeaseRegister | DynamicMethod::AuditEmit => 4096,
    }
}

fn call_import(method: DynamicMethod, input: &[u8], out: &mut [u8]) -> i32 {
    let (ip, il, op, om) = (input.as_ptr() as i32, input.len() as i32, out.as_mut_ptr() as i32, out.len() as i32);
    // SAFETY: FFI into the host's `bv.dynamic_*` imports. Both pointers are
    // into buffers this function borrows for the duration of the call; the
    // host reads at most `il` bytes and writes at most `om` bytes.
    unsafe {
        match method {
            DynamicMethod::LeaseRegister => raw::dynamic_lease_register(ip, il, op, om),
            DynamicMethod::AuditEmit => raw::dynamic_audit_emit(ip, il, op, om),
            DynamicMethod::PoolCheckout => raw::dynamic_pool_checkout(ip, il, op, om),
        }
    }
}

fn storage_error(op: &str, e: HostError) -> DynamicError {
    match e {
        HostError::Forbidden => DynamicError::Unavailable(format!("{op}: storage is not declared in the manifest")),
        HostError::NotFound => DynamicError::NotFound(op.to_string()),
        HostError::Internal => DynamicError::Unavailable(format!("{op}: host storage error")),
    }
}

/// [`HostCalls`] over the `bv.*` imports.
pub struct WasmHost {
    host: Host,
}

impl WasmHost {
    pub fn new() -> Self {
        Self { host: Host::new() }
    }
}

impl Default for WasmHost {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait(?Send)]
impl HostCalls for WasmHost {
    async fn dynamic_call(&mut self, method: DynamicMethod, mut params: Value) -> Result<Value, DynamicError> {
        // A host execution's params carry the connection's root secret.
        let input = serde_json::to_vec(&params).map(Zeroizing::new);
        crate::secret::wipe_value(&mut params);
        let input = input.map_err(|e| DynamicError::invalid(e.to_string()))?;
        let mut out = vec![0u8; reply_capacity(method)];
        let rc = call_import(method, &input, &mut out);
        if rc < 0 {
            return Err(DynamicError::from_wasm_code(method.name(), rc));
        }
        out.truncate(rc as usize);
        serde_json::from_slice(&out)
            .map_err(|_| DynamicError::Protocol(format!("{}: reply is not JSON", method.name())))
    }

    async fn storage_get(&mut self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, DynamicError> {
        match self.host.storage_get(key) {
            Ok(v) => Ok(Some(Zeroizing::new(v))),
            Err(HostError::NotFound) => Ok(None),
            Err(e) => Err(storage_error("storage_get", e)),
        }
    }

    async fn storage_put(&mut self, key: &str, value: &[u8]) -> Result<(), DynamicError> {
        self.host.storage_put(key, value).map_err(|e| storage_error("storage_put", e))
    }

    async fn storage_delete(&mut self, key: &str) -> Result<(), DynamicError> {
        self.host.storage_delete(key).map_err(|e| storage_error("storage_delete", e))
    }

    async fn storage_list(&mut self, prefix: &str) -> Result<Vec<String>, DynamicError> {
        self.host.storage_list(prefix).map_err(|e| storage_error("storage_list", e))
    }
}

/// Polls a future that never waits on anything but the host's synchronous
/// imports. A backend that awaits real I/O cannot run in WASM: it stays
/// pending, and the call fails instead of spinning forever.
pub fn block_on<F: Future>(fut: F) -> Option<F::Output> {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..64 {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return Some(v);
        }
    }
    None
}

/// Serve one `bv_run` call. Diagnostics go to `bv.log` at WARN.
pub fn run<B: DynamicCredentialBackend + ?Sized>(backend: &B, input: &[u8]) -> Response {
    let log = Host::new();
    let mut diag = |line: &str| log.log(LogLevel::Warn, line);
    let mut host = WasmHost::new();
    let reply = block_on(dispatch(backend, &mut host, input, &mut diag)).unwrap_or_else(|| {
        let e = DynamicError::Protocol("the backend awaited I/O the WASM runtime cannot provide".into());
        Reply::error(&e, &[])
    });
    Response { bytes: reply.body.to_vec(), status: reply.status }
}
