//! Host-call wrappers exposed via the [`Host`] handle.
//!
//! On `wasm32` targets these are thin shims around the `extern "C"`
//! imports the BastionVault wasmtime runtime registers under the `bv`
//! module. On non-wasm targets (and in `host_test` mode) they fall back
//! to thread-local stubs so plugin authors can `cargo test` against
//! their handlers without spinning up wasmtime.

use core::convert::From;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Trace = 1,
    Debug = 2,
    Info = 3,
    Warn = 4,
    Error = 5,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostError {
    /// Manifest didn't declare the capability this call needs (e.g. a
    /// `bv.storage_get` call when the plugin has no `storage_prefix`).
    Forbidden,
    /// Storage key didn't exist (only meaningful for `storage_get`).
    NotFound,
    /// Internal host error (storage backend unavailable, etc.).
    Internal,
}

impl From<i32> for HostError {
    fn from(code: i32) -> Self {
        match code {
            -1 => HostError::NotFound,
            -2 => HostError::Forbidden,
            _ => HostError::Internal,
        }
    }
}

/// Capability-gated handle to the host's services. Plugin authors get
/// one of these in `Plugin::handle`; calls fail with [`HostError`]
/// when the manifest didn't declare the relevant capability.
pub struct Host {
    _private: (),
}

impl Host {
    /// Construct a host handle. The [`crate::register!`] macro calls
    /// this from inside `bv_run`; plugin authors don't normally
    /// instantiate `Host` themselves.
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn log(&self, level: LogLevel, msg: &str) {
        bindings::log(level as i32, msg.as_bytes());
    }

    /// Advertise `bytes` to the host as the plugin's response payload.
    /// The host copies them out before tearing down the wasmtime store.
    pub fn set_response(&self, bytes: &[u8]) -> Result<(), HostError> {
        bindings::set_response(bytes);
        Ok(())
    }

    /// Read a value from barrier-encrypted storage at `key`. The key
    /// is interpreted relative to the plugin's declared `storage_prefix`
    /// — it must start with that prefix or the host returns
    /// [`HostError::Forbidden`].
    pub fn storage_get(&self, key: &str) -> Result<Vec<u8>, HostError> {
        // Loop with a growing buffer to handle the
        // `STORAGE_BUFFER_TOO_SMALL` (-3) case the runtime returns
        // when the value doesn't fit. Start at 1 KiB and double up to
        // 1 MiB; beyond that we treat the value as too large.
        let mut cap = 1024usize;
        loop {
            let mut buf = alloc::vec![0u8; cap];
            let rc = bindings::storage_get(key.as_bytes(), &mut buf);
            if rc >= 0 {
                buf.truncate(rc as usize);
                return Ok(buf);
            }
            if rc == -3 && cap < 1024 * 1024 {
                cap *= 2;
                continue;
            }
            return Err(HostError::from(rc));
        }
    }

    pub fn storage_put(&self, key: &str, value: &[u8]) -> Result<(), HostError> {
        let rc = bindings::storage_put(key.as_bytes(), value);
        if rc == 0 {
            Ok(())
        } else {
            Err(HostError::from(rc))
        }
    }

    pub fn storage_delete(&self, key: &str) -> Result<(), HostError> {
        let rc = bindings::storage_delete(key.as_bytes());
        if rc == 0 {
            Ok(())
        } else {
            Err(HostError::from(rc))
        }
    }

    pub fn storage_list(&self, prefix: &str) -> Result<Vec<String>, HostError> {
        let mut cap = 4096usize;
        loop {
            let mut buf = alloc::vec![0u8; cap];
            let rc = bindings::storage_list(prefix.as_bytes(), &mut buf);
            if rc >= 0 {
                buf.truncate(rc as usize);
                let s = core::str::from_utf8(&buf).map_err(|_| HostError::Internal)?;
                return Ok(s.split('\n').filter(|n| !n.is_empty()).map(|n| n.to_string()).collect());
            }
            if rc == -3 && cap < 1024 * 1024 {
                cap *= 2;
                continue;
            }
            return Err(HostError::from(rc));
        }
    }

    /// Emit an audit event with `payload` as the body. The host wraps
    /// the payload as `{"plugin_event": <payload>}` (parsed as JSON
    /// when possible so HMAC redaction handles string leaves).
    /// Capability-gated by `manifest.capabilities.audit_emit`.
    pub fn audit_emit(&self, payload: &[u8]) -> Result<(), HostError> {
        let rc = bindings::audit_emit(payload);
        if rc == 0 {
            Ok(())
        } else {
            Err(HostError::from(rc))
        }
    }

    /// Host wall-clock as milliseconds since the Unix epoch. Always
    /// available; not capability-gated. Useful for TOTP step counters,
    /// expiration checks, timestamping. Returns 0 only if the host's
    /// clock is set before 1970, which won't happen on a sane system.
    pub fn now_unix_ms(&self) -> i64 {
        bindings::now_unix_ms()
    }

    /// Read the operator-supplied value for a config key the plugin
    /// declared in `manifest.config_schema`. Returns `None` when the
    /// key is unset (the operator hasn't configured it yet, or the
    /// value was empty). The plugin should fall back to the default
    /// it declared in the schema.
    ///
    /// Convenience wrappers below decode well-known kinds.
    pub fn config_get(&self, key: &str) -> Option<String> {
        let mut cap = 256usize;
        loop {
            let mut buf = alloc::vec![0u8; cap];
            let rc = bindings::config_get(key.as_bytes(), &mut buf);
            if rc >= 0 {
                buf.truncate(rc as usize);
                return Some(String::from_utf8(buf).ok()?);
            }
            if rc == -3 && cap < 64 * 1024 {
                cap *= 2;
                continue;
            }
            return None;
        }
    }

    /// Convenience: parse a config field as `i64`. Returns `None` if
    /// unset or unparseable.
    pub fn config_get_i64(&self, key: &str) -> Option<i64> {
        self.config_get(key).and_then(|v| v.parse().ok())
    }

    /// Convenience: parse a config field as `bool`. Returns `None` if
    /// unset; treats `"true"` and `"false"` (case-sensitive) as
    /// true/false respectively.
    pub fn config_get_bool(&self, key: &str) -> Option<bool> {
        self.config_get(key).and_then(|v| match v.as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        })
    }
}

// ── Bindings ────────────────────────────────────────────────────────────────

#[cfg(all(target_arch = "wasm32", not(feature = "host_test")))]
mod bindings {
    // Raw extern imports declared by the host. The `bv` module name +
    // function names match what `crate::plugins::runtime::register_host_imports`
    // registers on the wasmtime side. Kept in a private inner `raw`
    // module so the safe `&[u8]`-taking wrappers below can share names
    // with the extern declarations without colliding.
    mod raw {
        #[link(wasm_import_module = "bv")]
        extern "C" {
            pub fn log(level: i32, ptr: i32, len: i32);
            pub fn set_response(ptr: i32, len: i32);
            pub fn storage_get(key_ptr: i32, key_len: i32, out_ptr: i32, out_max: i32) -> i32;
            pub fn storage_put(key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32) -> i32;
            pub fn storage_delete(key_ptr: i32, key_len: i32) -> i32;
            pub fn storage_list(prefix_ptr: i32, prefix_len: i32, out_ptr: i32, out_max: i32) -> i32;
            pub fn audit_emit(payload_ptr: i32, payload_len: i32) -> i32;
            pub fn now_unix_ms() -> i64;
            pub fn config_get(key_ptr: i32, key_len: i32, out_ptr: i32, out_max: i32) -> i32;
        }
    }

    pub fn log(level: i32, msg: &[u8]) {
        unsafe { raw::log(level, msg.as_ptr() as i32, msg.len() as i32); }
    }

    pub fn set_response(bytes: &[u8]) {
        unsafe { raw::set_response(bytes.as_ptr() as i32, bytes.len() as i32); }
    }

    pub fn storage_get(key: &[u8], out: &mut [u8]) -> i32 {
        unsafe {
            raw::storage_get(
                key.as_ptr() as i32,
                key.len() as i32,
                out.as_mut_ptr() as i32,
                out.len() as i32,
            )
        }
    }

    pub fn storage_put(key: &[u8], val: &[u8]) -> i32 {
        unsafe {
            raw::storage_put(
                key.as_ptr() as i32,
                key.len() as i32,
                val.as_ptr() as i32,
                val.len() as i32,
            )
        }
    }

    pub fn storage_delete(key: &[u8]) -> i32 {
        unsafe { raw::storage_delete(key.as_ptr() as i32, key.len() as i32) }
    }

    pub fn storage_list(prefix: &[u8], out: &mut [u8]) -> i32 {
        unsafe {
            raw::storage_list(
                prefix.as_ptr() as i32,
                prefix.len() as i32,
                out.as_mut_ptr() as i32,
                out.len() as i32,
            )
        }
    }

    pub fn audit_emit(payload: &[u8]) -> i32 {
        unsafe { raw::audit_emit(payload.as_ptr() as i32, payload.len() as i32) }
    }

    pub fn now_unix_ms() -> i64 {
        unsafe { raw::now_unix_ms() }
    }

    pub fn config_get(key: &[u8], out: &mut [u8]) -> i32 {
        unsafe {
            raw::config_get(
                key.as_ptr() as i32,
                key.len() as i32,
                out.as_mut_ptr() as i32,
                out.len() as i32,
            )
        }
    }

}

#[cfg(any(not(target_arch = "wasm32"), feature = "host_test"))]
mod bindings {
    //! Test stubs. Plugin authors who run `cargo test` against their
    //! plugin (in `host_test` mode or on the native host) get these
    //! in-memory mocks instead of real host imports.

    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use std::sync::Mutex;

    /// Per-test in-memory storage. Lives outside the `Host` struct so
    /// tests can pre-populate it before invoking the plugin.
    static STATE: Mutex<TestState> = Mutex::new(TestState::new_const());

    struct TestState {
        storage: Option<BTreeMap<Vec<u8>, Vec<u8>>>,
        response: Option<Vec<u8>>,
        log_lines: Option<Vec<(i32, Vec<u8>)>>,
        audit_events: Option<Vec<Vec<u8>>>,
        /// When set, `now_unix_ms` returns this value instead of the
        /// real wall-clock — lets plugin authors test deterministic
        /// time-dependent logic (e.g. TOTP step boundaries).
        mock_now_ms: Option<i64>,
        /// Operator-supplied config map for tests. Plugins call
        /// `host.config_get("key")`; tests pre-populate with
        /// `test_support::set_config(key, value)`.
        config: Option<BTreeMap<String, String>>,
    }

    impl TestState {
        const fn new_const() -> Self {
            Self {
                storage: None,
                response: None,
                log_lines: None,
                audit_events: None,
                mock_now_ms: None,
                config: None,
            }
        }

        fn storage_mut(&mut self) -> &mut BTreeMap<Vec<u8>, Vec<u8>> {
            self.storage.get_or_insert_with(BTreeMap::new)
        }

        fn log_lines_mut(&mut self) -> &mut Vec<(i32, Vec<u8>)> {
            self.log_lines.get_or_insert_with(Vec::new)
        }

        fn audit_events_mut(&mut self) -> &mut Vec<Vec<u8>> {
            self.audit_events.get_or_insert_with(Vec::new)
        }
    }

    pub fn log(level: i32, msg: &[u8]) {
        let mut s = STATE.lock().unwrap();
        s.log_lines_mut().push((level, msg.to_vec()));
    }

    pub fn set_response(bytes: &[u8]) {
        let mut s = STATE.lock().unwrap();
        s.response = Some(bytes.to_vec());
    }

    pub fn storage_get(key: &[u8], out: &mut [u8]) -> i32 {
        let s = STATE.lock().unwrap();
        let storage = match s.storage.as_ref() {
            Some(m) => m,
            None => return -2, // forbidden when no storage set up
        };
        match storage.get(key) {
            None => -1,
            Some(v) => {
                if v.len() > out.len() {
                    -3
                } else {
                    out[..v.len()].copy_from_slice(v);
                    v.len() as i32
                }
            }
        }
    }

    pub fn storage_put(key: &[u8], val: &[u8]) -> i32 {
        let mut s = STATE.lock().unwrap();
        s.storage_mut().insert(key.to_vec(), val.to_vec());
        0
    }

    pub fn storage_delete(key: &[u8]) -> i32 {
        let mut s = STATE.lock().unwrap();
        s.storage_mut().remove(key);
        0
    }

    pub fn storage_list(prefix: &[u8], out: &mut [u8]) -> i32 {
        let s = STATE.lock().unwrap();
        let storage = match s.storage.as_ref() {
            Some(m) => m,
            None => return -2,
        };
        let mut joined = Vec::new();
        let mut first = true;
        for k in storage.keys() {
            if k.starts_with(prefix) {
                if !first {
                    joined.push(b'\n');
                }
                first = false;
                joined.extend_from_slice(&k[prefix.len()..]);
            }
        }
        if joined.len() > out.len() {
            return -3;
        }
        out[..joined.len()].copy_from_slice(&joined);
        joined.len() as i32
    }

    pub fn audit_emit(payload: &[u8]) -> i32 {
        let mut s = STATE.lock().unwrap();
        s.audit_events_mut().push(payload.to_vec());
        0
    }

    pub fn now_unix_ms() -> i64 {
        let s = STATE.lock().unwrap();
        if let Some(mock) = s.mock_now_ms {
            return mock;
        }
        drop(s);
        // Fall through to the real wall-clock if no mock is set.
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    pub fn config_get(key: &[u8], out: &mut [u8]) -> i32 {
        let s = STATE.lock().unwrap();
        let key_str = match core::str::from_utf8(key) {
            Ok(s) => s,
            Err(_) => return -4,
        };
        let cfg = match s.config.as_ref() {
            Some(c) => c,
            None => return -1,
        };
        let v = match cfg.get(key_str) {
            Some(v) => v.as_bytes(),
            None => return -1,
        };
        if v.len() > out.len() {
            return -3;
        }
        out[..v.len()].copy_from_slice(v);
        v.len() as i32
    }

    /// Test helpers — exposed via `bastion_plugin_sdk::test_support`
    /// when the `host_test` feature is on.
    pub mod test_support {
        use super::STATE;
        use alloc::vec::Vec;

        pub fn reset() {
            let mut s = STATE.lock().unwrap();
            s.storage = None;
            s.response = None;
            s.log_lines = None;
            s.audit_events = None;
            s.mock_now_ms = None;
            s.config = None;
        }

        /// Pre-populate the config map a plugin will see via
        /// `Host::config_get`.
        pub fn set_config(key: &str, value: &str) {
            let mut s = STATE.lock().unwrap();
            s.config
                .get_or_insert_with(alloc::collections::BTreeMap::new)
                .insert(key.to_string(), value.to_string());
        }

        /// Pin `Host::now_unix_ms()` to a fixed value for the duration of
        /// the current test. Pass `None` to fall back to the real
        /// wall-clock.
        pub fn set_now_ms(value: Option<i64>) {
            let mut s = STATE.lock().unwrap();
            s.mock_now_ms = value;
        }

        pub fn put(key: &[u8], val: &[u8]) {
            let mut s = STATE.lock().unwrap();
            s.storage_mut().insert(key.to_vec(), val.to_vec());
        }

        pub fn take_response() -> Option<Vec<u8>> {
            let mut s = STATE.lock().unwrap();
            s.response.take()
        }

        pub fn log_lines() -> Vec<(i32, Vec<u8>)> {
            let s = STATE.lock().unwrap();
            s.log_lines.clone().unwrap_or_default()
        }

        pub fn audit_events() -> Vec<Vec<u8>> {
            let s = STATE.lock().unwrap();
            s.audit_events.clone().unwrap_or_default()
        }
    }
}

#[cfg(any(not(target_arch = "wasm32"), feature = "host_test"))]
pub use bindings::test_support;
