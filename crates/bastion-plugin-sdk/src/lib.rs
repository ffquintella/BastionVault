//! BastionVault plugin SDK.
//!
//! Provides a [`Plugin`] trait, a [`Host`] handle that wraps the
//! capability-gated host imports, and a [`register!`] macro that emits
//! the WASM ABI exports (`bv_run` + `bv_alloc` + linear `memory`) so
//! plugin authors can write a few dozen lines of Rust and end up with
//! a deployable `.wasm` plugin.
//!
//! # Example plugin
//!
//! ```ignore
//! use bastion_plugin_sdk::{register, Host, LogLevel, Plugin, Request, Response};
//!
//! struct Echo;
//!
//! impl Plugin for Echo {
//!     fn handle(req: Request<'_>, host: &Host) -> Response {
//!         host.log(LogLevel::Info, "echo got bytes");
//!         Response::ok(req.input().to_vec())
//!     }
//! }
//!
//! register!(Echo);
//! ```
//!
//! Build with:
//!
//! ```text
//! cargo build --release --target wasm32-wasip1 -p my-plugin
//! ```
//!
//! And register the resulting `.wasm` via `POST /v1/sys/plugins`.
//!
//! # Capability-gated host calls
//!
//! [`Host`] exposes calls that map 1:1 to the imports declared by the
//! BastionVault wasmtime runtime ([`crate::plugins::runtime`] in the
//! main `bastion_vault` crate). Each call returns either bytes or a
//! [`HostError`] describing why the host refused — typically because
//! the manifest didn't declare the capability the call needs.

// `no_std` only on real wasm builds. On the host (and in `host_test`
// mode, and during `cargo test`) we want `std` so the test stubs can
// use `std::sync::Mutex` without pulling in a no-std mutex crate.
#![cfg_attr(all(target_arch = "wasm32", not(feature = "host_test")), no_std)]
extern crate alloc;

use alloc::vec::Vec;

mod host;
pub use host::{Host, HostError, LogLevel};

#[cfg(feature = "host_test")]
pub use host::test_support;

/// A request handed to a plugin's [`Plugin::handle`]. Wraps the input
/// bytes the host wrote into linear memory before calling `bv_run`.
#[derive(Debug)]
pub struct Request<'a> {
    input: &'a [u8],
}

impl<'a> Request<'a> {
    /// Construct a request from raw input bytes. Plugin authors do not
    /// normally call this directly — the [`register!`] macro builds the
    /// request from the `bv_run` arguments.
    pub fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    /// Raw input bytes the host wrote into the plugin's linear memory.
    /// What they mean is up to the plugin's contract with its caller.
    pub fn input(&self) -> &'a [u8] {
        self.input
    }

    #[cfg(feature = "json")]
    /// Convenience: parse the input as JSON. Fails if the input isn't
    /// valid JSON for `T`. Available with the `json` feature.
    pub fn input_json<T: for<'de> serde::Deserialize<'de>>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(self.input)
    }
}

/// What a plugin's [`Plugin::handle`] returns. The bytes are the
/// response payload (advertised to the host via `bv.set_response`); the
/// status code is the value returned from `bv_run` (0 = success;
/// non-zero surfaces as `InvokeOutcome::PluginError(code)` on the host
/// side, with the response bytes still available).
#[derive(Debug, Clone)]
pub struct Response {
    pub bytes: Vec<u8>,
    pub status: i32,
}

impl Response {
    /// Succeed with `bytes` as the response.
    pub fn ok(bytes: Vec<u8>) -> Self {
        Self { bytes, status: 0 }
    }

    /// No-data success.
    pub fn ok_empty() -> Self {
        Self::ok(Vec::new())
    }

    /// Fail with the given non-zero status code; the response bytes are
    /// still copied back so the plugin can carry an error message in
    /// the body.
    pub fn err(status: i32, bytes: Vec<u8>) -> Self {
        let safe_status = if status == 0 { 1 } else { status };
        Self { bytes, status: safe_status }
    }

    #[cfg(feature = "json")]
    /// Convenience: serialise `value` as JSON for the response.
    /// Available with the `json` feature.
    pub fn ok_json<T: serde::Serialize>(value: &T) -> Result<Self, serde_json::Error> {
        Ok(Self::ok(serde_json::to_vec(value)?))
    }
}

/// The trait every plugin implements. The [`register!`] macro wires it
/// up to the WASM ABI; plugin authors only write the handler.
pub trait Plugin {
    fn handle(req: Request<'_>, host: &Host) -> Response;
}

// ── ABI exports + alloc ─────────────────────────────────────────────────────
//
// The `register!` macro emits `#[no_mangle] extern "C"` exports that
// route into a user's `Plugin` impl. We expose the supporting glue
// (alloc + dispatch) here so the macro stays small.

#[doc(hidden)]
pub mod abi {
    use super::{Host, Plugin, Request, Response};
    use alloc::vec::Vec;

    /// Allocate `len` bytes inside the plugin's linear memory and
    /// return the pointer. Exported as `bv_alloc` from the plugin
    /// crate. The host calls this before writing the input payload
    /// for `bv_run`.
    ///
    /// We leak the allocation on purpose: the wasmtime store frees the
    /// linear memory wholesale when the invocation returns, so the
    /// plugin doesn't need to free per-allocation. (And we couldn't
    /// safely free anyway — the host writes into the buffer after we
    /// return the pointer; reclaiming would race with that write.)
    pub fn bv_alloc_impl(len: i32) -> i32 {
        if len < 0 {
            return 0;
        }
        let mut v: Vec<u8> = Vec::with_capacity(len as usize);
        // SAFETY: we set len to the requested capacity; the host fills
        // it before any read. Out of bounds is the host's bug, not the
        // plugin's.
        unsafe {
            v.set_len(len as usize);
        }
        let ptr = v.as_ptr() as i32;
        core::mem::forget(v);
        ptr
    }

    /// Build a `Request`, run the user's handler, advertise the
    /// response back to the host. Exported as `bv_run` from the plugin
    /// crate.
    ///
    /// # Safety
    ///
    /// `ptr` and `len` come from the host and describe a region inside
    /// the plugin's linear memory. The host has just written `len`
    /// bytes there via the `bv_alloc`-returned pointer, so the slice
    /// is valid for the duration of the call.
    pub fn bv_run_impl<P: Plugin>(ptr: i32, len: i32) -> i32 {
        let input: &[u8] = if ptr <= 0 || len <= 0 {
            &[]
        } else {
            // SAFETY: the host's contract is that bytes [ptr, ptr+len)
            // are initialised and not aliased by anything else for the
            // duration of `bv_run`.
            unsafe { core::slice::from_raw_parts(ptr as usize as *const u8, len as usize) }
        };
        let req = Request::new(input);
        let host = Host::new();
        let resp: Response = P::handle(req, &host);
        let _ = host.set_response(&resp.bytes);
        resp.status
    }

    // Re-export for the macro so `register!` can name them without
    // requiring the user to `use` anything.
    pub use bv_alloc_impl as alloc;
    pub use bv_run_impl as run;
}

/// Wire a [`Plugin`] impl up to the WASM ABI.
///
/// The macro emits two `#[no_mangle] pub extern "C"` exports:
/// `bv_alloc(len) -> ptr` and `bv_run(input_ptr, input_len) -> status`.
/// On non-wasm targets (and in `host_test` mode) the macro is a no-op
/// — the user's `Plugin` impl is still callable from regular Rust code
/// for unit testing.
///
/// Usage:
/// ```ignore
/// register!(MyPlugin);
/// ```
#[macro_export]
macro_rules! register {
    ($plugin:ty) => {
        #[cfg(all(target_arch = "wasm32", not(feature = "host_test")))]
        #[no_mangle]
        pub extern "C" fn bv_alloc(len: i32) -> i32 {
            $crate::abi::alloc(len)
        }

        #[cfg(all(target_arch = "wasm32", not(feature = "host_test")))]
        #[no_mangle]
        pub extern "C" fn bv_run(ptr: i32, len: i32) -> i32 {
            $crate::abi::run::<$plugin>(ptr, len)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo;
    impl Plugin for Echo {
        fn handle(req: Request<'_>, _host: &Host) -> Response {
            Response::ok(req.input().to_vec())
        }
    }

    /// Direct handler test — the natural way for plugin authors to
    /// unit-test their `Plugin::handle` impl. Does not exercise the
    /// `bv_alloc` / `bv_run` ABI shims because the i32-pointer ABI is
    /// only meaningful on `wasm32` (host-side `usize` is 64 bits and
    /// the cast back to `*mut u8` would truncate). The full ABI is
    /// covered end-to-end by the `crate::plugins::runtime` tests in
    /// the main `bastion_vault` crate, which run a real wasmtime
    /// instance.
    #[cfg(feature = "host_test")]
    #[test]
    fn handler_round_trip() {
        host::test_support::reset();
        let req = Request::new(b"hello bastion plugin");
        let host = Host::new();
        let resp = Echo::handle(req, &host);
        assert_eq!(resp.status, 0);
        assert_eq!(resp.bytes, b"hello bastion plugin");

        // Echo writes its response back via host.set_response (no — it
        // returns it). The test_support::take_response slot is empty
        // because the dispatcher (which calls set_response) only runs
        // inside `abi::bv_run_impl`. This is the right behaviour: the
        // plugin author tests the handler in isolation; the ABI glue
        // is tested by the host's runtime crate.
        assert!(host::test_support::take_response().is_none());
    }

    #[test]
    fn response_err_normalises_zero_status() {
        let r = Response::err(0, b"failure".to_vec());
        assert_eq!(r.status, 1);
        assert_eq!(r.bytes, b"failure");
    }

    #[cfg(feature = "host_test")]
    #[test]
    #[serial_test::serial]
    fn host_log_records_lines() {
        host::test_support::reset();
        let host = Host::new();
        host.log(LogLevel::Info, "hello from a plugin");
        host.log(LogLevel::Warn, "warning text");
        let lines = host::test_support::log_lines();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].0, LogLevel::Info as i32);
        assert_eq!(&lines[0].1, b"hello from a plugin");
        assert_eq!(lines[1].0, LogLevel::Warn as i32);
    }

    #[cfg(feature = "host_test")]
    #[test]
    #[serial_test::serial]
    fn host_storage_round_trip() {
        host::test_support::reset();
        let host = Host::new();
        // Pre-population is a test-helper that writes directly into
        // the stub map — same as the host backend would have.
        host::test_support::put(b"k1", b"v1");
        let got = host.storage_get("k1").unwrap();
        assert_eq!(got, b"v1");

        host.storage_put("k2", b"v2").unwrap();
        host.storage_put("k3", b"v3").unwrap();
        let mut keys = host.storage_list("k").unwrap();
        keys.sort();
        assert_eq!(keys, alloc::vec!["1", "2", "3"]);

        host.storage_delete("k2").unwrap();
        let err = host.storage_get("k2").unwrap_err();
        assert_eq!(err, HostError::NotFound);
    }

    #[cfg(feature = "host_test")]
    #[test]
    #[serial_test::serial]
    fn host_storage_forbidden_when_no_state() {
        host::test_support::reset();
        let host = Host::new();
        // No `put` calls yet → stub returns -2 from storage_get to
        // mimic the runtime's `storage_prefix`-not-declared rejection.
        let err = host.storage_get("anything").unwrap_err();
        assert_eq!(err, HostError::Forbidden);
    }

    #[cfg(feature = "host_test")]
    #[test]
    #[serial_test::serial]
    fn host_audit_captures_payload() {
        host::test_support::reset();
        let host = Host::new();
        host.audit_emit(b"{\"event\":\"refreshed\"}").unwrap();
        let events = host::test_support::audit_events();
        assert_eq!(events.len(), 1);
        assert_eq!(&events[0], b"{\"event\":\"refreshed\"}");
    }

    #[cfg(feature = "host_test")]
    #[test]
    #[serial_test::serial]
    fn host_config_get_round_trip() {
        host::test_support::reset();
        host::test_support::set_config("endpoint", "https://api.example/");
        host::test_support::set_config("timeout_ms", "1500");
        host::test_support::set_config("secure", "true");
        let host = Host::new();
        assert_eq!(host.config_get("endpoint").as_deref(), Some("https://api.example/"));
        assert_eq!(host.config_get_i64("timeout_ms"), Some(1500));
        assert_eq!(host.config_get_bool("secure"), Some(true));
        assert_eq!(host.config_get("not-set"), None);
        assert_eq!(host.config_get_i64("not-set"), None);
        assert_eq!(host.config_get_bool("endpoint"), None);
    }

    #[cfg(feature = "host_test")]
    #[test]
    #[serial_test::serial]
    fn host_now_unix_ms_real_then_mocked() {
        host::test_support::reset();
        let host = Host::new();

        // No mock set → returns the real wall-clock, sandwiched by the
        // host's own `SystemTime::now` calls.
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let now = host.now_unix_ms();
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        assert!(now >= before && now <= after);

        // With a mock set, the wrapper returns it verbatim — the
        // pattern plugin authors use to test TOTP-window logic.
        host::test_support::set_now_ms(Some(1_700_000_000_000));
        assert_eq!(host.now_unix_ms(), 1_700_000_000_000);
        host::test_support::set_now_ms(None);
    }
}
