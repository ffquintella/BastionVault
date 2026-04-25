//! Plugin system — Phase 1 substrate.
//!
//! Loads WebAssembly modules registered via `/v1/sys/plugins/catalog/*`
//! and invokes them through a small ABI. Plugins are sandboxed by
//! wasmtime: no filesystem, no network, no clocks beyond monotonic, no
//! environment variables. Fuel + memory limits enforced per-invocation.
//!
//! v1 host capabilities exposed to plugins (via wasmtime imports):
//!
//! - `bv_log(ptr, len)` — write a log line through the host's `log`
//!   facade (subject to the BastionVault log level).
//! - `bv_set_response(ptr, len)` — declare the byte range of the
//!   plugin's response in its linear memory; the host copies it out
//!   and returns it from the invoke endpoint.
//!
//! Out of scope for v1 (tracked in `features/plugin-system.md`):
//!
//! - Out-of-process runtime (`tonic` over UDS / Windows named pipes).
//! - ML-DSA signature verification (sha256 integrity is enforced; ML-DSA
//!   lands once the Transit engine is implementable).
//! - Storage / audit / crypto host capabilities.
//! - Hot reload, GUI, `bastion-plugin-sdk` crate, capability-as-mount.

pub mod catalog;
pub mod manifest;
pub mod runtime;

pub use catalog::{PluginCatalog, PluginRecord, PLUGIN_PREFIX};
pub use manifest::{PluginManifest, RuntimeKind};
pub use runtime::{InvokeOutput, InvokeOutcome, RuntimeError, WasmRuntime, DEFAULT_FUEL, DEFAULT_MEMORY_BYTES};
