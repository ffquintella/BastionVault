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
pub mod config;
pub mod grants;
pub mod kernel_service;
pub mod logical_backend;
pub mod manifest;
pub mod net_gate;
pub mod net_http;
pub mod metrics;
pub mod module_cache;
pub mod process_runtime;
pub mod process_supervisor;
pub mod quarantine;
pub mod reload_lock;
pub mod runtime;
pub mod verifier;

pub use catalog::{PluginCatalog, PluginRecord, PLUGIN_PREFIX};
pub use config::ConfigStore;
pub use kernel_service::PluginRuntimeHost;
pub use logical_backend::{
    factory_for as plugin_logical_backend_factory, invoke_active_plugin, PluginLogicalBackend,
};
pub use manifest::{ConfigField, ConfigFieldKind, PluginManifest, RuntimeKind};
pub use module_cache::ModuleCache;
pub use process_runtime::{
    ensure_runtime_dir, plugin_runtime_dir, set_plugin_runtime_dir, ProcessRuntime,
    ProcessRuntimeError, DEFAULT_INVOKE_TIMEOUT,
};
pub use runtime::{InvokeOutput, InvokeOutcome, RuntimeError, WasmRuntime, DEFAULT_FUEL, DEFAULT_MEMORY_BYTES};

/// Mount type-prefix that triggers the [`PluginLogicalBackend`] path.
/// A `plugin:<name>` mount type resolves to a backend bound to that plugin.
pub const PLUGIN_MOUNT_PREFIX: &str = "plugin:";

/// Teach the mount table how to resolve `plugin:<name>` mount types.
///
/// The mount table used to strip [`PLUGIN_MOUNT_PREFIX`] and call
/// [`plugin_logical_backend_factory`] itself, which made `src/mount.rs` depend
/// on this runtime. Registration inverts that edge: the runtime is the side
/// that knows about plugins, so it is the side that speaks up.
///
/// Called from the assembly layer (`BastionVault::new`) rather than at mount
/// time, and idempotent — see [`crate::mount::set_dynamic_backend_resolver`].
///
/// Catalog lookup stays deferred inside the returned factory, so registration
/// order still does not matter as long as the plugin exists when the mount is
/// actually used.
pub fn register_mount_resolver() {
    crate::mount::set_dynamic_backend_resolver(std::sync::Arc::new(|logical_type: &str| {
        let name = logical_type.strip_prefix(PLUGIN_MOUNT_PREFIX)?;
        if name.is_empty() {
            return None;
        }
        Some(plugin_logical_backend_factory(name.to_string()))
    }));
}
