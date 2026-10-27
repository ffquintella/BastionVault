//! Dynamic-secrets plugin host (`features/dynamic-secrets.md`, T62).
//!
//! A thin specialisation of the generic plugin-as-mount bridge
//! ([`super::logical_backend`]): a `plugin:<name>` mount whose plugin has
//! `plugin_type = "secret/dynamic"` is served by [`backend::handle`], which
//! runs the plugin through the same runtimes, generates credentials and
//! expands statements in the host, and lets the lease manager own the lease.

pub mod backend;
pub mod cache;
pub mod host_calls;
pub mod pool;
pub mod session;
pub mod state;

#[cfg(test)]
pub(crate) mod mock;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;

pub use session::{DynamicSession, DynamicVerb};

use crate::kernel_api::VaultCtx;

/// Barrier prefix of a dynamic plugin's own storage (`storage_*` host calls):
/// one per mount, so two mounts of a plugin never share `config/` or
/// `roles/`. `None` outside a dynamic RPC, which then gets no storage.
pub fn plugin_data_root(plugin: &str, session: Option<&DynamicSession>) -> Option<String> {
    let mount_id = &session?.mount_id;
    let ok = !mount_id.is_empty() && mount_id.chars().all(|c| c.is_ascii_hexdigit());
    ok.then(|| format!("core/plugins/{plugin}/data/mounts/{mount_id}/"))
}

/// Write a `dynamic_secret` event: the `security` log line always, the audit
/// broker when a device is enabled. A broker failure is logged, not raised:
/// by the time an event is emitted the credential step it records happened.
pub(crate) async fn emit_event(core: Option<&dyn VaultCtx>, event: &bv_dynamic::audit::DynamicSecretEvent) {
    match core {
        Some(core) => {
            if let Err(e) = crate::kernel_api::mcp_events::emit(core, event, None).await {
                log::warn!("dynamic_secret event was not written to the audit broker: {e}");
            }
        }
        None => {
            let fields = crate::kernel_api::mcp_events::event_fields(event);
            log::info!(target: "security", "dynamic_secret {}", serde_json::Value::Object(fields));
        }
    }
}
