//! Seal reaches plugins (features/sql-browser.md §6.7). The kernel calls
//! every module's `cleanup` on seal, so the plugin runtime registers one
//! that tells each multiplexed child to close its sessions and zeroize what
//! it holds; a child that does not acknowledge in time is killed.

use std::{any::Any, sync::Arc, time::Duration};

use super::process_mux::{LifecycleEvent, LIFECYCLE_DEADLINE};
use crate::{errors::RvError, kernel_api::VaultCtx, modules::Module};

/// The plugin runtime's seal hook. Not an engine: it mounts nothing.
pub struct PluginLifecycleModule {
    deadline: Duration,
}

impl PluginLifecycleModule {
    pub const NAME: &'static str = "plugin-lifecycle";

    pub fn new() -> Self {
        Self { deadline: LIFECYCLE_DEADLINE }
    }

    #[cfg(test)]
    pub(crate) fn with_deadline(deadline: Duration) -> Self {
        Self { deadline }
    }
}

impl Default for PluginLifecycleModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for PluginLifecycleModule {
    fn name(&self) -> String {
        Self::NAME.to_string()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    /// Called on seal, synchronously, before the barrier closes. The
    /// teardown is asynchronous; it runs on the runtime and finishes within
    /// the deadline whether or not a child cooperates.
    fn cleanup(&self, _core: &dyn VaultCtx) -> Result<(), RvError> {
        let deadline = self.deadline;
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                rt.spawn(async move {
                    super::process_supervisor::lifecycle_all(LifecycleEvent::Seal, deadline).await;
                });
            }
            Err(_) => log::warn!(target: "plugin", "seal: no async runtime; plugin sessions were not notified"),
        }
        Ok(())
    }
}
