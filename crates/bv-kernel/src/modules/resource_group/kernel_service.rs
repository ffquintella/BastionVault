//! `ResourceGroupModule` as the vault's [`ResourceGroupIndex`].
//!
//! Pure forwarding. `prune_resource` and `rename_resource` return the affected
//! group names on the store; the two engine callers ignore them, so the trait
//! drops the value rather than making every caller write `let _ =`.

use std::sync::Arc;

use crate::{errors::RvError, kernel_api::resource_group::ResourceGroupIndex};

use super::{group_store::scope_of, ResourceGroupModule};

#[maybe_async::maybe_async]
impl ResourceGroupIndex for ResourceGroupModule {
    async fn prune_resource(&self, resource: &str, ns_path: Option<&str>) -> Result<(), RvError> {
        let Some(store) = self.store() else {
            return Ok(());
        };
        store.prune_resource(resource, &scope_of(ns_path)).await.map(|_| ())
    }

    async fn rename_resource(&self, old: &str, new: &str, ns_path: Option<&str>) -> Result<(), RvError> {
        let Some(store) = self.store() else {
            return Ok(());
        };
        store.rename_resource(old, new, &scope_of(ns_path)).await.map(|_| ())
    }

    async fn groups_for_resource(&self, resource: &str, ns_path: Option<&str>) -> Result<Vec<String>, RvError> {
        let Some(store) = self.store() else {
            return Ok(Vec::new());
        };
        store.groups_for_resource(resource, &scope_of(ns_path)).await
    }
}

/// Publish the resource-group module as the vault's asset-group index.
pub fn register(module: Arc<ResourceGroupModule>, services: &crate::kernel_api::KernelServices) {
    services.set_resource_groups(module);
}
