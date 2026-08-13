//! `AuthModule` as the vault's [`TokenService`] and [`AuthMountRegistry`].
//!
//! Two traits rather than one, because the consumers are unrelated: every
//! credential backend registers a mount, and exactly two callers look a token
//! up. Splitting them keeps a credential backend from being able to resolve
//! other people's tokens just because it needed to mount itself.
//!
//! [`TokenInfo`] is the readable half of `TokenEntry`. The parent link, use
//! counter, TTLs and creation time stay behind the boundary: they are the
//! token store's lifecycle state, and a caller that could read them would
//! sooner or later try to act on them.

use std::sync::Arc;

use crate::{
    errors::RvError,
    kernel_api::auth::{AuthMountRegistry, TokenInfo, TokenService},
    storage::barrier_view::BarrierView,
};

use super::AuthModule;

#[maybe_async::maybe_async]
impl TokenService for AuthModule {
    async fn lookup(&self, token: &str) -> Result<Option<TokenInfo>, RvError> {
        let Some(store) = self.token_store.load_full() else {
            // Sealed, or before `init`. Not an error: the caller's own
            // "unknown token" path is the right answer, and it is the
            // conservative one — an unknown token authorizes nothing.
            return Ok(None);
        };
        Ok(store.lookup(token).await?.map(|te| TokenInfo {
            display_name: te.display_name,
            policies: te.policies,
            meta: te.meta,
            path: te.path,
        }))
    }

    async fn revoke(&self, token: &str) -> Result<(), RvError> {
        let store = self
            .token_store
            .load_full()
            .ok_or_else(|| crate::bv_error_string!("token store not initialised"))?;
        store.revoke(token).await
    }
}

impl AuthMountRegistry for AuthModule {
    fn add_auth_backend(
        &self,
        logical_type: &str,
        backend: Arc<crate::core::LogicalBackendNewFunc>,
    ) -> Result<(), RvError> {
        self.mounts_router.add_backend(logical_type, backend)
    }

    fn delete_auth_backend(&self, logical_type: &str) -> Result<(), RvError> {
        self.mounts_router.delete_backend(logical_type)
    }

    fn auth_mount_views(&self, logical_type: &str) -> Result<Vec<BarrierView>, RvError> {
        let entries = self.mounts_router.entries.read()?;
        let mut views = Vec::new();
        for mount_entry in entries.values() {
            let entry = mount_entry.read()?;
            if entry.logical_type != logical_type {
                continue;
            }
            let barrier_path = format!("{}{}/", self.mounts_router.barrier_prefix, entry.uuid);
            views.push(BarrierView::new(self.mounts_router.barrier.clone(), &barrier_path));
        }
        Ok(views)
    }
}

/// Publish the auth module as both of its services.
pub fn register(module: Arc<AuthModule>, services: &crate::kernel_api::KernelServices) {
    services.set_tokens(module.clone());
    services.set_auth_mounts(module);
}
