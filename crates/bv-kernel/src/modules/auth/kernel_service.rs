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
    kernel_api::{
        auth::{AuthMountPrincipals, AuthMountRegistry, AuthMountView, TokenInfo, TokenService},
        leases::{LeaseRevocation, OwnedLeaseRevoker},
    },
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
        let store =
            self.token_store.load_full().ok_or_else(|| crate::bv_error_string!("token store not initialised"))?;
        store.revoke(token).await
    }

    async fn mint_root_token(&self) -> Result<String, RvError> {
        let store =
            self.token_store.load_full().ok_or_else(|| crate::bv_error_string!("token store not initialised"))?;
        Ok(store.root_token().await?.id)
    }

    fn set_auth_handlers(&self, handlers: Arc<Vec<Arc<dyn crate::handler::AuthHandler>>>) {
        AuthModule::set_auth_handlers(self, handlers)
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
        Ok(self.auth_mounts_of_type(logical_type)?.into_iter().map(|mount| mount.view).collect())
    }

    /// Every entry of the one auth table, tainted ones included: a mount
    /// being disabled or moved still holds its users until it is gone.
    fn auth_mounts_of_type(&self, logical_type: &str) -> Result<Vec<AuthMountView>, RvError> {
        let entries = self.mounts_router.entries.read()?;
        let mut mounts = Vec::new();
        for mount_entry in entries.values() {
            let entry = mount_entry.read()?;
            if entry.logical_type != logical_type {
                continue;
            }
            let barrier_path = format!("{}{}/", self.mounts_router.barrier_prefix, entry.uuid);
            let view = BarrierView::new(self.mounts_router.barrier.clone(), &barrier_path);
            mounts.push(AuthMountView { path: entry.path.clone(), view });
        }
        Ok(mounts)
    }

    fn set_auth_mount_principals(
        &self,
        logical_type: &str,
        principals: Option<Arc<dyn AuthMountPrincipals>>,
    ) -> Result<(), RvError> {
        let mut sources = self.principals.write()?;
        match principals {
            Some(source) => sources.insert(logical_type.to_string(), source),
            None => sources.remove(logical_type),
        };
        Ok(())
    }
}

/// The expiration manager is rebuilt on every unseal, after registration
/// ran, so the published service is the module and resolves it per call.
#[maybe_async::maybe_async]
impl OwnedLeaseRevoker for AuthModule {
    async fn revoke_owned_lease(&self, owner_mount: &str, lease_id: &str) -> Result<LeaseRevocation, RvError> {
        let expiration = self.expiration.load_full().ok_or(RvError::ErrBarrierSealed)?;
        expiration.revoke_owned_lease(owner_mount, lease_id).await
    }

    async fn check_lease_quota(&self, namespace_path: &str) -> Result<(), RvError> {
        let expiration = self.expiration.load_full().ok_or(RvError::ErrBarrierSealed)?;
        expiration.check_namespace_lease_quota(namespace_path).await
    }
}

/// Publish the auth module as its three services.
pub fn register(module: Arc<AuthModule>, services: &crate::kernel_api::KernelServices) {
    services.set_tokens(module.clone());
    services.set_lease_revoker(module.clone());
    services.set_auth_mounts(module);
}
