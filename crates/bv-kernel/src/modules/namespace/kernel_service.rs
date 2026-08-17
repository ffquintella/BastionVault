//! `NamespaceModule` as the vault's [`NamespaceRegistry`].
//!
//! The methods here were free functions in `token_binding`, `ns_assignment`,
//! `quota` and `policy_scope`, each taking a `&dyn VaultCtx` and each opening
//! with `core.module_manager().get_module::<NamespaceModule>(…)`. They are the
//! same code; what changed is that the module no longer has to find itself,
//! and — the point — an auth backend calling them no longer names it.
//!
//! [`NamespaceRef`] is the resolved answer, not the stored `Namespace`: uuid
//! and path are all a caller outside this module can act on. Parent links,
//! quotas and timestamps stay here.

use std::sync::Arc;

use crate::{
    errors::RvError,
    kernel_api::{
        namespace::{NamespaceRef, NamespaceRegistry},
        pipeline::{RequestPipeline, RerootActivation},
        VaultCtx,
    },
    logical::Request,
    mount::MountsRouter,
};

use super::{migrate, ns_assignment, quota, router, store::NamespaceStore, token_binding, NamespaceModule};

#[maybe_async::maybe_async]
impl NamespaceRegistry for NamespaceModule {
    async fn resolve(&self, raw: &str) -> Result<Option<NamespaceRef>, RvError> {
        let Some(store) = self.store() else {
            return Ok(None);
        };
        Ok(store
            .get_by_path(raw)
            .await?
            .map(|ns| NamespaceRef { uuid: ns.uuid, path: ns.path }))
    }

    async fn ensure_router(&self, uuid: &str, path: &str) -> Result<Arc<MountsRouter>, RvError> {
        self.registry.ensure_router(self.core.clone(), uuid, path).await
    }

    async fn resolve_login_namespace_for_principal(
        &self,
        req: &Request,
        mount: &str,
        name: &str,
    ) -> Result<(String, String), RvError> {
        token_binding::resolve_login_namespace_for_principal(&self.core, req, mount, name).await
    }

    async fn enforce_login_assignment(
        &self,
        mount: &str,
        name: &str,
        ns_path: &str,
    ) -> Result<(), RvError> {
        ns_assignment::enforce_login_assignment(&self.core, mount, name, ns_path).await
    }

    async fn check_entity_create(
        &self,
        mount: &str,
        name: &str,
        ns_path: &str,
    ) -> Result<(), RvError> {
        quota::check_entity_create(&self.core, mount, name, ns_path).await
    }

    async fn login_child_visible(&self, ns_path: &str) -> bool {
        token_binding::login_child_visible(&self.core, ns_path).await
    }

    async fn lease_quota_for_path(
        &self,
        req_path: &str,
    ) -> Result<Option<(String, u64)>, RvError> {
        let Some(store) = self.store() else {
            return Ok(None);
        };
        let resolved = store.resolve_request(None, req_path).await?;
        if resolved.namespace.is_root() {
            return Ok(None);
        }
        Ok(Some((resolved.namespace.path, resolved.namespace.quotas.max_leases)))
    }
}

/// The four per-request multi-tenancy steps `Core::handle_request` used to
/// call by name.
///
/// Each forwards to the free function that has always implemented it, with
/// this module's own `Arc<Core>` — the same value `Core` would have passed in,
/// since there is exactly one per server. Nothing about the steps changed;
/// what changed is that `Core` no longer names `modules::namespace`.
#[maybe_async::maybe_async]
impl RequestPipeline for NamespaceModule {
    async fn rewrite_request(&self, req: &mut Request) -> Result<(), RvError> {
        router::rewrite_request_for_namespace(&self.core, req).await
    }

    async fn enforce_token_binding(&self, req: &Request) -> Result<(), RvError> {
        token_binding::enforce_request_token_binding(&self.core, req).await
    }

    async fn enforce_request_rate(&self, req: &Request) -> Result<(), RvError> {
        quota::enforce_request_rate(&self.core, req).await
    }

    async fn enforce_write_storage_quota(&self, req: &Request) -> Result<(), RvError> {
        quota::enforce_write_storage_quota(&self.core, req).await
    }
}

/// The re-root migration, which runs before any module exists.
///
/// A unit struct rather than an impl on `NamespaceModule`: at the point
/// `post_unseal` calls this, `ModuleManager::setup` has not run, so there is
/// no module instance to have published itself. It takes the `&dyn VaultCtx`
/// the caller already has, which is all `NamespaceStore::new` and
/// `resolve_root_activation` ever needed.
pub struct NamespaceReroot;

#[maybe_async::maybe_async]
impl RerootActivation for NamespaceReroot {
    async fn resolve(&self, ctx: &dyn VaultCtx) -> Result<Option<String>, RvError> {
        let store = NamespaceStore::new(ctx)?;
        store.ensure_root().await?;
        migrate::resolve_root_activation(ctx, &store).await
    }
}

/// Publish the namespace module as the vault's namespace registry and
/// per-request pipeline.
pub fn register(module: Arc<NamespaceModule>, services: &crate::kernel_api::KernelServices) {
    services.set_namespaces(module.clone());
    services.set_request_pipeline(module);
}
