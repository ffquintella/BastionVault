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
    kernel_api::namespace::{NamespaceRef, NamespaceRegistry},
    logical::Request,
    mount::MountsRouter,
};

use super::{ns_assignment, quota, token_binding, NamespaceModule};

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

/// Publish the namespace module as the vault's namespace registry.
pub fn register(module: Arc<NamespaceModule>, services: &crate::kernel_api::KernelServices) {
    services.set_namespaces(module);
}
