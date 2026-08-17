//! Namespaces / multi-tenancy module.
//!
//! A namespace is an addressable container that isolates a tenant's mounts,
//! policies, identities, tokens, audit devices, and quotas from every other
//! tenant in the same deployment. Namespaces nest under a parent and inherit
//! nothing automatically — the same blast-radius model Vault Enterprise uses.
//!
//! This module owns the namespace *registry* ([`store::NamespaceStore`]) and
//! the request → namespace *resolver* ([`router`]). The CRUD HTTP surface is
//! served by the system backend under `sys/namespaces/*` (reached via the
//! `v2/` API prefix) because `sys/` is the only mount that may host
//! deployment-wide control endpoints.
//!
//! See `features/namespaces-multitenancy.md` for the full design.
//!
//! ## Phase status
//! - Phase 1 (this module): namespace container, path↔UUID registry,
//!   request resolver, per-namespace mount-router registry, and the
//!   barrier re-rooting migration.
//! - Phases 2–4 add per-namespace policy/token/audit, per-namespace
//!   identity + cross-tenant linking, and quota enforcement + GUI.

use std::{any::Any, sync::Arc};

use arc_swap::ArcSwap;

use super::Module;
use crate::kernel_api::VaultCtx;
use crate::{core::Core, errors::RvError};

pub mod identity_link;
pub mod kernel_service;
pub mod migrate;
pub mod mount_registry;
pub mod ns_assignment;
pub mod policy_scope;
pub mod quota;
pub mod router;
pub mod store;
pub mod token_binding;

pub use identity_link::{IdentityLink, IdentityLinkMember, IdentityLinkStore};
pub use mount_registry::NamespaceMountRegistry;
pub use ns_assignment::{NsAssignment, NsAssignmentStore};
pub use router::ResolvedNamespace;
pub use store::{Namespace, NamespaceQuotas, NamespaceStore};

/// Logical module name; used for `module_manager.get_module`.
pub const NAMESPACE_MODULE_NAME: &str = "namespace";

pub struct NamespaceModule {
    pub name: String,
    pub core: Arc<Core>,
    pub store: ArcSwap<Option<Arc<NamespaceStore>>>,
    /// Per-namespace mount routers. Shared (cheap to clone) so the system
    /// backend and the request resolver see the same registered mounts.
    pub registry: Arc<NamespaceMountRegistry>,
    /// Cross-tenant identity links (Phase 3). Installed at unseal alongside
    /// the registry.
    pub link_store: ArcSwap<Option<Arc<IdentityLinkStore>>>,
    /// Per-namespace request-rate limiter (Phase 4 quota enforcement). Lives
    /// for the module's lifetime; buckets are created lazily per namespace.
    pub rate_limiter: quota::RateLimiter,
}

impl NamespaceModule {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            name: NAMESPACE_MODULE_NAME.to_string(),
            core,
            store: ArcSwap::new(Arc::new(None)),
            registry: Arc::new(NamespaceMountRegistry::new()),
            link_store: ArcSwap::new(Arc::new(None)),
            rate_limiter: quota::RateLimiter::new(),
        }
    }

    pub fn store(&self) -> Option<Arc<NamespaceStore>> {
        self.store.load().as_ref().clone()
    }

    pub fn link_store(&self) -> Option<Arc<IdentityLinkStore>> {
        self.link_store.load().as_ref().clone()
    }
}

#[maybe_async::maybe_async]
impl Module for NamespaceModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn register(self: Arc<Self>, services: &crate::kernel_api::KernelServices) {
        kernel_service::register(self, services);
    }

    async fn init(&self, _core: &dyn VaultCtx) -> Result<(), RvError> {
        let store = Arc::new(NamespaceStore::new(&self.core)?);
        // Mint (or read back) the implicit root namespace. This is the anchor
        // the re-rooting migration and the per-namespace router registry both
        // depend on, so it must succeed before either runs.
        store.ensure_root().await?;
        self.store.store(Arc::new(Some(store)));
        let link_store = Arc::new(IdentityLinkStore::new(&self.core)?);
        self.link_store.store(Arc::new(Some(link_store)));
        Ok(())
    }

    fn cleanup(&self, _core: &dyn VaultCtx) -> Result<(), RvError> {
        self.store.store(Arc::new(None));
        self.link_store.store(Arc::new(None));
        Ok(())
    }
}


