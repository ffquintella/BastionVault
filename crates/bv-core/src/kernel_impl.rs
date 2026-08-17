//! `impl VaultCtx for Core` — the one place the kernel contract meets its
//! implementor.
//!
//! [`VaultCtx`](crate::kernel_api::VaultCtx) itself lives in `bv-kernel-api`,
//! below every engine in the crate graph. This impl cannot go with it: `Core`
//! is Tier 2 and `bv-kernel-api` must not depend on it — that is the cycle
//! Phase 2 cut. Implementing a foreign trait for a local type is exactly what
//! the orphan rule permits, so the impl stays here, in the crate that owns
//! `Core`.
//!
//! See roadmaps/workspace-decomposition.md § Phase 3.

use std::sync::{atomic::AtomicBool, Arc, Weak};

use crate::{
    audit::AuditBroker,
    cache::CacheConfig,
    core::Core,
    dos::DosGuard,
    errors::RvError,
    handler::{AuthHandler, Handler},
    kernel_api::{
        ctx::MountEntryHMACLevel, KernelServices, LogicalBackendNewFunc, VaultCtx,
    },
    logical::{Request, Response},
    mount::{MountsMonitor, MountsRouter},
    router::Router,
    stats::DashboardStats,
    storage::{barrier::SecurityBarrier, barrier_view::BarrierView, Backend as PhysicalBackend},
};

/// Delegates to `Core`'s existing inherent methods and fields, so runtime
/// behaviour is unchanged. If a method here does anything other than forward,
/// that is a bug in the abstraction.
#[maybe_async::maybe_async]
impl VaultCtx for Core {
    async fn handle_request(&self, req: &mut Request) -> Result<Option<Response>, RvError> {
        Core::handle_request(self, req).await
    }

    fn barrier(&self) -> Arc<dyn SecurityBarrier> {
        self.barrier.clone()
    }

    fn system_view(&self) -> Option<Arc<BarrierView>> {
        self.get_system_view()
    }

    fn hmac_key(&self) -> Vec<u8> {
        self.state.load().hmac_key.clone()
    }

    fn sealed(&self) -> bool {
        Core::sealed(self)
    }

    async fn inited(&self) -> Result<bool, RvError> {
        Core::inited(self).await
    }

    fn router(&self) -> Arc<Router> {
        self.router.clone()
    }

    fn mounts_router(&self) -> Arc<MountsRouter> {
        Core::mounts_router(self)
    }

    fn root_storage_prefix(&self) -> Arc<String> {
        self.root_storage_prefix.load_full()
    }

    fn add_logical_backend(&self, logical_type: &str, backend: Arc<LogicalBackendNewFunc>) -> Result<(), RvError> {
        Core::add_logical_backend(self, logical_type, backend)
    }

    fn delete_logical_backend(&self, logical_type: &str) -> Result<(), RvError> {
        Core::delete_logical_backend(self, logical_type)
    }

    fn add_handler(&self, handler: Arc<dyn Handler>) -> Result<(), RvError> {
        Core::add_handler(self, handler)
    }

    fn delete_handler(&self, handler: Arc<dyn Handler>) -> Result<(), RvError> {
        Core::delete_handler(self, handler)
    }

    fn add_auth_handler(&self, handler: Arc<dyn AuthHandler>) -> Result<(), RvError> {
        Core::add_auth_handler(self, handler)
    }

    fn delete_auth_handler(&self, handler: Arc<dyn AuthHandler>) -> Result<(), RvError> {
        Core::delete_auth_handler(self, handler)
    }

    fn mount_entry_hmac_level(&self) -> MountEntryHMACLevel {
        self.mount_entry_hmac_level
    }

    fn mounts_monitor(&self) -> Option<Arc<MountsMonitor>> {
        self.mounts_monitor.load_full()
    }

    fn kernel(&self) -> &KernelServices {
        &self.kernel_services
    }

    fn stats(&self) -> Arc<DashboardStats> {
        self.stats.clone()
    }

    fn audit_broker(&self) -> Option<Arc<AuditBroker>> {
        self.audit_broker.load_full()
    }

    fn dos_guard(&self) -> Arc<DosGuard> {
        self.dos_guard.clone()
    }

    fn approle_require_machine(&self) -> Arc<AtomicBool> {
        self.approle_require_machine.clone()
    }

    async fn set_approle_require_machine(&self, required: bool) -> Result<(), RvError> {
        Core::set_approle_require_machine(self, required).await
    }

    fn cache_config(&self) -> &CacheConfig {
        &self.cache_config
    }

    fn auth_handlers(&self) -> Arc<Vec<Arc<dyn AuthHandler>>> {
        self.auth_handlers.load_full()
    }

    fn root_logical_prefix(&self) -> String {
        Core::root_logical_prefix(self)
    }

    fn weak_ctx(&self) -> Weak<dyn VaultCtx> {
        // `Weak<Core>` -> `Weak<dyn VaultCtx>` is a plain unsizing coercion.
        self.self_ptr.clone()
    }

    fn physical(&self) -> Arc<dyn PhysicalBackend> {
        self.physical.clone()
    }

    fn require_machine_identity(&self) -> Arc<AtomicBool> {
        self.require_machine_identity.clone()
    }

    async fn set_require_machine_identity(&self, required: bool) -> Result<(), RvError> {
        Core::set_require_machine_identity(self, required).await
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of the trait is that an engine can hold
    /// `Arc<dyn VaultCtx>` instead of `Arc<Core>`. If `Core` ever stops being
    /// object-safe through this trait, every engine signature in Phase 2's
    /// next step breaks at once — so assert it here, where the failure is one
    /// clear error rather than a hundred.
    #[test]
    fn core_is_usable_as_a_dyn_vault_ctx() {
        fn assert_object_safe(_: &dyn VaultCtx) {}
        fn assert_arc_coercion(core: Arc<Core>) -> Arc<dyn VaultCtx> {
            core
        }
        let _ = assert_object_safe as fn(&dyn VaultCtx);
        let _ = assert_arc_coercion as fn(Arc<Core>) -> Arc<dyn VaultCtx>;
    }
}
