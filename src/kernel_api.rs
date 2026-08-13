//! The kernel contract: what a module is allowed to know about the vault.
//!
//! This is Phase 2 of [the decomposition](../roadmaps/workspace-decomposition.md)
//! — the one that cuts the `Core` ↔ `modules` cycle. Today every module holds
//! an `Arc<Core>` and `Core` imports `modules::auth::AuthModule` and
//! `modules::policy::PolicyModule`, so neither side can become a crate.
//! [`VaultCtx`] is the seam: modules depend on the trait, `Core` implements it,
//! and the concrete type stops being part of an engine's compile unit.
//!
//! ## Why this lives in the monolith and not in `bv-kernel-api`
//!
//! The roadmap has Phase 2 opening with "define `bv-kernel-api`". It cannot,
//! yet: these signatures name types that have not been extracted —
//! [`BarrierView`] and [`SecurityBarrier`] are `src/storage` (Tier 0, not done),
//! [`Router`] is `src/router` and [`MountsRouter`] is `src/mount` (both Tier 2).
//! A crate holding this trait would need all of them as dependencies.
//!
//! That is a sequencing problem, not a design problem, because **the crate is
//! not what breaks the cycle — the abstraction is.** So the trait starts here,
//! the modules move onto it, and the file becomes `bv-kernel-api` later, once
//! `bv-storage` exists and `router`/`mount` have moved into `bv-core`. Doing it
//! the other way round would block the phase on the extraction order it is
//! meant to enable.
//!
//! ## Shape of the surface
//!
//! Every method here was chosen by counting what `src/modules` actually
//! reaches for, not by mirroring `Core`'s public API. `Core` has ~30 public
//! fields; modules touch these:
//!
//! | reached as | sites | exposed here as |
//! |---|---|---|
//! | `core.handle_request(..)` | 87 | [`VaultCtx::handle_request`] |
//! | `core.module_manager.*` | 42 | [`VaultCtx::module_manager`] |
//! | `core.state.load().system_view` | 24 | [`VaultCtx::system_view`] |
//! | `core.barrier.*` | 39 | [`VaultCtx::barrier`] |
//! | `core.router.*` | 23 | [`VaultCtx::router`] |
//! | `core.state.load().sealed` | 11 | [`VaultCtx::sealed`] |
//! | `core.state.load().hmac_key` | 4 | [`VaultCtx::hmac_key`] |
//! | `core.add/delete_logical_backend` | 33 | [`VaultCtx::add_logical_backend`] |
//! | `core.mounts_router()` | 10 | [`VaultCtx::mounts_router`] |
//! | `core.dos_guard.*` | 5 | [`VaultCtx::dos_guard`] |
//! | `core.stats.*` | 6 | [`VaultCtx::stats`] |
//! | `core.audit_broker.*` | 4 | [`VaultCtx::audit_broker`] |
//!
//! Note what is *not* here: `self_ptr`, `physical`, `seal_provider_swap`,
//! `exchange_preview_store`, `mounts_monitor`. Those are kernel internals that
//! only `Core` and the `sys` HTTP surface use, and leaving them out is the
//! point — an engine that cannot name them cannot grow a dependency on them.
//!
//! ## What this commit does and does not do
//!
//! This is additive. The trait is defined and `Core` implements it by
//! delegating to its existing inherent methods and fields, so behaviour is
//! byte-identical and no call site changes. That makes it verifiable on its
//! own.
//!
//! The conversion is the next step, and it is not incremental per engine the
//! way the roadmap suggests ("module by module, cheapest first: transit (1
//! file), totp (2) …"). Two signatures make it atomic:
//!
//! ```ignore
//! // src/module_manager.rs — every one of the 17 modules implements this
//! fn setup(&self, core: &Core) -> Result<(), RvError>;
//! fn cleanup(&self, core: &Core) -> Result<(), RvError>;
//!
//! // src/core.rs:44 — every engine's mount closure is one of these
//! pub type LogicalBackendNewFunc =
//!     dyn Fn(Arc<Core>) -> Result<Arc<dyn Backend>, RvError> + Send + Sync;
//! ```
//!
//! Changing either flips all 17 modules at once. So the realistic order is:
//! this trait, then one commit that moves `Module::setup`/`cleanup` and
//! `LogicalBackendNewFunc` onto `dyn VaultCtx` together with every engine's
//! `core: Arc<Core>` field, then the ~101 kernel-five `get_module` call sites
//! behind typed accessors.

use std::sync::Arc;

use crate::{
    audit::AuditBroker,
    cli::config::MountEntryHMACLevel,
    core::{Core, LogicalBackendNewFunc},
    dos::DosGuard,
    errors::RvError,
    handler::{AuthHandler, Handler},
    logical::{Request, Response},
    module_manager::ModuleManager,
    mount::{MountsMonitor, MountsRouter},
    router::Router,
    stats::DashboardStats,
    storage::{barrier::SecurityBarrier, barrier_view::BarrierView},
};

/// The vault kernel, as an engine sees it.
///
/// `Core` is the only implementor in the server. Keeping this a trait is what
/// lets an engine crate compile without `bv-core`; keeping it *narrow* is what
/// stops the cycle growing back.
#[maybe_async::maybe_async]
pub trait VaultCtx: Send + Sync {
    // ── request dispatch ───────────────────────────────────────────────
    /// Dispatch a logical request through the handler chain and router.
    async fn handle_request(&self, req: &mut Request) -> Result<Option<Response>, RvError>;

    // ── barrier and encrypted storage ──────────────────────────────────
    fn barrier(&self) -> Arc<dyn SecurityBarrier>;

    /// The `sys/` barrier view, or `None` while sealed.
    fn system_view(&self) -> Option<Arc<BarrierView>>;

    /// Key for HMAC-ing mount-table entries and audit records.
    ///
    /// Returns an owned copy rather than a borrow: the real storage is behind
    /// an `ArcSwap`, so there is no stable reference to hand out.
    fn hmac_key(&self) -> Vec<u8>;

    fn sealed(&self) -> bool;

    async fn inited(&self) -> Result<bool, RvError>;

    // ── routing and mounts ─────────────────────────────────────────────
    fn router(&self) -> Arc<Router>;

    fn mounts_router(&self) -> Arc<MountsRouter>;

    /// Storage-prefix root for the tenant this context serves. Empty unless
    /// re-root activation is in effect.
    fn root_storage_prefix(&self) -> Arc<String>;

    /// Register a logical backend factory under a mount type.
    ///
    /// `LogicalBackendNewFunc` still names `Arc<Core>` in its own signature
    /// (`src/core.rs:44`). That is the single edge this trait cannot abstract
    /// away on its own, and retyping it to `Arc<dyn VaultCtx>` is the atomic
    /// step described in this module's docs.
    fn add_logical_backend(&self, logical_type: &str, backend: Arc<LogicalBackendNewFunc>) -> Result<(), RvError>;

    fn delete_logical_backend(&self, logical_type: &str) -> Result<(), RvError>;

    // ── handler chain ──────────────────────────────────────────────────
    fn add_handler(&self, handler: Arc<dyn Handler>) -> Result<(), RvError>;

    fn delete_handler(&self, handler: Arc<dyn Handler>) -> Result<(), RvError>;

    fn add_auth_handler(&self, handler: Arc<dyn AuthHandler>) -> Result<(), RvError>;

    fn delete_auth_handler(&self, handler: Arc<dyn AuthHandler>) -> Result<(), RvError>;

    // ── mount table plumbing ───────────────────────────────────────────
    /// How much of a mount-table entry its HMAC covers. The auth module needs
    /// it to load and persist the auth mount table.
    fn mount_entry_hmac_level(&self) -> MountEntryHMACLevel;

    /// The mount-table change monitor, or `None` when polling is disabled.
    /// A module owning a `MountsRouter` registers it here so re-mounts reach it.
    fn mounts_monitor(&self) -> Option<Arc<MountsMonitor>>;

    // ── ancillary subsystems ───────────────────────────────────────────
    /// Sibling-module lookup.
    ///
    /// Deliberately still the concrete `ModuleManager`. Replacing it with
    /// typed accessors (`TokenStore`, `IdentityStore`, `PolicyStore`,
    /// `NamespaceRegistry`, `ResourceGroupStore`) is the larger half of Phase
    /// 2 — ~101 production call sites — and wants its own change. Exposing it
    /// here keeps this commit additive rather than forcing both at once.
    fn module_manager(&self) -> &ModuleManager;

    fn stats(&self) -> Arc<DashboardStats>;

    /// The audit broker, or `None` before `post_unseal` installs it.
    fn audit_broker(&self) -> Option<Arc<AuditBroker>>;

    fn dos_guard(&self) -> Arc<DosGuard>;
}

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

    fn module_manager(&self) -> &ModuleManager {
        &self.module_manager
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
