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
//! | `core.module_manager().*` | 42 | [`VaultCtx::module_manager`] |
//! | `core.state.load().system_view` | 24 | [`VaultCtx::system_view`] |
//! | `core.barrier().*` | 39 | [`VaultCtx::barrier`] |
//! | `core.router().*` | 23 | [`VaultCtx::router`] |
//! | `core.sealed()` | 11 | [`VaultCtx::sealed`] |
//! | `core.hmac_key()` | 4 | [`VaultCtx::hmac_key`] |
//! | `core.add/delete_logical_backend` | 33 | [`VaultCtx::add_logical_backend`] |
//! | `core.mounts_router()` | 10 | [`VaultCtx::mounts_router`] |
//! | `core.dos_guard.*` | 5 | [`VaultCtx::dos_guard`] |
//! | `core.stats.*` | 6 | [`VaultCtx::stats`] |
//! | `core.audit_broker.*` | 4 | [`VaultCtx::audit_broker`] |
//!
//! The surface grew during the conversion — `mount_entry_hmac_level`,
//! `mounts_monitor`, `cache_config`, `auth_handlers`, the two machine-identity
//! gates, `weak_ctx`, `physical` — each added only when a real call site
//! needed it, never speculatively.
//!
//! Still deliberately absent: `seal_provider_swap`, `exchange_preview_store`,
//! and the `mount`/`unmount`/`remount`/`flush_caches`/`dos_*` management
//! operations. Those are kernel internals, used only by `Core` itself and the
//! `sys` HTTP surface, and leaving them out is the point — an engine that
//! cannot name them cannot grow a dependency on them.
//!
//! ## Tiering: who is allowed to name `Core`
//!
//! Not every module has to stop. The split that fell out of the conversion is
//! the one the roadmap's own graph implies:
//!
//! * **Kernel tier** — `auth`, `policy`, `identity`, `namespace`,
//!   `resource_group`, `system`. These *are* the kernel and ship with it in
//!   `bv-core` / `bv-kernel`, so naming `Core` is correct, not debt. They get
//!   it from their own `self.core` field, set at construction, rather than
//!   from a `VaultCtx` parameter. `PolicyStore` and `ExpirationManager` keep a
//!   `Weak<Core>` back-reference for the same reason.
//! * **Tier 3 engines** — everything else. All 14 directories (`transit`,
//!   `totp`, `ldap`, `pki`, `files`, `kv`, `kv_v2`, `ssh`, `ssh_broker`,
//!   `cert_lifecycle`, `resource`, `notifications`, `rustion`, `credential`)
//!   now contain **zero** code references to `Core` — only prose in doc
//!   comments. So does the plugin runtime, and `src/audit`'s sys emitter.
//!
//! That is the Phase 2 objective: an engine crate can compile against this
//! trait without `bv-core` in its dependency graph.
//!
//! ## Two things that bite when extending this
//!
//! `&Arc<T>` does **not** coerce to `&dyn Trait` — only `&T` does. That is why
//! there is a blanket `impl<T: VaultCtx + ?Sized> VaultCtx for Arc<T>` below:
//! without it every helper taking `&dyn VaultCtx` needs `.as_ref()` at each
//! call site, and engines hold their handle as an `Arc`. The corollary is that
//! **parameters should be `&dyn VaultCtx`, never `&Arc<dyn VaultCtx>`** —
//! `&Core`, `&Arc<Core>` and `&Arc<dyn VaultCtx>` all coerce to the former and
//! none of them to the latter. Use `Arc<dyn VaultCtx>` by value only where the
//! body genuinely needs to own the handle.
//!
//! Accessors that used to be fields now return owned values (`barrier()`,
//! `physical()` hand back an `Arc` clone), so `core.barrier().as_storage()`
//! borrows from a temporary and has to be bound to a local first.

use std::sync::{atomic::AtomicBool, Arc, Weak};

use crate::{
    audit::AuditBroker,
    cache::CacheConfig,
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
    storage::{barrier::SecurityBarrier, barrier_view::BarrierView, Backend as PhysicalBackend},
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
    /// `LogicalBackendNewFunc` is `dyn Fn(Arc<dyn VaultCtx>) -> ...`, so this
    /// signature carries no `Core` either. That alias sat in every engine's
    /// mount path and was the last shared edge forcing the engines to convert
    /// together.
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

    /// Server-wide gate for mandatory AppRole machine binding. The AppRole
    /// login handler reads it on every login, so it is handed out as the shared
    /// `Arc<AtomicBool>` rather than a snapshot — a copy would go stale the
    /// moment an operator flipped the config.
    fn approle_require_machine(&self) -> Arc<AtomicBool>;

    /// Flip the gate above and persist it to the system view.
    async fn set_approle_require_machine(&self, required: bool) -> Result<(), RvError>;

    /// Fast-path mirror of the FerroGate mount's `require_machine_identity`
    /// flag, consulted on every authenticated request. Shared `Arc` for the
    /// same reason as `approle_require_machine`.
    /// Cache subsystem configuration. Returned by reference: it is a plain
    /// config struct living in `Core`, read once at store construction.
    fn cache_config(&self) -> &CacheConfig;

    /// Snapshot of the registered auth handlers. The token store seeds its own
    /// `ArcSwap` from this at construction.
    fn auth_handlers(&self) -> Arc<Vec<Arc<dyn AuthHandler>>>;

    /// Logical mount prefix for the root tenant (`logical/`, or the re-rooted
    /// namespace path).
    fn root_logical_prefix(&self) -> String;

    /// A weak handle back to the kernel, for stores that must not keep it
    /// alive. `Core` owns the modules, which own the stores, so a strong
    /// handle here would be a reference cycle — which is exactly why `Core`
    /// carries a `self_ptr` in the first place.
    fn weak_ctx(&self) -> Weak<dyn VaultCtx>;

    /// The unencrypted physical backend, below the barrier. Needed to identify
    /// the local Raft node for scheduled-export catalog records.
    fn physical(&self) -> Arc<dyn PhysicalBackend>;

    fn require_machine_identity(&self) -> Arc<AtomicBool>;

    /// Flip the gate above and persist it.
    async fn set_require_machine_identity(&self, required: bool) -> Result<(), RvError>;
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

/// Blanket impl so an `Arc<dyn VaultCtx>` (or `Arc<Core>`) is itself a
/// `VaultCtx`.
///
/// Without this, `&Arc<dyn VaultCtx>` does not coerce to `&dyn VaultCtx` --
/// only `&T` does -- so every helper taking `&dyn VaultCtx` would need
/// `.as_ref()` at each call site. Engines hold their kernel handle as an
/// `Arc`, so that would have been ~60 call sites of pure noise. Forwarding
/// through `(**self)` costs one extra indirection and nothing else.
#[maybe_async::maybe_async]
impl<T: VaultCtx + ?Sized> VaultCtx for Arc<T> {
    async fn handle_request(&self, req: &mut Request) -> Result<Option<Response>, RvError> {
        (**self).handle_request(req).await
    }
    fn barrier(&self) -> Arc<dyn SecurityBarrier> {
        (**self).barrier()
    }
    fn system_view(&self) -> Option<Arc<BarrierView>> {
        (**self).system_view()
    }
    fn hmac_key(&self) -> Vec<u8> {
        (**self).hmac_key()
    }
    fn sealed(&self) -> bool {
        (**self).sealed()
    }
    async fn inited(&self) -> Result<bool, RvError> {
        (**self).inited().await
    }
    fn router(&self) -> Arc<Router> {
        (**self).router()
    }
    fn mounts_router(&self) -> Arc<MountsRouter> {
        (**self).mounts_router()
    }
    fn root_storage_prefix(&self) -> Arc<String> {
        (**self).root_storage_prefix()
    }
    fn add_logical_backend(&self, logical_type: &str, backend: Arc<LogicalBackendNewFunc>) -> Result<(), RvError> {
        (**self).add_logical_backend(logical_type, backend)
    }
    fn delete_logical_backend(&self, logical_type: &str) -> Result<(), RvError> {
        (**self).delete_logical_backend(logical_type)
    }
    fn add_handler(&self, handler: Arc<dyn Handler>) -> Result<(), RvError> {
        (**self).add_handler(handler)
    }
    fn delete_handler(&self, handler: Arc<dyn Handler>) -> Result<(), RvError> {
        (**self).delete_handler(handler)
    }
    fn add_auth_handler(&self, handler: Arc<dyn AuthHandler>) -> Result<(), RvError> {
        (**self).add_auth_handler(handler)
    }
    fn delete_auth_handler(&self, handler: Arc<dyn AuthHandler>) -> Result<(), RvError> {
        (**self).delete_auth_handler(handler)
    }
    fn mount_entry_hmac_level(&self) -> MountEntryHMACLevel {
        (**self).mount_entry_hmac_level()
    }
    fn mounts_monitor(&self) -> Option<Arc<MountsMonitor>> {
        (**self).mounts_monitor()
    }
    fn module_manager(&self) -> &ModuleManager {
        (**self).module_manager()
    }
    fn stats(&self) -> Arc<DashboardStats> {
        (**self).stats()
    }
    fn audit_broker(&self) -> Option<Arc<AuditBroker>> {
        (**self).audit_broker()
    }
    fn dos_guard(&self) -> Arc<DosGuard> {
        (**self).dos_guard()
    }
    fn approle_require_machine(&self) -> Arc<AtomicBool> {
        (**self).approle_require_machine()
    }
    async fn set_approle_require_machine(&self, required: bool) -> Result<(), RvError> {
        (**self).set_approle_require_machine(required).await
    }
    fn cache_config(&self) -> &CacheConfig {
        (**self).cache_config()
    }
    fn auth_handlers(&self) -> Arc<Vec<Arc<dyn AuthHandler>>> {
        (**self).auth_handlers()
    }
    fn root_logical_prefix(&self) -> String {
        (**self).root_logical_prefix()
    }
    fn weak_ctx(&self) -> Weak<dyn VaultCtx> {
        (**self).weak_ctx()
    }
    fn physical(&self) -> Arc<dyn PhysicalBackend> {
        (**self).physical()
    }
    fn require_machine_identity(&self) -> Arc<AtomicBool> {
        (**self).require_machine_identity()
    }
    async fn set_require_machine_identity(&self, required: bool) -> Result<(), RvError> {
        (**self).set_require_machine_identity(required).await
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
