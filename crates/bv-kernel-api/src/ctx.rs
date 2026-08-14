//! [`VaultCtx`]: the vault kernel, as an engine sees it.
//!
//! The seam that cuts the `Core` ↔ `modules` cycle. Every module used to hold
//! an `Arc<Core>` while `Core` imported `modules::auth::AuthModule` and
//! `modules::policy::PolicyModule`, so neither side could become a crate.
//! Modules now depend on this trait, `Core` implements it, and the concrete
//! kernel type is no longer part of an engine's compile unit.
//!
//! See [the crate docs](crate) for how this fits with the service registry,
//! and for why the routing and mount tables travel with it.
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
//! | `core.module_manager().*` | 42 | [`VaultCtx::kernel`] + the accessors on it |
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
//!   contain **zero** code references to `Core` — only prose in doc comments.
//!   So does the plugin runtime, and `src/audit`'s sys emitter. They also name
//!   no *sibling* module's concrete type: siblings are reached through
//!   [`VaultCtx::kernel`] and the [service registry](crate::services).
//!
//! That is the Phase 2 objective: an engine crate can compile against this
//! trait without `bv-core` or `bv-kernel` in its dependency graph.
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

use serde::{Deserialize, Serialize};

use bv_errors::RvError;
use bv_logical::{
    handler::{AuthHandler, Handler},
    Backend, Request, Response,
};
use bv_storage::{
    barrier::SecurityBarrier, barrier_view::BarrierView, cache::CacheConfig, Backend as PhysicalBackend,
};

use crate::{
    auth::{AuthMountRegistry, TokenService},
    dos::DosGuard,
    engines::{ConnectMfaGate, LoginClassPolicy, NotificationSink, PluginHost, TotpMfa},
    identity::IdentityService,
    mount::{MountsMonitor, MountsRouter},
    namespace::NamespaceRegistry,
    policy::PolicyGate,
    resource_group::ResourceGroupIndex,
    router::Router,
    services::KernelServices,
    stats::DashboardStats,
};
use bv_audit::AuditBroker;

/// Factory that builds a mounted logical backend for a given kernel handle.
///
/// Takes `Arc<dyn VaultCtx>`, not `Arc<Core>`: this alias is in every engine's
/// mount-registration path, so while it named `Core` no engine could compile
/// without the kernel. It lives here, next to the trait it names, rather than
/// in `Core` — that was the last thing forcing `crate::core` into an engine's
/// import list. See roadmaps/workspace-decomposition.md Phase 2.
pub type LogicalBackendNewFunc = dyn Fn(Arc<dyn VaultCtx>) -> Result<Arc<dyn Backend>, RvError> + Send + Sync;

/// How much of a mount-table entry its HMAC covers.
///
/// An operator setting, parsed from the server config file and re-exported
/// from `bastion_vault::cli::config` where it has always been named. It lives
/// here because [`VaultCtx::mount_entry_hmac_level`] returns it and the mount
/// table enforces it, both of which are below the CLI in the crate graph.
#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MountEntryHMACLevel {
    #[default]
    None,
    Compat,
    High,
}

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

    // ── sibling capabilities ───────────────────────────────────────────
    /// The capabilities the vault's modules publish to each other.
    ///
    /// This replaced `module_manager()`, which handed out the concrete
    /// `ModuleManager` so callers could `get_module::<T>()` a sibling by name
    /// and downcast it. That worked, and it was the last edge pinning the
    /// engines together: to reach identity you had to *name* `IdentityModule`.
    ///
    /// The convenience accessors below are what call sites use; this method is
    /// the one an implementor writes.
    fn kernel(&self) -> &KernelServices;

    /// Entities, group policy expansion, ownership, user audit.
    fn identity(&self) -> Option<Arc<dyn IdentityService>> {
        self.kernel().identity()
    }

    /// Token lookup and revocation.
    fn tokens(&self) -> Option<Arc<dyn TokenService>> {
        self.kernel().tokens()
    }

    /// Registration and inspection of `auth/` mounts.
    fn auth_mounts(&self) -> Option<Arc<dyn AuthMountRegistry>> {
        self.kernel().auth_mounts()
    }

    /// The authorization questions an engine may ask.
    fn policy(&self) -> Option<Arc<dyn PolicyGate>> {
        self.kernel().policy()
    }

    /// Namespace resolution and the login-time namespace binding.
    fn namespaces(&self) -> Option<Arc<dyn NamespaceRegistry>> {
        self.kernel().namespaces()
    }

    /// The asset-group reverse index.
    fn resource_groups(&self) -> Option<Arc<dyn ResourceGroupIndex>> {
        self.kernel().resource_groups()
    }

    /// Notification delivery, for plugins and engines that raise alerts.
    fn notifications(&self) -> Option<Arc<dyn NotificationSink>> {
        self.kernel().notifications()
    }

    /// The SSH brokering tier resolver.
    fn login_class(&self) -> Option<Arc<dyn LoginClassPolicy>> {
        self.kernel().login_class()
    }

    /// The per-profile connect-MFA gate.
    fn connect_mfa(&self) -> Option<Arc<dyn ConnectMfaGate>> {
        self.kernel().connect_mfa()
    }

    /// TOTP second-factor verification.
    fn totp_mfa(&self) -> Option<Arc<dyn TotpMfa>> {
        self.kernel().totp_mfa()
    }

    /// The plugin runtime, for engines that dispatch through a plugin.
    fn plugin_host(&self) -> Option<Arc<dyn PluginHost>> {
        self.kernel().plugin_host()
    }

    // ── ancillary subsystems ───────────────────────────────────────────
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
    fn kernel(&self) -> &KernelServices {
        (**self).kernel()
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

