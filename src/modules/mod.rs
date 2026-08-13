//! `bastion_vault::modules` contains a set of real BastionVault modules. Each sub module needs to
//! implement the `bastion_vault::modules::Module` trait defined here and then the module
//! could be added to module manager.
//!
//! It's important for the developers who want to implement a new BastionVault module themselves to
//! get the `trait Module` implemented correctly.

use std::{any::Any, sync::Arc};

use crate::{
    errors::RvError,
    kernel_api::{KernelServices, VaultCtx},
};

pub mod auth;
pub mod cert_lifecycle;
pub mod credential;
pub mod crypto;
pub mod files;
pub mod identity;
pub mod kv;
pub mod kv_v2;
pub mod ldap;
pub mod namespace;
pub mod notifications;
pub mod pki;
pub mod policy;
pub mod resource;
pub mod resource_group;
pub mod rustion;
pub mod ssh;
pub mod ssh_broker;
pub mod system;
pub mod totp;
pub mod transit;

#[maybe_async::maybe_async]
pub trait Module: Any + Send + Sync {
    //! Description for a trait itself.
    fn name(&self) -> String;

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync>;

    // `&dyn VaultCtx`, not `&Core`. This is the cut: an engine's lifecycle
    // hooks can no longer name the kernel's concrete type, so `Core` leaves
    // the engine's compile unit. `&Core` still coerces at every `ModuleManager`
    // call site, so the calling side is untouched.
    //
    // Kernel-tier modules (auth, policy, identity, namespace, resource_group,
    // system) legitimately still need `&Core` — they *are* the kernel, and
    // stay with it in `bv-core` / `bv-kernel`. They get it from their own
    // `self.core` field, set at construction, rather than from this parameter.
    // That is what keeps this change from cascading into the ~350
    // `Arc<Core>` / `Weak<Core>` sites their stores hold: see
    // roadmaps/workspace-decomposition.md § "Step 3 is not step-shaped".
    async fn init(&self, _core: &dyn VaultCtx) -> Result<(), RvError> {
        Ok(())
    }

    fn setup(&self, _core: &dyn VaultCtx) -> Result<(), RvError> {
        Ok(())
    }

    fn cleanup(&self, _core: &dyn VaultCtx) -> Result<(), RvError> {
        Ok(())
    }

    /// Publish this module's capabilities, and capture a handle to itself.
    ///
    /// Called once by `ModuleManager` as the module is installed, before any
    /// request can reach it. Two jobs, both of which need an `Arc<Self>` and so
    /// cannot be done in `init`/`setup`:
    ///
    /// * **Registration.** A module that provides a kernel or engine
    ///   capability stores itself into `services` as the matching trait object
    ///   — `services.set_identity(self)`. That is what lets a sibling ask for
    ///   the capability instead of naming the module's concrete type.
    /// * **Self-binding.** A module that needs a handle to itself elsewhere —
    ///   a detached background task, a logical backend built before its stores
    ///   exist — captures it here. (Engines that only need their own *stores*
    ///   share the store slots instead: see `rustion::RustionStores` and
    ///   `notifications::ServiceSlot`. Both replaced a
    ///   `get_module::<Self>(name)` self-lookup, which was an expensive way to
    ///   spell `self` and dragged `ModuleManager` into the engine.)
    ///
    /// A self-handle must be `Weak`: the module set owns the modules, so a
    /// strong self-reference would leak the module and the `Core` behind it.
    ///
    /// Default is a no-op — most engines publish nothing.
    fn register(self: Arc<Self>, _services: &KernelServices) {}

    /// Drop this module's in-memory caches and zeroize what they held.
    ///
    /// Called on seal and from the `sys/cache/flush` admin endpoint. Must not
    /// fail: half-flushed is worse than best-effort-flushed on a seal hot
    /// path, so a module that cannot flush logs and returns.
    ///
    /// Only the policy and token caches implement this today; both used to be
    /// reached from `Core::flush_caches` by name, which is the kernel naming
    /// its modules.
    fn flush_caches(&self) {}

    /// Start this module's detached background tasks.
    ///
    /// Called after `init`, once per unseal, with a strong kernel handle.
    /// Schedulers, pollers and sweepers live here rather than in
    /// `Core::post_unseal`, which used to name six engines' entry points
    /// directly (`pki::scheduler`, `rustion::{probe,poller,telemetry,
    /// attest_timer}`, `ldap::scheduler`, `files::scheduler`) — the kernel
    /// naming engines is exactly the edge Phase 2 removes.
    ///
    /// Implementations must not block: spawn and return. Tasks are detached by
    /// design and self-skip while sealed.
    fn start_background(&self, _core: Arc<dyn VaultCtx>) {}
}
