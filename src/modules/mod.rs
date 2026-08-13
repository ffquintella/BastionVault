//! `bastion_vault::modules` contains a set of real BastionVault modules. Each sub module needs to
//! implement the `bastion_vault::modules::Module` trait defined here and then the module
//! could be added to module manager.
//!
//! It's important for the developers who want to implement a new BastionVault module themselves to
//! get the `trait Module` implemented correctly.

use std::{any::Any, sync::Arc};

use crate::{errors::RvError, kernel_api::VaultCtx};

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
}
