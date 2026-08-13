//! BastionVault is consisted of many modules. Modules are the real components that implement the
//! features that users need. All modules in BastionVault are managed by `bastion_vault::module_manager`.
//!
//! In details, the module manager is able to organize, add, remove, setup, initialize, cleanup
//! other BastionVault modules.
//!
//! Do not mix up the BastionVault module with the concept of a Rust module. A BastionVault module is a
//! piece of code that implements some functionality. Although usually that piece of code is
//! organized in the form of a module of crate `bastion_vault` in Rust language concept.

use std::{any::Any, sync::Arc};

use arc_swap::ArcSwap;

use crate::kernel_api::{KernelServices, VaultCtx};
use crate::{core::Core, errors::RvError, modules::Module};

/// Builds one module, given the kernel handle.
///
/// A boxed closure would do for the current call site, but a trait keeps the
/// door open for what Phase 4 wants: a registration list a plugin or an
/// embedder can extend, rather than a `vec![]` literal compiled into the
/// kernel.
pub trait ModuleFactory: Send + Sync {
    fn build(&self, core: Arc<Core>) -> Arc<dyn Module>;
}

/// Blanket impl so a plain closure is a factory:
/// `Box::new(|c| Arc::new(PkiModule::new(c)) as Arc<dyn Module>)`.
impl<F> ModuleFactory for F
where
    F: Fn(Arc<Core>) -> Arc<dyn Module> + Send + Sync,
{
    fn build(&self, core: Arc<Core>) -> Arc<dyn Module> {
        self(core)
    }
}

pub struct ModuleManager {
    pub modules: ArcSwap<Vec<Arc<dyn Module>>>,
}

#[maybe_async::maybe_async]
impl ModuleManager {
    pub fn new() -> Self {
        Self { modules: ArcSwap::from_pointee(Vec::new()) }
    }

    /// Install the module set for this vault.
    ///
    /// The manager deliberately does **not** name the 17 concrete engine types
    /// any more. It takes factories and calls them, so `bv-core` can be a crate
    /// that knows nothing about `bv-engine-pki` and friends; the assembly point
    /// (`src/lib.rs`, later the `bastion_vault` facade) is what knows the list.
    /// See roadmaps/workspace-decomposition.md Phase 2 step 4.
    ///
    /// Order is load-bearing and preserved by the caller's `Vec`: the namespace
    /// module must initialise before the system module's request handlers
    /// reference its store.
    pub fn set_modules(&self, factories: Vec<Box<dyn ModuleFactory>>, core: Arc<Core>) -> Result<(), RvError> {
        let modules: Vec<Arc<dyn Module>> = factories.into_iter().map(|f| f.build(core.clone())).collect();
        for module in &modules {
            module.clone().register(&core.kernel_services);
        }
        self.modules.store(Arc::new(modules));
        Ok(())
    }

    /// Start every module's detached background tasks.
    ///
    /// Called once per unseal from `Core::post_unseal`, after `init`. Replaces
    /// the block there that named six engines' scheduler entry points.
    pub fn start_background(&self, core: Arc<Core>) {
        let ctx: Arc<dyn VaultCtx> = core;
        let modules = self.modules.load().clone();
        for module in modules.iter() {
            module.start_background(ctx.clone());
        }
    }

    #[inline]
    pub fn get_module<T: Any + Send + Sync>(&self, name: &str) -> Option<Arc<T>> {
        let modules = self.modules.load();
        for m in modules.iter() {
            if m.name().as_str() == name {
                let any_arc = m.clone().as_any_arc();
                return Arc::downcast::<T>(any_arc).ok();
            }
        }

        None
    }

    /// Install one more module after [`Self::set_modules`].
    ///
    /// Takes the registry so the module can publish its capabilities on the
    /// same terms as the ones installed in bulk — the auth and policy modules
    /// arrive this way, and both are kernel services every engine resolves.
    #[inline]
    pub fn add_module(&self, module: Arc<dyn Module>, services: &KernelServices) -> Result<(), RvError> {
        let modules = self.modules.load();
        for m in modules.iter() {
            if m.name().as_str() == module.name().as_str() {
                return Err(RvError::ErrModuleConflict);
            }
        }

        let old_modules = self.modules.load_full();
        let mut modules = (*old_modules).clone();
        module.clone().register(services);
        modules.push(module);

        let modules = Arc::new(modules);

        if !Arc::ptr_eq(&self.modules.load().clone(), &old_modules) {
            return Err(RvError::ErrModuleConflict);
        }

        self.modules.store(modules);

        Ok(())
    }

    pub fn remove_module(&self, name: &str) -> Result<(), RvError> {
        let old_modules = self.modules.load_full();
        let mut modules = (*old_modules).clone();
        modules.retain(|m| m.name().as_str() != name);

        let modules = Arc::new(modules);

        if !Arc::ptr_eq(&self.modules.load().clone(), &old_modules) {
            return Err(RvError::ErrModuleConflict);
        }

        self.modules.store(modules);

        Ok(())
    }

    pub fn setup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        let modules = self.modules.load().clone();
        for module in modules.iter() {
            module.setup(core)?;
        }

        Ok(())
    }

    pub async fn init(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        let modules = self.modules.load().clone();
        for module in modules.iter() {
            module.init(core).await?;
        }

        Ok(())
    }

    /// Flush every module's caches. Best-effort by contract; see
    /// [`Module::flush_caches`].
    pub fn flush_caches(&self) {
        let modules = self.modules.load().clone();
        for module in modules.iter() {
            module.flush_caches();
        }
    }

    pub fn cleanup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        let modules = self.modules.load().clone();
        for module in modules.iter() {
            module.cleanup(core)?;
        }

        Ok(())
    }
}
