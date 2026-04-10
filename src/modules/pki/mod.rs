//! The legacy X.509 PKI backend has been retired from the default BastionVault build.
//!
//! BastionVault now focuses its active cryptographic migration on post-quantum key management
//! through `ml-kem-768` and `ml-dsa-65`. The old certificate-centric PKI implementation was the
//! last large OpenSSL-bound subsystem, so it is intentionally disabled here until a new
//! certificate or trust-distribution model is introduced without OpenSSL.

use std::{any::Any, sync::Arc};

use crate::{core::Core, errors::RvError, modules::Module};

pub struct PkiModule {
    pub name: String,
    pub _core: Arc<Core>,
}

impl PkiModule {
    pub fn new(core: Arc<Core>) -> Self {
        Self { name: "pki".to_string(), _core: core }
    }
}

impl Module for PkiModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, _core: &Core) -> Result<(), RvError> {
        log::warn!("legacy PKI module is disabled in the OpenSSL-free build");
        Ok(())
    }
}
