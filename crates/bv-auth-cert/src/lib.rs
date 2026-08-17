//! The legacy certificate authentication backend has been retired from the default OpenSSL-free
//! BastionVault build.
//!
//! The previous implementation depended on OpenSSL for X.509 validation, CRL processing, and
//! extension inspection. BastionVault's active security direction is now PQ key management first,
//! so cert-auth stays disabled until it is redesigned on top of a non-OpenSSL trust model.

use std::{any::Any, sync::Arc};

use bv_kernel_api::{Module, VaultCtx};
use bv_errors::RvError;


pub struct CertModule {
    pub name: String,
    pub _core: Arc<dyn VaultCtx>,
}

impl CertModule {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self { name: "cert".to_string(), _core: core }
    }
}

impl Module for CertModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, _core: &dyn VaultCtx) -> Result<(), RvError> {
        log::warn!("legacy cert auth module is disabled in the OpenSSL-free build");
        Ok(())
    }
}
