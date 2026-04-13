//! The legacy certificate authentication backend has been retired from the default OpenSSL-free
//! BastionVault build.
//!
//! The previous implementation depended on OpenSSL for X.509 validation, CRL processing, and
//! extension inspection. BastionVault's active security direction is now PQ key management first,
//! so cert-auth stays disabled until it is redesigned on top of a non-OpenSSL trust model.

use std::{any::Any, sync::Arc};

use crate::{core::Core, errors::RvError, modules::Module};

pub mod cli {
    use serde_json::{Map, Value};

    use crate::{
        api::{auth::LoginHandler, client::Client, HttpResponse},
        errors::RvError,
        bv_error_string,
    };

    #[derive(Default)]
    pub struct CertAuthCliHandler;

    impl LoginHandler for CertAuthCliHandler {
        fn auth(&self, _client: &Client, _data: &Map<String, Value>) -> Result<HttpResponse, RvError> {
            Err(bv_error_string!("cert auth is disabled in the OpenSSL-free build"))
        }

        fn help(&self) -> String {
            "Usage: bvault login -method=cert\n\nThe legacy cert auth method is disabled in the OpenSSL-free build."
                .to_string()
        }
    }
}

pub struct CertModule {
    pub name: String,
    pub _core: Arc<Core>,
}

impl CertModule {
    pub fn new(core: Arc<Core>) -> Self {
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

    fn setup(&self, _core: &Core) -> Result<(), RvError> {
        log::warn!("legacy cert auth module is disabled in the OpenSSL-free build");
        Ok(())
    }
}
