//! FIDO2/WebAuthn credential backend.
//!
//! Provides authentication using FIDO2 hardware security keys (YubiKey, etc.)
//! and platform authenticators via the WebAuthn standard.

use std::{any::Any, sync::Arc};

use derive_more::Deref;

use crate::{
    core::Core,
    errors::RvError,
    logical::{Backend, LogicalBackend},
    modules::{auth::AuthModule, Module},
    new_logical_backend, new_logical_backend_internal,
};

pub mod path_config;
pub mod path_credentials;
pub mod path_login;
pub mod path_register;
pub mod types;

static FIDO2_BACKEND_HELP: &str = r#"
The "fido2" credential provider allows authentication using FIDO2/WebAuthn
hardware security keys (YubiKey, etc.) and platform authenticators.

Configure the relying party via the "config" endpoint. Register credentials
using the "register/begin" and "register/complete" endpoints. Authenticate
via the "login/begin" and "login/complete" endpoints.
"#;

pub struct Fido2Module {
    pub name: String,
    pub backend: Arc<Fido2Backend>,
}

pub struct Fido2BackendInner {
    pub core: Arc<Core>,
}

#[derive(Deref)]
pub struct Fido2Backend {
    #[deref]
    pub inner: Arc<Fido2BackendInner>,
}

impl Fido2Backend {
    pub fn new(core: Arc<Core>) -> Self {
        Self { inner: Arc::new(Fido2BackendInner { core }) }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let fido2_backend_ref = self.inner.clone();

        let mut backend = new_logical_backend!({
            unauth_paths: ["login/*"],
            auth_renew_handler: fido2_backend_ref.login_renew,
            help: FIDO2_BACKEND_HELP,
        });

        backend.paths.push(Arc::new(self.config_path()));
        backend.paths.push(Arc::new(self.credentials_path()));
        backend.paths.push(Arc::new(self.credential_list_path()));
        backend.paths.push(Arc::new(self.register_begin_path()));
        backend.paths.push(Arc::new(self.register_complete_path()));
        backend.paths.push(Arc::new(self.login_begin_path()));
        backend.paths.push(Arc::new(self.login_complete_path()));

        backend
    }
}

impl Fido2Module {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            name: "fido2".to_string(),
            backend: Arc::new(Fido2Backend::new(core)),
        }
    }
}

impl Module for Fido2Module {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, core: &Core) -> Result<(), RvError> {
        let fido2 = self.backend.clone();
        let fido2_backend_new_func = move |_c: Arc<Core>| -> Result<Arc<dyn Backend>, RvError> {
            let mut fido2_backend = fido2.new_backend();
            fido2_backend.init()?;
            Ok(Arc::new(fido2_backend))
        };

        if let Some(auth_module) = core.module_manager.get_module::<AuthModule>("auth") {
            return auth_module.add_auth_backend("fido2", Arc::new(fido2_backend_new_func));
        } else {
            log::error!("get auth module failed!");
        }

        Ok(())
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        if let Some(auth_module) = core.module_manager.get_module::<AuthModule>("auth") {
            return auth_module.delete_auth_backend("fido2");
        } else {
            log::error!("get auth module failed!");
        }

        Ok(())
    }
}
