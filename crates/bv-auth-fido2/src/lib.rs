//! FIDO2/WebAuthn credential backend.
//!
//! Provides authentication using FIDO2 hardware security keys (YubiKey, etc.)
//! and platform authenticators via the WebAuthn standard.

// The substrate, under the names this backend has always spelled it. Private:
// `crate::errors::RvError` and `crate::logical::Path` keep resolving inside
// the crate, and none of it leaks into the public API, so the extraction
// stayed a file move rather than an import rewrite.
// See roadmaps/workspace-decomposition.md § Phase 3.
use bv_context as context;
use bv_errors as errors;
use bv_kernel_api as kernel_api;
use bv_logical as logical;
use bv_storage as storage;
use bv_utils as utils;

// The eight backend-definition macros are `#[macro_export]`ed by `bv-logical`,
// which places them at *that* crate's root; the call sites import them as
// `crate::new_path` and friends. The `_internal` halves are the recursive arms
// the public macros expand into, so they must travel with them.
pub use bv_logical::{
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path,
    new_path_internal, new_secret, new_secret_internal,
};
pub use bv_errors::{bv_error_response, bv_error_response_status, bv_error_string};

use std::{any::Any, sync::Arc};

use derive_more::Deref;

use bv_kernel_api::{Module, VaultCtx};
use crate::{
    errors::RvError,
    logical::{Backend, LogicalBackend},
};

pub mod path_config;
pub mod path_credentials;
pub mod path_login;
pub mod path_register;
pub mod rp;
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
    pub core: Arc<dyn VaultCtx>,
}

#[derive(Deref)]
pub struct Fido2Backend {
    #[deref]
    pub inner: Arc<Fido2BackendInner>,
}

impl Fido2Backend {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
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
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
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

    fn setup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        let fido2 = self.backend.clone();
        let fido2_backend_new_func = move |_c: Arc<dyn VaultCtx>| -> Result<Arc<dyn Backend>, RvError> {
            let mut fido2_backend = fido2.new_backend();
            fido2_backend.init()?;
            Ok(Arc::new(fido2_backend))
        };

        if let Some(auth_mounts) = core.auth_mounts() {
            return auth_mounts.add_auth_backend("fido2", Arc::new(fido2_backend_new_func));
        } else {
            log::error!("get auth module failed!");
        }

        Ok(())
    }

    fn cleanup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        if let Some(auth_mounts) = core.auth_mounts() {
            return auth_mounts.delete_auth_backend("fido2");
        } else {
            log::error!("get auth module failed!");
        }

        Ok(())
    }
}
