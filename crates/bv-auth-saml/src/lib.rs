//! SAML 2.0 authentication backend — full SP-initiated SSO flow.
//!
//! Mirrors the Module/Backend pattern used by `userpass`, `approle`,
//! and `oidc`:
//!
//!   * `SamlModule` registers the backend with the auth module under
//!     the `"saml"` kind.
//!   * `SamlBackend` + `SamlBackendInner` hold the shared core handle;
//!     per-path handlers live in `path_config.rs` / `path_roles.rs`.
//!
//! Endpoints registered on the backend (all mounted under `auth/<mount>/`):
//!
//!   `config`                      — GET / POST  (root)   IdP configuration
//!   `role/<name>`                 — GET / POST / DELETE  per-role config
//!   `role/?`                      — LIST                 all role names
//!
//! Phase 3 (login / callback / XML-signature verification) is not yet
//! wired — the crate decision for XML-DSig verification is deferred
//! until we pick between `samael` (C-dep-heavy, feature-complete) and
//! a pure-Rust XML-DSig path. Config + role state is persisted now so
//! operators can describe their IdP ahead of the flow shipping.
//!
//! Single-mount assumption: one IdP config per mount. Multi-IdP
//! setups use multiple mounts (`auth/okta/`, `auth/adfs/`, etc.).

// The substrate, under the names this engine already spells it by. Private:
// `crate::errors::RvError` and `crate::logical::Path` keep resolving inside
// the crate, and none of it leaks into the public API, so the extraction
// stayed a file move rather than an import rewrite.
// See roadmaps/workspace-decomposition.md § Phase 3.
use bv_context as context;
use bv_errors as errors;
use bv_logical as logical;
use bv_storage as storage;

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

pub mod authn_request;
pub mod path_callback;
pub mod path_config;
pub mod path_login;
pub mod path_roles;
pub mod response;
pub mod validate;
pub mod verify;

static SAML_BACKEND_HELP: &str = r#"
The "saml" credential provider allows authentication against any
SAML 2.0 compliant identity provider (Okta, Azure AD, ADFS,
Keycloak, Shibboleth, etc.) using SP-initiated Single Sign-On.

IdP-level configuration (metadata URL or raw metadata, SP entity
id, ACS URL, signing certificate) is written once at the `config`
endpoint. Role configuration (attribute-to-policy mappings,
bound attributes / subjects, token TTLs) is written at
`role/<name>`. The login + callback endpoints will land in a
follow-up phase together with XML-signature verification.
"#;

pub struct SamlModule {
    pub name: String,
    pub backend: Arc<SamlBackend>,
}

pub struct SamlBackendInner {
    pub core: Arc<dyn VaultCtx>,
}

#[derive(Deref)]
pub struct SamlBackend {
    #[deref]
    pub inner: Arc<SamlBackendInner>,
}

impl SamlBackend {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self {
            inner: Arc::new(SamlBackendInner { core }),
        }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let saml_backend_ref = self.inner.clone();
        let mut backend = new_logical_backend!({
            // `login` and `callback` are the two endpoints the
            // browser-mediated flow needs to hit without a vault
            // token in hand; everything else is root-path admin.
            unauth_paths: ["login", "callback"],
            auth_renew_handler: saml_backend_ref.login_renew,
            help: SAML_BACKEND_HELP,
        });

        backend.paths.push(Arc::new(self.config_path()));
        backend.paths.push(Arc::new(self.roles_path()));
        backend.paths.push(Arc::new(self.role_list_path()));
        backend.paths.push(Arc::new(self.login_path()));
        backend.paths.push(Arc::new(self.callback_path()));

        backend
    }
}

impl SamlModule {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self {
            name: "saml".to_string(),
            backend: Arc::new(SamlBackend::new(core)),
        }
    }
}

impl Module for SamlModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        let saml = self.backend.clone();
        let saml_backend_new_func = move |_c: Arc<dyn VaultCtx>| -> Result<Arc<dyn Backend>, RvError> {
            let mut b = saml.new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };

        if let Some(auth_mounts) = core.auth_mounts() {
            return auth_mounts.add_auth_backend("saml", Arc::new(saml_backend_new_func));
        }
        log::error!("saml module: auth module missing on setup");
        Ok(())
    }

    fn cleanup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        if let Some(auth_mounts) = core.auth_mounts() {
            return auth_mounts.delete_auth_backend("saml");
        }
        Ok(())
    }
}

