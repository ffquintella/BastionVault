//! OpenID Connect authentication backend.
//!
//! Mirrors the Module/Backend pattern used by `userpass` and `approle`:
//!
//!   * `OidcModule` registers the backend with the auth module under
//!     the `"oidc"` kind.
//!   * `OidcBackend` + `OidcBackendInner` hold the shared core handle;
//!     per-path handlers live in `path_config.rs` / `path_roles.rs` /
//!     `path_auth_url.rs` / `path_callback.rs`.
//!
//! Endpoints registered on the backend (all mounted under `auth/<mount>/`):
//!
//!   `config`                      — GET / POST  (root)   provider config
//!   `role/<name>`                 — GET / POST / DELETE  per-role config
//!   `role/?`                      — LIST                 all role names
//!   `auth_url`                    — POST        (unauth) generate consent URL
//!   `callback`                    — POST        (unauth) finish consent flow
//!
//! The auth flow runs in two steps:
//!
//!   1. Client POSTs `auth_url` with a `role` + `redirect_uri`. We
//!      generate PKCE + CSRF state + nonce, stash them under
//!      `state/<state>` (short-lived), and return the authorization
//!      URL pointing at the IdP.
//!   2. Client POSTs `callback` with the `state` + `code` returned
//!      by the IdP. We load-and-delete the state record, exchange the
//!      code for tokens using `openidconnect`, verify the ID token
//!      against the IdP's JWKS, validate role-bound claims, and
//!      return an `Auth` carrying the role's policies. The token
//!      store then mints the vault token.
//!
//! Single-mount assumption: one config per mount. Multi-provider
//! setups use multiple mounts (`auth/okta/`, `auth/azuread/`, etc.).

// The substrate, under the names this engine already spells it by. Private:
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

pub mod path_auth_url;
pub mod path_callback;
pub mod path_config;
pub mod path_roles;

static OIDC_BACKEND_HELP: &str = r#"
The "oidc" credential provider allows authentication against any
OpenID Connect compliant identity provider (Okta, Azure AD,
Keycloak, Google, Auth0, etc.) using the Authorization Code Flow
with PKCE.

Provider-level configuration (discovery URL, client id/secret,
allowed redirect URIs, default scopes) is written once at the
`config` endpoint. Role configuration (claim-to-policy mappings,
bound audiences / claims, token TTLs) is written at `role/<name>`.
Clients initiate login by POSTing `auth_url` with a role + redirect
URI, open the returned authorization URL in a browser, and finish
by POSTing the returned `code` + `state` back to `callback`.
"#;

pub struct OidcModule {
    pub name: String,
    pub backend: Arc<OidcBackend>,
}

pub struct OidcBackendInner {
    pub core: Arc<dyn VaultCtx>,
}

#[derive(Deref)]
pub struct OidcBackend {
    #[deref]
    pub inner: Arc<OidcBackendInner>,
}

impl OidcBackend {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self {
            inner: Arc::new(OidcBackendInner { core }),
        }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        // The renew-handler macro expects `ident.ident`, so bind a
        // named handle first.
        let oidc_backend_ref = self.inner.clone();

        let mut backend = new_logical_backend!({
            // `auth_url` and `callback` are the two endpoints the
            // browser-mediated flow needs to hit without a vault
            // token in hand; everything else is root-path admin.
            unauth_paths: ["auth_url", "callback"],
            auth_renew_handler: oidc_backend_ref.login_renew,
            help: OIDC_BACKEND_HELP,
        });

        backend.paths.push(Arc::new(self.config_path()));
        backend.paths.push(Arc::new(self.roles_path()));
        backend.paths.push(Arc::new(self.role_list_path()));
        backend.paths.push(Arc::new(self.auth_url_path()));
        backend.paths.push(Arc::new(self.callback_path()));

        backend
    }
}

impl OidcModule {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self {
            name: "oidc".to_string(),
            backend: Arc::new(OidcBackend::new(core)),
        }
    }
}

impl Module for OidcModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        let oidc = self.backend.clone();
        let oidc_backend_new_func = move |_c: Arc<dyn VaultCtx>| -> Result<Arc<dyn Backend>, RvError> {
            let mut b = oidc.new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };

        if let Some(auth_mounts) = core.auth_mounts() {
            return auth_mounts.add_auth_backend("oidc", Arc::new(oidc_backend_new_func));
        }
        log::error!("oidc module: auth module missing on setup");
        Ok(())
    }

    fn cleanup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        if let Some(auth_mounts) = core.auth_mounts() {
            return auth_mounts.delete_auth_backend("oidc");
        }
        Ok(())
    }
}

