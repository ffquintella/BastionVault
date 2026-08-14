//! OpenLDAP / Active Directory password-rotation secret engine.
//!
//! Vault-compatible `/v1/openldap/*` surface; same path shapes as
//! HashiCorp Vault's `openldap` engine v1 (`config`, `static-role`,
//! `static-cred`, `rotate-role`, `library`, `library/<set>/check-{out,in}`,
//! `library/<set>/status`, `rotate-root`). Pure-Rust LDAP client via
//! `ldap3` (`tls-rustls-aws-lc-rs` feature) — no `libldap` /
//! `libsasl` / OpenSSL dependency.
//!
//! Phases shipped today:
//!
//!   * **Phase 1 — connection + static roles**. `config` CRUD with
//!     two-flag `insecure_tls` opt-in, `static-role` CRUD, on-demand
//!     `rotate-role` that writes the new password to the directory
//!     first and persists in storage second (rotation atomicity per
//!     the spec), `static-cred` reads that surface the
//!     last-rotated password + `last_vault_rotation_unix` + a
//!     synthetic `ttl_secs` against the role's `rotation_period`.
//!   * **Phase 2 — library check-out / check-in**. Per-mount mutex
//!     gates concurrent check-outs against the same set; lease-id
//!     minted as `ldap-library-<uuid>`; check-in rotates again and
//!     deletes the marker; `disable_check_in_enforcement = false`
//!     guards check-in against the caller's identity via
//!     `subtle::ConstantTimeEq`.
//!   * **Phase 3 — `rotate-root`**. Manual; auto-rotation scheduler
//!     remains a follow-up that hooks into `Core::post_unseal` once
//!     the engine has operator demand.
//!
//! Phases 4 (GUI) and 5 (identity-aware affinity) are tracked in
//! `features/ldap-secret-engine.md` and are independent of the
//! engine itself shipping.

// The substrate, under the names the LDAP engine has always spelled it. Private:
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
    logical::{Backend, LogicalBackend, Path},
};

pub mod client;
pub mod config;
pub mod password;
pub mod path_config;
pub mod path_library;
pub mod path_static;
pub mod policy;
pub mod scheduler;

const LDAP_BACKEND_HELP: &str = r#"
The OpenLDAP / Active Directory engine owns password rotation for
service accounts in the configured directory.

Two access modes per account:
  * static-role — long-lived account, rotated on demand or schedule.
  * library check-out / check-in — pool of pre-provisioned accounts
    shared across automation; check-out leases an account, check-in
    rotates and releases.

`bindpass`, `password`, and `client_tls_key` are HMAC'd in audit
logs by default. The plaintext password is returned to the caller
on `static-cred` reads and `check-out` responses; restrict those
paths to short-lived, narrowly-scoped tokens.
"#;

pub struct LdapBackendInner {
    pub core: Arc<dyn VaultCtx>,
}

#[derive(Deref)]
pub struct LdapBackend {
    #[deref]
    pub inner: Arc<LdapBackendInner>,
}

impl LdapBackend {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self {
            inner: Arc::new(LdapBackendInner { core }),
        }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let paths: Vec<Path> = vec![
            self.config_path(),
            self.rotate_root_path(),
            self.check_connection_path(),
            self.static_role_path(),
            self.static_role_list_path(),
            self.static_cred_path(),
            self.rotate_role_path(),
            self.library_set_path(),
            self.library_list_path(),
            self.library_check_out_path(),
            self.library_check_in_path(),
            self.library_status_path(),
        ];
        let mut backend = LogicalBackend::new();
        for p in paths {
            backend.paths.push(Arc::new(p));
        }
        backend.help = LDAP_BACKEND_HELP.to_string();
        backend
    }
}

pub struct LdapModule {
    pub name: String,
    pub backend: Arc<LdapBackend>,
}

impl LdapModule {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self {
            name: "openldap".to_string(),
            backend: Arc::new(LdapBackend::new(core)),
        }
    }
}

impl Module for LdapModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    /// Boot the OpenLDAP / AD static-role auto-rotation sweep (Phase 3).
    /// Ticks every 60s; per-role cadence comes from each role's persisted
    /// `rotation_period`, and roles with `rotation_period = 0` are skipped.
    fn start_background(&self, core: Arc<dyn VaultCtx>) {
        // Detached on purpose: dropping the handle does not stop the task.
        drop(scheduler::start_ldap_rotation_scheduler(core));
    }

    fn setup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        let backend = self.backend.clone();
        let new_func = move |_c: Arc<dyn VaultCtx>| -> Result<Arc<dyn Backend>, RvError> {
            let mut b = backend.new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };
        core.add_logical_backend("openldap", Arc::new(new_func))
    }

    fn cleanup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        core.delete_logical_backend("openldap")
    }
}
