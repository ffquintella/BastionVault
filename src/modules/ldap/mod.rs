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

use std::{any::Any, sync::Arc};

use derive_more::Deref;

use crate::{
    core::Core,
    errors::RvError,
    logical::{Backend, LogicalBackend, Path},
    modules::Module,
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
    pub core: Arc<Core>,
}

#[derive(Deref)]
pub struct LdapBackend {
    #[deref]
    pub inner: Arc<LdapBackendInner>,
}

impl LdapBackend {
    pub fn new(core: Arc<Core>) -> Self {
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
    pub fn new(core: Arc<Core>) -> Self {
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

    fn setup(&self, core: &Core) -> Result<(), RvError> {
        let backend = self.backend.clone();
        let new_func = move |_c: Arc<Core>| -> Result<Arc<dyn Backend>, RvError> {
            let mut b = backend.new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };
        core.add_logical_backend("openldap", Arc::new(new_func))
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        core.delete_logical_backend("openldap")
    }
}
