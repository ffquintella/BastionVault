//! SSH Secret Engine (Phase 1 — CA mode, Ed25519 only).
//!
//! Mirrors HashiCorp Vault's `ssh` engine surface so existing clients
//! (`vault write ssh/sign/<role> …`) work unchanged. The route table:
//!
//!   * `POST /ssh/config/ca` — generate or import the CA keypair
//!   * `GET  /ssh/config/ca` — read the public-side metadata
//!   * `DELETE /ssh/config/ca` — drop the CA (rotation)
//!   * `GET  /ssh/public_key` — convenience read of the OpenSSH pubkey
//!   * `POST /ssh/roles/:name`, `GET`, `DELETE`
//!   * `LIST /ssh/roles`
//!   * `POST /ssh/sign/:role` — sign a client public key
//!
//! Phases 2-4 add OTP roles, PQC algorithms (ML-DSA-65), and a GUI.
//! The route handlers live in their own files (`path_*.rs`) so each
//! gets its own focused review surface; this file only wires them up.

// The substrate, under the names the SSH engine has always spelled it. Private:
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

pub mod otp;
pub mod path_config_ca;
pub mod path_creds;
pub mod path_lookup;
pub mod path_roles;
pub mod path_sign;
pub mod policy;
pub mod ssh_ca_audit_store;
pub mod ssh_sign_audit_store;
#[cfg(feature = "ssh_pqc")]
pub mod pqc;

const SSH_BACKEND_HELP: &str = r#"
The SSH engine issues short-lived SSH credentials in two modes:

  * CA mode (Phase 1): POST a public key to `/sign/:role` to receive
    an OpenSSH certificate constrained by the role's principals,
    extensions, critical options, and TTL caps. Phase 1 supports
    Ed25519.
  * OTP mode (Phase 2): POST `/creds/:role` to mint a one-time
    password for a single SSH session against a target host that
    runs `bv-ssh-helper`. The helper validates the OTP via
    `/verify`. Use `/lookup` to find which OTP roles cover an
    `(ip, username)` pair without consuming a credential.
"#;

pub struct SshBackendInner {
    pub core: Arc<dyn VaultCtx>,
}

#[derive(Deref)]
pub struct SshBackend {
    #[deref]
    pub inner: Arc<SshBackendInner>,
}

impl SshBackend {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self {
            inner: Arc::new(SshBackendInner { core }),
        }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let paths: Vec<Path> = vec![
            self.config_ca_path(),
            self.public_key_path(),
            self.roles_path(),
            self.roles_list_path(),
            self.sign_path(),
            self.creds_path(),
            self.verify_path(),
            self.lookup_path(),
        ];
        let mut backend = LogicalBackend::new();
        for p in paths {
            backend.paths.push(Arc::new(p));
        }
        backend.help = SSH_BACKEND_HELP.to_string();
        backend
    }
}

pub struct SshModule {
    pub name: String,
    pub backend: Arc<SshBackend>,
}

impl SshModule {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self {
            name: "ssh".to_string(),
            backend: Arc::new(SshBackend::new(core)),
        }
    }
}

impl Module for SshModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        let backend = self.backend.clone();
        let new_func = move |_c: Arc<dyn VaultCtx>| -> Result<Arc<dyn Backend>, RvError> {
            let mut b = backend.new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };
        core.add_logical_backend("ssh", Arc::new(new_func))
    }

    fn cleanup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        core.delete_logical_backend("ssh")
    }
}
