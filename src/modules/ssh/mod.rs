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

use std::{any::Any, sync::Arc};

use derive_more::Deref;

use crate::{
    core::Core,
    errors::RvError,
    logical::{Backend, LogicalBackend, Path},
    modules::Module,
};

pub mod path_config_ca;
pub mod path_roles;
pub mod path_sign;
pub mod policy;

const SSH_BACKEND_HELP: &str = r#"
The SSH engine signs short-lived OpenSSH client certificates against a
self-managed CA. Phase 1 supports Ed25519 in CA mode. POST a public
key to `/sign/:role` to receive an OpenSSH cert constrained by the
role's principals, extensions, critical options, and TTL caps.
"#;

pub struct SshBackendInner {
    pub core: Arc<Core>,
}

#[derive(Deref)]
pub struct SshBackend {
    #[deref]
    pub inner: Arc<SshBackendInner>,
}

impl SshBackend {
    pub fn new(core: Arc<Core>) -> Self {
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
    pub fn new(core: Arc<Core>) -> Self {
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

    fn setup(&self, core: &Core) -> Result<(), RvError> {
        let backend = self.backend.clone();
        let new_func = move |_c: Arc<Core>| -> Result<Arc<dyn Backend>, RvError> {
            let mut b = backend.new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };
        core.add_logical_backend("ssh", Arc::new(new_func))
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        core.delete_logical_backend("ssh")
    }
}
