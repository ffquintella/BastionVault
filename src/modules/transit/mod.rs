//! Transit Secret Engine — encryption-as-a-service.
//!
//! Vault-compatible `/v1/transit/*` surface, pure-Rust crypto stack
//! built on `bv_crypto`. No OpenSSL, no `aws-lc-sys`.
//!
//! Phases shipped today:
//!
//!   * Phase 1 — symmetric AEAD (`chacha20-poly1305`), HMAC, random,
//!     hash, key versioning + rotate + trim.
//!   * Phase 2 (partial) — `ed25519` sign/verify. Classical RSA /
//!     ECDSA are deferred until operator demand surfaces.
//!   * Phase 3 — PQC: `ml-kem-768` (datakey wrap/unwrap),
//!     `ml-dsa-44/65/87` (sign/verify).
//!
//! Phase 4 (composite/hybrid sigs, BYOK import, convergent encryption)
//! is feature-gated and tracked in `features/transit-secret-engine.md`.

use std::{any::Any, sync::Arc};

use derive_more::Deref;

use crate::{
    core::Core,
    errors::RvError,
    logical::{Backend, LogicalBackend, Path},
    modules::Module,
};

pub mod backend;
pub mod crypto;
pub mod keytype;
pub mod path_datakey;
pub mod path_encrypt;
pub mod path_hmac;
#[cfg(feature = "transit_byok")]
pub mod path_import;
pub mod path_keys;
pub mod path_random;
pub mod path_sign;
pub mod policy;

const TRANSIT_BACKEND_HELP: &str = r#"
The Transit engine performs cryptographic operations on caller-supplied
data without ever storing the plaintext. Keys live inside the barrier,
rotate on demand, and carry their version inside every ciphertext /
signature so old material remains decryptable until trimmed.

Supported key types:
  * chacha20-poly1305 — symmetric AEAD (default).
  * hmac              — symmetric MAC only.
  * ed25519           — classical asymmetric signing.
  * ml-kem-768        — post-quantum KEM (datakey wrap/unwrap).
  * ml-dsa-{44,65,87} — post-quantum signing.

Operations:
  * keys CRUD + rotate + config + trim
  * encrypt / decrypt / rewrap   (symmetric AEAD only)
  * sign / verify                 (asymmetric signing keys)
  * hmac / verify-hmac            (any HMAC-capable key)
  * datakey/{plaintext,wrapped}   (KEM keys; KEM-derived 32-byte key)
  * datakey/unwrap                (recover the derived datakey)
  * random / hash                 (CSPRNG + SHA2 passthroughs)
"#;

pub struct TransitBackendInner {
    pub core: Arc<Core>,
}

#[derive(Deref)]
pub struct TransitBackend {
    #[deref]
    pub inner: Arc<TransitBackendInner>,
}

impl TransitBackend {
    pub fn new(core: Arc<Core>) -> Self {
        Self { inner: Arc::new(TransitBackendInner { core }) }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let paths: Vec<Path> = vec![
            self.keys_list_path(),
            self.keys_path(),
            self.rotate_path(),
            self.config_path(),
            self.trim_path(),
            self.encrypt_path(),
            self.decrypt_path(),
            self.rewrap_path(),
            self.sign_path(),
            self.verify_path(),
            self.hmac_path(),
            self.hmac_verify_path(),
            self.datakey_path(),
            self.datakey_unwrap_path(),
            self.random_path(),
            self.hash_path(),
            #[cfg(feature = "transit_byok")]
            self.wrapping_key_path(),
            #[cfg(feature = "transit_byok")]
            self.import_path(),
            #[cfg(feature = "transit_byok")]
            self.import_version_path(),
        ];
        let mut backend = LogicalBackend::new();
        for p in paths {
            backend.paths.push(Arc::new(p));
        }
        backend.help = TRANSIT_BACKEND_HELP.to_string();
        backend
    }
}

pub struct TransitModule {
    pub name: String,
    pub backend: Arc<TransitBackend>,
}

impl TransitModule {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            name: "transit".to_string(),
            backend: Arc::new(TransitBackend::new(core)),
        }
    }
}

impl Module for TransitModule {
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
        core.add_logical_backend("transit", Arc::new(new_func))
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        core.delete_logical_backend("transit")
    }
}
