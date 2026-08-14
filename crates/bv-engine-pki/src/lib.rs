//! PKI Secret Engine (Phase 1).
//!
//! Pure-Rust X.509 stack — `rcgen` for DER assembly, RustCrypto under the
//! hood for primitives. No OpenSSL, no aws-lc-sys. Phase 2 will plug ML-DSA
//! signers behind the same `CertSigner` seam used here. See
//! [features/pki-secret-engine.md](../../../features/pki-secret-engine.md)
//! for the full design and roadmap.

// The substrate, under the names this engine's 27 files have always spelled
// it. Private: `crate::errors::RvError` and `crate::logical::Path` keep
// resolving inside the crate, and none of it leaks into the public API, so the
// extraction stayed a file move instead of an import rewrite across 15,127
// lines. See roadmaps/workspace-decomposition.md § Phase 3.
// `storage` is deliberately absent from this list: this engine has its own
// `storage` module (the PKI key layout), and it wins the name. The handful of
// files that want the substrate's `Storage`/`StorageEntry` import them from
// `bv_storage` directly.
use bv_context as context;
use bv_errors as errors;
use bv_kernel_api as kernel_api;
use bv_logical as logical;
use bv_utils as utils;

// The eight backend-definition macros are `#[macro_export]`ed by `bv-logical`,
// which places them at *that* crate's root; the call sites import them as
// `crate::new_path` and friends. Same arrangement the root crate uses, and the
// `_internal` halves are the recursive arms the public macros expand into, so
// they must travel with them.
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

pub mod acme;
pub mod ad_ext;
#[cfg(feature = "pki_pqc_composite")]
pub mod composite;
pub mod crypto;
pub mod csr;
pub mod export;
pub mod issuers;
pub mod keys;
pub mod path_config;
pub mod path_csr;
pub mod path_export;
pub mod path_keys;
pub mod path_intermediate;
pub mod path_issuers;
pub mod path_crl;
pub mod path_fetch;
pub mod path_issue;
pub mod path_revoke;
pub mod path_roles;
pub mod path_root;
pub mod path_tidy;
pub mod scheduler;
pub mod pqc;
pub mod storage;
pub mod x509;
#[cfg(feature = "pki_pqc_composite")]
pub mod x509_composite;
pub mod x509_pqc;

const PKI_BACKEND_HELP: &str = r#"
The PKI engine issues X.509 certificates against a self-managed CA. Phase 1
provides the classical algorithm set (RSA, ECDSA P-256/P-384, Ed25519) on a
pure-Rust stack. Post-quantum (ML-DSA) roles land in Phase 2.

The route surface is intentionally Vault-compatible so existing clients keep
working unchanged. Endpoints not yet implemented in Phase 1 return a clear
"unsupported operation" error rather than a 404.
"#;

pub struct PkiBackendInner {
    pub core: Arc<dyn VaultCtx>,
}

#[derive(Deref)]
pub struct PkiBackend {
    #[deref]
    pub inner: Arc<PkiBackendInner>,
}

impl PkiBackend {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self { inner: Arc::new(PkiBackendInner { core }) }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let paths: Vec<Path> = vec![
            self.roles_path(),
            self.roles_list_path(),
            self.root_generate_path(),
            self.root_sign_intermediate_path(),
            self.intermediate_generate_path(),
            self.intermediate_set_signed_path(),
            self.csr_generate_path(),
            self.csr_list_path(),
            self.csr_set_signed_path(),
            self.csr_item_path(),
            self.cert_export_path(),
            self.issuer_export_path(),
            self.issue_path(),
            self.sign_path(),
            self.sign_verbatim_path(),
            self.tidy_path(),
            self.tidy_status_path(),
            self.config_auto_tidy_path(),
            self.fetch_cert_path(),
            self.cert_key_path(),
            self.fetch_ca_path(),
            self.fetch_ca_chain_path(),
            self.list_certs_path(),
            self.import_cert_path(),
            // ── L1 managed key store ──
            self.keys_list_path(),
            self.keys_generate_path(),
            self.keys_import_path(),
            self.key_path(),
            self.revoke_path(),
            self.crl_path(),
            self.crl_rotate_path(),
            self.issuer_crl_path(),
            self.issuers_list_path(),
            self.issuer_path(),
            self.issuer_chain_path(),
            self.config_issuers_path(),
            self.config_ca_path(),
            self.config_urls_path(),
            self.config_crl_path(),
            // ── ACME server endpoints (Phase 6.1 + 6.1.5) ──
            self.acme_config_path(),
            self.acme_directory_path(),
            self.acme_new_nonce_path(),
            self.acme_new_account_path(),
            self.acme_account_path(),
            self.acme_new_order_path(),
            self.acme_order_path(),
            self.acme_finalize_path(),
            self.acme_authz_path(),
            self.acme_chall_path(),
            self.acme_cert_path(),
            self.acme_revoke_path(),
            self.acme_eab_path(),
            self.acme_key_change_path(),
        ];

        // The `new_logical_backend!` macro takes a literal path-list. We build
        // ours dynamically because there are 20 routes and several are
        // generated by helper methods on `PkiBackend`. The init step (which
        // compiles regexes) runs in `setup()`.
        let mut backend = LogicalBackend::new();
        for p in paths {
            backend.paths.push(Arc::new(p));
        }
        // ACME protocol endpoints are unauthenticated at the engine
        // layer — JWS in the request body is the auth.
        // `acme/config` stays authenticated (operator config, not
        // protocol surface).
        backend.unauth_paths = Arc::new(
            acme::UNAUTH_PATHS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        );
        backend.help = PKI_BACKEND_HELP.to_string();
        backend
    }
}

pub struct PkiModule {
    pub name: String,
    pub backend: Arc<PkiBackend>,
}

impl PkiModule {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self { name: "pki".to_string(), backend: Arc::new(PkiBackend::new(core)) }
    }
}

impl Module for PkiModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    /// Boot the auto-tidy sweep (Phase 4.1). Ticks every 30s; per-mount
    /// cadence comes from each mount's persisted `pki/config/auto-tidy`, so a
    /// deployment that configures none is a no-op.
    fn start_background(&self, core: Arc<dyn VaultCtx>) {
        // Detached on purpose: dropping the handle does not stop the task.
        drop(scheduler::start_pki_tidy_scheduler(core));
    }

    fn setup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        let backend = self.backend.clone();
        let new_func = move |_c: Arc<dyn VaultCtx>| -> Result<Arc<dyn Backend>, RvError> {
            let mut b = backend.new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };
        core.add_logical_backend("pki", Arc::new(new_func))
    }

    fn cleanup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        core.delete_logical_backend("pki")
    }
}
