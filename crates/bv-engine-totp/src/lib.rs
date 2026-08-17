//! TOTP Secret Engine (RFC 6238).
//!
//! Vault-compatible `/v1/totp/*` surface:
//!
//!   * `LIST   /v1/totp/keys`
//!   * `POST   /v1/totp/keys/:name`        — create (generate or provider)
//!   * `GET    /v1/totp/keys/:name`        — metadata only
//!   * `DELETE /v1/totp/keys/:name`
//!   * `GET    /v1/totp/code/:name`        — generate-mode current code
//!   * `POST   /v1/totp/code/:name`        — provider-mode validate
//!
//! Built on a pure-Rust crypto stack (`hmac` + `sha1` + `sha2` +
//! `subtle`). No OpenSSL, no `aws-lc-sys`. Seeds are barrier-encrypted
//! at rest and disclosed exactly once (in the create response, when
//! generate=true and exported=true).

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

pub mod backend;
pub mod barcode;
pub mod crypto;
pub mod kernel_service;
pub mod mfa;
pub mod path_code;
pub mod path_keys;
pub mod policy;
pub mod tidy;

const TOTP_BACKEND_HELP: &str = r#"
The TOTP engine generates and validates time-based one-time passwords
per RFC 6238. A key is created in one of two modes:

  * generate — the engine picks a fresh seed and returns a one-shot
    `otpauth://` URL (plus a QR PNG) for the operator to enroll into
    an authenticator app. Subsequent reads only return metadata.
  * provider — the operator imports an existing TOTP seed (raw base32
    or full `otpauth://` URL); the engine stores it sealed and
    validates submitted codes against it.

Codes are generated/validated via /code/:name. Replay protection is on
by default; flip `replay_check=false` for strict HashiCorp Vault parity.
"#;

pub struct TotpBackendInner {
    pub core: Arc<dyn VaultCtx>,
}

#[derive(Deref)]
pub struct TotpBackend {
    #[deref]
    pub inner: Arc<TotpBackendInner>,
}

impl TotpBackend {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self {
            inner: Arc::new(TotpBackendInner { core }),
        }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let paths: Vec<Path> = vec![
            self.keys_path(),
            self.keys_list_path(),
            self.code_path(),
        ];
        let mut backend = LogicalBackend::new();
        for p in paths {
            backend.paths.push(Arc::new(p));
        }
        backend.help = TOTP_BACKEND_HELP.to_string();
        backend
    }
}

pub struct TotpModule {
    pub name: String,
    pub backend: Arc<TotpBackend>,
}

impl TotpModule {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self {
            name: "totp".to_string(),
            backend: Arc::new(TotpBackend::new(core)),
        }
    }
}

impl Module for TotpModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn register(self: Arc<Self>, services: &crate::kernel_api::KernelServices) {
        kernel_service::register(self, services);
    }

    fn setup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        let backend = self.backend.clone();
        let new_func = move |_c: Arc<dyn VaultCtx>| -> Result<Arc<dyn Backend>, RvError> {
            let mut b = backend.new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };
        core.add_logical_backend("totp", Arc::new(new_func))
    }

    fn cleanup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        core.delete_logical_backend("totp")
    }
}
