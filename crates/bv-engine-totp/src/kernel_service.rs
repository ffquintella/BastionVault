//! `TotpModule` as the vault's [`TotpMfa`] verifier.
//!
//! The userpass backend calls this at login and at step-up. It used to call
//! `crate::mfa::{normalize_mount, verify_code}` directly, which
//! put the TOTP engine in the credential backends' compile unit — and the
//! credential directory is the one the roadmap wants split into seven crates.
//!
//! The comparison itself stays in `mfa`: the skew walk is constant-time and
//! there must be exactly one of it.
//!
//! `verify_code` maps `TotpMfaError` to `RvError` here rather than at the call
//! sites. The mapping is lossless for the caller's purposes — every variant
//! means "the check could not run", which is never a pass.

use std::sync::Arc;

use crate::{errors::RvError, kernel_api::engines::TotpMfa};

use super::{mfa, TotpModule};

#[maybe_async::maybe_async]
impl TotpMfa for TotpModule {
    fn normalize_mount(&self, mount: &str) -> String {
        mfa::normalize_mount(mount)
    }

    async fn verify_code(
        &self,
        mount: &str,
        key_name: &str,
        code: &str,
        now_secs: u64,
    ) -> Result<bool, RvError> {
        mfa::verify_code(self.backend.core.as_ref(), mount, key_name, code, now_secs)
            .await
            .map_err(|e| crate::bv_error_string!(&e.to_string()))
    }
}

/// Publish the TOTP module as the vault's second-factor verifier.
pub fn register(module: Arc<TotpModule>, services: &crate::kernel_api::KernelServices) {
    services.set_totp_mfa(module);
}
