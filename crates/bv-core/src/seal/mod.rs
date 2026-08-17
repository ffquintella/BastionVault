//! Seal providers — how the barrier KEK is protected at rest and recovered.
//!
//! Historically BastionVault split the KEK with Shamir's Secret Sharing and
//! required operators to supply a threshold of shares at every unseal. The
//! [`SealProvider`] trait factors that decision out so the KEK lifecycle can be
//! anchored in an HSM instead (auto-unseal, [`hsm::HsmSealProvider`]) without
//! touching the operator share-collection state machine in
//! [`crate::core::Core::do_unseal`].
//!
//! * [`ShamirSealProvider`] reproduces the classic behavior: at init it splits
//!   the KEK into shares to hand back to the operator; it never auto-unseals.
//! * [`hsm::HsmSealProvider`] wraps the KEK under the local HSM at init and
//!   recovers it with a signed, audited unwrap at startup — no operator input.

use zeroize::Zeroizing;

use crate::{core::SealConfig, errors::RvError, shamir::ShamirSecret};

pub mod hsm;

/// Abstraction over KEK custody at rest.
#[maybe_async::maybe_async]
pub trait SealProvider: Send + Sync {
    /// `"shamir"` | `"hsm"`.
    fn seal_type(&self) -> &str;

    /// Whether unseal needs operator-supplied shares. `false` ⇒ auto-unseal.
    fn requires_shares(&self) -> bool;

    /// Persist whatever recovery material this provider needs for the freshly
    /// generated `kek`, and return the shares to hand back to the operator
    /// (empty for auto-unseal providers).
    async fn init_kek(&self, kek: &[u8], seal_config: &SealConfig) -> Result<Zeroizing<Vec<Vec<u8>>>, RvError>;

    /// Recover the KEK with no operator input. Only meaningful when
    /// [`Self::requires_shares`] is `false`; share-based providers return
    /// [`RvError::ErrBarrierUnsealing`].
    async fn recover_kek(&self) -> Result<Zeroizing<Vec<u8>>, RvError>;

    /// Provider-specific status for the `v2/sys/hsm/status` endpoint. Must not
    /// include secret material — safe for operator reporting.
    async fn status(&self) -> Result<serde_json::Value, RvError> {
        Ok(serde_json::json!({ "type": self.seal_type(), "auto_unseal": !self.requires_shares() }))
    }
}

/// Classic Shamir seal: split the KEK for the operator, no auto-unseal.
#[derive(Default)]
pub struct ShamirSealProvider;

impl ShamirSealProvider {
    pub fn new() -> Self {
        Self
    }
}

#[maybe_async::maybe_async]
impl SealProvider for ShamirSealProvider {
    fn seal_type(&self) -> &str {
        "shamir"
    }

    fn requires_shares(&self) -> bool {
        true
    }

    async fn init_kek(&self, kek: &[u8], seal_config: &SealConfig) -> Result<Zeroizing<Vec<Vec<u8>>>, RvError> {
        // Mirrors the original `Core::init` share step: a 1-of-1 config returns
        // the raw KEK as the single share; otherwise split T-of-N.
        if seal_config.secret_shares == 1 {
            Ok(Zeroizing::new(vec![kek.to_vec()]))
        } else {
            ShamirSecret::split(kek, seal_config.secret_shares, seal_config.secret_threshold)
        }
    }

    async fn recover_kek(&self) -> Result<Zeroizing<Vec<u8>>, RvError> {
        // Shamir unseal is operator-driven and multi-step; it flows through
        // `Core::do_unseal`, not through auto-recovery.
        Err(RvError::ErrBarrierUnsealing)
    }
}
