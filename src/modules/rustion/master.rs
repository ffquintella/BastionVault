//! Master signing-cert configuration for the Rustion integration.
//!
//! Phase 1 ships the **slot** (a stable storage key under `rustion/`
//! that points at the PKI mount + role + issuer used to mint the
//! master cert) plus the public-key export shape. The actual
//! issue / rotate state machine sits on top of the PKI engine and
//! lands alongside the BVRG-v1 envelope crate in Phase 2 — by the
//! time we're ready to send envelopes, we need a real keypair.
//!
//! Forward design notes:
//!   - Default algorithm = hybrid Ed25519 + ML-DSA-65 (matches the
//!     authority record shape Rustion expects).
//!   - Default TTL = 5 years. Operators rotate by issuing a fresh
//!     cert under the same PKI role and co-signing the cutover
//!     envelope with the outgoing key for a window (`rotate_grace`).
//!   - Public-key export carries both halves separately so an
//!     operator pasting it into a Rustion `authorities/<name>.yaml`
//!     gets the same `pubkey.ed25519` / `pubkey.mldsa65` shape Rustion
//!     wants without further reformatting.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    bv_error_string,
    core::Core,
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

/// Storage sub-view: a single record at `rustion/master/config`. Kept
/// as a sub-view (rather than a top-level key) so future phases can
/// add neighbouring records (issued-cert history, rotation pending
/// state, …) without churning the layout.
const MASTER_SUB_PATH: &str = "rustion/master/";
const CONFIG_KEY: &str = "config";

/// On-disk shape of the master-cert configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MasterConfig {
    /// PKI mount the master cert is minted from (e.g. `pki-internal/`).
    /// Operators can rotate to a different mount in-band; existing
    /// envelopes stay valid until the old cert's `not_after`.
    pub pki_mount: String,
    /// PKI role under that mount. Defaults to `rustion-master` if a
    /// role of that name is present on first init; operators can
    /// point at any role whose CA matches the expected hybrid algo.
    pub pki_role: String,
    /// Issuer ref under the PKI mount. Empty = mount default.
    #[serde(default)]
    pub issuer_ref: String,
    /// Algorithm marker — informational, the PKI role pins the actual
    /// algorithm at issue time.
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// Default TTL when issuing / rotating, in seconds. 5y default.
    #[serde(default = "default_ttl_secs")]
    pub default_ttl_secs: u64,
    /// Grace window (seconds) during which the previous cert remains
    /// accepted by enrolled Rustions. Default 1 day.
    #[serde(default = "default_rotate_grace_secs")]
    pub rotate_grace_secs: u64,
    /// Most recently issued cert serial. Empty before the first issue.
    /// Surfaced in the GUI's "current master cert" panel; the actual
    /// cert bytes live in the PKI engine's cert store.
    #[serde(default)]
    pub current_serial: String,
    /// `not_after` of the current cert (ISO-8601). Empty before the
    /// first issue.
    #[serde(default)]
    pub current_not_after: Option<DateTime<Utc>>,
    /// Wallclock the config was last touched.
    pub updated_at: DateTime<Utc>,
}

fn default_algorithm() -> String {
    "hybrid-ed25519-mldsa65".to_string()
}

fn default_ttl_secs() -> u64 {
    // 5 years.
    5 * 365 * 24 * 3600
}

fn default_rotate_grace_secs() -> u64 {
    // 1 day.
    24 * 3600
}

/// Exported pubkey shape, mirrors the authority record on the Rustion
/// side so the operator can paste it directly into
/// `authorities/<name>.yaml`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct MasterPubKeyExport {
    pub algorithm: String,
    pub ed25519_pem: String,
    pub mldsa65_pem: String,
    pub fingerprint: String,
    pub current_serial: String,
    pub current_not_after: Option<DateTime<Utc>>,
}

pub struct MasterStore {
    view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl MasterStore {
    pub async fn new(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };
        let view = Arc::new(system_view.new_sub_view(MASTER_SUB_PATH));
        Ok(Arc::new(Self { view }))
    }

    pub async fn get(&self) -> Result<Option<MasterConfig>, RvError> {
        let Some(entry) = self.view.get(CONFIG_KEY).await? else {
            return Ok(None);
        };
        let cfg: MasterConfig = serde_json::from_slice(&entry.value)
            .map_err(|e| bv_error_string!(&format!("decode rustion master config: {e}")))?;
        Ok(Some(cfg))
    }

    pub async fn put(&self, cfg: &MasterConfig) -> Result<(), RvError> {
        let value = serde_json::to_vec(cfg)
            .map_err(|e| bv_error_string!(&format!("encode rustion master config: {e}")))?;
        self.view
            .put(&StorageEntry {
                key: CONFIG_KEY.to_string(),
                value,
            })
            .await
    }

    /// Convenience: load-or-default-with-now. The default record has
    /// `pki_mount` + `pki_role` empty so the API can present a
    /// "configure me" state to the GUI without persisting anything.
    pub async fn get_or_default(&self) -> Result<MasterConfig, RvError> {
        if let Some(cfg) = self.get().await? {
            return Ok(cfg);
        }
        Ok(MasterConfig {
            updated_at: Utc::now(),
            algorithm: default_algorithm(),
            default_ttl_secs: default_ttl_secs(),
            rotate_grace_secs: default_rotate_grace_secs(),
            ..Default::default()
        })
    }
}
