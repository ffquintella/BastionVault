//! Barrier-persisted DoS-protection state.
//!
//! Persists exactly two things: the [`DosConfig`] thresholds and the set of
//! *manual* bans. Both are written through the core system view (barrier root
//! `sys/`), so they are transparently encrypted and — under the Hiqlite
//! backend — replicated across the HA cluster. Automatic bans and live
//! per-IP counters are intentionally **not** persisted; they are ephemeral
//! per-node state owned by [`super::guard::DosGuard`].
//!
//! Mirrors the singleton-config shape of
//! `bastion_vault::modules::rustion::policy::PolicyStore` (`get_global`/`put_global`).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use bv_errors::bv_error_string;
use bv_errors::RvError;
use bv_storage::{barrier_view::BarrierView, Storage, StorageEntry};

use crate::ctx::VaultCtx;

use super::config::DosConfig;
use super::guard::ManualBan;

/// System-view key holding the serialized [`PersistedDosState`]. Resolves to
/// the barrier key `sys/dos/state`.
const DOS_STATE_KEY: &str = "dos/state";

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The on-disk shape of the DoS subsystem's durable state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PersistedDosState {
    pub config: DosConfig,
    pub manual_bans: Vec<ManualBan>,
}

pub struct DosStore {
    view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl DosStore {
    /// Build a store bound to the core's system view. Errors when the vault is
    /// sealed (no system view available).
    pub fn new(core: &dyn VaultCtx) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.system_view() else {
            return Err(RvError::ErrBarrierSealed);
        };
        Ok(Arc::new(Self { view: system_view }))
    }

    /// Read the persisted state, or `None` when nothing has been written yet
    /// (fresh install). The `None` case is distinct from a stored all-defaults
    /// value, so callers can tell "never configured" from "configured to the
    /// defaults" — the startup `[dos]` seed depends on this.
    pub async fn get_stored(&self) -> Result<Option<PersistedDosState>, RvError> {
        match self.view.get(DOS_STATE_KEY).await? {
            Some(entry) => serde_json::from_slice(&entry.value)
                .map(Some)
                .map_err(|e| bv_error_string!(&format!("decode dos state: {e}"))),
            None => Ok(None),
        }
    }

    /// Read the persisted state, defaulting a missing key. Used by the CRUD
    /// handlers, which always want a concrete value to mutate.
    pub async fn get(&self) -> Result<PersistedDosState, RvError> {
        Ok(self.get_stored().await?.unwrap_or_default())
    }

    async fn put(&self, state: &PersistedDosState) -> Result<(), RvError> {
        let value = serde_json::to_vec(state)
            .map_err(|e| bv_error_string!(&format!("encode dos state: {e}")))?;
        self.view.put(&StorageEntry { key: DOS_STATE_KEY.to_string(), value }).await
    }

    /// Persist new thresholds, leaving the manual-ban set untouched.
    pub async fn put_config(&self, cfg: &DosConfig) -> Result<(), RvError> {
        let mut state = self.get().await?;
        state.config = cfg.clone();
        self.put(&state).await
    }

    /// Record a manual ban, replacing any prior ban for the same IP and
    /// dropping records that have already expired.
    pub async fn add_manual_ban(&self, ban: ManualBan) -> Result<(), RvError> {
        let mut state = self.get().await?;
        let now = now_unix();
        state.manual_bans.retain(|b| b.ip != ban.ip && b.until_unix > now);
        state.manual_bans.push(ban);
        self.put(&state).await
    }

    /// Remove a manual ban for `ip`. Returns whether a record existed.
    pub async fn remove_manual_ban(&self, ip: IpAddr) -> Result<bool, RvError> {
        let mut state = self.get().await?;
        let before = state.manual_bans.len();
        state.manual_bans.retain(|b| b.ip != ip);
        let removed = state.manual_bans.len() != before;
        if removed {
            self.put(&state).await?;
        }
        Ok(removed)
    }
}
