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
//! [`crate::modules::rustion::policy::PolicyStore`] (`get_global`/`put_global`).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::bv_error_string;
use crate::core::Core;
use crate::errors::RvError;
use crate::storage::{barrier_view::BarrierView, Storage, StorageEntry};

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
    pub fn new(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::new_unseal_test_bastion_vault;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn config_and_manual_bans_round_trip() {
        let (_bv, core, _root) = new_unseal_test_bastion_vault("dos_store_round_trip").await;
        let store = DosStore::new(&core).unwrap();

        // Fresh install: defaults.
        let initial = store.get().await.unwrap();
        assert!(initial.manual_bans.is_empty());

        // Persist a config and read it back.
        let mut cfg = DosConfig::default();
        cfg.max_requests = 42;
        cfg.ban_secs = 111;
        store.put_config(&cfg).await.unwrap();
        assert_eq!(store.get().await.unwrap().config.max_requests, 42);

        // Add two manual bans.
        let now = now_unix();
        store
            .add_manual_ban(ManualBan { ip: ip("203.0.113.5"), until_unix: now + 600, reason: "a".into() })
            .await
            .unwrap();
        store
            .add_manual_ban(ManualBan { ip: ip("203.0.113.6"), until_unix: now + 600, reason: "b".into() })
            .await
            .unwrap();
        assert_eq!(store.get().await.unwrap().manual_bans.len(), 2);
        // Config survives a manual-ban write.
        assert_eq!(store.get().await.unwrap().config.max_requests, 42);

        // Re-banning the same IP replaces rather than duplicates.
        store
            .add_manual_ban(ManualBan { ip: ip("203.0.113.5"), until_unix: now + 900, reason: "a2".into() })
            .await
            .unwrap();
        let state = store.get().await.unwrap();
        assert_eq!(state.manual_bans.len(), 2);
        assert_eq!(state.manual_bans.iter().find(|b| b.ip == ip("203.0.113.5")).unwrap().reason, "a2");

        // Remove one.
        assert!(store.remove_manual_ban(ip("203.0.113.5")).await.unwrap());
        assert!(!store.remove_manual_ban(ip("203.0.113.5")).await.unwrap());
        assert_eq!(store.get().await.unwrap().manual_bans.len(), 1);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn core_helpers_persist_and_reload_into_guard() {
        let (_bv, core, _root) = new_unseal_test_bastion_vault("dos_core_helpers").await;

        // set_dos_config persists and updates the live guard.
        let mut cfg = DosConfig::default();
        cfg.max_requests = 7;
        core.set_dos_config(cfg).await.unwrap();
        assert_eq!(core.dos_guard.config().max_requests, 7);

        // A manual ban is enforced by the guard and survives a fresh reload
        // from storage (simulating another HA node / a restart).
        let victim = ip("198.51.100.20");
        core.dos_manual_ban(victim, 600, "operator block").await.unwrap();
        assert!(core.dos_guard.check(victim, "/v1/x").is_err());

        // Drop the in-memory ban, then reload persisted state — it comes back.
        core.dos_guard.unban(victim);
        assert!(core.dos_guard.check(victim, "/v1/x").is_ok());
        core.load_dos_state().await.unwrap();
        assert!(core.dos_guard.check(victim, "/v1/x").is_err());
        // Reloaded config is the persisted one, not the default.
        assert_eq!(core.dos_guard.config().max_requests, 7);

        // Unban clears both memory and storage.
        assert!(core.dos_unban(victim).await.unwrap());
        core.load_dos_state().await.unwrap();
        assert!(core.dos_guard.check(victim, "/v1/x").is_ok());
    }

    // Regression: a fresh install (nothing persisted) must keep the guard's
    // seeded config rather than overwriting it with defaults. Previously
    // `load_dos_state` read a defaulted value and clobbered the `[dos]` seed.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn load_dos_state_preserves_seed_when_nothing_persisted() {
        let (_bv, core, _root) = new_unseal_test_bastion_vault("dos_seed_preserved").await;
        // Simulate the startup `[dos]` seed applied in BastionVault::new.
        let mut seed = DosConfig::default();
        seed.max_requests = 5;
        seed.window_secs = 60;
        core.dos_guard.set_config(seed);

        // Wipe any state persisted during unseal, then reload from an empty store.
        let store = DosStore::new(&core).unwrap();
        store.view.delete(DOS_STATE_KEY).await.unwrap();
        assert!(store.get_stored().await.unwrap().is_none());

        core.load_dos_state().await.unwrap();
        // The seed survives, and is now persisted for stability.
        assert_eq!(core.dos_guard.config().max_requests, 5);
        assert_eq!(store.get_stored().await.unwrap().unwrap().config.max_requests, 5);
    }
}
