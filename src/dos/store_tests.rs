//! Tests for [`crate::dos::store`], which lives in `bv-kernel-api`.
//!
//! They stayed behind for the reason recorded in Phase 1: they stand up a
//! whole vault through `crate::test_utils`, and a crate below the root cannot
//! depend on the root. Same shape as `src/storage_backend_tests.rs`.
//!
//! See roadmaps/workspace-decomposition.md § Phase 3.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::dos::{DosConfig, DosStore, ManualBan};
use crate::storage::Storage;
use crate::test_utils::new_unseal_test_bastion_vault;

/// Mirrors the private constant in `bv_kernel_api::dos::store`.
const DOS_STATE_KEY: &str = "dos/state";

mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn now_unix() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
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

        // Wipe any state persisted during unseal, then reload from an empty
        // store. Deleted through the system view rather than `store.view`,
        // which is private to `bv-kernel-api` — it is the same view the store
        // is built from.
        let store = DosStore::new(&core).unwrap();
        core.get_system_view().unwrap().delete(DOS_STATE_KEY).await.unwrap();
        assert!(store.get_stored().await.unwrap().is_none());

        core.load_dos_state().await.unwrap();
        // The seed survives, and is now persisted for stability.
        assert_eq!(core.dos_guard.config().max_requests, 5);
        assert_eq!(store.get_stored().await.unwrap().unwrap().config.max_requests, 5);
    }
}
