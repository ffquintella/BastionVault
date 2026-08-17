//! `Core`'s own tests, which could not travel with it into `bv-core`.
//!
//! Two reasons, both the recurring Phase 1 pattern: they drive
//! `test_utils::new_unseal_test_bastion_vault`, which stands up a whole vault
//! from the assembly layer, and one of them reaches
//! `modules::auth::AuthModule` — the kernel tier, which sits *above* `bv-core`.
//! A crate cannot test itself through the crates built on top of it.
//!
//! Fourth instance of this, after `storage_backend_tests.rs`,
//! `dos/store_tests.rs` and `metrics/{http,system}_metrics_tests.rs`. See
//! roadmaps/workspace-decomposition.md § Phase 4.5.

mod test {
    use crate::kernel_api::VaultCtx;
    use crate::{errors::RvError, test_utils::new_unseal_test_bastion_vault};

    #[test]
    #[allow(clippy::let_underscore_future)]
    fn test_core_init() {
        let _ = new_unseal_test_bastion_vault("test_core_init");
    }

    /// `Core::flush_caches` must clear the token cache so a previously
    /// cached entry can no longer be served without a storage re-read.
    /// Regression for the seal path: pre_seal invokes this helper, and
    /// a missed flush would leave live token payloads in memory after
    /// the unseal key has been released.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_core_flush_caches_empties_token_cache() {
        use crate::modules::auth::{
            token_store::TokenEntry, AuthModule,
        };

        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_core_flush_caches_empties_token_cache").await;

        let auth_module = core
            .module_manager
            .get_module::<AuthModule>("auth")
            .expect("auth module must exist in a default unseal");
        let token_store =
            auth_module.token_store.load_full().expect("token store must be installed");

        // The root token is already in storage; force a cache-populating
        // lookup, then verify the cache has it.
        let _ = token_store.lookup(&root_token).await.unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let salted = token_store.salt_id(&root_token);
        assert!(
            token_store.token_cache.as_ref().unwrap().lookup::<TokenEntry>(&salted).is_some(),
            "precondition: cache must be populated before flush"
        );

        // Also populate with a freshly created token so the test isn't
        // contingent on lookup behaviour alone.
        let mut entry = TokenEntry {
            policies: vec!["default".into()],
            path: "auth/token/create".into(),
            display_name: "flush-probe".into(),
            ..TokenEntry::default()
        };
        token_store.create(&mut entry).await.unwrap();
        token_store.lookup(&entry.id).await.unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let salted_probe = token_store.salt_id(&entry.id);
        assert!(token_store.token_cache.as_ref().unwrap().lookup::<TokenEntry>(&salted_probe).is_some());

        core.flush_caches();
        std::thread::sleep(std::time::Duration::from_millis(100));

        assert!(
            token_store.token_cache.as_ref().unwrap().lookup::<TokenEntry>(&salted).is_none(),
            "flush_caches must drop the root-token entry"
        );
        assert!(
            token_store.token_cache.as_ref().unwrap().lookup::<TokenEntry>(&salted_probe).is_none(),
            "flush_caches must drop every token cache entry"
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_generate_unseal_keys_basic() {
        let (_bvault, core, _) = new_unseal_test_bastion_vault("test_generate_unseal_keys_basic").await;

        // Test that generate_unseal_keys works when unsealed
        let result = core.generate_unseal_keys().await;
        assert!(result.is_ok());

        let keys = result.unwrap();
        let seal_config = core.seal_config().await.unwrap();
        assert_eq!(keys.len(), seal_config.secret_shares as usize); // Default test configuration: 3 shares

        // Each key should have the expected length (key bytes + 1 byte Shamir overhead)
        // ChaCha20Poly1305 barrier uses 64-byte ML-KEM-768 seeds, AES-GCM uses 32-byte keys
        let (min_key_len, _) = core.barrier().key_length_range();
        let expected_key_len = min_key_len + crate::shamir::SHAMIR_OVERHEAD;
        for key in keys.iter() {
            assert_eq!(key.len(), expected_key_len);
        }

        // Keys should be unique
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j]);
            }
        }
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_generate_unseal_keys_when_sealed() {
        let (_bvault, core, _) = new_unseal_test_bastion_vault("test_generate_unseal_keys_when_sealed").await;

        // Seal the vault
        let seal_result = core.seal().await;
        assert!(seal_result.is_ok());

        // Should fail when sealed
        let result = core.generate_unseal_keys().await;
        assert!(result.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_generate_unseal_keys_multiple_calls() {
        let (_bvault, core, _) = new_unseal_test_bastion_vault("test_generate_unseal_keys_multiple_calls").await;

        // Generate keys multiple times
        let keys1 = core.generate_unseal_keys().await.unwrap();
        let keys2 = core.generate_unseal_keys().await.unwrap();
        let keys3 = core.generate_unseal_keys().await.unwrap();

        // All should succeed and produce the same number of keys
        assert_eq!(keys1.len(), keys2.len());
        assert_eq!(keys2.len(), keys3.len());

        // But keys should be different (due to randomness in Shamir sharing)
        assert_ne!(keys1[0], keys2[0]);
        assert_ne!(keys2[0], keys3[0]);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_unseal_once_basic() {
        let (_bvault, core, _) = new_unseal_test_bastion_vault("test_unseal_once_basic").await;

        // Get initial keys for testing
        let initial_keys = core.generate_unseal_keys().await.unwrap();

        // Seal the vault
        core.seal().await.unwrap();

        // Test unseal_once with sufficient keys
        let mut new_keys = None;
        for key in initial_keys.iter() {
            match core.unseal_once(key).await {
                Ok(keys) => {
                    new_keys = Some(keys);
                    break;
                }
                Err(_) => continue,
            }
        }

        assert!(new_keys.is_some());
        let new_keys = new_keys.unwrap();
        let seal_config = core.seal_config().await.unwrap();
        assert_eq!(new_keys.len(), seal_config.secret_shares as usize); // Should generate new keys

        // Vault should be unsealed
        assert!(!core.sealed());

        // New keys should be different from initial keys
        assert_ne!(initial_keys[0], new_keys[0]);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_unseal_once_insufficient_keys() {
        let (_bvault, core, _) = new_unseal_test_bastion_vault("test_unseal_once_insufficient_keys").await;

        // Get initial keys
        let initial_keys = core.generate_unseal_keys().await.unwrap();

        // Seal the vault
        core.seal().await.unwrap();

        // Try unseal_once with just one key (insufficient for threshold=2)
        let result = core.unseal_once(&initial_keys[0]).await;
        assert!(result.is_err());

        // Vault should still be sealed
        assert!(core.sealed());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_unseal_once_key_deprecation() {
        let (_bvault, core, _) = new_unseal_test_bastion_vault("test_unseal_once_key_deprecation").await;

        // Get initial keys
        let initial_keys = core.generate_unseal_keys().await.unwrap();

        // Seal the vault
        core.seal().await.unwrap();

        // Use unseal_once to unseal
        let mut new_keys = None;
        for key in initial_keys.iter() {
            match core.unseal_once(key).await {
                Ok(keys) => {
                    new_keys = Some(keys);
                    break;
                }
                Err(_) => continue,
            }
        }

        assert!(new_keys.is_some());
        let new_keys = new_keys.unwrap();
        let seal_config = core.seal_config().await.unwrap();
        assert_eq!(new_keys.len(), seal_config.secret_shares as usize);

        // Seal again
        core.seal().await.unwrap();

        // Try to use the same key again - should fail due to deprecation
        for i in 0..5 {
            let result = core.unseal_once(&initial_keys[i]).await;
            assert!(matches!(result, Err(RvError::ErrBarrierKeyDeprecated)));
        }

        for i in 5..initial_keys.len() {
            let result = core.unseal_once(&initial_keys[i]).await;
            assert!(matches!(result, Err(RvError::ErrBarrierUnsealing)));
        }
        let result = core.unseal_once(&new_keys[0]).await;
        assert!(matches!(result, Err(RvError::ErrBarrierUnsealFailed)));

        // But new keys should work
        let mut new_keys2 = None;
        for key in new_keys.iter() {
            match core.unseal_once(key).await {
                Ok(keys) => {
                    new_keys2 = Some(keys);
                    break;
                }
                Err(_) => continue,
            }
        }

        assert!(new_keys2.is_some());
        let new_keys2 = new_keys2.unwrap();
        let seal_config = core.seal_config().await.unwrap();
        assert_eq!(new_keys2.len(), seal_config.secret_shares as usize);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_unseal_once_when_already_unsealed() {
        let (_bvault, core, _) = new_unseal_test_bastion_vault("test_unseal_once_when_already_unsealed").await;

        // Get keys for testing
        let keys = core.generate_unseal_keys().await.unwrap();

        // Vault is already unsealed, so unseal_once should fail
        let result = core.unseal_once(&keys[0]).await;
        assert!(result.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_unseal_once_forward_secrecy() {
        let (_bvault, core, _) = new_unseal_test_bastion_vault("test_unseal_once_forward_secrecy").await;

        // Get initial keys
        let keys1 = core.generate_unseal_keys().await.unwrap();

        // Seal and unseal_once to get new keys
        core.seal().await.unwrap();
        let mut keys2 = None;
        for key in keys1.iter() {
            match core.unseal_once(key).await {
                Ok(keys) => {
                    keys2 = Some(keys);
                    break;
                }
                Err(_) => continue,
            }
        }

        assert!(keys2.is_some());
        let keys2 = keys2.unwrap();
        let seal_config = core.seal_config().await.unwrap();
        assert_eq!(keys2.len(), seal_config.secret_shares as usize);

        // Seal and unseal_once again
        core.seal().await.unwrap();

        let mut keys3 = None;
        for key in keys2.iter() {
            match core.unseal_once(key).await {
                Ok(keys) => {
                    keys3 = Some(keys);
                    break;
                }
                Err(_) => continue,
            }
        }
        assert!(keys3.is_some());
        let keys3 = keys3.unwrap();
        let seal_config = core.seal_config().await.unwrap();
        assert_eq!(keys3.len(), seal_config.secret_shares as usize);

        // All key sets should be different (forward secrecy)
        for i in 0..keys1.len() {
            assert_ne!(keys1[i], keys2[i]);
            assert_ne!(keys2[i], keys3[i]);
            assert_ne!(keys1[i], keys3[i]);
        }

        // Old keys should be deprecated and unusable
        core.seal().await.unwrap();
        for key in keys1.iter() {
            let result = core.unseal_once(key).await;
            assert!(result.is_err());
        }
        for key in keys2.iter() {
            let result = core.unseal_once(key).await;
            assert!(result.is_err());
        }
        for key in keys3.iter() {
            if let Err(RvError::ErrBarrierUnsealFailed) = core.unseal_once(key).await {
                break;
            }
        }

        let result = core.unseal_once(&keys3[0]).await;
        assert!(matches!(result, Err(RvError::ErrBarrierUnsealing)));
        let result = core.unseal_once(&keys3[1]).await;
        assert!(matches!(result, Err(RvError::ErrBarrierUnsealing)));
        let result = core.unseal_once(&keys3[2]).await;
        assert!(matches!(result, Err(RvError::ErrBarrierUnsealing)));
        let result = core.unseal_once(&keys3[3]).await;
        assert!(matches!(result, Err(RvError::ErrBarrierUnsealing)));
        let result = core.unseal_once(&keys3[4]).await;
        assert!(result.is_ok());
    }
}
