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
        use crate::modules::auth::{token_store::TokenEntry, AuthModule};

        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_core_flush_caches_empties_token_cache").await;

        let auth_module =
            core.module_manager.get_module::<AuthModule>("auth").expect("auth module must exist in a default unseal");
        let token_store = auth_module.token_store.load_full().expect("token store must be installed");

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

    /// `init` lets storage reads retry transient cluster errors for its
    /// duration only: once the barrier is initialized a failed read throws the
    /// root token away, while steady-state reads must keep failing fast.
    mod init_read_retry {
        use std::sync::{Arc, Mutex};

        use bv_core::core::SealConfig;

        use crate::{
            errors::RvError,
            storage::{Backend, BackendEntry},
            test_utils::new_test_backend,
            BastionVault,
        };

        struct Recording {
            inner: Arc<dyn Backend>,
            toggles: Arc<Mutex<Vec<bool>>>,
        }

        #[async_trait::async_trait]
        impl Backend for Recording {
            async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
                self.inner.list(prefix).await
            }

            async fn get(&self, key: &str) -> Result<Option<BackendEntry>, RvError> {
                self.inner.get(key).await
            }

            async fn put(&self, entry: &BackendEntry) -> Result<(), RvError> {
                self.inner.put(entry).await
            }

            async fn delete(&self, key: &str) -> Result<(), RvError> {
                self.inner.delete(key).await
            }

            fn set_transient_read_retry(&self, on: bool) {
                self.toggles.lock().unwrap().push(on);
            }
        }

        #[tokio::test]
        async fn init_turns_read_retry_on_and_back_off() {
            let toggles = Arc::new(Mutex::new(Vec::new()));
            let backend = Recording { inner: new_test_backend("init_read_retry"), toggles: toggles.clone() };
            let bvault = BastionVault::new(Arc::new(backend), None).unwrap();

            let result = bvault.init(&SealConfig { secret_shares: 1, secret_threshold: 1 }).await.unwrap();
            assert!(!result.root_token.is_empty());
            assert_eq!(*toggles.lock().unwrap(), vec![true, false]);
        }
    }

    /// HSM auto-unseal rides out a transient cluster error on its storage
    /// reads (T475). Reported on a two-node hiqlite cluster: a read made by
    /// `post_unseal`, after the KEK was unwrapped, missed its leadership
    /// confirmation and the node stayed sealed until the next restart.
    #[cfg(not(feature = "sync_handler"))]
    mod auto_unseal_read_retry {
        use std::sync::{
            atomic::{AtomicBool, AtomicU32, Ordering::SeqCst},
            Arc, Mutex,
        };

        use bv_core::core::{Core, SealConfig};
        use zeroize::Zeroizing;

        use crate::{
            errors::{
                retry::{is_transient_cluster, retry_transient, MAX_ATTEMPTS},
                RvError,
            },
            kernel_api::mount::CORE_MOUNT_CONFIG_PATH,
            seal::SealProvider,
            storage::{Backend, BackendEntry},
            test_utils::new_test_backend,
            BastionVault,
        };

        /// A process-wide `log` sink (nextest runs each test in its own process).
        mod capture {
            use std::sync::{Mutex, OnceLock};

            static LINES: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
            static INSTALLED: OnceLock<bool> = OnceLock::new();
            struct Capture;
            impl log::Log for Capture {
                fn enabled(&self, _: &log::Metadata<'_>) -> bool {
                    true
                }
                fn log(&self, r: &log::Record<'_>) {
                    let line = format!("{} {} {}", r.level(), r.target(), r.args());
                    LINES.get_or_init(Default::default).lock().unwrap().push(line);
                }
                fn flush(&self) {}
            }
            static LOGGER: Capture = Capture;

            /// `false` when another logger was installed first (`cargo test`
            /// runs every test in one process): skip the log assertions then.
            pub fn install() -> bool {
                *INSTALLED.get_or_init(|| {
                    let ok = log::set_logger(&LOGGER).is_ok();
                    if ok {
                        log::set_max_level(log::LevelFilter::Info);
                    }
                    ok
                })
            }

            /// Captured lines that start with `prefix` and contain `text`.
            pub fn lines(prefix: &str, text: &str) -> Vec<String> {
                let all = LINES.get_or_init(Default::default).lock().unwrap();
                all.iter().filter(|l| l.starts_with(prefix) && l.contains(text)).cloned().collect()
            }
        }

        /// A file backend whose root mount-table read (made by `post_unseal`,
        /// after the unwrap, as on the reporting node) fails on demand. It
        /// honours the retry switch as `HiqliteBackend::retrying_read` does.
        struct Flaky {
            inner: Arc<dyn Backend>,
            label: String,
            retry: AtomicBool,
            toggles: Mutex<Vec<bool>>,
            failures_left: AtomicU32,
            fail_with: Mutex<fn() -> RvError>,
            failed_reads: AtomicU32,
        }

        impl Flaky {
            fn new(name: &str) -> Arc<Self> {
                Arc::new(Self {
                    inner: new_test_backend(name),
                    label: format!("flaky get ({name})"),
                    retry: AtomicBool::new(false),
                    toggles: Mutex::new(Vec::new()),
                    failures_left: AtomicU32::new(0),
                    fail_with: Mutex::new(|| RvError::ErrClusterQuorumLost),
                    failed_reads: AtomicU32::new(0),
                })
            }

            /// Fail the next `n` mount-table reads with `err`.
            fn fail_next(&self, n: u32, err: fn() -> RvError) {
                *self.fail_with.lock().unwrap() = err;
                self.failures_left.store(n, SeqCst);
            }

            async fn get_once(&self, key: &str) -> Result<Option<BackendEntry>, RvError> {
                if key.ends_with(CORE_MOUNT_CONFIG_PATH)
                    && self.failures_left.try_update(SeqCst, SeqCst, |n| n.checked_sub(1)).is_ok()
                {
                    self.failed_reads.fetch_add(1, SeqCst);
                    let err = *self.fail_with.lock().unwrap();
                    return Err(err());
                }
                self.inner.get(key).await
            }
        }

        #[async_trait::async_trait]
        impl Backend for Flaky {
            async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
                self.inner.list(prefix).await
            }

            async fn get(&self, key: &str) -> Result<Option<BackendEntry>, RvError> {
                if self.retry.load(SeqCst) {
                    retry_transient(&self.label, is_transient_cluster, || self.get_once(key)).await
                } else {
                    self.get_once(key).await
                }
            }

            async fn put(&self, entry: &BackendEntry) -> Result<(), RvError> {
                self.inner.put(entry).await
            }

            async fn delete(&self, key: &str) -> Result<(), RvError> {
                self.inner.delete(key).await
            }

            fn set_transient_read_retry(&self, on: bool) {
                self.retry.store(on, SeqCst);
                self.toggles.lock().unwrap().push(on);
            }
        }

        /// The HSM unwrap without the HSM: hands back the KEK, or fails with
        /// `verdict`, and counts the calls.
        struct FixedKek {
            kek: Zeroizing<Vec<u8>>,
            verdict: Option<fn() -> RvError>,
            unwraps: AtomicU32,
        }

        #[async_trait::async_trait]
        impl SealProvider for FixedKek {
            fn seal_type(&self) -> &str {
                "test-auto-unseal"
            }

            fn requires_shares(&self) -> bool {
                false
            }

            async fn init_kek(&self, _kek: &[u8], _: &SealConfig) -> Result<Zeroizing<Vec<Vec<u8>>>, RvError> {
                Err(RvError::ErrBarrierUnsealing)
            }

            async fn recover_kek(&self) -> Result<Zeroizing<Vec<u8>>, RvError> {
                self.unwraps.fetch_add(1, SeqCst);
                match self.verdict {
                    Some(verdict) => Err(verdict()),
                    None => Ok(self.kek.clone()),
                }
            }
        }

        struct Fixture {
            _bvault: BastionVault,
            core: Arc<Core>,
            flaky: Arc<Flaky>,
            provider: Arc<FixedKek>,
        }

        /// An initialized, sealed vault whose seal provider is `FixedKek`.
        async fn sealed_vault(name: &str, verdict: Option<fn() -> RvError>) -> Fixture {
            let flaky = Flaky::new(name);
            let bvault = BastionVault::new(flaky.clone(), None).unwrap();
            // 1-of-1 Shamir: the single share is the KEK itself.
            let init = bvault.init(&SealConfig { secret_shares: 1, secret_threshold: 1 }).await.unwrap();
            let core = bvault.core.load_full();
            assert!(core.sealed());
            let kek = Zeroizing::new(init.secret_shares[0].clone());
            let provider = Arc::new(FixedKek { kek, verdict, unwraps: AtomicU32::new(0) });
            core.set_seal_provider(provider.clone());
            Fixture { _bvault: bvault, core, flaky, provider }
        }

        #[tokio::test]
        async fn a_transient_read_error_after_the_unwrap_is_retried_and_the_vault_unseals() {
            let logs = capture::install();
            let name = "auto_unseal_retry_recovers";
            let f = sealed_vault(name, None).await;
            f.flaky.fail_next(2, || RvError::ErrClusterQuorumLost);

            f.core.auto_unseal_at_startup().await;

            assert!(!f.core.sealed(), "two quorum misses inside the budget must not keep the vault sealed");
            assert_eq!(f.flaky.failed_reads.load(SeqCst), 2);
            assert_eq!(f.provider.unwraps.load(SeqCst), 1, "the KEK is unwrapped once, never per retry");
            // On for init, off; on for the unseal, off: steady-state reads fail fast.
            assert_eq!(*f.flaky.toggles.lock().unwrap(), vec![true, false, true, false]);
            if logs {
                let warns = capture::lines("WARN security", &format!("flaky get ({name}): transient error"));
                assert_eq!(warns.len(), 2, "{warns:?}");
                assert!(warns[0].contains("Cluster lost quorum.") && warns[0].contains("attempt 1/5"), "{warns:?}");
                assert_eq!(capture::lines("INFO security", "HSM auto-unseal succeeded").len(), 1);
            }
        }

        #[tokio::test]
        async fn a_persistent_transient_error_fails_after_the_budget_and_stays_sealed() {
            let logs = capture::install();
            let name = "auto_unseal_retry_exhausted";
            let f = sealed_vault(name, None).await;
            f.flaky.fail_next(u32::MAX, || RvError::ErrClusterQuorumLost);

            f.core.auto_unseal_at_startup().await;

            assert!(f.core.sealed());
            assert_eq!(f.flaky.failed_reads.load(SeqCst), MAX_ATTEMPTS, "bounded by the policy's attempts");
            assert_eq!(f.provider.unwraps.load(SeqCst), 1);
            assert_eq!(f.flaky.toggles.lock().unwrap().last(), Some(&false));
            if logs {
                let warns = capture::lines("WARN security", &format!("flaky get ({name}): transient error"));
                assert_eq!(warns.len() as u32, MAX_ATTEMPTS - 1, "{warns:?}");
                let failed = capture::lines("ERROR security", "HSM auto-unseal failed; vault remains sealed");
                assert_eq!(failed.len(), 1, "{failed:?}");
                assert!(failed[0].ends_with("Cluster lost quorum."), "{failed:?}");
            }
        }

        #[tokio::test]
        async fn an_hsm_verdict_is_final_and_the_unwrap_runs_once() {
            let verdicts: [fn() -> RvError; 3] =
                [|| RvError::ErrHsmBlobInvalid, || RvError::ErrHsmContextMismatch, || RvError::ErrHsmAuthzInvalid];
            for (i, verdict) in verdicts.into_iter().enumerate() {
                let f = sealed_vault(&format!("auto_unseal_verdict_{i}"), Some(verdict)).await;

                assert_eq!(f.core.auto_unseal().await.unwrap_err(), verdict());
                assert_eq!(f.provider.unwraps.load(SeqCst), 1, "{}", verdict());
                assert!(f.core.sealed());
                assert_eq!(f.flaky.toggles.lock().unwrap().last(), Some(&false));
            }
        }

        #[tokio::test]
        async fn a_non_transient_storage_error_is_not_retried() {
            let f = sealed_vault("auto_unseal_storage_fatal", None).await;
            f.flaky.fail_next(u32::MAX, || RvError::ErrCluster("raft log corrupted".into()));

            let err = f.core.auto_unseal().await.unwrap_err();

            assert!(matches!(err, RvError::ErrCluster(_)), "{err}");
            assert_eq!(f.flaky.failed_reads.load(SeqCst), 1);
            assert_eq!(f.provider.unwraps.load(SeqCst), 1);
            assert!(f.core.sealed());
        }

        /// The startup path folds the old separate `inited()` check into
        /// `auto_unseal`: an uninitialized vault is reported, not an error.
        #[tokio::test]
        async fn an_uninitialized_vault_is_not_an_unseal_failure() {
            let logs = capture::install();
            let flaky = Flaky::new("auto_unseal_not_inited");
            let bvault = BastionVault::new(flaky.clone(), None).unwrap();
            let core = bvault.core.load_full();
            let provider =
                Arc::new(FixedKek { kek: Zeroizing::new(Vec::new()), verdict: None, unwraps: AtomicU32::new(0) });
            core.set_seal_provider(provider.clone());

            core.auto_unseal_at_startup().await;

            assert!(core.sealed());
            assert_eq!(provider.unwraps.load(SeqCst), 0);
            assert_eq!(*flaky.toggles.lock().unwrap(), vec![true, false]);
            if logs {
                assert_eq!(capture::lines("INFO security", "vault not initialized").len(), 1);
                assert!(capture::lines("ERROR security", "HSM auto-unseal failed").is_empty());
            }
        }
    }
}
