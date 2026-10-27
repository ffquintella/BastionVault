//! Hybrid PQC custody providers (spec § Capability 2, "Provider integration").
//!
//! `HsmCustodyKemProvider` / `HsmCustodySigProvider` wrap the software
//! `bv_crypto` ML-KEM-768 / ML-DSA-65 providers. The "secret key" at their
//! boundary is a [`BvHsmHandle`] into the [`CustodyStore`], never a blob or
//! raw key material (T454, `features/hsm-pool-ha.md` § What happens to the
//! existing modules). Unwrap, cache and zeroize live in the store.

use std::sync::Arc;

use bv_crypto::{KemCiphertext, KemProvider, MlDsa65Provider, MlKem768Provider, SharedSecret};

use crate::{
    errors::RvError,
    hsm::{
        custody_store::{BvHsmHandle, CustodyStore, PqcKeypair},
        derive::PqcKeyKind,
    },
};

// Layering note: the spec sketches these under `crates/bv_crypto/`, but the
// unwrap lifecycle needs the host `HsmBackend` (device unwrap, signed
// authorization, audit), which `bv_crypto` deliberately does not depend on.

/// ML-KEM-768 under HSM custody. Encapsulation needs no device round-trip;
/// decapsulation borrows the keypair from the store and zeroizes it after.
pub struct HsmCustodyKemProvider {
    store: Arc<CustodyStore>,
    inner: MlKem768Provider,
}

impl HsmCustodyKemProvider {
    pub fn new(store: Arc<CustodyStore>) -> Self {
        Self { store, inner: MlKem768Provider }
    }

    /// Encapsulate to a published public key. No private material involved.
    pub fn encapsulate(&self, public_key: &[u8]) -> Result<(KemCiphertext, SharedSecret), RvError> {
        self.inner.encapsulate(public_key).map_err(|e| RvError::ErrHsm(format!("ML-KEM encapsulate: {e}")))
    }

    /// Decapsulate under the custody key `handle`. A handle to a signature key
    /// is refused before any unwrap is authorized.
    #[maybe_async::maybe_async]
    pub async fn decapsulate(&self, handle: &BvHsmHandle, ciphertext: &[u8]) -> Result<SharedSecret, RvError> {
        self.store
            .with_private_as(handle, PqcKeyKind::MlKem768, |keypair| match keypair {
                PqcKeypair::MlKem768(k) => self
                    .inner
                    .decapsulate(k.secret_key(), ciphertext)
                    .map_err(|e| RvError::ErrHsm(format!("ML-KEM decapsulate: {e}"))),
                PqcKeypair::MlDsa65(_) => Err(RvError::ErrHsmContextMismatch),
            })
            .await?
    }

    pub fn clear_cache(&self) {
        self.store.clear_cache();
    }
}

/// ML-DSA-65 under HSM custody. Signing borrows the keypair from the store and
/// zeroizes it after.
pub struct HsmCustodySigProvider {
    store: Arc<CustodyStore>,
    inner: MlDsa65Provider,
}

impl HsmCustodySigProvider {
    pub fn new(store: Arc<CustodyStore>) -> Self {
        Self { store, inner: MlDsa65Provider }
    }

    /// Sign `message` (with an explicit domain-separating `sig_context`) under
    /// the custody key `handle`. A handle to a KEM key is refused before any
    /// unwrap is authorized.
    #[maybe_async::maybe_async]
    pub async fn sign(&self, handle: &BvHsmHandle, message: &[u8], sig_context: &[u8]) -> Result<Vec<u8>, RvError> {
        self.store
            .with_private_as(handle, PqcKeyKind::MlDsa65, |keypair| match keypair {
                PqcKeypair::MlDsa65(k) => self
                    .inner
                    .sign(k.secret_seed(), message, sig_context)
                    .map_err(|e| RvError::ErrHsm(format!("ML-DSA sign: {e}"))),
                PqcKeypair::MlKem768(_) => Err(RvError::ErrHsmContextMismatch),
            })
            .await?
    }

    pub fn clear_cache(&self) {
        self.store.clear_cache();
    }
}

#[cfg(all(test, feature = "hsm_mock", not(feature = "sync_handler")))]
mod tests {
    use std::time::Duration;

    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        hsm::{
            custody_store::CustodyScope, mock::MockHsmBackend, HsmBackend, HsmObjectIds, RecoveryMode,
            ResolvedHsmConfig,
        },
        storage::{barrier::SecurityBarrier, barrier_aes_gcm::AESGCMBarrier, test_support::new_test_backend, Storage},
    };

    fn cfg(ttl_secs: u64) -> ResolvedHsmConfig {
        ResolvedHsmConfig {
            backend_type: "mock".into(),
            connector: String::new(),
            objects: HsmObjectIds::default(),
            password: Zeroizing::new(String::new()),
            domains: vec![1],
            pqc_key_cache_ttl: Duration::from_secs(ttl_secs),
            recovery: RecoveryMode::None,
            state_path: String::new(),
            node_id: "n1".into(),
            pool: None,
            recovery_explicit: false,
        }
    }

    async fn store(name: &str, ttl: u64) -> Arc<CustodyStore> {
        let barrier = AESGCMBarrier::new(new_test_backend(name));
        let key = barrier.generate_key().unwrap();
        barrier.init(&key).await.unwrap();
        barrier.unseal(&key).await.unwrap();
        let storage: Arc<dyn Storage> = Arc::new(barrier);
        let backend = Arc::new(MockHsmBackend::open(&cfg(ttl)).await.unwrap());
        let scope = CustodyScope {
            cluster_uuid: "clu".into(),
            epoch: 0,
            ecdh_key: HsmObjectIds::default().identity,
            binding_pub: backend.identity_public_key().unwrap(),
            pqc_wrap_keys: Default::default(),
        };
        Arc::new(CustodyStore::new(storage, backend, cfg(ttl), scope).unwrap())
    }

    #[tokio::test]
    async fn kem_custody_round_trip() {
        let store = store("custody_kem_round_trip", 60).await;
        let (handle, public_key) = store.create(PqcKeyKind::MlKem768).await.unwrap();
        let provider = HsmCustodyKemProvider::new(store);
        let (ct, secret_a) = provider.encapsulate(&public_key).unwrap();
        let secret_b = provider.decapsulate(&handle, ct.as_bytes()).await.unwrap();
        assert_eq!(secret_a, secret_b);
    }

    #[tokio::test]
    async fn sig_custody_round_trip_and_cross_family_refusal() {
        let store = store("custody_sig_round_trip", 60).await;
        let (handle, _) = store.create(PqcKeyKind::MlDsa65).await.unwrap();
        let provider = HsmCustodySigProvider::new(store.clone());
        let msg = b"transcript bytes";
        let sig = provider.sign(&handle, msg, b"ctx").await.unwrap();
        let verified = store.with_private(&handle, |kp| match kp {
            PqcKeypair::MlDsa65(k) => MlDsa65Provider.verify(k.secret_seed(), msg, &sig, b"ctx").unwrap(),
            PqcKeypair::MlKem768(_) => false,
        });
        assert!(verified.await.unwrap(), "the signature verifies under the custody key");

        // A signature-key handle must be refused by the KEM provider, and vice versa.
        let kem = HsmCustodyKemProvider::new(store.clone());
        assert_eq!(kem.decapsulate(&handle, b"x").await.unwrap_err(), RvError::ErrHsmContextMismatch);
        let (kem_handle, _) = store.create(PqcKeyKind::MlKem768).await.unwrap();
        assert_eq!(provider.sign(&kem_handle, msg, b"ctx").await.unwrap_err(), RvError::ErrHsmContextMismatch);
    }

    #[tokio::test]
    async fn cache_can_be_cleared() {
        let store = store("custody_cache_clear", 60).await;
        let (handle, public_key) = store.create(PqcKeyKind::MlKem768).await.unwrap();
        let provider = HsmCustodyKemProvider::new(store.clone());
        let (ct, _) = provider.encapsulate(&public_key).unwrap();
        // Populate the cache, then clear it; a later op re-unwraps from the device.
        provider.decapsulate(&handle, ct.as_bytes()).await.unwrap();
        assert!(!store.cache_is_empty());
        provider.clear_cache();
        assert!(store.cache_is_empty());
        provider.decapsulate(&handle, ct.as_bytes()).await.unwrap();
    }

    #[tokio::test]
    async fn strict_mode_zero_ttl_does_not_cache() {
        let store = store("custody_strict_ttl", 0).await;
        let (handle, public_key) = store.create(PqcKeyKind::MlKem768).await.unwrap();
        let provider = HsmCustodyKemProvider::new(store.clone());
        let (ct, secret_a) = provider.encapsulate(&public_key).unwrap();
        let secret_b = provider.decapsulate(&handle, ct.as_bytes()).await.unwrap();
        assert_eq!(secret_a, secret_b);
        assert!(store.cache_is_empty());
    }
}
