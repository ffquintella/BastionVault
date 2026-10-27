//! Central, barrier-protected HSM custody store (T454 phases 1–2).
//!
//! PQC seeds live as [`BvHsmBlobSet`]s at `core/hsm/custody/<key_id>` in the
//! barrier keyspace; engines hold an opaque [`BvHsmHandle`], never a blob. All
//! writes take the `hsm-custody` storage lock. Seeds are wrapped on every pool
//! member and unwrapped through failover; use goes through the bounded session
//! cache. Spec: `features/hsm-pool-ha.md` § PQC seeds and the custody store.

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use bv_crypto::{KemKeypair, MlDsa65Keypair, MlDsa65Provider, MlKem768Provider};
use bv_metrics::hsm_metrics::{hsm_metrics, UnderReplicatedScope};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    errors::RvError,
    hsm::{
        authz::{self, UnwrapRequest},
        blob::{Context, HsmId},
        blobset::{unix_now_secs, BvHsmBlobSet},
        clock,
        derive::{self, PqcKeyKind, PqcKeyMaterial},
        pool::{HsmPool, LogEventSink, PoolMember, PoolMemberSpec},
        HsmBackend, HsmObjectId, ResolvedHsmConfig,
    },
    storage::{Storage, StorageEntry},
};

/// Barrier-keyspace prefix of the custody records.
pub const CUSTODY_STORE_PREFIX: &str = "core/hsm/custody/";
/// The one cluster lock every blob-set writer takes (spec § Write atomicity).
pub const HSM_CUSTODY_LOCK: &str = "hsm-custody";
/// Wire version of [`BvHsmHandle`].
pub const BV_HSM_HANDLE_VERSION: u8 = 1;

const CUSTODY_RECORD_VERSION: u8 = 1;
const KEY_ID_BYTES: usize = 16;

/// Opaque reference to one custody-held key: what an engine stores in place of
/// a "secret key". Validated before use, because it names a storage key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BvHsmHandle {
    pub version: u8,
    pub key_id: String,
}

impl BvHsmHandle {
    fn generate() -> Self {
        let mut id = [0u8; KEY_ID_BYTES];
        rand::rng().fill_bytes(&mut id);
        Self { version: BV_HSM_HANDLE_VERSION, key_id: hex::encode(id) }
    }

    /// Known version and a key id of exactly 32 lowercase hex characters, so
    /// no path separator or traversal can reach the storage layer.
    pub fn validate(&self) -> Result<(), RvError> {
        if self.version != BV_HSM_HANDLE_VERSION {
            return Err(RvError::ErrHsm(format!("unsupported HSM custody handle version {}", self.version)));
        }
        if !is_key_id(&self.key_id) {
            return Err(RvError::ErrHsm("malformed HSM custody handle key id".into()));
        }
        Ok(())
    }

    fn storage_key(&self) -> Result<String, RvError> {
        self.validate()?;
        Ok(format!("{CUSTODY_STORE_PREFIX}{}", self.key_id))
    }
}

pub(crate) fn is_key_id(s: &str) -> bool {
    s.len() == KEY_ID_BYTES * 2 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A custody-held keypair, lent to a [`CustodyStore::with_private`] callback.
/// Both variants zeroize their private half on drop.
pub enum PqcKeypair {
    MlKem768(KemKeypair),
    MlDsa65(MlDsa65Keypair),
}

impl PqcKeypair {
    pub fn kind(&self) -> PqcKeyKind {
        match self {
            PqcKeypair::MlKem768(_) => PqcKeyKind::MlKem768,
            PqcKeypair::MlDsa65(_) => PqcKeyKind::MlDsa65,
        }
    }

    pub fn public_key(&self) -> &[u8] {
        match self {
            PqcKeypair::MlKem768(k) => k.public_key(),
            PqcKeypair::MlDsa65(k) => k.public_key(),
        }
    }

    fn from_seed(kind: PqcKeyKind, seed: &[u8]) -> Result<Self, RvError> {
        match kind {
            PqcKeyKind::MlKem768 => MlKem768Provider
                .keypair_from_seed(seed)
                .map(PqcKeypair::MlKem768)
                .map_err(|e| RvError::ErrHsm(format!("ML-KEM keypair from seed: {e}"))),
            PqcKeyKind::MlDsa65 => MlDsa65Provider
                .keypair_from_seed(seed)
                .map(PqcKeypair::MlDsa65)
                .map_err(|e| RvError::ErrHsm(format!("ML-DSA keypair from seed: {e}"))),
        }
    }
}

/// What is stored at `core/hsm/custody/<key_id>`. The key id is repeated
/// inside so a record copied to another key is refused, and the public key
/// lets every use check that the unwrapped seed is the expected one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CustodyRecord {
    pub(crate) version: u8,
    pub(crate) key_id: String,
    #[serde(with = "serde_bytes")]
    pub(crate) public_key: Vec<u8>,
    pub(crate) set: BvHsmBlobSet,
}

impl CustodyRecord {
    pub(crate) fn decode(key_id: &str, bytes: &[u8]) -> Result<Self, RvError> {
        let invalid = |why: String| RvError::ErrHsm(format!("invalid HSM custody record {key_id}: {why}"));
        let record: Self = serde_json::from_slice(bytes).map_err(|e| invalid(e.to_string()))?;
        if record.version != CUSTODY_RECORD_VERSION {
            return Err(invalid(format!("unsupported version {}", record.version)));
        }
        if record.key_id != key_id {
            return Err(invalid(format!("record names key id {}", record.key_id)));
        }
        if record.public_key.is_empty() {
            return Err(invalid("empty public key".into()));
        }
        record.set.validate()?;
        record.kind()?;
        Ok(record)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, RvError> {
        self.set.validate()?;
        serde_json::to_vec(self).map_err(|e| RvError::ErrHsm(format!("custody record encode: {e}")))
    }

    pub(crate) fn kind(&self) -> Result<PqcKeyKind, RvError> {
        PqcKeyKind::from_purpose(self.set.purpose).ok_or_else(|| {
            RvError::ErrHsm(format!(
                "custody record {} holds a non-seed purpose {}",
                self.key_id,
                self.set.purpose.as_token()
            ))
        })
    }
}

/// Replication state of every custody set against the active members.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ReplicationReport {
    pub total_sets: usize,
    pub under_replicated: Vec<UnderReplicatedSet>,
    /// Entries under the custody prefix that could not be read as a record.
    /// Reported, never skipped silently.
    pub invalid: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnderReplicatedSet {
    pub key_id: String,
    pub missing: Vec<HsmId>,
}

/// The cluster and device inputs new seeds are derived and bound with.
#[derive(Debug, Clone)]
pub struct CustodyScope {
    pub cluster_uuid: String,
    /// Epoch new keys are created at. An existing set opens at its own epoch.
    pub epoch: u64,
    /// Device key contributing the ECDH input (`bv-identity` per node).
    pub ecdh_key: HsmObjectId,
    /// Cluster ECDH binding point (SEC1-uncompressed P-256).
    pub binding_pub: Vec<u8>,
}

/// A cached unwrapped seed with an expiry. The seed is `Zeroizing`.
struct SeedCacheSlot {
    key: String,
    seed: Zeroizing<Vec<u8>>,
    expires_at: Instant,
}

/// Custody store over an [`HsmPool`]: the pool topology's two members, or a
/// one-member pool for a per-node device. The persisted record is unchanged.
pub struct CustodyStore {
    storage: Arc<dyn Storage>,
    pool: Arc<HsmPool>,
    config: ResolvedHsmConfig,
    scope: CustodyScope,
    ttl: Duration,
    /// Single-slot session cache (the one `custody.rs` used to own), cleared on
    /// expiry, on [`Self::clear_cache`], on delete and on drop.
    cache: Mutex<Option<SeedCacheSlot>>,
    /// Process-monotonic counter for PQC unwrap authorizations, as before T454:
    /// the audit trail's sequence, not a cross-restart replay counter.
    counter: AtomicU64,
}

#[maybe_async::maybe_async]
impl CustodyStore {
    /// A store over one per-node device (a one-member pool).
    /// `storage` must be the barrier (keys are `core/hsm/custody/...`).
    pub fn new(
        storage: Arc<dyn Storage>,
        backend: Arc<dyn HsmBackend>,
        config: ResolvedHsmConfig,
        scope: CustodyScope,
    ) -> Result<Self, RvError> {
        let hsm_id = backend.hsm_id()?;
        let member = PoolMemberSpec { name: hsm_id.to_string(), hsm_id, prefer: false, device: Ok(backend) };
        let pool = HsmPool::new(&config.node_id, vec![member], 1, clock::monotonic(), Arc::new(LogEventSink))?;
        Ok(Self::with_pool(storage, Arc::new(pool), config, scope))
    }

    /// A store over `pool`, whose `min_wrap_copies` every new key must meet.
    pub fn with_pool(
        storage: Arc<dyn Storage>,
        pool: Arc<HsmPool>,
        config: ResolvedHsmConfig,
        scope: CustodyScope,
    ) -> Self {
        let ttl = config.pqc_key_cache_ttl;
        Self { storage, pool, config, scope, ttl, cache: Mutex::new(None), counter: AtomicU64::new(0) }
    }

    /// Seed inputs (device randomness and ECDH) from the preferred reachable
    /// member, failing over like a read. The ECDH result is consumed here once.
    async fn derive_material(&self, kind: PqcKeyKind) -> Result<PqcKeyMaterial, RvError> {
        let mut attempt = self.pool.read(|_| true);
        while let Some(member) = attempt.next_member() {
            let backend = member.backend()?;
            let derived = derive::derive_pqc_key_material(
                backend.as_ref(),
                &self.scope.cluster_uuid,
                self.scope.epoch,
                kind,
                &self.scope.binding_pub,
                self.scope.ecdh_key,
            )
            .await;
            match derived {
                Ok(material) => {
                    attempt.succeeded(member);
                    return Ok(material);
                }
                Err(e) => attempt.failed(member, "derive seed", e)?,
            }
        }
        Err(attempt.into_error("creating an HSM custody key"))
    }

    /// Create a PQC key under custody. Returns its handle and public key. The
    /// seed is wrapped on every reachable member; fewer than `min_wrap_copies`
    /// copies is `ErrHsmInsufficientCopies` and nothing is stored.
    pub async fn create(&self, kind: PqcKeyKind) -> Result<(BvHsmHandle, Vec<u8>), RvError> {
        let material = self.derive_material(kind).await?;
        let epoch = self.scope.epoch;
        let seed_context = kind.seed_context(&self.scope.cluster_uuid, epoch);
        let wrap_ctx = Context::new(seed_context, kind.purpose(), epoch, &self.config.node_id);
        let outcome = self.pool.wrap_all(self.config.objects.wrap_pqc, &wrap_ctx, &material.seed).await?;
        let public_key = material.public_key.clone();
        drop(material); // zeroizes the seed

        let mut copies = outcome.copies.into_values();
        let first = copies.next().ok_or_else(|| RvError::ErrHsmInsufficientCopies {
            have: 0,
            need: self.pool.min_wrap_copies(),
            unreachable: Vec::new(),
        })?;
        let mut set = BvHsmBlobSet::new(kind.purpose(), epoch, first, &self.config.node_id, unix_now_secs()?)?;
        for copy in copies {
            set.insert_copy(copy)?;
        }
        let handle = BvHsmHandle::generate();
        let record = CustodyRecord { version: CUSTODY_RECORD_VERSION, key_id: handle.key_id.clone(), public_key, set };
        let key = handle.storage_key()?;
        let value = record.encode()?;
        {
            let _custody_lock = self.storage.lock(HSM_CUSTODY_LOCK).await?;
            if self.storage.get(&key).await?.is_some() {
                return Err(RvError::ErrHsm(format!("HSM custody key id {} already exists", handle.key_id)));
            }
            self.storage.put(&StorageEntry { key, value }).await?;
        }
        let copies: Vec<&str> = record.set.copies.keys().map(HsmId::as_str).collect();
        let missing = record.set.missing_copies(&self.pool.active_ids());
        log::info!(
            target: "security",
            "hsm custody key created: key_id={} kind={kind:?} copies={copies:?} under_replicated={}",
            handle.key_id,
            !missing.is_empty()
        );
        self.pool.report_under_replicated(&format!("custody key {}", handle.key_id), &missing);
        Ok((handle, record.public_key))
    }

    /// Lend the private keypair behind `handle` to `f`, then zeroize it.
    pub async fn with_private<R, F>(&self, handle: &BvHsmHandle, f: F) -> Result<R, RvError>
    where
        F: FnOnce(&PqcKeypair) -> R,
    {
        self.with_private_inner(handle, None, f).await
    }

    /// [`Self::with_private`], refusing — before any unwrap is authorized — a
    /// handle whose key is not of the `expect` family (confused-deputy guard).
    pub(crate) async fn with_private_as<R, F>(
        &self,
        handle: &BvHsmHandle,
        expect: PqcKeyKind,
        f: F,
    ) -> Result<R, RvError>
    where
        F: FnOnce(&PqcKeypair) -> R,
    {
        self.with_private_inner(handle, Some(expect), f).await
    }

    async fn with_private_inner<R, F>(
        &self,
        handle: &BvHsmHandle,
        expect: Option<PqcKeyKind>,
        f: F,
    ) -> Result<R, RvError>
    where
        F: FnOnce(&PqcKeypair) -> R,
    {
        let (record, record_bytes) = self.load(handle).await?;
        let kind = record.kind()?;
        if expect.is_some_and(|expected| expected != kind) {
            return Err(RvError::ErrHsmContextMismatch);
        }
        // Bound to the exact stored record, so any change to it (a repaired
        // copy, a swapped public key) misses the cache.
        let cache_key = cache_key_of(&record.key_id, &record_bytes);
        let (seed, from_device) = match self.cache_get(&cache_key) {
            Some(seed) => (seed, false),
            None => (self.unwrap_with_failover(&record, kind).await?, true),
        };
        let keypair = PqcKeypair::from_seed(kind, &seed)?;
        if keypair.public_key() != record.public_key.as_slice() {
            log::error!(
                target: "security",
                "hsm custody key {}: the unwrapped seed does not derive the recorded public key",
                record.key_id
            );
            return Err(RvError::ErrHsmContextMismatch);
        }
        // Cached only once it is known to be the recorded key.
        if from_device {
            self.cache_put(cache_key, &seed);
        }
        Ok(f(&keypair))
    }

    /// Unwrap through the preferred member holding a copy, failing over on
    /// outages and never on a cryptographic failure. Never touches the cache.
    async fn unwrap_with_failover(
        &self,
        record: &CustodyRecord,
        kind: PqcKeyKind,
    ) -> Result<Zeroizing<Vec<u8>>, RvError> {
        let mut attempt = self.pool.read(|id| record.set.copy_for(id).is_some());
        while let Some(member) = attempt.next_member() {
            let Some(copy) = record.set.copy_for(member.hsm_id()) else { continue };
            let copy_bytes = copy.to_bytes()?;
            match self.unwrap_seed(record, kind, member, &copy_bytes).await {
                Ok(seed) => {
                    attempt.succeeded(member);
                    return Ok(seed);
                }
                Err(e) => attempt.failed(member, "unwrap custody seed", e)?,
            }
        }
        Err(attempt.into_error(&format!("HSM custody key {}", record.key_id)))
    }

    /// Unwrap `copy_bytes` (the copy for `member`) through a signed, audited
    /// authorization on that member.
    async fn unwrap_seed(
        &self,
        record: &CustodyRecord,
        kind: PqcKeyKind,
        member: &PoolMember,
        copy_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, RvError> {
        let backend = member.backend()?;
        // The expected context comes from this store's cluster, never from the
        // blob header, so a set from another cluster cannot be opened here.
        let epoch = record.set.epoch;
        let ctx = Context::new(
            kind.seed_context(&self.scope.cluster_uuid, epoch),
            kind.purpose(),
            epoch,
            &self.config.node_id,
        );
        let counter = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        let request =
            UnwrapRequest::new(ctx.context.clone(), copy_bytes, &self.config.node_id, epoch, counter, kind.purpose());
        let authorization = authz::sign_authorization(backend.as_ref(), self.config.objects.authz, request).await?;
        log::info!(
            target: "security",
            "hsm custody unwrap authorized (key_id={}, hsm_id={}): {}",
            record.key_id,
            member.hsm_id(),
            authz::audit_record(&authorization)
        );
        backend.unwrap_data(self.config.objects.wrap_pqc, &ctx, copy_bytes).await
    }

    /// Delete the key behind `handle`. Unknown handles are an error.
    pub async fn delete(&self, handle: &BvHsmHandle) -> Result<(), RvError> {
        let key = handle.storage_key()?;
        {
            let _custody_lock = self.storage.lock(HSM_CUSTODY_LOCK).await?;
            if self.storage.get(&key).await?.is_none() {
                return Err(RvError::ErrHsm(format!("unknown HSM custody handle {}", handle.key_id)));
            }
            self.storage.delete(&key).await?;
        }
        self.clear_cache();
        log::info!(target: "security", "hsm custody key deleted: key_id={}", handle.key_id);
        Ok(())
    }

    /// Every custody set's replication state against the active members. Also
    /// the source of the custody half of `bv_hsm_under_replicated_sets`.
    pub async fn replication_report(&self) -> Result<ReplicationReport, RvError> {
        let active = self.pool.active_ids();
        let mut report = ReplicationReport::default();
        for name in self.storage.list(CUSTODY_STORE_PREFIX).await? {
            if !is_key_id(&name) {
                log::error!(target: "security", "unexpected entry {name:?} under {CUSTODY_STORE_PREFIX}");
                report.invalid.push(name);
                continue;
            }
            let Some(entry) = self.storage.get(&format!("{CUSTODY_STORE_PREFIX}{name}")).await? else {
                continue; // deleted between list and get
            };
            match CustodyRecord::decode(&name, &entry.value) {
                Ok(record) => {
                    report.total_sets += 1;
                    let missing = record.set.missing_copies(&active);
                    if !missing.is_empty() {
                        report.under_replicated.push(UnderReplicatedSet { key_id: name, missing });
                    }
                }
                Err(e) => {
                    log::error!(target: "security", "{e}");
                    report.invalid.push(name);
                }
            }
        }
        hsm_metrics().set_under_replicated(UnderReplicatedScope::Custody, report.under_replicated.len());
        Ok(report)
    }

    /// The decoded record and the exact bytes it was decoded from.
    async fn load(&self, handle: &BvHsmHandle) -> Result<(CustodyRecord, Vec<u8>), RvError> {
        let key = handle.storage_key()?;
        let entry = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| RvError::ErrHsm(format!("unknown HSM custody handle {}", handle.key_id)))?;
        let record = CustodyRecord::decode(&handle.key_id, &entry.value)?;
        Ok((record, entry.value))
    }

    fn cache_get(&self, key: &str) -> Option<Zeroizing<Vec<u8>>> {
        if self.ttl.is_zero() {
            return None;
        }
        let mut guard = self.cache.lock().ok()?;
        if let Some(slot) = guard.as_ref() {
            if slot.key == key && Instant::now() < slot.expires_at {
                return Some(slot.seed.clone());
            }
        }
        // Stale or mismatched: drop it (zeroizes) so it can't linger.
        *guard = None;
        None
    }

    fn cache_put(&self, key: String, seed: &Zeroizing<Vec<u8>>) {
        if self.ttl.is_zero() {
            return;
        }
        if let Ok(mut guard) = self.cache.lock() {
            *guard = Some(SeedCacheSlot { key, seed: seed.clone(), expires_at: Instant::now() + self.ttl });
        }
    }

    /// Drop the cached seed, if any (zeroized on drop).
    pub fn clear_cache(&self) {
        if let Ok(mut guard) = self.cache.lock() {
            *guard = None;
        }
    }

    #[cfg(all(test, feature = "hsm_mock"))]
    pub(crate) fn cache_is_empty(&self) -> bool {
        self.cache.lock().map(|g| g.is_none()).unwrap_or(false)
    }

    #[cfg(all(test, feature = "hsm_mock"))]
    pub(crate) fn authorizations_issued(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }
}

/// Cache key: the key id plus the exact stored record bytes.
fn cache_key_of(key_id: &str, record_bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(key_id.as_bytes());
    h.update(record_bytes);
    hex::encode(h.finalize())
}

#[cfg(all(test, feature = "hsm_mock", not(feature = "sync_handler")))]
mod tests {
    use std::sync::Arc;

    use bv_crypto::KemProvider;

    use super::*;
    use crate::{
        hsm::{mock::MockHsmBackend, HsmObjectIds, RecoveryMode},
        storage::{barrier::SecurityBarrier, barrier_aes_gcm::AESGCMBarrier, test_support::new_test_backend},
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

    /// An initialized, unsealed AES-GCM barrier over a fresh file backend.
    async fn barrier(name: &str) -> Arc<dyn Storage> {
        let barrier = AESGCMBarrier::new(new_test_backend(name));
        let key = barrier.generate_key().unwrap();
        barrier.init(&key).await.unwrap();
        barrier.unseal(&key).await.unwrap();
        Arc::new(barrier)
    }

    async fn store_on(
        storage: Arc<dyn Storage>,
        backend: Arc<MockHsmBackend>,
        cluster: &str,
        ttl: u64,
    ) -> Arc<CustodyStore> {
        let scope = CustodyScope {
            cluster_uuid: cluster.into(),
            epoch: 0,
            ecdh_key: HsmObjectIds::default().identity,
            binding_pub: backend.identity_public_key().unwrap(),
        };
        Arc::new(CustodyStore::new(storage, backend, cfg(ttl), scope).unwrap())
    }

    async fn fresh_store(name: &str, ttl: u64) -> (Arc<CustodyStore>, Arc<dyn Storage>, Arc<MockHsmBackend>) {
        let storage = barrier(name).await;
        let backend = Arc::new(MockHsmBackend::open(&cfg(ttl)).await.unwrap());
        (store_on(storage.clone(), backend.clone(), "clu", ttl).await, storage, backend)
    }

    #[tokio::test]
    async fn create_then_use_both_key_families() {
        let (store, storage, backend) = fresh_store("custody_create_use", 60).await;

        let (kem, kem_pub) = store.create(PqcKeyKind::MlKem768).await.unwrap();
        let (ct, secret_a) = MlKem768Provider.encapsulate(&kem_pub).unwrap();
        let secret_b = store
            .with_private(&kem, |kp| match kp {
                PqcKeypair::MlKem768(k) => MlKem768Provider.decapsulate(k.secret_key(), ct.as_bytes()).unwrap(),
                PqcKeypair::MlDsa65(_) => panic!("wrong family"),
            })
            .await
            .unwrap();
        assert_eq!(secret_a, secret_b);

        let (dsa, dsa_pub) = store.create(PqcKeyKind::MlDsa65).await.unwrap();
        let derived_pub = store.with_private(&dsa, |kp| kp.public_key().to_vec()).await.unwrap();
        assert_eq!(derived_pub, dsa_pub);

        // Stored in the barrier keyspace as a one-copy v2 set for this device.
        let entry = storage.get(&format!("{CUSTODY_STORE_PREFIX}{}", kem.key_id)).await.unwrap().unwrap();
        let record = CustodyRecord::decode(&kem.key_id, &entry.value).unwrap();
        assert_eq!(record.set.copies.len(), 1);
        assert!(record.set.copy_for(&backend.hsm_id().unwrap()).is_some());
        assert_eq!(record.set.purpose, crate::hsm::Purpose::PqcKemSeed);
    }

    #[test]
    fn handles_are_validated_before_touching_storage() {
        let good = BvHsmHandle::generate();
        good.validate().unwrap();
        for key_id in
            ["../../core/hsm-seal", "ABCDEF0123456789ABCDEF0123456789", "abc", "", "0123456789abcdef0123456789abcdeg"]
        {
            let h = BvHsmHandle { version: 1, key_id: key_id.into() };
            assert!(h.validate().is_err(), "{key_id:?} must be rejected");
            assert!(h.storage_key().is_err());
        }
        assert!(BvHsmHandle { version: 2, key_id: good.key_id }.validate().is_err());
    }

    #[tokio::test]
    async fn unknown_and_deleted_handles_fail() {
        let (store, _, _) = fresh_store("custody_delete", 60).await;
        let (h, _) = store.create(PqcKeyKind::MlKem768).await.unwrap();
        store.with_private(&h, |_| ()).await.unwrap();
        assert!(!store.cache_is_empty());

        store.delete(&h).await.unwrap();
        assert!(store.cache_is_empty(), "delete clears the session cache");
        assert!(store.with_private(&h, |_| ()).await.is_err());
        assert!(store.delete(&h).await.is_err(), "deleting twice is an error, not a no-op");
        assert!(store.with_private(&BvHsmHandle::generate(), |_| ()).await.is_err());
    }

    #[tokio::test]
    async fn wrong_family_is_refused_before_any_unwrap() {
        let (store, _, _) = fresh_store("custody_wrong_family", 60).await;
        let (dsa, _) = store.create(PqcKeyKind::MlDsa65).await.unwrap();
        let before = store.authorizations_issued();
        let err = store.with_private_as(&dsa, PqcKeyKind::MlKem768, |_| ()).await.unwrap_err();
        assert_eq!(err, RvError::ErrHsmContextMismatch);
        assert_eq!(store.authorizations_issued(), before, "no unwrap may be authorized for the wrong family");
    }

    #[tokio::test]
    async fn records_cannot_be_moved_tampered_or_used_by_another_cluster() {
        let (store, storage, backend) = fresh_store("custody_tamper", 0).await;
        let (h, _) = store.create(PqcKeyKind::MlKem768).await.unwrap();
        let key = format!("{CUSTODY_STORE_PREFIX}{}", h.key_id);
        let entry = storage.get(&key).await.unwrap().unwrap();

        // Copied under another key id.
        let moved = BvHsmHandle::generate();
        storage
            .put(&StorageEntry { key: format!("{CUSTODY_STORE_PREFIX}{}", moved.key_id), value: entry.value.clone() })
            .await
            .unwrap();
        assert!(store.with_private(&moved, |_| ()).await.is_err());

        // Public key swapped: the seed no longer matches the record.
        let mut record = CustodyRecord::decode(&h.key_id, &entry.value).unwrap();
        record.public_key[0] ^= 0xff;
        storage.put(&StorageEntry { key: key.clone(), value: record.encode().unwrap() }).await.unwrap();
        assert_eq!(store.with_private(&h, |_| ()).await.unwrap_err(), RvError::ErrHsmContextMismatch);
        storage.put(&StorageEntry { key, value: entry.value }).await.unwrap();

        // A store for another cluster over the same storage and device.
        let other = store_on(storage, backend, "other-cluster", 0).await;
        assert_eq!(other.with_private(&h, |_| ()).await.unwrap_err(), RvError::ErrHsmContextMismatch);
        store.with_private(&h, |_| ()).await.unwrap();
    }

    #[tokio::test]
    async fn a_seed_that_fails_the_public_key_check_is_never_cached() {
        let (store, storage, _) = fresh_store("custody_no_cache_on_mismatch", 60).await;
        let (h, _) = store.create(PqcKeyKind::MlKem768).await.unwrap();
        let key = format!("{CUSTODY_STORE_PREFIX}{}", h.key_id);
        let entry = storage.get(&key).await.unwrap().unwrap();
        let mut record = CustodyRecord::decode(&h.key_id, &entry.value).unwrap();
        record.public_key[0] ^= 0xff;
        storage.put(&StorageEntry { key, value: record.encode().unwrap() }).await.unwrap();

        assert_eq!(store.with_private(&h, |_| ()).await.unwrap_err(), RvError::ErrHsmContextMismatch);
        assert!(store.cache_is_empty());
    }

    #[tokio::test]
    async fn replication_report_counts_missing_members_and_invalid_entries() {
        let (store_a, storage, _) = fresh_store("custody_report", 60).await;
        let (h, _) = store_a.create(PqcKeyKind::MlKem768).await.unwrap();

        let report_a = store_a.replication_report().await.unwrap();
        assert_eq!(report_a.total_sets, 1);
        assert!(report_a.under_replicated.is_empty());

        // The same storage seen through a second device: the set has no copy there.
        let device_b = Arc::new(MockHsmBackend::open(&cfg(60)).await.unwrap());
        let store_b = store_on(storage.clone(), device_b.clone(), "clu", 60).await;
        let report_b = store_b.replication_report().await.unwrap();
        assert_eq!(
            report_b.under_replicated,
            vec![UnderReplicatedSet { key_id: h.key_id.clone(), missing: vec![device_b.hsm_id().unwrap()] }]
        );
        assert!(store_b.with_private(&h, |_| ()).await.is_err(), "no copy for this device");

        let junk = BvHsmHandle::generate();
        storage
            .put(&StorageEntry { key: format!("{CUSTODY_STORE_PREFIX}{}", junk.key_id), value: b"{".to_vec() })
            .await
            .unwrap();
        let report = store_a.replication_report().await.unwrap();
        assert_eq!(report.total_sets, 1);
        assert_eq!(report.invalid, vec![junk.key_id]);
    }

    #[tokio::test]
    async fn strict_mode_zero_ttl_does_not_cache() {
        let (store, _, _) = fresh_store("custody_strict", 0).await;
        let (h, _) = store.create(PqcKeyKind::MlKem768).await.unwrap();
        store.with_private(&h, |_| ()).await.unwrap();
        store.with_private(&h, |_| ()).await.unwrap();
        assert!(store.cache_is_empty());
        assert_eq!(store.authorizations_issued(), 2, "every use is a fresh, authorized unwrap");
    }

    #[tokio::test]
    async fn cached_use_skips_the_device_until_cleared() {
        let (store, _, _) = fresh_store("custody_cache", 60).await;
        let (h, _) = store.create(PqcKeyKind::MlKem768).await.unwrap();
        store.with_private(&h, |_| ()).await.unwrap();
        store.with_private(&h, |_| ()).await.unwrap();
        assert_eq!(store.authorizations_issued(), 1);
        store.clear_cache();
        store.with_private(&h, |_| ()).await.unwrap();
        assert_eq!(store.authorizations_issued(), 2);
    }

    /// Regression (T454 phase 2): the `hsm-custody` guard used to be `!Send`,
    /// so these futures could not run from an HTTP handler. Compile-time check.
    #[allow(dead_code)]
    fn custody_futures_are_send(store: &CustodyStore, handle: &BvHsmHandle) {
        fn assert_send<T: Send>(_: T) {}
        assert_send(store.create(PqcKeyKind::MlKem768));
        assert_send(store.delete(handle));
        assert_send(store.with_private(handle, |_| ()));
        assert_send(store.replication_report());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn writes_wait_for_the_hsm_custody_lock() {
        let (store, storage, _) = fresh_store("custody_lock", 60).await;
        let held = storage.lock(HSM_CUSTODY_LOCK).await.unwrap();

        // A plain task on the runtime: possible now that the guard is `Send`.
        let writer = store.clone();
        let task = tokio::spawn(async move { writer.create(PqcKeyKind::MlKem768).await });
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!task.is_finished(), "create must not write while another holder has hsm-custody");
        assert_eq!(store.replication_report().await.unwrap().total_sets, 0);

        drop(held);
        let (h, _) = task.await.unwrap().unwrap();
        store.with_private(&h, |_| ()).await.unwrap();
    }
}
