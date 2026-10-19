//! HSM auto-unseal seal provider (spec § Capability 1; T454 phase 1).
//!
//! At init the barrier KEK is wrapped as a v2 blob under the local HSM's
//! `bv-wrap-barrier` key and stored as a one-copy blob set in the seal record
//! ([`record`]). At startup the KEK is recovered with a signed, audited,
//! replay-resistant unwrap — no operator share entry. Nothing on disk is
//! decryptable without the key inside an enrolled HSM (spec rule 6).

pub mod record;

use std::sync::Arc;

use rand::Rng;
use zeroize::Zeroizing;

use crate::{
    core::SealConfig,
    errors::RvError,
    hsm::{
        authz::{self, UnwrapRequest},
        blob::{BvHsmBlob, Context, Purpose, BV_HSM_BLOB_VERSION_V1},
        blobset::{unix_now_secs, BvHsmBlobSet},
        context, validate_node_id, HsmBackend, RecoveryMode, ResolvedHsmConfig,
    },
    seal::SealProvider,
    storage::{Backend as PhysicalBackend, BackendEntry},
};

use self::record::{HsmSealRecord, StoredSealRecord, Topology};

/// Physical-storage key for the HSM seal record. Non-secret (holds only
/// opaque wrapped blobs), so it lives in the pre-unseal physical layer.
const HSM_SEAL_RECORD_PATH: &str = "core/hsm-seal";
/// Pre-T454 cluster-wide unwrap counter. Read once per node, to start that
/// node's own counter above it; never written again, never deleted.
const HSM_AUTHZ_COUNTER_LEGACY_PATH: &str = "core/hsm-authz-counter";
/// Per-node unwrap counters: `core/hsm-authz-counter/<node_id>`.
const HSM_AUTHZ_COUNTER_PREFIX: &str = "core/hsm-authz-counter/";

/// Auto-unseal provider backed by an [`HsmBackend`].
pub struct HsmSealProvider {
    backend: Arc<dyn HsmBackend>,
    physical: Arc<dyn PhysicalBackend>,
    config: ResolvedHsmConfig,
}

impl HsmSealProvider {
    pub fn new(backend: Arc<dyn HsmBackend>, physical: Arc<dyn PhysicalBackend>, config: ResolvedHsmConfig) -> Self {
        Self { backend, physical, config }
    }

    pub fn backend(&self) -> Arc<dyn HsmBackend> {
        self.backend.clone()
    }

    #[maybe_async::maybe_async]
    async fn load_record(&self) -> Result<Option<StoredSealRecord>, RvError> {
        match self.physical.get(HSM_SEAL_RECORD_PATH).await? {
            Some(pe) => Ok(Some(HsmSealRecord::decode(&pe.value)?)),
            None => Ok(None),
        }
    }

    /// Write the record, always as v2 (a record loaded from v1 is converted
    /// here). Read-modify-write callers must hold the `hsm-custody` lock; the
    /// only phase-1 writer is init, which writes a fresh record.
    #[maybe_async::maybe_async]
    async fn store_record(&self, rec: &HsmSealRecord) -> Result<(), RvError> {
        let value = rec.encode()?;
        self.physical.put(&BackendEntry { key: HSM_SEAL_RECORD_PATH.to_string(), value }).await
    }

    /// Read, increment and persist this node's strictly-increasing unwrap
    /// counter, so a captured (blob, authorization) pair cannot be replayed
    /// across restarts. Per node, so concurrent unseals never share a key.
    #[maybe_async::maybe_async]
    async fn next_counter(&self) -> Result<u64, RvError> {
        validate_node_id(&self.config.node_id)?;
        let key = format!("{HSM_AUTHZ_COUNTER_PREFIX}{}", self.config.node_id);
        let current = match self.physical.get(&key).await? {
            Some(pe) => parse_counter(&key, &pe.value)?,
            // First use on this node: start above the legacy global counter,
            // so nothing authorized under it can be replayed.
            None => match self.physical.get(HSM_AUTHZ_COUNTER_LEGACY_PATH).await? {
                Some(pe) => parse_counter(HSM_AUTHZ_COUNTER_LEGACY_PATH, &pe.value)?,
                None => 0,
            },
        };
        let next =
            current.checked_add(1).ok_or_else(|| RvError::ErrHsm(format!("unwrap counter {key} is exhausted")))?;
        self.physical.put(&BackendEntry { key, value: next.to_string().into_bytes() }).await?;
        Ok(next)
    }

    fn barrier_context(&self, cluster_uuid: &str, epoch: u64) -> Context {
        Context::new(context::barrier_kek(cluster_uuid), Purpose::BarrierKek, epoch, &self.config.node_id)
    }

    /// Per-node + `shamir-ceremony` would initialize a vault with no recovery
    /// key while the config claims one, which is a silent failure. Refused.
    fn refuse_unavailable_recovery(&self) -> Result<(), RvError> {
        match self.config.recovery {
            RecoveryMode::None => Ok(()),
            RecoveryMode::ShamirCeremony => Err(RvError::ErrHsmConfigInvalid(
                "recovery = \"shamir-ceremony\" is not available for the per-node HSM topology: no recovery key \
                 would be generated and init would return no recovery shares. Set recovery = \"none\". See \
                 features/hsm-pool-ha.md § Recovery: Shamir ceremony (T454)"
                    .into(),
            )),
        }
    }

    fn recovery_requested(&self) -> &'static str {
        match self.config.recovery {
            RecoveryMode::None => "none",
            RecoveryMode::ShamirCeremony => "shamir-ceremony",
        }
    }
}

/// Counters are written as decimal by this module only. Anything else is
/// corruption or tampering, and is an error rather than a silent reset to 0.
fn parse_counter(key: &str, raw: &[u8]) -> Result<u64, RvError> {
    std::str::from_utf8(raw).ok().and_then(|s| s.parse::<u64>().ok()).ok_or_else(|| {
        RvError::ErrHsm(format!("unwrap counter at {key} is not a decimal integer; refusing to reset it"))
    })
}

#[maybe_async::maybe_async]
impl SealProvider for HsmSealProvider {
    fn seal_type(&self) -> &str {
        "hsm"
    }

    fn requires_shares(&self) -> bool {
        false
    }

    async fn check_init(&self, _seal_config: &SealConfig) -> Result<(), RvError> {
        self.refuse_unavailable_recovery()
    }

    async fn init_kek(&self, kek: &[u8], _seal_config: &SealConfig) -> Result<Zeroizing<Vec<Vec<u8>>>, RvError> {
        // `Core::init` already ran `check_init`; repeat it for direct callers.
        self.refuse_unavailable_recovery()?;

        // Fresh cluster identity for the barrier context (independent of the
        // namespace root uuid, which is not derived until post_unseal).
        let mut uuid_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut uuid_bytes);
        let cluster_uuid = hex::encode(uuid_bytes);
        let epoch = 0u64;

        let ctx = self.barrier_context(&cluster_uuid, epoch);
        let wrapped = self.backend.wrap_data(self.config.objects.wrap_barrier, &ctx, kek).await?;
        let copy = BvHsmBlob::from_bytes(&wrapped)?;
        let kek_set = BvHsmBlobSet::new(Purpose::BarrierKek, epoch, copy, &self.config.node_id, unix_now_secs()?)?;
        self.store_record(&HsmSealRecord::new_per_node(cluster_uuid, epoch, kek_set)).await?;

        log::warn!(
            target: "security",
            "HSM seal initialized with recovery=none: losing every cluster HSM makes this vault UNRECOVERABLE (intended posture)"
        );

        // Auto-unseal: no operator shares are produced.
        Ok(Zeroizing::new(Vec::new()))
    }

    async fn recover_kek(&self) -> Result<Zeroizing<Vec<u8>>, RvError> {
        let stored = self.load_record().await?.ok_or(RvError::ErrCoreSealConfigNotFound)?;
        let record = &stored.record;
        if record.topology != Topology::PerNode {
            log::error!(target: "security", "HSM seal record topology is `pool`, which this build cannot unseal; vault stays sealed");
            return Err(RvError::ErrHsm(
                "HSM seal record topology `pool` is not supported by this build (T454 phase 2)".into(),
            ));
        }
        if self.config.recovery == RecoveryMode::ShamirCeremony && record.recovery_pub.is_none() {
            log::error!(
                target: "security",
                "HSM seal config sets recovery = \"shamir-ceremony\", but this cluster has no recovery key: none was \
                 ever generated for the per-node topology. Losing this node's HSM loses the vault. See \
                 features/hsm-pool-ha.md § Recovery: Shamir ceremony (T454)"
            );
        }

        // Exactly one copy is chosen, deterministically: the v2 copy bound to
        // this device, else this node's legacy v1 blob. A failure on the chosen
        // copy is final; it is never retried against the other source.
        let node_id = &self.config.node_id;
        let hsm_id = self.backend.hsm_id()?;
        let (blob_bytes, source) = if let Some(copy) = record.kek.as_ref().and_then(|set| set.copy_for(&hsm_id)) {
            (copy.to_bytes()?, "v2")
        } else if let Some(legacy) = record.legacy_node_blobs.get(node_id) {
            if BvHsmBlob::from_bytes(legacy)?.version() != BV_HSM_BLOB_VERSION_V1 {
                return Err(RvError::ErrHsm(format!("legacy KEK blob for node {node_id} is not a v1 blob")));
            }
            (legacy.clone(), "legacy-v1")
        } else {
            return Err(RvError::ErrHsm(format!(
                "no HSM-wrapped KEK for node {node_id} on HSM {hsm_id}; this node must be enrolled"
            )));
        };

        // Signed unwrap authorization ("the signed part"): the release decision
        // is anchored in the HSM, replay-resistant, and audited.
        let counter = self.next_counter().await?;
        let ctx = self.barrier_context(&record.cluster_uuid, record.epoch);
        let request =
            UnwrapRequest::new(ctx.context.clone(), &blob_bytes, node_id, record.epoch, counter, Purpose::BarrierKek);
        let authorization =
            authz::sign_authorization(self.backend.as_ref(), self.config.objects.authz, request).await?;

        // Every key release is an attributable, HSM-signed audit event. The
        // audit broker is not up pre-unseal, so this goes to the security log.
        log::info!(
            target: "security",
            "hsm auto-unseal authorized (hsm_id={hsm_id}, kek_copy={source}): {}",
            authz::audit_record(&authorization)
        );

        self.backend.unwrap_data(self.config.objects.wrap_barrier, &ctx, &blob_bytes).await
    }

    async fn status(&self) -> Result<serde_json::Value, RvError> {
        use serde_json::{json, Value};

        let stored = self.load_record().await?;
        let hsm_id = self.backend.hsm_id().ok();
        let node_id = &self.config.node_id;
        let status = match &stored {
            Some(StoredSealRecord { record: r, stored_version }) => {
                let v2_copies = r.kek.as_ref().map(|k| k.copies.len()).unwrap_or(0);
                let has_v2_copy =
                    hsm_id.as_ref().is_some_and(|id| r.kek.as_ref().is_some_and(|k| k.copy_for(id).is_some()));
                json!({
                    "cluster_uuid": r.cluster_uuid,
                    "epoch": r.epoch,
                    // Per node, each v2 copy is one node's device.
                    "enrolled_nodes": r.legacy_node_blobs.len() + v2_copies,
                    "this_node_enrolled": has_v2_copy || r.legacy_node_blobs.contains_key(node_id),
                    "topology": r.topology.as_str(),
                    "recovery_configured": r.recovery_pub.is_some(),
                    "seal_record_version": stored_version,
                })
            }
            None => json!({
                "cluster_uuid": Value::Null,
                "epoch": Value::Null,
                "enrolled_nodes": 0,
                "this_node_enrolled": false,
                "topology": Topology::PerNode.as_str(),
                "recovery_configured": false,
                "seal_record_version": Value::Null,
            }),
        };
        let mut out = json!({
            "type": "hsm",
            "auto_unseal": true,
            "backend": self.backend.backend_type(),
            "device_serial": self.backend.device_serial(),
            "hsm_id": hsm_id.map(String::from),
            "node_id": node_id,
            "recovery": self.recovery_requested(),
            "recovery_requested": self.recovery_requested(),
            "pqc_key_cache_ttl_secs": self.config.pqc_key_cache_ttl.as_secs(),
        });
        if let (Some(out), Some(extra)) = (out.as_object_mut(), status.as_object()) {
            out.extend(extra.clone());
        }
        Ok(out)
    }
}

#[cfg(all(test, feature = "hsm_mock", not(feature = "sync_handler")))]
mod tests {
    use std::{collections::HashMap, time::Duration};

    use super::*;
    use crate::hsm::{mock::MockHsmBackend, HsmObjectIds};

    /// Throwaway mock-device keys and the records the pre-T454 code (commit
    /// f4139929) wrote with them: `init_kek` for node `fixture-node` with KEK
    /// `0, 1, …, 31`, then three `recover_kek` calls (legacy counter = 3).
    const FIXTURE_STATE: &[u8] = include_bytes!("testdata/hsm-seal-v1/mock-hsm-state.json");
    const FIXTURE_RECORD: &[u8] = include_bytes!("testdata/hsm-seal-v1/core-hsm-seal.json");
    const FIXTURE_COUNTER: &[u8] = include_bytes!("testdata/hsm-seal-v1/core-hsm-authz-counter");
    const FIXTURE_NODE: &str = "fixture-node";

    fn fixture_kek() -> Vec<u8> {
        (0u8..32).collect()
    }

    fn rand_id() -> String {
        let mut b = vec![0u8; 6];
        rand::rng().fill_bytes(&mut b);
        hex::encode(b)
    }

    fn temp_file_backend() -> Arc<dyn PhysicalBackend> {
        let dir = std::env::temp_dir().join(format!("bv-seal-hsm-{}", rand_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut conf: HashMap<String, serde_json::Value> = HashMap::new();
        conf.insert("path".to_string(), serde_json::Value::String(dir.to_string_lossy().to_string()));
        crate::storage::new_backend("file", &conf).unwrap()
    }

    fn cfg(node: &str) -> ResolvedHsmConfig {
        ResolvedHsmConfig {
            backend_type: "mock".into(),
            connector: String::new(),
            objects: HsmObjectIds::default(),
            password: Zeroizing::new(String::new()),
            domains: vec![1],
            pqc_key_cache_ttl: Duration::from_secs(60),
            recovery: RecoveryMode::None,
            state_path: String::new(),
            node_id: node.into(),
        }
    }

    fn seal_config() -> SealConfig {
        SealConfig { secret_shares: 1, secret_threshold: 1 }
    }

    async fn raw(physical: &Arc<dyn PhysicalBackend>, key: &str) -> Option<Vec<u8>> {
        physical.get(key).await.unwrap().map(|e| e.value)
    }

    async fn counter_of(physical: &Arc<dyn PhysicalBackend>, node: &str) -> Option<String> {
        raw(physical, &format!("{HSM_AUTHZ_COUNTER_PREFIX}{node}")).await.map(|v| String::from_utf8(v).unwrap())
    }

    /// The mock device the fixture was captured with, plus storage holding the
    /// fixture's two physical entries exactly as the old code wrote them.
    async fn fixture(
        mut config: ResolvedHsmConfig,
    ) -> (Arc<MockHsmBackend>, Arc<dyn PhysicalBackend>, ResolvedHsmConfig) {
        let state_path = std::env::temp_dir().join(format!("bv-seal-hsm-fixture-{}.json", rand_id()));
        std::fs::write(&state_path, FIXTURE_STATE).unwrap();
        config.state_path = state_path.to_string_lossy().to_string();
        let backend = Arc::new(MockHsmBackend::open(&config).await.unwrap());
        let physical = temp_file_backend();
        physical.put(&BackendEntry { key: HSM_SEAL_RECORD_PATH.into(), value: FIXTURE_RECORD.to_vec() }).await.unwrap();
        physical
            .put(&BackendEntry { key: HSM_AUTHZ_COUNTER_LEGACY_PATH.into(), value: FIXTURE_COUNTER.to_vec() })
            .await
            .unwrap();
        (backend, physical, config)
    }

    #[tokio::test]
    async fn init_then_recover_kek_round_trip() {
        let backend = Arc::new(MockHsmBackend::open(&cfg("n1")).await.unwrap());
        let physical = temp_file_backend();
        let provider = HsmSealProvider::new(backend.clone(), physical.clone(), cfg("n1"));

        let kek = vec![7u8; 32];
        let shares = provider.init_kek(&kek, &seal_config()).await.unwrap();
        assert!(shares.is_empty(), "HSM auto-unseal returns no operator shares");

        // New records are v2, per-node, with a one-copy v2 KEK set for this device.
        let stored = HsmSealRecord::decode(&raw(&physical, HSM_SEAL_RECORD_PATH).await.unwrap()).unwrap();
        assert_eq!(stored.stored_version, record::HSM_SEAL_RECORD_VERSION);
        assert_eq!(stored.record.topology, Topology::PerNode);
        assert!(stored.record.legacy_node_blobs.is_empty());
        let kek_set = stored.record.kek.as_ref().unwrap();
        assert_eq!(kek_set.copies.keys().cloned().collect::<Vec<_>>(), vec![backend.hsm_id().unwrap()]);

        // Recover twice: both succeed and the per-node counter advances.
        assert_eq!(provider.recover_kek().await.unwrap().as_slice(), kek.as_slice());
        assert_eq!(provider.recover_kek().await.unwrap().as_slice(), kek.as_slice());
        assert_eq!(counter_of(&physical, "n1").await.as_deref(), Some("2"));
        assert_eq!(raw(&physical, HSM_AUTHZ_COUNTER_LEGACY_PATH).await, None, "the legacy counter is never written");
    }

    #[tokio::test]
    async fn another_node_on_the_same_device_recovers_from_the_v2_copy() {
        let backend = Arc::new(MockHsmBackend::open(&cfg("n1")).await.unwrap());
        let physical = temp_file_backend();
        HsmSealProvider::new(backend.clone(), physical.clone(), cfg("n1"))
            .init_kek(&[9u8; 32], &seal_config())
            .await
            .unwrap();
        let provider_b = HsmSealProvider::new(backend, physical, cfg("n2"));
        assert_eq!(provider_b.recover_kek().await.unwrap().as_slice(), &[9u8; 32]);
    }

    #[tokio::test]
    async fn recover_fails_on_a_device_without_a_copy() {
        let physical = temp_file_backend();
        let device_a = Arc::new(MockHsmBackend::open(&cfg("n1")).await.unwrap());
        HsmSealProvider::new(device_a, physical.clone(), cfg("n1")).init_kek(&[9u8; 32], &seal_config()).await.unwrap();

        let device_b = Arc::new(MockHsmBackend::open(&cfg("n2")).await.unwrap());
        let err = HsmSealProvider::new(device_b, physical.clone(), cfg("n2")).recover_kek().await.unwrap_err();
        assert!(err.to_string().contains("must be enrolled"), "{err}");
        assert_eq!(counter_of(&physical, "n2").await, None, "no authorization is issued without a copy");
    }

    #[tokio::test]
    async fn v1_fixture_unseals_and_first_write_produces_v2() {
        let (backend, physical, config) = fixture(cfg(FIXTURE_NODE)).await;
        let provider = HsmSealProvider::new(backend, physical.clone(), config);

        let status = provider.status().await.unwrap();
        assert_eq!(status["seal_record_version"], 1);
        assert_eq!(status["topology"], "per-node");
        assert_eq!(status["this_node_enrolled"], true);
        assert_eq!(status["enrolled_nodes"], 1);

        // The v1 record unseals under the new code, from its legacy v1 blob.
        assert_eq!(provider.recover_kek().await.unwrap().as_slice(), fixture_kek().as_slice());
        // This node's counter starts above the legacy global one (3), which stays put.
        assert_eq!(counter_of(&physical, FIXTURE_NODE).await.as_deref(), Some("4"));
        assert_eq!(raw(&physical, HSM_AUTHZ_COUNTER_LEGACY_PATH).await.unwrap(), FIXTURE_COUNTER);
        // Unsealing is not a write: the record is still v1 on disk.
        assert_eq!(raw(&physical, HSM_SEAL_RECORD_PATH).await.unwrap(), FIXTURE_RECORD);

        // The first write converts it; the legacy blob survives byte for byte.
        let loaded = provider.load_record().await.unwrap().unwrap();
        provider.store_record(&loaded.record).await.unwrap();
        let written: serde_json::Value =
            serde_json::from_slice(&raw(&physical, HSM_SEAL_RECORD_PATH).await.unwrap()).unwrap();
        assert_eq!(written["version"], 2);
        let v1: serde_json::Value = serde_json::from_slice(FIXTURE_RECORD).unwrap();
        assert_eq!(written["legacy_node_blobs"][FIXTURE_NODE], v1["kek_blobs"][FIXTURE_NODE]);

        // ...and the converted record keeps unsealing.
        assert_eq!(provider.recover_kek().await.unwrap().as_slice(), fixture_kek().as_slice());
        assert_eq!(counter_of(&physical, FIXTURE_NODE).await.as_deref(), Some("5"));
        assert_eq!(provider.status().await.unwrap()["seal_record_version"], 2);
    }

    #[tokio::test]
    async fn v1_fixture_still_binds_its_node() {
        // v1 blobs bind node_id: another node on the same device cannot use it.
        let (backend, physical, _) = fixture(cfg("someone-else")).await;
        let provider = HsmSealProvider::new(backend, physical, cfg("someone-else"));
        assert!(provider.recover_kek().await.is_err());
    }

    #[tokio::test]
    async fn per_node_shamir_ceremony_is_refused_at_init() {
        let mut config = cfg("n1");
        config.recovery = RecoveryMode::ShamirCeremony;
        let backend = Arc::new(MockHsmBackend::open(&config).await.unwrap());
        let physical = temp_file_backend();
        let provider = HsmSealProvider::new(backend, physical.clone(), config);

        let err = provider.check_init(&seal_config()).await.unwrap_err();
        assert!(matches!(&err, RvError::ErrHsmConfigInvalid(m) if m.contains("features/hsm-pool-ha.md")), "{err}");
        assert!(provider.init_kek(&[1u8; 32], &seal_config()).await.is_err());
        assert_eq!(raw(&physical, HSM_SEAL_RECORD_PATH).await, None, "nothing is written");

        let mut ok = cfg("n1");
        ok.recovery = RecoveryMode::None;
        let backend = Arc::new(MockHsmBackend::open(&ok).await.unwrap());
        HsmSealProvider::new(backend, physical, ok).check_init(&seal_config()).await.unwrap();
    }

    #[tokio::test]
    async fn initialized_per_node_cluster_with_shamir_ceremony_keeps_unsealing_and_says_so() {
        let mut config = cfg(FIXTURE_NODE);
        config.recovery = RecoveryMode::ShamirCeremony;
        let (backend, physical, config) = fixture(config).await;
        let provider = HsmSealProvider::new(backend, physical, config);

        assert_eq!(provider.recover_kek().await.unwrap().as_slice(), fixture_kek().as_slice());
        let status = provider.status().await.unwrap();
        assert_eq!(status["recovery_requested"], "shamir-ceremony");
        assert_eq!(status["recovery"], "shamir-ceremony");
        assert_eq!(status["recovery_configured"], false, "a recovery that never existed is never reported");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn per_node_counters_do_not_race_under_concurrent_unseals() {
        let backend = Arc::new(MockHsmBackend::open(&cfg("n0")).await.unwrap());
        let physical = temp_file_backend();
        HsmSealProvider::new(backend.clone(), physical.clone(), cfg("n0"))
            .init_kek(&[5u8; 32], &seal_config())
            .await
            .unwrap();
        // A legacy global counter left by the pre-T454 code.
        physical.put(&BackendEntry { key: HSM_AUTHZ_COUNTER_LEGACY_PATH.into(), value: b"10".to_vec() }).await.unwrap();

        const NODES: usize = 6;
        const UNSEALS: u64 = 4;
        let mut tasks = Vec::new();
        for n in 0..NODES {
            let provider = Arc::new(HsmSealProvider::new(backend.clone(), physical.clone(), cfg(&format!("n{n}"))));
            tasks.push(tokio::spawn(async move {
                for _ in 0..UNSEALS {
                    assert_eq!(provider.recover_kek().await.unwrap().as_slice(), &[5u8; 32]);
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        for n in 0..NODES {
            let expected = (10 + UNSEALS).to_string();
            assert_eq!(counter_of(&physical, &format!("n{n}")).await.as_deref(), Some(expected.as_str()), "node n{n}");
        }
        assert_eq!(raw(&physical, HSM_AUTHZ_COUNTER_LEGACY_PATH).await.unwrap(), b"10");
    }

    #[tokio::test]
    async fn a_corrupt_counter_is_an_error_not_a_reset() {
        let backend = Arc::new(MockHsmBackend::open(&cfg("n1")).await.unwrap());
        let physical = temp_file_backend();
        let provider = HsmSealProvider::new(backend, physical.clone(), cfg("n1"));
        provider.init_kek(&[3u8; 32], &seal_config()).await.unwrap();

        physical
            .put(&BackendEntry { key: format!("{HSM_AUTHZ_COUNTER_PREFIX}n1"), value: b"12x".to_vec() })
            .await
            .unwrap();
        assert!(provider.recover_kek().await.is_err());

        physical.delete(&format!("{HSM_AUTHZ_COUNTER_PREFIX}n1")).await.unwrap();
        physical.put(&BackendEntry { key: HSM_AUTHZ_COUNTER_LEGACY_PATH.into(), value: b"-1".to_vec() }).await.unwrap();
        assert!(provider.recover_kek().await.is_err(), "a corrupt legacy counter does not seed 0");
    }

    #[tokio::test]
    async fn pool_records_and_unknown_versions_stay_sealed() {
        let backend = Arc::new(MockHsmBackend::open(&cfg("n1")).await.unwrap());
        let physical = temp_file_backend();
        let provider = HsmSealProvider::new(backend.clone(), physical.clone(), cfg("n1"));
        provider.init_kek(&[3u8; 32], &seal_config()).await.unwrap();

        let mut record = provider.load_record().await.unwrap().unwrap().record;
        record.topology = Topology::Pool;
        record.members.insert(
            backend.hsm_id().unwrap(),
            record::HsmMember {
                name: "hsm-a".into(),
                gateway: String::new(),
                serial: backend.device_serial(),
                identity_pub: backend.identity_public_key().unwrap(),
                seed_ecdh_pub: backend.identity_public_key().unwrap(),
                authz_pub: backend.authz_public_key().unwrap(),
                authz_alg: crate::hsm::AuthzAlg::Ed25519,
                attestation_fps: vec![],
                state: record::MemberState::Active,
                pending_revocations: vec![],
            },
        );
        provider.store_record(&record).await.unwrap();
        let err = provider.recover_kek().await.unwrap_err();
        assert!(err.to_string().contains("pool"), "{err}");

        let mut future: serde_json::Value = serde_json::from_slice(&record.encode().unwrap()).unwrap();
        future["version"] = 3.into();
        physical
            .put(&BackendEntry { key: HSM_SEAL_RECORD_PATH.into(), value: serde_json::to_vec(&future).unwrap() })
            .await
            .unwrap();
        assert!(provider.recover_kek().await.is_err());
        assert!(provider.status().await.is_err());
    }
}
