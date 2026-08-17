//! HSM auto-unseal seal provider (spec § Capability 1).
//!
//! At init the barrier KEK is wrapped under the local HSM's `bv-wrap-barrier`
//! key and the opaque blob is stored (per node) in physical storage. At startup
//! the KEK is recovered with a signed, audited, replay-resistant unwrap — no
//! operator share entry. Nothing on disk is decryptable without the key inside
//! an enrolled HSM (spec rule 6).

use std::{collections::BTreeMap, sync::Arc};

use rand::Rng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    core::SealConfig,
    errors::RvError,
    hsm::{
        authz::{self, UnwrapRequest},
        blob::{Context, Purpose},
        context, HsmBackend, RecoveryMode, ResolvedHsmConfig,
    },
    seal::SealProvider,
    storage::{Backend as PhysicalBackend, BackendEntry},
};

/// Physical-storage key for the per-node HSM seal record. Non-secret (holds
/// only opaque wrapped blobs), so it lives in the pre-unseal physical layer.
const HSM_SEAL_RECORD_PATH: &str = "core/hsm-seal";
/// Physical-storage key for the monotonic unwrap-authorization counter.
const HSM_AUTHZ_COUNTER_PATH: &str = "core/hsm-authz-counter";

const HSM_SEAL_RECORD_VERSION: u8 = 1;

/// Persisted, replicated custody record. Each cluster node stores its own
/// HSM-wrapped copy of the KEK, keyed by node id (spec § Capability 3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmSealRecord {
    pub version: u8,
    pub cluster_uuid: String,
    pub epoch: u64,
    /// node_id → serialized `BvHsmBlob` of the barrier KEK for that node.
    pub kek_blobs: BTreeMap<String, Vec<u8>>,
}

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
    async fn load_record(&self) -> Result<Option<HsmSealRecord>, RvError> {
        match self.physical.get(HSM_SEAL_RECORD_PATH).await? {
            Some(pe) => {
                let rec: HsmSealRecord =
                    serde_json::from_slice(&pe.value).map_err(|_| RvError::ErrHsmBlobInvalid)?;
                if rec.version != HSM_SEAL_RECORD_VERSION {
                    return Err(RvError::ErrHsmBlobInvalid);
                }
                Ok(Some(rec))
            }
            None => Ok(None),
        }
    }

    #[maybe_async::maybe_async]
    async fn store_record(&self, rec: &HsmSealRecord) -> Result<(), RvError> {
        let value = serde_json::to_vec(rec).map_err(|e| RvError::ErrHsm(format!("seal record encode: {e}")))?;
        self.physical.put(&BackendEntry { key: HSM_SEAL_RECORD_PATH.to_string(), value }).await
    }

    /// Read, increment, and persist the strictly-increasing unwrap counter so a
    /// captured (blob, authorization) pair cannot be replayed across restarts.
    #[maybe_async::maybe_async]
    async fn next_counter(&self) -> Result<u64, RvError> {
        let current = match self.physical.get(HSM_AUTHZ_COUNTER_PATH).await? {
            Some(pe) => String::from_utf8(pe.value).ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
            None => 0,
        };
        let next = current.saturating_add(1);
        self.physical
            .put(&BackendEntry { key: HSM_AUTHZ_COUNTER_PATH.to_string(), value: next.to_string().into_bytes() })
            .await?;
        Ok(next)
    }

    fn barrier_context(&self, cluster_uuid: &str, epoch: u64) -> Context {
        Context::new(context::barrier_kek(cluster_uuid), Purpose::BarrierKek, epoch, &self.config.node_id)
    }
}

#[maybe_async::maybe_async]
impl SealProvider for HsmSealProvider {
    fn seal_type(&self) -> &str {
        "hsm"
    }

    fn requires_shares(&self) -> bool {
        false
    }

    async fn init_kek(&self, kek: &[u8], _seal_config: &SealConfig) -> Result<Zeroizing<Vec<Vec<u8>>>, RvError> {
        // Fresh cluster identity for the barrier context (independent of the
        // namespace root uuid, which is not derived until post_unseal).
        let mut uuid_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut uuid_bytes);
        let cluster_uuid = hex::encode(uuid_bytes);
        let epoch = 0u64;

        let ctx = self.barrier_context(&cluster_uuid, epoch);
        let blob = self.backend.wrap_data(self.config.objects.wrap_barrier, &ctx, kek).await?;

        let mut kek_blobs = BTreeMap::new();
        kek_blobs.insert(self.config.node_id.clone(), blob);
        let record = HsmSealRecord { version: HSM_SEAL_RECORD_VERSION, cluster_uuid, epoch, kek_blobs };
        self.store_record(&record).await?;

        match self.config.recovery {
            RecoveryMode::None => log::warn!(
                target: "security",
                "HSM seal initialized with recovery=none: losing every cluster HSM makes this vault UNRECOVERABLE (intended posture)"
            ),
            RecoveryMode::ShamirCeremony => log::warn!(
                target: "security",
                "HSM seal initialized with recovery=shamir-ceremony: store the recovery shares offline"
            ),
        }

        // Auto-unseal: no operator shares are produced.
        Ok(Zeroizing::new(Vec::new()))
    }

    async fn recover_kek(&self) -> Result<Zeroizing<Vec<u8>>, RvError> {
        let record = self.load_record().await?.ok_or(RvError::ErrCoreSealConfigNotFound)?;
        let node_id = &self.config.node_id;
        let blob = record
            .kek_blobs
            .get(node_id)
            .ok_or_else(|| RvError::ErrHsm(format!("no HSM-wrapped KEK for node {node_id}; this node must be enrolled")))?;

        // Signed unwrap authorization ("the signed part"): the release decision
        // is anchored in the HSM, replay-resistant, and audited.
        let counter = self.next_counter().await?;
        let ctx = self.barrier_context(&record.cluster_uuid, record.epoch);
        let request =
            UnwrapRequest::new(ctx.context.clone(), blob, node_id, record.epoch, counter, Purpose::BarrierKek);
        let authorization = authz::sign_authorization(self.backend.as_ref(), self.config.objects.authz, request).await?;

        // Every key release is an attributable, HSM-signed audit event. The
        // audit broker is not up pre-unseal, so this goes to the security log.
        log::info!(target: "security", "hsm auto-unseal authorized: {}", authz::audit_record(&authorization));

        self.backend.unwrap_data(self.config.objects.wrap_barrier, &ctx, blob).await
    }

    async fn status(&self) -> Result<serde_json::Value, RvError> {
        let record = self.load_record().await?;
        let recovery = match self.config.recovery {
            RecoveryMode::None => "none",
            RecoveryMode::ShamirCeremony => "shamir-ceremony",
        };
        let (cluster_uuid, epoch, enrolled_nodes, this_node_enrolled) = match &record {
            Some(r) => (
                serde_json::Value::String(r.cluster_uuid.clone()),
                serde_json::Value::from(r.epoch),
                serde_json::Value::from(r.kek_blobs.len()),
                serde_json::Value::from(r.kek_blobs.contains_key(&self.config.node_id)),
            ),
            None => (serde_json::Value::Null, serde_json::Value::Null, serde_json::Value::from(0), serde_json::Value::from(false)),
        };
        Ok(serde_json::json!({
            "type": "hsm",
            "auto_unseal": true,
            "backend": self.backend.backend_type(),
            "device_serial": self.backend.device_serial(),
            "node_id": self.config.node_id,
            "cluster_uuid": cluster_uuid,
            "epoch": epoch,
            "enrolled_nodes": enrolled_nodes,
            "this_node_enrolled": this_node_enrolled,
            "recovery": recovery,
            "pqc_key_cache_ttl_secs": self.config.pqc_key_cache_ttl.as_secs(),
        }))
    }
}

#[cfg(all(test, feature = "hsm_mock"))]
mod tests {
    use super::*;
    use crate::hsm::{mock::MockHsmBackend, HsmObjectIds};
    use std::{collections::HashMap, time::Duration};

    fn temp_file_backend() -> Arc<dyn PhysicalBackend> {
        let dir = std::env::temp_dir().join(format!("bv-seal-hsm-{}", hex::encode(rand_id())));
        std::fs::create_dir_all(&dir).unwrap();
        let mut conf: HashMap<String, serde_json::Value> = HashMap::new();
        conf.insert("path".to_string(), serde_json::Value::String(dir.to_string_lossy().to_string()));
        crate::storage::new_backend("file", &conf).unwrap()
    }

    fn rand_id() -> Vec<u8> {
        let mut b = vec![0u8; 6];
        rand::rng().fill_bytes(&mut b);
        b
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

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn init_then_recover_kek_round_trip() {
        let backend = Arc::new(MockHsmBackend::open(&cfg("n1")).await.unwrap());
        let physical = temp_file_backend();
        let provider = HsmSealProvider::new(backend, physical, cfg("n1"));

        let kek = vec![7u8; 32];
        let shares = provider.init_kek(&kek, &SealConfig { secret_shares: 1, secret_threshold: 1 }).await.unwrap();
        assert!(shares.is_empty(), "HSM auto-unseal returns no operator shares");

        // Recover twice: both succeed (KEK survives the storage round-trip) and
        // the monotonic authorization counter advances.
        let recovered = provider.recover_kek().await.unwrap();
        assert_eq!(recovered.as_slice(), kek.as_slice());
        let recovered2 = provider.recover_kek().await.unwrap();
        assert_eq!(recovered2.as_slice(), kek.as_slice());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn recover_fails_for_unenrolled_node() {
        let backend = Arc::new(MockHsmBackend::open(&cfg("n1")).await.unwrap());
        let physical = temp_file_backend();
        // Init wraps the KEK for node "n1"...
        let provider_a = HsmSealProvider::new(backend.clone(), physical.clone(), cfg("n1"));
        provider_a.init_kek(&[9u8; 32], &SealConfig { secret_shares: 1, secret_threshold: 1 }).await.unwrap();

        // ...but a node "n2" sharing the same storage has no wrapped copy.
        let provider_b = HsmSealProvider::new(backend, physical, cfg("n2"));
        assert!(provider_b.recover_kek().await.is_err());
    }
}
