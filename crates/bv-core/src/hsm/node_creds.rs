//! Node transport keys and credential delivery (T454 phase 4).
//!
//! A pool node owns an ML-KEM-768 transport key in `credential_dir` and
//! publishes its public half at `core/hsm/node-pending/<node_id>`. Enrollment
//! seals each per-member credential to it (`KemDemEnvelopeV1`) at
//! `core/hsm/node-credentials/<node_id>`; the node installs them locally and
//! deletes the entry. Spec: `features/hsm-pool-ha.md` § Node enrollment.

use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
};

use bv_crypto::{KemDemEnvelopeV1, KemKeypair, MlKem768Provider, ML_KEM_768_SEED_LEN};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    errors::RvError,
    hsm::{
        admin::NodeCredential,
        blob::HsmId,
        blobset::{deserialize_unique_map, unix_now_secs},
        custody_store::HSM_CUSTODY_LOCK,
        validate_node_id,
    },
    storage::{Backend as PhysicalBackend, BackendEntry},
};

/// Physical keyspace (a sealed node reads and writes these through Raft).
pub const NODE_PENDING_PREFIX: &str = "core/hsm/node-pending/";
pub const NODE_CREDENTIALS_PREFIX: &str = "core/hsm/node-credentials/";

const RECORD_VERSION: u8 = 1;
const TRANSPORT_SEED_FILE: &str = "transport.seed";
const CREDENTIALS_FILE: &str = "credentials.json";
const DELIVERY_AAD_CONTEXT: &str = "bastionvault/hsm/node-credential/v1";
/// FIPS 203 ML-KEM-768 encapsulation-key length.
const ML_KEM_768_PUBLIC_KEY_LEN: usize = 1184;

/// Hex SHA-256 of a transport public key: what the operator compares with
/// the node's log before enrolling it.
pub fn transport_fingerprint(public_key: &[u8]) -> String {
    hex::encode(Sha256::digest(public_key))
}

/// A node waiting to be enrolled: its transport public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingNode {
    pub version: u8,
    pub node_id: String,
    #[serde(with = "serde_bytes")]
    pub transport_pub: Vec<u8>,
    pub transport_fp: String,
    pub created_at: u64,
}

impl PendingNode {
    pub fn decode(node_id: &str, bytes: &[u8]) -> Result<Self, RvError> {
        let invalid = |why: String| RvError::ErrHsm(format!("invalid pending HSM node record {node_id}: {why}"));
        let rec: Self = serde_json::from_slice(bytes).map_err(|e| invalid(e.to_string()))?;
        if rec.version != RECORD_VERSION {
            return Err(invalid(format!("unsupported version {}", rec.version)));
        }
        if rec.node_id != node_id {
            return Err(invalid(format!("record names node {}", rec.node_id)));
        }
        if rec.transport_pub.len() != ML_KEM_768_PUBLIC_KEY_LEN {
            return Err(invalid("transport key is not an ML-KEM-768 public key".into()));
        }
        if rec.transport_fp != transport_fingerprint(&rec.transport_pub) {
            return Err(invalid("transport key fingerprint does not match the key".into()));
        }
        Ok(rec)
    }
}

/// One credential sealed to a node's transport key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveredCredential {
    pub auth_key_id: u16,
    pub envelope: KemDemEnvelopeV1,
}

/// What enrollment leaves for a node: one sealed credential per member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialDelivery {
    pub version: u8,
    pub node_id: String,
    pub transport_fp: String,
    #[serde(deserialize_with = "deserialize_unique_map")]
    pub credentials: BTreeMap<HsmId, DeliveredCredential>,
}

impl CredentialDelivery {
    pub fn new(node_id: &str, transport_fp: &str) -> Self {
        Self {
            version: RECORD_VERSION,
            node_id: node_id.to_string(),
            transport_fp: transport_fp.to_string(),
            credentials: BTreeMap::new(),
        }
    }

    pub fn decode(node_id: &str, bytes: &[u8]) -> Result<Self, RvError> {
        let invalid = |why: String| RvError::ErrHsm(format!("invalid HSM credential delivery for {node_id}: {why}"));
        let rec: Self = serde_json::from_slice(bytes).map_err(|e| invalid(e.to_string()))?;
        if rec.version != RECORD_VERSION {
            return Err(invalid(format!("unsupported version {}", rec.version)));
        }
        if rec.node_id != node_id {
            return Err(invalid(format!("record names node {}", rec.node_id)));
        }
        Ok(rec)
    }

    pub fn encode(&self) -> Result<Vec<u8>, RvError> {
        serde_json::to_vec(self).map_err(|e| RvError::ErrHsm(format!("credential delivery encode: {e}")))
    }
}

/// AAD of a sealed credential: binds node, device, auth key and the exact
/// transport key, so an envelope moved to another of them does not open.
fn delivery_aad(node_id: &str, hsm_id: &HsmId, auth_key_id: u16, transport_fp: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for part in
        [DELIVERY_AAD_CONTEXT.as_bytes(), node_id.as_bytes(), hsm_id.as_str().as_bytes(), transport_fp.as_bytes()]
    {
        out.extend_from_slice(&(part.len() as u64).to_be_bytes());
        out.extend_from_slice(part);
    }
    out.extend_from_slice(&auth_key_id.to_be_bytes());
    out
}

/// Seal `credential` for `node_id` on `hsm_id` to the node's transport key.
pub fn seal_credential(
    node_id: &str,
    hsm_id: &HsmId,
    transport_pub: &[u8],
    credential: &NodeCredential,
) -> Result<DeliveredCredential, RvError> {
    let fp = transport_fingerprint(transport_pub);
    let aad = delivery_aad(node_id, hsm_id, credential.auth_key_id(), &fp);
    let envelope = KemDemEnvelopeV1::seal(&MlKem768Provider, transport_pub, &aad, credential.key())
        .map_err(|e| RvError::ErrHsm(format!("sealing the HSM credential for {node_id}: {e}")))?;
    Ok(DeliveredCredential { auth_key_id: credential.auth_key_id(), envelope })
}

/// Local, at-rest form of the node's credentials (`credentials.json`, 0600).
/// Each entry zeroizes its key on drop.
#[derive(Serialize, Deserialize)]
struct LocalCredentials {
    version: u8,
    node_id: String,
    transport_fp: String,
    members: BTreeMap<String, LocalCredential>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct LocalCredential {
    auth_key_id: u16,
    /// Hex of the 32-byte credential.
    key: String,
}

/// The node's `credential_dir`: transport key seed and installed credentials.
/// Files are created 0600 and refused when group or others can read them.
pub struct NodeCredentialStore {
    dir: PathBuf,
    node_id: String,
}

impl NodeCredentialStore {
    pub fn new(dir: &str, node_id: &str) -> Result<Self, RvError> {
        validate_node_id(node_id)?;
        if dir.trim().is_empty() {
            return Err(RvError::ErrHsmConfigInvalid("the HSM pool `credential_dir` is empty".into()));
        }
        Ok(Self { dir: PathBuf::from(dir), node_id: node_id.to_string() })
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Create the transport key on first use; return this node's pending
    /// record. The fingerprint is logged for out-of-band confirmation.
    pub fn ensure_transport_key(&self) -> Result<PendingNode, RvError> {
        let path = self.dir.join(TRANSPORT_SEED_FILE);
        if !path.exists() {
            create_private_dir(&self.dir)?;
            let mut seed = Zeroizing::new(vec![0u8; ML_KEM_768_SEED_LEN]);
            rand::rng().fill_bytes(seed.as_mut_slice());
            write_private_file(&path, &seed, true)?;
            log::info!(target: "security", "created the HSM pool transport key in {}", self.dir.display());
        }
        let keypair = self.transport_keypair()?;
        let transport_fp = transport_fingerprint(keypair.public_key());
        log::info!(
            target: "security",
            "HSM pool node {} transport key fingerprint: {transport_fp} (confirm it before `node add`)",
            self.node_id
        );
        Ok(PendingNode {
            version: RECORD_VERSION,
            node_id: self.node_id.clone(),
            transport_pub: keypair.public_key().to_vec(),
            transport_fp,
            created_at: unix_now_secs()?,
        })
    }

    fn transport_keypair(&self) -> Result<KemKeypair, RvError> {
        let seed = read_private_file(&self.dir.join(TRANSPORT_SEED_FILE))?;
        MlKem768Provider
            .keypair_from_seed(&seed)
            .map_err(|e| RvError::ErrHsm(format!("HSM pool transport key in {}: {e}", self.dir.display())))
    }

    fn load_local(&self) -> Result<Option<LocalCredentials>, RvError> {
        let path = self.dir.join(CREDENTIALS_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = read_private_file(&path)?;
        let local: LocalCredentials = serde_json::from_slice(&bytes)
            .map_err(|e| RvError::ErrHsm(format!("HSM credentials file {} is corrupt: {e}", path.display())))?;
        if local.version != RECORD_VERSION || local.node_id != self.node_id {
            return Err(RvError::ErrHsm(format!(
                "HSM credentials file {} is version {} for node {:?}; this is node {:?}",
                path.display(),
                local.version,
                local.node_id,
                self.node_id
            )));
        }
        Ok(Some(local))
    }

    /// The installed credential for `hsm_id`, if any.
    pub fn credential_for(&self, hsm_id: &HsmId) -> Result<Option<NodeCredential>, RvError> {
        let Some(local) = self.load_local()? else { return Ok(None) };
        let Some(entry) = local.members.get(hsm_id.as_str()) else { return Ok(None) };
        let key = Zeroizing::new(
            hex::decode(&entry.key).map_err(|_| RvError::ErrHsm(format!("HSM credential for {hsm_id} is not hex")))?,
        );
        NodeCredential::from_parts(entry.auth_key_id, key).map(Some)
    }

    /// Members this node holds a credential for.
    pub fn members(&self) -> Result<Vec<String>, RvError> {
        Ok(self.load_local()?.map(|l| l.members.keys().cloned().collect()).unwrap_or_default())
    }

    /// Store credentials this process made itself (the init node's bootstrap
    /// enrollment): they never pass through storage (spec § Bootstrap, step 2).
    pub fn install_direct(&self, credentials: &[(HsmId, NodeCredential)]) -> Result<(), RvError> {
        let local_fp = transport_fingerprint(self.transport_keypair()?.public_key());
        self.merge(local_fp, credentials)
    }

    fn merge(&self, local_fp: String, credentials: &[(HsmId, NodeCredential)]) -> Result<(), RvError> {
        let mut local = self.load_local()?.unwrap_or_else(|| LocalCredentials {
            version: RECORD_VERSION,
            node_id: self.node_id.clone(),
            transport_fp: local_fp.clone(),
            members: BTreeMap::new(),
        });
        local.transport_fp = local_fp;
        for (hsm_id, credential) in credentials {
            let entry = LocalCredential { auth_key_id: credential.auth_key_id(), key: hex::encode(credential.key()) };
            local.members.insert(hsm_id.to_string(), entry);
        }
        let bytes = Zeroizing::new(
            serde_json::to_vec(&local).map_err(|e| RvError::ErrHsm(format!("HSM credentials encode: {e}")))?,
        );
        write_private_file(&self.dir.join(CREDENTIALS_FILE), &bytes, false)
    }

    /// Open every credential in `delivery` and merge them into the local
    /// file. Nothing is written unless every envelope opens.
    pub fn install(&self, delivery: &CredentialDelivery) -> Result<Vec<HsmId>, RvError> {
        if delivery.node_id != self.node_id {
            return Err(RvError::ErrHsm(format!(
                "HSM credentials for node {} delivered to {}",
                delivery.node_id, self.node_id
            )));
        }
        let keypair = self.transport_keypair()?;
        let local_fp = transport_fingerprint(keypair.public_key());
        if delivery.transport_fp != local_fp {
            return Err(RvError::ErrHsm(format!(
                "HSM credentials for {} were sealed to transport key {}, but this node's is {local_fp}; re-run `node \
                 add` after confirming the fingerprint",
                self.node_id, delivery.transport_fp
            )));
        }
        let mut opened = Vec::new();
        for (hsm_id, sealed) in &delivery.credentials {
            let aad = delivery_aad(&self.node_id, hsm_id, sealed.auth_key_id, &local_fp);
            let key =
                Zeroizing::new(sealed.envelope.open(&MlKem768Provider, keypair.secret_key(), &aad).map_err(|e| {
                    log::error!(target: "security", "HSM credential envelope for {hsm_id} does not open: {e}");
                    RvError::ErrHsm(format!("the HSM credential for {hsm_id} does not open with this node's key: {e}"))
                })?);
            opened.push((hsm_id.clone(), NodeCredential::from_parts(sealed.auth_key_id, key)?));
        }
        self.merge(local_fp, &opened)?;
        Ok(opened.into_iter().map(|(id, _)| id).collect())
    }
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> Result<(), RvError> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| RvError::ErrHsm(format!("creating HSM credential_dir {}: {e}", dir.display())))
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> Result<(), RvError> {
    std::fs::create_dir_all(dir)
        .map_err(|e| RvError::ErrHsm(format!("creating HSM credential_dir {}: {e}", dir.display())))
}

/// Write `bytes` 0600: through a temporary file and a rename, or, for a key
/// that must never be replaced (`create_new`), refusing an existing file.
fn write_private_file(path: &Path, bytes: &[u8], create_new: bool) -> Result<(), RvError> {
    let err = |e: std::io::Error| RvError::ErrHsm(format!("writing {}: {e}", path.display()));
    let target = if create_new { path.to_path_buf() } else { path.with_extension("tmp") };
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&target).map_err(err)?;
    file.write_all(bytes).map_err(err)?;
    file.sync_all().map_err(err)?;
    if !create_new {
        std::fs::rename(&target, path).map_err(err)?;
    }
    Ok(())
}

/// Read a private file, refusing one that group or others can access.
fn read_private_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, RvError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|e| RvError::ErrHsm(format!("reading {}: {e}", path.display())))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            log::error!(target: "security", "refusing {}: mode {mode:o} lets group or others read it", path.display());
            return Err(RvError::ErrHsm(format!(
                "{} has mode {mode:o}; HSM credential files must be 0600 (chmod 600)",
                path.display()
            )));
        }
    }
    std::fs::read(path).map(Zeroizing::new).map_err(|e| RvError::ErrHsm(format!("reading {}: {e}", path.display())))
}

fn pending_key(node_id: &str) -> Result<String, RvError> {
    validate_node_id(node_id)?;
    Ok(format!("{NODE_PENDING_PREFIX}{node_id}"))
}

fn delivery_key(node_id: &str) -> Result<String, RvError> {
    validate_node_id(node_id)?;
    Ok(format!("{NODE_CREDENTIALS_PREFIX}{node_id}"))
}

/// Publish this node's pending record unless the same one is there.
#[maybe_async::maybe_async]
pub async fn publish_pending(physical: &dyn PhysicalBackend, pending: &PendingNode) -> Result<(), RvError> {
    let key = pending_key(&pending.node_id)?;
    if let Some(entry) = physical.get(&key).await? {
        if PendingNode::decode(&pending.node_id, &entry.value).is_ok_and(|p| p.transport_fp == pending.transport_fp) {
            return Ok(());
        }
    }
    let value = serde_json::to_vec(pending).map_err(|e| RvError::ErrHsm(format!("pending node encode: {e}")))?;
    physical.put(&BackendEntry { key, value }).await
}

#[maybe_async::maybe_async]
pub async fn read_pending(physical: &dyn PhysicalBackend, node_id: &str) -> Result<Option<PendingNode>, RvError> {
    match physical.get(&pending_key(node_id)?).await? {
        Some(entry) => PendingNode::decode(node_id, &entry.value).map(Some),
        None => Ok(None),
    }
}

/// Node ids with a pending record.
#[maybe_async::maybe_async]
pub async fn list_pending(physical: &dyn PhysicalBackend) -> Result<Vec<String>, RvError> {
    Ok(physical.list(NODE_PENDING_PREFIX).await?.into_iter().filter(|n| validate_node_id(n).is_ok()).collect())
}

#[maybe_async::maybe_async]
pub async fn read_delivery(
    physical: &dyn PhysicalBackend,
    node_id: &str,
) -> Result<Option<CredentialDelivery>, RvError> {
    match physical.get(&delivery_key(node_id)?).await? {
        Some(entry) => CredentialDelivery::decode(node_id, &entry.value).map(Some),
        None => Ok(None),
    }
}

/// Write a delivery. The caller holds `hsm-custody`.
#[maybe_async::maybe_async]
pub async fn write_delivery(physical: &dyn PhysicalBackend, delivery: &CredentialDelivery) -> Result<(), RvError> {
    let key = delivery_key(&delivery.node_id)?;
    physical.put(&BackendEntry { key, value: delivery.encode()? }).await
}

/// Remove a node's undelivered credentials and pending record (revocation:
/// a revoked node must never install credentials made before it).
#[maybe_async::maybe_async]
pub async fn discard_node_entries(physical: &dyn PhysicalBackend, node_id: &str) -> Result<(), RvError> {
    physical.delete(&delivery_key(node_id)?).await?;
    physical.delete(&pending_key(node_id)?).await
}

#[maybe_async::maybe_async]
pub async fn delete_pending(physical: &dyn PhysicalBackend, node_id: &str) -> Result<(), RvError> {
    physical.delete(&pending_key(node_id)?).await
}

/// Install any credentials waiting for this node, then delete the entry, all
/// under `hsm-custody` so a concurrent enrollment is never lost.
#[maybe_async::maybe_async]
pub async fn pick_up(physical: &dyn PhysicalBackend, store: &NodeCredentialStore) -> Result<Vec<HsmId>, RvError> {
    let key = delivery_key(store.node_id())?;
    let _custody_lock = physical.lock(HSM_CUSTODY_LOCK).await?;
    let Some(entry) = physical.get(&key).await? else { return Ok(Vec::new()) };
    let delivery = CredentialDelivery::decode(store.node_id(), &entry.value)?;
    let installed = store.install(&delivery)?;
    physical.delete(&key).await?;
    log::info!(target: "security", "installed HSM pool credentials for {installed:?} and removed the delivery");
    Ok(installed)
}

#[cfg(all(test, not(feature = "sync_handler")))]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> String {
        let mut b = [0u8; 6];
        rand::rng().fill_bytes(&mut b);
        std::env::temp_dir().join(format!("bv-hsm-creds-{tag}-{}", hex::encode(b))).to_string_lossy().to_string()
    }

    fn id(serial: &str) -> HsmId {
        HsmId::from_parts("mock", serial).unwrap()
    }

    #[test]
    fn delivery_round_trip_installs_only_for_the_right_node_and_key() {
        let store = NodeCredentialStore::new(&temp_dir("rt"), "vault-1").unwrap();
        let pending = store.ensure_transport_key().unwrap();
        assert_eq!(store.ensure_transport_key().unwrap().transport_fp, pending.transport_fp, "the key is stable");
        PendingNode::decode("vault-1", &serde_json::to_vec(&pending).unwrap()).unwrap();

        let cred = NodeCredential::generate(0x100).unwrap();
        let mut delivery = CredentialDelivery::new("vault-1", &pending.transport_fp);
        delivery
            .credentials
            .insert(id("A"), seal_credential("vault-1", &id("A"), &pending.transport_pub, &cred).unwrap());
        assert_eq!(store.install(&delivery).unwrap(), vec![id("A")]);
        assert_eq!(store.credential_for(&id("A")).unwrap().unwrap().key(), cred.key());
        assert!(store.credential_for(&id("B")).unwrap().is_none());

        // An envelope moved to another device entry does not open (AAD binds the device).
        let mut moved = CredentialDelivery::new("vault-1", &pending.transport_fp);
        moved.credentials.insert(id("B"), delivery.credentials[&id("A")].clone());
        assert!(store.install(&moved).is_err());
        assert!(store.credential_for(&id("B")).unwrap().is_none(), "nothing is written on failure");

        // Sealed to another node's key, or addressed to another node: refused.
        let other = NodeCredentialStore::new(&temp_dir("other"), "vault-2").unwrap().ensure_transport_key().unwrap();
        let mut foreign = CredentialDelivery::new("vault-1", &other.transport_fp);
        foreign.credentials.insert(id("A"), seal_credential("vault-1", &id("A"), &other.transport_pub, &cred).unwrap());
        assert!(store.install(&foreign).unwrap_err().to_string().contains("re-run `node add`"));
        let addressed = CredentialDelivery::new("vault-2", &pending.transport_fp);
        assert!(store.install(&addressed).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn credential_files_are_private_and_loose_ones_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("mode");
        let store = NodeCredentialStore::new(&dir, "vault-1").unwrap();
        store.ensure_transport_key().unwrap();
        let seed = Path::new(&dir).join(TRANSPORT_SEED_FILE);
        assert_eq!(std::fs::metadata(&seed).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.ensure_transport_key().unwrap_err().to_string().contains("chmod 600"));
    }

    #[test]
    fn malformed_records_are_refused() {
        assert!(PendingNode::decode("n", b"{").is_err());
        let store = NodeCredentialStore::new(&temp_dir("bad"), "n").unwrap();
        let mut p = store.ensure_transport_key().unwrap();
        p.transport_fp = "00".repeat(32);
        assert!(PendingNode::decode("n", &serde_json::to_vec(&p).unwrap()).is_err(), "fingerprint must match");
        let dup = br#"{"version":1,"node_id":"n","transport_fp":"x","credentials":{"mock:A":{"auth_key_id":256,"envelope":null},"mock:A":{"auth_key_id":256,"envelope":null}}}"#;
        assert!(CredentialDelivery::decode("n", dup).is_err());
        assert!(NodeCredentialStore::new("", "n").is_err());
        assert!(NodeCredentialStore::new("/tmp/x", "../n").is_err());
    }
}
