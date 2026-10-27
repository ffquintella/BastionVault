//! Ceremony records and checks for the pool topology (T454 phase 4).
//!
//! The attestation bundle `provision` emits and `member add` verifies, and
//! the per-node enrollment record at `core/hsm/nodes/<node_id>`, each entry
//! signed by that member's `bv-identity`. The flows that use them are on
//! [`crate::seal::hsm::HsmSealProvider`]. Spec: `features/hsm-pool-ha.md`.

use std::collections::BTreeMap;

use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    errors::RvError,
    hsm::{
        admin::{node_slot_of, verify_layout, HsmAdminSession},
        blob::HsmId,
        blobset::deserialize_unique_map,
        validate_node_id, verify_identity_signature, HsmObjectIds,
    },
    storage::{Backend as PhysicalBackend, BackendEntry},
};

/// Physical keyspace of enrollment records.
pub const NODE_ENROLLMENT_PREFIX: &str = "core/hsm/nodes/";
/// Physical keyspace of member promotion transcripts.
pub const PROMOTION_PREFIX: &str = "core/hsm/promotions/";

const RECORD_VERSION: u8 = 1;
pub const ENROLLMENT_CONTEXT: &str = "bastionvault/hsm/node-enrollment/v1";
const CHALLENGE_CONTEXT: &str = "bastionvault/hsm/attestation-challenge/v1";
pub const PROMOTION_CONTEXT: &str = "bastionvault/hsm/member-promotion/v1";

fn push(out: &mut Vec<u8>, part: &[u8]) {
    out.extend_from_slice(&(part.len() as u64).to_be_bytes());
    out.extend_from_slice(part);
}

/// What `provision` hands the operator and `member add` verifies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationBundle {
    pub version: u8,
    pub backend_type: String,
    pub serial: String,
    pub firmware: String,
    /// Hex attestation of `bv-identity`.
    pub identity_attestation: String,
    /// Hex attestation of `bv-authz`.
    pub authz_attestation: String,
    /// Hex attestation of `bv-seed-ecdh`.
    #[serde(default)]
    pub seed_ecdh_attestation: String,
}

impl AttestationBundle {
    pub fn new(backend_type: &str, serial: &str, firmware: &str, identity: &[u8], authz: &[u8]) -> Self {
        Self {
            version: RECORD_VERSION,
            backend_type: backend_type.to_string(),
            serial: serial.to_string(),
            firmware: firmware.to_string(),
            identity_attestation: hex::encode(identity),
            authz_attestation: hex::encode(authz),
            seed_ecdh_attestation: String::new(),
        }
    }

    pub fn with_seed_ecdh(mut self, attestation: &[u8]) -> Self {
        self.seed_ecdh_attestation = hex::encode(attestation);
        self
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RvError> {
        let bundle: Self = serde_json::from_slice(bytes)
            .map_err(|e| RvError::ErrHsmAttestationInvalid(format!("malformed attestation bundle: {e}")))?;
        if bundle.version != RECORD_VERSION {
            return Err(RvError::ErrHsmAttestationInvalid(format!("unsupported bundle version {}", bundle.version)));
        }
        bundle.hsm_id()?;
        Ok(bundle)
    }

    pub fn hsm_id(&self) -> Result<HsmId, RvError> {
        HsmId::from_parts(&self.backend_type, &self.serial)
            .map_err(|e| RvError::ErrHsmAttestationInvalid(format!("bundle names no valid device: {e}")))
    }

    fn attestation(hex_value: &str, what: &str) -> Result<Vec<u8>, RvError> {
        hex::decode(hex_value).map_err(|_| RvError::ErrHsmAttestationInvalid(format!("{what} attestation is not hex")))
    }

    /// Hex SHA-256 of each attestation, as the seal record keeps them.
    pub fn fingerprints(&self) -> Vec<String> {
        [&self.identity_attestation, &self.authz_attestation, &self.seed_ecdh_attestation]
            .iter()
            .filter(|a| !a.is_empty())
            .map(|a| hex::encode(Sha256::digest(a.as_bytes())))
            .collect()
    }
}

/// A device that passed [`verify_member`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMember {
    pub hsm_id: HsmId,
    pub identity_pub: Vec<u8>,
    pub authz_pub: Vec<u8>,
    pub seed_ecdh_pub: Vec<u8>,
    pub attestation_fps: Vec<String>,
}

/// Spec § Attestation verification, through an admin session on the device:
/// the bundle names this device, both attested keys are the device's own
/// non-exportable keys, `bv-identity` answers a fresh challenge in this very
/// session, and the layout verifies. Pinning the Yubico chain is yubihsm2-only.
#[maybe_async::maybe_async]
pub async fn verify_member(
    session: &dyn HsmAdminSession,
    bundle: &AttestationBundle,
    objects: &HsmObjectIds,
) -> Result<VerifiedMember, RvError> {
    let refuse = |why: String| {
        log::error!(target: "security", "HSM member attestation refused: {why}");
        RvError::ErrHsmAttestationInvalid(why)
    };
    let hsm_id = session.hsm_id()?;
    if bundle.hsm_id()? != hsm_id {
        return Err(refuse(format!("the bundle is for {}, but the device reached is {hsm_id}", bundle.hsm_id()?)));
    }
    let mut keys = Vec::new();
    for (what, hex_value, id, label) in [
        ("identity", &bundle.identity_attestation, objects.identity, "bv-identity"),
        ("authz", &bundle.authz_attestation, objects.authz, "bv-authz"),
        ("seed-ecdh", &bundle.seed_ecdh_attestation, objects.seed_ecdh, "bv-seed-ecdh"),
    ] {
        if hex_value.is_empty() {
            return Err(refuse(format!("the bundle has no {what} attestation")));
        }
        let attested = session.verify_attestation(&AttestationBundle::attestation(hex_value, what)?).await?;
        if attested.serial != bundle.serial || attested.object_id != id || attested.label != label {
            return Err(refuse(format!(
                "the {what} attestation is for {} object {} on {}, expected {label} object {id} on {}",
                attested.label, attested.object_id, attested.serial, bundle.serial
            )));
        }
        if !attested.non_exportable {
            return Err(refuse(format!("{label} is exportable")));
        }
        if session.public_key(id).await? != attested.public_key {
            return Err(refuse(format!("{label} on the device is not the attested key")));
        }
        keys.push(attested.public_key);
    }
    let mut challenge = [0u8; 32];
    rand::rng().fill_bytes(&mut challenge);
    let signature = session.identity_sign(objects.identity, CHALLENGE_CONTEXT, &challenge).await?;
    verify_identity_signature(&keys[0], CHALLENGE_CONTEXT, &challenge, &signature)
        .map_err(|_| refuse("bv-identity did not answer the challenge in this session".into()))?;
    verify_layout(session, objects).await?;
    let seed_ecdh_pub = keys.pop().unwrap_or_default();
    let authz_pub = keys.pop().unwrap_or_default();
    let identity_pub = keys.pop().unwrap_or_default();
    Ok(VerifiedMember { hsm_id, identity_pub, authz_pub, seed_ecdh_pub, attestation_fps: bundle.fingerprints() })
}

/// Who revoked a node, and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    pub revoked_at: u64,
    pub revoked_by: String,
}

/// `core/hsm/nodes/<node_id>`: a node's auth key on each member, the
/// transport key its credentials were sealed to, and per-member signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeEnrollment {
    pub version: u8,
    pub node_id: String,
    #[serde(with = "serde_bytes")]
    pub transport_pub: Vec<u8>,
    pub transport_fp: String,
    #[serde(deserialize_with = "deserialize_unique_map")]
    pub auth_keys: BTreeMap<HsmId, u16>,
    pub enrolled_at: u64,
    pub enrolled_by: String,
    /// Hex `bv-identity` signature of each member over [`Self::tbs`].
    #[serde(default, deserialize_with = "deserialize_unique_map")]
    pub signatures: BTreeMap<HsmId, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<Revocation>,
}

impl NodeEnrollment {
    /// What `hsm_id`'s identity signs: one member's entry, so adding a member
    /// later never invalidates the others' signatures.
    pub fn tbs(&self, hsm_id: &HsmId) -> Result<Vec<u8>, RvError> {
        let auth_key = self
            .auth_keys
            .get(hsm_id)
            .ok_or_else(|| RvError::ErrHsm(format!("node {} has no auth key on {hsm_id}", self.node_id)))?;
        let mut out = Vec::new();
        for part in [ENROLLMENT_CONTEXT.as_bytes(), self.node_id.as_bytes(), self.transport_fp.as_bytes()] {
            push(&mut out, part);
        }
        push(&mut out, hsm_id.as_str().as_bytes());
        push(&mut out, &auth_key.to_be_bytes());
        push(&mut out, &self.enrolled_at.to_be_bytes());
        Ok(out)
    }

    /// Verify `hsm_id`'s signature against that member's identity key.
    pub fn verify(&self, hsm_id: &HsmId, identity_pub: &[u8]) -> Result<(), RvError> {
        let sig = self.signatures.get(hsm_id).ok_or_else(|| RvError::ErrHsm(format!("no signature by {hsm_id}")))?;
        let sig = hex::decode(sig).map_err(|_| RvError::ErrHsm("enrollment signature is not hex".into()))?;
        verify_identity_signature(identity_pub, ENROLLMENT_CONTEXT, &self.tbs(hsm_id)?, &sig)
    }

    /// The node's slot (the same on every member).
    pub fn slot(&self) -> Result<usize, RvError> {
        let mut slots = self.auth_keys.values().map(|id| node_slot_of(*id));
        let first = slots.next().ok_or_else(|| RvError::ErrHsm(format!("node {} has no auth key", self.node_id)))??;
        if slots.any(|s| s.ok() != Some(first)) {
            return Err(RvError::ErrHsm(format!("node {} uses different slots on different members", self.node_id)));
        }
        Ok(first)
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked.is_some()
    }

    pub fn decode(node_id: &str, bytes: &[u8]) -> Result<Self, RvError> {
        let invalid = |why: String| RvError::ErrHsm(format!("invalid HSM enrollment record {node_id}: {why}"));
        let rec: Self = serde_json::from_slice(bytes).map_err(|e| invalid(e.to_string()))?;
        if rec.version != RECORD_VERSION {
            return Err(invalid(format!("unsupported version {}", rec.version)));
        }
        if rec.node_id != node_id {
            return Err(invalid(format!("record names node {}", rec.node_id)));
        }
        rec.slot().map_err(|e| invalid(e.to_string()))?;
        Ok(rec)
    }

    pub fn encode(&self) -> Result<Vec<u8>, RvError> {
        serde_json::to_vec(self).map_err(|e| RvError::ErrHsm(format!("enrollment record encode: {e}")))
    }

    pub fn new(node_id: &str, transport_pub: Vec<u8>, transport_fp: String, enrolled_at: u64, by: &str) -> Self {
        Self {
            version: RECORD_VERSION,
            node_id: node_id.to_string(),
            transport_pub,
            transport_fp,
            auth_keys: BTreeMap::new(),
            enrolled_at,
            enrolled_by: by.to_string(),
            signatures: BTreeMap::new(),
            revoked: None,
        }
    }
}

fn enrollment_key(node_id: &str) -> Result<String, RvError> {
    validate_node_id(node_id)?;
    Ok(format!("{NODE_ENROLLMENT_PREFIX}{node_id}"))
}

#[maybe_async::maybe_async]
pub async fn read_enrollment(physical: &dyn PhysicalBackend, node_id: &str) -> Result<Option<NodeEnrollment>, RvError> {
    match physical.get(&enrollment_key(node_id)?).await? {
        Some(entry) => NodeEnrollment::decode(node_id, &entry.value).map(Some),
        None => Ok(None),
    }
}

/// Every enrollment record. A malformed one is an error naming it, never
/// skipped: a hidden record could hide a slot or a revocation.
#[maybe_async::maybe_async]
pub async fn list_enrollments(physical: &dyn PhysicalBackend) -> Result<Vec<NodeEnrollment>, RvError> {
    let mut out = Vec::new();
    for name in physical.list(NODE_ENROLLMENT_PREFIX).await? {
        if let Some(rec) = read_enrollment(physical, &name).await? {
            out.push(rec);
        }
    }
    Ok(out)
}

/// Write an enrollment record. The caller holds `hsm-custody`.
#[maybe_async::maybe_async]
pub async fn write_enrollment(physical: &dyn PhysicalBackend, rec: &NodeEnrollment) -> Result<(), RvError> {
    let key = enrollment_key(&rec.node_id)?;
    physical.put(&BackendEntry { key, value: rec.encode()? }).await
}

/// Physical key of the members init's bootstrap attested.
pub const BOOTSTRAP_RECORD_PATH: &str = "core/hsm/bootstrap";

/// What `bootstrap` attested about each initial member, for `init` to pin
/// into the seal record. Init compares it with what the device reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapRecord {
    pub version: u8,
    pub node_id: String,
    #[serde(deserialize_with = "deserialize_unique_map")]
    pub members: BTreeMap<HsmId, BootstrapMember>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapMember {
    pub name: String,
    #[serde(with = "serde_bytes")]
    pub identity_pub: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub authz_pub: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub seed_ecdh_pub: Vec<u8>,
    pub attestation_fps: Vec<String>,
}

impl BootstrapRecord {
    pub fn new(node_id: &str) -> Self {
        Self { version: RECORD_VERSION, node_id: node_id.to_string(), members: BTreeMap::new() }
    }

    pub fn insert(&mut self, name: &str, verified: &VerifiedMember) {
        self.members.insert(
            verified.hsm_id.clone(),
            BootstrapMember {
                name: name.to_string(),
                identity_pub: verified.identity_pub.clone(),
                authz_pub: verified.authz_pub.clone(),
                seed_ecdh_pub: verified.seed_ecdh_pub.clone(),
                attestation_fps: verified.attestation_fps.clone(),
            },
        );
    }
}

#[maybe_async::maybe_async]
pub async fn read_bootstrap(physical: &dyn PhysicalBackend) -> Result<Option<BootstrapRecord>, RvError> {
    let Some(entry) = physical.get(BOOTSTRAP_RECORD_PATH).await? else { return Ok(None) };
    let rec: BootstrapRecord = serde_json::from_slice(&entry.value)
        .map_err(|e| RvError::ErrHsm(format!("invalid HSM bootstrap record: {e}")))?;
    if rec.version != RECORD_VERSION {
        return Err(RvError::ErrHsm(format!("unsupported HSM bootstrap record version {}", rec.version)));
    }
    Ok(Some(rec))
}

#[maybe_async::maybe_async]
pub async fn write_bootstrap(physical: &dyn PhysicalBackend, rec: &BootstrapRecord) -> Result<(), RvError> {
    let value = serde_json::to_vec(rec).map_err(|e| RvError::ErrHsm(format!("bootstrap record encode: {e}")))?;
    physical.put(&BackendEntry { key: BOOTSTRAP_RECORD_PATH.to_string(), value }).await
}

/// A member's promotion from `joining` to `active`, signed by its identity
/// and by an active member's identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionTranscript {
    pub version: u8,
    pub cluster_uuid: String,
    pub epoch: u64,
    pub promoted: HsmId,
    pub sets_checked: usize,
    pub at: u64,
    #[serde(deserialize_with = "deserialize_unique_map")]
    pub signatures: BTreeMap<HsmId, String>,
}

impl PromotionTranscript {
    pub fn new(cluster_uuid: &str, epoch: u64, promoted: &HsmId, sets_checked: usize, at: u64) -> Self {
        Self {
            version: RECORD_VERSION,
            cluster_uuid: cluster_uuid.to_string(),
            epoch,
            promoted: promoted.clone(),
            sets_checked,
            at,
            signatures: BTreeMap::new(),
        }
    }

    pub fn tbs(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for part in [PROMOTION_CONTEXT.as_bytes(), self.cluster_uuid.as_bytes(), self.promoted.as_str().as_bytes()] {
            push(&mut out, part);
        }
        push(&mut out, &self.epoch.to_be_bytes());
        push(&mut out, &(self.sets_checked as u64).to_be_bytes());
        push(&mut out, &self.at.to_be_bytes());
        out
    }
}

#[maybe_async::maybe_async]
pub async fn write_promotion(physical: &dyn PhysicalBackend, t: &PromotionTranscript) -> Result<(), RvError> {
    let serial = t.promoted.as_str().replace(':', "_");
    let value = serde_json::to_vec(t).map_err(|e| RvError::ErrHsm(format!("promotion transcript encode: {e}")))?;
    physical.put(&BackendEntry { key: format!("{PROMOTION_PREFIX}{serial}-{}", t.at), value }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(serial: &str) -> HsmId {
        HsmId::from_parts("mock", serial).unwrap()
    }

    #[test]
    fn enrollment_records_are_validated_and_signed_per_member() {
        let mut rec = NodeEnrollment::new("vault-1", vec![1; 4], "fp".into(), 7, "root");
        rec.auth_keys.insert(id("A"), 0x101);
        rec.auth_keys.insert(id("B"), 0x101);
        assert_eq!(rec.slot().unwrap(), 1);
        let bytes = rec.encode().unwrap();
        assert_eq!(NodeEnrollment::decode("vault-1", &bytes).unwrap(), rec);
        assert!(NodeEnrollment::decode("vault-2", &bytes).is_err(), "a record copied to another node is refused");
        assert_ne!(rec.tbs(&id("A")).unwrap(), rec.tbs(&id("B")).unwrap(), "each member signs its own entry");
        assert!(rec.tbs(&id("C")).is_err());

        let mut split = rec.clone();
        split.auth_keys.insert(id("B"), 0x102);
        assert!(split.slot().is_err(), "one slot per node");
        let mut admin = rec.clone();
        admin.auth_keys.insert(id("A"), 2);
        assert!(NodeEnrollment::decode("vault-1", &admin.encode().unwrap()).is_err(), "never a non-node key");
        let v2 = String::from_utf8(bytes).unwrap().replace("\"version\":1", "\"version\":2");
        assert!(NodeEnrollment::decode("vault-1", v2.as_bytes()).is_err());
    }

    #[test]
    fn bundles_are_strict() {
        let b = AttestationBundle::new("mock", "A", "mock", b"id", b"az");
        let bytes = serde_json::to_vec(&b).unwrap();
        assert_eq!(AttestationBundle::decode(&bytes).unwrap(), b);
        assert_eq!(b.fingerprints().len(), 2);
        let extra = String::from_utf8(bytes.clone()).unwrap().replace("\"version\":1", "\"version\":1,\"x\":1");
        assert!(AttestationBundle::decode(extra.as_bytes()).is_err(), "unknown fields are refused");
        let bad = AttestationBundle::new("softhsm", "A", "x", b"", b"");
        assert!(AttestationBundle::decode(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
}
