//! The HSM seal record at `core/hsm-seal` (physical storage, pre-unseal).
//!
//! v2 (T454) holds `topology`, pool `members`, the barrier KEK as a
//! [`BvHsmBlobSet`], an optional recovery public key, and `legacy_node_blobs`
//! (the v1 per-node blobs, verbatim). A v1 record loads as `per-node` with
//! `legacy_node_blobs`; every write is v2. See `features/hsm-pool-ha.md`
//! § Persisted formats and migration.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    errors::RvError,
    hsm::{
        blob::{AuthzAlg, HsmId, Purpose},
        blobset::{deserialize_unique_map, BvHsmBlobSet},
        HsmObjectId, HsmObjectIds,
    },
};

/// The wrap keys of one epoch, the same ids on every live member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrapKeyIds {
    pub barrier: HsmObjectId,
    pub pqc: HsmObjectId,
}

impl WrapKeyIds {
    pub fn of(objects: &HsmObjectIds) -> Self {
        Self { barrier: objects.wrap_barrier, pqc: objects.wrap_pqc }
    }
}

/// Pre-T454 record: `kek_blobs: node_id → v1 blob`.
pub const HSM_SEAL_RECORD_VERSION_V1: u8 = 1;
/// The version every write produces.
pub const HSM_SEAL_RECORD_VERSION: u8 = 2;

/// FIPS 203 ML-KEM-768 encapsulation-key length.
const ML_KEM_768_PUBLIC_KEY_LEN: usize = 1184;

/// How the cluster reaches its HSMs. Mutually exclusive per cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Topology {
    /// One device per node (S17). Every pre-T454 record.
    PerNode,
    /// Two shared devices for the whole cluster (T454 phase 2 onwards).
    Pool,
}

impl Topology {
    pub fn as_str(&self) -> &'static str {
        match self {
            Topology::PerNode => "per-node",
            Topology::Pool => "pool",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MemberState {
    Joining,
    Active,
    Retired,
    Faulted,
}

/// One pool member as the record knows it; the record, not the config, is
/// authoritative after init. Defined now, first written by T454 phase 2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HsmMember {
    pub name: String,
    #[serde(default)]
    pub gateway: String,
    pub serial: String,
    #[serde(with = "serde_bytes")]
    pub identity_pub: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub seed_ecdh_pub: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub authz_pub: Vec<u8>,
    pub authz_alg: AuthzAlg,
    #[serde(default)]
    pub attestation_fps: Vec<String>,
    pub state: MemberState,
    #[serde(default)]
    pub pending_revocations: Vec<String>,
}

/// The recovery key's public half and its fingerprint (T454 phase 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPublicKey {
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    /// Hex SHA-256 of `public_key`.
    pub fingerprint: String,
}

/// Seal record, version 2 (in memory and on disk).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HsmSealRecord {
    pub version: u8,
    pub cluster_uuid: String,
    pub epoch: u64,
    pub topology: Topology,
    #[serde(default, deserialize_with = "deserialize_unique_map")]
    pub members: BTreeMap<HsmId, HsmMember>,
    /// `None` only for a record converted from v1, whose KEK copies are all
    /// legacy v1 blobs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kek: Option<BvHsmBlobSet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_pub: Option<RecoveryPublicKey>,
    /// node_id → serialized v1 `BvHsmBlob` of the KEK, kept byte for byte.
    #[serde(default, deserialize_with = "deserialize_unique_map")]
    pub legacy_node_blobs: BTreeMap<String, Vec<u8>>,
    /// Wrap-key ids by epoch (T454 phase 4, `rotate-epoch`). Absent on every
    /// record written before it: those use the config's ids at any epoch.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty", deserialize_with = "deserialize_unique_map")]
    pub wrap_keys: BTreeMap<u64, WrapKeyIds>,
    /// The epoch a rotation is moving to; `Some` until it completes, so an
    /// interrupted rotation resumes with the keys it already created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotating_to: Option<u64>,
}

/// A decoded record plus the version it was stored at, so a caller can tell
/// a record still waiting for its first v2 write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSealRecord {
    pub record: HsmSealRecord,
    pub stored_version: u8,
}

/// The pre-T454 shape, read-only.
#[derive(Deserialize)]
struct HsmSealRecordV1 {
    cluster_uuid: String,
    epoch: u64,
    kek_blobs: BTreeMap<String, Vec<u8>>,
}

#[derive(Deserialize)]
struct VersionProbe {
    version: u8,
}

fn invalid(why: impl std::fmt::Display) -> RvError {
    RvError::ErrHsm(format!("invalid HSM seal record: {why}"))
}

impl HsmSealRecord {
    /// A fresh per-node record whose KEK is a v2 set.
    pub fn new_per_node(cluster_uuid: String, epoch: u64, kek: BvHsmBlobSet) -> Self {
        Self {
            version: HSM_SEAL_RECORD_VERSION,
            cluster_uuid,
            epoch,
            topology: Topology::PerNode,
            members: BTreeMap::new(),
            kek: Some(kek),
            recovery_pub: None,
            legacy_node_blobs: BTreeMap::new(),
            wrap_keys: BTreeMap::new(),
            rotating_to: None,
        }
    }

    /// The wrap keys of `epoch`: the recorded ones, or the config's on a
    /// record that predates rotation. A recorded map without `epoch` is an
    /// error, never a guess.
    pub fn wrap_key_ids(&self, epoch: u64, defaults: &HsmObjectIds) -> Result<WrapKeyIds, RvError> {
        if self.wrap_keys.is_empty() {
            return Ok(WrapKeyIds::of(defaults));
        }
        self.wrap_keys.get(&epoch).copied().ok_or_else(|| invalid(format!("no wrap keys recorded for epoch {epoch}")))
    }

    /// A fresh pool record: `members` are authoritative from here on.
    pub fn new_pool(cluster_uuid: String, epoch: u64, members: BTreeMap<HsmId, HsmMember>, kek: BvHsmBlobSet) -> Self {
        Self {
            version: HSM_SEAL_RECORD_VERSION,
            cluster_uuid,
            epoch,
            topology: Topology::Pool,
            members,
            kek: Some(kek),
            recovery_pub: None,
            legacy_node_blobs: BTreeMap::new(),
            wrap_keys: BTreeMap::new(),
            rotating_to: None,
        }
    }

    /// Active members, the ones a set must have a copy for.
    pub fn active_members(&self) -> impl Iterator<Item = (&HsmId, &HsmMember)> {
        self.members.iter().filter(|(_, m)| m.state == MemberState::Active)
    }

    /// Decode a stored record of either version. Unknown versions (a record
    /// written by a newer build) are refused, never guessed at.
    pub fn decode(bytes: &[u8]) -> Result<StoredSealRecord, RvError> {
        let probe: VersionProbe =
            serde_json::from_slice(bytes).map_err(|e| invalid(format!("not a seal record: {e}")))?;
        let record = match probe.version {
            HSM_SEAL_RECORD_VERSION_V1 => {
                let v1: HsmSealRecordV1 = serde_json::from_slice(bytes).map_err(|e| invalid(format!("v1: {e}")))?;
                HsmSealRecord {
                    version: HSM_SEAL_RECORD_VERSION,
                    cluster_uuid: v1.cluster_uuid,
                    epoch: v1.epoch,
                    topology: Topology::PerNode,
                    members: BTreeMap::new(),
                    kek: None,
                    recovery_pub: None,
                    legacy_node_blobs: v1.kek_blobs,
                    wrap_keys: BTreeMap::new(),
                    rotating_to: None,
                }
            }
            HSM_SEAL_RECORD_VERSION => serde_json::from_slice(bytes).map_err(|e| invalid(format!("v2: {e}")))?,
            other => {
                return Err(invalid(format!(
                    "unsupported version {other}; this build reads versions {HSM_SEAL_RECORD_VERSION_V1} and \
                     {HSM_SEAL_RECORD_VERSION} (was it written by a newer BastionVault?)"
                )))
            }
        };
        record.validate()?;
        Ok(StoredSealRecord { record, stored_version: probe.version })
    }

    /// Encode as v2. This is the "first write converts the record" step for a
    /// record that was loaded from v1.
    pub fn encode(&self) -> Result<Vec<u8>, RvError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|e| RvError::ErrHsm(format!("seal record encode: {e}")))
    }

    pub fn validate(&self) -> Result<(), RvError> {
        if self.version != HSM_SEAL_RECORD_VERSION {
            return Err(invalid(format!("in-memory version {} is not {HSM_SEAL_RECORD_VERSION}", self.version)));
        }
        if self.cluster_uuid.is_empty() {
            return Err(invalid("empty cluster_uuid"));
        }
        if let Some(kek) = &self.kek {
            kek.validate()?;
            if kek.purpose != Purpose::BarrierKek {
                return Err(invalid(format!("kek set has purpose {}", kek.purpose.as_token())));
            }
            if kek.epoch != self.epoch {
                return Err(invalid(format!("kek set epoch {} differs from record epoch {}", kek.epoch, self.epoch)));
            }
        }
        if !self.wrap_keys.is_empty() && !self.wrap_keys.contains_key(&self.epoch) {
            return Err(invalid(format!("wrap keys recorded, but none for the current epoch {}", self.epoch)));
        }
        if let Some(target) = self.rotating_to {
            if target <= self.epoch || !self.wrap_keys.contains_key(&target) {
                return Err(invalid(format!("rotation to epoch {target} from {} has no recorded keys", self.epoch)));
            }
        }
        for (node_id, blob) in &self.legacy_node_blobs {
            if node_id.is_empty() || blob.is_empty() {
                return Err(invalid("empty legacy_node_blobs entry"));
            }
        }
        if let Some(recovery) = &self.recovery_pub {
            if recovery.public_key.len() != ML_KEM_768_PUBLIC_KEY_LEN {
                return Err(invalid("recovery public key is not an ML-KEM-768 key"));
            }
            if recovery.fingerprint != hex::encode(Sha256::digest(&recovery.public_key)) {
                return Err(invalid("recovery public key fingerprint does not match the key"));
            }
        }
        match self.topology {
            Topology::PerNode => {
                if !self.members.is_empty() {
                    return Err(invalid("per-node record carries pool members"));
                }
                if self.kek.is_none() && self.legacy_node_blobs.is_empty() {
                    return Err(invalid("no KEK copy"));
                }
            }
            Topology::Pool => {
                let kek = self.kek.as_ref().ok_or_else(|| invalid("pool record has no KEK set"))?;
                if !self.legacy_node_blobs.is_empty() {
                    return Err(invalid("pool record still carries legacy per-node blobs"));
                }
                if !self.members.values().any(|m| m.state == MemberState::Active) {
                    return Err(invalid("pool record has no active member"));
                }
                if let Some(stray) = kek.copies.keys().find(|id| !self.members.contains_key(*id)) {
                    return Err(invalid(format!("KEK copy for {stray}, which is not a member")));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hsm::blob::{seal_blob, BvHsmBlob, Context, DeviceBinding};

    /// Captured from the pre-T454 code (commit f4139929): `init_kek` on a mock
    /// device for node `fixture-node`, then three `recover_kek` calls. The
    /// provider-level fixture tests in `seal::hsm` unseal it.
    const V1_FIXTURE: &[u8] = include_bytes!("../testdata/hsm-seal-v1/core-hsm-seal.json");

    fn v2_kek_set(serial: &str, epoch: u64) -> BvHsmBlobSet {
        let device = DeviceBinding {
            hsm_id: HsmId::from_parts("mock", serial).unwrap(),
            authz_alg: AuthzAlg::Ed25519,
            authz_fp: "fp".into(),
        };
        let ctx = Context::new("bastionvault/hsm/v1/barrier-kek/clu", Purpose::BarrierKek, epoch, "n1");
        let bytes = seal_blob("mock", 2, &ctx, &device, b"kek", |i| Ok(i.to_vec())).unwrap();
        BvHsmBlobSet::new(Purpose::BarrierKek, epoch, BvHsmBlob::from_bytes(&bytes).unwrap(), "n1", 1).unwrap()
    }

    fn member(state: MemberState) -> HsmMember {
        HsmMember {
            name: "hsm-a".into(),
            gateway: "https://hsm-a.internal:8250".into(),
            serial: "A".into(),
            identity_pub: vec![4; 65],
            seed_ecdh_pub: vec![4; 65],
            authz_pub: vec![1; 32],
            authz_alg: AuthzAlg::Ed25519,
            attestation_fps: vec![],
            state,
            pending_revocations: vec![],
        }
    }

    #[test]
    fn wrap_keys_read_old_and_write_new() {
        let defaults = HsmObjectIds::default();
        let mut rec = HsmSealRecord::new_pool(
            "clu".into(),
            0,
            BTreeMap::from([(HsmId::from_parts("mock", "A").unwrap(), member(MemberState::Active))]),
            v2_kek_set("A", 0),
        );
        // A record from before rotation: no map, the config's ids, and it
        // still encodes without the field (byte-compatible with part 2).
        assert_eq!(rec.wrap_key_ids(7, &defaults).unwrap(), WrapKeyIds::of(&defaults));
        let old = rec.encode().unwrap();
        assert!(!String::from_utf8(old.clone()).unwrap().contains("wrap_keys"));
        assert_eq!(HsmSealRecord::decode(&old).unwrap().record.wrap_keys, BTreeMap::new());

        rec.wrap_keys.insert(0, WrapKeyIds { barrier: 0x20, pqc: 0x21 });
        let new = HsmSealRecord::decode(&rec.encode().unwrap()).unwrap().record;
        assert_eq!(new.wrap_key_ids(0, &defaults).unwrap(), WrapKeyIds { barrier: 0x20, pqc: 0x21 });
        assert!(new.wrap_key_ids(1, &defaults).is_err(), "never a guess for an unrecorded epoch");

        let mut no_current = rec.clone();
        no_current.wrap_keys = BTreeMap::from([(3, WrapKeyIds { barrier: 1, pqc: 2 })]);
        assert!(no_current.encode().is_err());
        let mut rotating = rec.clone();
        rotating.rotating_to = Some(1);
        assert!(rotating.encode().is_err(), "the target epoch's keys must be recorded first");
        rotating.wrap_keys.insert(1, WrapKeyIds { barrier: 0x22, pqc: 0x23 });
        HsmSealRecord::decode(&rotating.encode().unwrap()).unwrap();
    }

    #[test]
    fn v1_fixture_loads_as_per_node_with_legacy_blobs() {
        let stored = HsmSealRecord::decode(V1_FIXTURE).unwrap();
        assert_eq!(stored.stored_version, HSM_SEAL_RECORD_VERSION_V1);
        let r = &stored.record;
        assert_eq!(r.topology, Topology::PerNode);
        assert!(r.kek.is_none() && r.members.is_empty() && r.recovery_pub.is_none());
        assert_eq!(r.legacy_node_blobs.keys().collect::<Vec<_>>(), vec!["fixture-node"]);

        // The legacy blob is carried verbatim: the bytes are the v1 originals.
        let v1: serde_json::Value = serde_json::from_slice(V1_FIXTURE).unwrap();
        let original: Vec<u8> = serde_json::from_value(v1["kek_blobs"]["fixture-node"].clone()).unwrap();
        assert_eq!(r.legacy_node_blobs["fixture-node"], original);
        let blob = BvHsmBlob::from_bytes(&original).unwrap();
        assert_eq!(blob.version(), 1);
        // Re-serializing the old code's v1 blob reproduces it byte for byte.
        assert_eq!(blob.to_bytes().unwrap(), original);
    }

    #[test]
    fn first_write_converts_v1_to_v2_and_round_trips() {
        let stored = HsmSealRecord::decode(V1_FIXTURE).unwrap();
        let written = stored.record.encode().unwrap();
        let json: serde_json::Value = serde_json::from_slice(&written).unwrap();
        assert_eq!(json["version"], 2);
        assert_eq!(json["topology"], "per-node");
        assert!(json.get("kek_blobs").is_none(), "the v1 field is not written back");

        let reread = HsmSealRecord::decode(&written).unwrap();
        assert_eq!(reread.stored_version, HSM_SEAL_RECORD_VERSION);
        assert_eq!(reread.record, stored.record);
    }

    #[test]
    fn fresh_per_node_and_pool_records_round_trip() {
        let per_node = HsmSealRecord::new_per_node("clu".into(), 0, v2_kek_set("A", 0));
        assert_eq!(HsmSealRecord::decode(&per_node.encode().unwrap()).unwrap().record, per_node);

        let mut pool = per_node.clone();
        pool.topology = Topology::Pool;
        pool.members.insert(HsmId::from_parts("mock", "A").unwrap(), member(MemberState::Active));
        assert_eq!(HsmSealRecord::decode(&pool.encode().unwrap()).unwrap().record, pool);
    }

    #[test]
    fn unknown_versions_and_malformed_records_are_rejected() {
        let good = HsmSealRecord::new_per_node("clu".into(), 0, v2_kek_set("A", 0));
        let json: serde_json::Value = serde_json::from_slice(&good.encode().unwrap()).unwrap();
        let reject = |v: &serde_json::Value| HsmSealRecord::decode(&serde_json::to_vec(v).unwrap()).is_err();

        for version in [0, 3, 255] {
            let mut v = json.clone();
            v["version"] = version.into();
            assert!(reject(&v), "version {version}");
        }

        let mut no_kek = json.clone();
        no_kek.as_object_mut().unwrap().remove("kek");
        assert!(reject(&no_kek), "per-node record with no KEK copy at all");

        let mut empty_copies = json.clone();
        empty_copies["kek"]["copies"] = serde_json::json!({});
        assert!(reject(&empty_copies), "empty copies");

        let mut epoch_skew = json.clone();
        epoch_skew["epoch"] = 1.into();
        assert!(reject(&epoch_skew), "KEK set epoch must match the record");

        let mut topology = json.clone();
        topology["topology"] = "mesh".into();
        assert!(reject(&topology), "unknown topology");

        let bytes = good.encode().unwrap();
        assert!(HsmSealRecord::decode(&bytes[..bytes.len() - 3]).is_err(), "truncated");
        assert!(HsmSealRecord::decode(&V1_FIXTURE[..V1_FIXTURE.len() / 2]).is_err(), "truncated v1");
    }

    #[test]
    fn duplicate_member_or_legacy_node_keys_are_rejected() {
        let mut pool = HsmSealRecord::new_per_node("clu".into(), 0, v2_kek_set("A", 0));
        pool.topology = Topology::Pool;
        pool.members.insert(HsmId::from_parts("mock", "A").unwrap(), member(MemberState::Active));
        let text = String::from_utf8(pool.encode().unwrap()).unwrap();
        let m = serde_json::to_string(&member(MemberState::Active)).unwrap();
        let dup = text.replacen(
            &format!("\"members\":{{\"mock:A\":{m}"),
            &format!("\"members\":{{\"mock:A\":{m},\"mock:A\":{m}"),
            1,
        );
        assert_ne!(dup, text);
        assert!(HsmSealRecord::decode(dup.as_bytes()).is_err());

        let legacy = String::from_utf8(V1_FIXTURE.to_vec()).unwrap();
        let mut converted: serde_json::Value =
            serde_json::from_slice(&HsmSealRecord::decode(legacy.as_bytes()).unwrap().record.encode().unwrap())
                .unwrap();
        let blob = converted["legacy_node_blobs"]["fixture-node"].take();
        let dup = format!(
            "{{\"version\":2,\"cluster_uuid\":\"clu\",\"epoch\":0,\"topology\":\"per-node\",\
             \"legacy_node_blobs\":{{\"n1\":{blob},\"n1\":{blob}}}}}"
        );
        assert!(HsmSealRecord::decode(dup.as_bytes()).is_err());
    }

    #[test]
    fn topology_invariants() {
        let mut per_node_with_members = HsmSealRecord::new_per_node("clu".into(), 0, v2_kek_set("A", 0));
        per_node_with_members.members.insert(HsmId::from_parts("mock", "A").unwrap(), member(MemberState::Active));
        assert!(per_node_with_members.encode().is_err());

        let mut pool = HsmSealRecord::new_per_node("clu".into(), 0, v2_kek_set("A", 0));
        pool.topology = Topology::Pool;
        assert!(pool.encode().is_err(), "pool record without members");
        pool.members.insert(HsmId::from_parts("mock", "B").unwrap(), member(MemberState::Active));
        assert!(pool.encode().is_err(), "KEK copy for a non-member");
        pool.members.insert(HsmId::from_parts("mock", "A").unwrap(), member(MemberState::Retired));
        pool.encode().unwrap();
        for m in pool.members.values_mut() {
            m.state = MemberState::Retired;
        }
        assert!(pool.encode().is_err(), "no active member");

        let mut pool_with_legacy = HsmSealRecord::decode(V1_FIXTURE).unwrap().record;
        pool_with_legacy.topology = Topology::Pool;
        pool_with_legacy.kek = Some(v2_kek_set("A", 0));
        pool_with_legacy.members.insert(HsmId::from_parts("mock", "A").unwrap(), member(MemberState::Active));
        assert!(pool_with_legacy.encode().is_err(), "pool records drop legacy per-node blobs");
    }

    #[test]
    fn recovery_public_key_must_match_its_fingerprint() {
        let mut r = HsmSealRecord::new_per_node("clu".into(), 0, v2_kek_set("A", 0));
        let public_key = vec![7u8; ML_KEM_768_PUBLIC_KEY_LEN];
        let fingerprint = hex::encode(Sha256::digest(&public_key));
        r.recovery_pub = Some(RecoveryPublicKey { public_key: public_key.clone(), fingerprint });
        assert_eq!(HsmSealRecord::decode(&r.encode().unwrap()).unwrap().record, r);
        r.recovery_pub = Some(RecoveryPublicKey { public_key, fingerprint: "00".into() });
        assert!(r.encode().is_err());
    }
}
