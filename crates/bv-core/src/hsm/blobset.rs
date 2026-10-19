//! `BvHsmBlobSet` v1 — one protected secret, one v2 copy per HSM that holds it.
//!
//! A set is fully replicated when it holds a copy for every *active* member and
//! under-replicated otherwise; the optional recovery copy never counts towards
//! replication. See `features/hsm-pool-ha.md` § Blob set.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    marker::PhantomData,
    time::{SystemTime, UNIX_EPOCH},
};

use bv_crypto::{envelope::KEM_DEM_ENVELOPE_V1, KemAlgorithm, KemDemEnvelopeV1};
use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};

use crate::{
    errors::RvError,
    hsm::blob::{BvHsmBlob, HsmId, Purpose},
};

/// Wire-format version of [`BvHsmBlobSet`].
pub const BV_HSM_BLOB_SET_VERSION: u8 = 1;

// Sizes a well-formed ML-KEM-768 + ChaCha20-Poly1305 `KemDemEnvelopeV1` has
// (FIPS 203 ciphertext; 12-byte nonce; 16-byte tag over a 32-byte data key).
const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;
const AEAD_NONCE_LEN: usize = 12;
const AEAD_TAG_LEN: usize = 16;
const DATA_KEY_LEN: usize = 32;

/// One protected secret (the barrier KEK or a PQC seed) as a set of v2 copies,
/// keyed by the [`HsmId`] each copy is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BvHsmBlobSet {
    pub version: u8,
    pub purpose: Purpose,
    pub epoch: u64,
    #[serde(deserialize_with = "deserialize_unique_map")]
    pub copies: BTreeMap<HsmId, BvHsmBlob>,
    /// Recovery copy sealed to the cluster recovery key. Defined by the format
    /// now; written only once recovery (T454 phase 5) exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<KemDemEnvelopeV1>,
    /// Unix seconds. Informational only; never used for ordering decisions.
    pub created_at: u64,
    /// Node id of the node that created the set.
    pub created_by: String,
}

fn invalid(why: impl fmt::Display) -> RvError {
    RvError::ErrHsm(format!("invalid HSM blob set: {why}"))
}

impl BvHsmBlobSet {
    /// A new set holding its first copy.
    pub fn new(
        purpose: Purpose,
        epoch: u64,
        first: BvHsmBlob,
        created_by: &str,
        created_at: u64,
    ) -> Result<Self, RvError> {
        let mut set = Self {
            version: BV_HSM_BLOB_SET_VERSION,
            purpose,
            epoch,
            copies: BTreeMap::new(),
            recovery: None,
            created_at,
            created_by: created_by.to_string(),
        };
        set.insert_copy(first)?;
        set.validate()?;
        Ok(set)
    }

    /// Add the copy for a member that has none yet. Refuses to overwrite an
    /// existing copy: replacing one is a repair decision, not an insert.
    pub fn insert_copy(&mut self, blob: BvHsmBlob) -> Result<(), RvError> {
        let hsm_id = self.check_copy(None, &blob)?;
        if self.copies.contains_key(&hsm_id) {
            return Err(invalid(format!("set already holds a copy for {hsm_id}")));
        }
        self.copies.insert(hsm_id, blob);
        Ok(())
    }

    /// A copy must be v2, bound to the member it is keyed by, and carry the
    /// set's own purpose and epoch.
    fn check_copy(&self, keyed_by: Option<&HsmId>, blob: &BvHsmBlob) -> Result<HsmId, RvError> {
        let bound_to = blob.aad.hsm_id().ok_or_else(|| invalid("copy is a v1 blob; sets hold only v2 copies"))?;
        if let Some(key) = keyed_by {
            if key != bound_to {
                return Err(invalid(format!("copy keyed by {key} is bound to {bound_to}")));
            }
        }
        if blob.aad.purpose() != self.purpose {
            return Err(invalid(format!("copy for {bound_to} has purpose {}", blob.aad.purpose().as_token())));
        }
        if blob.aad.epoch() != self.epoch {
            return Err(invalid(format!("copy for {bound_to} has epoch {}, set has {}", blob.aad.epoch(), self.epoch)));
        }
        if blob.wrapped.is_empty() {
            return Err(invalid(format!("copy for {bound_to} has no wrapped bytes")));
        }
        Ok(bound_to.clone())
    }

    pub fn validate(&self) -> Result<(), RvError> {
        if self.version != BV_HSM_BLOB_SET_VERSION {
            return Err(invalid(format!("unsupported version {}", self.version)));
        }
        if !matches!(self.purpose, Purpose::BarrierKek | Purpose::PqcKemSeed | Purpose::PqcSigSeed) {
            return Err(invalid(format!("purpose {} cannot be held in a set", self.purpose.as_token())));
        }
        if self.copies.is_empty() {
            return Err(invalid("no copies"));
        }
        if self.created_by.is_empty() {
            return Err(invalid("created_by is empty"));
        }
        for (hsm_id, blob) in &self.copies {
            self.check_copy(Some(hsm_id), blob)?;
        }
        if let Some(env) = &self.recovery {
            validate_recovery_envelope(env)?;
        }
        Ok(())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RvError> {
        let set: Self = serde_json::from_slice(bytes).map_err(invalid)?;
        set.validate()?;
        Ok(set)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, RvError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|e| RvError::ErrHsm(format!("blob set serialize failed: {e}")))
    }

    pub fn copy_for(&self, hsm_id: &HsmId) -> Option<&BvHsmBlob> {
        self.copies.get(hsm_id)
    }

    /// Active members that hold no copy. The recovery copy does not count.
    pub fn missing_copies(&self, active: &BTreeSet<HsmId>) -> Vec<HsmId> {
        active.iter().filter(|id| !self.copies.contains_key(*id)).cloned().collect()
    }

    pub fn is_under_replicated(&self, active: &BTreeSet<HsmId>) -> bool {
        !self.missing_copies(active).is_empty()
    }
}

/// Structural check of a recovery envelope: catches a truncated or foreign
/// envelope at load time instead of at the recovery ceremony.
fn validate_recovery_envelope(env: &KemDemEnvelopeV1) -> Result<(), RvError> {
    if env.version != KEM_DEM_ENVELOPE_V1 {
        return Err(invalid(format!("unsupported recovery envelope version {}", env.version)));
    }
    if env.kem_algorithm != KemAlgorithm::MlKem768 {
        return Err(invalid("recovery envelope is not ML-KEM-768"));
    }
    let truncated = |field: &str| invalid(format!("truncated recovery envelope ({field})"));
    if env.kem_ciphertext.len() != ML_KEM_768_CIPHERTEXT_LEN {
        return Err(truncated("kem_ciphertext"));
    }
    if env.wrapped_key_nonce.len() != AEAD_NONCE_LEN || env.payload_nonce.len() != AEAD_NONCE_LEN {
        return Err(truncated("nonce"));
    }
    if env.wrapped_key_ciphertext.len() != DATA_KEY_LEN + AEAD_TAG_LEN {
        return Err(truncated("wrapped_key_ciphertext"));
    }
    if env.payload_ciphertext.len() <= AEAD_TAG_LEN {
        return Err(truncated("payload_ciphertext"));
    }
    Ok(())
}

/// Unix seconds now, for `created_at`. A clock before 1970 is an error, not 0.
pub(crate) fn unix_now_secs() -> Result<u64, RvError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| RvError::ErrHsm("system clock is before the Unix epoch".into()))
}

/// Deserialize a map, refusing duplicate keys. serde's `BTreeMap` impl keeps
/// the last duplicate silently, which would let a crafted record shadow one
/// member's copy with another.
pub(crate) fn deserialize_unique_map<'de, D, K, V>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: Deserialize<'de> + Ord + fmt::Display,
    V: Deserialize<'de>,
{
    struct UniqueMap<K, V>(PhantomData<(K, V)>);

    impl<'de, K, V> Visitor<'de> for UniqueMap<K, V>
    where
        K: Deserialize<'de> + Ord + fmt::Display,
        V: Deserialize<'de>,
    {
        type Value = BTreeMap<K, V>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a map with unique keys")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
            let mut out = BTreeMap::new();
            while let Some((key, value)) = access.next_entry::<K, V>()? {
                if out.contains_key(&key) {
                    return Err(de::Error::custom(format_args!("duplicate key {key}")));
                }
                out.insert(key, value);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_map(UniqueMap(PhantomData))
}

#[cfg(test)]
mod tests {
    use bv_crypto::{KemProvider, MlKem768Provider};

    use super::*;
    use crate::hsm::blob::{seal_blob, AuthzAlg, Context, DeviceBinding};

    fn device(serial: &str) -> DeviceBinding {
        DeviceBinding {
            hsm_id: HsmId::from_parts("mock", serial).unwrap(),
            authz_alg: AuthzAlg::Ed25519,
            authz_fp: format!("fp-{serial}"),
        }
    }

    fn copy_on(serial: &str, purpose: Purpose, epoch: u64) -> BvHsmBlob {
        let ctx = Context::new("bastionvault/hsm/v1/barrier-kek/clu", purpose, epoch, "n1");
        let bytes = seal_blob("mock", 2, &ctx, &device(serial), b"secret", |i| Ok(i.to_vec())).unwrap();
        BvHsmBlob::from_bytes(&bytes).unwrap()
    }

    fn id(serial: &str) -> HsmId {
        HsmId::from_parts("mock", serial).unwrap()
    }

    fn one_copy_set() -> BvHsmBlobSet {
        BvHsmBlobSet::new(Purpose::BarrierKek, 0, copy_on("A", Purpose::BarrierKek, 0), "n1", 1).unwrap()
    }

    fn recovery_envelope(plaintext: &[u8]) -> (KemDemEnvelopeV1, bv_crypto::KemKeypair) {
        let provider = MlKem768Provider;
        let keypair = provider.generate_keypair().unwrap();
        let env = KemDemEnvelopeV1::seal(&provider, keypair.public_key(), b"recovery-aad", plaintext).unwrap();
        (env, keypair)
    }

    #[test]
    fn one_copy_with_two_active_members_is_under_replicated() {
        let set = one_copy_set();
        let both: BTreeSet<HsmId> = [id("A"), id("B")].into_iter().collect();
        assert!(set.is_under_replicated(&both));
        assert_eq!(set.missing_copies(&both), vec![id("B")]);

        let only_a: BTreeSet<HsmId> = [id("A")].into_iter().collect();
        assert!(!set.is_under_replicated(&only_a));

        let mut full = set.clone();
        full.insert_copy(copy_on("B", Purpose::BarrierKek, 0)).unwrap();
        assert!(!full.is_under_replicated(&both));
    }

    #[test]
    fn the_recovery_copy_does_not_count_towards_replication() {
        let mut set = one_copy_set();
        set.recovery = Some(recovery_envelope(b"kek").0);
        set.validate().unwrap();
        let both: BTreeSet<HsmId> = [id("A"), id("B")].into_iter().collect();
        assert!(set.is_under_replicated(&both));
    }

    #[test]
    fn round_trip_and_recovery_envelope_round_trip() {
        let mut set = one_copy_set();
        let (env, keypair) = recovery_envelope(b"the-kek");
        set.recovery = Some(env);
        let parsed = BvHsmBlobSet::from_bytes(&set.to_bytes().unwrap()).unwrap();
        assert_eq!(parsed, set);
        let opened = parsed.recovery.unwrap().open(&MlKem768Provider, keypair.secret_key(), b"recovery-aad").unwrap();
        assert_eq!(opened, b"the-kek");
    }

    #[test]
    fn insert_refuses_overwrite_and_foreign_copies() {
        let mut set = one_copy_set();
        assert!(set.insert_copy(copy_on("A", Purpose::BarrierKek, 0)).is_err(), "no silent overwrite");
        assert!(set.insert_copy(copy_on("B", Purpose::PqcKemSeed, 0)).is_err(), "purpose mismatch");
        assert!(set.insert_copy(copy_on("B", Purpose::BarrierKek, 1)).is_err(), "epoch mismatch");
    }

    #[test]
    fn malformed_sets_are_rejected() {
        let set = one_copy_set();
        let good: serde_json::Value = serde_json::from_slice(&set.to_bytes().unwrap()).unwrap();
        let reject = |v: &serde_json::Value| BvHsmBlobSet::from_bytes(&serde_json::to_vec(v).unwrap()).is_err();

        let mut unknown_version = good.clone();
        unknown_version["version"] = 2.into();
        assert!(reject(&unknown_version), "unknown version");

        let mut empty = good.clone();
        empty["copies"] = serde_json::json!({});
        assert!(reject(&empty), "empty copies");

        let mut rekeyed = good.clone();
        let copy = rekeyed["copies"]["mock:A"].clone();
        rekeyed["copies"] = serde_json::json!({ "mock:B": copy });
        assert!(reject(&rekeyed), "copy keyed by a different hsm_id than it is bound to");

        let mut bad_key = good.clone();
        bad_key["copies"] = serde_json::json!({ "mock:": good["copies"]["mock:A"].clone() });
        assert!(reject(&bad_key), "invalid hsm_id key");

        let mut replication = good.clone();
        replication["purpose"] = "replication-channel".into();
        assert!(reject(&replication), "purpose not storable in a set");

        let mut no_creator = good.clone();
        no_creator["created_by"] = "".into();
        assert!(reject(&no_creator), "created_by required");

        let bytes = set.to_bytes().unwrap();
        assert!(BvHsmBlobSet::from_bytes(&bytes[..bytes.len() - 7]).is_err(), "truncated data");
    }

    #[test]
    fn duplicate_hsm_id_is_rejected_not_shadowed() {
        let a = serde_json::to_string(&copy_on("A", Purpose::BarrierKek, 0)).unwrap();
        let dup = format!(
            "{{\"version\":1,\"purpose\":\"barrier-kek\",\"epoch\":0,\"copies\":{{\"mock:A\":{a},\"mock:A\":{a}}},\
             \"created_at\":1,\"created_by\":\"n1\"}}"
        );
        let err = BvHsmBlobSet::from_bytes(dup.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("duplicate key mock:A"), "{err}");
    }

    #[test]
    fn v1_copies_are_rejected() {
        let mut good: serde_json::Value = serde_json::from_slice(&one_copy_set().to_bytes().unwrap()).unwrap();
        let copy = &mut good["copies"]["mock:A"];
        copy["version"] = 1.into();
        copy["aad"]["node_id"] = "n1".into();
        copy["aad"].as_object_mut().unwrap().remove("hsm_id");
        copy["aad"].as_object_mut().unwrap().remove("authz_alg");
        assert!(BvHsmBlobSet::from_bytes(&serde_json::to_vec(&good).unwrap()).is_err());
    }

    #[test]
    fn truncated_recovery_envelope_is_rejected() {
        let mut set = one_copy_set();
        let (mut env, _) = recovery_envelope(b"kek");
        env.kem_ciphertext.truncate(100);
        set.recovery = Some(env);
        assert!(set.validate().is_err());
        assert!(set.to_bytes().is_err(), "an invalid set is never written");

        let mut wrong_version = one_copy_set();
        let (mut env, _) = recovery_envelope(b"kek");
        env.version = 9;
        wrong_version.recovery = Some(env);
        assert!(wrong_version.validate().is_err());
    }
}
