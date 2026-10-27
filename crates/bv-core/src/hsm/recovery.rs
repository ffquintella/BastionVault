//! Recovery key primitives for the HSM pool (T454 phase 5). Init generates an
//! ML-KEM-768 keypair from a 64-byte seed, Shamir-splits the seed and returns
//! the shares once; only the public key, its fingerprint and the split are
//! stored. Recovery copies are `KemDemEnvelopeV1`s sealed to that key, and a
//! recombination is accepted only if it yields the stored fingerprint.
//! Spec: `features/hsm-pool-ha.md` § Recovery: Shamir ceremony.

use std::fmt;

use bv_crypto::{KemDemEnvelopeV1, KemKeypair, MlKem768Provider, ML_KEM_768_SEED_LEN};
use rand::Rng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    errors::RvError,
    hsm::{blob::Purpose, context, derive::PqcKeyKind},
    shamir::ShamirSecret,
};

/// Domain of every recovery-copy AAD. A new layout is a new version string.
pub const RECOVERY_COPY_CONTEXT: &str = "bastionvault/hsm/recovery-copy/v1";
/// The `subject` the barrier KEK's recovery copy binds (custody sets bind
/// their key id).
pub const KEK_RECOVERY_SUBJECT: &str = "barrier-kek";
/// `recovery_shares` when init leaves it out (spec: default 5 / 3).
pub const DEFAULT_RECOVERY_SHARES: u8 = 5;
/// `recovery_threshold` when init leaves it out.
pub const DEFAULT_RECOVERY_THRESHOLD: u8 = 3;
/// A share is the seed's length plus the x coordinate `bv-shamir` appends.
pub const RECOVERY_SHARE_LEN: usize = ML_KEM_768_SEED_LEN + 1;
/// `bv-shamir` refuses 255 parts; one byte holds the x coordinate.
const MAX_RECOVERY_SHARES: u8 = 254;

/// How many recovery shares init produces, and how many recombine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoverySplit {
    pub shares: u8,
    pub threshold: u8,
}

impl Default for RecoverySplit {
    fn default() -> Self {
        Self { shares: DEFAULT_RECOVERY_SHARES, threshold: DEFAULT_RECOVERY_THRESHOLD }
    }
}

impl RecoverySplit {
    /// `2 <= threshold <= shares <= 254`. A 1-of-N split would make any single
    /// holder the whole recovery key, so it is refused, not accepted quietly.
    pub fn validate(&self) -> Result<(), RvError> {
        if self.threshold < 2 || self.threshold > self.shares || self.shares > MAX_RECOVERY_SHARES {
            return Err(RvError::ErrHsmConfigInvalid(format!(
                "recovery_shares = {} / recovery_threshold = {} is not a valid split: it needs 2 <= threshold <= \
                 shares <= {MAX_RECOVERY_SHARES}",
                self.shares, self.threshold
            )));
        }
        Ok(())
    }
}

/// Hex SHA-256 of a recovery public key.
pub fn recovery_fingerprint(public_key: &[u8]) -> String {
    hex::encode(Sha256::digest(public_key))
}

/// The AAD a recovery copy is sealed under: the set's context string,
/// purpose and epoch, plus a subject (the custody key id, or
/// [`KEK_RECOVERY_SUBJECT`]), each length-prefixed so no two field lists
/// encode alike. A copy moved to another set, purpose, epoch or key fails
/// authentication instead of opening.
pub fn recovery_aad(context: &str, purpose: Purpose, epoch: u64, subject: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(96 + context.len() + subject.len());
    for field in [RECOVERY_COPY_CONTEXT, context, purpose.as_token()] {
        out.extend_from_slice(&(field.len() as u64).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&(subject.len() as u64).to_be_bytes());
    out.extend_from_slice(subject.as_bytes());
    out.extend_from_slice(b"recovery");
    out
}

/// The AAD of the barrier KEK's recovery copy at `epoch`.
pub fn kek_recovery_aad(cluster_uuid: &str, epoch: u64) -> Vec<u8> {
    recovery_aad(&context::barrier_kek(cluster_uuid), Purpose::BarrierKek, epoch, KEK_RECOVERY_SUBJECT)
}

/// The AAD of custody key `key_id`'s recovery copy at `epoch`.
pub fn custody_recovery_aad(cluster_uuid: &str, kind: PqcKeyKind, epoch: u64, key_id: &str) -> Vec<u8> {
    recovery_aad(&kind.seed_context(cluster_uuid, epoch), kind.purpose(), epoch, key_id)
}

/// A freshly generated recovery key: the public half to store and the
/// shares to hand out once. The seed itself is gone when this is returned.
pub struct GeneratedRecoveryKey {
    pub public_key: Vec<u8>,
    pub shares: Zeroizing<Vec<Vec<u8>>>,
}

impl fmt::Debug for GeneratedRecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedRecoveryKey")
            .field("fingerprint", &recovery_fingerprint(&self.public_key))
            .field("shares", &format_args!("<{} redacted>", self.shares.len()))
            .finish()
    }
}

/// Generate the recovery keypair from a fresh host-CSPRNG seed and split the
/// seed. The seed and the keypair's private half are zeroized on return.
pub fn generate(split: RecoverySplit) -> Result<GeneratedRecoveryKey, RvError> {
    split.validate()?;
    let mut seed = Zeroizing::new(vec![0u8; ML_KEM_768_SEED_LEN]);
    rand::rng().fill_bytes(seed.as_mut_slice());
    let keypair = keypair_from_seed(&seed)?;
    let shares = ShamirSecret::split(&seed, split.shares, split.threshold)?;
    Ok(GeneratedRecoveryKey { public_key: keypair.public_key().to_vec(), shares })
}

fn keypair_from_seed(seed: &[u8]) -> Result<KemKeypair, RvError> {
    MlKem768Provider.keypair_from_seed(seed).map_err(|e| RvError::ErrHsm(format!("recovery keypair from seed: {e}")))
}

/// Seal `secret` to the recovery public key. Needs no secret: this is what
/// init, custody create, repair and rotation call.
pub fn seal_copy(public_key: &[u8], aad: &[u8], secret: &[u8]) -> Result<KemDemEnvelopeV1, RvError> {
    KemDemEnvelopeV1::seal(&MlKem768Provider, public_key, aad, secret)
        .map_err(|e| RvError::ErrHsm(format!("sealing a recovery copy failed: {e}")))
}

/// The recombined recovery private key, alive only for one ceremony. No
/// `Clone`, no key bytes in `Debug`; the keypair zeroizes on drop.
pub struct RecoveryKey {
    keypair: KemKeypair,
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryKey").field("fingerprint", &self.fingerprint()).finish_non_exhaustive()
    }
}

impl RecoveryKey {
    pub fn fingerprint(&self) -> String {
        recovery_fingerprint(self.keypair.public_key())
    }

    /// Open a recovery copy. A wrong AAD, key or a tampered envelope is an
    /// error, never a partial result.
    pub fn open(&self, envelope: &KemDemEnvelopeV1, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, RvError> {
        envelope.open(&MlKem768Provider, self.keypair.secret_key(), aad).map(Zeroizing::new).map_err(|_| {
            RvError::ErrHsm(
                "a recovery copy did not open under the recovery key (tampered, or moved from another set)".into(),
            )
        })
    }
}

/// Shares submitted so far for one recovery ceremony. Held in memory only,
/// every share zeroized when this is dropped or reset.
#[derive(Default)]
pub struct ShareSet {
    shares: Vec<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for ShareSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareSet").field("indexes", &self.indexes()).finish()
    }
}

impl ShareSet {
    pub fn len(&self) -> usize {
        self.shares.len()
    }

    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }

    /// The x coordinate of each share, in submission order: what the audit
    /// event records. Not secret on its own.
    pub fn indexes(&self) -> Vec<u8> {
        self.shares.iter().filter_map(|s| s.last().copied()).collect()
    }

    /// Add one share. Refuses a share of the wrong length, x = 0 (no such
    /// share exists), or an x already submitted; the error never echoes it.
    pub fn add(&mut self, share: Zeroizing<Vec<u8>>) -> Result<(), RvError> {
        if share.len() != RECOVERY_SHARE_LEN {
            return Err(RvError::ErrHsm(format!(
                "a recovery share is {RECOVERY_SHARE_LEN} bytes ({} hex characters); this one is {}",
                RECOVERY_SHARE_LEN * 2,
                share.len()
            )));
        }
        let index = share[RECOVERY_SHARE_LEN - 1];
        if index == 0 {
            return Err(RvError::ErrHsm("malformed recovery share (index 0)".into()));
        }
        if self.indexes().contains(&index) {
            return Err(RvError::ErrHsm(format!("recovery share {index} was already submitted")));
        }
        self.shares.push(share);
        Ok(())
    }

    /// Recombine the shares and accept the key only if its public half has
    /// `expected_fingerprint`. Fewer than `threshold` shares are refused
    /// before anything is combined: Shamir would return a wrong secret
    /// silently, so the count and the fingerprint both gate the result.
    pub fn combine(&self, threshold: u8, expected_fingerprint: &str) -> Result<RecoveryKey, RvError> {
        if self.shares.len() < usize::from(threshold.max(2)) {
            return Err(RvError::ErrHsm(format!(
                "{} of {threshold} recovery shares submitted; the ceremony needs {threshold}",
                self.shares.len()
            )));
        }
        // `bv-shamir` takes owned shares; these copies are not zeroized by it
        // (a `bv-shamir` limitation, recorded as a follow-up in the spec).
        let owned: Vec<Vec<u8>> = self.shares.iter().map(|s| s.to_vec()).collect();
        let seed = Zeroizing::new(
            ShamirSecret::combine(owned)
                .ok_or_else(|| RvError::ErrHsm("the recovery shares could not be combined".into()))?,
        );
        if seed.len() != ML_KEM_768_SEED_LEN {
            return Err(RvError::ErrHsm("the recovery shares do not reconstruct a recovery key".into()));
        }
        let keypair = keypair_from_seed(&seed)?;
        drop(seed);
        let key = RecoveryKey { keypair };
        if key.fingerprint() != expected_fingerprint {
            log::error!(
                target: "security",
                "HSM recovery ceremony: the submitted shares (indexes {:?}) do not reconstruct this cluster's \
                 recovery key",
                self.indexes()
            );
            return Err(RvError::ErrHsm(
                "the recovery shares do not reconstruct this cluster's recovery key (wrong, tampered or too few \
                 shares); submit them again"
                    .into(),
            ));
        }
        Ok(key)
    }
}

/// Decode a hex share, refusing anything else without echoing it.
pub fn decode_share(hex_share: &str) -> Result<Zeroizing<Vec<u8>>, RvError> {
    hex::decode(hex_share.trim())
        .map(Zeroizing::new)
        .map_err(|_| RvError::ErrHsm("a recovery share must be hex (as init printed it)".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(shares: u8, threshold: u8) -> (GeneratedRecoveryKey, String) {
        let generated = generate(RecoverySplit { shares, threshold }).unwrap();
        let fp = recovery_fingerprint(&generated.public_key);
        (generated, fp)
    }

    fn set_of(shares: &[Vec<u8>]) -> ShareSet {
        let mut set = ShareSet::default();
        for s in shares {
            set.add(Zeroizing::new(s.clone())).unwrap();
        }
        set
    }

    #[test]
    fn splits_are_validated() {
        RecoverySplit::default().validate().unwrap();
        for (shares, threshold) in [(5, 1), (2, 3), (255, 3), (1, 1), (0, 0)] {
            assert!(RecoverySplit { shares, threshold }.validate().is_err(), "{shares}/{threshold}");
        }
        assert!(generate(RecoverySplit { shares: 3, threshold: 1 }).is_err());
    }

    #[test]
    fn any_threshold_subset_recombines_and_the_key_opens_its_copies() {
        let (generated, fp) = split(5, 3);
        assert_eq!(generated.shares.len(), 5);
        assert!(generated.shares.iter().all(|s| s.len() == RECOVERY_SHARE_LEN));
        let aad = recovery_aad("ctx", Purpose::BarrierKek, 4, KEK_RECOVERY_SUBJECT);
        let copy = seal_copy(&generated.public_key, &aad, b"the-kek").unwrap();
        for subset in [[0usize, 1, 2], [4, 2, 0], [1, 3, 4]] {
            let shares: Vec<Vec<u8>> = subset.iter().map(|i| generated.shares[*i].clone()).collect();
            let key = set_of(&shares).combine(3, &fp).unwrap();
            assert_eq!(key.open(&copy, &aad).unwrap().as_slice(), b"the-kek");
        }
        let all = set_of(&generated.shares);
        assert_eq!(all.indexes(), vec![1, 2, 3, 4, 5]);
        all.combine(3, &fp).unwrap();
    }

    #[test]
    fn too_few_wrong_or_tampered_shares_are_refused() {
        let (generated, fp) = split(5, 3);
        let two = set_of(&generated.shares[..2]);
        let err = two.combine(3, &fp).unwrap_err();
        assert!(err.to_string().contains("2 of 3"), "{err}");
        // A lowered threshold (a tampered record) still fails the fingerprint.
        assert!(two.combine(2, &fp).is_err(), "two shares of a 3-of-5 split never yield the key");

        let (other, _) = split(5, 3);
        let mixed = set_of(&[generated.shares[0].clone(), generated.shares[1].clone(), other.shares[2].clone()]);
        assert!(mixed.combine(3, &fp).is_err(), "a share from another split");

        let mut flipped = generated.shares[2].clone();
        flipped[7] ^= 0x01;
        let tampered = set_of(&[generated.shares[0].clone(), generated.shares[1].clone(), flipped]);
        let err = tampered.combine(3, &fp).unwrap_err();
        assert!(err.to_string().contains("do not reconstruct"), "{err}");
    }

    #[test]
    fn malformed_shares_are_refused_without_being_echoed() {
        let (generated, _) = split(3, 2);
        let mut set = ShareSet::default();
        assert!(set.add(Zeroizing::new(vec![1u8; 10])).is_err(), "short");
        assert!(set.add(Zeroizing::new(vec![1u8; RECOVERY_SHARE_LEN + 1])).is_err(), "long");
        let mut zero = generated.shares[0].clone();
        *zero.last_mut().unwrap() = 0;
        assert!(set.add(Zeroizing::new(zero)).is_err(), "index 0");
        set.add(Zeroizing::new(generated.shares[0].clone())).unwrap();
        let dup = set.add(Zeroizing::new(generated.shares[0].clone())).unwrap_err();
        assert!(dup.to_string().contains("already submitted"), "{dup}");
        assert_eq!(set.len(), 1);
        let secret_hex = hex::encode(&generated.shares[1]);
        let err = decode_share(&format!("{secret_hex}zz")).unwrap_err();
        assert!(!err.to_string().contains(&secret_hex), "never echoed");
        assert_eq!(decode_share(&secret_hex).unwrap().as_slice(), generated.shares[1].as_slice());
    }

    #[test]
    fn the_aad_binds_context_purpose_epoch_and_subject() {
        let (generated, fp) = split(3, 2);
        let key = set_of(&generated.shares[..2]).combine(2, &fp).unwrap();
        let aad = recovery_aad("ctx", Purpose::PqcKemSeed, 1, "key-a");
        let copy = seal_copy(&generated.public_key, &aad, b"seed").unwrap();
        for other in [
            recovery_aad("ctx2", Purpose::PqcKemSeed, 1, "key-a"),
            recovery_aad("ctx", Purpose::PqcSigSeed, 1, "key-a"),
            recovery_aad("ctx", Purpose::PqcKemSeed, 2, "key-a"),
            recovery_aad("ctx", Purpose::PqcKemSeed, 1, "key-b"),
        ] {
            assert!(key.open(&copy, &other).is_err());
        }
        let mut tampered = copy.clone();
        tampered.payload_ciphertext[0] ^= 0x80;
        assert!(key.open(&tampered, &aad).is_err(), "a tampered copy");
        assert_eq!(key.open(&copy, &aad).unwrap().as_slice(), b"seed");
    }

    #[test]
    fn debug_output_never_carries_key_material() {
        let (generated, fp) = split(3, 2);
        let rendered = format!("{generated:?}");
        for share in generated.shares.iter() {
            assert!(!rendered.contains(&hex::encode(share)), "{rendered}");
        }
        let set = set_of(&generated.shares[..2]);
        let key = set.combine(2, &fp).unwrap();
        assert!(format!("{key:?}").contains(&fp));
        assert!(!format!("{set:?}").contains(&hex::encode(&generated.shares[0])));
    }
}
