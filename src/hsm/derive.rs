//! Hybrid PQC seed derivation and key generation (spec § Capability 2).
//!
//! The YubiHSM 2 cannot run ML-KEM-768 / ML-DSA-65, so PQC keys use a hybrid
//! custody model: the HSM is the custody / wrapping / attestation anchor while
//! the PQC math runs in software over transiently-unwrapped seeds. Every seed
//! is derived from three independent inputs and never persists in plaintext:
//!
//! 1. **Fresh host entropy** — `OsRng(64)` (rule 3, mandatory, never optional).
//! 2. **HSM randomness** — `get_random(32)` from the local device (augments,
//!    never replaces, the host CSPRNG).
//! 3. **Classical HSM contribution** — `derive_ecdh(bv-identity, binding_pub)`,
//!    a secret computable only inside an enrolled HSM. It is an *additional*
//!    input, never the sole one (rule 1): a quantum adversary who breaks the
//!    ECDH still cannot reconstruct the seed without the host entropy.
//!
//! `seed = HKDF-SHA-512(ikm = e_host ‖ e_hsm ‖ s_ecdh, salt = cluster_uuid,
//! info = context)`, with a distinct context per key purpose (rules 4, 5).

use bv_crypto::{MlDsa65Provider, MlKem768Provider, ML_DSA_65_SEED_LEN, ML_KEM_768_SEED_LEN};
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::{
    errors::RvError,
    hsm::{
        blob::{Context, Purpose},
        context, HsmBackend, ResolvedHsmConfig,
    },
};

/// Which PQC key family a seed is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqcKeyKind {
    MlKem768,
    MlDsa65,
}

impl PqcKeyKind {
    fn seed_len(&self) -> usize {
        match self {
            PqcKeyKind::MlKem768 => ML_KEM_768_SEED_LEN,
            PqcKeyKind::MlDsa65 => ML_DSA_65_SEED_LEN,
        }
    }

    fn purpose(&self) -> Purpose {
        match self {
            PqcKeyKind::MlKem768 => Purpose::PqcKemSeed,
            PqcKeyKind::MlDsa65 => Purpose::PqcSigSeed,
        }
    }

    fn seed_context(&self, cluster_uuid: &str, epoch: u64) -> String {
        match self {
            PqcKeyKind::MlKem768 => context::pqc_kem_seed(cluster_uuid, epoch),
            PqcKeyKind::MlDsa65 => context::pqc_sig_seed(cluster_uuid, epoch),
        }
    }
}

/// Derive a PQC seed from the three entropy inputs via HKDF-SHA-512. Pure and
/// deterministic in its inputs so it can be unit-tested without an HSM.
pub fn derive_pqc_seed(
    e_host: &[u8],
    e_hsm: &[u8],
    s_ecdh: &[u8],
    cluster_uuid: &str,
    seed_context: &str,
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>, RvError> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(e_host.len() + e_hsm.len() + s_ecdh.len()));
    ikm.extend_from_slice(e_host);
    ikm.extend_from_slice(e_hsm);
    ikm.extend_from_slice(s_ecdh);

    let hk = Hkdf::<Sha512>::new(Some(cluster_uuid.as_bytes()), &ikm);
    let mut okm = Zeroizing::new(vec![0u8; out_len]);
    hk.expand(seed_context.as_bytes(), okm.as_mut_slice())
        .map_err(|_| RvError::ErrHsm("HKDF expand failed for PQC seed".into()))?;
    Ok(okm)
}

/// The published public key plus the HSM-wrapped seed blob for a new PQC key.
/// The plaintext seed never leaves this function's `Zeroizing` buffers.
pub struct GeneratedPqcKey {
    pub kind: PqcKeyKind,
    pub public_key: Vec<u8>,
    /// Serialized `BvHsmBlob` wrapping the seed under `bv-wrap-pqc`.
    pub wrapped_seed: Vec<u8>,
}

/// Generate a PQC key under hybrid custody: gather the three entropy inputs,
/// derive the seed, publish the public key, wrap the seed, and zeroize all
/// intermediate material. `binding_pub` is the cluster ECDH binding point
/// (SEC1-uncompressed P-256), typically the bootstrap node's `bv-identity`
/// public key from the custody root.
#[maybe_async::maybe_async]
pub async fn generate_pqc_key(
    backend: &dyn HsmBackend,
    config: &ResolvedHsmConfig,
    cluster_uuid: &str,
    epoch: u64,
    kind: PqcKeyKind,
    binding_pub: &[u8],
) -> Result<GeneratedPqcKey, RvError> {
    // 1. Fresh host entropy (mandatory).
    let mut e_host = Zeroizing::new(vec![0u8; 64]);
    rand::rng().fill_bytes(e_host.as_mut_slice());
    // 2. HSM randomness.
    let e_hsm = backend.get_random(32).await?;
    // 3. Classical HSM ECDH contribution (only computable inside the device).
    let s_ecdh = backend.derive_ecdh(config.objects.identity, binding_pub).await?;

    let seed_context = kind.seed_context(cluster_uuid, epoch);
    let seed = derive_pqc_seed(&e_host, &e_hsm, &s_ecdh, cluster_uuid, &seed_context, kind.seed_len())?;

    let public_key = match kind {
        PqcKeyKind::MlKem768 => MlKem768Provider
            .keypair_from_seed(&seed)
            .map_err(|e| RvError::ErrHsm(format!("ML-KEM keypair from seed: {e}")))?
            .public_key()
            .to_vec(),
        PqcKeyKind::MlDsa65 => MlDsa65Provider
            .keypair_from_seed(&seed)
            .map_err(|e| RvError::ErrHsm(format!("ML-DSA keypair from seed: {e}")))?
            .public_key()
            .to_vec(),
    };

    let wrap_ctx = Context::new(seed_context, kind.purpose(), epoch, &config.node_id);
    let wrapped_seed = backend.wrap_data(config.objects.wrap_pqc, &wrap_ctx, &seed).await?;

    // e_host, e_hsm, s_ecdh, seed all zeroize on drop here.
    Ok(GeneratedPqcKey { kind, public_key, wrapped_seed })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_changes_when_any_input_changes() {
        let base = derive_pqc_seed(&[1u8; 64], &[2u8; 32], &[3u8; 32], "clu", "ctx", 64).unwrap();
        let diff_host = derive_pqc_seed(&[9u8; 64], &[2u8; 32], &[3u8; 32], "clu", "ctx", 64).unwrap();
        let diff_hsm = derive_pqc_seed(&[1u8; 64], &[9u8; 32], &[3u8; 32], "clu", "ctx", 64).unwrap();
        let diff_ecdh = derive_pqc_seed(&[1u8; 64], &[2u8; 32], &[9u8; 32], "clu", "ctx", 64).unwrap();
        assert_ne!(base.as_slice(), diff_host.as_slice());
        assert_ne!(base.as_slice(), diff_hsm.as_slice());
        assert_ne!(base.as_slice(), diff_ecdh.as_slice());
    }

    #[test]
    fn seed_is_deterministic_for_identical_inputs() {
        let a = derive_pqc_seed(&[1u8; 64], &[2u8; 32], &[3u8; 32], "clu", "ctx", 64).unwrap();
        let b = derive_pqc_seed(&[1u8; 64], &[2u8; 32], &[3u8; 32], "clu", "ctx", 64).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn different_context_yields_unrelated_seed() {
        let kem = derive_pqc_seed(&[1u8; 64], &[2u8; 32], &[3u8; 32], "clu", "kem-ctx", 64).unwrap();
        let sig = derive_pqc_seed(&[1u8; 64], &[2u8; 32], &[3u8; 32], "clu", "sig-ctx", 64).unwrap();
        assert_ne!(kem.as_slice(), sig.as_slice());
    }

    #[test]
    fn different_salt_yields_unrelated_seed() {
        let a = derive_pqc_seed(&[1u8; 64], &[2u8; 32], &[3u8; 32], "cluster-a", "ctx", 64).unwrap();
        let b = derive_pqc_seed(&[1u8; 64], &[2u8; 32], &[3u8; 32], "cluster-b", "ctx", 64).unwrap();
        assert_ne!(a.as_slice(), b.as_slice());
    }
}
