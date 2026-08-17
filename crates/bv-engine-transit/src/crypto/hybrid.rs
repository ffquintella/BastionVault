//! Hybrid (composite) primitives — Phase 4, `transit_pqc_hybrid` feature.
//!
//! Two separate constructions live here:
//!
//!   * **Composite signing** (`hybrid-ed25519+ml-dsa-65`):
//!     Each half signs the same caller-supplied message under its
//!     own algorithm. The wire format concatenates the two raw
//!     signatures with a length prefix on the first half:
//!
//!     ```text
//!     u16-be(len(ed25519_sig)) || ed25519_sig || mldsa65_sig
//!     ```
//!
//!     A verifier MUST validate **both** halves; either failing
//!     fails the verify. We deliberately do *not* track the IETF
//!     `draft-ietf-lamps-pq-composite-sigs` SEQUENCE-of-two-BIT-STRINGs
//!     wire shape here — that draft was still moving on the prehash
//!     domain at the time this code was written, and Vault's `transit`
//!     surface doesn't otherwise touch DER. Operators who need the
//!     IETF wire format use the PKI engine's `pki_pqc_composite`
//!     code path.
//!
//!   * **Hybrid KEM** (`hybrid-x25519+ml-kem-768`):
//!     X25519 ECDH || ML-KEM-768 KEM. The two shared secrets are
//!     concatenated and fed through HKDF-SHA-256 (info
//!     `"bvault-transit-hybrid-kem"`) to derive a 32-byte
//!     AES-shaped key. The wire format for the wrapped form
//!     concatenates the X25519 ephemeral pubkey with the ML-KEM
//!     ciphertext:
//!
//!     ```text
//!     u16-be(len(x25519_eph_pk)) || x25519_eph_pk || ml_kem_ct
//!     ```
//!
//!     This is the IETF KEM-combiner shape per
//!     `draft-ietf-lamps-pq-composite-kem` modulo the OID arc, which
//!     this engine doesn't surface (it's a plain-bytes KEM, not a
//!     PKIX cert).

use bv_crypto::{KemProvider, MlDsa65Provider, MlKem768Provider};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::RngExt;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use super::{ed25519, ml_dsa, ml_kem};
use crate::errors::RvError;

const HYBRID_KEM_INFO: &[u8] = b"bvault-transit-hybrid-kem";
pub const HYBRID_DATAKEY_LEN: usize = 32;
const X25519_KEY_LEN: usize = 32;

// ── Composite signing keypair (Ed25519 + ML-DSA-65) ──────────────

/// Material layout for `hybrid-ed25519+ml-dsa-65`:
///
/// ```text
/// material: u16-be(32) || ed25519_seed (32) || ml_dsa_65_seed (32)
/// pk:       u16-be(32) || ed25519_pk   (32) || ml_dsa_65_pk
/// ```
///
/// The length prefix is what lets a future revision swap one half
/// for a different security level (e.g. add ML-DSA-87 alongside the
/// classical ed25519) without breaking the parser.
pub fn generate_signing_keypair() -> Result<(Vec<u8>, Vec<u8>), RvError> {
    let (ed_seed, ed_pk) = ed25519::generate_keypair();
    let (ml_seed, ml_pk) = ml_dsa::generate_keypair(super::super::keytype::KeyType::MlDsa65)?;

    let material = pack_two(&ed_seed, &ml_seed);
    let pk = pack_two(&ed_pk, &ml_pk);
    Ok((material, pk))
}

pub fn sign_composite(material: &[u8], message: &[u8]) -> Result<Vec<u8>, RvError> {
    let (ed_seed, ml_seed) = unpack_two(material)?;

    let ed_sig = ed25519::sign(ed_seed, message)?;
    let ml_sig = ml_dsa::sign(super::super::keytype::KeyType::MlDsa65, ml_seed, message)?;

    Ok(pack_two(&ed_sig, &ml_sig))
}

pub fn verify_composite(pk: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, RvError> {
    let (ed_pk, ml_pk_unused_today) = unpack_two(pk)?;
    let _ = ml_pk_unused_today; // bv_crypto::ml_dsa rederives from seed; we use seed-side verify.

    let (ed_sig, ml_sig) = unpack_two(signature)?;

    // Verify Ed25519 directly — the existing `ed25519::verify` takes
    // the public key, exactly what we have.
    let ed_ok = ed25519::verify(ed_pk, message, ed_sig)?;
    if !ed_ok {
        // Fail-fast on the cheap classical half so we don't spend
        // ML-DSA verify cycles on a payload the classical side has
        // already rejected.
        return Ok(false);
    }

    // For the PQC half we don't have a direct "verify against public
    // key" path through `bv_crypto` — the wrapper only exposes
    // verify-from-seed. We re-derive the seed's verify path through
    // the published `ml_dsa::verify` helper, which itself rederives
    // the public key from a seed. To avoid round-tripping the seed
    // here, use the FIPS 204 verifier directly: this is safe to
    // reach at this layer because the public key is the input the
    // verifier wants.
    use fips204::ml_dsa_65;
    use fips204::traits::{SerDes, Verifier as _};

    let ml_pk_arr: [u8; ml_dsa_65::PK_LEN] = ml_pk_unused_today.try_into().map_err(|_| {
        RvError::ErrString(format!(
            "ml-dsa-65 pubkey must be {} bytes, got {}",
            ml_dsa_65::PK_LEN,
            pk.len()
        ))
    })?;
    let ml_sig_arr: [u8; ml_dsa_65::SIG_LEN] = ml_sig.try_into().map_err(|_| {
        RvError::ErrString(format!(
            "ml-dsa-65 signature must be {} bytes, got {}",
            ml_dsa_65::SIG_LEN,
            ml_sig.len()
        ))
    })?;
    let ml_pk_obj = ml_dsa_65::PublicKey::try_from_bytes(ml_pk_arr)
        .map_err(|e| RvError::ErrString(format!("ml-dsa-65 pubkey parse: {e}")))?;
    let pq_ok = ml_pk_obj.verify(message, &ml_sig_arr, &[]);
    Ok(pq_ok)
}

// ── Hybrid KEM (X25519 + ML-KEM-768) ─────────────────────────────

/// Material layout for `hybrid-x25519+ml-kem-768`:
///
/// ```text
/// material: u16-be(32) || x25519_secret (32) || ml_kem_secret_key
/// pk:       u16-be(32) || x25519_public (32) || ml_kem_public_key
/// ```
pub fn generate_kem_keypair() -> Result<(Vec<u8>, Vec<u8>), RvError> {
    // X25519 static secret + matching public.
    let mut x_secret_bytes = [0u8; X25519_KEY_LEN];
    rand::rng().fill(&mut x_secret_bytes[..]);
    let x_secret = XStaticSecret::from(x_secret_bytes);
    let x_public = XPublicKey::from(&x_secret).to_bytes();

    let (ml_sk, ml_pk) = ml_kem::generate_keypair()?;

    let material = pack_two(x_secret.as_bytes().as_slice(), &ml_sk);
    let pk = pack_two(&x_public, &ml_pk);
    Ok((material, pk))
}

/// Encapsulate to the recipient's hybrid public key. Returns
/// `(datakey_plaintext, kem_ciphertext)`.
pub fn encapsulate_hybrid_datakey(pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), RvError> {
    let (x_pk_bytes, ml_pk) = unpack_two(pk)?;

    // Generate an ephemeral X25519 secret for ECDH.
    let mut eph_secret_bytes = [0u8; X25519_KEY_LEN];
    rand::rng().fill(&mut eph_secret_bytes[..]);
    let eph_secret = XStaticSecret::from(eph_secret_bytes);
    let eph_public = XPublicKey::from(&eph_secret).to_bytes();

    let x_pk_arr: [u8; X25519_KEY_LEN] = x_pk_bytes.try_into().map_err(|_| {
        RvError::ErrString(format!("x25519 pubkey must be {X25519_KEY_LEN} bytes"))
    })?;
    let x_recipient_pk = XPublicKey::from(x_pk_arr);
    let x_ss = eph_secret.diffie_hellman(&x_recipient_pk);

    // ML-KEM encapsulation against the recipient's PQ public.
    let provider = MlKem768Provider;
    let (ml_ct, ml_ss) = provider
        .encapsulate(ml_pk)
        .map_err(|e| RvError::ErrString(format!("ml-kem-768 encapsulate: {e:?}")))?;

    let dk = combine_secrets(x_ss.as_bytes(), ml_ss.as_bytes())?;
    let wrapped = pack_two(&eph_public, ml_ct.as_bytes());
    Ok((dk, wrapped))
}

pub fn decapsulate_hybrid_datakey(material: &[u8], kem_blob: &[u8]) -> Result<Vec<u8>, RvError> {
    let (x_secret_bytes, ml_secret) = unpack_two(material)?;
    let (x_eph_pub_bytes, ml_ct) = unpack_two(kem_blob)?;

    let x_sk_arr: [u8; X25519_KEY_LEN] = x_secret_bytes.try_into().map_err(|_| {
        RvError::ErrString(format!("x25519 secret must be {X25519_KEY_LEN} bytes"))
    })?;
    let x_eph_pk_arr: [u8; X25519_KEY_LEN] = x_eph_pub_bytes.try_into().map_err(|_| {
        RvError::ErrString(format!("x25519 ephemeral pubkey must be {X25519_KEY_LEN} bytes"))
    })?;

    let x_secret = XStaticSecret::from(x_sk_arr);
    let x_eph_pub = XPublicKey::from(x_eph_pk_arr);
    let x_ss = x_secret.diffie_hellman(&x_eph_pub);

    let provider = MlKem768Provider;
    let ml_ss = provider
        .decapsulate(ml_secret, ml_ct)
        .map_err(|e| RvError::ErrString(format!("ml-kem-768 decapsulate: {e:?}")))?;

    combine_secrets(x_ss.as_bytes(), ml_ss.as_bytes())
}

fn combine_secrets(classical_ss: &[u8], pqc_ss: &[u8]) -> Result<Vec<u8>, RvError> {
    // Concatenated-shared-secret combiner. The IETF
    // draft-ietf-lamps-pq-composite-kem variant we track today wraps
    // both halves into HKDF-SHA-256 directly — no separate domain
    // string per half — and trusts the asymmetric structure of HKDF
    // to derive a fresh symmetric key from the joint material.
    let mut ikm = Vec::with_capacity(classical_ss.len() + pqc_ss.len());
    ikm.extend_from_slice(classical_ss);
    ikm.extend_from_slice(pqc_ss);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut out = vec![0u8; HYBRID_DATAKEY_LEN];
    hk.expand(HYBRID_KEM_INFO, &mut out)
        .map_err(|e| RvError::ErrString(format!("hkdf expand: {e}")))?;
    Ok(out)
}

// ── Length-prefix codec ──────────────────────────────────────────

fn pack_two(first: &[u8], second: &[u8]) -> Vec<u8> {
    let n = first.len();
    assert!(n <= u16::MAX as usize, "first half exceeds u16::MAX bytes");
    let mut out = Vec::with_capacity(2 + n + second.len());
    out.extend_from_slice(&(n as u16).to_be_bytes());
    out.extend_from_slice(first);
    out.extend_from_slice(second);
    out
}

fn unpack_two(buf: &[u8]) -> Result<(&[u8], &[u8]), RvError> {
    if buf.len() < 2 {
        return Err(RvError::ErrString(
            "hybrid blob too short to contain a length prefix".into(),
        ));
    }
    let n = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + n {
        return Err(RvError::ErrString(format!(
            "hybrid blob truncated: header says first half is {n} bytes, only {} bytes follow",
            buf.len() - 2
        )));
    }
    Ok((&buf[2..2 + n], &buf[2 + n..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composite_sign_verify_round_trip() {
        let (material, pk) = generate_signing_keypair().unwrap();
        let msg = b"hybrid composite sig";
        let sig = sign_composite(&material, msg).unwrap();
        assert!(verify_composite(&pk, msg, &sig).unwrap());
        assert!(!verify_composite(&pk, b"tampered", &sig).unwrap());
    }

    #[test]
    fn composite_signature_two_halves_required() {
        let (material, pk) = generate_signing_keypair().unwrap();
        let msg = b"x";
        let mut sig = sign_composite(&material, msg).unwrap();
        // Flip a byte inside the ML-DSA half: should fail verify.
        let last = sig.len() - 1;
        sig[last] ^= 0x01;
        assert!(!verify_composite(&pk, msg, &sig).unwrap_or(false));
    }

    #[test]
    fn hybrid_kem_round_trip() {
        let (material, pk) = generate_kem_keypair().unwrap();
        let (dk_send, kem_ct) = encapsulate_hybrid_datakey(&pk).unwrap();
        let dk_recv = decapsulate_hybrid_datakey(&material, &kem_ct).unwrap();
        assert_eq!(dk_send, dk_recv);
        assert_eq!(dk_send.len(), HYBRID_DATAKEY_LEN);
    }

    #[test]
    fn hybrid_kem_tampered_fails() {
        let (material, pk) = generate_kem_keypair().unwrap();
        let (_dk_send, mut kem_ct) = encapsulate_hybrid_datakey(&pk).unwrap();
        let last = kem_ct.len() - 1;
        kem_ct[last] ^= 0x01;
        // The ML-KEM half rejects a tampered ciphertext with implicit
        // rejection — decapsulate may "succeed" but produce a different
        // key. Either way, sender and receiver disagree.
        let result = decapsulate_hybrid_datakey(&material, &kem_ct);
        if let Ok(dk_recv) = result {
            assert_ne!(_dk_send, dk_recv, "tampered KEM produced matching datakey");
        }
    }

    #[test]
    fn unpack_truncated_rejected() {
        // Header claims 100 bytes but only 5 follow.
        let mut bad = vec![0, 100];
        bad.extend_from_slice(&[0u8; 5]);
        assert!(unpack_two(&bad).is_err());
    }
}

// Suppress unused-import warnings on builds that don't reach into
// the verifier types directly.
#[allow(dead_code)]
fn _unused_sigs() {
    let _ = SigningKey::from_bytes(&[0u8; 32]);
    let _ = VerifyingKey::from_bytes(&[0u8; 32]);
    let _ = MlDsa65Provider;
    let _: fn(&[u8], &[u8]) -> Result<Vec<u8>, _> =
        |seed: &[u8], msg: &[u8]| MlDsa65Provider.sign(seed, msg, &[]);
    fn _siggy<S: Signer<ed25519_dalek::Signature>>(_s: &S) {}
    fn _verify<V: Verifier<ed25519_dalek::Signature>>(_v: &V) {}
}
