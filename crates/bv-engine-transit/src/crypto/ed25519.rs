//! Ed25519 sign / verify.
//!
//! `ed25519-dalek` 3.x is the RustCrypto implementation; already in
//! the transitive tree via russh's `ssh-key` and promoted to a direct
//! dep in `Cargo.toml`. Sign / verify are constant-time per the
//! upstream contract.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngExt;

use crate::errors::RvError;

pub const ED25519_SEED_LEN: usize = 32;
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Generate a fresh Ed25519 keypair. Returns `(seed, public_key)`.
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut seed = [0u8; ED25519_SEED_LEN];
    rand::rng().fill(&mut seed[..]);
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();
    (seed.to_vec(), pk.to_vec())
}

pub fn sign(seed: &[u8], message: &[u8]) -> Result<Vec<u8>, RvError> {
    let seed: &[u8; ED25519_SEED_LEN] =
        seed.try_into().map_err(|_| RvError::ErrString(format!("ed25519 seed must be {ED25519_SEED_LEN} bytes")))?;
    let sk = SigningKey::from_bytes(seed);
    let sig: Signature = sk.sign(message);
    Ok(sig.to_bytes().to_vec())
}

pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, RvError> {
    let pk: &[u8; ED25519_PUBLIC_KEY_LEN] = public_key
        .try_into()
        .map_err(|_| RvError::ErrString(format!("ed25519 public key must be {ED25519_PUBLIC_KEY_LEN} bytes")))?;
    let vk =
        VerifyingKey::from_bytes(pk).map_err(|e| RvError::ErrString(format!("invalid ed25519 public key: {e}")))?;
    let sig: &[u8; ED25519_SIGNATURE_LEN] = signature
        .try_into()
        .map_err(|_| RvError::ErrString(format!("ed25519 signature must be {ED25519_SIGNATURE_LEN} bytes")))?;
    let sig = Signature::from_bytes(sig);
    Ok(vk.verify(message, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn round_trip() {
        let (seed, pk) = generate_keypair();
        let msg = b"hello";
        let sig = sign(&seed, msg).unwrap();
        assert!(verify(&pk, msg, &sig).unwrap());
        assert!(!verify(&pk, b"world", &sig).unwrap());
    }

    /// RFC 8032 §7.1 TEST 1 and TEST 2 through this module's wrappers.
    #[test]
    fn matches_rfc8032_vectors() {
        let t1 = from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let t1_pk = from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let t1_sig = sign(&t1, b"").unwrap();
        assert_eq!(
            to_hex(&t1_sig),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        assert!(verify(&t1_pk, b"", &t1_sig).unwrap());

        let t2 = from_hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let t2_pk = from_hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let t2_sig = sign(&t2, &[0x72]).unwrap();
        assert_eq!(
            to_hex(&t2_sig),
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        );
        assert!(verify(&t2_pk, &[0x72], &t2_sig).unwrap());
        // Malformed input: wrong lengths are errors, a flipped bit is a clean `false`.
        assert!(verify(&t2_pk[..31], &[0x72], &t2_sig).is_err());
        assert!(verify(&t2_pk, &[0x72], &t2_sig[..63]).is_err());
        let mut bad = t2_sig.clone();
        bad[0] ^= 0x01;
        assert!(!verify(&t2_pk, &[0x72], &bad).unwrap());
    }
}
