//! Ed25519 sign / verify.
//!
//! `ed25519-dalek` 2.x is the RustCrypto implementation; already in
//! the transitive tree via `ssh-key` and now promoted to a direct
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
    let seed: &[u8; ED25519_SEED_LEN] = seed
        .try_into()
        .map_err(|_| RvError::ErrString(format!("ed25519 seed must be {ED25519_SEED_LEN} bytes")))?;
    let sk = SigningKey::from_bytes(seed);
    let sig: Signature = sk.sign(message);
    Ok(sig.to_bytes().to_vec())
}

pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, RvError> {
    let pk: &[u8; ED25519_PUBLIC_KEY_LEN] = public_key.try_into().map_err(|_| {
        RvError::ErrString(format!("ed25519 public key must be {ED25519_PUBLIC_KEY_LEN} bytes"))
    })?;
    let vk = VerifyingKey::from_bytes(pk)
        .map_err(|e| RvError::ErrString(format!("invalid ed25519 public key: {e}")))?;
    let sig: &[u8; ED25519_SIGNATURE_LEN] = signature.try_into().map_err(|_| {
        RvError::ErrString(format!("ed25519 signature must be {ED25519_SIGNATURE_LEN} bytes"))
    })?;
    let sig = Signature::from_bytes(sig);
    Ok(vk.verify(message, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let (seed, pk) = generate_keypair();
        let msg = b"hello";
        let sig = sign(&seed, msg).unwrap();
        assert!(verify(&pk, msg, &sig).unwrap());
        assert!(!verify(&pk, b"world", &sig).unwrap());
    }
}
