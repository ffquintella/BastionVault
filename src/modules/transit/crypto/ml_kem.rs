//! ML-KEM-768 datakey wrapping.
//!
//! Built on `bv_crypto::MlKem768Provider` (which wraps the `ml-kem`
//! crate). The Transit `datakey` semantic for a KEM key:
//!
//! 1. Engine encapsulates to the parent's encapsulation key.
//! 2. The shared secret is fed through HKDF-SHA-256 with info
//!    `"bvault-transit-datakey"` to derive a 256-bit AES-style key.
//! 3. Engine returns:
//!      * `plaintext` — the derived 256-bit key (only on the
//!        `/datakey/plaintext/...` path).
//!      * `wrapped`   — base64 of `kem_ciphertext` (the recipient
//!        decapsulates with their decapsulation key to recover the
//!        same shared secret + HKDF derivation).
//!
//! The framer surrounds `wrapped` with `bvault:vN:pqc:ml-kem-768:...`.

use bv_crypto::{KemProvider, MlKem768Provider};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::errors::RvError;

pub const HKDF_INFO: &[u8] = b"bvault-transit-datakey";
pub const DERIVED_DATAKEY_LEN: usize = 32;

/// Generate a fresh ML-KEM-768 keypair. Returns `(secret_key_bytes, public_key_bytes)`.
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), RvError> {
    let provider = MlKem768Provider;
    let kp = provider
        .generate_keypair()
        .map_err(|e| RvError::ErrString(format!("ml-kem-768 keygen: {e:?}")))?;
    Ok((kp.secret_key().to_vec(), kp.public_key().to_vec()))
}

/// Encapsulate to the public key, derive a 256-bit datakey, return
/// `(datakey_plaintext, kem_ciphertext)`.
pub fn encapsulate_datakey(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), RvError> {
    let provider = MlKem768Provider;
    let (kem_ct, ss) = provider
        .encapsulate(public_key)
        .map_err(|e| RvError::ErrString(format!("ml-kem-768 encapsulate: {e:?}")))?;
    let dk = derive_datakey(ss.as_bytes())?;
    Ok((dk, kem_ct.as_bytes().to_vec()))
}

/// Inverse of `encapsulate_datakey`. Decapsulate with the secret key,
/// re-derive the same 256-bit datakey via HKDF.
pub fn decapsulate_datakey(secret_key: &[u8], kem_ct: &[u8]) -> Result<Vec<u8>, RvError> {
    let provider = MlKem768Provider;
    let ss = provider
        .decapsulate(secret_key, kem_ct)
        .map_err(|e| RvError::ErrString(format!("ml-kem-768 decapsulate: {e:?}")))?;
    derive_datakey(ss.as_bytes())
}

fn derive_datakey(ss: &[u8]) -> Result<Vec<u8>, RvError> {
    let hk = Hkdf::<Sha256>::new(None, ss);
    let mut out = vec![0u8; DERIVED_DATAKEY_LEN];
    hk.expand(HKDF_INFO, &mut out)
        .map_err(|e| RvError::ErrString(format!("hkdf expand: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datakey_round_trip() {
        let (sk, pk) = generate_keypair().unwrap();
        let (dk1, kem_ct) = encapsulate_datakey(&pk).unwrap();
        let dk2 = decapsulate_datakey(&sk, &kem_ct).unwrap();
        assert_eq!(dk1, dk2, "decapsulated datakey must match encapsulated one");
        assert_eq!(dk1.len(), DERIVED_DATAKEY_LEN);
    }
}
