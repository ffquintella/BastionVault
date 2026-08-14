//! Symmetric AEAD operations on top of `bv_crypto::aead`.
//!
//! Phase 1 ships ChaCha20-Poly1305 (the project-wide default). The
//! function shape leaves room for AES-GCM and XChaCha20-Poly1305
//! later — adding them is a `match self.key_type { ... }` per
//! algorithm in this file.

use bv_crypto::{AeadCipher, Chacha20Poly1305Cipher, Nonce, SymmetricKey};
use rand::RngExt;

use super::super::keytype::KeyType;
use crate::errors::RvError;

/// Length of a ChaCha20-Poly1305 key. Encoded into `KeyVersion.material`.
pub const CHACHA_KEY_LEN: usize = 32;
/// Length of a ChaCha20-Poly1305 nonce.
pub const CHACHA_NONCE_LEN: usize = 12;

pub fn generate_aead_key(kt: KeyType) -> Result<Vec<u8>, RvError> {
    match kt {
        KeyType::Chacha20Poly1305 => {
            let mut bytes = vec![0u8; CHACHA_KEY_LEN];
            rand::rng().fill(&mut bytes[..]);
            Ok(bytes)
        }
        other => Err(RvError::ErrString(format!(
            "{} is not a symmetric AEAD key type",
            other.as_str()
        ))),
    }
}

/// Encrypt under a symmetric AEAD key. Returns `nonce || ciphertext_with_tag`
/// (the `Vec<u8>` the framer base64-encodes into the wire format).
pub fn aead_encrypt(
    kt: KeyType,
    key_bytes: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, RvError> {
    match kt {
        KeyType::Chacha20Poly1305 => {
            if key_bytes.len() != CHACHA_KEY_LEN {
                return Err(RvError::ErrString(format!(
                    "chacha20-poly1305 key must be {CHACHA_KEY_LEN} bytes, got {}",
                    key_bytes.len()
                )));
            }
            let key = SymmetricKey::try_from_slice(key_bytes)
                .map_err(|e| RvError::ErrString(format!("symmetric key: {e:?}")))?;
            let mut nonce_bytes = [0u8; CHACHA_NONCE_LEN];
            rand::rng().fill(&mut nonce_bytes[..]);
            let nonce = Nonce::try_from_slice(&nonce_bytes)
                .map_err(|e| RvError::ErrString(format!("nonce: {e:?}")))?;
            let cipher = Chacha20Poly1305Cipher;
            let ct = cipher
                .encrypt(&key, &nonce, aad, plaintext)
                .map_err(|e| RvError::ErrString(format!("aead encrypt: {e:?}")))?;
            let mut out = Vec::with_capacity(CHACHA_NONCE_LEN + ct.len());
            out.extend_from_slice(&nonce_bytes);
            out.extend_from_slice(&ct);
            Ok(out)
        }
        other => Err(RvError::ErrString(format!(
            "{} is not a symmetric AEAD key type",
            other.as_str()
        ))),
    }
}

/// Encrypt with a caller-supplied (deterministic) nonce. Used by
/// convergent mode — the nonce is derived from the plaintext so the
/// engine cannot generate a fresh random one. The serialised wire
/// shape is identical to `aead_encrypt` (`nonce || ct || tag`) so
/// the decrypt path doesn't need to branch on convergent vs. random.
pub fn aead_encrypt_with_nonce(
    kt: KeyType,
    key_bytes: &[u8],
    nonce_bytes: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, RvError> {
    match kt {
        KeyType::Chacha20Poly1305 => {
            if key_bytes.len() != CHACHA_KEY_LEN {
                return Err(RvError::ErrString(format!(
                    "chacha20-poly1305 key must be {CHACHA_KEY_LEN} bytes, got {}",
                    key_bytes.len()
                )));
            }
            if nonce_bytes.len() != CHACHA_NONCE_LEN {
                return Err(RvError::ErrString(format!(
                    "chacha20-poly1305 nonce must be {CHACHA_NONCE_LEN} bytes, got {}",
                    nonce_bytes.len()
                )));
            }
            let key = SymmetricKey::try_from_slice(key_bytes)
                .map_err(|e| RvError::ErrString(format!("symmetric key: {e:?}")))?;
            let nonce = Nonce::try_from_slice(nonce_bytes)
                .map_err(|e| RvError::ErrString(format!("nonce: {e:?}")))?;
            let cipher = Chacha20Poly1305Cipher;
            let ct = cipher
                .encrypt(&key, &nonce, aad, plaintext)
                .map_err(|e| RvError::ErrString(format!("aead encrypt: {e:?}")))?;
            let mut out = Vec::with_capacity(CHACHA_NONCE_LEN + ct.len());
            out.extend_from_slice(nonce_bytes);
            out.extend_from_slice(&ct);
            Ok(out)
        }
        other => Err(RvError::ErrString(format!(
            "{} is not a symmetric AEAD key type",
            other.as_str()
        ))),
    }
}

/// Inverse of `aead_encrypt`. Expects `nonce || ciphertext_with_tag`.
pub fn aead_decrypt(
    kt: KeyType,
    key_bytes: &[u8],
    blob: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, RvError> {
    match kt {
        KeyType::Chacha20Poly1305 => {
            if blob.len() < CHACHA_NONCE_LEN + 16 {
                return Err(RvError::ErrString(
                    "aead ciphertext too short to contain nonce + tag".into(),
                ));
            }
            let (nonce_bytes, ct) = blob.split_at(CHACHA_NONCE_LEN);
            let key = SymmetricKey::try_from_slice(key_bytes)
                .map_err(|e| RvError::ErrString(format!("symmetric key: {e:?}")))?;
            let nonce = Nonce::try_from_slice(nonce_bytes)
                .map_err(|e| RvError::ErrString(format!("nonce: {e:?}")))?;
            let cipher = Chacha20Poly1305Cipher;
            cipher
                .decrypt(&key, &nonce, aad, ct)
                .map_err(|e| RvError::ErrString(format!("aead decrypt: {e:?}")))
        }
        other => Err(RvError::ErrString(format!(
            "{} is not a symmetric AEAD key type",
            other.as_str()
        ))),
    }
}

/// Generate raw HMAC key bytes (32 bytes — wide enough for SHA-512).
pub fn generate_hmac_key() -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    rand::rng().fill(&mut bytes[..]);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_round_trip() {
        let key = generate_aead_key(KeyType::Chacha20Poly1305).unwrap();
        let pt = b"hello world";
        let ct = aead_encrypt(KeyType::Chacha20Poly1305, &key, pt, b"aad").unwrap();
        let back = aead_decrypt(KeyType::Chacha20Poly1305, &key, &ct, b"aad").unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn aead_aad_mismatch_fails() {
        let key = generate_aead_key(KeyType::Chacha20Poly1305).unwrap();
        let pt = b"x";
        let ct = aead_encrypt(KeyType::Chacha20Poly1305, &key, pt, b"a").unwrap();
        assert!(aead_decrypt(KeyType::Chacha20Poly1305, &key, &ct, b"b").is_err());
    }

    #[test]
    fn aead_tampered_tag_fails() {
        let key = generate_aead_key(KeyType::Chacha20Poly1305).unwrap();
        let mut ct = aead_encrypt(KeyType::Chacha20Poly1305, &key, b"x", b"").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(aead_decrypt(KeyType::Chacha20Poly1305, &key, &ct, b"").is_err());
    }
}
