//! `.bvx` password-encrypted envelope.
//!
//! The envelope is itself a small JSON document so it's self-describing
//! and inspectable before decryption. Layout:
//!
//! ```json
//! {
//!   "magic": "BVX",
//!   "version": 1,
//!   "kdf": { "alg": "argon2id", "version": 19, "m_cost_kib": 65536,
//!            "t_cost": 3, "p_cost": 1, "salt_b64": "..." },
//!   "aead": { "alg": "xchacha20-poly1305", "nonce_b64": "..." },
//!   "ciphertext_b64": "...",
//!   "created_at": "2026-04-25T18:00:00Z",
//!   "vault_fingerprint_b64": "...",
//!   "comment": "..."
//! }
//! ```
//!
//! Tampering with the envelope outer fields makes the AEAD decryption fail
//! closed (the recomputed key under a swapped salt produces a different
//! key, the AEAD tag check rejects the ciphertext). The envelope's outer
//! JSON itself is not authenticated by the password — that's intentional;
//! the only thing the recipient learns from a tampered envelope is "this
//! file does not decrypt with my password."

use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::RvError;
use crate::exchange::kdf::{derive_key, KdfParams, DERIVED_KEY_LEN};

pub const ENVELOPE_MAGIC: &str = "BVX";
pub const ENVELOPE_VERSION: u32 = 1;
pub const AEAD_ALG_XCHACHA: &str = "xchacha20-poly1305";
pub const XCHACHA_NONCE_LEN: usize = 24;

/// Minimum password length the envelope encoder accepts. Operators can
/// raise this floor per-mount via config.
pub const MIN_PASSWORD_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("password too short: minimum is {min} characters")]
    PasswordTooShort { min: usize },
    #[error("envelope decryption failed (wrong password or tampered file)")]
    DecryptionFailed,
    #[error("envelope is malformed: {0}")]
    Malformed(&'static str),
    #[error("envelope version {got} is not supported (host supports {supported})")]
    UnsupportedVersion { got: u32, supported: u32 },
    #[error("envelope KDF or AEAD parameters out of bounds")]
    BadParameters,
}

impl From<EnvelopeError> for RvError {
    fn from(e: EnvelopeError) -> Self {
        match e {
            EnvelopeError::PasswordTooShort { .. }
            | EnvelopeError::DecryptionFailed
            | EnvelopeError::Malformed(_)
            | EnvelopeError::UnsupportedVersion { .. }
            | EnvelopeError::BadParameters => {
                log::warn!("exchange envelope error: {e}");
                RvError::ErrRequestInvalid
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub magic: String,
    pub version: u32,
    pub kdf: KdfParams,
    pub aead: AeadParams,
    pub ciphertext_b64: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vault_fingerprint_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AeadParams {
    pub alg: String,
    pub nonce_b64: String,
}

/// RAII wrapper that zeroizes the derived key on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct DerivedKey([u8; DERIVED_KEY_LEN]);

/// Encrypt `plaintext` with `password`, producing a serialised `.bvx` JSON
/// document (UTF-8 bytes, ready to write to disk or stream over HTTP).
///
/// `vault_fingerprint_b64` is a non-secret hash of the vault's identity
/// (e.g. BLAKE2b-256 over a public root). Pass an empty string when you
/// don't have one — a future GUI can still warn on cross-vault import
/// based on other heuristics.
pub fn encrypt_bvx(
    plaintext: &[u8],
    password: &str,
    vault_fingerprint_b64: &str,
    comment: Option<String>,
) -> Result<Vec<u8>, RvError> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(EnvelopeError::PasswordTooShort { min: MIN_PASSWORD_LEN }.into());
    }

    let kdf_params = KdfParams::fresh_default();
    let derived = DerivedKey(derive_key(password, &kdf_params)?);

    let mut nonce_bytes = [0u8; XCHACHA_NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);

    let cipher = XChaCha20Poly1305::new_from_slice(&derived.0)
        .map_err(|_| RvError::ErrRequestInvalid)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload { msg: plaintext, aad: ENVELOPE_MAGIC.as_bytes() },
        )
        .map_err(|_| RvError::ErrRequestInvalid)?;

    let envelope = Envelope {
        magic: ENVELOPE_MAGIC.to_string(),
        version: ENVELOPE_VERSION,
        kdf: kdf_params,
        aead: AeadParams {
            alg: AEAD_ALG_XCHACHA.to_string(),
            nonce_b64: base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
        },
        ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(&ciphertext),
        created_at: chrono::Utc::now().to_rfc3339(),
        vault_fingerprint_b64: vault_fingerprint_b64.to_string(),
        comment,
    };

    // Pretty-print so the envelope is human-inspectable; the canonical
    // requirement only applies to the *inner* document.
    let json = serde_json::to_vec_pretty(&envelope)?;
    Ok(json)
}

/// Decrypt a `.bvx` envelope, returning the inner plaintext bytes (the
/// canonical bvx.v1 JSON document).
pub fn decrypt_bvx(envelope_bytes: &[u8], password: &str) -> Result<Vec<u8>, RvError> {
    let envelope: Envelope = serde_json::from_slice(envelope_bytes)
        .map_err(|_| EnvelopeError::Malformed("not a bvx envelope"))?;

    if envelope.magic != ENVELOPE_MAGIC {
        return Err(EnvelopeError::Malformed("magic mismatch").into());
    }
    if envelope.version != ENVELOPE_VERSION {
        return Err(EnvelopeError::UnsupportedVersion {
            got: envelope.version,
            supported: ENVELOPE_VERSION,
        }
        .into());
    }
    if envelope.aead.alg != AEAD_ALG_XCHACHA {
        return Err(EnvelopeError::Malformed("unsupported aead algorithm").into());
    }

    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(envelope.aead.nonce_b64.as_bytes())
        .map_err(|_| EnvelopeError::Malformed("nonce not base64"))?;
    if nonce_bytes.len() != XCHACHA_NONCE_LEN {
        return Err(EnvelopeError::Malformed("nonce wrong length").into());
    }
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(envelope.ciphertext_b64.as_bytes())
        .map_err(|_| EnvelopeError::Malformed("ciphertext not base64"))?;

    let derived = DerivedKey(derive_key(password, &envelope.kdf)?);
    let cipher = XChaCha20Poly1305::new_from_slice(&derived.0)
        .map_err(|_| RvError::ErrRequestInvalid)?;

    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload { msg: &ciphertext, aad: ENVELOPE_MAGIC.as_bytes() },
        )
        .map_err(|_| EnvelopeError::DecryptionFailed)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_password() -> &'static str {
        "correct-horse-battery-staple"
    }

    #[test]
    fn round_trip_known_password() {
        let plaintext = br#"{"hello":"world"}"#;
        let bytes = encrypt_bvx(plaintext, test_password(), "", None).unwrap();
        let decrypted = decrypt_bvx(&bytes, test_password()).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_password_fails_closed() {
        let plaintext = b"{}";
        let bytes = encrypt_bvx(plaintext, test_password(), "", None).unwrap();
        let err = decrypt_bvx(&bytes, "wrong-password-also-long").unwrap_err();
        // The exact RvError variant is ErrRequestInvalid (we squash to
        // avoid a distinguishing oracle); just confirm it's an error.
        assert!(matches!(err, RvError::ErrRequestInvalid));
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let plaintext = b"{}";
        let bytes = encrypt_bvx(plaintext, test_password(), "", None).unwrap();
        let mut env: Envelope = serde_json::from_slice(&bytes).unwrap();
        // Flip one bit in the ciphertext.
        let mut ct = base64::engine::general_purpose::STANDARD
            .decode(env.ciphertext_b64.as_bytes())
            .unwrap();
        ct[0] ^= 0x01;
        env.ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(&ct);
        let tampered = serde_json::to_vec(&env).unwrap();
        assert!(decrypt_bvx(&tampered, test_password()).is_err());
    }

    #[test]
    fn tampered_salt_fails_closed() {
        let plaintext = b"{}";
        let bytes = encrypt_bvx(plaintext, test_password(), "", None).unwrap();
        let mut env: Envelope = serde_json::from_slice(&bytes).unwrap();
        // Different salt -> different derived key -> AEAD tag check fails.
        let mut salt = base64::engine::general_purpose::STANDARD
            .decode(env.kdf.salt_b64.as_bytes())
            .unwrap();
        salt[0] ^= 0x01;
        env.kdf.salt_b64 = base64::engine::general_purpose::STANDARD.encode(&salt);
        let tampered = serde_json::to_vec(&env).unwrap();
        assert!(decrypt_bvx(&tampered, test_password()).is_err());
    }

    #[test]
    fn refuses_short_password() {
        let plaintext = b"{}";
        assert!(encrypt_bvx(plaintext, "short", "", None).is_err());
    }

    #[test]
    fn fingerprint_and_comment_round_trip() {
        let plaintext = b"{}";
        let bytes = encrypt_bvx(
            plaintext,
            test_password(),
            "fingerprint-abc",
            Some("nightly export".to_string()),
        )
        .unwrap();
        let env: Envelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(env.vault_fingerprint_b64, "fingerprint-abc");
        assert_eq!(env.comment.as_deref(), Some("nightly export"));
    }
}
