//! HKDF-based per-context subkey derivation for `derived` keys, plus
//! the deterministic-nonce computation for `convergent_encryption`.
//!
//! Two separate derivations live here so the path handlers cannot
//! accidentally share an HMAC key between subkey derivation and nonce
//! derivation:
//!
//!   * `subkey(parent, context)` — HKDF-SHA-256, salt empty,
//!     info `"bvault-transit-derive\0" || context`. Returns 32 bytes
//!     (suitable for ChaCha20-Poly1305).
//!   * `convergent_nonce(parent, context, plaintext)` — HMAC-SHA-256
//!     keyed on `parent || "bvault-transit-conv-nonce"`, message
//!     `len(context) || context || plaintext`. Truncated to 12 bytes
//!     (the ChaCha20-Poly1305 nonce length). The keying domain
//!     separator is what stops a caller who can submit chosen
//!     plaintext from steering an HMAC over `parent` directly.

use hkdf::Hkdf;
use hmac::{digest::KeyInit, Mac};
use sha2::Sha256;

use crate::errors::RvError;

const SUBKEY_DOMAIN: &[u8] = b"bvault-transit-derive\0";
const NONCE_KEY_DOMAIN: &[u8] = b"bvault-transit-conv-nonce";
pub const SUBKEY_LEN: usize = 32;
pub const CHACHA_NONCE_LEN: usize = 12;

/// HKDF a per-context subkey from the parent key. Empty `context`
/// is rejected — the whole point of `derived` mode is that the
/// caller commits to a separation domain on every operation.
pub fn subkey(parent: &[u8], context: &[u8]) -> Result<Vec<u8>, RvError> {
    if context.is_empty() {
        return Err(RvError::ErrString(
            "derived keys require a non-empty `context` on every encrypt / decrypt".into(),
        ));
    }
    let hk = Hkdf::<Sha256>::new(None, parent);
    let mut info = Vec::with_capacity(SUBKEY_DOMAIN.len() + context.len());
    info.extend_from_slice(SUBKEY_DOMAIN);
    info.extend_from_slice(context);
    let mut out = vec![0u8; SUBKEY_LEN];
    hk.expand(&info, &mut out)
        .map_err(|e| RvError::ErrString(format!("hkdf expand: {e}")))?;
    Ok(out)
}

/// Deterministic 12-byte AEAD nonce for convergent mode.
pub fn convergent_nonce(parent: &[u8], context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, RvError> {
    if context.is_empty() {
        return Err(RvError::ErrString(
            "convergent encryption requires a non-empty `context`".into(),
        ));
    }
    // Bind the HMAC key to a domain that no other Transit primitive
    // uses, so a caller who finds an HMAC oracle on this key cannot
    // recover the plain HMAC of arbitrary data under `parent`.
    let mut domain_keyed = Vec::with_capacity(parent.len() + NONCE_KEY_DOMAIN.len());
    domain_keyed.extend_from_slice(parent);
    domain_keyed.extend_from_slice(NONCE_KEY_DOMAIN);
    let mut mac = <hmac::Hmac<Sha256> as KeyInit>::new_from_slice(&domain_keyed)
        .expect("hmac accepts any key length");

    // Length-prefix `context` to make the HMAC injection-safe: an
    // attacker who controls part of `plaintext` can't shift the
    // boundary by padding `context` into `plaintext`.
    let ctx_len = (context.len() as u64).to_be_bytes();
    mac.update(&ctx_len);
    mac.update(context);
    mac.update(plaintext);

    let tag = mac.finalize().into_bytes();
    Ok(tag[..CHACHA_NONCE_LEN].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subkey_is_deterministic_per_context() {
        let parent = vec![1u8; 32];
        let a1 = subkey(&parent, b"row-42").unwrap();
        let a2 = subkey(&parent, b"row-42").unwrap();
        let b = subkey(&parent, b"row-43").unwrap();
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
        assert_eq!(a1.len(), SUBKEY_LEN);
    }

    #[test]
    fn empty_context_rejected() {
        let parent = vec![1u8; 32];
        assert!(subkey(&parent, b"").is_err());
        assert!(convergent_nonce(&parent, b"", b"x").is_err());
    }

    #[test]
    fn convergent_nonce_is_deterministic_and_separates() {
        let parent = vec![7u8; 32];
        let n1 = convergent_nonce(&parent, b"ctx", b"hello").unwrap();
        let n2 = convergent_nonce(&parent, b"ctx", b"hello").unwrap();
        let n3 = convergent_nonce(&parent, b"ctx", b"world").unwrap();
        let n4 = convergent_nonce(&parent, b"other", b"hello").unwrap();
        assert_eq!(n1, n2);
        assert_ne!(n1, n3);
        assert_ne!(n1, n4);
        assert_eq!(n1.len(), CHACHA_NONCE_LEN);
    }
}
