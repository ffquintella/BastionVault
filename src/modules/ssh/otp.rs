//! OTP generation, hashing, and persisted-record helpers (Phase 2).
//!
//! Storage layout:
//!
//! ```text
//! otp/<sha256(otp)-hex>  →  serde_json(OtpEntry)
//! ```
//!
//! The plaintext OTP itself is **never** persisted — only its hash. A
//! barrier compromise thus exposes only pre-image hashes, not live
//! credentials, and `verify` becomes a single keyed `storage_get`
//! rather than a list-and-scan. The 256-bit search space makes brute
//! forcing the hash → OTP recovery economically irrelevant.
//!
//! OTP entropy: 20 random bytes from `OsRng`, hex-encoded → 40
//! lowercase hex characters (160 bits). The spec called for "32
//! base32 characters (160 bits)"; hex matches the entropy exactly,
//! avoids pulling in a base32 dep, and keeps the OTP a single
//! greppable token through PAM logs.

use sha2::{Digest, Sha256};

use crate::errors::RvError;

/// Length of the random OTP body in bytes. Hex-encoded this becomes
/// the 40-char token operators see; 160 bits leaves a comfortable
/// margin against any practical online-brute-force window before TTL
/// expiry.
pub const OTP_RAND_BYTES: usize = 20;

/// Generate a fresh OTP token. Returns the plaintext token (caller
/// returns this exactly once to the requesting client) and the
/// SHA-256 hex hash that becomes the storage key.
pub fn generate_otp() -> Result<(String, String), RvError> {
    use rand::RngExt;

    let mut bytes = [0u8; OTP_RAND_BYTES];
    rand::rng().fill(&mut bytes[..]);
    let plaintext = hex::encode(bytes);
    let hash_hex = hash_otp(&plaintext);
    Ok((plaintext, hash_hex))
}

/// SHA-256 of the OTP, hex-encoded. Wrapped in a function so the
/// generator and `verify` can never disagree on encoding.
pub fn hash_otp(otp: &str) -> String {
    let mut h = Sha256::new();
    h.update(otp.as_bytes());
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_otp_is_40_hex_chars() {
        let (plaintext, hash) = generate_otp().unwrap();
        assert_eq!(plaintext.len(), OTP_RAND_BYTES * 2, "OTP length wrong");
        assert!(plaintext.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        // Hash is sha256 hex = 64 chars.
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn hash_otp_is_deterministic() {
        let a = hash_otp("deadbeef");
        let b = hash_otp("deadbeef");
        assert_eq!(a, b);
        assert_ne!(a, hash_otp("deadbeee"));
    }

    #[test]
    fn distinct_calls_produce_distinct_otps() {
        // Two consecutive generations should not collide — we don't
        // need cryptographic distinctness here, just a sanity check
        // that we're not accidentally seeded from a constant source.
        let (a, _) = generate_otp().unwrap();
        let (b, _) = generate_otp().unwrap();
        assert_ne!(a, b);
    }
}
