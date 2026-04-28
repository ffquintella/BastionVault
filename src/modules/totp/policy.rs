//! Persisted TOTP key policy.
//!
//! One `KeyPolicy` per `totp/key/<name>` storage entry. The barrier
//! provides at-rest encryption (ChaCha20-Poly1305) so the seed bytes
//! never land on disk in plaintext. Plaintext seeds are returned to
//! the caller exactly once, in the create-call response, when
//! `exported = true` (generate mode only).

use serde::{Deserialize, Serialize};

pub const KEY_PREFIX: &str = "key/";
pub const USED_PREFIX: &str = "used/";

pub const DEFAULT_PERIOD: u64 = 30;
pub const DEFAULT_DIGITS: u32 = 6;
pub const DEFAULT_SKEW: u32 = 1;
pub const DEFAULT_KEY_SIZE: usize = 20;
pub const DEFAULT_QR_SIZE: u32 = 200;

/// Hash algorithm for the inner HMAC. Matches the `algorithm`
/// parameter on the `otpauth://` URL — Google Authenticator and most
/// consumer apps support only `SHA1`. SHA-256 / SHA-512 are exposed
/// for callers (e.g. YubiKey OATH) that handle them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    #[serde(rename = "SHA1", alias = "sha1")]
    Sha1,
    #[serde(rename = "SHA256", alias = "sha256")]
    Sha256,
    #[serde(rename = "SHA512", alias = "sha512")]
    Sha512,
}

impl Algorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_uppercase().as_str() {
            "SHA1" | "" => Ok(Algorithm::Sha1),
            "SHA256" => Ok(Algorithm::Sha256),
            "SHA512" => Ok(Algorithm::Sha512),
            other => Err(format!(
                "unsupported algorithm `{other}`; expected one of SHA1, SHA256, SHA512"
            )),
        }
    }
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::Sha1
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPolicy {
    /// True when the engine generated the seed. False = imported
    /// (provider mode). Stored so the code endpoints can route to
    /// the correct semantic (`GET` vs `POST` on `/code/:name`).
    pub generate: bool,

    /// Raw HMAC key bytes. Stored as a Vec for serde compatibility;
    /// barrier-encrypted at rest. The base32 form is derived on
    /// demand (and only ever returned in the create response when
    /// `exported = true`).
    pub key: Vec<u8>,

    /// `Issuer` portion of the `otpauth://` URL.
    #[serde(default)]
    pub issuer: String,

    /// `AccountName` portion of the `otpauth://` URL.
    #[serde(default)]
    pub account_name: String,

    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
    pub skew: u32,

    /// Replay-check toggle. Default `true`. Operators who need exact
    /// HashiCorp Vault parity (no replay dedupe) flip this off at
    /// key-create time.
    #[serde(default = "default_true")]
    pub replay_check: bool,

    /// Whether the seed has already been disclosed in a create
    /// response. Generate-mode keys flip this to `false` after the
    /// first read so the seed is never re-exposed; provider-mode
    /// keys are never exported.
    #[serde(default)]
    pub exported: bool,
}

fn default_true() -> bool {
    true
}

impl KeyPolicy {
    /// Validate field shape independent of mode. Mode-specific
    /// validation (`key` required in provider mode, refused in
    /// generate mode) lives in the path handler.
    pub fn validate(&self) -> Result<(), String> {
        if !(self.digits == 6 || self.digits == 8) {
            return Err(format!(
                "digits must be 6 or 8, got {}",
                self.digits
            ));
        }
        if self.period == 0 {
            return Err("period must be > 0".to_string());
        }
        if self.skew > 10 {
            return Err(format!(
                "skew must be <= 10 (got {}); larger windows defeat the point of TOTP",
                self.skew
            ));
        }
        if self.key.is_empty() {
            return Err("key is empty".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_parse_is_case_insensitive() {
        assert_eq!(Algorithm::parse("sha1").unwrap(), Algorithm::Sha1);
        assert_eq!(Algorithm::parse("SHA256").unwrap(), Algorithm::Sha256);
        assert_eq!(Algorithm::parse("Sha512").unwrap(), Algorithm::Sha512);
        assert_eq!(Algorithm::parse("").unwrap(), Algorithm::Sha1);
        assert!(Algorithm::parse("md5").is_err());
    }

    #[test]
    fn validate_rejects_bad_digits() {
        let p = KeyPolicy {
            generate: true,
            key: vec![1; 20],
            issuer: "i".into(),
            account_name: "a".into(),
            algorithm: Algorithm::Sha1,
            digits: 7,
            period: 30,
            skew: 1,
            replay_check: true,
            exported: false,
        };
        assert!(p.validate().is_err());
    }
}
