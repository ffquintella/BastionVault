//! WebAuthn challenges.
//!
//! A challenge is 32 random bytes. We carry both the raw bytes and their
//! base64url-no-pad encoding so we can JSON-serialize the registration
//! state cheaply and compare against the encoded form returned by the
//! browser inside `clientDataJSON.challenge` without re-encoding.

use rand::Rng;
use serde::{Deserialize, Serialize};

use super::b64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// base64url-no-pad encoding of the 32 random bytes.
    pub b64: String,
}

impl Challenge {
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        Self { b64: b64::encode(&bytes) }
    }

    /// Construct from a fixed byte slice. Test-only entry point.
    #[cfg(test)]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self { b64: b64::encode(bytes) }
    }
}
