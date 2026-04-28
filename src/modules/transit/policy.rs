//! Persisted key policy + version material.
//!
//! Storage layout under the engine's per-mount UUID-scoped barrier prefix:
//!
//! ```text
//! transit/policy/<name>  →  JSON(KeyPolicy)
//! ```
//!
//! Every `KeyVersion` carries the raw key bytes (or seed for ML-DSA);
//! the barrier (ChaCha20-Poly1305) wraps the JSON before it ever
//! touches physical storage. Plaintext key material never persists.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::keytype::KeyType;

pub const POLICY_PREFIX: &str = "policy/";

/// One version of a key. The shape of `material` depends on `key_type`:
///
/// | Key type        | `material` contents                              |
/// |-----------------|--------------------------------------------------|
/// | symmetric AEAD  | 32 raw key bytes                                 |
/// | hmac            | 32 raw key bytes                                 |
/// | ed25519         | 32-byte seed                                     |
/// | ml-kem-768      | encapsulation key bytes  (`pk` field separate)   |
/// | ml-dsa-44/65/87 | 32-byte seed                                     |
///
/// `pk` is the public-key material for asymmetric types — kept
/// separate from `material` so `GET /keys/:name` can return it
/// without ever loading the secret half through the same code path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyVersion {
    /// Sequence number; the latest is what `encrypt` / `sign` use.
    pub version: u32,
    /// Unix-seconds creation time.
    pub created_at: u64,
    /// Secret material. For ML-KEM / ML-DSA this is a seed or the
    /// secret-key bytes; for symmetric AEAD it's the raw 32-byte key.
    pub material: Vec<u8>,
    /// Public material for asymmetric types. Empty for symmetric.
    #[serde(default)]
    pub pk: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPolicy {
    pub name: String,
    pub key_type: KeyType,
    /// Highest version number minted; `latest_version >= 1` always.
    pub latest_version: u32,
    /// Minimum version accepted on decrypt / verify. Lets operators
    /// retire suspect versions without losing the ability to decrypt
    /// newer payloads.
    #[serde(default = "one")]
    pub min_decryption_version: u32,
    /// Minimum version kept in the policy. `trim` drops anything
    /// below this.
    #[serde(default = "one")]
    pub min_available_version: u32,
    /// Operator must explicitly opt in to deletion. Once a key has
    /// been used, deleting it strands every ciphertext / signature
    /// produced under it; default-closed protects against accidents.
    #[serde(default)]
    pub deletion_allowed: bool,
    /// True if `GET /keys/:name/export/...` is allowed for this key.
    /// **Sticky once-false** — the engine refuses to flip back to
    /// true after creation.
    #[serde(default)]
    pub exportable: bool,
    /// Versions, keyed by version number for O(log n) lookup on
    /// decrypt / verify. BTreeMap preserves order on serialise so
    /// the on-disk shape is stable across reads.
    pub versions: BTreeMap<u32, KeyVersion>,

    // ── Phase 4: derived + convergent ─────────────────────────────
    //
    /// `derived = true` — every encrypt / decrypt request must carry
    /// a `context`; the engine derives a per-context subkey via
    /// HKDF-SHA-256(parent_key, info=context). Lets one logical key
    /// drive many cryptographic separation domains (per-row, per-
    /// tenant) without operators allocating one Transit key each.
    /// Symmetric-AEAD keys only.
    #[serde(default)]
    pub derived: bool,
    /// `convergent_encryption = true` (requires `derived`) — the AEAD
    /// nonce is derived deterministically from
    /// `HMAC-SHA-256(parent_key, plaintext || context)[..12]` so the
    /// same `(key, context, plaintext)` produces byte-identical
    /// ciphertext. Useful for de-duplication and equality search
    /// over encrypted columns. Symmetric-AEAD only; PQC keys do not
    /// support convergent mode (ML-KEM is randomised by FIPS spec).
    #[serde(default)]
    pub convergent_encryption: bool,
}

fn one() -> u32 {
    1
}

impl KeyPolicy {
    pub fn new(name: String, key_type: KeyType, first: KeyVersion) -> Self {
        let mut versions = BTreeMap::new();
        let v = first.version;
        versions.insert(v, first);
        Self {
            name,
            key_type,
            latest_version: v,
            min_decryption_version: 1,
            min_available_version: 1,
            deletion_allowed: false,
            exportable: false,
            versions,
            derived: false,
            convergent_encryption: false,
        }
    }

    pub fn latest(&self) -> Option<&KeyVersion> {
        self.versions.get(&self.latest_version)
    }

    /// Returns the version usable for decrypt at the given version
    /// number, or an error if the requested version is below
    /// `min_decryption_version` or absent.
    pub fn version_for_decrypt(&self, v: u32) -> Result<&KeyVersion, String> {
        if v < self.min_decryption_version {
            return Err(format!(
                "version {v} is below min_decryption_version {}",
                self.min_decryption_version
            ));
        }
        self.versions
            .get(&v)
            .ok_or_else(|| format!("version {v} not found on key `{}`", self.name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(material: Vec<u8>) -> KeyVersion {
        KeyVersion {
            version: 1,
            created_at: 0,
            material,
            pk: Vec::new(),
        }
    }

    #[test]
    fn version_for_decrypt_respects_min() {
        let mut p = KeyPolicy::new("k".into(), KeyType::Chacha20Poly1305, sample(vec![0; 32]));
        p.versions.insert(
            2,
            KeyVersion {
                version: 2,
                created_at: 1,
                material: vec![0; 32],
                pk: Vec::new(),
            },
        );
        p.latest_version = 2;
        p.min_decryption_version = 2;
        assert!(p.version_for_decrypt(1).is_err());
        assert!(p.version_for_decrypt(2).is_ok());
        assert!(p.version_for_decrypt(3).is_err());
    }
}
