//! Tamper-evident hash chain across audit entries.
//!
//! Each entry carries a `prev_hash` field that is the SHA-256 of the
//! previous entry's serialized-line form. The chain is per-broker
//! (not per-device) — every device sees the same `prev_hash` for a
//! given entry, so chains from different devices can be cross-
//! verified even when one is truncated or lost.
//!
//! This is *tamper-evident*, not *tamper-proof*. An attacker with
//! storage access can recompute the entire chain after modifying
//! entries. Stronger guarantees require publishing the chain head
//! to an external witness — out of scope for Phase 1.

use sha2::{Digest, Sha256};

use super::entry::{serialize_line, AuditEntry};
use crate::errors::RvError;

/// Genesis hash: what `prev_hash` reads for the first entry in the
/// chain. A 32-byte zero SHA-256 digest, prefixed with `"sha256:"`
/// for symmetry with the live hash format.
pub fn genesis() -> String {
    format!("sha256:{}", "0".repeat(64))
}

/// SHA-256 of the entry's serialized form, prefixed with `"sha256:"`.
pub fn digest(entry: &AuditEntry) -> Result<String, RvError> {
    let line = serialize_line(entry)?;
    let mut hasher = Sha256::new();
    hasher.update(line.as_bytes());
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// Verify a contiguous sequence of entries. Returns the final
/// chain head on success, or the index of the first invalid link on
/// failure. `expected_first_prev` is what the first entry's
/// `prev_hash` must equal — usually `genesis()` for full-chain
/// verification.
pub fn verify(
    entries: &[AuditEntry],
    expected_first_prev: &str,
) -> Result<String, VerifyError> {
    let mut expected = expected_first_prev.to_string();
    for (i, e) in entries.iter().enumerate() {
        if e.prev_hash != expected {
            return Err(VerifyError::BrokenAt(i));
        }
        expected = digest(e).map_err(|_| VerifyError::SerializeFailed(i))?;
    }
    Ok(expected)
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The entry at this index did not reference the prior hash.
    BrokenAt(usize),
    /// Serialization of the entry at this index failed.
    SerializeFailed(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(prev: &str) -> AuditEntry {
        AuditEntry {
            time: "2026-04-21T00:00:00Z".into(),
            r#type: "request".into(),
            prev_hash: prev.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn genesis_hash_is_zero() {
        assert_eq!(genesis(), "sha256:".to_owned() + &"0".repeat(64));
    }

    #[test]
    fn verify_accepts_a_consistent_chain() {
        let mut entries = Vec::new();
        let mut prev = genesis();
        for _ in 0..5 {
            let e = mk(&prev);
            prev = digest(&e).unwrap();
            entries.push(e);
        }
        let head = verify(&entries, &genesis()).unwrap();
        assert_eq!(head, prev);
    }

    #[test]
    fn verify_detects_tampering() {
        let mut entries = Vec::new();
        let mut prev = genesis();
        for _ in 0..3 {
            let e = mk(&prev);
            prev = digest(&e).unwrap();
            entries.push(e);
        }
        // Tamper with entry 1 — break the link.
        entries[1].time = "TAMPERED".into();
        let err = verify(&entries, &genesis()).unwrap_err();
        assert_eq!(err, VerifyError::BrokenAt(2));
    }

    #[test]
    fn verify_detects_missing_prev() {
        let mut entries = Vec::new();
        let mut prev = genesis();
        for _ in 0..2 {
            let e = mk(&prev);
            prev = digest(&e).unwrap();
            entries.push(e);
        }
        // Drop the first entry — second entry's prev_hash no longer
        // matches the expected genesis.
        entries.remove(0);
        let err = verify(&entries, &genesis()).unwrap_err();
        assert_eq!(err, VerifyError::BrokenAt(0));
    }
}
