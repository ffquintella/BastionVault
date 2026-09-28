//! MRTR `requestState`: `base64(payload || BLAKE3-keyed-hash(key, payload))`.
//! Verified, single-use, and never treated as authentication — the retry
//! that presents a confirmed `requestState` is re-authenticated from
//! scratch by the caller (the bearer token check happens independently).

use std::{
    collections::HashSet,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

use crate::error::McpError;

/// Max lifetime of a `requestState`, per spec §6.
pub const MAX_TTL_SECS: u64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestStatePayload {
    pub token_accessor: String,
    pub tool: String,
    pub args_hash: String,
    pub decision: String,
    pub exp: u64,
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Mint a `requestState` for `payload`, HMAC-bound with `key` (a
/// barrier-derived key in production; a fixed test key in unit tests).
pub fn mint(payload: &RequestStatePayload, key: &[u8]) -> String {
    let json = serde_json::to_vec(payload).expect("RequestStatePayload always serializes");
    let mac = blake3::keyed_hash(&derive_mac_key(key), &json);
    let mut buf = json;
    buf.extend_from_slice(mac.as_bytes());
    STANDARD.encode(buf)
}

/// Verify and decode a `requestState` string. Does not check single-use or
/// expiry — see [`SingleUseGuard`] for that half.
pub fn verify(encoded: &str, key: &[u8]) -> Result<RequestStatePayload, McpError> {
    let buf = STANDARD.decode(encoded).map_err(|_| McpError::ConfirmationInvalid)?;
    if buf.len() < 32 {
        return Err(McpError::ConfirmationInvalid);
    }
    let (json, mac_bytes) = buf.split_at(buf.len() - 32);
    let expected = blake3::keyed_hash(&derive_mac_key(key), json);
    if expected.as_bytes() != mac_bytes {
        return Err(McpError::ConfirmationInvalid);
    }
    let payload: RequestStatePayload = serde_json::from_slice(json).map_err(|_| McpError::ConfirmationInvalid)?;
    if payload.exp > now_secs() + MAX_TTL_SECS || payload.exp < now_secs() {
        return Err(McpError::ConfirmationInvalid);
    }
    Ok(payload)
}

/// `blake3::keyed_hash` requires exactly a 32-byte key; derive one from
/// whatever length the barrier hands us the same way the audit HMAC key is
/// derived elsewhere in this codebase (hash-to-fixed-length).
fn derive_mac_key(key: &[u8]) -> [u8; 32] {
    *blake3::hash(key).as_bytes()
}

/// In-process, single-process replay guard: a `(accessor, args_hash, exp)`
/// tuple may be consumed exactly once. Cleared entries are never re-added,
/// so this is safe to check-then-insert without a TOCTOU window as long as
/// both happen under the same lock (see [`SingleUseGuard::consume`]).
#[derive(Default)]
pub struct SingleUseGuard {
    seen: Mutex<HashSet<(String, String, u64)>>,
}

impl SingleUseGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` the first time this exact tuple is seen (and records
    /// it), `false` on every subsequent call — the replay case.
    pub fn consume(&self, payload: &RequestStatePayload) -> bool {
        let key = (payload.token_accessor.clone(), payload.args_hash.clone(), payload.exp);
        let mut seen = self.seen.lock().expect("SingleUseGuard mutex poisoned");
        seen.insert(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> RequestStatePayload {
        RequestStatePayload {
            token_accessor: "acc-1".into(),
            tool: "bv_kv_read".into(),
            args_hash: "hash-1".into(),
            decision: "reveal".into(),
            exp: now_secs() + 60,
        }
    }

    #[test]
    fn mint_then_verify_round_trips() {
        let key = b"test-key";
        let p = payload();
        let encoded = mint(&p, key);
        let decoded = verify(&encoded, key).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let key = b"test-key";
        let mut encoded = mint(&payload(), key).into_bytes();
        // Flip a byte inside the base64 body — the decoded JSON or the MAC
        // will no longer match.
        encoded[5] ^= 0x01;
        let encoded = String::from_utf8(encoded).unwrap();
        assert!(verify(&encoded, key).is_err());
    }

    #[test]
    fn wrong_key_is_rejected() {
        let encoded = mint(&payload(), b"key-a");
        assert!(verify(&encoded, b"key-b").is_err());
    }

    #[test]
    fn expired_payload_is_rejected() {
        let mut p = payload();
        p.exp = now_secs().saturating_sub(1);
        let encoded = mint(&p, b"test-key");
        assert!(verify(&encoded, b"test-key").is_err());
    }

    #[test]
    fn ttl_beyond_max_is_rejected() {
        let mut p = payload();
        p.exp = now_secs() + MAX_TTL_SECS + 60;
        let encoded = mint(&p, b"test-key");
        assert!(verify(&encoded, b"test-key").is_err());
    }

    #[test]
    fn single_use_guard_refuses_replay() {
        let guard = SingleUseGuard::new();
        let p = payload();
        assert!(guard.consume(&p), "first use must be accepted");
        assert!(!guard.consume(&p), "second use must be refused");
    }
}
