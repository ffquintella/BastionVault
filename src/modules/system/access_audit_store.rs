//! Successful-request audit trail (the read/write "access" log).
//!
//! Companion to [`super::denial_audit_store`]. Where the denial store
//! captures the 403 path, this store captures the *successful* path:
//! the data-plane operations that the audit broker's local `audit.log`
//! file already records but which the unified Audit page never saw
//! (the page aggregates replicated system-view stores, not the local
//! file device). Before this store, a denied `secret/…` read appeared
//! on the Audit page but a *successful* one did not — the asymmetry
//! this store closes.
//!
//! It is not written from the request hot path. Writing every
//! successful read straight into the replicated barrier would turn a
//! read into a Raft write on the busiest code path. Instead, a
//! per-node background reconciler (`access_audit_reconciler`) tails
//! this node's local `audit.log` and ingests new lines here. Each node
//! ingests only its own local file; because the store is barrier-backed
//! (and therefore Hiqlite-replicated), the union of every node's
//! ingest is what the Audit page reads — so a cluster shows every
//! member's successful access, regardless of which node serves the GUI.
//!
//! Storage:
//!   sys/access-audit/<20-digit-nanos>-<16-hex-digest> -> AccessAuditEntry JSON
//!
//! The key carries two parts:
//!   * a 20-digit zero-padded nanosecond timestamp (same shape as the
//!     other append stores) so `list_since` can range-scan the recent
//!     tail and the whole store sorts chronologically; and
//!   * a 16-hex-char prefix of the SHA-256 of the *raw audit line* that
//!     produced the entry.
//!
//! The digest suffix is what makes ingest **idempotent**: re-reading the
//! same audit line (after a reconciler restart, a cursor reset, or a log
//! rotation re-scan) produces the identical key and identical value, so
//! the `put` overwrites in place instead of creating a duplicate row.
//! It also disambiguates two distinct events that share a nanosecond.
//! The line digest is effectively unique across the whole cluster (each
//! audit entry embeds a hash-chain `prev_hash`, timestamp, and request
//! id), so two nodes never collide.

use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    core::Core,
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

const ACCESS_AUDIT_SUB_PATH: &str = "access-audit/";

/// One row in the successful-access log. Carries only the non-secret
/// metadata the Audit page renders; the audit line it is derived from
/// is already HMAC-redacted, and we copy only the header fields anyway
/// (never the request body or response data).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessAuditEntry {
    /// RFC3339 timestamp copied from the source audit entry.
    pub ts: String,
    /// Display name of the caller when the token resolved to a named
    /// principal, else `"(unnamed principal)"`. Never the token itself.
    pub user: String,
    /// The request path that succeeded.
    pub path: String,
    /// The operation (`read`, `write`, `list`, `delete`, …).
    pub operation: String,
    /// Derived client address, best-effort (empty when the source
    /// entry had none).
    #[serde(default)]
    pub remote_addr: String,
    /// The namespace the request's token was bound to (`""` = root).
    #[serde(default)]
    pub namespace: String,
}

pub struct AccessAuditStore {
    view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl AccessAuditStore {
    pub fn from_core(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };
        let view = Arc::new(system_view.new_sub_view(ACCESS_AUDIT_SUB_PATH));
        Ok(Arc::new(Self { view }))
    }

    /// Append an entry keyed by `(timestamp-nanos, digest-of-raw-line)`.
    /// `raw_line` is the exact audit-log line the entry was parsed from;
    /// hashing it (rather than a re-serialization of the parsed struct)
    /// keeps the key stable no matter how the parsed entry round-trips.
    /// The write is idempotent: the same `raw_line` always lands on the
    /// same key, so a re-scan overwrites rather than duplicates.
    pub async fn append(&self, entry: AccessAuditEntry, raw_line: &str) -> Result<(), RvError> {
        let key = Self::entry_key(&entry.ts, raw_line);
        let value = serde_json::to_vec(&entry)?;
        self.view.put(&StorageEntry { key, value }).await
    }

    /// Full log, newest first.
    pub async fn list_all(&self) -> Result<Vec<AccessAuditEntry>, RvError> {
        Ok(Self::decode(self.view.get_entries("").await?))
    }

    /// Entries from `since_key` onward (inclusive), newest first.
    /// `since_key` is a 20-digit zero-padded nanosecond key; because our
    /// keys prefix that same fixed-width nanos field, a plain string
    /// range scan bounds the window to the recent tail.
    pub async fn list_since(&self, since_key: &str) -> Result<Vec<AccessAuditEntry>, RvError> {
        Ok(Self::decode(self.view.get_entries_since("", since_key).await?))
    }

    /// Storage key for an entry: `<20-digit-nanos>-<16-hex-digest>`.
    /// Nanos come from the RFC3339 `ts`; an unparseable timestamp falls
    /// back to `now` so a malformed source line still lands somewhere
    /// scannable rather than being dropped.
    fn entry_key(ts: &str, raw_line: &str) -> String {
        let nanos = chrono::DateTime::parse_from_rfc3339(ts)
            .ok()
            .and_then(|dt| dt.timestamp_nanos_opt())
            .unwrap_or_else(|| Utc::now().timestamp_nanos_opt().unwrap_or(0))
            .max(0) as u128;
        let mut hasher = Sha256::new();
        hasher.update(raw_line.as_bytes());
        let digest = hex::encode(hasher.finalize());
        format!("{nanos:020}-{}", &digest[..16])
    }

    /// Sort newest-first (keys sort chronologically via the nanos
    /// prefix) and decode, skipping values that fail to parse.
    fn decode(mut entries: Vec<StorageEntry>) -> Vec<AccessAuditEntry> {
        entries.sort_by(|a, b| b.key.cmp(&a.key));
        entries
            .into_iter()
            .filter_map(|e| serde_json::from_slice::<AccessAuditEntry>(&e.value).ok())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ts: &str) -> AccessAuditEntry {
        AccessAuditEntry {
            ts: ts.to_string(),
            user: "felipe".into(),
            path: "secret/data/foo".into(),
            operation: "read".into(),
            remote_addr: "10.0.0.1".into(),
            namespace: String::new(),
        }
    }

    #[test]
    fn same_line_yields_same_key() {
        let e = entry("2026-07-21T09:15:19Z");
        let raw = r#"{"time":"2026-07-21T09:15:19Z","type":"response"}"#;
        assert_eq!(
            AccessAuditStore::entry_key(&e.ts, raw),
            AccessAuditStore::entry_key(&e.ts, raw),
            "idempotent: identical raw line must key identically",
        );
    }

    #[test]
    fn different_lines_at_same_nanos_differ() {
        let ts = "2026-07-21T09:15:19Z";
        let a = AccessAuditStore::entry_key(ts, r#"{"a":1}"#);
        let b = AccessAuditStore::entry_key(ts, r#"{"a":2}"#);
        assert_ne!(a, b, "digest suffix must disambiguate same-nanos events");
        // ...but they share the sortable nanos prefix.
        assert_eq!(a.split('-').next(), b.split('-').next());
    }

    #[test]
    fn key_prefix_is_fixed_width_nanos() {
        let k = AccessAuditStore::entry_key("2026-07-21T09:15:19Z", "line");
        let nanos = k.split('-').next().unwrap();
        assert_eq!(nanos.len(), 20, "nanos field must be zero-padded to 20 digits");
        assert!(nanos.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn malformed_ts_still_produces_a_key() {
        // Falls back to `now` nanos rather than panicking / dropping.
        let k = AccessAuditStore::entry_key("not-a-date", "line");
        assert_eq!(k.split('-').next().unwrap().len(), 20);
    }

    #[test]
    fn decode_sorts_newest_first() {
        let older = StorageEntry {
            key: "00000000000000000001-aaaaaaaaaaaaaaaa".into(),
            value: serde_json::to_vec(&entry("2026-07-21T09:00:00Z")).unwrap(),
        };
        let newer = StorageEntry {
            key: "00000000000000000002-bbbbbbbbbbbbbbbb".into(),
            value: serde_json::to_vec(&entry("2026-07-21T09:15:19Z")).unwrap(),
        };
        let out = AccessAuditStore::decode(vec![older, newer]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].ts, "2026-07-21T09:15:19Z", "newest must come first");
    }
}
