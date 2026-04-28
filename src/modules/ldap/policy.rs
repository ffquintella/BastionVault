//! Persisted role + library set + check-out records.
//!
//! Storage layout under the engine's per-mount UUID-scoped barrier prefix:
//!
//! ```text
//! static-role/<name>          → JSON(StaticRole)
//! static-cred/<name>          → JSON(StaticCred)        # last-rotated password
//! library/<set>               → JSON(LibrarySet)
//! library/<set>/checked-out/<account>  → JSON(CheckOutRecord)
//! ```

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::utils::{deserialize_duration, serialize_duration};

pub const STATIC_ROLE_PREFIX: &str = "static-role/";
pub const STATIC_CRED_PREFIX: &str = "static-cred/";
pub const LIBRARY_PREFIX: &str = "library/";

pub const DEFAULT_LIBRARY_TTL: Duration = Duration::from_secs(60 * 60); // 1h
pub const DEFAULT_LIBRARY_MAX_TTL: Duration = Duration::from_secs(24 * 60 * 60); // 24h

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticRole {
    /// Full DN of the managed account.
    pub dn: String,
    /// Short login name. Surfaced in `static-cred` responses + audit.
    pub username: String,
    /// `0` = manual rotation only; non-zero schedules an auto-rotate
    /// at `last_vault_rotation + rotation_period`. Auto-rotation
    /// scheduler is a Phase 3 follow-up; today the field is
    /// persisted and the manual `/rotate-role/:name` endpoint drives
    /// every rotation.
    #[serde(
        default,
        serialize_with = "serialize_duration",
        deserialize_with = "deserialize_duration"
    )]
    pub rotation_period: Duration,
    /// Per-role generator override. Empty = mount default.
    #[serde(default)]
    pub password_policy: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StaticCred {
    /// Current cleartext password. Barrier-encrypted at rest like
    /// every other persisted byte. Returned to authorised callers
    /// via `GET /static-cred/:name`.
    pub password: String,
    /// Unix-seconds wall-clock of the last successful rotation.
    pub last_vault_rotation_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibrarySet {
    /// DNs (or short names) of every account in the pool. The
    /// engine rotates each on check-out / check-in; pool membership
    /// is operator-managed.
    pub service_account_names: Vec<String>,
    #[serde(
        default = "default_library_ttl",
        serialize_with = "serialize_duration",
        deserialize_with = "deserialize_duration"
    )]
    pub ttl: Duration,
    #[serde(
        default = "default_library_max_ttl",
        serialize_with = "serialize_duration",
        deserialize_with = "deserialize_duration"
    )]
    pub max_ttl: Duration,
    /// When false (default), `check-in` requires the same entity id
    /// that did `check-out`. Operators with a shared-credential
    /// workflow can flip to true; the audit log still carries both
    /// entity ids on every event.
    #[serde(default)]
    pub disable_check_in_enforcement: bool,
    /// Phase 5 — identity-aware check-out affinity. When the same
    /// entity checks out from this set within `affinity_ttl` of its
    /// previous check-in, the engine hands back the same account
    /// (still freshly rotated). Reduces audit-log noise and keeps
    /// per-account log aggregation meaningful for callers that
    /// repeatedly grab + release in quick succession (CI runners,
    /// short-lived agents). `Duration::ZERO` (default) disables
    /// affinity — every check-out picks the first available account.
    /// The affinity record is written at check-in time, keyed by
    /// entity id, and consulted on the next check-out from the same
    /// entity. Expired records are dropped on first sight (lazy
    /// expiration); a periodic sweep is a follow-up.
    #[serde(
        default,
        serialize_with = "serialize_duration",
        deserialize_with = "deserialize_duration"
    )]
    pub affinity_ttl: Duration,
}

fn default_library_ttl() -> Duration {
    DEFAULT_LIBRARY_TTL
}

fn default_library_max_ttl() -> Duration {
    DEFAULT_LIBRARY_MAX_TTL
}

/// Phase 5 — affinity record persisted under
/// `library/<set>/affinity/<entity>` after a successful check-in
/// (when `affinity_ttl > 0`). The next check-out from the same
/// entity consults the record: if it's still fresh and the recorded
/// account is currently available, that account is picked. If the
/// record is stale or the account is checked out by someone else,
/// affinity falls back silently to the normal first-available pick.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffinityRecord {
    pub set: String,
    pub entity: String,
    pub account: String,
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckOutRecord {
    pub set: String,
    /// Short / DN form as it appeared in the pool.
    pub account: String,
    /// Lease id minted on check-out. The lease's `revoke_handler`
    /// rotates the password and removes this record on expiry or
    /// explicit revoke.
    pub lease_id: String,
    /// Caller's entity id. Empty for root-token check-outs.
    #[serde(default)]
    pub checked_out_by: String,
    pub checked_out_at_unix: u64,
    pub expires_at_unix: u64,
}

impl LibrarySet {
    pub fn validate(&self) -> Result<(), String> {
        if self.service_account_names.is_empty() {
            return Err("service_account_names must contain at least one entry".into());
        }
        if self.max_ttl < self.ttl {
            return Err(format!(
                "max_ttl {:?} must be >= ttl {:?}",
                self.max_ttl, self.ttl
            ));
        }
        for n in &self.service_account_names {
            if n.trim().is_empty() {
                return Err("service_account_names contains an empty entry".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_validate_rejects_empty_pool() {
        let l = LibrarySet {
            service_account_names: vec![],
            ttl: DEFAULT_LIBRARY_TTL,
            max_ttl: DEFAULT_LIBRARY_MAX_TTL,
            disable_check_in_enforcement: false,
            affinity_ttl: Duration::ZERO,
        };
        assert!(l.validate().is_err());
    }

    #[test]
    fn library_validate_rejects_inverted_ttls() {
        let l = LibrarySet {
            service_account_names: vec!["svc1".into()],
            ttl: Duration::from_secs(3600),
            max_ttl: Duration::from_secs(60),
            disable_check_in_enforcement: false,
            affinity_ttl: Duration::ZERO,
        };
        assert!(l.validate().is_err());
    }

    #[test]
    fn affinity_record_serde_roundtrip() {
        let r = AffinityRecord {
            set: "etl".into(),
            entity: "alice".into(),
            account: "CN=svc_etl_a,DC=example,DC=com".into(),
            expires_at_unix: 1_700_000_000,
        };
        let bytes = serde_json::to_vec(&r).unwrap();
        let back: AffinityRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.account, r.account);
        assert_eq!(back.expires_at_unix, r.expires_at_unix);
    }

    #[test]
    fn library_default_affinity_is_off() {
        let l = LibrarySet {
            service_account_names: vec!["svc1".into()],
            ttl: DEFAULT_LIBRARY_TTL,
            max_ttl: DEFAULT_LIBRARY_MAX_TTL,
            disable_check_in_enforcement: false,
            affinity_ttl: Duration::ZERO,
        };
        assert!(l.affinity_ttl.is_zero(), "affinity must be off by default");
    }

    #[test]
    fn role_serde_roundtrip() {
        let r = StaticRole {
            dn: "CN=svc,DC=example,DC=com".into(),
            username: "svc".into(),
            rotation_period: Duration::from_secs(3600),
            password_policy: String::new(),
        };
        let bytes = serde_json::to_vec(&r).unwrap();
        let back: StaticRole = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.dn, r.dn);
        assert_eq!(back.rotation_period, r.rotation_period);
    }
}
