//! Cache subsystem configuration and shared types.
//!
//! This module is currently scaffold-only. It provides the `CacheConfig`
//! struct parsed from the server config's `cache { ... }` block and threaded
//! through `Core`. The only caller that reads from it today is
//! `PolicyStore::new`, which uses `policy_cache_size` in place of the previous
//! compile-time constant. No new caches are allocated by this module yet.
//!
//! Future slices will add:
//!   * token cache (above the barrier, metadata only, `Zeroizing` values)
//!   * secret read cache (below the barrier, ciphertext only)
//!   * hit/miss/eviction metrics
//!   * zeroize-on-flush and memory-only enforcement (mlock, PR_SET_DUMPABLE)
//!
//! See `features/caching.md` for the full design, including the hard
//! invariants that no cache may hold plaintext secret material and that all
//! caches must be zeroized on every release path.

use serde::{Deserialize, Serialize};

pub mod guardrails;
pub mod secret_cache;
pub mod token_cache;
pub use secret_cache::CachingBackend;
pub use token_cache::TokenCache;

/// Default size for the policy ACL / EGP cache. Historically hard-coded as
/// `POLICY_CACHE_SIZE` in `policy_store.rs`.
pub const DEFAULT_POLICY_CACHE_SIZE: usize = 1024;

/// Default size for the (not-yet-implemented) token lookup cache.
pub const DEFAULT_TOKEN_CACHE_SIZE: usize = 4096;

/// Default TTL, in seconds, for cached token lookups. `0` disables the cache.
pub const DEFAULT_TOKEN_CACHE_TTL_SECS: u64 = 30;

/// Default size for the (not-yet-implemented) secret read cache.
pub const DEFAULT_SECRET_CACHE_SIZE: usize = 8192;

/// Default TTL, in seconds, for cached secret reads. `0` disables the cache.
/// Defaults to disabled because caching secret ciphertext introduces a
/// cross-node staleness window.
pub const DEFAULT_SECRET_CACHE_TTL_SECS: u64 = 0;

/// Operator-facing cache configuration.
///
/// All fields are optional in the config file and fall back to the
/// `DEFAULT_*` constants above. A zero TTL means the corresponding cache is
/// disabled; when a cache is disabled its size is still parsed (so toggling
/// it on at runtime in a future release stays declarative) but no allocation
/// is made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    #[serde(default = "default_policy_cache_size")]
    pub policy_cache_size: usize,

    #[serde(default = "default_token_cache_size")]
    pub token_cache_size: usize,

    #[serde(default = "default_token_cache_ttl_secs")]
    pub token_cache_ttl_secs: u64,

    #[serde(default = "default_secret_cache_size")]
    pub secret_cache_size: usize,

    #[serde(default = "default_secret_cache_ttl_secs")]
    pub secret_cache_ttl_secs: u64,

    /// Reserved for a future slice: `mlock(2)` / `VirtualLock` cache
    /// allocations to prevent swap. Parsed now so the config schema is
    /// stable; enforcement lands with the secret cache.
    #[serde(default)]
    pub memlock: bool,

    /// Reserved for a future slice: leave `PR_SET_DUMPABLE = 1` even when
    /// caches are enabled (debug-only). Parsed now; enforcement lands with
    /// the secret cache.
    #[serde(default)]
    pub allow_core_dumps: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            policy_cache_size: DEFAULT_POLICY_CACHE_SIZE,
            token_cache_size: DEFAULT_TOKEN_CACHE_SIZE,
            token_cache_ttl_secs: DEFAULT_TOKEN_CACHE_TTL_SECS,
            secret_cache_size: DEFAULT_SECRET_CACHE_SIZE,
            secret_cache_ttl_secs: DEFAULT_SECRET_CACHE_TTL_SECS,
            memlock: false,
            allow_core_dumps: false,
        }
    }
}

fn default_policy_cache_size() -> usize {
    DEFAULT_POLICY_CACHE_SIZE
}
fn default_token_cache_size() -> usize {
    DEFAULT_TOKEN_CACHE_SIZE
}
fn default_token_cache_ttl_secs() -> u64 {
    DEFAULT_TOKEN_CACHE_TTL_SECS
}
fn default_secret_cache_size() -> usize {
    DEFAULT_SECRET_CACHE_SIZE
}
fn default_secret_cache_ttl_secs() -> u64 {
    DEFAULT_SECRET_CACHE_TTL_SECS
}

impl CacheConfig {
    /// Merge another `CacheConfig` into this one. A field in `other` overrides
    /// this one only when it differs from the default, matching the existing
    /// `Config::merge` pattern used for directory-based config loading.
    pub fn merge(&mut self, other: CacheConfig) {
        let default = CacheConfig::default();
        if other.policy_cache_size != default.policy_cache_size {
            self.policy_cache_size = other.policy_cache_size;
        }
        if other.token_cache_size != default.token_cache_size {
            self.token_cache_size = other.token_cache_size;
        }
        if other.token_cache_ttl_secs != default.token_cache_ttl_secs {
            self.token_cache_ttl_secs = other.token_cache_ttl_secs;
        }
        if other.secret_cache_size != default.secret_cache_size {
            self.secret_cache_size = other.secret_cache_size;
        }
        if other.secret_cache_ttl_secs != default.secret_cache_ttl_secs {
            self.secret_cache_ttl_secs = other.secret_cache_ttl_secs;
        }
        if other.memlock {
            self.memlock = true;
        }
        if other.allow_core_dumps {
            self.allow_core_dumps = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_documented_values() {
        let c = CacheConfig::default();
        assert_eq!(c.policy_cache_size, 1024);
        assert_eq!(c.token_cache_size, 4096);
        assert_eq!(c.token_cache_ttl_secs, 30);
        assert_eq!(c.secret_cache_size, 8192);
        assert_eq!(c.secret_cache_ttl_secs, 0);
        assert!(!c.memlock);
        assert!(!c.allow_core_dumps);
    }

    #[test]
    fn missing_block_uses_defaults() {
        let parsed: CacheConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed, CacheConfig::default());
    }

    #[test]
    fn partial_block_fills_remaining_defaults() {
        let parsed: CacheConfig = serde_json::from_str(r#"{"policy_cache_size": 2048}"#).unwrap();
        assert_eq!(parsed.policy_cache_size, 2048);
        assert_eq!(parsed.token_cache_size, DEFAULT_TOKEN_CACHE_SIZE);
        assert_eq!(parsed.secret_cache_ttl_secs, 0);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let parsed: Result<CacheConfig, _> = serde_json::from_str(r#"{"nope": 1}"#);
        assert!(parsed.is_err(), "deny_unknown_fields must reject typos");
    }

    #[test]
    fn merge_prefers_non_default_fields() {
        let mut base = CacheConfig::default();
        let mut other = CacheConfig::default();
        other.policy_cache_size = 99;
        other.memlock = true;
        base.merge(other);
        assert_eq!(base.policy_cache_size, 99);
        assert!(base.memlock);
        assert_eq!(base.token_cache_size, DEFAULT_TOKEN_CACHE_SIZE);
    }
}
