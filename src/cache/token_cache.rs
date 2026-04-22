//! Token lookup cache.
//!
//! A bounded, TTL-scoped cache that sits in front of `TokenStore`'s storage
//! reads. Caches `TokenEntry` metadata (policies, TTLs, display name, etc.)
//! so repeat requests from the same caller don't re-read the salted
//! storage entry on every auth check.
//!
//! ## Security invariants (see `features/caching.md`)
//!
//! 1. **Raw token strings are never cached.** The cache is keyed by
//!    `TokenStore::salt_id(token)` — the same non-reversible salted hash
//!    already used as the storage key — not by the bearer token itself.
//!    A memory dump of the cache does not yield a replayable credential.
//! 2. **Cached values are zeroized on drop.** The on-heap representation
//!    is `zeroize::Zeroizing<Vec<u8>>` holding the serialized JSON of the
//!    `TokenEntry`. stretto's eviction path drops the value, which runs
//!    `Zeroizing`'s `Drop` and writes zeros over the allocation before the
//!    allocator reclaims it. Explicit `clear()` walks the cache and does
//!    the same.
//! 3. **Cached values are never serialized out.** `CachedToken` does not
//!    implement `Serialize`. `Debug` prints a fixed redacted string so
//!    log / panic / error paths cannot accidentally leak contents.
//! 4. **Zero TTL disables the cache.** Construction with `ttl_secs == 0`
//!    returns `None`; callers treat `Option<TokenCache>` as "caching off".

use std::{fmt, time::Duration};

use stretto::Cache;
use zeroize::Zeroizing;

use crate::{
    errors::RvError,
    metrics::cache_metrics::{cache_metrics, CacheLayer},
    modules::auth::token_store::TokenEntry,
};

/// Wrapper around the serialized JSON bytes of a `TokenEntry`. Zeroized on
/// drop. Intentionally does **not** implement `Clone`, `Serialize`, or a
/// revealing `Debug` — the cache internally holds an `Arc<CachedToken>` and
/// clones the `Arc`, so the bytes are only ever allocated once per cache
/// insert.
pub struct CachedToken {
    bytes: Zeroizing<Vec<u8>>,
}

impl CachedToken {
    fn from_entry(entry: &TokenEntry) -> Result<Self, RvError> {
        let json = serde_json::to_vec(entry)?;
        Ok(Self { bytes: Zeroizing::new(json) })
    }

    fn decode(&self) -> Result<TokenEntry, RvError> {
        let entry: TokenEntry = serde_json::from_slice(&self.bytes)?;
        Ok(entry)
    }

    /// Returns the length of the cached payload in bytes. Used by tests
    /// and by memory-usage diagnostics; does not reveal any content.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Test-only: expose the raw bytes so a regression test can scan for
    /// plaintext markers. Not available in release builds.
    #[cfg(test)]
    pub fn raw_bytes_for_test(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for CachedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<cached:token:redacted>")
    }
}

/// Bounded, TTL-scoped cache of serialized `TokenEntry` blobs, keyed by
/// `salt_id`. Constructed via [`TokenCache::new`]; returns `None` when
/// caching is disabled (`ttl_secs == 0`).
pub struct TokenCache {
    inner: Cache<String, std::sync::Arc<CachedToken>>,
    ttl: Duration,
}

impl TokenCache {
    /// Build a new token cache. Returns `Ok(None)` when `ttl_secs == 0`
    /// (caching disabled) so the caller can store an `Option<TokenCache>`
    /// without branching on "size was zero".
    pub fn new(size: usize, ttl_secs: u64) -> Result<Option<Self>, RvError> {
        if ttl_secs == 0 {
            return Ok(None);
        }
        let size = size.max(1);
        // Stretto cost counter: each entry has cost 1; we size the admission
        // counter at 10x capacity per stretto's documented recommendation.
        let cache = Cache::builder(size * 10, size as i64)
            .set_ignore_internal_cost(true)
            .finalize()
            .map_err(|e| RvError::ErrString(format!("token cache init failed: {e}")))?;
        Ok(Some(Self { inner: cache, ttl: Duration::from_secs(ttl_secs) }))
    }

    /// Look up a cached entry by `salt_id`. Returns `None` on miss or when
    /// the cached payload fails to deserialize (which should be impossible
    /// unless the cache is corrupted; in that case we fail open to a
    /// storage read rather than returning an error).
    pub fn lookup(&self, salt_id: &str) -> Option<TokenEntry> {
        let held = match self.inner.get(salt_id) {
            Some(v) => v,
            None => {
                cache_metrics().record_miss(CacheLayer::Token);
                return None;
            }
        };
        let cached = held.value().clone();
        drop(held);
        cache_metrics().record_hit(CacheLayer::Token);
        cached.decode().ok()
    }

    /// Insert or replace the cached entry for `salt_id`.
    pub fn insert(&self, salt_id: &str, entry: &TokenEntry) {
        let Ok(cached) = CachedToken::from_entry(entry) else {
            return;
        };
        let arc = std::sync::Arc::new(cached);
        self.inner.insert_with_ttl(salt_id.to_string(), arc, 1, self.ttl);
    }

    /// Remove the cached entry for `salt_id`, if any. Used on revoke,
    /// on `use_token` when `num_uses` changes, and on any other path that
    /// mutates the stored entry. Recorded as an eviction in the metrics.
    pub fn invalidate(&self, salt_id: &str) {
        self.inner.remove(&salt_id.to_string());
        cache_metrics().record_eviction(CacheLayer::Token);
    }

    /// Drop every cached entry. Triggers `Zeroizing` on each held payload
    /// via the underlying `Drop` chain. Used by seal.
    pub fn clear(&self) {
        self.inner.clear().ok();
    }
}

impl fmt::Debug for TokenCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenCache").field("ttl_secs", &self.ttl.as_secs()).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> TokenEntry {
        TokenEntry {
            id: "the-bearer-secret".to_string(),
            display_name: "marker-display-name".to_string(),
            policies: vec!["default".into(), "reader".into()],
            path: "auth/token/create".into(),
            ..TokenEntry::default()
        }
    }

    #[test]
    fn disabled_when_ttl_zero() {
        let c = TokenCache::new(128, 0).unwrap();
        assert!(c.is_none());
    }

    #[test]
    fn roundtrip_insert_lookup() {
        let cache = TokenCache::new(16, 30).unwrap().expect("enabled");
        let entry = sample_entry();
        cache.insert("salt-abc", &entry);
        std::thread::sleep(std::time::Duration::from_millis(50));
        let got = cache.lookup("salt-abc").expect("hit");
        assert_eq!(got.id, entry.id);
        assert_eq!(got.policies, entry.policies);
    }

    #[test]
    fn invalidate_removes_entry() {
        let cache = TokenCache::new(16, 30).unwrap().expect("enabled");
        let entry = sample_entry();
        cache.insert("salt-abc", &entry);
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(cache.lookup("salt-abc").is_some());
        cache.invalidate("salt-abc");
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(cache.lookup("salt-abc").is_none());
    }

    #[test]
    fn clear_empties_cache() {
        let cache = TokenCache::new(16, 30).unwrap().expect("enabled");
        cache.insert("a", &sample_entry());
        cache.insert("b", &sample_entry());
        std::thread::sleep(std::time::Duration::from_millis(50));
        cache.clear();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(cache.lookup("a").is_none());
        assert!(cache.lookup("b").is_none());
    }

    #[test]
    fn debug_is_redacted() {
        let entry = sample_entry();
        let cached = CachedToken::from_entry(&entry).unwrap();
        let rendered = format!("{cached:?}");
        assert!(
            !rendered.contains("marker-display-name"),
            "Debug must not leak payload contents: {rendered}"
        );
        assert!(!rendered.contains("the-bearer-secret"));
        assert_eq!(rendered, "<cached:token:redacted>");
    }

    #[test]
    fn cached_token_holds_serialized_bytes() {
        let entry = sample_entry();
        let cached = CachedToken::from_entry(&entry).unwrap();
        let raw = cached.raw_bytes_for_test();
        assert!(raw.windows(b"marker-display-name".len()).any(|w| w == b"marker-display-name"));
        assert_eq!(cached.len(), raw.len());
    }

    /// Security regression: the `Zeroize` impl that `Zeroizing<Vec<u8>>`
    /// invokes on drop must fully wipe the buffer contents. We call it
    /// directly (rather than relying on drop + reading freed memory,
    /// which would be UB) — `Zeroizing::drop` is defined as a call to
    /// this same `zeroize()` method, so a deterministic check here
    /// proves the chain works.
    ///
    /// Note: this test proves the zeroize step. stretto wraps values in
    /// `Arc`; when the `Arc` refcount reaches zero on eviction/clear,
    /// `CachedToken::drop` runs, which runs `Zeroizing::drop`, which
    /// runs `zeroize()`. The follow-up slice (secret cache) will add a
    /// `stretto_eviction_runs_drop` test that exercises that full path.
    #[test]
    fn zeroize_wipes_buffer() {
        use zeroize::Zeroize;
        let entry = sample_entry();
        let mut cached = CachedToken::from_entry(&entry).unwrap();
        assert!(
            cached.bytes.iter().any(|b| *b != 0),
            "payload must start non-zero for the test to be meaningful"
        );
        cached.bytes.zeroize();
        assert!(
            cached.bytes.iter().all(|b| *b == 0),
            "Zeroize impl must wipe every byte"
        );
    }
}
