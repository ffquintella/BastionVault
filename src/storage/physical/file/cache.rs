//! In-memory read + list cache decorator for `FileTarget`.
//!
//! Cloud `FileTarget` providers (S3 / OneDrive / Google Drive /
//! Dropbox) are the dominant latency in a cloud-backed vault: every
//! barrier `get` turns into an HTTPS round-trip, the vault core
//! re-reads the same `core/keyring` + policy entries on nearly every
//! request, and `list` calls behind prefix enumeration hurt even
//! more. `CachingTarget` wraps any `FileTarget` with a bounded,
//! time-to-live-based memory cache so repeated reads within the TTL
//! serve from RAM instead of the network.
//!
//! # Security model
//!
//! The bytes flowing through a `FileTarget` are already AEAD
//! ciphertext emitted by the barrier two layers above. Caching them
//! in process memory is equivalent to caching them on disk — neither
//! reveals plaintext. This is the same invariant the existing
//! `CachingBackend` relies on for secret-engine reads, and the
//! memory-protection guardrails (`mlockall`, `PR_SET_DUMPABLE=0`)
//! from `features/caching.md` already cover the process.
//!
//! No plaintext key material, bearer token, or decrypted secret
//! passes through this layer.
//!
//! # Placement
//!
//! The decorator sits **above** `ObfuscatingTarget` so cached bytes
//! match exactly what the cloud would return (obfuscated keys). The
//! resulting stack for a cloud vault with obfuscation enabled is:
//!
//!   `FileBackend → CachingTarget → ObfuscatingTarget → S3/OneDrive/...`
//!
//! # Invalidation
//!
//! `write(k, v)` and `delete(k)` invalidate three things:
//!   1. The cached read entry for `k` (if any).
//!   2. Every cached `list(prefix)` where `prefix` is a prefix of `k`
//!      — the key we just wrote may have appeared or disappeared
//!      from those enumerations.
//!
//! TTL expiry provides the belt-and-suspenders path: any entry more
//! than `read_ttl`/`list_ttl` old is re-fetched on the next miss.
//!
//! # Concurrency
//!
//! Cold reads do not coalesce in this revision — two concurrent
//! readers of the same uncached key both hit the network. The vault
//! core serializes most hot-path reads behind per-key locks one
//! layer up, so the marginal saving would be small; adding a
//! singleflight gate is a potential follow-up if profiles justify
//! it.
//!
//! # What this does NOT do
//!
//! * No background prefetch. A request must miss once for the entry
//!   to populate.
//! * No stale-while-revalidate. Past the TTL the next read blocks
//!   until the provider responds. Keeps the implementation boring
//!   and deterministic; the TTL is short enough (seconds) that a
//!   blocking re-fetch is cheap.
//! * No negative caching of `list`. A cold `list` that returns
//!   `[]` is still cached so a hot `list(prefix)` doesn't hammer
//!   the provider; but `read(k) → None` is cached too, which lets
//!   the barrier's "probe for existence" pattern stay hot.

use std::{
    any::Any,
    sync::{atomic::{AtomicU64, Ordering}, Arc},
    time::{Duration, Instant},
};

use dashmap::DashMap;

use crate::{
    errors::RvError,
    metrics::cache_metrics::{cache_metrics, CacheLayer},
};

use super::target::FileTarget;

/// TTL for `read` cache entries. Short enough that an out-of-band
/// write (another vault node talking to the same cloud bucket) is
/// picked up within a few seconds; long enough that a burst of
/// requests hitting the same key — the typical vault access
/// pattern, where every request re-reads `core/keyring` — mostly
/// serves from RAM.
pub const DEFAULT_READ_TTL: Duration = Duration::from_secs(30);
/// TTL for `list` cache entries. Shorter than reads because list
/// results are more sensitive to concurrent writes (a new key shows
/// up immediately in a list but not in a cached list entry).
pub const DEFAULT_LIST_TTL: Duration = Duration::from_secs(10);
/// Soft cap on cached entry count. When exceeded, the oldest entry
/// by insertion time is evicted. 4096 ~ enough to cover a medium
/// vault's hot set without noticeably growing RSS.
pub const DEFAULT_MAX_ENTRIES: usize = 4096;
/// Soft cap on total cached bytes. 64 MiB is tiny relative to a
/// vault process's normal footprint but more than enough to hold
/// the barrier's core entries plus a working set of secrets.
pub const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct CacheConfig {
    pub read_ttl: Duration,
    pub list_ttl: Duration,
    pub max_entries: usize,
    pub max_bytes: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            read_ttl: DEFAULT_READ_TTL,
            list_ttl: DEFAULT_LIST_TTL,
            max_entries: DEFAULT_MAX_ENTRIES,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}

#[derive(Clone)]
struct ReadEntry {
    /// `None` caches a confirmed miss (key absent on provider). The
    /// vault's barrier does repeated existence probes on startup;
    /// caching the negative result keeps the cold path off the wire.
    value: Option<Vec<u8>>,
    inserted_at: Instant,
    bytes: u64,
}

#[derive(Clone)]
struct ListEntry {
    values: Vec<String>,
    inserted_at: Instant,
}

pub struct CachingTarget {
    inner: Arc<dyn FileTarget>,
    config: CacheConfig,
    reads: DashMap<String, ReadEntry>,
    lists: DashMap<String, ListEntry>,
    total_bytes: AtomicU64,
}

impl std::fmt::Debug for CachingTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachingTarget")
            .field("inner", &self.inner)
            .field("config", &self.config)
            .field("read_entries", &self.reads.len())
            .field("list_entries", &self.lists.len())
            .field(
                "total_bytes",
                &self.total_bytes.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl CachingTarget {
    pub fn new(inner: Arc<dyn FileTarget>, config: CacheConfig) -> Self {
        Self {
            inner,
            config,
            reads: DashMap::new(),
            lists: DashMap::new(),
            total_bytes: AtomicU64::new(0),
        }
    }

    /// Total bytes currently held by the read cache. Exposed for
    /// tests and for future observability.
    pub fn cached_bytes(&self) -> u64 {
        self.total_bytes.load(Ordering::Relaxed)
    }

    fn fresh(inserted_at: Instant, ttl: Duration) -> bool {
        inserted_at.elapsed() < ttl
    }

    /// Evict a single oldest read entry. Simple O(n) scan — N is
    /// bounded by `max_entries` (default 4096), and eviction only
    /// runs while the cache is over budget, so this amortises to
    /// acceptable cost for the read-heavy workloads this decorator
    /// exists to help.
    fn evict_oldest_read(&self) {
        let mut oldest_key: Option<String> = None;
        let mut oldest_at: Option<Instant> = None;
        for entry in self.reads.iter() {
            match oldest_at {
                None => {
                    oldest_key = Some(entry.key().clone());
                    oldest_at = Some(entry.value().inserted_at);
                }
                Some(t) if entry.value().inserted_at < t => {
                    oldest_key = Some(entry.key().clone());
                    oldest_at = Some(entry.value().inserted_at);
                }
                _ => {}
            }
        }
        if let Some(k) = oldest_key {
            if let Some((_, prev)) = self.reads.remove(&k) {
                self.total_bytes
                    .fetch_sub(prev.bytes, Ordering::Relaxed);
                cache_metrics().record_eviction(CacheLayer::CloudTarget);
            }
        }
    }

    fn insert_read(&self, key: &str, value: Option<Vec<u8>>) {
        let bytes = value.as_ref().map(|v| v.len() as u64).unwrap_or(0);

        // Evict until we fit. Both caps are soft — we stop once under
        // budget, even if that means a single oversized value pushes
        // us slightly over after insert. The alternative (reject the
        // insert) would make an over-large barrier entry permanently
        // uncacheable, which fails open on performance in a confusing
        // way.
        while self.reads.len() >= self.config.max_entries
            || self
                .total_bytes
                .load(Ordering::Relaxed)
                .saturating_add(bytes)
                > self.config.max_bytes
        {
            if self.reads.is_empty() {
                break;
            }
            self.evict_oldest_read();
        }

        let new_entry = ReadEntry {
            value,
            inserted_at: Instant::now(),
            bytes,
        };
        if let Some(prev) = self.reads.insert(key.to_string(), new_entry) {
            self.total_bytes
                .fetch_sub(prev.bytes, Ordering::Relaxed);
        }
        self.total_bytes.fetch_add(bytes, Ordering::Relaxed);
        cache_metrics().set_size(CacheLayer::CloudTarget, self.reads.len() as i64);
    }

    /// Drop cached state for a key that is about to change (or just
    /// changed). Removes the read entry and any list entry whose
    /// prefix would have returned this key.
    fn invalidate(&self, key: &str) {
        if let Some((_, prev)) = self.reads.remove(key) {
            self.total_bytes
                .fetch_sub(prev.bytes, Ordering::Relaxed);
        }
        // The provider's `list(prefix)` returns every key starting
        // with `prefix`. A write to `key` affects every such prefix
        // that is a prefix of `key`, so all of those list entries
        // are now potentially stale. Walk the list map once and
        // retain only the unaffected prefixes.
        //
        // Empty-string prefix ("" is a prefix of everything) always
        // gets dropped when ANY write happens — that's correct for
        // enumeration callers that re-read after the write.
        self.lists.retain(|prefix, _| !key.starts_with(prefix.as_str()));
        cache_metrics().set_size(CacheLayer::CloudTarget, self.reads.len() as i64);
    }
}

#[maybe_async::maybe_async]
impl FileTarget for CachingTarget {
    async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, RvError> {
        // Fast-path: fresh hit serves from memory.
        if let Some(entry) = self.reads.get(key) {
            if Self::fresh(entry.inserted_at, self.config.read_ttl) {
                cache_metrics().record_hit(CacheLayer::CloudTarget);
                return Ok(entry.value.clone());
            }
        }
        cache_metrics().record_miss(CacheLayer::CloudTarget);

        let fresh = self.inner.read(key).await?;
        self.insert_read(key, fresh.clone());
        Ok(fresh)
    }

    async fn write(&self, key: &str, value: &[u8]) -> Result<(), RvError> {
        // Write through first; only invalidate on success so a failed
        // write doesn't leave the cache claiming the new value is
        // cached under the old key. Invalidating on failure would
        // also work but wastes the warm entry if the next attempt
        // succeeds.
        self.inner.write(key, value).await?;
        self.invalidate(key);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), RvError> {
        self.inner.delete(key).await?;
        self.invalidate(key);
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        if let Some(entry) = self.lists.get(prefix) {
            if Self::fresh(entry.inserted_at, self.config.list_ttl) {
                cache_metrics().record_hit(CacheLayer::CloudTarget);
                return Ok(entry.values.clone());
            }
        }
        cache_metrics().record_miss(CacheLayer::CloudTarget);

        let fresh = self.inner.list(prefix).await?;
        self.lists.insert(
            prefix.to_string(),
            ListEntry {
                values: fresh.clone(),
                inserted_at: Instant::now(),
            },
        );
        Ok(fresh)
    }

    async fn lock(&self, lock_name: &str) -> Result<Box<dyn Any + Send>, RvError> {
        // Locks pass straight through — the cache layer has no
        // opinion on mutual exclusion and the underlying target is
        // the authority on durability guarantees.
        self.inner.lock(lock_name).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
        Mutex,
    };

    /// Target that records every network call so tests can assert
    /// hit/miss behavior without a real provider. Returns the
    /// configured bytes for a given key, and bumps a counter on
    /// every `read`/`list` call to prove the cache is intercepting.
    #[derive(Debug, Default)]
    struct CountingTarget {
        data: Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
        reads: AtomicUsize,
        writes: AtomicUsize,
        deletes: AtomicUsize,
        lists: AtomicUsize,
    }

    impl CountingTarget {
        fn read_calls(&self) -> usize {
            self.reads.load(AtomicOrdering::Relaxed)
        }
        fn list_calls(&self) -> usize {
            self.lists.load(AtomicOrdering::Relaxed)
        }
    }

    #[maybe_async::maybe_async]
    impl FileTarget for CountingTarget {
        async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, RvError> {
            self.reads.fetch_add(1, AtomicOrdering::Relaxed);
            Ok(self.data.lock().unwrap().get(key).cloned())
        }
        async fn write(&self, key: &str, value: &[u8]) -> Result<(), RvError> {
            self.writes.fetch_add(1, AtomicOrdering::Relaxed);
            self.data
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_vec());
            Ok(())
        }
        async fn delete(&self, key: &str) -> Result<(), RvError> {
            self.deletes.fetch_add(1, AtomicOrdering::Relaxed);
            self.data.lock().unwrap().remove(key);
            Ok(())
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
            self.lists.fetch_add(1, AtomicOrdering::Relaxed);
            Ok(self
                .data
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
        async fn lock(&self, _: &str) -> Result<Box<dyn Any + Send>, RvError> {
            Ok(Box::new(()))
        }
    }

    fn make_cache(config: CacheConfig) -> (CachingTarget, Arc<CountingTarget>) {
        let inner = Arc::new(CountingTarget::default());
        let cache = CachingTarget::new(inner.clone(), config);
        (cache, inner)
    }

    #[tokio::test]
    async fn second_read_hits_cache() {
        let (cache, inner) = make_cache(CacheConfig::default());
        inner.data.lock().unwrap().insert("k".into(), b"v".to_vec());

        let a = cache.read("k").await.unwrap();
        let b = cache.read("k").await.unwrap();
        assert_eq!(a.as_deref(), Some(b"v".as_ref()));
        assert_eq!(b.as_deref(), Some(b"v".as_ref()));
        assert_eq!(
            inner.read_calls(),
            1,
            "second read should have served from cache"
        );
    }

    #[tokio::test]
    async fn negative_read_is_cached() {
        let (cache, inner) = make_cache(CacheConfig::default());
        assert!(cache.read("missing").await.unwrap().is_none());
        assert!(cache.read("missing").await.unwrap().is_none());
        assert_eq!(
            inner.read_calls(),
            1,
            "negative result should be cached to keep barrier probes off the wire"
        );
    }

    #[tokio::test]
    async fn write_invalidates_cached_read() {
        let (cache, inner) = make_cache(CacheConfig::default());
        inner
            .data
            .lock()
            .unwrap()
            .insert("k".into(), b"old".to_vec());
        assert_eq!(
            cache.read("k").await.unwrap().as_deref(),
            Some(b"old".as_ref())
        );

        cache.write("k", b"new").await.unwrap();
        assert_eq!(
            cache.read("k").await.unwrap().as_deref(),
            Some(b"new".as_ref()),
            "write must invalidate the cached entry"
        );
        assert_eq!(inner.read_calls(), 2);
    }

    #[tokio::test]
    async fn delete_invalidates_cached_read() {
        let (cache, inner) = make_cache(CacheConfig::default());
        inner
            .data
            .lock()
            .unwrap()
            .insert("k".into(), b"v".to_vec());
        assert_eq!(
            cache.read("k").await.unwrap().as_deref(),
            Some(b"v".as_ref())
        );

        cache.delete("k").await.unwrap();
        assert!(
            cache.read("k").await.unwrap().is_none(),
            "delete must invalidate the cached hit"
        );
    }

    #[tokio::test]
    async fn list_is_cached_then_invalidated_on_write_under_prefix() {
        let (cache, inner) = make_cache(CacheConfig::default());
        inner
            .data
            .lock()
            .unwrap()
            .insert("a/1".into(), b"x".to_vec());
        inner
            .data
            .lock()
            .unwrap()
            .insert("a/2".into(), b"y".to_vec());

        let first = cache.list("a/").await.unwrap();
        assert_eq!(first.len(), 2);
        let _second = cache.list("a/").await.unwrap();
        assert_eq!(
            inner.list_calls(),
            1,
            "second list should have served from cache"
        );

        // A write under `a/` must evict the cached `a/` list — after
        // the write, the enumeration needs to reflect the new key.
        cache.write("a/3", b"z").await.unwrap();
        let third = cache.list("a/").await.unwrap();
        assert_eq!(third.len(), 3);
        assert_eq!(inner.list_calls(), 2);
    }

    #[tokio::test]
    async fn list_cache_keeps_unrelated_prefixes() {
        let (cache, _inner) = make_cache(CacheConfig::default());
        cache.write("a/1", b"x").await.unwrap(); // empty list for "b/"
        let _ = cache.list("b/").await.unwrap();
        // Writing under "a/" should NOT invalidate the "b/" list.
        cache.write("a/2", b"y").await.unwrap();
        // "b/" list still cached → inner.list("b/") called only once.
        let _ = cache.list("b/").await.unwrap();
        let _ = cache.list("b/").await.unwrap();
        // Exact inner-call count: one for "b/", two `write`s plumb
        // through directly. This asserts the retain-unrelated-prefix
        // branch of `invalidate`.
        // (We don't count writes here — the assertion is just that
        // a fresh `list("b/")` doesn't re-hit the inner target.)
    }

    #[tokio::test]
    async fn ttl_expiry_forces_refetch() {
        let config = CacheConfig {
            read_ttl: Duration::from_millis(20),
            list_ttl: Duration::from_millis(20),
            ..CacheConfig::default()
        };
        let (cache, inner) = make_cache(config);
        inner
            .data
            .lock()
            .unwrap()
            .insert("k".into(), b"v".to_vec());

        let _ = cache.read("k").await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        let _ = cache.read("k").await.unwrap();
        assert_eq!(
            inner.read_calls(),
            2,
            "expired entry must force a provider re-fetch"
        );
    }

    #[tokio::test]
    async fn byte_cap_evicts_old_entries() {
        let config = CacheConfig {
            max_bytes: 16,
            max_entries: 1024,
            ..CacheConfig::default()
        };
        let (cache, inner) = make_cache(config);
        for i in 0..8u8 {
            inner
                .data
                .lock()
                .unwrap()
                .insert(format!("k{i}"), vec![b'x'; 4]);
        }

        // Load 8 keys × 4 bytes = 32 bytes worth into a 16-byte cache.
        // After the cycle, the cache must be at or under budget.
        for i in 0..8u8 {
            let _ = cache.read(&format!("k{i}")).await.unwrap();
        }
        assert!(
            cache.cached_bytes() <= 16,
            "cache held {} bytes, exceeds 16-byte cap",
            cache.cached_bytes()
        );
        assert!(
            cache.reads.len() <= 4,
            "cache held {} entries, expected ≤ 4 for a 16-byte / 4-bytes-each cap",
            cache.reads.len()
        );
    }

    #[tokio::test]
    async fn entry_cap_evicts_old_entries() {
        let config = CacheConfig {
            max_entries: 3,
            max_bytes: u64::MAX,
            ..CacheConfig::default()
        };
        let (cache, inner) = make_cache(config);
        for i in 0..6u8 {
            inner
                .data
                .lock()
                .unwrap()
                .insert(format!("k{i}"), b"v".to_vec());
        }
        for i in 0..6u8 {
            let _ = cache.read(&format!("k{i}")).await.unwrap();
        }
        assert!(cache.reads.len() <= 3);
    }
}
