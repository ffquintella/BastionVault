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
//!   `FileBackend → ObfuscatingTarget → CachingTarget → S3/OneDrive/...`
//!
//! # Invalidation
//!
//! `write(k, v)` and `delete(k)` invalidate two things:
//!   1. The cached read entry for `k` (if any).
//!   2. Every cached `list(prefix)` where `prefix` is a prefix of `k`
//!      — the key we just wrote may have appeared or disappeared
//!      from those enumerations.
//!
//! TTL expiry provides the belt-and-suspenders path: any entry more
//! than `read_ttl`/`list_ttl` old is re-fetched on the next miss.
//!
//! # Freshness model
//!
//! Each cache entry has two thresholds:
//!
//!   * `stale_after = inserted_at + read_ttl * stale_ratio`
//!     (default ratio: 0.5 — i.e. entries are fresh for the first
//!     half of their TTL.) Past this but before the TTL, reads are
//!     served from cache AND a background refresh is spawned
//!     ("stale-while-revalidate"). The caller sees sub-microsecond
//!     latency while the provider's next response becomes the new
//!     cached value.
//!
//!   * `expires_at = inserted_at + read_ttl`. Past this the entry
//!     is invalid — the next reader fetches synchronously, while
//!     the singleflight gate prevents a burst of concurrent readers
//!     from all hitting the provider for the same key.
//!
//! # Concurrency
//!
//! `read` uses a per-key singleflight gate: concurrent readers of an
//! uncached key serialize through a `tokio::sync::Mutex`, so the
//! underlying provider receives exactly one request per cold key
//! even under fan-out. The gate is dropped once the fetch completes;
//! steady-state hits never touch it.
//!
//! # Background prefetch
//!
//! An optional `prefetch_keys` list on the config is read in parallel
//! (bounded by `prefetch_concurrency`) when the cache is constructed.
//! Empty by default — opt-in, because the "right" warmup set depends
//! on the deployment. A typical setup fills in the barrier's hot
//! entries (`core/keyring`, `core/master`) so the very first vault
//! request doesn't pay cold-cache latency.
//!
//! # What this does NOT do
//!
//! * No adaptive prefetch from access history. Only explicit keys
//!   listed in `prefetch_keys` are loaded.
//! * No per-entry TTL. All reads share `read_ttl`; all lists share
//!   `list_ttl`. A future rev could thread per-key hints through
//!   the FileTarget trait, but the current uniformity keeps the
//!   implementation small and the cache behavior predictable.

use std::{
    any::Any,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
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
/// by insertion time is evicted.
pub const DEFAULT_MAX_ENTRIES: usize = 65_536;
/// Soft cap on total cached bytes. 500 MiB is large enough to hold
/// the hot set of a medium-sized vault (tens of thousands of small
/// ciphertext entries, thousands of small file blobs) without
/// spilling to the provider on every read. Still a small fraction
/// of typical server RSS, and every cached byte is AEAD ciphertext
/// emitted by the barrier — caching it reveals no plaintext.
pub const DEFAULT_MAX_BYTES: u64 = 500 * 1024 * 1024;
/// Fraction of `read_ttl` after which an entry is considered stale
/// but still serveable (stale-while-revalidate kicks in). `0.5`
/// means the cache proactively refreshes starting at the halfway
/// point — reads stay hot, and the next expired-read is rare.
pub const DEFAULT_STALE_RATIO: f32 = 0.5;
/// Parallelism cap on the background prefetch task. Small because
/// providers throttle aggressively on bursts; prefetch is best-
/// effort and not worth triggering rate-limits.
pub const DEFAULT_PREFETCH_CONCURRENCY: usize = 4;

#[derive(Clone, Debug)]
pub struct CacheConfig {
    pub read_ttl: Duration,
    pub list_ttl: Duration,
    pub max_entries: usize,
    pub max_bytes: u64,
    /// Fraction of `read_ttl` at which entries become "stale but
    /// serveable". Clamped to `[0.0, 1.0]` — `0.0` disables SWR
    /// entirely (every post-insert read triggers a refresh),
    /// `1.0` disables it too (entries are never stale, only
    /// expired). Default `0.5`.
    pub stale_ratio: f32,
    /// Keys to preload into the cache when the target is
    /// constructed. Empty disables the prefetch task. Prefetch runs
    /// in the background and tolerates individual key failures
    /// silently — the cache will miss-fetch on first use anyway.
    pub prefetch_keys: Vec<String>,
    /// Max concurrent in-flight prefetch requests.
    pub prefetch_concurrency: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            read_ttl: DEFAULT_READ_TTL,
            list_ttl: DEFAULT_LIST_TTL,
            max_entries: DEFAULT_MAX_ENTRIES,
            max_bytes: DEFAULT_MAX_BYTES,
            stale_ratio: DEFAULT_STALE_RATIO,
            prefetch_keys: Vec::new(),
            prefetch_concurrency: DEFAULT_PREFETCH_CONCURRENCY,
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

/// The mutable state of the cache. Wrapped in an `Arc` by
/// `CachingTarget` so background tasks (SWR refresh, prefetch) can
/// clone the handle and reach into the maps after the originating
/// request has returned.
struct CachingState {
    target: Arc<dyn FileTarget>,
    config: CacheConfig,
    reads: DashMap<String, ReadEntry>,
    lists: DashMap<String, ListEntry>,
    total_bytes: AtomicU64,
    /// Per-key singleflight gates. On a cold miss, readers of the
    /// same key contend on the same `tokio::sync::Mutex` so the
    /// underlying provider sees exactly one request per (key, miss).
    /// Only populated on the miss path; empty in steady state.
    #[cfg(not(feature = "sync_handler"))]
    inflight: DashMap<String, Arc<tokio::sync::Mutex<()>>>,
}

pub struct CachingTarget {
    state: Arc<CachingState>,
}

impl std::fmt::Debug for CachingTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachingTarget")
            .field("inner", &self.state.target)
            .field("config", &self.state.config)
            .field("read_entries", &self.state.reads.len())
            .field("list_entries", &self.state.lists.len())
            .field(
                "total_bytes",
                &self.state.total_bytes.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl CachingTarget {
    pub fn new(inner: Arc<dyn FileTarget>, mut config: CacheConfig) -> Self {
        // Clamp the SWR threshold into a sane range so a misconfigured
        // value doesn't produce nonsense (e.g. negative elapsed ratios).
        if !config.stale_ratio.is_finite() {
            config.stale_ratio = DEFAULT_STALE_RATIO;
        }
        config.stale_ratio = config.stale_ratio.clamp(0.0, 1.0);
        if config.prefetch_concurrency == 0 {
            config.prefetch_concurrency = 1;
        }

        let prefetch_keys = std::mem::take(&mut config.prefetch_keys);
        let prefetch_concurrency = config.prefetch_concurrency;

        let state = Arc::new(CachingState {
            target: inner,
            config,
            reads: DashMap::new(),
            lists: DashMap::new(),
            total_bytes: AtomicU64::new(0),
            #[cfg(not(feature = "sync_handler"))]
            inflight: DashMap::new(),
        });

        // Background prefetch only makes sense on async builds — the
        // sync_handler feature collapses the runtime and has no
        // `tokio::spawn`. Keeping it async-gated avoids pulling a
        // runtime dependency into sync callers.
        #[cfg(not(feature = "sync_handler"))]
        {
            if !prefetch_keys.is_empty() {
                let prefetch_state = state.clone();
                tokio::spawn(async move {
                    prefetch_state
                        .run_prefetch(prefetch_keys, prefetch_concurrency)
                        .await;
                });
            }
        }
        #[cfg(feature = "sync_handler")]
        {
            let _ = prefetch_keys;
            let _ = prefetch_concurrency;
        }

        Self { state }
    }

    /// Total bytes currently held by the read cache. Exposed for
    /// tests and for future observability.
    pub fn cached_bytes(&self) -> u64 {
        self.state.total_bytes.load(Ordering::Relaxed)
    }

    /// Number of cached read entries.
    pub fn cached_entries(&self) -> usize {
        self.state.reads.len()
    }
}

impl CachingState {
    #[inline]
    fn stale_after(&self) -> Duration {
        // stale_ratio is already clamped into [0, 1] in `new`, so
        // multiplication can't overflow or produce a negative value.
        let ttl = self.config.read_ttl.as_secs_f32();
        Duration::from_secs_f32(ttl * self.config.stale_ratio)
    }

    fn fresh(&self, inserted_at: Instant) -> bool {
        inserted_at.elapsed() < self.stale_after()
    }

    fn stale_but_live(&self, inserted_at: Instant) -> bool {
        let age = inserted_at.elapsed();
        age >= self.stale_after() && age < self.config.read_ttl
    }

    fn list_fresh(&self, inserted_at: Instant) -> bool {
        inserted_at.elapsed() < self.config.list_ttl
    }

    /// Evict a single oldest read entry. Simple O(n) scan — N is
    /// bounded by `max_entries`, and eviction only runs while the
    /// cache is over budget, so this amortises to acceptable cost
    /// for the read-heavy workloads this decorator exists to help.
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
        self.lists.retain(|prefix, _| !key.starts_with(prefix.as_str()));
        cache_metrics().set_size(CacheLayer::CloudTarget, self.reads.len() as i64);
    }

    /// Cold-path read. Acquires the per-key singleflight gate so
    /// concurrent readers of the same uncached key share a single
    /// provider round-trip.
    #[cfg(not(feature = "sync_handler"))]
    async fn singleflight_fetch(
        self: &Arc<Self>,
        key: &str,
    ) -> Result<Option<Vec<u8>>, RvError> {
        let gate = self
            .inflight
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = gate.lock().await;

        // Re-check after acquiring the gate: a prior holder may have
        // already populated the cache, in which case we serve from
        // RAM and skip the provider call. This is the whole point
        // of the gate — N concurrent misses become 1 provider call
        // + (N-1) cache hits.
        if let Some(entry) = self.reads.get(key) {
            // Accept any non-expired entry here (fresh OR stale-but-live).
            // The outer caller already determined a refresh was warranted,
            // but if something else beat us to it the entry is good enough
            // to skip a duplicate fetch.
            if entry.inserted_at.elapsed() < self.config.read_ttl {
                cache_metrics().record_hit(CacheLayer::CloudTarget);
                return Ok(entry.value.clone());
            }
        }

        let fresh = self.target.read(key).await?;
        self.insert_read(key, fresh.clone());

        drop(_guard);
        // Best-effort cleanup of the per-key gate. Racy against a
        // concurrent acquirer that took `gate.clone()` before us —
        // if that race loses, the lingering empty mutex gets
        // overwritten by the next singleflight_fetch, so no leak.
        self.inflight.remove(key);

        Ok(fresh)
    }

    /// Sync fallback for the `sync_handler` feature — no singleflight,
    /// no spawned refresh, just a direct pass-through.
    #[cfg(feature = "sync_handler")]
    async fn singleflight_fetch(
        self: &Arc<Self>,
        key: &str,
    ) -> Result<Option<Vec<u8>>, RvError> {
        let fresh = self.target.read(key).await?;
        self.insert_read(key, fresh.clone());
        Ok(fresh)
    }

    /// SWR background refresh. Called from `tokio::spawn` — errors
    /// are logged but otherwise dropped, because the caller already
    /// got the stale value and forward progress isn't gated on this.
    #[cfg(not(feature = "sync_handler"))]
    async fn refresh_in_background(self: Arc<Self>, key: String) {
        match self.target.read(&key).await {
            Ok(fresh) => {
                self.insert_read(&key, fresh);
            }
            Err(e) => {
                log::debug!(
                    "cache: background refresh failed for `{key}`: {e} \
                     (stale entry still serving)"
                );
            }
        }
    }

    /// Bounded-concurrency prefetch loop. Walks `keys` and issues up
    /// to `concurrency` reads in flight at any time. Failures are
    /// silent — prefetch is best-effort.
    #[cfg(not(feature = "sync_handler"))]
    async fn run_prefetch(self: Arc<Self>, keys: Vec<String>, concurrency: usize) {
        use tokio::sync::Semaphore;
        let sem = Arc::new(Semaphore::new(concurrency.max(1)));
        let mut handles = Vec::with_capacity(keys.len());
        for key in keys {
            let permit_sem = sem.clone();
            let state = self.clone();
            handles.push(tokio::spawn(async move {
                // Semaphore bounds concurrency; `acquire_owned` so the
                // permit drops automatically when the task ends.
                let _permit = match permit_sem.acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                if let Ok(value) = state.target.read(&key).await {
                    state.insert_read(&key, value);
                }
            }));
        }
        for h in handles {
            let _ = h.await;
        }
    }
}

#[maybe_async::maybe_async]
impl FileTarget for CachingTarget {
    async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, RvError> {
        // Fast-path: fresh hit serves from memory, no spawn, no gate.
        // Scope the guard so it drops before we potentially spawn.
        let stale_hit: Option<Option<Vec<u8>>> = {
            if let Some(entry) = self.state.reads.get(key) {
                if self.state.fresh(entry.inserted_at) {
                    cache_metrics().record_hit(CacheLayer::CloudTarget);
                    return Ok(entry.value.clone());
                }
                if self.state.stale_but_live(entry.inserted_at) {
                    Some(entry.value.clone())
                } else {
                    None
                }
            } else {
                None
            }
        };

        // Stale hit — serve cached value, spawn a background refresh.
        // Under `sync_handler` we can't spawn, so fall through to
        // singleflight (which will re-populate synchronously).
        if let Some(cached) = stale_hit {
            cache_metrics().record_hit(CacheLayer::CloudTarget);
            #[cfg(not(feature = "sync_handler"))]
            {
                let state = self.state.clone();
                let k = key.to_string();
                tokio::spawn(async move {
                    state.refresh_in_background(k).await;
                });
                return Ok(cached);
            }
            #[cfg(feature = "sync_handler")]
            {
                let _ = cached;
                // fall through to miss path
            }
        }

        cache_metrics().record_miss(CacheLayer::CloudTarget);
        self.state.singleflight_fetch(key).await
    }

    async fn write(&self, key: &str, value: &[u8]) -> Result<(), RvError> {
        // Write through first; only invalidate on success so a failed
        // write doesn't leave the cache claiming the new value is
        // cached under the old key.
        self.state.target.write(key, value).await?;
        self.state.invalidate(key);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), RvError> {
        self.state.target.delete(key).await?;
        self.state.invalidate(key);
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        if let Some(entry) = self.state.lists.get(prefix) {
            if self.state.list_fresh(entry.inserted_at) {
                cache_metrics().record_hit(CacheLayer::CloudTarget);
                return Ok(entry.values.clone());
            }
        }
        cache_metrics().record_miss(CacheLayer::CloudTarget);

        let fresh = self.state.target.list(prefix).await?;
        self.state.lists.insert(
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
        self.state.target.lock(lock_name).await
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
    /// hit/miss behavior without a real provider.
    #[derive(Debug, Default)]
    struct CountingTarget {
        data: Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
        reads: AtomicUsize,
        writes: AtomicUsize,
        deletes: AtomicUsize,
        lists: AtomicUsize,
        /// Optional per-read delay, used by the singleflight test to
        /// keep concurrent misses overlapping long enough that the
        /// gate is observable.
        read_delay: Mutex<Duration>,
    }

    impl CountingTarget {
        fn read_calls(&self) -> usize {
            self.reads.load(AtomicOrdering::Relaxed)
        }
        fn list_calls(&self) -> usize {
            self.lists.load(AtomicOrdering::Relaxed)
        }
        fn set_read_delay(&self, d: Duration) {
            *self.read_delay.lock().unwrap() = d;
        }
    }

    #[maybe_async::maybe_async]
    impl FileTarget for CountingTarget {
        async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, RvError> {
            let delay = *self.read_delay.lock().unwrap();
            if delay > Duration::ZERO {
                #[cfg(not(feature = "sync_handler"))]
                tokio::time::sleep(delay).await;
            }
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

        cache.write("a/3", b"z").await.unwrap();
        let third = cache.list("a/").await.unwrap();
        assert_eq!(third.len(), 3);
        assert_eq!(inner.list_calls(), 2);
    }

    #[tokio::test]
    async fn ttl_expiry_forces_refetch() {
        // stale_ratio = 1.0 disables SWR so the test measures pure
        // TTL-expiry behavior without a background refresh racing
        // in. Would otherwise flake on slow runners.
        let config = CacheConfig {
            read_ttl: Duration::from_millis(20),
            list_ttl: Duration::from_millis(20),
            stale_ratio: 1.0,
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
        for i in 0..8u8 {
            let _ = cache.read(&format!("k{i}")).await.unwrap();
        }
        assert!(
            cache.cached_bytes() <= 16,
            "cache held {} bytes, exceeds 16-byte cap",
            cache.cached_bytes()
        );
        assert!(
            cache.cached_entries() <= 4,
            "cache held {} entries, expected ≤ 4 for a 16-byte / 4-bytes-each cap",
            cache.cached_entries()
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
        assert!(cache.cached_entries() <= 3);
    }

    // ── new feature coverage ───────────────────────────────────────

    #[tokio::test]
    async fn singleflight_coalesces_concurrent_misses() {
        let (cache, inner) = make_cache(CacheConfig::default());
        inner
            .data
            .lock()
            .unwrap()
            .insert("hot".into(), b"v".to_vec());
        // 10ms per read is plenty for 8 tasks to all be in flight by
        // the time the first one reaches the provider.
        inner.set_read_delay(Duration::from_millis(10));

        let cache = Arc::new(cache);
        let mut handles = Vec::new();
        for _ in 0..8 {
            let c = cache.clone();
            handles.push(tokio::spawn(async move {
                c.read("hot").await.unwrap()
            }));
        }
        for h in handles {
            let got = h.await.unwrap();
            assert_eq!(got.as_deref(), Some(b"v".as_ref()));
        }
        assert_eq!(
            inner.read_calls(),
            1,
            "8 concurrent readers of the same cold key should have coalesced into 1 provider call"
        );
    }

    #[tokio::test]
    async fn stale_while_revalidate_serves_fast_and_refreshes() {
        // 100ms TTL, 50% stale ratio → fresh for 50ms, stale for
        // the next 50ms. Sleep to 60ms: still serveable, should
        // trigger SWR.
        let config = CacheConfig {
            read_ttl: Duration::from_millis(100),
            list_ttl: Duration::from_millis(100),
            stale_ratio: 0.5,
            ..CacheConfig::default()
        };
        let (cache, inner) = make_cache(config);
        inner
            .data
            .lock()
            .unwrap()
            .insert("k".into(), b"v1".to_vec());
        let _ = cache.read("k").await.unwrap(); // populate
        assert_eq!(inner.read_calls(), 1);

        tokio::time::sleep(Duration::from_millis(60)).await;

        // Mutate the provider so the background refresh picks up
        // the new value, and issue a read. The read should serve
        // the OLD cached value (SWR) while a spawn goes out.
        inner
            .data
            .lock()
            .unwrap()
            .insert("k".into(), b"v2".to_vec());

        let got = cache.read("k").await.unwrap();
        assert_eq!(
            got.as_deref(),
            Some(b"v1".as_ref()),
            "stale hit should return the cached value, not block on refresh"
        );

        // Give the spawned refresh a moment to complete.
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(
            inner.read_calls(),
            2,
            "background refresh should have produced a second provider call"
        );

        // Next read (still within new TTL of the refreshed entry)
        // sees the updated value without another provider call.
        let got2 = cache.read("k").await.unwrap();
        assert_eq!(got2.as_deref(), Some(b"v2".as_ref()));
        assert_eq!(
            inner.read_calls(),
            2,
            "fresh hit after SWR refresh should NOT have called the provider again"
        );
    }

    #[tokio::test]
    async fn prefetch_loads_configured_keys_on_startup() {
        let inner = Arc::new(CountingTarget::default());
        inner
            .data
            .lock()
            .unwrap()
            .insert("warm/a".into(), b"1".to_vec());
        inner
            .data
            .lock()
            .unwrap()
            .insert("warm/b".into(), b"2".to_vec());
        inner
            .data
            .lock()
            .unwrap()
            .insert("cold".into(), b"3".to_vec());

        let config = CacheConfig {
            prefetch_keys: vec!["warm/a".into(), "warm/b".into()],
            ..CacheConfig::default()
        };
        let cache = CachingTarget::new(inner.clone(), config);

        // Give the background prefetch spawn a chance to run. In
        // CI under load, 200ms is plenty for two local reads.
        for _ in 0..40 {
            if cache.cached_entries() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            cache.cached_entries() >= 2,
            "prefetch should have loaded both keys (entries = {})",
            cache.cached_entries()
        );
        let pre_reads = inner.read_calls();

        // Subsequent reads hit the cache; provider not touched again.
        let a = cache.read("warm/a").await.unwrap();
        let b = cache.read("warm/b").await.unwrap();
        assert_eq!(a.as_deref(), Some(b"1".as_ref()));
        assert_eq!(b.as_deref(), Some(b"2".as_ref()));
        assert_eq!(
            inner.read_calls(),
            pre_reads,
            "cache hits after prefetch should not touch the provider"
        );

        // An unprefetched key still misses first, as expected.
        let c = cache.read("cold").await.unwrap();
        assert_eq!(c.as_deref(), Some(b"3".as_ref()));
        assert_eq!(inner.read_calls(), pre_reads + 1);
    }

    #[tokio::test]
    async fn stale_ratio_clamps_out_of_range_values() {
        // NaN, negative, and >1 all collapse to valid clamped
        // configurations rather than producing panics or nonsense.
        for bad in [f32::NAN, -1.0, 2.0, f32::INFINITY] {
            let cfg = CacheConfig {
                stale_ratio: bad,
                ..CacheConfig::default()
            };
            let (cache, inner) = make_cache(cfg);
            inner
                .data
                .lock()
                .unwrap()
                .insert("k".into(), b"v".to_vec());
            // Must not panic.
            let _ = cache.read("k").await.unwrap();
        }
    }

    #[tokio::test]
    async fn default_cache_is_500mib() {
        // Sanity check so a future refactor doesn't silently drop
        // the cache cap below the documented size.
        assert_eq!(DEFAULT_MAX_BYTES, 500 * 1024 * 1024);
        let c = CacheConfig::default();
        assert_eq!(c.max_bytes, 500 * 1024 * 1024);
    }
}
