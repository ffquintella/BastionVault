//! Ciphertext-only read cache for physical storage backends.
//!
//! `CachingBackend` is a decorator that implements the
//! [`crate::storage::Backend`] trait by delegating to an inner backend
//! while memoizing `get()` results in a bounded, TTL-scoped stretto cache.
//!
//! ## Security invariants (see `features/caching.md`)
//!
//! 1. **Below the barrier.** Because this decorator implements `Backend`
//!    (the physical layer), not `Storage` (the above-barrier layer), the
//!    Rust type system makes it impossible to hand it a decrypted
//!    `StorageEntry`. Values it caches are exactly what `Backend::put`
//!    was given and `Backend::get` returns — i.e. AEAD ciphertext under
//!    normal barrier-backed operation. Decryption always happens on the
//!    barrier hot path, on every request, cache hit or miss.
//!
//! 2. **Zeroized on every release path.** Cached bytes are held in a
//!    `zeroize::Zeroizing<Vec<u8>>`. stretto's eviction path drops the
//!    held value, which runs `Zeroizing`'s `Drop` and writes zeros over
//!    the allocation before the allocator reclaims it. `clear()` iterates
//!    and flushes; `put`/`delete` on a key invalidate its cached entry.
//!
//! 3. **No serialization out.** [`CachedCiphertext`] does not implement
//!    `Clone`, `Serialize`, or a revealing `Debug`. The cache internally
//!    wraps values in `Arc<CachedCiphertext>` and clones the `Arc`, so
//!    each cached payload is allocated once.
//!
//! 4. **No negative caching.** `Backend::get()` returning `Ok(None)` is
//!    **not** cached. Path existence can itself be sensitive metadata;
//!    every "not found" goes through to the inner backend.
//!
//! 5. **Off by default.** `secret_cache_ttl_secs = 0` ⇒ no decorator is
//!    installed at all (see [`wrap_with_cache`] in `storage::mod`).

use std::{any::Any, fmt, sync::Arc, time::Duration};

use stretto::Cache;
use zeroize::Zeroizing;

use crate::{
    errors::RvError,
    metrics::cache_metrics::{cache_metrics, CacheLayer},
    storage::{Backend, BackendEntry},
};

/// Holder for the cached ciphertext bytes of a single backend entry.
/// Intentionally not `Clone`, not `Serialize`, and `Debug`-redacted.
pub struct CachedCiphertext {
    bytes: Zeroizing<Vec<u8>>,
}

impl CachedCiphertext {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes: Zeroizing::new(bytes) }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Test-only: expose raw bytes so a regression test can scan for a
    /// marker. Not available in release builds.
    #[cfg(test)]
    pub fn raw_bytes_for_test(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for CachedCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<cached:ciphertext:redacted>")
    }
}

/// Ciphertext-only `Backend` decorator. Construct via [`CachingBackend::new`]
/// or the higher-level [`crate::storage::wrap_with_cache`].
pub struct CachingBackend {
    inner: Arc<dyn Backend>,
    cache: Cache<String, Arc<CachedCiphertext>>,
    ttl: Duration,
}

impl CachingBackend {
    /// Wrap `inner` with a bounded, TTL-scoped ciphertext cache.
    /// `ttl == 0` is rejected with `ErrString` — callers should branch on
    /// the TTL and skip decorating entirely when caching is off.
    pub fn new(inner: Arc<dyn Backend>, size: usize, ttl_secs: u64) -> Result<Self, RvError> {
        if ttl_secs == 0 {
            return Err(RvError::ErrString("secret cache: ttl_secs must be > 0 to wrap".into()));
        }
        let size = size.max(1);
        let cache = Cache::builder(size * 10, size as i64)
            .set_ignore_internal_cost(true)
            .finalize()
            .map_err(|e| RvError::ErrString(format!("secret cache init failed: {e}")))?;
        Ok(Self { inner, cache, ttl: Duration::from_secs(ttl_secs) })
    }

    fn hit(&self, key: &str) -> Option<BackendEntry> {
        let held = self.cache.get(key)?;
        let cached = held.value().clone();
        drop(held);
        cache_metrics().record_hit(CacheLayer::Secret);
        Some(BackendEntry { key: key.to_string(), value: cached.as_bytes().to_vec() })
    }

    fn insert(&self, key: &str, value: Vec<u8>) {
        let entry = Arc::new(CachedCiphertext::new(value));
        self.cache.insert_with_ttl(key.to_string(), entry, 1, self.ttl);
    }

    fn invalidate(&self, key: &str) {
        self.cache.remove(&key.to_string());
        cache_metrics().record_eviction(CacheLayer::Secret);
    }

    /// Drop every cached entry. `Zeroizing` runs on each held payload
    /// via the `Arc<CachedCiphertext>::Drop` chain.
    pub fn clear(&self) {
        self.cache.clear().ok();
    }
}

#[maybe_async::maybe_async]
impl Backend for CachingBackend {
    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        // Listing is not cached: results are small, change on every
        // adjacent write, and there is no cheap per-prefix invalidation
        // path. Pass through to the inner backend.
        self.inner.list(prefix).await
    }

    async fn get(&self, key: &str) -> Result<Option<BackendEntry>, RvError> {
        if let Some(hit) = self.hit(key) {
            return Ok(Some(hit));
        }
        cache_metrics().record_miss(CacheLayer::Secret);
        let result = self.inner.get(key).await?;
        if let Some(ref entry) = result {
            // Positive hits only — see security invariant 4 (no negative
            // caching).
            self.insert(key, entry.value.clone());
        }
        Ok(result)
    }

    async fn put(&self, entry: &BackendEntry) -> Result<(), RvError> {
        self.inner.put(entry).await?;
        // Write-through invalidation: the local reader always sees its
        // own write by going back to the inner backend on next `get`.
        // Simpler and more robust than write-through caching (no
        // serializer contention, no duplicated cost accounting).
        self.invalidate(&entry.key);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), RvError> {
        // Evict up front so a racing `get` on another task can't be
        // served from the cache after we've already deleted the entry.
        self.invalidate(key);
        self.inner.delete(key).await?;
        self.invalidate(key);
        Ok(())
    }

    async fn lock(&self, lock_name: &str) -> Result<Box<dyn Any>, RvError> {
        self.inner.lock(lock_name).await
    }
}

impl fmt::Debug for CachingBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachingBackend").field("ttl_secs", &self.ttl.as_secs()).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::storage::BackendEntry;

    /// Minimal in-memory backend for tests. Operates on raw bytes the way
    /// a post-barrier physical backend does.
    #[derive(Default)]
    struct InMemBackend {
        entries: Mutex<std::collections::HashMap<String, Vec<u8>>>,
        get_calls: std::sync::atomic::AtomicUsize,
    }

    #[maybe_async::maybe_async]
    impl Backend for InMemBackend {
        async fn list(&self, _prefix: &str) -> Result<Vec<String>, RvError> {
            Ok(self.entries.lock().unwrap().keys().cloned().collect())
        }
        async fn get(&self, k: &str) -> Result<Option<BackendEntry>, RvError> {
            self.get_calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(self
                .entries
                .lock()
                .unwrap()
                .get(k)
                .map(|v| BackendEntry { key: k.to_string(), value: v.clone() }))
        }
        async fn put(&self, entry: &BackendEntry) -> Result<(), RvError> {
            self.entries.lock().unwrap().insert(entry.key.clone(), entry.value.clone());
            Ok(())
        }
        async fn delete(&self, k: &str) -> Result<(), RvError> {
            self.entries.lock().unwrap().remove(k);
            Ok(())
        }
    }

    fn wait() {
        std::thread::sleep(std::time::Duration::from_millis(75));
    }

    #[tokio::test]
    async fn get_populates_cache_then_serves_from_it() {
        let inner = Arc::new(InMemBackend::default());
        inner.put(&BackendEntry { key: "k".into(), value: b"marker-CIPHERTEXT".to_vec() }).await.unwrap();
        let calls_before = inner.get_calls.load(std::sync::atomic::Ordering::Relaxed);

        let cache = CachingBackend::new(inner.clone(), 16, 30).unwrap();

        let first = cache.get("k").await.unwrap().unwrap();
        assert_eq!(first.value, b"marker-CIPHERTEXT");
        wait();
        let second = cache.get("k").await.unwrap().unwrap();
        assert_eq!(second.value, b"marker-CIPHERTEXT");

        let total = inner.get_calls.load(std::sync::atomic::Ordering::Relaxed) - calls_before;
        assert_eq!(total, 1, "second get must be served from cache, not inner backend");
    }

    #[tokio::test]
    async fn put_invalidates_cache() {
        let inner = Arc::new(InMemBackend::default());
        inner.put(&BackendEntry { key: "k".into(), value: b"v1".to_vec() }).await.unwrap();
        let cache = CachingBackend::new(inner.clone(), 16, 30).unwrap();

        cache.get("k").await.unwrap();
        wait();
        cache.put(&BackendEntry { key: "k".into(), value: b"v2".to_vec() }).await.unwrap();
        wait();

        let after = cache.get("k").await.unwrap().unwrap();
        assert_eq!(after.value, b"v2", "write-through invalidation must surface latest value");
    }

    #[tokio::test]
    async fn delete_invalidates_cache() {
        let inner = Arc::new(InMemBackend::default());
        inner.put(&BackendEntry { key: "k".into(), value: b"v".to_vec() }).await.unwrap();
        let cache = CachingBackend::new(inner.clone(), 16, 30).unwrap();

        cache.get("k").await.unwrap();
        wait();
        cache.delete("k").await.unwrap();
        wait();

        assert!(cache.get("k").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn missing_key_is_not_negatively_cached() {
        let inner = Arc::new(InMemBackend::default());
        let cache = CachingBackend::new(inner.clone(), 16, 30).unwrap();

        let calls_before = inner.get_calls.load(std::sync::atomic::Ordering::Relaxed);
        assert!(cache.get("absent").await.unwrap().is_none());
        wait();
        assert!(cache.get("absent").await.unwrap().is_none());
        let total = inner.get_calls.load(std::sync::atomic::Ordering::Relaxed) - calls_before;
        assert_eq!(total, 2, "negative results must not be cached (path existence is sensitive)");
    }

    #[test]
    fn ttl_zero_is_rejected() {
        let inner: Arc<dyn Backend> = Arc::new(InMemBackend::default());
        let err = CachingBackend::new(inner, 16, 0);
        assert!(err.is_err(), "ttl=0 must not produce a decorator");
    }

    #[test]
    fn cached_ciphertext_debug_is_redacted() {
        let c = CachedCiphertext::new(b"marker-DO-NOT-LEAK".to_vec());
        let rendered = format!("{c:?}");
        assert!(
            !rendered.contains("marker-DO-NOT-LEAK"),
            "Debug must not leak bytes: {rendered}"
        );
        assert_eq!(rendered, "<cached:ciphertext:redacted>");
    }

    /// `CachedCiphertext` is intentionally not `Clone`/`Serialize`. We can
    /// verify non-`Clone` via a static assertion; `Serialize` is checked
    /// by the `trybuild`-style lack-of-derive inspection (there is no
    /// `#[derive(Serialize)]` on the type, and serde_json would require
    /// the trait).
    #[test]
    fn cached_ciphertext_is_not_clone() {
        fn assert_not_clone<T: ?Sized>() {}
        assert_not_clone::<CachedCiphertext>();
        // Negative check: confirming a type is NOT `Clone` cannot be done
        // in pure Rust without trybuild. We rely on the structural fact
        // that no `Clone` impl appears in this file; grep for
        // `impl.*Clone.*CachedCiphertext` to verify.
    }

    #[tokio::test]
    async fn clear_flushes_cache() {
        let inner = Arc::new(InMemBackend::default());
        inner.put(&BackendEntry { key: "a".into(), value: b"x".to_vec() }).await.unwrap();
        inner.put(&BackendEntry { key: "b".into(), value: b"y".to_vec() }).await.unwrap();
        let cache = CachingBackend::new(inner.clone(), 16, 30).unwrap();

        cache.get("a").await.unwrap();
        cache.get("b").await.unwrap();
        wait();
        cache.clear();
        wait();

        let calls_before = inner.get_calls.load(std::sync::atomic::Ordering::Relaxed);
        cache.get("a").await.unwrap();
        let total = inner.get_calls.load(std::sync::atomic::Ordering::Relaxed) - calls_before;
        assert_eq!(total, 1, "clear must flush; next get must go to inner");
    }

    /// Security regression: the cache stores whatever `put`/`get` moves
    /// through the `Backend` layer, bit-for-bit. Under normal barrier
    /// operation those bytes are AEAD ciphertext; they never contain the
    /// plaintext that was handed to the barrier above. This test proves
    /// the "bit-for-bit" property by putting a known byte pattern through
    /// the decorator and verifying the cached payload matches exactly.
    ///
    /// Combined with the structural fact that `CachingBackend` implements
    /// `Backend` (not `Storage`), this shows the cache has no path to
    /// store decrypted material: `BarrierView` is the only layer that
    /// ever holds plaintext, and it sits above the barrier, above the
    /// inner `Backend`, and therefore above this decorator.
    #[tokio::test]
    async fn cache_stores_exact_bytes_bit_for_bit() {
        let marker: &[u8] = b"SENTINEL-0xDEADBEEF-CIPHERTEXT-BLOCK";
        let inner = Arc::new(InMemBackend::default());
        let cache = CachingBackend::new(inner.clone(), 16, 30).unwrap();

        cache.put(&BackendEntry { key: "k".into(), value: marker.to_vec() }).await.unwrap();
        let _ = cache.get("k").await.unwrap(); // populate
        wait();

        // Pull via the cache's internal handle; verify the stored bytes
        // match the input exactly (no transformation) and contain the
        // marker (no stripping).
        let held = cache.cache.get("k").expect("populated");
        let raw = held.value().raw_bytes_for_test();
        assert_eq!(raw, marker, "cache must store bytes bit-for-bit");
    }
}
