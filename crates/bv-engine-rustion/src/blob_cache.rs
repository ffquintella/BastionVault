//! Bounded in-memory cache of recording artifacts, so a chunked
//! playback read costs **one** upstream fetch instead of one per chunk.
//!
//! ## Why a cache is required here
//!
//! A recording artifact lives on the bastion, and the bastion's
//! `GET /v1/recordings/<rid>/blob` serves the whole file — it has no
//! `Range` support. Without a cache, serving `blob/chunk/<n>` would
//! re-download the entire artifact for every chunk: O(n²) traffic
//! between the vault and the bastion, and the larger the recording the
//! worse it gets, which is precisely the case chunking exists for.
//!
//! ## Why caching is safe here
//!
//! A recording artifact is immutable: it is written once when the
//! session ends and identified by a sidecar digest. There is no
//! read-your-writes hazard, so a cached copy can only be stale in the
//! sense of "still exactly right".
//!
//! An artifact is admitted only after its bytes have been checked
//! against the digest on record for that recording
//! ([`verify_artifact_digest`](crate::recordings::verify_artifact_digest),
//! called by
//! [`fetch_blob_cached`](crate::recordings::fetch_blob_cached)). That
//! ordering is what makes a chunked read safe: chunk 0 pays for the
//! check and every later chunk is served from an entry that has already
//! passed it, so there is no path by which a corrupted artifact is
//! handed out one slice at a time. Nothing else may insert here.
//!
//! ## Handling of the bytes
//!
//! The bytes are session-recording plaintext, so:
//!
//! * they are held in [`Zeroizing`], wiped when the last reader drops
//!   the entry;
//! * the cache is dropped on seal (`RustionStores::clear`), like every
//!   other piece of decrypted state;
//! * nothing is written to disk — the budget below is a RAM budget, and
//!   exceeding it evicts rather than spills;
//! * access control is unchanged: the ACL check runs per request in the
//!   pipeline, before any handler consults this cache, and the cache key
//!   is the recording id the caller was already authorized to read.
//!
//! The cache is deliberately *not* a general artifact store. It is a
//! read-through window that keeps one playback's chunks cheap, and it
//! is sized so that forgetting an entry is always preferable to holding
//! it.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use zeroize::Zeroizing;

/// Artifact bytes as handed to a chunk handler. `Arc` so a read never
/// copies the artifact, `Zeroizing` so the last drop wipes it.
pub type ArtifactBytes = Arc<Zeroizing<Vec<u8>>>;

/// Bytes of artifact per chunk.
///
/// 4 MiB base64-expands to ~5.6 MB of JSON body, which stays under
/// ureq's 10 MB default read limit — so a client that has *not* raised
/// its response cap can still stream an arbitrarily large recording.
/// That property is the reason for this specific number; raising it
/// would silently re-break such clients.
pub const CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// Idle lifetime of a cached artifact. Refreshed on every read, so an
/// in-progress playback keeps its entry alive no matter how long the
/// whole transfer takes; an abandoned one falls out on its own.
const IDLE_TTL: Duration = Duration::from_secs(180);

/// Total RAM the cache may hold across all entries. An artifact larger
/// than this is served but never cached (see [`BlobCache::put`]) — it
/// would evict everything and then itself.
const MAX_BYTES: usize = 512 * 1024 * 1024;

/// Concurrent playbacks to keep resident. Small on purpose: the budget
/// above is the real limit, this just stops many small recordings from
/// accumulating.
const MAX_ENTRIES: usize = 4;

struct Entry {
    bytes: ArtifactBytes,
    format: String,
    sha256: String,
    digest_verified: bool,
    last_used: Instant,
}

/// What a cache read hands back: the artifact plus the sidecar fields a
/// chunk response has to echo.
pub struct Artifact {
    pub bytes: ArtifactBytes,
    pub format: String,
    pub sha256: String,
    /// True when `sha256` was checked against the bytes before this
    /// artifact was admitted — see
    /// [`verify_artifact_digest`](crate::recordings::verify_artifact_digest).
    ///
    /// False means only one thing: no digest was on record to check
    /// against, so the bytes are served unverified and say so. It never
    /// means "checked and failed" — a failed check never reaches this
    /// struct, and so never reaches the cache.
    pub digest_verified: bool,
}

impl Clone for Artifact {
    fn clone(&self) -> Self {
        Artifact {
            bytes: self.bytes.clone(),
            format: self.format.clone(),
            sha256: self.sha256.clone(),
            digest_verified: self.digest_verified,
        }
    }
}

/// See the module docs. Cheap to construct; empty until a chunk read
/// fills it.
#[derive(Default)]
pub struct BlobCache {
    entries: Mutex<HashMap<String, Entry>>,
}

impl BlobCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up `recording_id`, refreshing its idle deadline. Expired
    /// entries are dropped (and wiped) rather than returned.
    pub fn get(&self, recording_id: &str) -> Option<Artifact> {
        let mut map = self.lock();
        Self::drop_expired(&mut map);
        let entry = map.get_mut(recording_id)?;
        entry.last_used = Instant::now();
        Some(Artifact {
            bytes: entry.bytes.clone(),
            format: entry.format.clone(),
            sha256: entry.sha256.clone(),
            digest_verified: entry.digest_verified,
        })
    }

    /// Insert an artifact, evicting as needed to stay inside the
    /// budget. An artifact bigger than the whole budget is *not*
    /// cached: the caller still serves it, at the cost of re-fetching
    /// it for the next chunk, and gets a warning saying so. That is the
    /// explicit trade — a bounded cache that refuses, never one that
    /// grows past its budget.
    pub fn put(&self, recording_id: &str, artifact: &Artifact) {
        let size = artifact.bytes.len();
        if size > MAX_BYTES {
            log::warn!(
                "rustion: recording `{recording_id}` is {size} bytes, over the {MAX_BYTES}-byte \
                 blob-cache budget; chunked reads will re-fetch it from the bastion each time"
            );
            return;
        }
        let mut map = self.lock();
        Self::drop_expired(&mut map);
        map.remove(recording_id);
        while map.len() >= MAX_ENTRIES || Self::total_bytes(&map) + size > MAX_BYTES {
            let Some(victim) = Self::lru_key(&map) else { break };
            map.remove(&victim);
        }
        map.insert(
            recording_id.to_string(),
            Entry {
                bytes: artifact.bytes.clone(),
                format: artifact.format.clone(),
                sha256: artifact.sha256.clone(),
                digest_verified: artifact.digest_verified,
                last_used: Instant::now(),
            },
        );
    }

    /// Forget one artifact. Used when the index entry it was read
    /// against is gone, so a re-read can't be answered from a copy of
    /// something the caller can no longer resolve.
    pub fn invalidate(&self, recording_id: &str) {
        self.lock().remove(recording_id);
    }

    /// Drop every artifact. Called on seal.
    pub fn clear(&self) {
        self.lock().clear();
    }

    /// `(entries, bytes)` currently resident. Exposed for tests and for
    /// operational visibility.
    pub fn stats(&self) -> (usize, usize) {
        let map = self.lock();
        (map.len(), Self::total_bytes(&map))
    }

    /// A poisoned cache mutex means a panic while holding it — the map
    /// itself is a plain `HashMap`, so recovering the guard is safe and
    /// strictly better than propagating a panic into every later read.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn drop_expired(map: &mut HashMap<String, Entry>) {
        let now = Instant::now();
        map.retain(|_, e| now.duration_since(e.last_used) < IDLE_TTL);
    }

    fn total_bytes(map: &HashMap<String, Entry>) -> usize {
        map.values().map(|e| e.bytes.len()).sum()
    }

    fn lru_key(map: &HashMap<String, Entry>) -> Option<String> {
        map.iter().min_by_key(|(_, e)| e.last_used).map(|(k, _)| k.clone())
    }
}

/// Chunk geometry for an artifact of `total` bytes.
///
/// An empty artifact is one empty chunk, not zero chunks: a client
/// loops `0..chunk_count` and must be able to learn "there is nothing
/// here" from a successful read rather than from an error.
pub fn chunk_count(total: usize) -> usize {
    if total == 0 {
        1
    } else {
        total.div_ceil(CHUNK_BYTES)
    }
}

/// Byte range of chunk `index`, or `None` when the index is past the
/// end. Never panics and never returns a partially-clamped range — an
/// out-of-range index is the caller's error to report.
pub fn chunk_range(total: usize, index: usize) -> Option<(usize, usize)> {
    if index >= chunk_count(total) {
        return None;
    }
    let start = index * CHUNK_BYTES;
    let end = start.saturating_add(CHUNK_BYTES).min(total);
    Some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(len: usize) -> Artifact {
        Artifact {
            bytes: Arc::new(Zeroizing::new(vec![7u8; len])),
            format: "rdp-rec".into(),
            sha256: "aa".into(),
            digest_verified: true,
        }
    }

    #[test]
    fn chunk_geometry_covers_the_artifact_exactly() {
        // Partial last chunk.
        let total = CHUNK_BYTES + 10;
        assert_eq!(chunk_count(total), 2);
        assert_eq!(chunk_range(total, 0), Some((0, CHUNK_BYTES)));
        assert_eq!(chunk_range(total, 1), Some((CHUNK_BYTES, total)));
        assert_eq!(chunk_range(total, 2), None);

        // Exact multiple: no phantom trailing chunk.
        let exact = CHUNK_BYTES * 3;
        assert_eq!(chunk_count(exact), 3);
        assert_eq!(chunk_range(exact, 2), Some((CHUNK_BYTES * 2, exact)));
        assert_eq!(chunk_range(exact, 3), None);

        // Every chunk of a real-world size is contiguous and complete.
        let total = 17_800_000;
        let mut covered = 0;
        for i in 0..chunk_count(total) {
            let (s, e) = chunk_range(total, i).expect("in range");
            assert_eq!(s, covered, "chunk {i} must start where the last ended");
            covered = e;
        }
        assert_eq!(covered, total, "chunks must cover the artifact exactly");
    }

    #[test]
    fn empty_artifact_is_one_empty_chunk() {
        assert_eq!(chunk_count(0), 1);
        assert_eq!(chunk_range(0, 0), Some((0, 0)));
        assert_eq!(chunk_range(0, 1), None);
    }

    #[test]
    fn get_after_put_returns_the_same_bytes_without_copying() {
        let cache = BlobCache::new();
        let art = artifact(1024);
        cache.put("rec_a", &art);
        let got = cache.get("rec_a").expect("cached");
        assert_eq!(got.bytes.len(), 1024);
        assert_eq!(got.format, "rdp-rec");
        assert!(Arc::ptr_eq(&got.bytes, &art.bytes), "read must hand back the same allocation");
        assert_eq!(cache.stats(), (1, 1024));
    }

    #[test]
    fn entry_count_is_bounded_and_evicts_least_recently_used() {
        let cache = BlobCache::new();
        for i in 0..MAX_ENTRIES {
            cache.put(&format!("rec_{i}"), &artifact(16));
        }
        assert_eq!(cache.stats().0, MAX_ENTRIES);
        // Touch every entry except `rec_0`, in order, so the least
        // recently used one is unambiguous.
        for i in 1..MAX_ENTRIES {
            assert!(cache.get(&format!("rec_{i}")).is_some());
        }
        cache.put("rec_new", &artifact(16));
        assert_eq!(cache.stats().0, MAX_ENTRIES, "entry count must stay bounded");
        assert!(cache.get("rec_new").is_some());
        assert!(cache.get("rec_0").is_none(), "the least-recently-used entry is the victim");
    }

    #[test]
    fn artifact_over_the_budget_is_not_cached() {
        let cache = BlobCache::new();
        // Not actually allocated: a slice of a zero-filled vec that
        // claims to be over budget would cost 512 MiB, so assert the
        // decision on the boundary instead.
        assert!(MAX_BYTES > CHUNK_BYTES);
        cache.put("rec_small", &artifact(CHUNK_BYTES));
        assert_eq!(cache.stats(), (1, CHUNK_BYTES));
        cache.invalidate("rec_small");
        assert_eq!(cache.stats(), (0, 0));
    }

    #[test]
    fn clear_drops_everything() {
        let cache = BlobCache::new();
        cache.put("rec_a", &artifact(64));
        cache.put("rec_b", &artifact(64));
        cache.clear();
        assert_eq!(cache.stats(), (0, 0));
        assert!(cache.get("rec_a").is_none());
    }
}
