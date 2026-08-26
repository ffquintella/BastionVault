//! This crate manages all storage related code by defining a 'barrier' concept and a 'backend'
//! concept.
//!
//! Each different storage type needs to implement the `backend` trait to complete the support.
//!
//! Each barrier represents a specific cryptography method for ecrypting or decrypting data before
//! the data connects to a specific backend. A barrier is defined by implementing the `SecurityBarrier`
//! trait.
//!
//! So one example of a whole data path could be something like this:
//!
//! HTTP API -> some module (e.g. KV) -> barrier -> backend -> real storage (file, MySQL...)
//!
//! Typical storage types may be direct file, databases, remote network filesystem and etc.
//! Different strage types are all as sub-module of this module.
//!
//! Tier 0 of the workspace decomposition
//! (`roadmaps/workspace-decomposition.md` § Phase 1). Re-exported by the root
//! crate as `bastion_vault::storage`, with [`cache`] as `bastion_vault::cache`
//! and [`schema`] as `bastion_vault::schema`, so no call site outside these
//! directories changed when they moved.

use std::{any::Any, collections::HashMap, sync::Arc};

use better_default::Default;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use bv_errors::RvError;

pub mod barrier;
pub mod barrier_aes_gcm;
pub mod barrier_chacha20_poly1305;
pub mod barrier_chacha20_poly1305_init;
pub mod barrier_view;
#[cfg(feature = "storage_mysql")]
pub mod mysql;
pub mod physical;
pub mod pq_key_envelope;
#[cfg(all(not(feature = "sync_handler"), feature = "storage_hiqlite"))]
pub mod hiqlite;
#[cfg(not(feature = "sync_handler"))]
pub mod migrate;

/// The feature-independent cluster view of the physical backend. Always
/// compiled: a caller must not need `storage_hiqlite` of its own to ask
/// whether storage is clustered. See the module docs for the reporting bug
/// that made this necessary.
pub mod cluster;

/// The read caches that sit in front of the physical layer. Folded into this
/// crate rather than made its own: `CachingBackend` implements [`Backend`] and
/// [`wrap_with_cache`] installs it, so the two are mutually dependent.
pub mod cache;
/// Diesel's generated table definition for the MySQL backend, and its only
/// reader. Gated on the same feature as the backend — the root crate declared
/// `pub mod schema` behind `storage_mysql` for the same reason.
#[cfg(feature = "storage_mysql")]
pub mod schema;

/// Backend and barrier fixtures shared by this crate's tests and, through the
/// `test-support` feature, by the root crate's.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BarrierType {
    #[default]
    AesGcm,
    Chacha20Poly1305,
}

/// A trait that abstracts core methods for all storage barrier types.
#[maybe_async::maybe_async]
pub trait Storage: Send + Sync {
    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError>;
    async fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError>;
    async fn put(&self, entry: &StorageEntry) -> Result<(), RvError>;
    async fn delete(&self, key: &str) -> Result<(), RvError>;
    async fn lock(&self, _lock_name: &str) -> Result<Box<dyn Any>, RvError> {
        Ok(Box::new(true))
    }

    /// Bulk-read every entry under `prefix` (recursively), optionally
    /// restricted to keys `>= start_key`. Semantically equivalent to a
    /// `list` walk plus a `get` per key, but implementors backed by a
    /// queryable store override this to fetch the whole subtree in a
    /// single round-trip — avoiding the 1+N reads that dominate large
    /// audit/history scans (the prefix walk plus one read per entry).
    ///
    /// `start_key` is an inclusive lower bound on the *full* key, used
    /// for time-windowed scans over chronologically-keyed append logs
    /// whose keys sort in timestamp order.
    async fn scan(&self, prefix: &str, start_key: Option<&str>) -> Result<Vec<StorageEntry>, RvError> {
        let mut stack = vec![prefix.to_string()];
        let mut out = Vec::new();
        while let Some(curr) = stack.pop() {
            for child in self.list(&curr).await? {
                let full = format!("{curr}{child}");
                if child.ends_with('/') {
                    stack.push(full);
                } else if start_key.map(|s| full.as_str() >= s).unwrap_or(true) {
                    if let Some(e) = self.get(&full).await? {
                        out.push(e);
                    }
                }
            }
        }
        Ok(out)
    }
}

/// This struct is used to describe a specific storage entry
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageEntry {
    pub key: String,
    pub value: Vec<u8>,
}

impl StorageEntry {
    pub fn new(k: &str, v: &impl Serialize) -> Result<StorageEntry, RvError> {
        let data = serde_json::to_string(v)?;

        Ok(StorageEntry { key: k.to_string(), value: data.into_bytes() })
    }
}

#[maybe_async::maybe_async]
pub trait Backend: Send + Sync + std::any::Any {
    //! This trait decsribes the generic methods that a storage backend needs to implement.
    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError>;
    async fn get(&self, key: &str) -> Result<Option<BackendEntry>, RvError>;
    async fn put(&self, entry: &BackendEntry) -> Result<(), RvError>;
    async fn delete(&self, key: &str) -> Result<(), RvError>;
    async fn lock(&self, _lock_name: &str) -> Result<Box<dyn Any>, RvError> {
        Ok(Box::new(true))
    }

    /// Stable label for *which* backend this is -- the same strings
    /// [`new_backend`] dispatches on (`file`, `mysql`, `hiqlite`, `mock`).
    ///
    /// Exists so an operator-facing surface (`sys/info`,
    /// `sys/cluster-status`, `bvault status`) can report the storage kind
    /// without a downcast, and therefore without depending on which
    /// optional features the *reporting* crate happened to be compiled
    /// with. Decorators delegate to the backend they wrap, so the label
    /// always names the physical layer.
    ///
    /// The default is `"unknown"` rather than a guess: reporting a kind we
    /// cannot establish would be exactly the silent fallback that hid a
    /// live hiqlite cluster behind `storage_type: "file"`.
    fn backend_kind(&self) -> &'static str {
        "unknown"
    }

    /// Physical-layer counterpart of [`Storage::scan`]: bulk-read every
    /// entry under `prefix` (recursively), optionally restricted to keys
    /// `>= start_key`. The default walks `list` + `get`; backends that
    /// can return a whole subtree in one query (e.g. hiqlite) override
    /// this so the barrier's `scan` is a single round-trip instead of
    /// 1+N consistent reads.
    async fn scan(&self, prefix: &str, start_key: Option<&str>) -> Result<Vec<BackendEntry>, RvError> {
        let mut stack = vec![prefix.to_string()];
        let mut out = Vec::new();
        while let Some(curr) = stack.pop() {
            for child in self.list(&curr).await? {
                let full = format!("{curr}{child}");
                if child.ends_with('/') {
                    stack.push(full);
                } else if start_key.map(|s| full.as_str() >= s).unwrap_or(true) {
                    if let Some(e) = self.get(&full).await? {
                        out.push(e);
                    }
                }
            }
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendEntry {
    pub key: String,
    pub value: Vec<u8>,
}

/// this is a generic function that instantiates different storage backends.
///
/// **Note**: the sync constructor cannot honour `obfuscate_keys = true`
/// for the `file` backend — the salt bootstrap requires async I/O
/// against the wrapped target. Callers that need obfuscation should
/// reach for [`new_backend_async`] instead.
pub fn new_backend(t: &str, conf: &HashMap<String, Value>) -> Result<Arc<dyn Backend>, RvError> {
    match t {
        "file" => {
            let backend = physical::file::FileBackend::new(conf)?;
            Ok(Arc::new(backend))
        }
        #[cfg(feature = "storage_mysql")]
        "mysql" => {
            let backend = mysql::mysql_backend::MysqlBackend::new(conf)?;
            Ok(Arc::new(backend))
        }
        #[cfg(all(not(feature = "sync_handler"), feature = "storage_hiqlite"))]
        "hiqlite" => {
            let backend = hiqlite::HiqliteBackend::new(conf)?;
            Ok(Arc::new(backend))
        }
        "mock" => Ok(Arc::new(physical::mock::MockBackend::new())),
        _ => Err(RvError::ErrPhysicalTypeInvalid),
    }
}

/// Async sibling of [`new_backend`]. Routes the `file` backend
/// through [`physical::file::FileBackend::new_maybe_obfuscated`] so
/// the salt bootstrap for `obfuscate_keys = true` runs before the
/// backend is handed back. Other backends use the sync constructor
/// unchanged — they don't have an obfuscation layer.
pub async fn new_backend_async(
    t: &str,
    conf: &HashMap<String, Value>,
) -> Result<Arc<dyn Backend>, RvError> {
    match t {
        "file" => {
            let backend = physical::file::FileBackend::new_maybe_obfuscated(conf).await?;
            Ok(Arc::new(backend))
        }
        _ => new_backend(t, conf),
    }
}

/// Peel every storage decorator off `backend` and hand back the physical
/// backend underneath.
///
/// `Core::physical` is whatever [`wrap_with_cache`] returned, so on a
/// deployment with `cache.secret_cache_ttl_secs > 0` it is a
/// [`cache::CachingBackend`], not the backend the operator configured. Any
/// caller that reaches for a concrete backend type by
/// `Any::downcast_ref` must go through here first, or it silently sees
/// "not that backend" the moment caching is switched on.
pub fn physical_root(backend: &dyn Backend) -> &dyn Backend {
    let mut current = backend;
    // One decorator today; the loop keeps the invariant if another is added.
    loop {
        let as_any: &dyn Any = current;
        match as_any.downcast_ref::<cache::CachingBackend>() {
            Some(caching) => current = caching.inner().as_ref(),
            None => return current,
        }
    }
}

/// The hiqlite backend behind `backend`, decorators peeled, or `None` when
/// this deployment is not clustered.
///
/// Crate-private on purpose: [`cluster`] is the only caller, so exactly one
/// module in the workspace names the concrete type behind the
/// `storage_hiqlite` feature, and the peel in [`physical_root`] cannot be
/// forgotten by a caller that reaches for the type itself.
#[cfg(all(not(feature = "sync_handler"), feature = "storage_hiqlite"))]
pub(crate) fn as_hiqlite(backend: &dyn Backend) -> Option<&hiqlite::HiqliteBackend> {
    let root: &dyn Any = physical_root(backend);
    root.downcast_ref::<hiqlite::HiqliteBackend>()
}

pub fn new_barrier(barrier_type: BarrierType, backend: Arc<dyn Backend>) -> Arc<dyn barrier::SecurityBarrier> {
    match barrier_type {
        BarrierType::AesGcm => Arc::new(barrier_aes_gcm::AESGCMBarrier::new(backend)),
        BarrierType::Chacha20Poly1305 => Arc::new(barrier_chacha20_poly1305::ChaCha20Poly1305Barrier::new(backend)),
    }
}

/// Wrap a physical `Backend` in the ciphertext-only read cache when the
/// operator has enabled `cache.secret_cache_ttl_secs > 0`. Returns the
/// original `Arc` unchanged when caching is disabled so no decorator is
/// installed at all — callers pay zero overhead in the default config.
///
/// The decorator implements `Backend`, which is the physical layer below
/// the barrier. By construction it can only see whatever bytes are
/// handed to `Backend::put` and returned by `Backend::get` — i.e. AEAD
/// ciphertext under normal barrier-backed operation. See
/// `src/cache/secret_cache.rs` for the full security invariants.
pub fn wrap_with_cache(
    backend: Arc<dyn Backend>,
    cache_config: &crate::cache::CacheConfig,
) -> Result<Arc<dyn Backend>, RvError> {
    if cache_config.secret_cache_ttl_secs == 0 {
        return Ok(backend);
    }
    let decorator = crate::cache::CachingBackend::new(
        backend,
        cache_config.secret_cache_size,
        cache_config.secret_cache_ttl_secs,
    )?;
    Ok(Arc::new(decorator))
}

/// The backend conformance suite: every physical backend runs the same
/// CRUD / list-prefix assertions against itself. Exposed under
/// `test-support` as well as `test` because the root crate's two
/// multi-process backend tests (which need its `bvault` CLI harness) run
/// these same assertions.
#[cfg(any(test, feature = "test-support"))]
pub mod test {
    use crate::{Backend, BackendEntry};

    // `test_new_backend` used to live here. It moved to the `dispatch` module
    // below because it is a plain unit test, not part of the shared suite —
    // under `test-support` without `cfg(test)` it would compile to nothing but
    // unused imports.

    #[maybe_async::maybe_async]
    pub async fn test_backend_curd(backend: &dyn Backend) {
        // Should be empty
        let keys = backend.list("").await;
        assert!(keys.is_ok());
        assert_eq!(keys.unwrap().len(), 0);

        let keys = backend.list("bar").await;
        assert!(keys.is_ok());
        assert_eq!(keys.unwrap().len(), 0);

        // Delete should work if it does not exist
        let res = backend.delete("bar").await;
        assert!(res.is_ok());

        // Get should work, but result is None
        let res = backend.get("bar").await;
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), None);

        // Make an Entry
        let entry = BackendEntry { key: "bar".to_string(), value: "test".as_bytes().to_vec() };

        let res = backend.put(&entry).await;
        assert!(res.is_ok());

        // Get should ok
        let res = backend.get("bar").await;
        assert!(res.is_ok());
        match res.unwrap() {
            Some(e) => {
                assert_eq!(e, entry);
            }
            None => panic!("Get should ok!"),
        }

        // List should not be empty
        let keys = backend.list("").await;
        assert!(keys.is_ok());
        let keys = keys.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], "bar".to_string());

        // Delete should ok
        let res = backend.delete("bar").await;
        assert!(res.is_ok());

        // List should be empty
        let keys = backend.list("").await;
        assert!(keys.is_ok());
        let keys = keys.unwrap();
        assert_eq!(keys.len(), 0);

        // Get should work, but result is None
        let res = backend.get("bar").await;
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), None);
    }

    #[maybe_async::maybe_async]
    pub async fn test_backend_list_prefix(backend: &dyn Backend) {
        let entry1 = BackendEntry { key: "bar".to_string(), value: "test".as_bytes().to_vec() };
        let entry2 = BackendEntry { key: "bar/foo".to_string(), value: "test".as_bytes().to_vec() };
        let entry3 = BackendEntry { key: "bar/foo/goo".to_string(), value: "test".as_bytes().to_vec() };

        let res = backend.put(&entry1).await;
        assert!(res.is_ok());

        let res = backend.put(&entry2).await;
        assert!(res.is_ok());

        let res = backend.put(&entry3).await;
        assert!(res.is_ok());

        // Scan the root
        let keys = backend.list("").await;
        assert!(keys.is_ok());
        let keys = keys.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.join("") == "barbar/" || keys.join("") == "bar/bar");

        // Scan bar/
        let keys = backend.list("bar/").await;
        assert!(keys.is_ok());
        let keys = keys.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.join("") == "foofoo/" || keys.join("") == "foo/foo");

        // Scan bar/foo/
        let keys = backend.list("bar/foo/").await;
        assert!(keys.is_ok());
        let keys = keys.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], "goo".to_string());
    }

    /// Cross-backend contract: a prefix is matched **literally**.
    ///
    /// SQL-backed backends translate the prefix into a `LIKE` pattern,
    /// where `_` matches any single character and `%` any sequence —
    /// and vault keys carry `_` routinely. A backend that leaks the
    /// over-matched rows hands the caller keys from a sibling subtree,
    /// so every backend must be held to the same literal-prefix rule.
    #[maybe_async::maybe_async]
    pub async fn test_backend_list_prefix_is_literal(backend: &dyn Backend) {
        for key in [
            "pfx/my_app/db",
            "pfx/my_app/nested/token",
            // Matches `pfx/my_app/%` only because `_` is a wildcard.
            "pfx/myXapp/db",
            // Same, for `%`.
            "pfx/my%app/db",
        ] {
            let entry = BackendEntry { key: key.to_string(), value: b"v".to_vec() };
            assert!(backend.put(&entry).await.is_ok());
        }

        let mut keys = backend.list("pfx/my_app/").await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["db".to_string(), "nested/".to_string()]);

        let keys = backend.list("pfx/my%app/").await.unwrap();
        assert_eq!(keys, vec!["db".to_string()]);

        let mut keys = backend.list("pfx/").await.unwrap();
        keys.sort();
        assert_eq!(
            keys,
            vec!["my%app/".to_string(), "myXapp/".to_string(), "my_app/".to_string()]
        );

        // `scan` walks the same prefix and must agree with `list`.
        let mut scanned: Vec<String> =
            backend.scan("pfx/my_app/", None).await.unwrap().into_iter().map(|e| e.key).collect();
        scanned.sort();
        assert_eq!(
            scanned,
            vec!["pfx/my_app/db".to_string(), "pfx/my_app/nested/token".to_string()]
        );
    }
}

#[cfg(test)]
mod dispatch {
    use std::{collections::HashMap, env, fs};

    use serde_json::Value;

    use crate::{new_backend, test_support::TEST_DIR};

    #[test]
    fn test_new_backend() {
        let dir = env::temp_dir().join(TEST_DIR).join("new_backend");
        let _ = fs::remove_dir_all(&dir);
        assert!(fs::create_dir_all(&dir).is_ok());

        let mut conf: HashMap<String, Value> = HashMap::new();
        conf.insert("path".to_string(), Value::String(dir.to_string_lossy().into_owned()));

        let backend = new_backend("file", &conf);
        assert!(backend.is_ok());

        let backend = new_backend("foo", &conf);
        assert!(backend.is_err());
    }
}
