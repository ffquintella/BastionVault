//! Encrypted File storage backend — Phase-1 refactor.
//!
//! `FileBackend` is now a thin wrapper around an `Arc<dyn FileTarget>`.
//! The target is the pluggable I/O primitive that decides *where* the
//! serialized `BackendEntry` JSON bytes actually live. Today the only
//! implementor is `LocalFsTarget` (carrying the exact behavior of the
//! pre-refactor backend); later phases of
//! `features/cloud-storage-backend.md` add S3 / OneDrive / Google
//! Drive / Dropbox targets without touching this file, the barrier,
//! or the storage schema.
//!
//! The public API is unchanged: `FileBackend::new(conf)` still takes
//! the same config map and every existing `Backend` consumer sees
//! identical behavior. `target = "local"` is the default when the
//! field is absent, so existing configs that only set `path = "..."`
//! keep working bit-for-bit.

use std::{any::Any, collections::HashMap, sync::Arc};

use serde_json::Value;

use crate::{
    errors::RvError,
    storage::{Backend, BackendEntry},
};

pub mod cache;
pub mod creds;
pub mod local;
pub mod obfuscate;
pub mod target;
#[cfg(feature = "cloud_s3")]
pub mod s3;
#[cfg(feature = "cloud_onedrive")]
pub mod onedrive;
#[cfg(feature = "cloud_gdrive")]
pub mod gdrive;
#[cfg(feature = "cloud_dropbox")]
pub mod dropbox;
pub mod oauth;

pub use local::LocalFsTarget;
pub use target::FileTarget;

/// Build a `CacheConfig` from the target's config map. Parses the
/// optional `cache_read_ttl_secs`, `cache_list_ttl_secs`,
/// `cache_max_entries`, `cache_max_bytes` keys; missing keys fall
/// through to the `CacheConfig::default` values documented in
/// `cache.rs`.
fn cache_config_from(conf: &HashMap<String, Value>) -> cache::CacheConfig {
    let mut cfg = cache::CacheConfig::default();
    if let Some(n) = conf.get("cache_read_ttl_secs").and_then(|v| v.as_u64()) {
        cfg.read_ttl = std::time::Duration::from_secs(n);
    }
    if let Some(n) = conf.get("cache_list_ttl_secs").and_then(|v| v.as_u64()) {
        cfg.list_ttl = std::time::Duration::from_secs(n);
    }
    if let Some(n) = conf.get("cache_max_entries").and_then(|v| v.as_u64()) {
        cfg.max_entries = n as usize;
    }
    if let Some(n) = conf.get("cache_max_bytes").and_then(|v| v.as_u64()) {
        cfg.max_bytes = n;
    }
    // Stale-while-revalidate threshold. `0.5` means entries proactively
    // refresh halfway through their TTL. Clamped into `[0,1]` by the
    // cache ctor, so hand-edited configs can't break it.
    if let Some(n) = conf.get("cache_stale_ratio").and_then(|v| v.as_f64()) {
        cfg.stale_ratio = n as f32;
    }
    // Opt-in background prefetch. Accepts either a JSON array of
    // strings or a comma-separated string for CLI-friendliness.
    if let Some(v) = conf.get("cache_prefetch_keys") {
        cfg.prefetch_keys = match v {
            Value::Array(a) => a
                .iter()
                .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
                .filter(|s| !s.is_empty())
                .collect(),
            Value::String(s) => s
                .split(',')
                .map(|p| p.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            _ => Vec::new(),
        };
    }
    if let Some(n) = conf
        .get("cache_prefetch_concurrency")
        .and_then(|v| v.as_u64())
    {
        cfg.prefetch_concurrency = n as usize;
    }
    cfg
}

/// Whether the cache decorator should wrap a target of kind `kind`.
/// Defaults to on for every cloud kind (S3 / OneDrive / Google Drive
/// / Dropbox) because those are the latency-dominant case, and off
/// for `local` because the local filesystem already serves faster
/// than the cache's own lookup. Explicit `cache = true`/`false` in
/// config overrides the default in either direction.
fn cache_enabled_for(kind: &str, conf: &HashMap<String, Value>) -> bool {
    if let Some(explicit) = conf.get("cache").and_then(|v| v.as_bool()) {
        return explicit;
    }
    matches!(kind, "s3" | "onedrive" | "gdrive" | "dropbox")
}

#[derive(Debug)]
pub struct FileBackend {
    target: Arc<dyn FileTarget>,
}

impl FileBackend {
    /// Construct a `FileBackend` from a raw config map.
    ///
    /// `target` selects the target kind (`"local"` is the default
    /// and the only option in Phase 1). Target-specific keys are
    /// parsed by the target's own constructor.
    pub fn new(conf: &HashMap<String, Value>) -> Result<Self, RvError> {
        let kind = conf
            .get("target")
            .and_then(|v| v.as_str())
            .unwrap_or("local");
        let use_cache = cache_enabled_for(kind, conf);

        // Loud warning when `obfuscate_keys` is set through the
        // sync path — the salt bootstrap needs async I/O, so this
        // code path can't honour the flag. Callers who need
        // obfuscation use `new_maybe_obfuscated` from async context.
        if conf
            .get("obfuscate_keys")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            log::warn!(
                "file backend: `obfuscate_keys = true` is set but this construction path \
                 cannot honor it. Use the async `new_maybe_obfuscated` constructor (or ensure \
                 your bootstrap chain routes through it) to enable key obfuscation."
            );
        }

        match kind {
            "local" => {
                let path = conf
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or(RvError::ErrPhysicalConfigItemMissing)?;
                let target = LocalFsTarget::new(path.into())?;
                Ok(Self { target: Arc::new(target) })
            }
            #[cfg(feature = "cloud_s3")]
            "s3" => {
                let target = s3::S3Target::from_config(conf)?;
                Ok(Self { target: Arc::new(target) })
            }
            #[cfg(not(feature = "cloud_s3"))]
            "s3" => Err(RvError::ErrString(
                "file target `s3` requires the `cloud_s3` build feature".into(),
            )),
            #[cfg(feature = "cloud_onedrive")]
            "onedrive" => {
                let target = onedrive::OneDriveTarget::from_config(conf)?;
                Ok(Self { target: Arc::new(target) })
            }
            #[cfg(not(feature = "cloud_onedrive"))]
            "onedrive" => Err(RvError::ErrString(
                "file target `onedrive` requires the `cloud_onedrive` build feature".into(),
            )),
            #[cfg(feature = "cloud_gdrive")]
            "gdrive" => {
                let target = gdrive::GoogleDriveTarget::from_config(conf)?;
                Ok(Self { target: Arc::new(target) })
            }
            #[cfg(not(feature = "cloud_gdrive"))]
            "gdrive" => Err(RvError::ErrString(
                "file target `gdrive` requires the `cloud_gdrive` build feature".into(),
            )),
            #[cfg(feature = "cloud_dropbox")]
            "dropbox" => {
                let target = dropbox::DropboxTarget::from_config(conf)?;
                Ok(Self { target: Arc::new(target) })
            }
            #[cfg(not(feature = "cloud_dropbox"))]
            "dropbox" => Err(RvError::ErrString(
                "file target `dropbox` requires the `cloud_dropbox` build feature".into(),
            )),
            other => {
                log::error!("unknown file target kind: {other}");
                return Err(RvError::ErrPhysicalConfigItemMissing);
            }
        }
        .map(|b: Self| {
            if use_cache {
                let cfg = cache_config_from(conf);
                Self {
                    target: Arc::new(cache::CachingTarget::new(b.target, cfg)),
                }
            } else {
                b
            }
        })
    }

    /// Test hook / future-phase hook: construct a `FileBackend` from
    /// an already-built target. Used by unit tests that want to
    /// exercise the backend against a stub target, and by cloud
    /// phases that construct their targets out-of-band.
    pub fn from_target(target: Arc<dyn FileTarget>) -> Self {
        Self { target }
    }

    /// Async convenience constructor that wraps the base target
    /// with `ObfuscatingTarget` when `obfuscate_keys = true` is set
    /// in config.
    ///
    /// Separate from the sync `new` because bootstrapping the
    /// obfuscation salt requires at least one async call against
    /// the wrapped target (read the salt key; mint + write one if
    /// absent). Callers who construct `FileBackend` inside an
    /// async context pick this up via `new_maybe_obfuscated`; the
    /// sync `new` path ignores `obfuscate_keys` entirely and logs
    /// a warning so a misconfigured config is loud rather than
    /// silently degraded.
    pub async fn new_maybe_obfuscated(
        conf: &HashMap<String, Value>,
    ) -> Result<Self, RvError> {
        let base = Self::new(conf)?;
        let obfuscate = conf
            .get("obfuscate_keys")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !obfuscate {
            return Ok(base);
        }
        let wrapped = obfuscate::ObfuscatingTarget::bootstrap(base.target.clone()).await?;
        Ok(Self {
            target: Arc::new(wrapped),
        })
    }
}

#[maybe_async::maybe_async]
impl Backend for FileBackend {
    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        self.target.list(prefix).await
    }

    async fn get(&self, key: &str) -> Result<Option<BackendEntry>, RvError> {
        match self.target.read(key).await? {
            Some(bytes) => {
                // The JSON payload is what the pre-refactor backend
                // wrote directly to disk. Keeping the serialization
                // on this side of the trait means cloud targets in
                // later phases receive the same bytes that currently
                // land on disk, with zero divergence in at-rest
                // format — important for `operator migrate` round-
                // trips between target kinds.
                let s = std::str::from_utf8(&bytes)
                    .map_err(|e| RvError::ErrString(format!("file backend: invalid utf-8: {e}")))?;
                let entry: BackendEntry = serde_json::from_str(s)?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    async fn put(&self, entry: &BackendEntry) -> Result<(), RvError> {
        let k = entry.key.as_str();
        let serialized = serde_json::to_vec(entry)?;
        let _lock = self.target.lock(k).await?;
        self.target.write(k, &serialized).await
    }

    async fn delete(&self, key: &str) -> Result<(), RvError> {
        let _lock = self.target.lock(key).await?;
        self.target.delete(key).await
    }

    async fn lock(&self, lock_name: &str) -> Result<Box<dyn Any>, RvError> {
        // The trait-object re-box is necessary because `Backend::lock`
        // returns `Box<dyn Any>` (no `Send` bound) while `FileTarget::
        // lock` returns `Box<dyn Any + Send>` — we need `Send` so a
        // target implementation can return a tokio-friendly guard,
        // but the outer `Backend` trait does not require it.
        let guard = self.target.lock(lock_name).await?;
        Ok(Box::new(guard))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use super::super::super::test::{test_backend_curd, test_backend_list_prefix};
    use crate::test_utils::{
        new_test_backend, new_test_file_backend, new_test_temp_dir, test_multi_routine,
    };

    use std::sync::Mutex;

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_backend() {
        let backend = new_test_backend("test_file_backend");

        test_backend_curd(backend.as_ref()).await;
        test_backend_list_prefix(backend.as_ref()).await;
    }

    /// Drives a second vault process against the same backend via
    /// the `bvault` CLI, so the project's runnable binary must be
    /// pre-built before this test will succeed.
    ///
    /// Run with:
    ///
    /// ```sh
    /// cargo build --bin bvault
    /// cargo test --lib test_file_backend_multi_routine -- --ignored
    /// ```
    ///
    /// Marked `#[ignore]` so a plain `cargo test` doesn't surface a
    /// spawn failure that actually means "the operator forgot to
    /// build the bin." The MySQL sibling at `mysql_backend.rs` has
    /// the same prerequisite and is only run behind the
    /// `storage_mysql` feature flag, which similarly gates it from
    /// default test runs.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    #[ignore]
    async fn test_file_backend_multi_routine() {
        let dir = new_test_temp_dir("test_file_backend_multi_routine");
        let backend = new_test_file_backend(&dir);
        test_multi_routine(backend);
    }

    /// Recording target — stores bytes in a `HashMap` so tests can
    /// inspect exactly what `FileBackend` hands to the target. Anchors
    /// the Phase-1 seam: if this passes, Phase-2 cloud targets only
    /// need to implement `FileTarget` correctly to plug in.
    #[derive(Debug, Default)]
    struct RecordingTarget {
        writes: Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
    }

    #[maybe_async::maybe_async]
    impl FileTarget for RecordingTarget {
        async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, RvError> {
            Ok(self.writes.lock().unwrap().get(key).cloned())
        }
        async fn write(&self, key: &str, value: &[u8]) -> Result<(), RvError> {
            self.writes.lock().unwrap().insert(key.to_string(), value.to_vec());
            Ok(())
        }
        async fn delete(&self, key: &str) -> Result<(), RvError> {
            self.writes.lock().unwrap().remove(key);
            Ok(())
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
            Ok(self
                .writes
                .lock()
                .unwrap()
                .keys()
                .filter_map(|k| k.strip_prefix(prefix).map(|s| s.to_string()))
                .collect())
        }
        async fn lock(&self, _: &str) -> Result<Box<dyn Any + Send>, RvError> {
            Ok(Box::new(()))
        }
    }

    /// Phase 8 library piece: when `obfuscate_keys = true` is set on
    /// a local target, the resulting `FileBackend` stores ciphertext
    /// under HMAC'd file names on disk — the plaintext key never
    /// appears in the filesystem. Round-trips still work because
    /// the decorator re-hashes on read.
    #[tokio::test]
    async fn test_file_backend_honors_obfuscate_keys() {
        let dir = new_test_temp_dir("test_file_backend_obfuscate");
        let mut conf: std::collections::HashMap<String, serde_json::Value> =
            std::collections::HashMap::new();
        conf.insert(
            "path".into(),
            serde_json::Value::String(dir.clone()),
        );
        conf.insert(
            "obfuscate_keys".into(),
            serde_json::Value::Bool(true),
        );

        let backend = FileBackend::new_maybe_obfuscated(&conf).await.unwrap();
        let entry = BackendEntry {
            key: "sys/policy/admin".to_string(),
            value: b"encrypted-payload".to_vec(),
        };
        backend.put(&entry).await.unwrap();
        let got = backend.get("sys/policy/admin").await.unwrap().unwrap();
        assert_eq!(got, entry);

        // Scan the underlying dir: the plaintext key must not appear
        // as a path component. The salt marker (`_bvault_salt`) is
        // an acceptable resident.
        fn walk_names(root: &std::path::Path, out: &mut Vec<String>) {
            if let Ok(entries) = std::fs::read_dir(root) {
                for e in entries.flatten() {
                    out.push(e.file_name().to_string_lossy().into_owned());
                    let p = e.path();
                    if p.is_dir() {
                        walk_names(&p, out);
                    }
                }
            }
        }
        let mut names = Vec::new();
        walk_names(std::path::Path::new(&dir), &mut names);
        for n in &names {
            assert!(
                !n.contains("policy") && !n.contains("admin"),
                "plaintext key component `{n}` found on disk; obfuscation didn't apply (all: {names:?})"
            );
        }
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_backend_delegates_to_target() {
        let target = Arc::new(RecordingTarget::default());
        let backend = FileBackend::from_target(target.clone());

        // put -> target receives serialized JSON bytes
        let entry = BackendEntry {
            key: "sys/foo".to_string(),
            value: b"ciphertext-ish".to_vec(),
        };
        backend.put(&entry).await.unwrap();

        let raw = target.writes.lock().unwrap().get("sys/foo").cloned().unwrap();
        // Round-trips through serde: target stores JSON, backend.get
        // deserializes it back to the original entry.
        let round: BackendEntry = serde_json::from_slice(&raw).unwrap();
        assert_eq!(round, entry);

        let got = backend.get("sys/foo").await.unwrap().unwrap();
        assert_eq!(got, entry);

        // delete + miss on get
        backend.delete("sys/foo").await.unwrap();
        assert!(backend.get("sys/foo").await.unwrap().is_none());
    }
}
