//! Plugin Extensibility v1 — client-side surface cache.
//!
//! The cache stores `ActiveSurfaceBundle` payloads on disk so the
//! GUI can render plugin menus and forms without round-tripping the
//! server on every page navigation. Asset bytes (form-hook WASM
//! today) are content-addressed so re-uploading the same asset under
//! a new plugin version is a no-op rather than a duplicated copy.
//!
//! Layout (`<root>` = `<dirs::cache>/com.bastionvault.gui/plugins`):
//!
//! ```text
//! <root>/<vault-id>/_meta.json                 — { etag, fetched_at, plugins: [...] }
//! <root>/<vault-id>/_assets/<sha256>.bin       — content-addressed assets
//! <root>/<vault-id>/<plugin-name>/<version>/
//!     surface.json                             — pinned surface bytes
//! ```
//!
//! `<vault-id>` is the SHA-256 of the vault's address + identifier
//! so two vaults sharing a `dirs::cache` don't collide.
//!
//! The cache is **safe to delete at any time.** A missing or corrupt
//! cache directory degrades to a full re-fetch.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bv_plugin_surface::ActiveSurfaceBundle;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    backend::{Backend, SurfaceFetch},
    error::ClientError,
};

/// On-disk cache index. Lives at `<vault-cache>/_meta.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SurfaceCacheMeta {
    /// ETag returned by the server on the last successful fetch.
    /// Sent back as `If-None-Match` to short-circuit unchanged
    /// bundles to a 304.
    #[serde(default)]
    pub etag: String,
    /// Unix-millis timestamp of the last successful fetch.
    #[serde(default)]
    pub fetched_at_ms: u64,
    /// `(plugin, version, surface_sha256, [asset_sha256, ...])`
    /// snapshot — used for tombstoning evicted entries on the next
    /// fetch and for surfaces sanity-check on read.
    #[serde(default)]
    pub plugins: Vec<CachedPluginSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedPluginSnapshot {
    pub plugin: String,
    pub version: String,
    pub surface_sha256: String,
    /// Asset hashes referenced by this version's surface.
    #[serde(default)]
    pub asset_hashes: Vec<String>,
}

/// On-disk cache rooted at a per-vault directory. Cheap to clone —
/// state lives on disk; this struct is just a typed `PathBuf`.
#[derive(Debug, Clone)]
pub struct SurfaceCache {
    root: PathBuf,
}

impl SurfaceCache {
    /// Build a cache at `<base>/<vault-id>/`. `base` is typically
    /// `dirs::cache_dir().join("com.bastionvault.gui/plugins")`.
    /// `vault_id` should be the result of [`vault_id_for`] so two
    /// vaults sharing a `base` don't collide.
    pub fn new<P: Into<PathBuf>>(base: P, vault_id: &str) -> Self {
        let root = base.into().join(vault_id);
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn meta_path(&self) -> PathBuf {
        self.root.join("_meta.json")
    }

    pub fn assets_dir(&self) -> PathBuf {
        self.root.join("_assets")
    }

    fn surface_path(&self, plugin: &str, version: &str) -> PathBuf {
        self.root.join(plugin).join(version).join("surface.json")
    }

    fn asset_path(&self, sha256: &str) -> PathBuf {
        self.assets_dir().join(format!("{sha256}.bin"))
    }

    /// Read the cache index. Returns the default (empty) meta on a
    /// missing or corrupt file — a corrupt cache shouldn't block
    /// the GUI from running, just from short-circuiting fetches.
    pub fn read_meta(&self) -> SurfaceCacheMeta {
        match std::fs::read(self.meta_path()) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_default(),
            Err(_) => SurfaceCacheMeta::default(),
        }
    }

    /// Read the bundle assembled from cached surfaces for the given
    /// snapshot. Returns `None` if any snapshot entry is missing
    /// from disk or fails the hash check — that drops the cache to
    /// a cold state and forces the next fetch to re-download.
    pub fn read_bundle(&self) -> Option<ActiveSurfaceBundle> {
        let meta = self.read_meta();
        if meta.plugins.is_empty() && meta.etag.is_empty() {
            return None;
        }
        let mut entries = Vec::with_capacity(meta.plugins.len());
        for snap in &meta.plugins {
            let bytes = std::fs::read(self.surface_path(&snap.plugin, &snap.version)).ok()?;
            if !verify_hash(&bytes, &snap.surface_sha256) {
                return None;
            }
            let surface: bv_plugin_surface::SurfaceManifest =
                serde_json::from_slice(&bytes).ok()?;
            // We don't have the mount or asset name pairs cached
            // (they live in the bundle envelope, not on the surface
            // file itself); reconstitute the assets list from the
            // snapshot — names are unknown without re-fetch, so we
            // leave `name` empty. The GUI cache layer is expected to
            // call `Backend::active_surfaces` and replace this
            // synthesised bundle whenever the etag check fails.
            entries.push(bv_plugin_surface::ActiveSurfaceEntry {
                plugin: snap.plugin.clone(),
                version: snap.version.clone(),
                mount: String::new(),
                surface,
                assets: snap
                    .asset_hashes
                    .iter()
                    .map(|h| (String::new(), h.clone()))
                    .collect(),
                // Grants and the app-module descriptor live in the
                // bundle envelope, not the cached per-plugin snapshot;
                // the GUI cache layer replaces this synthesised bundle
                // via `Backend::active_surfaces` whenever the etag check
                // fails.
                grant: None,
                app_module: None,
            });
        }
        Some(ActiveSurfaceBundle { etag: meta.etag, entries })
    }

    /// Persist a fresh bundle. Writes each plugin's `surface.json`,
    /// updates the meta index, and tombstones plugin/version
    /// directories that aren't in the new bundle.
    pub fn write_bundle(&self, bundle: &ActiveSurfaceBundle) -> Result<(), CacheError> {
        std::fs::create_dir_all(&self.root)?;
        std::fs::create_dir_all(self.assets_dir())?;

        let mut snapshots = Vec::with_capacity(bundle.entries.len());
        let mut keep_dirs: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for entry in &bundle.entries {
            let bytes = serde_json::to_vec(&entry.surface)
                .map_err(|e| CacheError::Encode(format!("surface.json: {e}")))?;
            let surface_sha256 = sha256_hex(&bytes);
            let dir = self.surface_path(&entry.plugin, &entry.version);
            if let Some(parent) = dir.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&dir, &bytes)?;
            snapshots.push(CachedPluginSnapshot {
                plugin: entry.plugin.clone(),
                version: entry.version.clone(),
                surface_sha256,
                asset_hashes: entry.assets.iter().map(|(_, h)| h.clone()).collect(),
            });
            keep_dirs
                .entry(entry.plugin.clone())
                .or_default()
                .push(entry.version.clone());
        }

        // Tombstone old plugin/version subtrees the new bundle didn't
        // declare. We do this best-effort — read errors here just mean
        // the GC didn't run; it'll catch up on the next session.
        if let Ok(read_dir) = std::fs::read_dir(&self.root) {
            for ent in read_dir.flatten() {
                let name = ent.file_name();
                let s = name.to_string_lossy();
                if s == "_meta.json" || s == "_assets" {
                    continue;
                }
                let plugin = s.to_string();
                let keep_versions = keep_dirs.get(&plugin);
                if let Some(versions) = keep_versions {
                    if let Ok(version_dirs) = std::fs::read_dir(ent.path()) {
                        for v in version_dirs.flatten() {
                            let vname = v.file_name();
                            let vstr = vname.to_string_lossy().to_string();
                            if !versions.contains(&vstr) {
                                let _ = std::fs::remove_dir_all(v.path());
                            }
                        }
                    }
                } else {
                    let _ = std::fs::remove_dir_all(ent.path());
                }
            }
        }

        let meta = SurfaceCacheMeta {
            etag: bundle.etag.clone(),
            fetched_at_ms: now_unix_ms(),
            plugins: snapshots,
        };
        let meta_bytes = serde_json::to_vec_pretty(&meta)
            .map_err(|e| CacheError::Encode(format!("_meta.json: {e}")))?;
        atomic_write(&self.meta_path(), &meta_bytes)?;
        Ok(())
    }

    /// Read an asset by content hash. Returns `None` when not cached.
    pub fn read_asset(&self, sha256: &str) -> Option<Vec<u8>> {
        let bytes = std::fs::read(self.asset_path(sha256)).ok()?;
        if verify_hash(&bytes, sha256) {
            Some(bytes)
        } else {
            // Tampered or corrupt — drop and force a re-fetch.
            let _ = std::fs::remove_file(self.asset_path(sha256));
            None
        }
    }

    /// Persist an asset by its content hash. The caller is expected
    /// to have already verified the bytes against the manifest.
    pub fn write_asset(&self, sha256: &str, bytes: &[u8]) -> Result<(), CacheError> {
        if !verify_hash(bytes, sha256) {
            return Err(CacheError::HashMismatch {
                expected: sha256.to_string(),
                actual: sha256_hex(bytes),
            });
        }
        std::fs::create_dir_all(self.assets_dir())?;
        atomic_write(&self.asset_path(sha256), bytes)?;
        Ok(())
    }

    /// Drop the entire cache for this vault.
    pub fn purge(&self) -> Result<(), CacheError> {
        if self.root.exists() {
            std::fs::remove_dir_all(&self.root)?;
        }
        Ok(())
    }
}

/// Top-level orchestration: fetch the active-surfaces bundle from
/// `backend`, cache it, and return the bundle the GUI should render.
/// On a 304 from the server, the cached bundle is returned untouched.
pub async fn refresh<B: Backend + ?Sized>(
    backend: &B,
    cache: &SurfaceCache,
    token: &str,
) -> Result<ActiveSurfaceBundle, ClientError> {
    let cached = cache.read_bundle();
    let etag = cached.as_ref().map(|b| b.etag.as_str());
    match backend.active_surfaces(token, etag).await? {
        SurfaceFetch::NotModified => match cached {
            Some(b) => Ok(b),
            None => {
                // Server said 304 but we have nothing on disk. Fall
                // through to a force-fetch by clearing our etag and
                // calling once more — defensive, shouldn't normally
                // trigger.
                match backend.active_surfaces(token, None).await? {
                    SurfaceFetch::Bundle(b) => {
                        let _ = cache.write_bundle(&b);
                        Ok(b)
                    }
                    SurfaceFetch::NotModified => Ok(ActiveSurfaceBundle {
                        etag: String::new(),
                        entries: Vec::new(),
                    }),
                }
            }
        },
        SurfaceFetch::Bundle(b) => {
            // Best-effort cache write — a disk error here doesn't
            // block returning the bundle the GUI is about to render.
            let _ = cache.write_bundle(&b);
            Ok(b)
        }
    }
}

/// Plugin Extensibility v1 / Phase 5 — long-poll watcher.
///
/// Issues `watch_active_surfaces` against `backend`, blocking until
/// either the bundle ETag changes (server-side detected) or the
/// underlying transport's timeout fires. Returns the new bundle on
/// change. Returns `Ok(None)` on `SurfaceFetch::NotModified` —
/// callers typically loop on the same handle so a 304 just maps to
/// "try again with the same etag".
///
/// Intentionally separate from [`refresh`] so callers can decide
/// whether to commit the new bundle to the cache or display it
/// transiently (the GUI does both: cache write + Tauri event emit).
pub async fn watch_once<B: Backend + ?Sized>(
    backend: &B,
    cache: &SurfaceCache,
    token: &str,
) -> Result<Option<ActiveSurfaceBundle>, ClientError> {
    let cached = cache.read_bundle();
    let etag = cached.as_ref().map(|b| b.etag.as_str());
    match backend.watch_active_surfaces(token, etag).await? {
        SurfaceFetch::NotModified => Ok(None),
        SurfaceFetch::Bundle(b) => {
            // Best-effort persist; a write failure doesn't change
            // the in-memory bundle the caller is about to render.
            let _ = cache.write_bundle(&b);
            Ok(Some(b))
        }
    }
}

/// Fetch (and cache) one asset. Re-uses the on-disk copy when the
/// hash matches; otherwise round-trips the server.
pub async fn ensure_asset<B: Backend + ?Sized>(
    backend: &B,
    cache: &SurfaceCache,
    plugin: &str,
    version: &str,
    sha256: &str,
    token: &str,
) -> Result<Option<Vec<u8>>, ClientError> {
    if let Some(bytes) = cache.read_asset(sha256) {
        return Ok(Some(bytes));
    }
    match backend.fetch_asset(plugin, version, sha256, token).await? {
        Some(bytes) => {
            let _ = cache.write_asset(sha256, &bytes);
            Ok(Some(bytes))
        }
        None => Ok(None),
    }
}

/// Stable per-vault identifier. SHA-256 of `address || \0 || identifier`
/// hex-encoded, truncated to 32 chars. Operators don't see this, so a
/// short prefix is fine and keeps directory names readable.
pub fn vault_id_for(address: &str, identifier: &str) -> String {
    let mut h = Sha256::new();
    h.update(address.as_bytes());
    h.update([0u8]);
    h.update(identifier.as_bytes());
    let digest = hex::encode(h.finalize());
    digest[..32].to_string()
}

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("encode: {0}")]
    Encode(String),
    #[error("asset hash mismatch: expected `{expected}`, got `{actual}`")]
    HashMismatch { expected: String, actual: String },
}

// ── Helpers ──────────────────────────────────────────────────────────

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn verify_hash(bytes: &[u8], expected_hex: &str) -> bool {
    sha256_hex(bytes) == expected_hex
}

fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Write `bytes` to `path` via a `<path>.tmp` rename so a power loss
/// mid-write doesn't leave a half-written meta file behind.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), CacheError> {
    let tmp = path.with_extension("tmp");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bv_plugin_surface::{
        ActiveSurfaceEntry, SurfaceBinding, SurfaceColumn, SurfaceComponent, SurfaceManifest,
        SurfaceMenu, SurfaceOp, SurfacePage, SurfaceSection, SurfaceTable,
    };
    use serde_json::{Map, Value};

    use crate::types::{JsonResponse, Operation};

    /// In-memory stub backend. `surface_calls` records the etags it
    /// was asked with so tests can assert on the cache short-circuit.
    struct StubBackend {
        bundles: std::sync::Mutex<Vec<ActiveSurfaceBundle>>,
        assets: std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
        surface_calls: std::sync::Mutex<Vec<Option<String>>>,
        asset_calls: std::sync::Mutex<Vec<String>>,
        idx: std::sync::Mutex<usize>,
    }

    impl StubBackend {
        fn new(bundles: Vec<ActiveSurfaceBundle>) -> Self {
            Self {
                bundles: std::sync::Mutex::new(bundles),
                assets: std::sync::Mutex::new(Default::default()),
                surface_calls: std::sync::Mutex::new(Vec::new()),
                asset_calls: std::sync::Mutex::new(Vec::new()),
                idx: std::sync::Mutex::new(0),
            }
        }
        fn put_asset(&self, sha: &str, bytes: Vec<u8>) {
            self.assets.lock().unwrap().insert(sha.to_string(), bytes);
        }
    }

    #[async_trait]
    impl Backend for StubBackend {
        async fn handle(
            &self,
            _op: Operation,
            _path: &str,
            _body: Option<Map<String, Value>>,
            _token: &str,
        ) -> Result<Option<JsonResponse>, ClientError> {
            unimplemented!("stub doesn't dispatch logical requests")
        }

        async fn active_surfaces(
            &self,
            _token: &str,
            etag: Option<&str>,
        ) -> Result<SurfaceFetch, ClientError> {
            self.surface_calls
                .lock()
                .unwrap()
                .push(etag.map(|s| s.to_string()));
            let mut idx = self.idx.lock().unwrap();
            let bundles = self.bundles.lock().unwrap();
            let next = bundles.get(*idx).cloned().unwrap_or_else(|| ActiveSurfaceBundle {
                etag: "empty".into(),
                entries: vec![],
            });
            *idx += 1;
            // If etag matches the next bundle, return NotModified.
            if let Some(e) = etag {
                if e == next.etag {
                    return Ok(SurfaceFetch::NotModified);
                }
            }
            Ok(SurfaceFetch::Bundle(next))
        }

        async fn fetch_asset(
            &self,
            _plugin: &str,
            _version: &str,
            sha256: &str,
            _token: &str,
        ) -> Result<Option<Vec<u8>>, ClientError> {
            self.asset_calls.lock().unwrap().push(sha256.to_string());
            Ok(self.assets.lock().unwrap().get(sha256).cloned())
        }
    }

    fn sample_surface(plugin: &str) -> SurfaceManifest {
        SurfaceManifest {
            schema_version: 1,
            title: plugin.to_string(),
            icon: String::new(),
            menus: vec![SurfaceMenu {
                id: format!("{plugin}.main"),
                label: "Main".into(),
                icon: String::new(),
                section: SurfaceSection::Secrets,
                route: format!("/plugin/{plugin}/codes"),
                min_policy: String::new(),
            }],
            pages: vec![SurfacePage {
                route: format!("/plugin/{plugin}/codes"),
                title: "Codes".into(),
                components: vec![SurfaceComponent::Table(SurfaceTable {
                    id: format!("{plugin}.list"),
                    binding: SurfaceBinding {
                        op: SurfaceOp::List,
                        path: "{mount}/codes".into(),
                    },
                    columns: vec![SurfaceColumn {
                        field: "name".into(),
                        label: "Name".into(),
                    }],
                    row_actions: vec![],
                    empty_text: String::new(),
                })],
            }],
            config_form: None,
        }
    }

    fn bundle_with(plugin: &str, etag: &str) -> ActiveSurfaceBundle {
        let entry = ActiveSurfaceEntry {
            plugin: plugin.to_string(),
            version: "1.0.0".to_string(),
            mount: format!("secret/{plugin}"),
            surface: sample_surface(plugin),
            assets: vec![],
            grant: None,
            app_module: None,
        };
        ActiveSurfaceBundle {
            etag: etag.to_string(),
            entries: vec![entry],
        }
    }

    #[tokio::test]
    async fn cold_cache_writes_and_reads_back() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SurfaceCache::new(tmp.path(), "vault-a");
        let backend = StubBackend::new(vec![bundle_with("totp", "etag-1")]);
        let bundle = refresh(&backend, &cache, "tok").await.unwrap();
        assert_eq!(bundle.etag, "etag-1");
        assert_eq!(bundle.entries.len(), 1);

        // Backend got called with no etag (cold cache).
        let calls = backend.surface_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], None);

        // Meta + surface file landed on disk.
        assert!(cache.meta_path().exists());
        assert!(cache.root().join("totp/1.0.0/surface.json").exists());
    }

    #[tokio::test]
    async fn warm_cache_sends_etag_and_short_circuits() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SurfaceCache::new(tmp.path(), "vault-a");
        // Two refreshes against a backend that responds with the same
        // etag both times — second call should round-trip with the
        // etag and resolve via NotModified.
        let backend =
            StubBackend::new(vec![bundle_with("totp", "etag-1"), bundle_with("totp", "etag-1")]);
        let _ = refresh(&backend, &cache, "tok").await.unwrap();
        let bundle = refresh(&backend, &cache, "tok").await.unwrap();
        assert_eq!(bundle.etag, "etag-1");

        let calls = backend.surface_calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], None);
        assert_eq!(calls[1].as_deref(), Some("etag-1"));
    }

    #[tokio::test]
    async fn etag_change_swaps_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SurfaceCache::new(tmp.path(), "vault-a");
        let backend = StubBackend::new(vec![
            bundle_with("totp", "etag-1"),
            bundle_with("totp", "etag-2"),
        ]);
        let _ = refresh(&backend, &cache, "tok").await.unwrap();
        let bundle = refresh(&backend, &cache, "tok").await.unwrap();
        assert_eq!(bundle.etag, "etag-2");
        // Cache picked up the new etag.
        let meta = cache.read_meta();
        assert_eq!(meta.etag, "etag-2");
    }

    #[tokio::test]
    async fn corrupt_surface_falls_back_to_cold_fetch() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SurfaceCache::new(tmp.path(), "vault-a");
        let backend = StubBackend::new(vec![
            bundle_with("totp", "etag-1"),
            bundle_with("totp", "etag-1"),
        ]);
        let _ = refresh(&backend, &cache, "tok").await.unwrap();

        // Tamper: rewrite the cached surface with random bytes. The
        // hash check on read should reject it; the next refresh must
        // re-fetch with no etag (cold-cache path).
        let surface_path = cache.root().join("totp/1.0.0/surface.json");
        std::fs::write(&surface_path, b"not-json").unwrap();

        let bundle = refresh(&backend, &cache, "tok").await.unwrap();
        // Got a fresh bundle from the second response.
        assert_eq!(bundle.etag, "etag-1");
        let calls = backend.surface_calls.lock().unwrap();
        // First fetch (cold) + second fetch which had to ignore the
        // corrupt cache and re-issue without an etag.
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], None);
        assert_eq!(calls[1], None);
    }

    #[tokio::test]
    async fn evicted_plugin_directory_is_tombstoned() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SurfaceCache::new(tmp.path(), "vault-a");
        let mut bundle_a = bundle_with("totp", "etag-1");
        bundle_a.entries.push(ActiveSurfaceEntry {
            plugin: "extra".into(),
            version: "0.1.0".into(),
            mount: "secret/extra".into(),
            surface: sample_surface("extra"),
            assets: vec![],
            grant: None,
            app_module: None,
        });
        bundle_a.etag = ActiveSurfaceBundle::compute_etag(&bundle_a.entries);
        let bundle_b = bundle_with("totp", "etag-2");

        let backend = StubBackend::new(vec![bundle_a.clone(), bundle_b]);
        let _ = refresh(&backend, &cache, "tok").await.unwrap();
        assert!(cache.root().join("extra/0.1.0/surface.json").exists());

        let _ = refresh(&backend, &cache, "tok").await.unwrap();
        // After the second refresh, "extra" is no longer in the
        // bundle and its directory should be cleaned up.
        assert!(!cache.root().join("extra").exists());
        assert!(cache.root().join("totp/1.0.0/surface.json").exists());
    }

    #[tokio::test]
    async fn ensure_asset_caches_then_serves_locally() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SurfaceCache::new(tmp.path(), "vault-a");
        let asset = b"\x00asm\x01\x00\x00\x00 (mock wasm)".to_vec();
        let h = sha256_hex(&asset);
        let backend = StubBackend::new(vec![]);
        backend.put_asset(&h, asset.clone());

        let got1 = ensure_asset(&backend, &cache, "totp", "1.0.0", &h, "tok")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got1, asset);

        let got2 = ensure_asset(&backend, &cache, "totp", "1.0.0", &h, "tok")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got2, asset);

        // Backend was hit once; the second call resolved from cache.
        let asset_calls = backend.asset_calls.lock().unwrap();
        assert_eq!(asset_calls.len(), 1);
    }

    #[tokio::test]
    async fn write_asset_rejects_hash_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SurfaceCache::new(tmp.path(), "vault-a");
        let err = cache
            .write_asset(&"a".repeat(64), b"different bytes")
            .unwrap_err();
        assert!(matches!(err, CacheError::HashMismatch { .. }));
    }

    #[tokio::test]
    async fn watch_once_returns_new_bundle_when_etag_changed() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SurfaceCache::new(tmp.path(), "vault-a");
        let backend = StubBackend::new(vec![
            bundle_with("totp", "etag-1"),
            bundle_with("totp", "etag-2"),
        ]);
        // Seed the cache with etag-1 so watch_once can compare.
        let _ = refresh(&backend, &cache, "tok").await.unwrap();
        // Now the stub will hand back etag-2 — watch_once should
        // return Some(bundle) and the cache should advance. The
        // default `watch_active_surfaces` impl delegates to
        // `active_surfaces`, so the stub serves the next queued
        // bundle exactly the way it does for `refresh`.
        let got = watch_once(&backend, &cache, "tok").await.unwrap();
        assert!(got.is_some());
        assert_eq!(got.as_ref().unwrap().etag, "etag-2");
        assert_eq!(cache.read_meta().etag, "etag-2");
    }

    #[tokio::test]
    async fn watch_once_returns_none_on_unchanged_etag() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SurfaceCache::new(tmp.path(), "vault-a");
        // Both queued bundles share the same etag — the stub maps
        // matching etag to NotModified, which watch_once surfaces
        // as None to its caller.
        let backend = StubBackend::new(vec![
            bundle_with("totp", "etag-1"),
            bundle_with("totp", "etag-1"),
        ]);
        let _ = refresh(&backend, &cache, "tok").await.unwrap();
        let got = watch_once(&backend, &cache, "tok").await.unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn vault_id_is_stable_and_collision_resistant() {
        let a = vault_id_for("https://a.example", "v1");
        let b = vault_id_for("https://b.example", "v1");
        let c = vault_id_for("https://a.example", "v1");
        assert_eq!(a.len(), 32);
        assert_eq!(a, c);
        assert_ne!(a, b);
    }
}
