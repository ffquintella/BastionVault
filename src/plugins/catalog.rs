//! Barrier-encrypted plugin catalog with versioning.
//!
//! Phase 3 introduces multi-version registration: a single plugin
//! `name` can carry several registered `version`s, with one of them
//! marked `active`. Operators stage new versions, smoke-test via the
//! invoke endpoint, then activate when ready. The previously-active
//! version stays registered and can be re-activated for a roll-back.
//!
//! Storage layout (Phase 3):
//! ```text
//! core/plugins/<name>/versions/<version>/manifest   — PluginManifest JSON
//! core/plugins/<name>/versions/<version>/binary     — raw plugin bytes
//! core/plugins/<name>/active                        — single string: active version
//! core/plugins/<name>/config                        — operator-set config (one set per name)
//! core/plugins/<name>/data/...                      — plugin's own storage scope (one set per name)
//! ```
//!
//! Config + the plugin's data slot are **per-name, not per-version**
//! by design: switching to a new version of a plugin shouldn't lose
//! its configured endpoint URL or its accumulated state. If a version
//! genuinely needs to break compatibility on its config schema, the
//! operator re-registers under a different `name`.
//!
//! ## Backward-compatible reads
//!
//! Phase-1/2 plugins were stored at the un-versioned paths
//! `core/plugins/<name>/{manifest,binary}` with no `active` pointer.
//! [`PluginCatalog::get`] / `get_manifest` / `list` transparently fall
//! back to those paths when no `active` pointer is present, so
//! existing registrations keep working without operator action.
//!
//! New `put` calls always write the versioned layout. The first
//! `put` after upgrading from Phase 1/2 will leave the legacy entries
//! in place; they are unreachable through the catalog API once the
//! new versioned entry exists, so the operator can clean them up
//! manually when convenient.

use sha2::{Digest, Sha256};

use crate::{
    errors::RvError,
    storage::{Storage, StorageEntry},
};

use super::manifest::PluginManifest;

pub const PLUGIN_PREFIX: &str = "core/plugins/";

#[derive(Debug, Clone)]
pub struct PluginRecord {
    pub manifest: PluginManifest,
    pub binary: Vec<u8>,
}

#[derive(Default, Clone)]
pub struct PluginCatalog;

impl PluginCatalog {
    pub fn new() -> Self {
        Self
    }

    pub async fn list(&self, storage: &dyn Storage) -> Result<Vec<PluginManifest>, RvError> {
        let names = storage.list(PLUGIN_PREFIX).await?;
        let mut out = Vec::with_capacity(names.len());
        for entry in names {
            // `list` returns either `<name>/` directory entries or
            // bare keys (older code wrote both shapes). Normalise.
            let name = entry.strip_suffix('/').unwrap_or(&entry).to_string();
            if name.is_empty() {
                continue;
            }
            if let Some(manifest) = self.get_manifest(storage, &name).await? {
                out.push(manifest);
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out.dedup_by(|a, b| a.name == b.name);
        Ok(out)
    }

    /// Fetch the active (or only) record for `name`.
    pub async fn get(&self, storage: &dyn Storage, name: &str) -> Result<Option<PluginRecord>, RvError> {
        let manifest = match self.get_manifest(storage, name).await? {
            Some(m) => m,
            None => return Ok(None),
        };
        let bin = match self.read_binary_for(storage, name, &manifest.version).await? {
            Some(b) => b,
            None => return Ok(None),
        };
        Self::verify_integrity(&manifest, &bin)?;
        Ok(Some(PluginRecord { manifest, binary: bin }))
    }

    pub async fn get_manifest(
        &self,
        storage: &dyn Storage,
        name: &str,
    ) -> Result<Option<PluginManifest>, RvError> {
        if let Some(active) = self.read_active(storage, name).await? {
            return self.read_versioned_manifest(storage, name, &active).await;
        }
        // Phase-1/2 fallback: no active pointer; try the un-versioned
        // path the older catalog wrote.
        self.read_legacy_manifest(storage, name).await
    }

    /// Fetch a specific version's record. Used by the GUI's "test this
    /// version before activating" workflow and the activate endpoint.
    pub async fn get_version(
        &self,
        storage: &dyn Storage,
        name: &str,
        version: &str,
    ) -> Result<Option<PluginRecord>, RvError> {
        let manifest = match self.read_versioned_manifest(storage, name, version).await? {
            Some(m) => m,
            None => return Ok(None),
        };
        let bin = match storage.get(&binary_versioned_key(name, version)).await? {
            Some(e) => e.value,
            None => return Ok(None),
        };
        Self::verify_integrity(&manifest, &bin)?;
        Ok(Some(PluginRecord { manifest, binary: bin }))
    }

    /// List every registered version of `name`, sorted ascending.
    pub async fn list_versions(
        &self,
        storage: &dyn Storage,
        name: &str,
    ) -> Result<Vec<PluginManifest>, RvError> {
        let prefix = format!("{}{}/versions/", PLUGIN_PREFIX, name);
        let entries = storage.list(&prefix).await.unwrap_or_default();
        let mut out = Vec::new();
        for entry in entries {
            let version = entry.strip_suffix('/').unwrap_or(&entry).to_string();
            if version.is_empty() {
                continue;
            }
            if let Some(m) = self.read_versioned_manifest(storage, name, &version).await? {
                out.push(m);
            }
        }
        // No `active` pointer + legacy un-versioned record present? Surface it
        // as a single-version list so the GUI doesn't show the plugin as
        // versionless.
        if out.is_empty() {
            if let Some(m) = self.read_legacy_manifest(storage, name).await? {
                out.push(m);
            }
        }
        out.sort_by(|a, b| a.version.cmp(&b.version));
        Ok(out)
    }

    /// Currently-active version string for `name`, if any. Falls back
    /// to the manifest's own `version` field for plugins still on the
    /// legacy un-versioned layout.
    pub async fn get_active_version(
        &self,
        storage: &dyn Storage,
        name: &str,
    ) -> Result<Option<String>, RvError> {
        if let Some(v) = self.read_active(storage, name).await? {
            return Ok(Some(v));
        }
        Ok(self.read_legacy_manifest(storage, name).await?.map(|m| m.version))
    }

    /// Register a new version. Sets `active = manifest.version` if the
    /// plugin is currently un-registered or if no `active` pointer is
    /// present (legacy layout); otherwise leaves the active version
    /// alone so operators can stage without flipping production.
    pub async fn put(
        &self,
        storage: &dyn Storage,
        manifest: &PluginManifest,
        binary: &[u8],
    ) -> Result<(), RvError> {
        manifest.validate().map_err(|_| RvError::ErrRequestInvalid)?;
        Self::verify_integrity(manifest, binary)?;
        // Write binary first so a half-failed registration doesn't
        // leave a manifest pointing at nothing.
        storage
            .put(&StorageEntry {
                key: binary_versioned_key(&manifest.name, &manifest.version),
                value: binary.to_vec(),
            })
            .await?;
        let manifest_bytes = serde_json::to_vec(manifest)?;
        storage
            .put(&StorageEntry {
                key: manifest_versioned_key(&manifest.name, &manifest.version),
                value: manifest_bytes,
            })
            .await?;
        // Activate when this is the first registered version (or when
        // we're upgrading from the legacy layout and there's no active
        // pointer yet).
        if self.read_active(storage, &manifest.name).await?.is_none() {
            self.set_active(storage, &manifest.name, &manifest.version).await?;
        }
        Ok(())
    }

    /// Switch the active version. Refuses to point at a version that
    /// isn't registered.
    pub async fn set_active(
        &self,
        storage: &dyn Storage,
        name: &str,
        version: &str,
    ) -> Result<(), RvError> {
        if self.read_versioned_manifest(storage, name, version).await?.is_none() {
            return Err(RvError::ErrRequestInvalid);
        }
        storage
            .put(&StorageEntry {
                key: active_key(name),
                value: version.as_bytes().to_vec(),
            })
            .await
    }

    /// Drop a single version. Refuses to delete the active version
    /// (operator must `set_active` to a different version first).
    /// Per-name shared records (config, data) are preserved.
    pub async fn delete_version(
        &self,
        storage: &dyn Storage,
        name: &str,
        version: &str,
    ) -> Result<(), RvError> {
        if let Some(active) = self.read_active(storage, name).await? {
            if active == version {
                return Err(RvError::ErrRequestInvalid);
            }
        }
        let _ = storage.delete(&binary_versioned_key(name, version)).await;
        let _ = storage.delete(&manifest_versioned_key(name, version)).await;
        Ok(())
    }

    /// Drop every version of `name` plus the per-name shared records
    /// (active pointer, config). Mirrors the pre-Phase-3 catalog
    /// `delete` semantics so the existing HTTP + GUI delete path
    /// keeps working.
    pub async fn delete(&self, storage: &dyn Storage, name: &str) -> Result<(), RvError> {
        // Drop every versioned record.
        let prefix = format!("{}{}/versions/", PLUGIN_PREFIX, name);
        if let Ok(entries) = storage.list(&prefix).await {
            for entry in entries {
                let version = entry.strip_suffix('/').unwrap_or(&entry);
                let _ = storage.delete(&binary_versioned_key(name, version)).await;
                let _ = storage.delete(&manifest_versioned_key(name, version)).await;
            }
        }
        // Active pointer + legacy entries.
        let _ = storage.delete(&active_key(name)).await;
        let _ = storage.delete(&legacy_binary_key(name)).await;
        let _ = storage.delete(&legacy_manifest_key(name)).await;
        // Config (per-name; ConfigStore.delete is the canonical path
        // but that's a separate module — replicate the prefix here).
        let _ = storage.delete(&format!("{}{}{}", PLUGIN_PREFIX, name, "/config")).await;
        Ok(())
    }

    /// Recompute sha256 over the raw binary bytes and compare with
    /// the manifest's declared digest. Also asserts size.
    pub fn verify_integrity(manifest: &PluginManifest, binary: &[u8]) -> Result<(), RvError> {
        if (binary.len() as u64) != manifest.size {
            return Err(RvError::ErrRequestInvalid);
        }
        let mut hasher = Sha256::new();
        hasher.update(binary);
        let computed = hasher.finalize();
        let expected = match hex_decode(&manifest.sha256) {
            Some(b) => b,
            None => return Err(RvError::ErrRequestInvalid),
        };
        if computed.as_slice() != expected.as_slice() {
            return Err(RvError::ErrRequestInvalid);
        }
        Ok(())
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    async fn read_active(
        &self,
        storage: &dyn Storage,
        name: &str,
    ) -> Result<Option<String>, RvError> {
        let key = active_key(name);
        match storage.get(&key).await? {
            None => Ok(None),
            Some(entry) => match String::from_utf8(entry.value) {
                Ok(s) if !s.is_empty() => Ok(Some(s)),
                _ => Ok(None),
            },
        }
    }

    async fn read_versioned_manifest(
        &self,
        storage: &dyn Storage,
        name: &str,
        version: &str,
    ) -> Result<Option<PluginManifest>, RvError> {
        match storage.get(&manifest_versioned_key(name, version)).await? {
            None => Ok(None),
            Some(entry) => serde_json::from_slice::<PluginManifest>(&entry.value)
                .map(Some)
                .map_err(|_| RvError::ErrRequestInvalid),
        }
    }

    async fn read_legacy_manifest(
        &self,
        storage: &dyn Storage,
        name: &str,
    ) -> Result<Option<PluginManifest>, RvError> {
        match storage.get(&legacy_manifest_key(name)).await? {
            None => Ok(None),
            Some(entry) => serde_json::from_slice::<PluginManifest>(&entry.value)
                .map(Some)
                .map_err(|_| RvError::ErrRequestInvalid),
        }
    }

    async fn read_binary_for(
        &self,
        storage: &dyn Storage,
        name: &str,
        version: &str,
    ) -> Result<Option<Vec<u8>>, RvError> {
        if let Some(entry) = storage.get(&binary_versioned_key(name, version)).await? {
            return Ok(Some(entry.value));
        }
        // Fall back to the legacy un-versioned path so plugins that
        // were registered before Phase 3 keep responding.
        Ok(storage.get(&legacy_binary_key(name)).await?.map(|e| e.value))
    }
}

fn active_key(name: &str) -> String {
    format!("{PLUGIN_PREFIX}{name}/active")
}

fn manifest_versioned_key(name: &str, version: &str) -> String {
    format!("{PLUGIN_PREFIX}{name}/versions/{version}/manifest")
}

fn binary_versioned_key(name: &str, version: &str) -> String {
    format!("{PLUGIN_PREFIX}{name}/versions/{version}/binary")
}

fn legacy_manifest_key(name: &str) -> String {
    format!("{PLUGIN_PREFIX}{name}/manifest")
}

fn legacy_binary_key(name: &str) -> String {
    format!("{PLUGIN_PREFIX}{name}/binary")
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hi = ascii_hex(chunk[0])?;
        let lo = ascii_hex(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn ascii_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::manifest::{Capabilities, RuntimeKind};

    fn manifest_with(name: &str, version: &str, binary: &[u8]) -> PluginManifest {
        let mut hasher = Sha256::new();
        hasher.update(binary);
        let digest = hasher.finalize();
        let hex = digest.iter().map(|b| format!("{b:02x}")).collect::<String>();
        PluginManifest {
            name: name.to_string(),
            version: version.to_string(),
            plugin_type: "secret-engine".to_string(),
            runtime: RuntimeKind::Wasm,
            abi_version: "1.0".to_string(),
            sha256: hex,
            size: binary.len() as u64,
            capabilities: Capabilities::default(),
            description: String::new(),
            config_schema: vec![],
        }
    }

    #[test]
    fn verify_integrity_round_trip() {
        let bin = b"some-binary-content".to_vec();
        let m = manifest_with("test", "0.1.0", &bin);
        assert!(PluginCatalog::verify_integrity(&m, &bin).is_ok());
    }

    #[test]
    fn rejects_truncated_binary() {
        let bin = b"some-binary-content".to_vec();
        let m = manifest_with("test", "0.1.0", &bin);
        let truncated = &bin[..bin.len() - 1];
        assert!(PluginCatalog::verify_integrity(&m, truncated).is_err());
    }

    #[test]
    fn rejects_tampered_byte() {
        let bin = b"some-binary-content".to_vec();
        let m = manifest_with("test", "0.1.0", &bin);
        let mut tampered = bin.clone();
        tampered[0] ^= 1;
        assert!(PluginCatalog::verify_integrity(&m, &tampered).is_err());
    }

    /// In-memory `Storage` so we can drive the full versioned API
    /// without standing up a barrier.
    #[derive(Default)]
    struct MemStorage {
        inner: std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
    }
    #[async_trait::async_trait]
    impl Storage for MemStorage {
        async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
            let g = self.inner.lock().unwrap();
            let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            for k in g.keys() {
                if let Some(rest) = k.strip_prefix(prefix) {
                    if let Some(slash) = rest.find('/') {
                        out.insert(format!("{}/", &rest[..slash]));
                    } else {
                        out.insert(rest.to_string());
                    }
                }
            }
            Ok(out.into_iter().collect())
        }
        async fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError> {
            let g = self.inner.lock().unwrap();
            Ok(g.get(key)
                .map(|v| StorageEntry { key: key.to_string(), value: v.clone() }))
        }
        async fn put(&self, entry: &StorageEntry) -> Result<(), RvError> {
            self.inner.lock().unwrap().insert(entry.key.clone(), entry.value.clone());
            Ok(())
        }
        async fn delete(&self, key: &str) -> Result<(), RvError> {
            self.inner.lock().unwrap().remove(key);
            Ok(())
        }
    }

    #[tokio::test]
    async fn put_then_get_uses_versioned_layout_and_activates() {
        let s = MemStorage::default();
        let cat = PluginCatalog::new();
        let bin = b"v1-bytes".to_vec();
        let m = manifest_with("p", "0.1.0", &bin);
        cat.put(&s, &m, &bin).await.unwrap();
        // Active pointer set to the registered version.
        assert_eq!(
            cat.get_active_version(&s, "p").await.unwrap().as_deref(),
            Some("0.1.0"),
        );
        let r = cat.get(&s, "p").await.unwrap().unwrap();
        assert_eq!(r.manifest.version, "0.1.0");
        assert_eq!(r.binary, bin);
    }

    #[tokio::test]
    async fn second_version_does_not_auto_activate() {
        let s = MemStorage::default();
        let cat = PluginCatalog::new();
        let v1 = b"v1".to_vec();
        let v2 = b"v2-different".to_vec();
        cat.put(&s, &manifest_with("p", "0.1.0", &v1), &v1).await.unwrap();
        cat.put(&s, &manifest_with("p", "0.2.0", &v2), &v2).await.unwrap();
        assert_eq!(
            cat.get_active_version(&s, "p").await.unwrap().as_deref(),
            Some("0.1.0"),
        );
        let versions = cat.list_versions(&s, "p").await.unwrap();
        assert_eq!(versions.len(), 2);
        // Activate v2 explicitly.
        cat.set_active(&s, "p", "0.2.0").await.unwrap();
        let r = cat.get(&s, "p").await.unwrap().unwrap();
        assert_eq!(r.manifest.version, "0.2.0");
        assert_eq!(r.binary, v2);
    }

    #[tokio::test]
    async fn cannot_delete_active_version() {
        let s = MemStorage::default();
        let cat = PluginCatalog::new();
        let bin = b"v1".to_vec();
        cat.put(&s, &manifest_with("p", "0.1.0", &bin), &bin).await.unwrap();
        assert!(cat.delete_version(&s, "p", "0.1.0").await.is_err());
    }

    #[tokio::test]
    async fn legacy_layout_still_readable() {
        let s = MemStorage::default();
        // Hand-write the legacy un-versioned layout — no active pointer,
        // no /versions/ subtree.
        let bin = b"legacy".to_vec();
        let m = manifest_with("legacy-plugin", "1.2.3", &bin);
        s.put(&StorageEntry {
            key: legacy_manifest_key("legacy-plugin"),
            value: serde_json::to_vec(&m).unwrap(),
        })
        .await
        .unwrap();
        s.put(&StorageEntry {
            key: legacy_binary_key("legacy-plugin"),
            value: bin.clone(),
        })
        .await
        .unwrap();

        let cat = PluginCatalog::new();
        let got = cat.get(&s, "legacy-plugin").await.unwrap().unwrap();
        assert_eq!(got.manifest.version, "1.2.3");
        assert_eq!(got.binary, bin);
        // get_active_version falls back to the manifest's own version
        // when no /active pointer exists.
        assert_eq!(
            cat.get_active_version(&s, "legacy-plugin").await.unwrap().as_deref(),
            Some("1.2.3"),
        );
        // list_versions surfaces the legacy entry as a single-version list.
        let versions = cat.list_versions(&s, "legacy-plugin").await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "1.2.3");
    }

    #[tokio::test]
    async fn delete_clears_versions_and_per_name_records() {
        let s = MemStorage::default();
        let cat = PluginCatalog::new();
        let v1 = b"v1".to_vec();
        let v2 = b"v2-different".to_vec();
        cat.put(&s, &manifest_with("p", "0.1.0", &v1), &v1).await.unwrap();
        cat.put(&s, &manifest_with("p", "0.2.0", &v2), &v2).await.unwrap();
        cat.delete(&s, "p").await.unwrap();
        assert!(cat.get(&s, "p").await.unwrap().is_none());
        assert!(cat.list_versions(&s, "p").await.unwrap().is_empty());
        assert!(cat.get_active_version(&s, "p").await.unwrap().is_none());
    }
}
