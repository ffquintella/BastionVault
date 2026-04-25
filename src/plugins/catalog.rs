//! Barrier-encrypted plugin catalog.
//!
//! Layout:
//! ```text
//! core/plugins/<name>/manifest      — PluginManifest JSON
//! core/plugins/<name>/binary        — raw WASM bytes (or future runtime payload)
//! ```
//!
//! The binary lives next to the manifest under the same key prefix so
//! the loader can fetch them atomically. The barrier handles encryption
//! at rest; on load we recompute sha256 against the bytes and compare
//! against the manifest, so tampering on the physical backend is
//! detected before instantiation.

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
        for name in names {
            // `list` returns `<name>/` directory entries; trim the slash.
            let name = name.strip_suffix('/').unwrap_or(&name).to_string();
            if let Some(manifest) = self.get_manifest(storage, &name).await? {
                out.push(manifest);
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    pub async fn get(&self, storage: &dyn Storage, name: &str) -> Result<Option<PluginRecord>, RvError> {
        let Some(manifest) = self.get_manifest(storage, name).await? else {
            return Ok(None);
        };
        let bin_key = binary_key(name);
        let binary = match storage.get(&bin_key).await? {
            Some(e) => e.value,
            None => return Ok(None),
        };
        Self::verify_integrity(&manifest, &binary)?;
        Ok(Some(PluginRecord { manifest, binary }))
    }

    pub async fn get_manifest(
        &self,
        storage: &dyn Storage,
        name: &str,
    ) -> Result<Option<PluginManifest>, RvError> {
        let key = manifest_key(name);
        match storage.get(&key).await? {
            None => Ok(None),
            Some(entry) => serde_json::from_slice::<PluginManifest>(&entry.value)
                .map(Some)
                .map_err(|_| RvError::ErrRequestInvalid),
        }
    }

    pub async fn put(
        &self,
        storage: &dyn Storage,
        manifest: &PluginManifest,
        binary: &[u8],
    ) -> Result<(), RvError> {
        manifest.validate().map_err(|_| RvError::ErrRequestInvalid)?;
        Self::verify_integrity(manifest, binary)?;
        // Write binary first so a half-failed registration doesn't leave a
        // manifest pointing at nothing.
        storage
            .put(&StorageEntry { key: binary_key(&manifest.name), value: binary.to_vec() })
            .await?;
        let manifest_bytes = serde_json::to_vec(manifest)?;
        storage
            .put(&StorageEntry { key: manifest_key(&manifest.name), value: manifest_bytes })
            .await
    }

    pub async fn delete(&self, storage: &dyn Storage, name: &str) -> Result<(), RvError> {
        let _ = storage.delete(&binary_key(name)).await;
        let _ = storage.delete(&manifest_key(name)).await;
        Ok(())
    }

    /// Recompute sha256 over the raw WASM bytes and compare with the
    /// manifest's declared digest. Also asserts size match so a truncated
    /// upload fails immediately rather than via a downstream parse error.
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
}

fn manifest_key(name: &str) -> String {
    format!("{PLUGIN_PREFIX}{name}/manifest")
}

fn binary_key(name: &str) -> String {
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

    fn manifest_with(binary: &[u8]) -> PluginManifest {
        let mut hasher = Sha256::new();
        hasher.update(binary);
        let digest = hasher.finalize();
        let hex = digest.iter().map(|b| format!("{b:02x}")).collect::<String>();
        PluginManifest {
            name: "test-plugin".to_string(),
            version: "0.1.0".to_string(),
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
        let m = manifest_with(&bin);
        assert!(PluginCatalog::verify_integrity(&m, &bin).is_ok());
    }

    #[test]
    fn rejects_truncated_binary() {
        let bin = b"some-binary-content".to_vec();
        let m = manifest_with(&bin);
        let truncated = &bin[..bin.len() - 1];
        assert!(PluginCatalog::verify_integrity(&m, truncated).is_err());
    }

    #[test]
    fn rejects_tampered_byte() {
        let bin = b"some-binary-content".to_vec();
        let m = manifest_with(&bin);
        let mut tampered = bin.clone();
        tampered[0] ^= 1;
        assert!(PluginCatalog::verify_integrity(&m, &tampered).is_err());
    }
}
