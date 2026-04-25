//! Scope resolver, exporter, and importer for the bvx.v1 schema.
//!
//! v1 supports KV-mount selectors only (`ScopeSelector::KvPath`). Future
//! variants (resources, asset/resource groups, files) extend `ExchangeItems`
//! and the resolution logic here without changing the on-disk format.
//!
//! All storage I/O goes through the barrier-decrypted view (`&dyn Storage`)
//! the same way the existing `crate::backup::export` module does. The caller
//! is responsible for handing in a barrier view from `core.barrier.as_storage()`.

use std::pin::Pin;

use serde_json::Value;

use crate::{
    errors::RvError,
    exchange::schema::{
        ExchangeDocument, ExchangeItems, ExporterInfo, KvItem, ScopeSelector, ScopeSpec,
    },
    storage::{Storage, StorageEntry},
};

/// What to do when an imported item collides with an existing target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictPolicy {
    /// Keep the existing version; the import is a no-op for this item.
    Skip,
    /// Replace the existing version with the imported one.
    Overwrite,
    /// Write the imported version under a sibling path with a timestamp
    /// suffix; original is preserved.
    Rename,
}

impl Default for ConflictPolicy {
    fn default() -> Self {
        Self::Skip
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportClassification {
    /// Target path does not exist in the destination vault.
    New,
    /// Target exists with byte-identical bytes — no-op.
    Identical,
    /// Target exists with different bytes; conflict policy decides.
    Conflict,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ImportedItem {
    pub mount: String,
    pub path: String,
    pub classification: ImportClassification,
    pub action: ImportAction,
    /// When `action == Renamed`, the path the imported version was written to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renamed_to: Option<String>,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportAction {
    /// Wrote to the destination.
    Written,
    /// Existed already with the same bytes; nothing was written.
    Unchanged,
    /// Conflict-policy `Skip` was honoured; existing target preserved.
    Skipped,
    /// Conflict-policy `Rename` wrote to a sibling path.
    Renamed,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ImportResult {
    pub items: Vec<ImportedItem>,
    pub written: u64,
    pub unchanged: u64,
    pub skipped: u64,
    pub renamed: u64,
}

/// Resolve a `ScopeSpec` into an `ExchangeDocument` by reading the
/// barrier-decrypted storage view. Each `ScopeSelector::KvPath` recursively
/// walks the storage tree under `mount + path`.
pub async fn export_to_document(
    storage: &dyn Storage,
    exporter: ExporterInfo,
    scope: ScopeSpec,
) -> Result<ExchangeDocument, RvError> {
    let mut items = ExchangeItems::default();
    let mut warnings: Vec<String> = Vec::new();

    for selector in &scope.include {
        match selector {
            ScopeSelector::KvPath { mount, path } => {
                let mount_norm = ensure_trailing_slash(mount);
                let prefix = format!("{mount_norm}{path}");
                let keys = list_recursive(storage, &prefix).await?;
                for full_key in keys {
                    if let Some(entry) = storage.get(&full_key).await? {
                        let value = entry_value_to_json(&entry);
                        let relative = full_key.strip_prefix(&mount_norm).unwrap_or(&full_key).to_string();
                        items.kv.push(KvItem {
                            mount: mount_norm.clone(),
                            path: relative,
                            value,
                        });
                    }
                }
            }
            ScopeSelector::Resource { id }
            | ScopeSelector::AssetGroup { id }
            | ScopeSelector::ResourceGroup { id } => {
                // The schema reserves these variants so future versions can
                // emit them and older importers ignore them gracefully. The
                // exporter side requires per-mount UUID resolution against
                // the mount table, which is wired in a follow-up phase.
                // Emitting a warning makes the deferral visible in the
                // document instead of silently producing an empty export.
                let kind = match selector {
                    ScopeSelector::Resource { .. } => "resource",
                    ScopeSelector::AssetGroup { .. } => "asset_group",
                    ScopeSelector::ResourceGroup { .. } => "resource_group",
                    _ => unreachable!(),
                };
                warnings.push(format!(
                    "scope selector \"{kind}\" with id={id} not resolved \
                     (resource / group selectors are reserved in the v1 schema; \
                     full resolution lands in a follow-up phase)"
                ));
            }
        }
    }

    // Deterministic ordering for canonical JSON.
    items.kv.sort_by(|a, b| (a.mount.as_str(), a.path.as_str()).cmp(&(b.mount.as_str(), b.path.as_str())));
    items.resources.sort_by(|a, b| a.id.cmp(&b.id));
    items.files.sort_by(|a, b| a.id.cmp(&b.id));
    items.asset_groups.sort_by(|a, b| a.id.cmp(&b.id));
    items.resource_groups.sort_by(|a, b| a.id.cmp(&b.id));

    let mut doc = ExchangeDocument::new(exporter, scope, items);
    doc.warnings = warnings;
    Ok(doc)
}

/// Apply a parsed `ExchangeDocument` to the vault according to the conflict
/// policy. Returns a per-item result so the caller can audit each write.
pub async fn import_from_document(
    storage: &dyn Storage,
    document: &ExchangeDocument,
    policy: ConflictPolicy,
) -> Result<ImportResult, RvError> {
    document.validate_schema_tag().map_err(|_| RvError::ErrRequestInvalid)?;

    let mut result = ImportResult::default();

    for kv in &document.items.kv {
        let mount = ensure_trailing_slash(&kv.mount);
        let full_path = format!("{mount}{}", strip_leading_slash(&kv.path));
        let new_bytes = json_value_to_storage_bytes(&kv.value)?;

        let existing = storage.get(&full_path).await?;
        let classification = match &existing {
            None => ImportClassification::New,
            Some(e) if e.value == new_bytes => ImportClassification::Identical,
            Some(_) => ImportClassification::Conflict,
        };

        let (action, renamed_to) = match (&classification, policy) {
            (ImportClassification::New, _) => {
                storage.put(&StorageEntry { key: full_path.clone(), value: new_bytes }).await?;
                (ImportAction::Written, None)
            }
            (ImportClassification::Identical, _) => (ImportAction::Unchanged, None),
            (ImportClassification::Conflict, ConflictPolicy::Overwrite) => {
                storage.put(&StorageEntry { key: full_path.clone(), value: new_bytes }).await?;
                (ImportAction::Written, None)
            }
            (ImportClassification::Conflict, ConflictPolicy::Skip) => (ImportAction::Skipped, None),
            (ImportClassification::Conflict, ConflictPolicy::Rename) => {
                let suffix = chrono::Utc::now().format("%Y%m%dT%H%M%S").to_string();
                let renamed = format!("{full_path}.imported.{suffix}");
                storage.put(&StorageEntry { key: renamed.clone(), value: new_bytes }).await?;
                (ImportAction::Renamed, Some(renamed))
            }
        };

        match action {
            ImportAction::Written => result.written += 1,
            ImportAction::Unchanged => result.unchanged += 1,
            ImportAction::Skipped => result.skipped += 1,
            ImportAction::Renamed => result.renamed += 1,
        }

        result.items.push(ImportedItem {
            mount: kv.mount.clone(),
            path: kv.path.clone(),
            classification,
            action,
            renamed_to,
        });
    }

    Ok(result)
}

fn ensure_trailing_slash(s: &str) -> String {
    if s.ends_with('/') {
        s.to_string()
    } else {
        format!("{s}/")
    }
}

fn strip_leading_slash(s: &str) -> &str {
    s.strip_prefix('/').unwrap_or(s)
}

fn entry_value_to_json(entry: &StorageEntry) -> Value {
    match serde_json::from_slice::<Value>(&entry.value) {
        Ok(v) => v,
        Err(_) => {
            use base64::Engine;
            // Self-describing fallback so an importer can reconstitute the
            // original bytes without guessing.
            serde_json::json!({
                "_base64": base64::engine::general_purpose::STANDARD.encode(&entry.value),
            })
        }
    }
}

fn json_value_to_storage_bytes(v: &Value) -> Result<Vec<u8>, RvError> {
    if let Value::Object(map) = v {
        if map.len() == 1 {
            if let Some(Value::String(b64)) = map.get("_base64") {
                use base64::Engine;
                return base64::engine::general_purpose::STANDARD
                    .decode(b64.as_bytes())
                    .map_err(|_| RvError::ErrRequestInvalid);
            }
        }
    }
    Ok(serde_json::to_vec(v)?)
}

/// Recursively walk storage under `prefix` and return every leaf key.
fn list_recursive<'a>(
    storage: &'a dyn Storage,
    prefix: &'a str,
) -> Pin<Box<dyn std::future::Future<Output = Result<Vec<String>, RvError>> + Send + 'a>> {
    Box::pin(async move {
        let mut leaves = Vec::new();
        let entries = storage.list(prefix).await?;
        for entry in entries {
            let full = format!("{prefix}{entry}");
            if entry.ends_with('/') {
                leaves.extend(list_recursive(storage, &full).await?);
            } else {
                leaves.push(full);
            }
        }
        Ok(leaves)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::canonical::to_canonical_vec;
    use crate::exchange::schema::ScopeKind;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// In-memory `Storage` for tests. A `BTreeMap` gives us list-by-prefix
    /// for free and keeps key ordering deterministic.
    #[derive(Default)]
    struct MemStorage {
        inner: Mutex<BTreeMap<String, Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl Storage for MemStorage {
        async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
            let map = self.inner.lock().unwrap();
            // Vault-style list: return immediate children of `prefix`,
            // with subdirectories suffixed by '/'.
            let mut seen = std::collections::BTreeSet::new();
            for k in map.keys() {
                if let Some(rest) = k.strip_prefix(prefix) {
                    if let Some(slash) = rest.find('/') {
                        seen.insert(format!("{}/", &rest[..slash]));
                    } else {
                        seen.insert(rest.to_string());
                    }
                }
            }
            Ok(seen.into_iter().collect())
        }
        async fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError> {
            let map = self.inner.lock().unwrap();
            Ok(map.get(key).map(|v| StorageEntry { key: key.to_string(), value: v.clone() }))
        }
        async fn put(&self, entry: &StorageEntry) -> Result<(), RvError> {
            let mut map = self.inner.lock().unwrap();
            map.insert(entry.key.clone(), entry.value.clone());
            Ok(())
        }
        async fn delete(&self, key: &str) -> Result<(), RvError> {
            let mut map = self.inner.lock().unwrap();
            map.remove(key);
            Ok(())
        }
    }

    async fn populate(storage: &dyn Storage, kv: &[(&str, &Value)]) {
        for (k, v) in kv {
            let bytes = serde_json::to_vec(v).unwrap();
            storage
                .put(&StorageEntry { key: (*k).to_string(), value: bytes })
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn export_import_round_trip() {
        let src = MemStorage::default();
        let v1 = serde_json::json!({"u":"alice","p":"hunter2"});
        let v2 = serde_json::json!({"k":"v"});
        populate(&src, &[("secret/myapp/db", &v1), ("secret/myapp/api", &v2)]).await;

        let scope = ScopeSpec {
            kind: ScopeKind::Selective,
            include: vec![ScopeSelector::KvPath {
                mount: "secret/".to_string(),
                path: "myapp/".to_string(),
            }],
        };
        let doc = export_to_document(&src, ExporterInfo::default(), scope).await.unwrap();
        assert_eq!(doc.items.kv.len(), 2);
        // Deterministic ordering.
        assert_eq!(doc.items.kv[0].path, "myapp/api");
        assert_eq!(doc.items.kv[1].path, "myapp/db");

        // Round-trip canonical JSON.
        let bytes_a = to_canonical_vec(&doc).unwrap();
        let bytes_b = to_canonical_vec(&doc).unwrap();
        assert_eq!(bytes_a, bytes_b);

        // Import into a fresh vault.
        let dst = MemStorage::default();
        let result = import_from_document(&dst, &doc, ConflictPolicy::Skip).await.unwrap();
        assert_eq!(result.written, 2);
        assert_eq!(result.unchanged, 0);
        assert_eq!(result.skipped, 0);
        assert_eq!(dst.get("secret/myapp/db").await.unwrap().unwrap().value, serde_json::to_vec(&v1).unwrap());
    }

    #[tokio::test]
    async fn conflict_policy_skip_preserves_existing() {
        let store = MemStorage::default();
        let original = serde_json::json!({"v":"existing"});
        populate(&store, &[("secret/x/y", &original)]).await;

        let doc = ExchangeDocument::new(
            ExporterInfo::default(),
            ScopeSpec { kind: ScopeKind::Full, include: vec![] },
            ExchangeItems {
                kv: vec![KvItem {
                    mount: "secret/".to_string(),
                    path: "x/y".to_string(),
                    value: serde_json::json!({"v":"incoming"}),
                }],
                ..Default::default()
            },
        );

        let result = import_from_document(&store, &doc, ConflictPolicy::Skip).await.unwrap();
        assert_eq!(result.skipped, 1);
        assert_eq!(result.written, 0);
        let after = store.get("secret/x/y").await.unwrap().unwrap();
        assert_eq!(after.value, serde_json::to_vec(&original).unwrap());
    }

    #[tokio::test]
    async fn conflict_policy_rename_writes_sibling() {
        let store = MemStorage::default();
        let original = serde_json::json!({"v":"existing"});
        populate(&store, &[("secret/x/y", &original)]).await;

        let doc = ExchangeDocument::new(
            ExporterInfo::default(),
            ScopeSpec { kind: ScopeKind::Full, include: vec![] },
            ExchangeItems {
                kv: vec![KvItem {
                    mount: "secret/".to_string(),
                    path: "x/y".to_string(),
                    value: serde_json::json!({"v":"incoming"}),
                }],
                ..Default::default()
            },
        );

        let result = import_from_document(&store, &doc, ConflictPolicy::Rename).await.unwrap();
        assert_eq!(result.renamed, 1);
        let after = store.get("secret/x/y").await.unwrap().unwrap();
        assert_eq!(after.value, serde_json::to_vec(&original).unwrap());
        let renamed_path = result.items[0].renamed_to.as_ref().unwrap();
        assert!(renamed_path.starts_with("secret/x/y.imported."));
        let renamed_entry = store.get(renamed_path).await.unwrap().unwrap();
        assert_eq!(renamed_entry.value, serde_json::to_vec(&serde_json::json!({"v":"incoming"})).unwrap());
    }

    #[tokio::test]
    async fn identical_bytes_classified_unchanged() {
        let store = MemStorage::default();
        let v = serde_json::json!({"v":1});
        populate(&store, &[("secret/x", &v)]).await;

        let doc = ExchangeDocument::new(
            ExporterInfo::default(),
            ScopeSpec { kind: ScopeKind::Full, include: vec![] },
            ExchangeItems {
                kv: vec![KvItem {
                    mount: "secret/".to_string(),
                    path: "x".to_string(),
                    value: v.clone(),
                }],
                ..Default::default()
            },
        );

        let result = import_from_document(&store, &doc, ConflictPolicy::Skip).await.unwrap();
        assert_eq!(result.unchanged, 1);
        assert_eq!(result.written, 0);
    }
}
