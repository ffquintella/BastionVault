//! Scope resolver, exporter, and importer for the bvx.v1 schema.
//!
//! v1 supports KV-mount selectors only (`ScopeSelector::KvPath`). Future
//! variants (resources, asset/resource groups, files) extend `ExchangeItems`
//! and the resolution logic here without changing the on-disk format.
//!
//! All storage I/O goes through the barrier-decrypted view (`&dyn Storage`)
//! the same way the existing `crate::backup::export` module does. The caller
//! is responsible for handing in a barrier view from `core.barrier.as_storage()`.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::Value;

use crate::{
    core::Core,
    errors::RvError,
    exchange::schema::{
        AssetGroupItem, ExchangeDocument, ExchangeItems, ExporterInfo, FileItem, KvItem,
        ResourceGroupItem, ResourceItem, ScopeSelector, ScopeSpec,
    },
    mount::LOGICAL_BARRIER_PREFIX,
    storage::{Storage, StorageEntry},
};

/// Resolver context: maps `logical_type` to a list of (mount_path, uuid)
/// pairs so the resource / group selectors can find the right per-mount
/// barrier prefix without re-scanning the table on every call.
#[derive(Default, Clone)]
pub struct MountIndex {
    by_type: HashMap<String, Vec<(String, String)>>,
}

impl MountIndex {
    pub fn from_core(core: &Arc<Core>) -> Result<Self, RvError> {
        let entries = core
            .mounts_router
            .mounts
            .entries
            .read()
            .map_err(|_| RvError::ErrUnknown)?;
        let mut by_type: HashMap<String, Vec<(String, String)>> = HashMap::new();
        for (path, lock) in entries.iter() {
            let me = lock.read().map_err(|_| RvError::ErrUnknown)?;
            by_type
                .entry(me.logical_type.clone())
                .or_default()
                .push((path.clone(), me.uuid.clone()));
        }
        Ok(Self { by_type })
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn mounts_of_type(&self, logical_type: &str) -> &[(String, String)] {
        self.by_type
            .get(logical_type)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}

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
/// Resolve a `ScopeSpec` into an `ExchangeDocument`.
///
/// The `mounts` index lets the resolver find the per-mount barrier prefix
/// for `resource` / `files` mounts when expanding `Resource` /
/// `AssetGroup` / `ResourceGroup` selectors. Pass `MountIndex::empty()`
/// for selectors that only touch raw KV paths (e.g. tests).
pub async fn export_to_document(
    storage: &dyn Storage,
    mounts: &MountIndex,
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
            ScopeSelector::Resource { id } => {
                resolve_resource(storage, mounts, id, &mut items, &mut warnings).await?;
            }
            ScopeSelector::AssetGroup { id } | ScopeSelector::ResourceGroup { id } => {
                let kind = if matches!(selector, ScopeSelector::AssetGroup { .. }) {
                    GroupKind::Asset
                } else {
                    GroupKind::Resource
                };
                resolve_group(storage, mounts, id, kind, &mut items, &mut warnings).await?;
            }
        }
    }

    // Deterministic ordering for canonical JSON.
    items.kv.sort_by(|a, b| (a.mount.as_str(), a.path.as_str()).cmp(&(b.mount.as_str(), b.path.as_str())));
    items.resources.sort_by(|a, b| a.id.cmp(&b.id));
    items.files.sort_by(|a, b| a.id.cmp(&b.id));
    items.asset_groups.sort_by(|a, b| a.id.cmp(&b.id));
    items.resource_groups.sort_by(|a, b| a.id.cmp(&b.id));
    items.kv.dedup_by(|a, b| a.mount == b.mount && a.path == b.path);
    items.resources.dedup_by(|a, b| a.id == b.id);
    items.files.dedup_by(|a, b| a.id == b.id);

    let mut doc = ExchangeDocument::new(exporter, scope, items);
    doc.warnings = warnings;
    Ok(doc)
}

#[derive(Copy, Clone)]
enum GroupKind { Asset, Resource }

/// Read a single resource (and its embedded secrets / metadata / version
/// history) from the first `resource`-typed mount in the index. Records
/// emitted under the **mount path** (not UUID) so the importer can re-route
/// to a destination vault's matching mount.
async fn resolve_resource(
    storage: &dyn Storage,
    mounts: &MountIndex,
    id: &str,
    items: &mut ExchangeItems,
    warnings: &mut Vec<String>,
) -> Result<(), RvError> {
    let resource_mounts = mounts.mounts_of_type("resource");
    if resource_mounts.is_empty() {
        warnings.push(format!(
            "scope selector resource id={id} skipped: no mount of type \"resource\" found"
        ));
        return Ok(());
    }

    // Resources are addressed by id, but the same id could in principle
    // exist on more than one resource mount. We try every mount and emit
    // the first hit; warn if multiple match (operators normally only
    // configure one).
    let mut found = false;
    for (mount_path, uuid) in resource_mounts {
        let bp = mount_barrier_prefix(uuid);
        let meta_key = format!("{bp}meta/{id}");
        if let Some(meta_entry) = storage.get(&meta_key).await? {
            if found {
                warnings.push(format!(
                    "resource id={id} also exists on mount {mount_path}; first hit kept"
                ));
                break;
            }
            found = true;
            let meta_value = parse_json_or_b64(&meta_entry.value);
            let mut bundle = serde_json::Map::new();
            bundle.insert("mount_path".to_string(), Value::String(mount_path.clone()));
            bundle.insert("meta".to_string(), meta_value);

            // Optional: history (best-effort, ignore if absent).
            if let Ok(Some(h)) = storage.get(&format!("{bp}hist/{id}")).await {
                bundle.insert("history".to_string(), parse_json_or_b64(&h.value));
            }

            // Embedded per-resource secrets: meta + value + version log.
            let secrets = collect_resource_secrets(storage, &bp, id).await?;
            if !secrets.is_empty() {
                bundle.insert("secrets".to_string(), Value::Object(secrets));
            }

            items.resources.push(ResourceItem {
                id: id.to_string(),
                data: Value::Object(bundle),
            });
        }
    }
    if !found {
        warnings.push(format!("resource id={id} not found in any resource mount"));
    }
    Ok(())
}

/// Walk `secret/<id>/`, `smeta/<id>/`, `sver/<id>/<key>/` under the resource
/// mount's barrier prefix and return them as a structured map. Each
/// secret-key bundles its current value, metadata, and version history.
async fn collect_resource_secrets(
    storage: &dyn Storage,
    barrier_prefix: &str,
    id: &str,
) -> Result<serde_json::Map<String, Value>, RvError> {
    let mut out: serde_json::Map<String, Value> = serde_json::Map::new();
    let secret_prefix = format!("{barrier_prefix}secret/{id}/");
    let names = match storage.list(&secret_prefix).await {
        Ok(v) => v,
        Err(_) => return Ok(out),
    };
    for name in names {
        if name.ends_with('/') { continue; }
        let key_full = format!("{secret_prefix}{name}");
        let mut bundle = serde_json::Map::new();
        if let Some(e) = storage.get(&key_full).await? {
            bundle.insert("value".to_string(), parse_json_or_b64(&e.value));
        }
        if let Ok(Some(meta)) = storage
            .get(&format!("{barrier_prefix}smeta/{id}/{name}"))
            .await
        {
            bundle.insert("meta".to_string(), parse_json_or_b64(&meta.value));
        }
        // Version history (`sver/<id>/<key>/<version>`).
        let sver_prefix = format!("{barrier_prefix}sver/{id}/{name}/");
        if let Ok(versions) = storage.list(&sver_prefix).await {
            let mut vers = serde_json::Map::new();
            for v in versions {
                if v.ends_with('/') { continue; }
                if let Some(ve) = storage.get(&format!("{sver_prefix}{v}")).await? {
                    vers.insert(v, parse_json_or_b64(&ve.value));
                }
            }
            if !vers.is_empty() {
                bundle.insert("versions".to_string(), Value::Object(vers));
            }
        }
        out.insert(name, Value::Object(bundle));
    }
    Ok(out)
}

/// Read a resource-group / asset-group record from `sys/resource-group/group/<id>`
/// and emit it. If the record references resources, KV-secrets, or files,
/// drag those in too (best-effort — silently skip ones the actor cannot
/// read; the resource resolver itself emits per-id warnings).
async fn resolve_group(
    storage: &dyn Storage,
    mounts: &MountIndex,
    id: &str,
    kind: GroupKind,
    items: &mut ExchangeItems,
    warnings: &mut Vec<String>,
) -> Result<(), RvError> {
    let canonical = id.trim().to_lowercase();
    let group_key = format!("sys/resource-group/group/{canonical}");
    let entry = match storage.get(&group_key).await? {
        Some(e) => e,
        None => {
            warnings.push(format!("group id={id} not found at {group_key}"));
            return Ok(());
        }
    };
    let group_value: Value = serde_json::from_slice(&entry.value)
        .unwrap_or_else(|_| parse_json_or_b64(&entry.value));

    // Drag in members.
    if let Some(members) = group_value.get("members").and_then(|v| v.as_array()) {
        for m in members {
            if let Some(member_id) = m.as_str() {
                resolve_resource(storage, mounts, member_id, items, warnings).await?;
            }
        }
    }
    if let Some(secrets) = group_value.get("secrets").and_then(|v| v.as_array()) {
        for s in secrets {
            if let Some(path) = s.as_str() {
                drag_in_secret_path(storage, mounts, path, items, warnings).await?;
            }
        }
    }
    if let Some(files) = group_value.get("files").and_then(|v| v.as_array()) {
        for f in files {
            if let Some(file_id) = f.as_str() {
                resolve_file(storage, mounts, file_id, items, warnings).await?;
            }
        }
    }

    match kind {
        GroupKind::Asset => {
            items.asset_groups.push(AssetGroupItem { id: canonical, data: group_value });
        }
        GroupKind::Resource => {
            items.resource_groups.push(ResourceGroupItem { id: canonical, data: group_value });
        }
    }
    Ok(())
}

async fn drag_in_secret_path(
    storage: &dyn Storage,
    mounts: &MountIndex,
    canonical_path: &str,
    items: &mut ExchangeItems,
    warnings: &mut Vec<String>,
) -> Result<(), RvError> {
    // The resource_group store keeps secret paths in canonical form
    // ("<mount-path-without-trailing-slash>/<key>"). Find the matching
    // KV-or-KV-v2 mount by prefix.
    let mut best: Option<(&str, &str, String)> = None; // (mount_path, uuid, relative_key)
    for ty in ["kv", "kv-v2"] {
        for (mount_path, uuid) in mounts.mounts_of_type(ty) {
            let mp = mount_path.trim_end_matches('/');
            if let Some(rest) = canonical_path.strip_prefix(&format!("{mp}/")) {
                if best.as_ref().map(|(p, _, _)| p.len()).unwrap_or(0) < mp.len() {
                    best = Some((mount_path.as_str(), uuid.as_str(), rest.to_string()));
                }
            }
        }
    }
    let Some((mount_path, uuid, rel)) = best else {
        warnings.push(format!("secret path {canonical_path} did not match any KV mount"));
        return Ok(());
    };
    let bp = mount_barrier_prefix(uuid);
    let abs = format!("{bp}{rel}");
    if let Some(entry) = storage.get(&abs).await? {
        items.kv.push(KvItem {
            mount: ensure_trailing_slash(mount_path),
            path: rel,
            value: parse_json_or_b64(&entry.value),
        });
    } else {
        warnings.push(format!("secret path {canonical_path} not found in storage"));
    }
    Ok(())
}

async fn resolve_file(
    storage: &dyn Storage,
    mounts: &MountIndex,
    id: &str,
    items: &mut ExchangeItems,
    warnings: &mut Vec<String>,
) -> Result<(), RvError> {
    let file_mounts = mounts.mounts_of_type("files");
    if file_mounts.is_empty() {
        warnings.push(format!("file id={id} skipped: no mount of type \"files\""));
        return Ok(());
    }
    for (_mount_path, uuid) in file_mounts {
        let bp = mount_barrier_prefix(uuid);
        let meta_key = format!("{bp}meta/{id}");
        if let Some(meta_entry) = storage.get(&meta_key).await? {
            let metadata = parse_json_or_b64(&meta_entry.value);
            let blob_key = format!("{bp}blob/{id}");
            let content_b64 = if let Some(blob) = storage.get(&blob_key).await? {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(&blob.value)
            } else {
                String::new()
            };
            items.files.push(FileItem {
                id: id.to_string(),
                metadata,
                content_b64,
            });
            return Ok(());
        }
    }
    warnings.push(format!("file id={id} not found in any files mount"));
    Ok(())
}

fn mount_barrier_prefix(uuid: &str) -> String {
    format!("{LOGICAL_BARRIER_PREFIX}{uuid}/")
}

/// Parse storage bytes as JSON; fall back to a `{"_base64": "..."}` wrapper
/// so the document remains self-describing when the value isn't JSON.
fn parse_json_or_b64(bytes: &[u8]) -> Value {
    use base64::Engine;
    match serde_json::from_slice::<Value>(bytes) {
        Ok(v) => v,
        Err(_) => serde_json::json!({
            "_base64": base64::engine::general_purpose::STANDARD.encode(bytes),
        }),
    }
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
        let doc = export_to_document(&src, &MountIndex::empty(), ExporterInfo::default(), scope)
            .await
            .unwrap();
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
