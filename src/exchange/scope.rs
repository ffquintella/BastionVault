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
        ResourceGroupItem, ResourceItem, ScopeKind, ScopeSelector, ScopeSpec,
    },
    mount::{LOGICAL_BARRIER_PREFIX, SYSTEM_BARRIER_PREFIX},
    storage::{Storage, StorageEntry},
};

/// Resolver context: maps `logical_type` to a list of (mount_path, uuid)
/// pairs so the resource / group selectors can find the right per-mount
/// barrier prefix without re-scanning the table on every call.
///
/// `logical_prefix` / `system_prefix` carry the **active root-tenant storage
/// prefixes** so the resolver addresses keys at the same place the live vault
/// does. Re-root activation is the default for every install, so in
/// production these are `namespaces/<root_uuid>/logical/` and
/// `namespaces/<root_uuid>/sys/` — not the bare `logical/` / `sys/`. The
/// resolver reads through the raw barrier (`core.barrier.as_storage()`), so it
/// MUST prepend these prefixes or every list/get misses and the export comes
/// out empty (see `Core::root_logical_prefix`).
#[derive(Clone)]
pub struct MountIndex {
    by_type: HashMap<String, Vec<(String, String)>>,
    logical_prefix: String,
    system_prefix: String,
}

impl Default for MountIndex {
    fn default() -> Self {
        // Bare prefixes — the pre-re-root layout. Only used by `empty()` and
        // tests; `from_core` always overrides with the live core's prefixes.
        Self {
            by_type: HashMap::new(),
            logical_prefix: LOGICAL_BARRIER_PREFIX.to_string(),
            system_prefix: SYSTEM_BARRIER_PREFIX.to_string(),
        }
    }
}

impl MountIndex {
    pub fn from_core(core: &Arc<Core>) -> Result<Self, RvError> {
        let mounts_router = core.mounts_router();
        let entries = mounts_router
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
        Ok(Self {
            by_type,
            logical_prefix: core.root_logical_prefix(),
            system_prefix: core.root_system_prefix(),
        })
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

    /// Barrier-storage prefix for a logical mount's data, e.g.
    /// `namespaces/<root_uuid>/logical/<uuid>/`.
    fn barrier_prefix(&self, uuid: &str) -> String {
        format!("{}{uuid}/", self.logical_prefix)
    }

    /// Barrier-storage prefix for the root tenant's system view, e.g.
    /// `namespaces/<root_uuid>/sys/`.
    fn system_prefix(&self) -> &str {
        &self.system_prefix
    }

    /// Find the uuid of a `kv` / `kv-v2` mount by its mount path
    /// (trailing-slash form, e.g. `secret/`).
    fn kv_uuid_for_mount(&self, mount_path: &str) -> Option<&str> {
        for ty in ["kv", "kv-v2"] {
            for (path, uuid) in self.mounts_of_type(ty) {
                if path == mount_path {
                    return Some(uuid);
                }
            }
        }
        None
    }

    /// Resolve a KV item's `(mount, path)` to the barrier-storage key where
    /// the live kv backend actually reads/writes it. `kv.path` is
    /// barrier-relative (e.g. `data/myapp/db`); under the default re-rooted
    /// layout the data lives at `namespaces/<root_uuid>/logical/<uuid>/…`, so
    /// callers must resolve through the mount prefix rather than using the
    /// bare `mount + path`. Falls back to the bare mount path when the mount
    /// is unknown (hand-built documents / legacy layouts).
    ///
    /// This is the single source of truth shared by the import write path and
    /// the dry-run preview classification so they agree on where to look.
    pub fn resolve_kv_key(&self, mount: &str, path: &str) -> String {
        let mount = ensure_trailing_slash(mount);
        let rel = strip_leading_slash(path);
        match self.kv_uuid_for_mount(&mount) {
            Some(uuid) => format!("{}{rel}", self.barrier_prefix(uuid)),
            None => format!("{mount}{rel}"),
        }
    }

    /// Test-only constructor that fixes the mount table and storage prefixes
    /// explicitly so a re-rooted (`namespaces/<uuid>/…`) layout can be
    /// exercised without a live `Core`.
    #[cfg(test)]
    fn for_test(
        by_type: HashMap<String, Vec<(String, String)>>,
        logical_prefix: &str,
        system_prefix: &str,
    ) -> Self {
        Self {
            by_type,
            logical_prefix: logical_prefix.to_string(),
            system_prefix: system_prefix.to_string(),
        }
    }
}

/// What to do when an imported item collides with an existing target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ConflictPolicy {
    /// Keep the existing version; the import is a no-op for this item.
    #[default]
    Skip,
    /// Replace the existing version with the imported one.
    Overwrite,
    /// Write the imported version under a sibling path with a timestamp
    /// suffix; original is preserved.
    Rename,
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

    // `Full` scope: enumerate everything the actor can read — every KV
    // mount, every resource, every file blob, and every resource/asset
    // group — without the caller having to hand-list selectors. The
    // explicit `include` list is still honoured (normally empty for a
    // full export); the dedup pass below collapses any overlap.
    if scope.kind == ScopeKind::Full {
        resolve_full(storage, mounts, &mut items, &mut warnings).await?;
    }

    for selector in &scope.include {
        match selector {
            ScopeSelector::KvPath { mount, path } => {
                let mount_norm = ensure_trailing_slash(mount);
                read_kv_mount(storage, mounts, &mount_norm, Some(path), &mut items).await?;
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
    items.asset_groups.dedup_by(|a, b| a.id == b.id);
    items.resource_groups.dedup_by(|a, b| a.id == b.id);

    let mut doc = ExchangeDocument::new(exporter, scope, items);
    doc.warnings = warnings;
    Ok(doc)
}

#[derive(Copy, Clone)]
enum GroupKind { Asset, Resource }

/// Enumerate the entire readable vault for a `ScopeKind::Full` export.
///
/// Walks every KV / KV-v2 mount recursively, every resource and file
/// blob under each resource/files mount, and every resource-group record.
/// Group expansion drags in member resources / secrets / files, which the
/// caller's dedup pass collapses against the direct scans here. Listing
/// failures on any single mount are downgraded to warnings so one
/// unreadable mount can't sink the whole backup.
async fn resolve_full(
    storage: &dyn Storage,
    mounts: &MountIndex,
    items: &mut ExchangeItems,
    warnings: &mut Vec<String>,
) -> Result<(), RvError> {
    // KV mounts: capture each mount's entire barrier subtree (kv-v1 leaves,
    // kv-v2 `data/` + `metadata/` + `config`) so the bytes round-trip through
    // `import_from_document`. Keys live under the mount's barrier prefix
    // (`<root>logical/<uuid>/`), NOT the bare mount path.
    for ty in ["kv", "kv-v2"] {
        for (mount_path, _uuid) in mounts.mounts_of_type(ty) {
            let mount_norm = ensure_trailing_slash(mount_path);
            read_kv_mount(storage, mounts, &mount_norm, None, items).await?;
        }
    }

    // Resources: ids live under `<barrier>/meta/<id>`.
    for (_mount_path, uuid) in mounts.mounts_of_type("resource") {
        let bp = mounts.barrier_prefix(uuid);
        let ids = storage.list(&format!("{bp}meta/")).await.unwrap_or_default();
        for id in ids {
            if id.ends_with('/') {
                continue;
            }
            resolve_resource(storage, mounts, &id, items, warnings).await?;
        }
    }

    // File blobs: same `meta/<id>` addressing on files-typed mounts.
    for (_mount_path, uuid) in mounts.mounts_of_type("files") {
        let bp = mounts.barrier_prefix(uuid);
        let ids = storage.list(&format!("{bp}meta/")).await.unwrap_or_default();
        for id in ids {
            if id.ends_with('/') {
                continue;
            }
            resolve_file(storage, mounts, &id, items, warnings).await?;
        }
    }

    // Resource / asset groups share one store keyed by name. They differ
    // only in GUI labelling, so a full export records each as a resource
    // group; the member resources / secrets / files come along via
    // `resolve_group`.
    let groups = storage
        .list(&format!("{}resource-group/group/", mounts.system_prefix()))
        .await
        .unwrap_or_default();
    for name in groups {
        if name.ends_with('/') {
            continue;
        }
        resolve_group(storage, mounts, &name, GroupKind::Resource, items, warnings).await?;
    }

    Ok(())
}

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
        let bp = mounts.barrier_prefix(uuid);
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
    let group_key = format!("{}resource-group/group/{canonical}", mounts.system_prefix());
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
    let bp = mounts.barrier_prefix(uuid);
    // KvItem.path is the barrier-relative key so it round-trips through
    // `import_from_document`. kv-v2 keeps the live value under `data/<key>`;
    // kv-v1 stores it directly. Try the kv-v2 layout first.
    for barrier_rel in [format!("data/{rel}"), rel.clone()] {
        if let Some(entry) = storage.get(&format!("{bp}{barrier_rel}")).await? {
            items.kv.push(KvItem {
                mount: ensure_trailing_slash(mount_path),
                path: barrier_rel,
                value: parse_json_or_b64(&entry.value),
            });
            return Ok(());
        }
    }
    warnings.push(format!("secret path {canonical_path} not found in storage"));
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
        let bp = mounts.barrier_prefix(uuid);
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

/// Capture a `kv` / `kv-v2` mount's secrets from its barrier subtree
/// (`<root>logical/<uuid>/…`), emitting one `KvItem` per leaf key. The stored
/// `path` is the key **relative to the mount's barrier prefix** (e.g.
/// `data/myapp/db`, `metadata/myapp/db` for kv-v2; `myapp/db` for kv-v1), so
/// `import_from_document` can write it straight back under the destination
/// mount's barrier prefix.
///
/// `logical_filter` scopes a selective `KvPath` export to a logical secret
/// path: a kv-v2 key `data/<lp>` / `metadata/<lp>` (or a kv-v1 key `<lp>`) is
/// kept only when `<lp>` is under the requested path. `None` captures the
/// whole mount (full-vault export).
///
/// If the mount has no entry in the index (e.g. a hand-built document or a
/// legacy bare-path layout), falls back to listing the mount path directly so
/// older flows keep working.
async fn read_kv_mount(
    storage: &dyn Storage,
    mounts: &MountIndex,
    mount_norm: &str,
    logical_filter: Option<&str>,
    items: &mut ExchangeItems,
) -> Result<(), RvError> {
    let (scan_prefix, barrier_addressed) = match mounts.kv_uuid_for_mount(mount_norm) {
        Some(uuid) => (mounts.barrier_prefix(uuid), true),
        None => (mount_norm.to_string(), false),
    };
    let keys = list_recursive(storage, &scan_prefix).await?;
    for full_key in keys {
        let relative = full_key
            .strip_prefix(&scan_prefix)
            .unwrap_or(&full_key)
            .to_string();
        if let Some(lp) = logical_filter {
            let matches = if barrier_addressed {
                kv_logical_key_matches(&relative, lp)
            } else {
                relative.starts_with(strip_leading_slash(lp))
            };
            if !matches {
                continue;
            }
        }
        if let Some(entry) = storage.get(&full_key).await? {
            items.kv.push(KvItem {
                mount: mount_norm.to_string(),
                path: relative,
                value: entry_value_to_json(&entry),
            });
        }
    }
    Ok(())
}

/// Does a kv-v2 / kv-v1 barrier-relative key fall under the logical secret
/// path `lp`? Strips the kv-v2 `data/` or `metadata/` tree prefix before
/// comparing; kv-v1 keys are compared directly.
fn kv_logical_key_matches(relative: &str, lp: &str) -> bool {
    let lp = strip_leading_slash(lp);
    for tree in ["data/", "metadata/"] {
        if let Some(rest) = relative.strip_prefix(tree) {
            return rest.starts_with(lp);
        }
    }
    relative.starts_with(lp)
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
    mounts: &MountIndex,
    document: &ExchangeDocument,
    policy: ConflictPolicy,
) -> Result<ImportResult, RvError> {
    document.validate_schema_tag().map_err(|_| RvError::ErrRequestInvalid)?;

    let mut result = ImportResult::default();

    for kv in &document.items.kv {
        // Resolve to where the live kv backend reads/writes the item (under
        // the re-rooted barrier prefix), so the preview and the write agree.
        let full_path = mounts.resolve_kv_key(&kv.mount, &kv.path);
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

    /// Re-root activation is the default for every install, so the live
    /// barrier keys are `namespaces/<root_uuid>/…`. Tests model that layout.
    const ROOT_LOGICAL: &str = "namespaces/root-uuid/logical/";
    const ROOT_SYSTEM: &str = "namespaces/root-uuid/sys/";

    /// Build a re-rooted `MountIndex` from `(logical_type, mount_path, uuid)`
    /// triples.
    fn reroot_index(mounts: &[(&str, &str, &str)]) -> MountIndex {
        let mut by_type: HashMap<String, Vec<(String, String)>> = HashMap::new();
        for (ty, path, uuid) in mounts {
            by_type
                .entry((*ty).to_string())
                .or_default()
                .push(((*path).to_string(), (*uuid).to_string()));
        }
        MountIndex::for_test(by_type, ROOT_LOGICAL, ROOT_SYSTEM)
    }

    #[test]
    fn resolve_kv_key_uses_reroot_prefix() {
        let mounts = reroot_index(&[("kv-v2", "secret/", "u-secret")]);
        // A known mount must resolve to the live re-rooted barrier key, not the
        // bare `secret/…` path. This is what the restore dry-run looks up; the
        // old bare-path lookup found nothing and reported everything as `new`.
        assert_eq!(
            mounts.resolve_kv_key("secret/", "data/myapp/db"),
            "namespaces/root-uuid/logical/u-secret/data/myapp/db",
        );
        // Mount without a trailing slash and path with a leading slash are
        // normalized the same way the write path normalizes them.
        assert_eq!(
            mounts.resolve_kv_key("secret", "/data/myapp/db"),
            "namespaces/root-uuid/logical/u-secret/data/myapp/db",
        );
        // Unknown mount falls back to the bare mount path (legacy / hand-built).
        assert_eq!(
            mounts.resolve_kv_key("nope/", "data/x"),
            "nope/data/x",
        );
    }

    #[tokio::test]
    async fn export_import_round_trip() {
        let src = MemStorage::default();
        let v1 = serde_json::json!({"u":"alice","p":"hunter2"});
        let v2 = serde_json::json!({"k":"v"});
        // kv-v2 stores live values under `data/<key>` in the mount's barrier
        // subtree. `other/` must be excluded by the `myapp/` path filter.
        populate(
            &src,
            &[
                ("namespaces/root-uuid/logical/u-secret/data/myapp/db", &v1),
                ("namespaces/root-uuid/logical/u-secret/data/myapp/api", &v2),
                ("namespaces/root-uuid/logical/u-secret/data/other/x", &v2),
            ],
        )
        .await;
        let mounts = reroot_index(&[("kv-v2", "secret/", "u-secret")]);

        let scope = ScopeSpec {
            kind: ScopeKind::Selective,
            include: vec![ScopeSelector::KvPath {
                mount: "secret/".to_string(),
                path: "myapp/".to_string(),
            }],
        };
        let doc = export_to_document(&src, &mounts, ExporterInfo::default(), scope)
            .await
            .unwrap();
        // Only the two `myapp/` secrets, captured as barrier-relative paths.
        assert_eq!(doc.items.kv.len(), 2);
        assert_eq!(doc.items.kv[0].path, "data/myapp/api");
        assert_eq!(doc.items.kv[1].path, "data/myapp/db");

        // Round-trip canonical JSON.
        let bytes_a = to_canonical_vec(&doc).unwrap();
        let bytes_b = to_canonical_vec(&doc).unwrap();
        assert_eq!(bytes_a, bytes_b);

        // Import into a fresh vault — must land back under the barrier prefix.
        let dst = MemStorage::default();
        let result = import_from_document(&dst, &mounts, &doc, ConflictPolicy::Skip).await.unwrap();
        assert_eq!(result.written, 2);
        assert_eq!(result.unchanged, 0);
        assert_eq!(result.skipped, 0);
        assert_eq!(
            dst.get("namespaces/root-uuid/logical/u-secret/data/myapp/db")
                .await
                .unwrap()
                .unwrap()
                .value,
            serde_json::to_vec(&v1).unwrap()
        );
    }

    #[tokio::test]
    async fn full_scope_walks_every_kv_mount() {
        let src = MemStorage::default();
        populate(
            &src,
            &[
                ("namespaces/root-uuid/logical/u-secret/data/app/db", &serde_json::json!({"u": "a"})),
                ("namespaces/root-uuid/logical/u-secret/data/app/api", &serde_json::json!({"k": "v"})),
                ("namespaces/root-uuid/logical/u-kv2/data/team/token", &serde_json::json!({"t": 1})),
            ],
        )
        .await;
        let mounts = reroot_index(&[
            ("kv", "secret/", "u-secret"),
            ("kv-v2", "kv2/", "u-kv2"),
        ]);

        // `Full` with an empty include list must still enumerate everything.
        let scope = ScopeSpec { kind: ScopeKind::Full, include: vec![] };
        let doc = export_to_document(&src, &mounts, ExporterInfo::default(), scope)
            .await
            .unwrap();

        assert_eq!(doc.items.kv.len(), 3);
        let paths: Vec<_> = doc.items.kv.iter().map(|k| (k.mount.as_str(), k.path.as_str())).collect();
        assert!(paths.contains(&("secret/", "data/app/api")));
        assert!(paths.contains(&("secret/", "data/app/db")));
        assert!(paths.contains(&("kv2/", "data/team/token")));
    }

    /// Regression test for the reported bug: a full-vault export of a
    /// re-rooted vault (`namespaces/<uuid>/…`, the default layout) must
    /// capture KV secrets, file blobs, resources, and groups — not come back
    /// empty. The pre-fix resolver hardcoded the bare `logical/` / `sys/`
    /// prefixes and produced a zero-item document.
    #[tokio::test]
    async fn full_scope_reroot_captures_all_mount_types() {
        let src = MemStorage::default();
        let secret_val = serde_json::json!({"password": "s3cr3t"});
        let resource_meta = serde_json::json!({"id": "t12", "kind": "host"});
        let file_meta = serde_json::json!({"name": "doc.bin", "sha256": "ab"});
        let group_val = serde_json::json!({"name": "grp", "members": [], "secrets": [], "files": []});
        populate(
            &src,
            &[
                ("namespaces/root-uuid/logical/u-secret/data/myapp/db", &secret_val),
                ("namespaces/root-uuid/logical/u-res/meta/t12", &resource_meta),
                ("namespaces/root-uuid/logical/u-files/meta/f1", &file_meta),
                ("namespaces/root-uuid/sys/resource-group/group/grp", &group_val),
            ],
        )
        .await;
        // The file blob is raw bytes (non-JSON) addressed by id.
        src.put(&StorageEntry {
            key: "namespaces/root-uuid/logical/u-files/blob/f1".to_string(),
            value: vec![1u8, 2, 3, 4],
        })
        .await
        .unwrap();

        let mounts = reroot_index(&[
            ("kv-v2", "secret/", "u-secret"),
            ("resource", "resources/", "u-res"),
            ("files", "files/", "u-files"),
        ]);

        let scope = ScopeSpec { kind: ScopeKind::Full, include: vec![] };
        let doc = export_to_document(&src, &mounts, ExporterInfo::default(), scope)
            .await
            .unwrap();

        assert_eq!(doc.items.kv.len(), 1, "KV secret must be captured");
        assert_eq!(doc.items.kv[0].path, "data/myapp/db");
        assert_eq!(doc.items.resources.len(), 1, "resource must be captured");
        assert_eq!(doc.items.resources[0].id, "t12");
        assert_eq!(doc.items.files.len(), 1, "file blob must be captured");
        assert_eq!(doc.items.files[0].id, "f1");
        use base64::Engine;
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(doc.items.files[0].content_b64.as_bytes())
                .unwrap(),
            vec![1u8, 2, 3, 4]
        );
        assert_eq!(doc.items.resource_groups.len(), 1, "group must be captured");
        assert_eq!(doc.items.resource_groups[0].id, "grp");
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

        let result = import_from_document(&store, &MountIndex::empty(), &doc, ConflictPolicy::Skip).await.unwrap();
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

        let result = import_from_document(&store, &MountIndex::empty(), &doc, ConflictPolicy::Rename).await.unwrap();
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

        let result = import_from_document(&store, &MountIndex::empty(), &doc, ConflictPolicy::Skip).await.unwrap();
        assert_eq!(result.unchanged, 1);
        assert_eq!(result.written, 0);
    }
}
