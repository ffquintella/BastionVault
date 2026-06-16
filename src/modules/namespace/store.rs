//! `NamespaceStore`: persistence and lookup for the multi-tenant namespace
//! tree.
//!
//! A namespace is an addressable container identified by a slash-delimited
//! *path* (`engineering`, `engineering/platform`) and an immutable *UUID*.
//! The path is mutable (rename); the UUID is the storage key and never
//! changes. The root namespace is implicit, has the empty path `""`, and is
//! created on first unseal by [`NamespaceStore::ensure_root`].
//!
//! ## Storage layout
//!
//! The registry lives at the barrier-root prefix `namespaces/registry/`,
//! which is *outside* every per-namespace data prefix
//! (`namespaces/<uuid>/...`). Keeping it there avoids a circular dependency:
//! the re-rooting migration (see [`super::migrate`]) moves per-namespace data
//! under `namespaces/<root_uuid>/` but never touches the registry, and the
//! reserved key segment `registry` can never collide with a UUID.
//!
//! ```text
//! namespaces/registry/
//!   root-uuid                 -> the root namespace's UUID (plain bytes)
//!   config/<uuid>             -> Namespace (JSON)
//!   by-path/<b64url(path)>    -> <uuid> (plain bytes; path index)
//! ```
//!
//! Children are discovered by scanning `config/` and filtering on
//! `parent_uuid`; namespace counts are operationally small (tens to low
//! hundreds) so a linear scan is cheaper than maintaining a second index.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    bv_error_response_status, bv_error_string,
    core::Core,
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
    utils::generate_uuid,
};

/// Barrier-root prefix for the namespace registry. Reserved: no namespace
/// UUID can equal `registry`, so `namespaces/registry/` never collides with
/// a per-namespace data prefix `namespaces/<uuid>/`.
pub const NAMESPACE_REGISTRY_PREFIX: &str = "namespaces/registry/";

const ROOT_UUID_KEY: &str = "root-uuid";
const CONFIG_PREFIX: &str = "config/";
const BY_PATH_PREFIX: &str = "by-path/";

/// Per-namespace resource quotas. Carried on every namespace from Phase 1 so
/// the config format is stable; enforcement is wired in Phase 4
/// (`super::quota`). A value of `0` means "unlimited" for every field.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NamespaceQuotas {
    #[serde(default)]
    pub max_storage_bytes: u64,
    #[serde(default)]
    pub max_leases: u64,
    #[serde(default)]
    pub request_rate: u64,
    #[serde(default)]
    pub max_mounts: u64,
    #[serde(default)]
    pub max_entities: u64,
    #[serde(default)]
    pub max_child_namespaces: u64,
}

/// A namespace record. `path` is the full slash-delimited path with no
/// trailing slash (root = `""`); `parent_uuid` is empty for the root.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Namespace {
    pub uuid: String,
    pub path: String,
    #[serde(default)]
    pub parent_uuid: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub quotas: NamespaceQuotas,
    /// Default `child_visible` flag applied to tokens minted in this
    /// namespace when the create request does not specify one. The
    /// per-token flag itself lands in Phase 2 (`super::token_binding`).
    #[serde(default)]
    pub child_visible_default: bool,
}

impl Namespace {
    pub fn is_root(&self) -> bool {
        self.parent_uuid.is_empty() && self.path.is_empty()
    }
}

/// Validate a single namespace path segment. Rejects empty segments and any
/// segment containing a path separator, parent-traversal, or wildcard. These
/// are the characters that would let a namespace name escape its registry key
/// or alias another namespace's storage prefix.
pub fn validate_segment(segment: &str) -> Result<(), RvError> {
    if segment.is_empty() {
        return Err(bv_error_string!("namespace segment must not be empty"));
    }
    if segment.contains('/') || segment.contains("..") || segment.contains('*') {
        return Err(bv_error_string!(format!(
            "invalid namespace segment {segment:?}: must not contain '/', '..', or '*'"
        )));
    }
    // Defense in depth: the segment becomes part of a storage key, so refuse
    // control characters and leading/trailing whitespace that could confuse
    // path comparisons.
    if segment.trim() != segment || segment.chars().any(|c| c.is_control()) {
        return Err(bv_error_string!(format!(
            "invalid namespace segment {segment:?}: surrounding whitespace or control characters"
        )));
    }
    Ok(())
}

/// Normalize a caller-supplied namespace path: strip surrounding slashes and
/// whitespace, reject empties, and validate every segment. Returns the
/// canonical form (no leading/trailing slash). The empty string maps to the
/// root namespace.
pub fn normalize_path(raw: &str) -> Result<String, RvError> {
    let trimmed = raw.trim().trim_matches('/');
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let mut segments = Vec::new();
    for seg in trimmed.split('/') {
        validate_segment(seg)?;
        segments.push(seg);
    }
    Ok(segments.join("/"))
}

/// Split a canonical path into `(parent_path, leaf_name)`. Root has no parent.
fn split_parent(path: &str) -> Option<(String, String)> {
    if path.is_empty() {
        return None;
    }
    match path.rsplit_once('/') {
        Some((parent, leaf)) => Some((parent.to_string(), leaf.to_string())),
        None => Some((String::new(), path.to_string())),
    }
}

fn path_index_key(path: &str) -> String {
    format!("{BY_PATH_PREFIX}{}", URL_SAFE_NO_PAD.encode(path.as_bytes()))
}

fn config_key(uuid: &str) -> String {
    format!("{CONFIG_PREFIX}{uuid}")
}

pub struct NamespaceStore {
    view: Arc<BarrierView>,
    /// `path -> uuid` cache, refreshed on every mutation. Bounded by the
    /// number of namespaces (operationally small).
    path_cache: RwLock<HashMap<String, String>>,
    root_uuid: RwLock<String>,
}

#[maybe_async::maybe_async]
impl NamespaceStore {
    pub fn new(core: &Core) -> Result<Self, RvError> {
        let barrier = core.barrier.clone();
        let view = Arc::new(BarrierView::new(barrier, NAMESPACE_REGISTRY_PREFIX));
        Ok(Self {
            view,
            path_cache: RwLock::new(HashMap::new()),
            root_uuid: RwLock::new(String::new()),
        })
    }

    /// Ensure the implicit root namespace exists, returning its UUID. Idempotent:
    /// the first call mints the root and records its UUID; later calls read it
    /// back. The root UUID is also held in memory for the lifetime of the store.
    pub async fn ensure_root(&self) -> Result<String, RvError> {
        if let Some(entry) = self.view.get(ROOT_UUID_KEY).await? {
            let uuid = String::from_utf8(entry.value)
                .map_err(|e| bv_error_string!(format!("corrupt root-uuid record: {e}")))?;
            *self.root_uuid.write()? = uuid.clone();
            return Ok(uuid);
        }

        let uuid = generate_uuid();
        let ns = Namespace {
            uuid: uuid.clone(),
            path: String::new(),
            parent_uuid: String::new(),
            created_at: Utc::now().to_rfc3339(),
            quotas: NamespaceQuotas::default(),
            child_visible_default: false,
        };
        self.persist(&ns).await?;
        self.view
            .put(&StorageEntry { key: ROOT_UUID_KEY.to_string(), value: uuid.clone().into_bytes() })
            .await?;
        *self.root_uuid.write()? = uuid.clone();
        Ok(uuid)
    }

    pub fn root_uuid(&self) -> Result<String, RvError> {
        let uuid = self.root_uuid.read()?.clone();
        if uuid.is_empty() {
            return Err(bv_error_string!("namespace store not initialized (no root uuid)"));
        }
        Ok(uuid)
    }

    async fn persist(&self, ns: &Namespace) -> Result<(), RvError> {
        let value = serde_json::to_vec(ns)?;
        self.view.put(&StorageEntry { key: config_key(&ns.uuid), value }).await?;
        self.view
            .put(&StorageEntry { key: path_index_key(&ns.path), value: ns.uuid.clone().into_bytes() })
            .await?;
        self.path_cache.write()?.insert(ns.path.clone(), ns.uuid.clone());
        Ok(())
    }

    pub async fn get_by_uuid(&self, uuid: &str) -> Result<Option<Namespace>, RvError> {
        match self.view.get(&config_key(uuid)).await? {
            Some(entry) => Ok(Some(serde_json::from_slice(&entry.value)?)),
            None => Ok(None),
        }
    }

    pub async fn get_by_path(&self, raw_path: &str) -> Result<Option<Namespace>, RvError> {
        let path = normalize_path(raw_path)?;
        // Clone out of the cache and drop the guard before any await — the
        // guard is not Send and must not be held across the suspension point.
        let cached = self.path_cache.read()?.get(&path).cloned();
        if let Some(uuid) = cached {
            return self.get_by_uuid(&uuid).await;
        }
        match self.view.get(&path_index_key(&path)).await? {
            Some(entry) => {
                let uuid = String::from_utf8(entry.value)
                    .map_err(|e| bv_error_string!(format!("corrupt path index: {e}")))?;
                self.path_cache.write()?.insert(path, uuid.clone());
                self.get_by_uuid(&uuid).await
            }
            None => Ok(None),
        }
    }

    /// Resolve a namespace path to its UUID, returning a 404-style error if no
    /// such namespace exists. The router uses this to distinguish "no such
    /// namespace" (404) from "not allowed" (403).
    pub async fn resolve_path_to_uuid(&self, raw_path: &str) -> Result<String, RvError> {
        match self.get_by_path(raw_path).await? {
            Some(ns) => Ok(ns.uuid),
            None => {
                let path = normalize_path(raw_path).unwrap_or_else(|_| raw_path.to_string());
                Err(bv_error_response_status!(404, &format!("no such namespace: {path:?}")))
            }
        }
    }

    /// All namespace records, unordered.
    pub async fn list_all(&self) -> Result<Vec<Namespace>, RvError> {
        let keys = self.view.list(CONFIG_PREFIX).await?;
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            let uuid = k.trim_end_matches('/');
            if let Some(ns) = self.get_by_uuid(uuid).await? {
                out.push(ns);
            }
        }
        Ok(out)
    }

    /// Immediate child namespaces of `parent_path` (leaf names, sorted).
    pub async fn list_children(&self, parent_path: &str) -> Result<Vec<String>, RvError> {
        let parent = self.get_by_path(parent_path).await?.ok_or_else(|| {
            bv_error_response_status!(404, &format!("no such namespace: {parent_path:?}"))
        })?;
        let mut names: Vec<String> = self
            .list_all()
            .await?
            .into_iter()
            .filter(|ns| ns.parent_uuid == parent.uuid && ns.uuid != parent.uuid)
            .filter_map(|ns| split_parent(&ns.path).map(|(_, leaf)| leaf))
            .collect();
        names.sort();
        Ok(names)
    }

    /// Create a child namespace at `path`. The parent must already exist; the
    /// path must not already be taken. Returns the new record.
    pub async fn create(
        &self,
        raw_path: &str,
        quotas: NamespaceQuotas,
        child_visible_default: bool,
    ) -> Result<Namespace, RvError> {
        let path = normalize_path(raw_path)?;
        if path.is_empty() {
            return Err(bv_error_string!("cannot create the root namespace"));
        }
        if self.get_by_path(&path).await?.is_some() {
            return Err(bv_error_response_status!(409, &format!("namespace already exists: {path:?}")));
        }
        let (parent_path, _leaf) =
            split_parent(&path).ok_or_else(|| bv_error_string!("invalid namespace path"))?;
        let parent = self.get_by_path(&parent_path).await?.ok_or_else(|| {
            bv_error_response_status!(404, &format!("parent namespace does not exist: {parent_path:?}"))
        })?;

        let ns = Namespace {
            uuid: generate_uuid(),
            path,
            parent_uuid: parent.uuid,
            created_at: Utc::now().to_rfc3339(),
            quotas,
            child_visible_default,
        };
        self.persist(&ns).await?;
        Ok(ns)
    }

    /// Update mutable fields of an existing namespace. `None` means "leave
    /// unchanged". The root namespace's quotas may be updated but it cannot be
    /// renamed.
    pub async fn update(
        &self,
        raw_path: &str,
        quotas: Option<NamespaceQuotas>,
        child_visible_default: Option<bool>,
    ) -> Result<Namespace, RvError> {
        let mut ns = self.get_by_path(raw_path).await?.ok_or_else(|| {
            let p = normalize_path(raw_path).unwrap_or_else(|_| raw_path.to_string());
            bv_error_response_status!(404, &format!("no such namespace: {p:?}"))
        })?;
        if let Some(q) = quotas {
            ns.quotas = q;
        }
        if let Some(cv) = child_visible_default {
            ns.child_visible_default = cv;
        }
        self.persist(&ns).await?;
        Ok(ns)
    }

    /// Delete a namespace. Refused for the root, for namespaces with children,
    /// or (when `mount_count > 0`) for namespaces that still hold mounts. The
    /// mount check is supplied by the caller because the mount table lives in
    /// `Core`, not the store.
    pub async fn delete(&self, raw_path: &str, mount_count: usize) -> Result<(), RvError> {
        let ns = self.get_by_path(raw_path).await?.ok_or_else(|| {
            let p = normalize_path(raw_path).unwrap_or_else(|_| raw_path.to_string());
            bv_error_response_status!(404, &format!("no such namespace: {p:?}"))
        })?;
        if ns.is_root() {
            return Err(bv_error_string!("cannot delete the root namespace"));
        }
        let children = self.list_children(&ns.path).await?;
        if !children.is_empty() {
            return Err(bv_error_response_status!(
                409,
                &format!("namespace {:?} has child namespaces: {}", ns.path, children.join(", "))
            ));
        }
        if mount_count > 0 {
            return Err(bv_error_response_status!(
                409,
                &format!("namespace {:?} still has {mount_count} mount(s); unmount them first", ns.path)
            ));
        }
        self.view.delete(&config_key(&ns.uuid)).await?;
        self.view.delete(&path_index_key(&ns.path)).await?;
        self.path_cache.write()?.remove(&ns.path);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_segment_rejects_dangerous_names() {
        assert!(validate_segment("engineering").is_ok());
        assert!(validate_segment("team-a_1").is_ok());
        // Empty, separators, traversal, wildcards, whitespace, control chars.
        assert!(validate_segment("").is_err());
        assert!(validate_segment("a/b").is_err());
        assert!(validate_segment("..").is_err());
        assert!(validate_segment("a..b").is_err());
        assert!(validate_segment("a*").is_err());
        assert!(validate_segment(" a").is_err());
        assert!(validate_segment("a ").is_err());
        assert!(validate_segment("a\tb").is_err());
    }

    #[test]
    fn test_normalize_path_roundtrips_and_canonicalizes() {
        assert_eq!(normalize_path("").unwrap(), "");
        assert_eq!(normalize_path("/").unwrap(), "");
        assert_eq!(normalize_path("engineering").unwrap(), "engineering");
        assert_eq!(normalize_path("/engineering/").unwrap(), "engineering");
        assert_eq!(
            normalize_path("engineering/platform/secops").unwrap(),
            "engineering/platform/secops"
        );
        assert_eq!(normalize_path("  engineering/platform  ").unwrap(), "engineering/platform");
        // Any invalid segment fails the whole path.
        assert!(normalize_path("engineering/../marketing").is_err());
        assert!(normalize_path("engineering/team*").is_err());
    }

    #[test]
    fn test_split_parent() {
        assert_eq!(split_parent(""), None);
        assert_eq!(split_parent("a"), Some((String::new(), "a".to_string())));
        assert_eq!(
            split_parent("a/b/c"),
            Some(("a/b".to_string(), "c".to_string()))
        );
    }
}
