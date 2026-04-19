//! Asset-group store (internally named resource-group for historical
//! reasons — the mount path, storage keys, and module name all predate
//! the KV-secret extension). Stores named collections of resources
//! **and KV-secret paths** behind the vault barrier. Two parallel
//! reverse indexes make "which groups contain this resource?" and
//! "which groups contain this secret?" O(1) per target.
//!
//! Storage layout (all under the system barrier view):
//!   sys/resource-group/group/{name}                -> ResourceGroupEntry (JSON)
//!   sys/resource-group/member-index/{resource}     -> Vec<String>  (group names)
//!   sys/resource-group/secret-index/{b64(path)}    -> Vec<String>  (group names)
//!   sys/resource-group/history/{name}/<seq>        -> ResourceGroupHistoryEntry
//!
//! Group names are lowercased on write. Resource-member names are
//! canonicalized (trimmed, lowercased) before persisting. KV-secret
//! paths are canonicalized by stripping the `data/` or `metadata/`
//! segment that KV-v2 inserts between the mount and the logical key,
//! so `secret/data/foo/bar`, `secret/metadata/foo/bar`, and
//! `secret/foo/bar` all map to the same group-membership entry. The
//! stored `members` list is deduped and sorted; the stored `secrets`
//! list is likewise deduped and sorted.
//!
//! Authorization integration (the `groups` ACL qualifier) is a separate
//! concern — this store only maintains the data and the reverse indexes.

use std::{sync::Arc, collections::BTreeSet};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    core::Core,
    errors::RvError,
    bv_error_string,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

const GROUP_SUB_PATH: &str = "resource-group/group/";
const MEMBER_INDEX_SUB_PATH: &str = "resource-group/member-index/";
const SECRET_INDEX_SUB_PATH: &str = "resource-group/secret-index/";
const HISTORY_SUB_PATH: &str = "resource-group/history/";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceGroupEntry {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Resource names in the group. Lowercased, trimmed, deduped,
    /// sorted on every write.
    #[serde(default)]
    pub members: Vec<String>,
    /// KV-secret paths in the group, stored in canonical form (no
    /// `data/` or `metadata/` segment). Deduped, sorted on every write.
    #[serde(default)]
    pub secrets: Vec<String>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
}

/// Audit log entry for a resource-group change. Mirrors
/// `GroupHistoryEntry` from identity groups so the GUI can reuse its
/// before/after diff renderer.
///
/// Values:
///   - `description`: JSON string
///   - `members`:     JSON array of strings
///
/// For `create`, `before` is empty; for `delete`, `after` is empty; for
/// `update`, both hold values for exactly the changed fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceGroupHistoryEntry {
    pub ts: String,
    pub user: String,
    /// "create" | "update" | "delete"
    pub op: String,
    #[serde(default)]
    pub changed_fields: Vec<String>,
    #[serde(default)]
    pub before: Map<String, Value>,
    #[serde(default)]
    pub after: Map<String, Value>,
}

pub struct ResourceGroupStore {
    group_view: Arc<BarrierView>,
    index_view: Arc<BarrierView>,
    secret_index_view: Arc<BarrierView>,
    history_view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl ResourceGroupStore {
    pub async fn new(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };

        let group_view = Arc::new(system_view.new_sub_view(GROUP_SUB_PATH));
        let index_view = Arc::new(system_view.new_sub_view(MEMBER_INDEX_SUB_PATH));
        let secret_index_view = Arc::new(system_view.new_sub_view(SECRET_INDEX_SUB_PATH));
        let history_view = Arc::new(system_view.new_sub_view(HISTORY_SUB_PATH));

        Ok(Arc::new(Self {
            group_view,
            index_view,
            secret_index_view,
            history_view,
        }))
    }

    pub(crate) fn sanitize_name(name: &str) -> Result<String, RvError> {
        let n = name.trim().to_lowercase();
        if n.is_empty() {
            return Err(bv_error_string!("group name missing"));
        }
        if n.contains('/') || n.contains("..") {
            return Err(bv_error_string!("invalid group name"));
        }
        Ok(n)
    }

    fn sanitize_member(m: &str) -> Option<String> {
        let t = m.trim().to_lowercase();
        if t.is_empty() || t.contains('/') || t.contains("..") {
            return None;
        }
        Some(t)
    }

    /// Canonicalize a KV-secret path for membership storage and lookup.
    ///
    /// - Leading / trailing slashes stripped.
    /// - The `data/` or `metadata/` segment that KV-v2 inserts between
    ///   the mount and the logical key is removed when it appears in
    ///   the second position. So `secret/data/foo/bar`,
    ///   `secret/metadata/foo/bar`, and `secret/foo/bar` all canonicalize
    ///   to `secret/foo/bar`. This is a heuristic — a mount literally
    ///   named `data` or `metadata` would be misclassified, which we
    ///   accept as a documented limitation.
    /// - Case-preserving: KV paths are case-sensitive on the backend,
    ///   so we don't lowercase here.
    /// - `..` is rejected to avoid path-traversal in the key space.
    ///
    /// Returns `None` when the resulting path is empty or contains `..`.
    pub(crate) fn canonicalize_secret_path(raw: &str) -> Option<String> {
        let trimmed = raw.trim().trim_matches('/');
        if trimmed.is_empty() || trimmed.split('/').any(|s| s == "..") {
            return None;
        }
        let segs: Vec<&str> = trimmed.split('/').collect();
        let canonical: String = if segs.len() >= 2 && (segs[1] == "data" || segs[1] == "metadata") {
            let mut out = String::from(segs[0]);
            for s in &segs[2..] {
                out.push('/');
                out.push_str(s);
            }
            out
        } else {
            trimmed.to_string()
        };
        if canonical.is_empty() {
            None
        } else {
            Some(canonical)
        }
    }

    /// Storage-key for a canonical secret path. Uses base64url (no
    /// padding) so the stored key never contains `/` and is safe to
    /// use as a BarrierView leaf name.
    fn secret_index_key(canonical_path: &str) -> String {
        URL_SAFE_NO_PAD.encode(canonical_path.as_bytes())
    }

    /// Read-modify-write the primary record *and* keep both reverse
    /// indexes (resources + secrets) in sync with the diff between old
    /// and new membership. Reverse-index failures surface as errors —
    /// callers should treat a failed write as a failed set.
    pub async fn set_group(
        &self,
        mut entry: ResourceGroupEntry,
    ) -> Result<ResourceGroupEntry, RvError> {
        let name = Self::sanitize_name(&entry.name)?;
        entry.name = name.clone();

        // Canonicalize resource members: lowercase, trim, drop empties,
        // dedup, sort. Sort produces a stable on-disk order.
        let mut canonical_members: BTreeSet<String> = BTreeSet::new();
        for m in entry.members.drain(..) {
            if let Some(c) = Self::sanitize_member(&m) {
                canonical_members.insert(c);
            }
        }
        entry.members = canonical_members.iter().cloned().collect();

        // Canonicalize secret paths: strip leading/trailing slashes,
        // drop the KV-v2 `data/` / `metadata/` segment, dedup, sort.
        let mut canonical_secrets: BTreeSet<String> = BTreeSet::new();
        for s in entry.secrets.drain(..) {
            if let Some(c) = Self::canonicalize_secret_path(&s) {
                canonical_secrets.insert(c);
            }
        }
        entry.secrets = canonical_secrets.iter().cloned().collect();

        let (old_members, old_secrets) = match self.get_group(&name).await? {
            Some(g) => (
                g.members.into_iter().collect::<BTreeSet<String>>(),
                g.secrets.into_iter().collect::<BTreeSet<String>>(),
            ),
            None => (BTreeSet::new(), BTreeSet::new()),
        };
        let new_members: BTreeSet<String> = entry.members.iter().cloned().collect();
        let new_secrets: BTreeSet<String> = entry.secrets.iter().cloned().collect();

        let value = serde_json::to_vec(&entry)?;
        self.group_view.put(&StorageEntry { key: name.clone(), value }).await?;

        for m in new_members.difference(&old_members) {
            self.add_to_index(m, &name).await?;
        }
        for m in old_members.difference(&new_members) {
            self.remove_from_index(m, &name).await?;
        }
        for s in new_secrets.difference(&old_secrets) {
            self.add_to_secret_index(s, &name).await?;
        }
        for s in old_secrets.difference(&new_secrets) {
            self.remove_from_secret_index(s, &name).await?;
        }

        Ok(entry)
    }

    pub async fn get_group(&self, name: &str) -> Result<Option<ResourceGroupEntry>, RvError> {
        let name = Self::sanitize_name(name)?;
        let entry = self.group_view.get(&name).await?;
        match entry {
            Some(e) => {
                let g: ResourceGroupEntry = serde_json::from_slice(&e.value)?;
                Ok(Some(g))
            }
            None => Ok(None),
        }
    }

    pub async fn list_groups(&self) -> Result<Vec<String>, RvError> {
        let mut keys = self.group_view.get_keys().await?;
        keys.sort();
        Ok(keys)
    }

    pub async fn delete_group(&self, name: &str) -> Result<(), RvError> {
        let name = Self::sanitize_name(name)?;
        let (old_members, old_secrets) = match self.get_group(&name).await? {
            Some(g) => (g.members, g.secrets),
            None => (Vec::new(), Vec::new()),
        };

        self.group_view.delete(&name).await?;

        for m in old_members {
            self.remove_from_index(&m, &name).await?;
        }
        for s in old_secrets {
            self.remove_from_secret_index(&s, &name).await?;
        }
        Ok(())
    }

    /// List every group that currently contains `resource_name`. Returns an
    /// empty vec when the resource is not a member of any group.
    pub async fn groups_for_resource(&self, resource_name: &str) -> Result<Vec<String>, RvError> {
        let Some(key) = Self::sanitize_member(resource_name) else {
            return Ok(Vec::new());
        };
        match self.index_view.get(&key).await? {
            Some(e) => {
                let names: Vec<String> = serde_json::from_slice(&e.value).unwrap_or_default();
                Ok(names)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Prune `resource_name` from every group it is currently in.
    /// Intended as a lifecycle hook for resource deletion — callers may
    /// invoke this to keep groups tidy when a resource is destroyed. The
    /// primary records are rewritten to drop the member; the reverse-index
    /// entry for the resource is removed.
    pub async fn prune_resource(&self, resource_name: &str) -> Result<Vec<String>, RvError> {
        let groups = self.groups_for_resource(resource_name).await?;
        let target = resource_name.trim().to_lowercase();

        for g_name in &groups {
            if let Some(mut g) = self.get_group(g_name).await? {
                g.members.retain(|m| m.trim().to_lowercase() != target);
                g.updated_at = now_iso();
                let value = serde_json::to_vec(&g)?;
                self.group_view.put(&StorageEntry { key: g.name.clone(), value }).await?;
            }
        }

        if let Some(key) = Self::sanitize_member(resource_name) {
            self.index_view.delete(&key).await?;
        }
        Ok(groups)
    }

    /// List every group that currently contains `path` as a secret
    /// member. The lookup canonicalizes `path` the same way writes do,
    /// so callers may pass either the logical form (`secret/foo/bar`)
    /// or the KV-v2 API form (`secret/data/foo/bar` /
    /// `secret/metadata/foo/bar`). Returns an empty vec when the path
    /// is not a member of any group.
    pub async fn groups_for_secret(&self, path: &str) -> Result<Vec<String>, RvError> {
        let Some(canonical) = Self::canonicalize_secret_path(path) else {
            return Ok(Vec::new());
        };
        let key = Self::secret_index_key(&canonical);
        match self.secret_index_view.get(&key).await? {
            Some(e) => {
                let names: Vec<String> = serde_json::from_slice(&e.value).unwrap_or_default();
                Ok(names)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Prune `path` from every group it is currently a secret member
    /// of. Intended as a lifecycle hook for KV delete/destroy. The
    /// primary records are rewritten to drop the secret; the reverse
    /// index entry is removed. Accepts any form (logical or
    /// KV-v2 `data/`/`metadata/` variant) — the lookup and the
    /// stored-member comparison both canonicalize first.
    pub async fn prune_secret(&self, path: &str) -> Result<Vec<String>, RvError> {
        let Some(canonical) = Self::canonicalize_secret_path(path) else {
            return Ok(Vec::new());
        };
        let groups = self.groups_for_secret(&canonical).await?;

        for g_name in &groups {
            if let Some(mut g) = self.get_group(g_name).await? {
                g.secrets.retain(|s| s != &canonical);
                g.updated_at = now_iso();
                let value = serde_json::to_vec(&g)?;
                self.group_view.put(&StorageEntry { key: g.name.clone(), value }).await?;
            }
        }

        let key = Self::secret_index_key(&canonical);
        self.secret_index_view.delete(&key).await?;
        Ok(groups)
    }

    async fn add_to_secret_index(&self, secret_path: &str, group_name: &str) -> Result<(), RvError> {
        let Some(canonical) = Self::canonicalize_secret_path(secret_path) else {
            return Ok(());
        };
        let key = Self::secret_index_key(&canonical);
        let mut names: Vec<String> = match self.secret_index_view.get(&key).await? {
            Some(e) => serde_json::from_slice(&e.value).unwrap_or_default(),
            None => Vec::new(),
        };
        if !names.iter().any(|n| n == group_name) {
            names.push(group_name.to_string());
            names.sort();
        }
        let value = serde_json::to_vec(&names)?;
        self.secret_index_view.put(&StorageEntry { key, value }).await
    }

    async fn remove_from_secret_index(&self, secret_path: &str, group_name: &str) -> Result<(), RvError> {
        let Some(canonical) = Self::canonicalize_secret_path(secret_path) else {
            return Ok(());
        };
        let key = Self::secret_index_key(&canonical);
        let mut names: Vec<String> = match self.secret_index_view.get(&key).await? {
            Some(e) => serde_json::from_slice(&e.value).unwrap_or_default(),
            None => return Ok(()),
        };
        names.retain(|n| n != group_name);
        if names.is_empty() {
            self.secret_index_view.delete(&key).await
        } else {
            let value = serde_json::to_vec(&names)?;
            self.secret_index_view.put(&StorageEntry { key, value }).await
        }
    }

    async fn add_to_index(&self, resource: &str, group_name: &str) -> Result<(), RvError> {
        let Some(key) = Self::sanitize_member(resource) else {
            return Ok(());
        };
        let mut names: Vec<String> = match self.index_view.get(&key).await? {
            Some(e) => serde_json::from_slice(&e.value).unwrap_or_default(),
            None => Vec::new(),
        };
        if !names.iter().any(|n| n == group_name) {
            names.push(group_name.to_string());
            names.sort();
        }
        let value = serde_json::to_vec(&names)?;
        self.index_view.put(&StorageEntry { key, value }).await
    }

    async fn remove_from_index(&self, resource: &str, group_name: &str) -> Result<(), RvError> {
        let Some(key) = Self::sanitize_member(resource) else {
            return Ok(());
        };
        let mut names: Vec<String> = match self.index_view.get(&key).await? {
            Some(e) => serde_json::from_slice(&e.value).unwrap_or_default(),
            None => return Ok(()),
        };
        names.retain(|n| n != group_name);
        if names.is_empty() {
            self.index_view.delete(&key).await
        } else {
            let value = serde_json::to_vec(&names)?;
            self.index_view.put(&StorageEntry { key, value }).await
        }
    }

    /// Append an audit entry for a group change. History keys are
    /// `{name}/{20-digit-nanos}` so `list_history` returns them in
    /// chronological order.
    pub async fn append_history(
        &self,
        name: &str,
        entry: ResourceGroupHistoryEntry,
    ) -> Result<(), RvError> {
        let name = Self::sanitize_name(name)?;
        let key = format!("{name}/{}", hist_seq());
        let value = serde_json::to_vec(&entry)?;
        self.history_view.put(&StorageEntry { key, value }).await
    }

    /// Return the full history for a single group, newest entry first.
    /// History persists after the group itself is deleted so audit
    /// records remain available until explicitly purged.
    pub async fn list_history(
        &self,
        name: &str,
    ) -> Result<Vec<ResourceGroupHistoryEntry>, RvError> {
        let name = Self::sanitize_name(name)?;
        let prefix = format!("{name}/");
        let mut keys = self.history_view.list(&prefix).await?;
        keys.sort();
        keys.reverse();

        let mut entries = Vec::with_capacity(keys.len());
        for k in keys {
            let full = format!("{prefix}{k}");
            if let Some(e) = self.history_view.get(&full).await? {
                if let Ok(h) = serde_json::from_slice::<ResourceGroupHistoryEntry>(&e.value) {
                    entries.push(h);
                }
            }
        }
        Ok(entries)
    }

    /// Rebuild both reverse indexes from the primary records. Intended
    /// for recovery after an interrupted write or for diagnostics;
    /// callers must have admin-level access since this overwrites
    /// index state.
    pub async fn reindex(&self) -> Result<usize, RvError> {
        for k in self.index_view.get_keys().await? {
            self.index_view.delete(&k).await?;
        }
        for k in self.secret_index_view.get_keys().await? {
            self.secret_index_view.delete(&k).await?;
        }

        let groups = self.list_groups().await?;
        let mut touched = 0usize;
        for gname in &groups {
            if let Some(g) = self.get_group(gname).await? {
                for m in g.members {
                    self.add_to_index(&m, gname).await?;
                    touched += 1;
                }
                for s in g.secrets {
                    self.add_to_secret_index(&s, gname).await?;
                    touched += 1;
                }
            }
        }
        Ok(touched)
    }
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

/// Monotonic-ish 20-digit zero-padded nanoseconds since UNIX epoch.
fn hist_seq() -> String {
    let n = Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_else(|| Utc::now().timestamp_millis() * 1_000_000);
    format!("{:020}", n.max(0) as u128)
}
