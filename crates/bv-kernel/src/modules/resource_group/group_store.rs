//! Asset-group store (internally named resource-group for historical
//! reasons — the mount path, storage keys, and module name all predate
//! the KV-secret extension). Stores named collections of resources
//! **and KV-secret paths** behind the vault barrier. Two parallel
//! reverse indexes make "which groups contain this resource?" and
//! "which groups contain this secret?" O(1) per target.
//!
//! Every group lives in one *scope*, the namespace it was created in, which
//! owns its records, reverse indexes and history. Root keeps the legacy
//! `resource-group/{group,member-index,secret-index,file-index,history}/`
//! keys (old records read as root, no migration); a namespace scope lives
//! under `resource-group/ns/<b64url(ns_path)>/…`. See
//! features/resource-groups.md for the inheritance rules.
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
//!
//! Each scope also keeps a persisted *change version* (`meta/version`), bumped
//! after every mutation of the scope's groups or indexes and never by a read.
//! [`ResourceGroupStore::chain_version`] combines a scope's and its ancestors'
//! records into the token the v2 batch read returns, so a client can ask "has
//! anything I can see changed?" without re-reading every group.

use std::{
    collections::{BTreeMap, BTreeSet},
    hash::{BuildHasher, Hasher},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, OnceLock,
    },
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::kernel_api::VaultCtx;
use crate::{
    bv_error_string,
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

/// Root of every asset-group keyspace; the root scope sits directly under it.
const RESOURCE_GROUP_SUB_PATH: &str = "resource-group/";
/// Parent of the per-namespace scopes: `resource-group/ns/<b64url(ns)>/`.
const NS_SCOPE_SUB_PATH: &str = "resource-group/ns/";

/// The keyspaces every scope owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Keyspace {
    Group,
    MemberIndex,
    SecretIndex,
    FileIndex,
    History,
    /// Scope bookkeeping; holds only the change-version record.
    Meta,
}

impl Keyspace {
    fn leaf(self) -> &'static str {
        match self {
            Keyspace::Group => "group/",
            Keyspace::MemberIndex => "member-index/",
            Keyspace::SecretIndex => "secret-index/",
            Keyspace::FileIndex => "file-index/",
            Keyspace::History => "history/",
            Keyspace::Meta => "meta/",
        }
    }
}

/// Leaf key of the change-version record inside a scope's `meta/` keyspace.
const VERSION_LEAF: &str = "version";
/// Format of [`ScopeVersion`] this build writes and the newest it reads.
const SCOPE_VERSION_FORMAT: u32 = 1;

/// A scope's persisted change version, in vault storage so HA nodes agree.
/// Written after every mutation of the scope's groups or indexes, never by a
/// read. `counter` rises by one per bump for writers that do not race; racing
/// bumps may write the same `counter`, so change detection compares the whole
/// record, and `stamp` is unique per bump. Neither field is secret.
///
/// Absent on scopes that predate it or were never written: that reads as
/// `counter = 0`, `stamp = ""` (read-old); the first mutation writes format 1.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeVersion {
    #[serde(default)]
    pub format: u32,
    #[serde(default)]
    pub counter: u64,
    #[serde(default)]
    pub stamp: String,
}

/// A scope as an operator reads it in a log line.
fn describe(scope: &str) -> String {
    if scope.is_empty() {
        "the root namespace".to_string()
    } else {
        format!("namespace '{scope}'")
    }
}

/// System-view-relative key of scope `ns_path`'s change-version record.
/// Shared with the `.bvx` importer, which writes group records without the
/// store and must bump the same record.
pub fn version_key(ns_path: &str) -> String {
    format!("{}{VERSION_LEAF}", keyspace_path(&scope_of(Some(ns_path)), Keyspace::Meta))
}

/// Decode a stored change-version record. A format newer than this build
/// understands is an error, never a guess.
fn decode_scope_version(bytes: &[u8]) -> Result<ScopeVersion, RvError> {
    let v: ScopeVersion = serde_json::from_slice(bytes)?;
    if v.format > SCOPE_VERSION_FORMAT {
        return Err(bv_error_string!(format!(
            "asset-group change-version record has format {}, newer than this build reads ({SCOPE_VERSION_FORMAT})",
            v.format
        )));
    }
    Ok(v)
}

/// A per-bump unique stamp: BLAKE3 over the scope, the new counter, the wall
/// clock, a per-process seed and a per-process sequence. A cache tag, not a
/// secret and not a security control; uniqueness is all it provides.
fn new_stamp(scope: &str, counter: u64) -> String {
    static SEED: OnceLock<u64> = OnceLock::new();
    static SEQ: AtomicU64 = AtomicU64::new(0);
    // `RandomState` is seeded from the OS once per process, so two nodes (or a
    // restarted node) do not share a seed.
    let seed = *SEED.get_or_init(|| std::collections::hash_map::RandomState::new().build_hasher().finish());
    let nanos = Utc::now().timestamp_nanos_opt().unwrap_or_default();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut h = blake3::Hasher::new();
    for part in
        [scope.as_bytes(), &counter.to_le_bytes(), &nanos.to_le_bytes(), &seed.to_le_bytes(), &seq.to_le_bytes()]
    {
        h.update(&(part.len() as u64).to_le_bytes());
        h.update(part);
    }
    h.finalize().to_hex()[..32].to_string()
}

/// Bump the change-version record at `key` (system-view-relative) in `storage`.
/// Read-modify-write; see [`ScopeVersion`] for what a race costs. A storage
/// error is returned. An undecodable record is replaced, with a warning, by one
/// whose counter restarts at the wall clock in milliseconds (above any count a
/// scope reaches), so the version still moves after the data write landed.
#[maybe_async::maybe_async]
pub async fn bump_version_at(storage: &dyn Storage, key: &str, scope: &str) -> Result<ScopeVersion, RvError> {
    let previous = match storage.get(key).await? {
        None => 0,
        Some(e) => match decode_scope_version(&e.value) {
            Ok(v) => v.counter,
            Err(err) => {
                log::warn!(
                    "asset-group change-version record of {} is unreadable ({err}); replacing it",
                    describe(scope)
                );
                Utc::now().timestamp_millis().max(0) as u64
            }
        },
    };
    let counter = previous.saturating_add(1);
    let next = ScopeVersion { format: SCOPE_VERSION_FORMAT, counter, stamp: new_stamp(scope, counter) };
    storage.put(&StorageEntry { key: key.to_string(), value: serde_json::to_vec(&next)? }).await?;
    Ok(next)
}

/// Scope key of a namespace path: trimmed of whitespace and slashes, case
/// preserved (namespace paths are case-sensitive). `""` is root.
pub fn scope_of(ns_path: Option<&str>) -> String {
    ns_path.map(|n| n.trim().trim_matches('/')).unwrap_or("").to_string()
}

/// System-view-relative prefix of `keyspace` for `scope`. The namespace is
/// base64url'd so it is one key segment and cannot traverse.
fn keyspace_path(scope: &str, keyspace: Keyspace) -> String {
    if scope.is_empty() {
        format!("{RESOURCE_GROUP_SUB_PATH}{}", keyspace.leaf())
    } else {
        format!("{NS_SCOPE_SUB_PATH}{}/{}", URL_SAFE_NO_PAD.encode(scope.as_bytes()), keyspace.leaf())
    }
}

/// Prefix (relative to the system view) of namespace `ns_path`'s group
/// records. Shared with the `.bvx` exporter/importer so they cannot drift.
pub fn group_keyspace(ns_path: &str) -> String {
    keyspace_path(&scope_of(Some(ns_path)), Keyspace::Group)
}

/// Scopes a by-name read from `scope` resolves through, nearest first and
/// ending at root: `"a/b"` gives `["a/b", "a", ""]`.
pub fn scope_chain(scope: &str) -> Vec<String> {
    let segments: Vec<&str> = scope.trim().trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();
    let mut chain: Vec<String> = (1..=segments.len()).rev().map(|i| segments[..i].join("/")).collect();
    chain.push(String::new());
    chain
}

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
    /// File-resource ids (UUIDs) in the group. Lowercased, trimmed,
    /// deduped, sorted on every write. Parallel to `members` (resources)
    /// and `secrets` (KV). Empty on legacy groups created before file
    /// resources existed; `reindex` will populate file-index entries
    /// from any backfilled files.
    #[serde(default)]
    pub files: Vec<String>,
    /// `entity_id` of the caller that created the group, captured on
    /// the first write. Used to gate membership edits to the owner
    /// plus admins, and to drive the GUI's owner badge. Immutable
    /// except through the admin `sys/asset-group-owner/transfer`
    /// endpoint. Empty on groups created by a root token or a caller
    /// whose `entity_id` couldn't be resolved, in which case only
    /// admin policies can edit the group.
    #[serde(default)]
    pub owner_entity_id: String,
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

/// Every stateful method takes `ns_path`, the namespace it acts in (`""` =
/// root). There is no scope-less overload on purpose: a caller that forgot
/// the namespace would silently act on root, the leak scopes exist to close.
pub struct ResourceGroupStore {
    system_view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl ResourceGroupStore {
    pub async fn new(core: &dyn VaultCtx) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.system_view() else {
            return Err(RvError::ErrBarrierSealed);
        };
        Ok(Arc::new(Self { system_view }))
    }

    /// One scope's keyspace view: a prefix over the barrier, no storage I/O.
    fn view(&self, ns_path: &str, keyspace: Keyspace) -> BarrierView {
        self.system_view.new_sub_view(&keyspace_path(&scope_of(Some(ns_path)), keyspace))
    }

    /// Record that scope `ns_path` changed. Called after the mutation's data
    /// writes, so a reader that reads the version before the data never pairs
    /// a new version with old data.
    async fn bump_version(&self, ns_path: &str) -> Result<ScopeVersion, RvError> {
        bump_version_at(self.system_view.as_ref(), &version_key(ns_path), &scope_of(Some(ns_path))).await
    }

    /// Scope `ns_path`'s own change-version record, exactly that scope.
    /// `counter = 0` when none was ever written; an undecodable record or a
    /// storage failure is an error.
    pub async fn scope_version(&self, ns_path: &str) -> Result<ScopeVersion, RvError> {
        match self.system_view.get(&version_key(ns_path)).await? {
            Some(e) => decode_scope_version(&e.value),
            None => Ok(ScopeVersion::default()),
        }
    }

    /// The change token a reader in `ns_path` sees: a digest over the records
    /// of the scope and every ancestor up to root (the scopes a read from
    /// `ns_path` resolves through), so a change in any of them moves it and a
    /// sibling's never does. `None` when any record is unreadable: callers
    /// must then treat the data as changed (fail closed), never as current.
    pub async fn chain_version(&self, ns_path: &str) -> Option<String> {
        let mut h = blake3::Hasher::new();
        for scope in scope_chain(ns_path) {
            let v = match self.scope_version(&scope).await {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("asset-group change version unavailable for {}: {e}", describe(&scope));
                    return None;
                }
            };
            for part in [scope.as_bytes(), &v.counter.to_le_bytes(), v.stamp.as_bytes()] {
                h.update(&(part.len() as u64).to_le_bytes());
                h.update(part);
            }
        }
        Some(h.finalize().to_hex()[..32].to_string())
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

    /// Canonicalize a file-resource id. File ids are server-assigned
    /// UUIDs, never operator-supplied — we lowercase and reject any
    /// non-empty input containing `/` so the canonical form matches
    /// what the files module stores.
    fn sanitize_file_id(raw: &str) -> Option<String> {
        let t = raw.trim().to_lowercase();
        if t.is_empty() || t.contains('/') {
            return None;
        }
        Some(t)
    }

    /// Read-modify-write the primary record *and* keep both reverse
    /// indexes (resources + secrets) in sync with the diff between old
    /// and new membership. Reverse-index failures surface as errors —
    /// callers should treat a failed write as a failed set.
    pub async fn set_group(&self, mut entry: ResourceGroupEntry, ns_path: &str) -> Result<ResourceGroupEntry, RvError> {
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

        // Canonicalize file ids: lowercase, trim, drop empties / `/`,
        // dedup, sort.
        let mut canonical_files: BTreeSet<String> = BTreeSet::new();
        for f in entry.files.drain(..) {
            if let Some(c) = Self::sanitize_file_id(&f) {
                canonical_files.insert(c);
            }
        }
        entry.files = canonical_files.iter().cloned().collect();

        let (old_members, old_secrets, old_files, old_owner) = match self.get_group(&name, ns_path).await? {
            Some(g) => (
                g.members.into_iter().collect::<BTreeSet<String>>(),
                g.secrets.into_iter().collect::<BTreeSet<String>>(),
                g.files.into_iter().collect::<BTreeSet<String>>(),
                g.owner_entity_id,
            ),
            None => (BTreeSet::new(), BTreeSet::new(), BTreeSet::new(), String::new()),
        };
        // Owner is immutable via `set_group` — preserved on update,
        // captured on first write (caller supplies the initial value).
        // Use `set_owner` for the admin-only transfer flow.
        if !old_owner.is_empty() {
            entry.owner_entity_id = old_owner;
        }
        let new_members: BTreeSet<String> = entry.members.iter().cloned().collect();
        let new_secrets: BTreeSet<String> = entry.secrets.iter().cloned().collect();
        let new_files: BTreeSet<String> = entry.files.iter().cloned().collect();

        let value = serde_json::to_vec(&entry)?;
        self.view(ns_path, Keyspace::Group).put(&StorageEntry { key: name.clone(), value }).await?;

        for m in new_members.difference(&old_members) {
            self.add_to_index(m, &name, ns_path).await?;
        }
        for m in old_members.difference(&new_members) {
            self.remove_from_index(m, &name, ns_path).await?;
        }
        for s in new_secrets.difference(&old_secrets) {
            self.add_to_secret_index(s, &name, ns_path).await?;
        }
        for s in old_secrets.difference(&new_secrets) {
            self.remove_from_secret_index(s, &name, ns_path).await?;
        }
        for f in new_files.difference(&old_files) {
            self.add_to_file_index(f, &name, ns_path).await?;
        }
        for f in old_files.difference(&new_files) {
            self.remove_from_file_index(f, &name, ns_path).await?;
        }

        self.bump_version(ns_path).await?;
        Ok(entry)
    }

    /// The group `name` in exactly scope `ns_path`, no inheritance. A read
    /// that should see ancestors' groups uses [`Self::resolve_group`].
    pub async fn get_group(&self, name: &str, ns_path: &str) -> Result<Option<ResourceGroupEntry>, RvError> {
        let name = Self::sanitize_name(name)?;
        let entry = self.view(ns_path, Keyspace::Group).get(&name).await?;
        match entry {
            Some(e) => {
                let g: ResourceGroupEntry = serde_json::from_slice(&e.value)?;
                Ok(Some(g))
            }
            None => Ok(None),
        }
    }

    /// Resolve `name` as a read from `ns_path` sees it: own scope, then each
    /// ancestor nearest first, then root. Returns `(home scope, record)`.
    /// A storage error anywhere in the chain is returned, never skipped, so a
    /// farther ancestor's group cannot stand in for the one that shadows it.
    pub async fn resolve_group(
        &self,
        name: &str,
        ns_path: &str,
    ) -> Result<Option<(String, ResourceGroupEntry)>, RvError> {
        let name = Self::sanitize_name(name)?;
        for scope in scope_chain(ns_path) {
            if let Some(g) = self.get_group(&name, &scope).await? {
                return Ok(Some((scope, g)));
            }
        }
        Ok(None)
    }

    /// Group names stored in exactly scope `ns_path`, sorted.
    pub async fn list_groups(&self, ns_path: &str) -> Result<Vec<String>, RvError> {
        let mut keys = self.view(ns_path, Keyspace::Group).get_keys().await?;
        keys.sort();
        Ok(keys)
    }

    /// Every group visible from `ns_path` as `(name, home scope)`, sorted by
    /// name; a nearer scope shadows a farther one of the same name. Errors
    /// propagate for the same reason as in [`Self::resolve_group`].
    pub async fn list_visible_groups(&self, ns_path: &str) -> Result<Vec<(String, String)>, RvError> {
        let mut visible: BTreeMap<String, String> = BTreeMap::new();
        for scope in scope_chain(ns_path) {
            for name in self.list_groups(&scope).await? {
                visible.entry(name).or_insert_with(|| scope.clone());
            }
        }
        Ok(visible.into_iter().collect())
    }

    pub async fn delete_group(&self, name: &str, ns_path: &str) -> Result<(), RvError> {
        let name = Self::sanitize_name(name)?;
        let previous = self.get_group(&name, ns_path).await?;
        let existed = previous.is_some();
        let (old_members, old_secrets, old_files) = match previous {
            Some(g) => (g.members, g.secrets, g.files),
            None => (Vec::new(), Vec::new(), Vec::new()),
        };

        self.view(ns_path, Keyspace::Group).delete(&name).await?;

        for m in old_members {
            self.remove_from_index(&m, &name, ns_path).await?;
        }
        for s in old_secrets {
            self.remove_from_secret_index(&s, &name, ns_path).await?;
        }
        for f in old_files {
            self.remove_from_file_index(&f, &name, ns_path).await?;
        }
        if existed {
            self.bump_version(ns_path).await?;
        }
        Ok(())
    }

    /// Every group of scope `ns_path` containing `resource_name`, a
    /// mount-relative resource name in that namespace. Empty when none.
    pub async fn groups_for_resource(&self, resource_name: &str, ns_path: &str) -> Result<Vec<String>, RvError> {
        let Some(key) = Self::sanitize_member(resource_name) else {
            return Ok(Vec::new());
        };
        match self.view(ns_path, Keyspace::MemberIndex).get(&key).await? {
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
    pub async fn prune_resource(&self, resource_name: &str, ns_path: &str) -> Result<Vec<String>, RvError> {
        let groups = self.groups_for_resource(resource_name, ns_path).await?;
        let target = resource_name.trim().to_lowercase();
        let group_view = self.view(ns_path, Keyspace::Group);

        for g_name in &groups {
            if let Some(mut g) = self.get_group(g_name, ns_path).await? {
                g.members.retain(|m| m.trim().to_lowercase() != target);
                g.updated_at = now_iso();
                let value = serde_json::to_vec(&g)?;
                group_view.put(&StorageEntry { key: g.name.clone(), value }).await?;
            }
        }

        if let Some(key) = Self::sanitize_member(resource_name) {
            self.view(ns_path, Keyspace::MemberIndex).delete(&key).await?;
        }
        if !groups.is_empty() {
            self.bump_version(ns_path).await?;
        }
        Ok(groups)
    }

    /// Re-point every group membership from `old_name` to `new_name`
    /// when a resource is renamed. Each group that listed the old name
    /// now lists the new one; `set_group` keeps the reverse index in
    /// sync (dropping `member-index/<old>` and adding
    /// `member-index/<new>`). Returns the groups that were updated.
    ///
    /// A resource that belongs to no group is a no-op (empty vec). A
    /// `new_name` that canonicalizes to `old_name` is also a no-op.
    pub async fn rename_resource(&self, old_name: &str, new_name: &str, ns_path: &str) -> Result<Vec<String>, RvError> {
        let Some(new_member) = Self::sanitize_member(new_name) else {
            return Err(bv_error_string!("invalid new resource name"));
        };
        let old_target = old_name.trim().to_lowercase();
        if new_member == old_target {
            return Ok(Vec::new());
        }

        let groups = self.groups_for_resource(old_name, ns_path).await?;
        for g_name in &groups {
            if let Some(mut g) = self.get_group(g_name, ns_path).await? {
                // Drop the old member and add the new one. `set_group`
                // canonicalizes + dedups the member list and diffs it
                // against the stored record to fix both directions of
                // the reverse index, so this swap is sufficient.
                g.members.retain(|m| m.trim().to_lowercase() != old_target);
                g.members.push(new_member.clone());
                g.updated_at = now_iso();
                self.set_group(g, ns_path).await?;
            }
        }
        Ok(groups)
    }

    /// List every group that currently contains `path` as a secret
    /// member. The lookup canonicalizes `path` the same way writes do,
    /// so callers may pass either the logical form (`secret/foo/bar`)
    /// or the KV-v2 API form (`secret/data/foo/bar` /
    /// `secret/metadata/foo/bar`). Returns an empty vec when the path
    /// is not a member of any group.
    pub async fn groups_for_secret(&self, path: &str, ns_path: &str) -> Result<Vec<String>, RvError> {
        let Some(canonical) = Self::canonicalize_secret_path(path) else {
            return Ok(Vec::new());
        };
        let key = Self::secret_index_key(&canonical);
        match self.view(ns_path, Keyspace::SecretIndex).get(&key).await? {
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
    pub async fn prune_secret(&self, path: &str, ns_path: &str) -> Result<Vec<String>, RvError> {
        let Some(canonical) = Self::canonicalize_secret_path(path) else {
            return Ok(Vec::new());
        };
        let groups = self.groups_for_secret(&canonical, ns_path).await?;
        let group_view = self.view(ns_path, Keyspace::Group);

        for g_name in &groups {
            if let Some(mut g) = self.get_group(g_name, ns_path).await? {
                g.secrets.retain(|s| s != &canonical);
                g.updated_at = now_iso();
                let value = serde_json::to_vec(&g)?;
                group_view.put(&StorageEntry { key: g.name.clone(), value }).await?;
            }
        }

        let key = Self::secret_index_key(&canonical);
        self.view(ns_path, Keyspace::SecretIndex).delete(&key).await?;
        if !groups.is_empty() {
            self.bump_version(ns_path).await?;
        }
        Ok(groups)
    }

    async fn add_to_secret_index(&self, secret_path: &str, group_name: &str, ns_path: &str) -> Result<(), RvError> {
        let Some(canonical) = Self::canonicalize_secret_path(secret_path) else {
            return Ok(());
        };
        let key = Self::secret_index_key(&canonical);
        let view = self.view(ns_path, Keyspace::SecretIndex);
        let mut names: Vec<String> = match view.get(&key).await? {
            Some(e) => serde_json::from_slice(&e.value).unwrap_or_default(),
            None => Vec::new(),
        };
        if !names.iter().any(|n| n == group_name) {
            names.push(group_name.to_string());
            names.sort();
        }
        let value = serde_json::to_vec(&names)?;
        view.put(&StorageEntry { key, value }).await
    }

    async fn remove_from_secret_index(
        &self,
        secret_path: &str,
        group_name: &str,
        ns_path: &str,
    ) -> Result<(), RvError> {
        let Some(canonical) = Self::canonicalize_secret_path(secret_path) else {
            return Ok(());
        };
        let key = Self::secret_index_key(&canonical);
        let view = self.view(ns_path, Keyspace::SecretIndex);
        let mut names: Vec<String> = match view.get(&key).await? {
            Some(e) => serde_json::from_slice(&e.value).unwrap_or_default(),
            None => return Ok(()),
        };
        names.retain(|n| n != group_name);
        if names.is_empty() {
            view.delete(&key).await
        } else {
            let value = serde_json::to_vec(&names)?;
            view.put(&StorageEntry { key, value }).await
        }
    }

    /// Every group of scope `ns_path` containing file `id`. Empty when none.
    pub async fn groups_for_file(&self, id: &str, ns_path: &str) -> Result<Vec<String>, RvError> {
        let Some(canonical) = Self::sanitize_file_id(id) else {
            return Ok(Vec::new());
        };
        match self.view(ns_path, Keyspace::FileIndex).get(&canonical).await? {
            Some(e) => Ok(serde_json::from_slice(&e.value).unwrap_or_default()),
            None => Ok(Vec::new()),
        }
    }

    /// Prune `id` from every group it is currently a file member of.
    /// Called from `PolicyStore::post_route` on `files/files/<id>`
    /// DELETE so groups stay tidy when a file is destroyed. Mirror of
    /// `prune_secret` / `prune_resource`.
    pub async fn prune_file(&self, id: &str, ns_path: &str) -> Result<Vec<String>, RvError> {
        let Some(canonical) = Self::sanitize_file_id(id) else {
            return Ok(Vec::new());
        };
        let groups = self.groups_for_file(&canonical, ns_path).await?;
        let group_view = self.view(ns_path, Keyspace::Group);

        for g_name in &groups {
            if let Some(mut g) = self.get_group(g_name, ns_path).await? {
                g.files.retain(|f| f != &canonical);
                g.updated_at = now_iso();
                let value = serde_json::to_vec(&g)?;
                group_view.put(&StorageEntry { key: g.name.clone(), value }).await?;
            }
        }

        self.view(ns_path, Keyspace::FileIndex).delete(&canonical).await?;
        if !groups.is_empty() {
            self.bump_version(ns_path).await?;
        }
        Ok(groups)
    }

    async fn add_to_file_index(&self, file_id: &str, group_name: &str, ns_path: &str) -> Result<(), RvError> {
        let Some(canonical) = Self::sanitize_file_id(file_id) else {
            return Ok(());
        };
        let view = self.view(ns_path, Keyspace::FileIndex);
        let mut names: Vec<String> = match view.get(&canonical).await? {
            Some(e) => serde_json::from_slice(&e.value).unwrap_or_default(),
            None => Vec::new(),
        };
        if !names.iter().any(|n| n == group_name) {
            names.push(group_name.to_string());
            names.sort();
        }
        let value = serde_json::to_vec(&names)?;
        view.put(&StorageEntry { key: canonical, value }).await
    }

    async fn remove_from_file_index(&self, file_id: &str, group_name: &str, ns_path: &str) -> Result<(), RvError> {
        let Some(canonical) = Self::sanitize_file_id(file_id) else {
            return Ok(());
        };
        let view = self.view(ns_path, Keyspace::FileIndex);
        let mut names: Vec<String> = match view.get(&canonical).await? {
            Some(e) => serde_json::from_slice(&e.value).unwrap_or_default(),
            None => return Ok(()),
        };
        names.retain(|n| n != group_name);
        if names.is_empty() {
            view.delete(&canonical).await
        } else {
            let value = serde_json::to_vec(&names)?;
            view.put(&StorageEntry { key: canonical, value }).await
        }
    }

    async fn add_to_index(&self, resource: &str, group_name: &str, ns_path: &str) -> Result<(), RvError> {
        let Some(key) = Self::sanitize_member(resource) else {
            return Ok(());
        };
        let view = self.view(ns_path, Keyspace::MemberIndex);
        let mut names: Vec<String> = match view.get(&key).await? {
            Some(e) => serde_json::from_slice(&e.value).unwrap_or_default(),
            None => Vec::new(),
        };
        if !names.iter().any(|n| n == group_name) {
            names.push(group_name.to_string());
            names.sort();
        }
        let value = serde_json::to_vec(&names)?;
        view.put(&StorageEntry { key, value }).await
    }

    async fn remove_from_index(&self, resource: &str, group_name: &str, ns_path: &str) -> Result<(), RvError> {
        let Some(key) = Self::sanitize_member(resource) else {
            return Ok(());
        };
        let view = self.view(ns_path, Keyspace::MemberIndex);
        let mut names: Vec<String> = match view.get(&key).await? {
            Some(e) => serde_json::from_slice(&e.value).unwrap_or_default(),
            None => return Ok(()),
        };
        names.retain(|n| n != group_name);
        if names.is_empty() {
            view.delete(&key).await
        } else {
            let value = serde_json::to_vec(&names)?;
            view.put(&StorageEntry { key, value }).await
        }
    }

    /// Append an audit entry for a change to group `name` of scope `ns_path`.
    /// Keys are `{name}/{20-digit-nanos}`, so `list_history` is chronological.
    pub async fn append_history(
        &self,
        name: &str,
        entry: ResourceGroupHistoryEntry,
        ns_path: &str,
    ) -> Result<(), RvError> {
        let name = Self::sanitize_name(name)?;
        let key = format!("{name}/{}", hist_seq());
        let value = serde_json::to_vec(&entry)?;
        self.view(ns_path, Keyspace::History).put(&StorageEntry { key, value }).await
    }

    /// Full history of group `name` of scope `ns_path`, newest first. History
    /// outlives the group so audit records survive until explicitly purged.
    pub async fn list_history(&self, name: &str, ns_path: &str) -> Result<Vec<ResourceGroupHistoryEntry>, RvError> {
        let name = Self::sanitize_name(name)?;
        let view = self.view(ns_path, Keyspace::History);
        let prefix = format!("{name}/");
        let mut keys = view.list(&prefix).await?;
        keys.sort();
        keys.reverse();

        let mut entries = Vec::with_capacity(keys.len());
        for k in keys {
            let full = format!("{prefix}{k}");
            if let Some(e) = view.get(&full).await? {
                if let Ok(h) = serde_json::from_slice::<ResourceGroupHistoryEntry>(&e.value) {
                    entries.push(h);
                }
            }
        }
        Ok(entries)
    }

    /// Every history entry, paired with the group name, in one bulk
    /// subtree read.
    ///
    /// The per-group [`list_history`](Self::list_history) costs a storage
    /// round-trip per history row, so aggregating across all groups with it
    /// scales with total history. The caller filters by name and timestamp
    /// in memory. Order is unspecified; undecodable rows are skipped.
    pub async fn list_history_all(&self, ns_path: &str) -> Result<Vec<(String, ResourceGroupHistoryEntry)>, RvError> {
        let entries = self.view(ns_path, Keyspace::History).get_entries("").await?;
        Ok(entries
            .into_iter()
            .filter_map(|e| {
                // Keys are `{name}/{20-digit-nanos}`; group names cannot
                // contain `/` (see `sanitize_name`).
                let (name, _seq) = e.key.rsplit_once('/')?;
                let h = serde_json::from_slice::<ResourceGroupHistoryEntry>(&e.value).ok()?;
                Some((name.to_string(), h))
            })
            .collect())
    }

    /// Admin-only: overwrite the owner of a group. Distinct from
    /// `set_group` which preserves the existing owner to prevent
    /// privilege escalation via a regular write. Callers must gate
    /// this behind an admin ACL (the HTTP route at
    /// `sys/asset-group-owner/transfer` does so). Acts on scope `ns_path`
    /// only: an inherited group's owner is changed from its own namespace.
    pub async fn set_owner(&self, name: &str, new_owner: &str, ns_path: &str) -> Result<(), RvError> {
        let name = Self::sanitize_name(name)?;
        let new_owner = new_owner.trim();
        if new_owner.is_empty() {
            return Err(bv_error_string!("new_owner_entity_id is required"));
        }
        let Some(mut g) = self.get_group(&name, ns_path).await? else {
            return Err(bv_error_string!(format!("asset group '{name}' not found")));
        };
        g.owner_entity_id = new_owner.to_string();
        g.updated_at = now_iso();
        let value = serde_json::to_vec(&g)?;
        self.view(ns_path, Keyspace::Group).put(&StorageEntry { key: name, value }).await?;
        self.bump_version(ns_path).await.map(|_| ())
    }

    /// Rebuild scope `ns_path`'s reverse indexes from its primary records,
    /// leaving every other scope alone. Recovery after an interrupted write;
    /// callers must hold admin-level access since this overwrites index state.
    pub async fn reindex(&self, ns_path: &str) -> Result<usize, RvError> {
        for keyspace in [Keyspace::MemberIndex, Keyspace::SecretIndex, Keyspace::FileIndex] {
            let view = self.view(ns_path, keyspace);
            for k in view.get_keys().await? {
                view.delete(&k).await?;
            }
        }

        let groups = self.list_groups(ns_path).await?;
        let mut touched = 0usize;
        for gname in &groups {
            if let Some(g) = self.get_group(gname, ns_path).await? {
                for m in g.members {
                    self.add_to_index(&m, gname, ns_path).await?;
                    touched += 1;
                }
                for s in g.secrets {
                    self.add_to_secret_index(&s, gname, ns_path).await?;
                    touched += 1;
                }
                for f in g.files {
                    self.add_to_file_index(&f, gname, ns_path).await?;
                    touched += 1;
                }
            }
        }
        // The indexes were rewritten wholesale (possibly repairing drift a
        // reader saw), so the scope counts as changed even when nothing did.
        self.bump_version(ns_path).await?;
        Ok(touched)
    }
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

/// Monotonic-ish 20-digit zero-padded nanoseconds since UNIX epoch.
fn hist_seq() -> String {
    let n = Utc::now().timestamp_nanos_opt().unwrap_or_else(|| Utc::now().timestamp_millis() * 1_000_000);
    format!("{:020}", n.max(0) as u128)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::new_unseal_test_bastion_vault;

    const ALL: [Keyspace; 6] = [
        Keyspace::Group,
        Keyspace::MemberIndex,
        Keyspace::SecretIndex,
        Keyspace::FileIndex,
        Keyspace::History,
        Keyspace::Meta,
    ];

    fn entry(name: &str, members: &[&str], secrets: &[&str], files: &[&str]) -> ResourceGroupEntry {
        let owned = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        ResourceGroupEntry {
            name: name.into(),
            members: owned(members),
            secrets: owned(secrets),
            files: owned(files),
            ..Default::default()
        }
    }

    #[test]
    fn version_record_keys_follow_the_scope_layout() {
        assert_eq!(version_key(""), "resource-group/meta/version");
        assert_eq!(version_key("/"), "resource-group/meta/version");
        assert_eq!(
            version_key("dti/esi"),
            format!("resource-group/ns/{}/meta/version", URL_SAFE_NO_PAD.encode("dti/esi"))
        );
    }

    #[test]
    fn version_record_reads_old_and_refuses_unknown_formats() {
        // Read-old: a record without `format` (or an absent record) is a count.
        let v = decode_scope_version(br#"{"counter":3,"stamp":"s"}"#).unwrap();
        assert_eq!((v.format, v.counter, v.stamp.as_str()), (0, 3, "s"));
        assert_eq!(decode_scope_version(br#"{"format":1,"counter":7}"#).unwrap().counter, 7);
        assert!(decode_scope_version(br#"{"format":2,"counter":7}"#).is_err(), "newer format is refused");
        assert!(decode_scope_version(b"not json").is_err());
    }

    #[test]
    fn stamps_are_unique_per_bump() {
        let a = new_stamp("dti", 1);
        let b = new_stamp("dti", 1);
        assert_ne!(a, b, "two bumps with the same counter must still differ");
        assert_eq!(a.len(), 32);
    }

    /// Every mutation kind moves the scope's version, and no read does.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn version_bumps_on_every_mutation_and_never_on_reads() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("rg_version_bumps_on_every_mutation").await;
        let store = ResourceGroupStore::new(&core).await.unwrap();
        let ns = "";
        assert_eq!(store.scope_version(ns).await.unwrap(), ScopeVersion::default(), "absent reads as zero");

        let mut last = snapshot(&store, ns).await;
        // `bumped`: the record moved by one and the chain token with it;
        // otherwise neither moved.
        let mut check = |what: &str, now: (u64, String), bumped: bool| {
            if bumped {
                assert_eq!(now.0, last.0 + 1, "{what} must bump the version");
                assert_ne!(now.1, last.1, "{what} must move the chain token");
            } else {
                assert_eq!(now, last, "{what} must not bump the version");
            }
            last = now;
        };

        store.set_group(entry("g1", &["web1"], &["kv/a"], &["f1"]), ns).await.unwrap();
        check("create", snapshot(&store, ns).await, true);
        store.set_group(entry("g1", &["web1", "web2"], &["kv/a"], &["f1"]), ns).await.unwrap();
        check("update", snapshot(&store, ns).await, true);

        store.get_group("g1", ns).await.unwrap();
        store.resolve_group("g1", ns).await.unwrap();
        store.list_groups(ns).await.unwrap();
        store.list_visible_groups(ns).await.unwrap();
        store.groups_for_resource("web1", ns).await.unwrap();
        store.groups_for_secret("kv/a", ns).await.unwrap();
        store.groups_for_file("f1", ns).await.unwrap();
        store.list_history("g1", ns).await.unwrap();
        store.list_history_all(ns).await.unwrap();
        check("reads", snapshot(&store, ns).await, false);
        store.append_history("g1", ResourceGroupHistoryEntry::default(), ns).await.unwrap();
        check("a history append", snapshot(&store, ns).await, false);

        store.set_owner("g1", "entity-2", ns).await.unwrap();
        check("an owner transfer", snapshot(&store, ns).await, true);
        store.rename_resource("web2", "web3", ns).await.unwrap();
        check("a rename", snapshot(&store, ns).await, true);
        store.prune_resource("web3", ns).await.unwrap();
        check("a resource prune", snapshot(&store, ns).await, true);
        store.prune_secret("kv/data/a", ns).await.unwrap();
        check("a secret prune", snapshot(&store, ns).await, true);
        store.prune_file("f1", ns).await.unwrap();
        check("a file prune", snapshot(&store, ns).await, true);

        assert!(store.prune_resource("nobody", ns).await.unwrap().is_empty());
        assert!(store.prune_secret("kv/none", ns).await.unwrap().is_empty());
        assert!(store.prune_file("f9", ns).await.unwrap().is_empty());
        check("a prune that removed nothing", snapshot(&store, ns).await, false);

        store.reindex(ns).await.unwrap();
        check("a reindex", snapshot(&store, ns).await, true);
        store.delete_group("g1", ns).await.unwrap();
        check("a delete", snapshot(&store, ns).await, true);
        store.delete_group("g1", ns).await.unwrap();
        check("deleting a group that does not exist", snapshot(&store, ns).await, false);
    }

    #[maybe_async::maybe_async]
    async fn snapshot(store: &ResourceGroupStore, ns: &str) -> (u64, String) {
        (store.scope_version(ns).await.unwrap().counter, store.chain_version(ns).await.expect("readable"))
    }

    #[maybe_async::maybe_async]
    async fn token(store: &ResourceGroupStore, ns: &str) -> String {
        store.chain_version(ns).await.expect("readable")
    }

    /// Each scope counts its own writes; a reader's token covers its scope and
    /// its ancestors, never a sibling or a descendant.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn version_is_per_scope_and_the_chain_follows_ancestors() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("rg_version_is_per_scope").await;
        let s = ResourceGroupStore::new(&core).await.unwrap();
        let (child, parent, sibling, root) =
            (token(&s, "a/c").await, token(&s, "a").await, token(&s, "b").await, token(&s, "").await);

        s.set_group(entry("ga", &["web1"], &[], &[]), "a").await.unwrap();
        assert_eq!(s.scope_version("a").await.unwrap().counter, 1);
        assert_eq!(s.scope_version("").await.unwrap().counter, 0, "root is untouched");
        assert_eq!(s.scope_version("b").await.unwrap().counter, 0, "a sibling is untouched");
        assert_eq!(s.scope_version("a/c").await.unwrap().counter, 0, "a child is untouched");
        assert_ne!(token(&s, "a").await, parent, "own scope moved");
        assert_ne!(token(&s, "a/c").await, child, "a child sees its ancestor's change");
        assert_eq!(token(&s, "b").await, sibling, "a sibling does not");
        assert_eq!(token(&s, "").await, root, "nor does the parent");

        let (child, parent, sibling) = (token(&s, "a/c").await, token(&s, "a").await, token(&s, "b").await);
        s.set_group(entry("rootg", &["web1"], &[], &[]), "").await.unwrap();
        assert_ne!(token(&s, "a/c").await, child, "root is every scope's ancestor");
        assert_ne!(token(&s, "a").await, parent);
        assert_ne!(token(&s, "b").await, sibling);

        let parent = token(&s, "a").await;
        s.set_group(entry("gc", &["web1"], &[], &[]), "a/c").await.unwrap();
        assert_eq!(token(&s, "a").await, parent, "a parent does not see its child's groups");
    }

    /// An unreadable record must never read as "unchanged": the chain token is
    /// withheld, and the next mutation replaces the record so the token returns.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn unreadable_version_fails_closed_and_is_repaired_by_the_next_write() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("rg_unreadable_version").await;
        let store = ResourceGroupStore::new(&core).await.unwrap();
        let system_view = core.system_view().expect("unsealed");
        for garbage in [b"not json".to_vec(), br#"{"format":9,"counter":1}"#.to_vec()] {
            system_view.put(&StorageEntry { key: version_key("a"), value: garbage }).await.unwrap();
            assert!(store.scope_version("a").await.is_err());
            assert!(store.chain_version("a").await.is_none(), "own scope unreadable");
            assert!(store.chain_version("a/c").await.is_none(), "an ancestor unreadable");
            assert!(store.chain_version("b").await.is_some(), "a sibling is unaffected");

            store.set_group(entry("ga", &["web1"], &[], &[]), "a").await.unwrap();
            let repaired = store.scope_version("a").await.expect("the write replaced the record");
            assert_eq!(repaired.format, SCOPE_VERSION_FORMAT);
            assert!(repaired.counter > 1, "the counter restarts above any realistic count");
            assert!(store.chain_version("a").await.is_some());
        }
    }

    #[test]
    fn root_scope_keeps_the_legacy_keyspaces() {
        // Pre-namespace records must read back as root with no migration.
        assert_eq!(keyspace_path("", Keyspace::Group), "resource-group/group/");
        assert_eq!(keyspace_path("", Keyspace::MemberIndex), "resource-group/member-index/");
        assert_eq!(keyspace_path("", Keyspace::SecretIndex), "resource-group/secret-index/");
        assert_eq!(keyspace_path("", Keyspace::FileIndex), "resource-group/file-index/");
        assert_eq!(keyspace_path("", Keyspace::History), "resource-group/history/");
        assert_eq!(group_keyspace(""), "resource-group/group/");
        assert_eq!(group_keyspace("/"), "resource-group/group/");
    }

    #[test]
    fn namespace_scopes_are_disjoint_from_root_and_each_other() {
        let child = keyspace_path("dti/esi", Keyspace::MemberIndex);
        assert_eq!(child, format!("resource-group/ns/{}/member-index/", URL_SAFE_NO_PAD.encode("dti/esi")));
        // No keyspace is a prefix of another scope's, so a recursive scan of
        // one (`get_keys`, `get_entries`) never reads into the other.
        for ks in ALL {
            let root = keyspace_path("", ks);
            let (a, b) = (keyspace_path("dti/esi", ks), keyspace_path("dti", ks));
            for scoped in [&a, &b] {
                assert!(!scoped.starts_with(&root) && !root.starts_with(scoped.as_str()), "{root} vs {scoped}");
            }
            assert!(!a.starts_with(&b) && !b.starts_with(&a), "{a} vs {b}");
        }
        // One key segment for the namespace; surrounding slashes are noise.
        assert_eq!(group_keyspace("dti/esi").matches('/').count(), 4);
        assert_eq!(group_keyspace("/dti/esi/"), group_keyspace("dti/esi"));
    }

    #[test]
    fn scope_chain_walks_ancestors_nearest_first_to_root() {
        assert_eq!(scope_chain(""), vec![String::new()]);
        assert_eq!(scope_chain("a"), vec!["a".to_string(), String::new()]);
        assert_eq!(
            scope_chain("dti/importacao/test02"),
            vec!["dti/importacao/test02".to_string(), "dti/importacao".to_string(), "dti".to_string(), String::new()]
        );
        assert_eq!(scope_chain("/a/b/"), vec!["a/b".to_string(), "a".to_string(), String::new()]);
    }

    #[test]
    fn scope_of_normalizes_without_changing_case() {
        assert_eq!(scope_of(None), "");
        assert_eq!(scope_of(Some("")), "");
        assert_eq!(scope_of(Some(" /Dti/Esi/ ")), "Dti/Esi");
    }
}
