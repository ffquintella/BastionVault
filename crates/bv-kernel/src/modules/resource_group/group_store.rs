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
//! canonicalized (trimmed, lowercased) before persisting. A KV-secret
//! member is, from record format 1 (T507), the secret's own name
//! `<mount>/<name>`, stored as given: `secret/data/x` is the secret `data/x`.
//! Format 0 records hold the pre-T507 form, which stripped a `data`/`metadata`
//! second segment whatever the mount; the T507 migration converts them (see
//! `secret_name_migrate`). Both lists are deduped and sorted.
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
        atomic::{AtomicBool, AtomicU64, Ordering},
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
    /// KV-secret members under their pre-T507 key (format 0 lists).
    SecretIndex,
    /// KV-secret members under the secret's own name (format 1, T507).
    SecretNameIndex,
    /// Format 1 records' kept pre-T507 members, under their pre-T507 key.
    SecretKeptIndex,
    FileIndex,
    History,
    /// Scope bookkeeping: the change-version record, and at root the T507 marker.
    Meta,
}

impl Keyspace {
    fn leaf(self) -> &'static str {
        match self {
            Keyspace::Group => "group/",
            Keyspace::MemberIndex => "member-index/",
            Keyspace::SecretIndex => "secret-index/",
            Keyspace::SecretNameIndex => "secret-name-index/",
            Keyspace::SecretKeptIndex => "secret-kept-index/",
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
/// Leaf key, in the root scope's `meta/` keyspace, of the T507 marker: set
/// once every scope's records are format 1, then lookups use own names.
const SECRET_NAMES_MARKER: &str = "secret-names";
/// Format of [`ResourceGroupEntry::secrets`] this build writes and the newest
/// it reads: 1 is the secret's own name (T507), 0 the pre-T507 key.
pub const SECRETS_FORMAT: u32 = 1;

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
    /// KV-secret members, deduped and sorted. Format 1: each secret's own
    /// `<mount>/<name>` as given (a path no KV mount serves, as given).
    /// Format 0: the pre-T507 key, `data`/`metadata` stripped at index 1.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// How `secrets` names a secret ([`SECRETS_FORMAT`]); absent is 0.
    #[serde(default)]
    pub secrets_format: u32,
    /// Format 1: pre-T507 members the own-name form cannot express exactly
    /// (route-specific, or reaching no mount), still matched by the pre-T507
    /// rule. Only ever shrinks: an operator regroups them by own name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets_legacy_kept: Vec<String>,
    /// On a record the T507 migration converted, the format 0 list it
    /// replaced: kept for rollback, never read for access once switched.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub legacy_secrets: Vec<String>,
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

impl ResourceGroupEntry {
    /// The members as the pre-T507 code reads them: a format 0 `secrets`, or
    /// the list a format 1 record was converted from.
    pub fn legacy_list(&self) -> &[String] {
        match self.secrets_format {
            0 => &self.secrets,
            _ => &self.legacy_secrets,
        }
    }

    /// The members keyed on a secret's own name: a format 1 `secrets`, none
    /// for format 0 (its keys are not own names until converted).
    pub fn own_list(&self) -> &[String] {
        match self.secrets_format {
            0 => &[],
            _ => &self.secrets,
        }
    }

    /// A format 1 record's members still matched by the pre-T507 rule.
    pub fn kept_list(&self) -> &[String] {
        match self.secrets_format {
            0 => &[],
            _ => &self.secrets_legacy_kept,
        }
    }
}

/// Decode a stored group record. A `secrets_format` newer than this build
/// reads is an error, never read as another format.
fn decode_group(bytes: &[u8]) -> Result<ResourceGroupEntry, RvError> {
    let g: ResourceGroupEntry = serde_json::from_slice(bytes)?;
    if g.secrets_format > SECRETS_FORMAT {
        return Err(bv_error_string!(format!(
            "asset group '{}' has secrets format {}, newer than this build reads ({SECRETS_FORMAT})",
            g.name, g.secrets_format
        )));
    }
    Ok(g)
}

fn as_set(list: &[String]) -> BTreeSet<&str> {
    list.iter().map(String::as_str).collect()
}

/// The refusal of a write that changes a group's KV-secret members in a
/// format other than the stored one (the T507 migration converted it under
/// the write, or the switch happened): nothing is written; read it again.
fn converted_during_write(name: &str) -> RvError {
    RvError::ErrResponseStatus(
        409,
        format!(
            "asset group '{name}' was converted to the secret-name member format (T507) while this write was \
             prepared; nothing was written, read the group again and repeat the change"
        ),
    )
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
    /// Cached once the T507 marker is seen: see [`Self::secret_names`].
    secret_names: AtomicBool,
}

#[maybe_async::maybe_async]
impl ResourceGroupStore {
    pub async fn new(core: &dyn VaultCtx) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.system_view() else {
            return Err(RvError::ErrBarrierSealed);
        };
        Ok(Arc::new(Self { system_view, secret_names: AtomicBool::new(false) }))
    }

    /// Whether the T507 migration has completed: KV-secret members and lookups
    /// use a secret's own name. The replicated marker is cached once seen;
    /// until then each call reads it. Unreadable or garbled is an error.
    pub async fn secret_names(&self) -> Result<bool, RvError> {
        if self.secret_names.load(Ordering::Acquire) {
            return Ok(true);
        }
        let Some(entry) = self.view("", Keyspace::Meta).get(SECRET_NAMES_MARKER).await? else {
            return Ok(false);
        };
        let done = serde_json::from_slice::<u32>(&entry.value)? >= SECRETS_FORMAT;
        if done {
            self.secret_names.store(true, Ordering::Release);
        }
        Ok(done)
    }

    /// Record that every record is format 1 and switch lookups to own names.
    pub(crate) async fn mark_secret_names(&self) -> Result<(), RvError> {
        let value = serde_json::to_vec(&SECRETS_FORMAT)?;
        self.view("", Keyspace::Meta).put(&StorageEntry { key: SECRET_NAMES_MARKER.to_string(), value }).await?;
        self.secret_names.store(true, Ordering::Release);
        Ok(())
    }

    /// Test support: back to the pre-T507 lookups, marker gone.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn unmark_secret_names_for_test(&self) -> Result<(), RvError> {
        self.view("", Keyspace::Meta).delete(SECRET_NAMES_MARKER).await?;
        self.secret_names.store(false, Ordering::Release);
        Ok(())
    }

    /// Test support: a garbled marker, which every reader must refuse.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn garble_secret_names_marker_for_test(&self) -> Result<(), RvError> {
        self.secret_names.store(false, Ordering::Release);
        let garbage = StorageEntry { key: SECRET_NAMES_MARKER.to_string(), value: b"garbled".to_vec() };
        self.view("", Keyspace::Meta).put(&garbage).await
    }

    /// Write group record `g` of scope `ns_path`. Once switched, a format 0
    /// record with members is refused (nothing may bring the old keys back);
    /// one without members is written as format 1.
    async fn put_record(&self, mut g: ResourceGroupEntry, ns_path: &str) -> Result<ResourceGroupEntry, RvError> {
        if g.secrets_format < SECRETS_FORMAT && self.secret_names().await? {
            if !g.secrets.is_empty() {
                return Err(converted_during_write(&g.name));
            }
            g.secrets_format = SECRETS_FORMAT;
        }
        let value = serde_json::to_vec(&g)?;
        self.view(ns_path, Keyspace::Group).put(&StorageEntry { key: g.name.clone(), value }).await?;
        Ok(g)
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

    /// A KV-secret member as format 1 stores it (T507): whitespace and
    /// surrounding `/` trimmed and nothing stripped, so a member passed back in
    /// is returned unchanged. `None` when empty or holding a `..` segment.
    pub fn checked_secret_name(raw: &str) -> Option<String> {
        let trimmed = raw.trim().trim_matches('/');
        (!trimmed.is_empty() && !trimmed.split('/').any(|s| s == "..")).then(|| trimmed.to_string())
    }

    /// The key every release before T507 gave a KV-secret member and a
    /// mount-relative request path: surrounding `/` trimmed, a `data` or
    /// `metadata` second segment stripped whatever the mount (so a kv v1
    /// `kv/data/x` was `kv/x`). Kept for format 0 records, lookups while the
    /// T507 switch is pending, and the migration. `None` if empty or `..`.
    pub(crate) fn legacy_secret_key(raw: &str) -> Option<String> {
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

    /// Read-modify-write the primary record *and* keep the reverse indexes in
    /// sync with the diff between old and new membership. KV-secret members
    /// are stored as given, never re-keyed, in the record's format (T507).
    /// Reverse-index failures surface as errors: a failed write is a failed set.
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

        // KV-secret members: trimmed, deduped, sorted, nothing stripped.
        let checked: BTreeSet<String> = entry.secrets.drain(..).filter_map(|s| Self::checked_secret_name(&s)).collect();
        entry.secrets = checked.into_iter().collect();

        // Canonicalize file ids: lowercase, trim, drop empties / `/`,
        // dedup, sort.
        let mut canonical_files: BTreeSet<String> = BTreeSet::new();
        for f in entry.files.drain(..) {
            if let Some(c) = Self::sanitize_file_id(&f) {
                canonical_files.insert(c);
            }
        }
        entry.files = canonical_files.iter().cloned().collect();

        let old = self.get_group(&name, ns_path).await?.unwrap_or_default();
        // Owner is immutable via `set_group` — preserved on update,
        // captured on first write (caller supplies the initial value).
        // Use `set_owner` for the admin-only transfer flow.
        if !old.owner_entity_id.is_empty() {
            entry.owner_entity_id = old.owner_entity_id.clone();
        }
        Self::keep_secrets_format(&mut entry, &old)?;
        let old_members: BTreeSet<String> = old.members.iter().cloned().collect();
        let old_files: BTreeSet<String> = old.files.iter().cloned().collect();
        let new_members: BTreeSet<String> = entry.members.iter().cloned().collect();
        let new_files: BTreeSet<String> = entry.files.iter().cloned().collect();

        let entry = self.put_record(entry, ns_path).await?;

        for m in new_members.difference(&old_members) {
            self.add_to_index(m, &name, ns_path).await?;
        }
        for m in old_members.difference(&new_members) {
            self.remove_from_index(m, &name, ns_path).await?;
        }
        // Each list in its own index: the pre-T507 keys while they decide,
        // the own names once switched (T507).
        for (index, old_list, new_list) in [
            (Keyspace::SecretIndex, old.legacy_list(), entry.legacy_list()),
            (Keyspace::SecretNameIndex, old.own_list(), entry.own_list()),
            (Keyspace::SecretKeptIndex, old.kept_list(), entry.kept_list()),
        ] {
            let (old_set, new_set) = (as_set(old_list), as_set(new_list));
            for s in new_set.difference(&old_set) {
                self.add_to_secret_index(index, s, &name, ns_path).await?;
            }
            for s in old_set.difference(&new_set) {
                self.remove_from_secret_index(index, s, &name, ns_path).await?;
            }
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

    /// Give `entry` the stored record's KV-secret format. A write prepared on
    /// a format 0 read that the T507 migration converted meanwhile carries the
    /// converted lists when it left the members unchanged, else it is refused.
    /// The rollback copy never changes; kept members can only be removed.
    fn keep_secrets_format(entry: &mut ResourceGroupEntry, old: &ResourceGroupEntry) -> Result<(), RvError> {
        if old.secrets_format > entry.secrets_format {
            if as_set(&entry.secrets) != as_set(old.legacy_list()) {
                return Err(converted_during_write(&entry.name));
            }
            entry.secrets = old.secrets.clone();
            entry.secrets_legacy_kept = old.secrets_legacy_kept.clone();
            entry.secrets_format = old.secrets_format;
        } else if old.secrets_format < entry.secrets_format && !old.secrets.is_empty() {
            // Converting members is `convert_record`'s, which keeps the old list.
            return Err(converted_during_write(&entry.name));
        }
        let kept: BTreeSet<String> =
            entry.secrets_legacy_kept.drain(..).filter_map(|s| Self::checked_secret_name(&s)).collect();
        if !kept.iter().all(|k| old.kept_list().contains(k)) {
            return Err(RvError::ErrResponseStatus(
                400,
                format!("asset group '{}': kept pre-T507 members can only be removed, not added", entry.name),
            ));
        }
        entry.secrets_legacy_kept = kept.into_iter().collect();
        if old.secrets_format > 0 {
            entry.legacy_secrets = old.legacy_secrets.clone();
        } else if entry.secrets_format == 0 {
            entry.legacy_secrets.clear();
        }
        Ok(())
    }

    /// The group `name` in exactly scope `ns_path`, no inheritance. A read
    /// that should see ancestors' groups uses [`Self::resolve_group`].
    pub async fn get_group(&self, name: &str, ns_path: &str) -> Result<Option<ResourceGroupEntry>, RvError> {
        let name = Self::sanitize_name(name)?;
        match self.view(ns_path, Keyspace::Group).get(&name).await? {
            Some(e) => decode_group(&e.value).map(Some),
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
        let old = previous.unwrap_or_default();

        self.view(ns_path, Keyspace::Group).delete(&name).await?;

        for m in &old.members {
            self.remove_from_index(m, &name, ns_path).await?;
        }
        for s in old.legacy_list() {
            self.remove_from_secret_index(Keyspace::SecretIndex, s, &name, ns_path).await?;
        }
        for s in old.own_list() {
            self.remove_from_secret_index(Keyspace::SecretNameIndex, s, &name, ns_path).await?;
        }
        for s in old.kept_list() {
            self.remove_from_secret_index(Keyspace::SecretKeptIndex, s, &name, ns_path).await?;
        }
        for f in &old.files {
            self.remove_from_file_index(f, &name, ns_path).await?;
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

        for g_name in &groups {
            if let Some(mut g) = self.get_group(g_name, ns_path).await? {
                g.members.retain(|m| m.trim().to_lowercase() != target);
                g.updated_at = now_iso();
                self.put_record(g, ns_path).await?;
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

    /// The groups of scope `ns_path` listing the secret `name`: a format 1
    /// member (its own `<mount>/<name>`, or a path no KV mount serves) looked
    /// up as given in the name index (T507). Empty when none.
    pub async fn groups_for_secret_name(&self, name: &str, ns_path: &str) -> Result<Vec<String>, RvError> {
        let Some(name) = Self::checked_secret_name(name) else {
            return Ok(Vec::new());
        };
        self.index_lookup(Keyspace::SecretNameIndex, &name, ns_path).await
    }

    /// The groups a pre-T507 lookup of the mount-relative `path` finds: its
    /// [`Self::legacy_secret_key`] in the legacy index. What decides while
    /// the T507 switch is pending.
    pub async fn groups_for_legacy_secret(&self, path: &str, ns_path: &str) -> Result<Vec<String>, RvError> {
        let Some(key) = Self::legacy_secret_key(path) else {
            return Ok(Vec::new());
        };
        self.index_lookup(Keyspace::SecretIndex, &key, ns_path).await
    }

    async fn index_lookup(&self, index: Keyspace, member: &str, ns_path: &str) -> Result<Vec<String>, RvError> {
        match self.view(ns_path, index).get(&Self::secret_index_key(member)).await? {
            Some(e) => Ok(serde_json::from_slice(&e.value).unwrap_or_default()),
            None => Ok(Vec::new()),
        }
    }

    /// Remove the secret `name` (a format 1 member, as given) from every group
    /// of scope `ns_path` listing it, and drop its name-index entry: the
    /// KV-delete lifecycle hook once switched (T507). Rollback copies stay.
    pub async fn prune_secret_name(&self, name: &str, ns_path: &str) -> Result<Vec<String>, RvError> {
        let Some(name) = Self::checked_secret_name(name) else {
            return Ok(Vec::new());
        };
        let groups = self.index_lookup(Keyspace::SecretNameIndex, &name, ns_path).await?;
        for g_name in &groups {
            if let Some(mut g) = self.get_group(g_name, ns_path).await? {
                if g.secrets_format == 0 {
                    continue;
                }
                g.secrets.retain(|s| s != &name);
                g.updated_at = now_iso();
                self.put_record(g, ns_path).await?;
            }
        }
        self.view(ns_path, Keyspace::SecretNameIndex).delete(&Self::secret_index_key(&name)).await?;
        if !groups.is_empty() {
            self.bump_version(ns_path).await?;
        }
        Ok(groups)
    }

    /// The groups whose kept pre-T507 members (format 1) a pre-T507 lookup
    /// of the mount-relative `path` finds: matched by the old rule once
    /// switched, beside [`Self::groups_for_secret_name`].
    pub async fn groups_for_kept_secret(&self, path: &str, ns_path: &str) -> Result<Vec<String>, RvError> {
        let Some(key) = Self::legacy_secret_key(path) else {
            return Ok(Vec::new());
        };
        self.index_lookup(Keyspace::SecretKeptIndex, &key, ns_path).await
    }

    /// The pre-T507 KV-delete prune for kept members: remove the pre-T507 key
    /// of the deleted mount-relative `path` from every kept list, as the old
    /// rule removed it. Own-name members are `prune_secret_name`'s.
    pub async fn prune_kept_secret(&self, path: &str, ns_path: &str) -> Result<Vec<String>, RvError> {
        let Some(key) = Self::legacy_secret_key(path) else {
            return Ok(Vec::new());
        };
        let groups = self.index_lookup(Keyspace::SecretKeptIndex, &key, ns_path).await?;
        for g_name in &groups {
            if let Some(mut g) = self.get_group(g_name, ns_path).await? {
                if g.secrets_format == 0 {
                    continue;
                }
                g.secrets_legacy_kept.retain(|s| s != &key);
                g.updated_at = now_iso();
                self.put_record(g, ns_path).await?;
            }
        }
        self.view(ns_path, Keyspace::SecretKeptIndex).delete(&Self::secret_index_key(&key)).await?;
        if !groups.is_empty() {
            self.bump_version(ns_path).await?;
        }
        Ok(groups)
    }

    /// Convert group `name`'s format 0 members `from` to own names `own` and
    /// kept members `kept` (the T507 migration), keeping `from` as the
    /// rollback copy. Index entries are added before the record is written,
    /// so no format 1 record ever lacks them. Re-reads: `false`, writing
    /// nothing, when the record is gone, converted, or no longer lists `from`.
    pub(crate) async fn convert_record(
        &self,
        name: &str,
        ns_path: &str,
        from: &[String],
        own: &[String],
        kept: &[String],
    ) -> Result<bool, RvError> {
        let Some(mut g) = self.get_group(name, ns_path).await? else {
            return Ok(false);
        };
        if g.secrets_format >= SECRETS_FORMAT || as_set(&g.secrets) != as_set(from) {
            return Ok(false);
        }
        let checked = |v: &[String]| -> Vec<String> {
            v.iter().filter_map(|s| Self::checked_secret_name(s)).collect::<BTreeSet<_>>().into_iter().collect()
        };
        let (own, kept) = (checked(own), checked(kept));
        for (index, list) in [(Keyspace::SecretNameIndex, &own), (Keyspace::SecretKeptIndex, &kept)] {
            for s in list {
                self.add_to_secret_index(index, s, &g.name, ns_path).await?;
            }
        }
        g.legacy_secrets = std::mem::take(&mut g.secrets);
        g.secrets = own;
        g.secrets_legacy_kept = kept;
        g.secrets_format = SECRETS_FORMAT;
        let value = serde_json::to_vec(&g)?;
        self.view(ns_path, Keyspace::Group).put(&StorageEntry { key: g.name.clone(), value }).await?;
        self.bump_version(ns_path).await?;
        Ok(true)
    }

    /// Before the T507 marker is set: make sure every format 1 record of scope
    /// `ns_path` is filed in the name and kept indexes, adding what a racing
    /// writer lost, never deleting (no lookup reads them yet, and nothing may
    /// leave them while pending). Returns the records still format 0.
    pub(crate) async fn repair_converted(&self, ns_path: &str) -> Result<Vec<String>, RvError> {
        let mut unconverted = Vec::new();
        for gname in self.list_groups(ns_path).await? {
            let Some(g) = self.get_group(&gname, ns_path).await? else {
                continue;
            };
            if g.secrets_format == 0 {
                if !g.secrets.is_empty() {
                    unconverted.push(gname);
                }
                continue;
            }
            for (index, list) in [(Keyspace::SecretNameIndex, g.own_list()), (Keyspace::SecretKeptIndex, g.kept_list())]
            {
                for s in list {
                    if !self.index_lookup(index, s, ns_path).await?.iter().any(|n| n == &gname) {
                        self.add_to_secret_index(index, s, &gname, ns_path).await?;
                    }
                }
            }
        }
        Ok(unconverted)
    }

    /// File `group_name` in `index` under the stored member `member`, as given.
    async fn add_to_secret_index(
        &self,
        index: Keyspace,
        member: &str,
        group_name: &str,
        ns_path: &str,
    ) -> Result<(), RvError> {
        if member.is_empty() {
            return Ok(());
        }
        let key = Self::secret_index_key(member);
        let view = self.view(ns_path, index);
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

    /// Drop `group_name` from `index` under the stored member `member`, as given.
    async fn remove_from_secret_index(
        &self,
        index: Keyspace,
        member: &str,
        group_name: &str,
        ns_path: &str,
    ) -> Result<(), RvError> {
        if member.is_empty() {
            return Ok(());
        }
        let key = Self::secret_index_key(member);
        let view = self.view(ns_path, index);
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
    /// `prune_secret_name` / `prune_resource`.
    pub async fn prune_file(&self, id: &str, ns_path: &str) -> Result<Vec<String>, RvError> {
        let Some(canonical) = Self::sanitize_file_id(id) else {
            return Ok(Vec::new());
        };
        let groups = self.groups_for_file(&canonical, ns_path).await?;

        for g_name in &groups {
            if let Some(mut g) = self.get_group(g_name, ns_path).await? {
                g.files.retain(|f| f != &canonical);
                g.updated_at = now_iso();
                self.put_record(g, ns_path).await?;
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
        self.put_record(g, ns_path).await?;
        self.bump_version(ns_path).await.map(|_| ())
    }

    /// Rebuild scope `ns_path`'s reverse indexes from its primary records,
    /// leaving every other scope alone. An entry is rewritten only if it
    /// differs and stale ones are deleted last, so a live index never reads
    /// empty mid-rebuild. Recovery after an interrupted write; admin-level.
    pub async fn reindex(&self, ns_path: &str) -> Result<usize, RvError> {
        let mut want: Vec<(Keyspace, BTreeMap<String, BTreeSet<String>>)> = [
            Keyspace::MemberIndex,
            Keyspace::SecretIndex,
            Keyspace::SecretNameIndex,
            Keyspace::SecretKeptIndex,
            Keyspace::FileIndex,
        ]
        .into_iter()
        .map(|k| (k, BTreeMap::new()))
        .collect();
        let mut touched = 0usize;
        for gname in self.list_groups(ns_path).await? {
            let Some(g) = self.get_group(&gname, ns_path).await? else {
                continue;
            };
            let keyed = |list: &[String], key: fn(&str) -> Option<String>| list.iter().filter_map(|m| key(m)).collect();
            let lists: [Vec<String>; 5] = [
                keyed(&g.members, Self::sanitize_member),
                keyed(g.legacy_list(), Self::secret_entry_key),
                keyed(g.own_list(), Self::secret_entry_key),
                keyed(g.kept_list(), Self::secret_entry_key),
                keyed(&g.files, Self::sanitize_file_id),
            ];
            touched += g.members.len() + g.secrets.len() + g.files.len();
            for ((_, index), keys) in want.iter_mut().zip(lists) {
                for key in keys {
                    index.entry(key).or_default().insert(gname.clone());
                }
            }
        }
        for (keyspace, desired) in want {
            self.replace_index(ns_path, keyspace, desired).await?;
        }
        // The indexes were rewritten wholesale (possibly repairing drift a
        // reader saw), so the scope counts as changed even when nothing did.
        self.bump_version(ns_path).await?;
        Ok(touched)
    }

    /// Rebuild only scope `ns_path`'s legacy secret index from the records'
    /// pre-T507 lists, without a gap (the T499 datafix, while T507 is pending
    /// and that index decides; nothing may change secret membership then).
    pub(crate) async fn repair_legacy_index(&self, ns_path: &str) -> Result<(), RvError> {
        let mut desired: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for gname in self.list_groups(ns_path).await? {
            if let Some(g) = self.get_group(&gname, ns_path).await? {
                for key in g.legacy_list().iter().filter_map(|m| Self::secret_entry_key(m)) {
                    desired.entry(key).or_default().insert(gname.clone());
                }
            }
        }
        self.replace_index(ns_path, Keyspace::SecretIndex, desired).await?;
        self.bump_version(ns_path).await.map(|_| ())
    }

    /// The index key of KV-secret member `member`, as `add_to_secret_index` files it.
    fn secret_entry_key(member: &str) -> Option<String> {
        (!member.is_empty()).then(|| Self::secret_index_key(member))
    }

    /// Make `keyspace` of scope `ns_path` hold exactly `desired` (index key ->
    /// group names): differing entries are written first, stale ones deleted
    /// after, so no key a reader needs is ever missing on the way.
    async fn replace_index(
        &self,
        ns_path: &str,
        keyspace: Keyspace,
        desired: BTreeMap<String, BTreeSet<String>>,
    ) -> Result<(), RvError> {
        let view = self.view(ns_path, keyspace);
        for (key, names) in &desired {
            let names: Vec<&String> = names.iter().collect();
            let current = view.get(key).await?.and_then(|e| serde_json::from_slice::<Vec<String>>(&e.value).ok());
            if current.as_ref().map(|c| c.iter().collect::<Vec<_>>()) != Some(names.clone()) {
                view.put(&StorageEntry { key: key.clone(), value: serde_json::to_vec(&names)? }).await?;
            }
        }
        for key in view.get_keys().await? {
            if !desired.contains_key(&key) {
                view.delete(&key).await?;
            }
        }
        Ok(())
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

    const ALL: [Keyspace; 7] = [
        Keyspace::Group,
        Keyspace::MemberIndex,
        Keyspace::SecretIndex,
        Keyspace::SecretNameIndex,
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
            secrets_format: SECRETS_FORMAT,
            files: owned(files),
            ..Default::default()
        }
    }

    /// A record as a release before T507 stored it: format 0, legacy keys.
    fn legacy(name: &str, secrets: &[&str]) -> ResourceGroupEntry {
        ResourceGroupEntry { secrets_format: 0, ..entry(name, &[], secrets, &[]) }
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
        store.groups_for_secret_name("kv/a", ns).await.unwrap();
        store.groups_for_legacy_secret("kv/a", ns).await.unwrap();
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
        store.prune_secret_name("kv/a", ns).await.unwrap();
        check("a secret prune", snapshot(&store, ns).await, true);
        store.prune_file("f1", ns).await.unwrap();
        check("a file prune", snapshot(&store, ns).await, true);

        assert!(store.prune_resource("nobody", ns).await.unwrap().is_empty());
        assert!(store.prune_secret_name("kv/none", ns).await.unwrap().is_empty());
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
        assert_eq!(keyspace_path("", Keyspace::SecretNameIndex), "resource-group/secret-name-index/");
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

    /// From format 1 a member is stored as given (T507): nothing is stripped,
    /// an edit that leaves the list alone keeps it, and lookups take it as is.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn format_1_members_are_stored_as_given() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("rg_t507_as_given").await;
        let store = ResourceGroupStore::new(&core).await.unwrap();
        assert!(store.secret_names().await.unwrap(), "a fresh vault switches at its first unseal");
        let g = entry("g", &[], &[" /kv/data/x/ ", "secret/data/data/x", "kv/../x", ""], &[]);
        let stored = store.set_group(g, "").await.unwrap();
        assert_eq!(stored.secrets, ["kv/data/x", "secret/data/data/x"]);
        let edit = ResourceGroupEntry { description: "edited".into(), ..stored };
        assert_eq!(store.set_group(edit, "").await.unwrap().secrets, ["kv/data/x", "secret/data/data/x"]);
        assert_eq!(store.groups_for_secret_name("kv/data/x", "").await.unwrap(), ["g"]);
        assert!(store.groups_for_secret_name("kv/x", "").await.unwrap().is_empty());
        assert!(store.groups_for_secret_name("secret/data/x", "").await.unwrap().is_empty());
        assert_eq!(store.prune_secret_name("kv/data/x", "").await.unwrap(), ["g"]);
        assert_eq!(store.get_group("g", "").await.unwrap().unwrap().secrets, ["secret/data/data/x"]);
    }

    /// A format 0 record keeps deciding through the legacy index until it is
    /// converted; conversion keeps the old list, files the new one, and runs
    /// once. A write prepared on the old record carries the conversion or,
    /// if it changed the members, is refused.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn a_format_0_record_converts_once_and_keeps_its_old_list() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("rg_t507_convert").await;
        let store = ResourceGroupStore::new(&core).await.unwrap();
        store.unmark_secret_names_for_test().await.unwrap();
        store.set_group(legacy("g", &["kv/x"]), "").await.unwrap();
        assert_eq!(store.groups_for_legacy_secret("kv/data/x", "").await.unwrap(), ["g"], "pre-T507 lookup");
        assert!(store.groups_for_secret_name("kv/x", "").await.unwrap().is_empty(), "not an own name yet");

        let (from, to) = (vec!["kv/x".to_string()], vec!["kv/data/x".to_string(), "kv/x".to_string()]);
        assert!(!store.convert_record("g", "", &["kv/y".to_string()], &to, &[]).await.unwrap(), "another list");
        assert!(store.convert_record("g", "", &from, &to, &[]).await.unwrap());
        assert!(!store.convert_record("g", "", &from, &to, &[]).await.unwrap(), "once");
        let g = store.get_group("g", "").await.unwrap().unwrap();
        assert_eq!((g.secrets_format, g.secrets.clone(), g.legacy_secrets.clone()), (1, to.clone(), from.clone()));
        assert_eq!(store.groups_for_secret_name("kv/data/x", "").await.unwrap(), ["g"]);
        assert_eq!(store.groups_for_legacy_secret("kv/x", "").await.unwrap(), ["g"], "the old index stays");

        let stale = ResourceGroupEntry { description: "edited".into(), ..legacy("g", &["kv/x"]) };
        let rebased = store.set_group(stale, "").await.unwrap();
        assert_eq!((rebased.secrets_format, rebased.secrets, rebased.legacy_secrets), (1, to, from));
        let changed = store.set_group(legacy("g", &["kv/x", "kv/y"]), "").await;
        assert!(matches!(changed, Err(RvError::ErrResponseStatus(409, _))), "{changed:?}");
    }

    /// Once switched nothing writes the old keys back: a format 0 record with
    /// members is refused, one without is stored as format 1.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn once_switched_a_format_0_record_with_members_is_refused() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("rg_t507_switched_refuses").await;
        let store = ResourceGroupStore::new(&core).await.unwrap();
        assert!(store.secret_names().await.unwrap());
        let r = store.set_group(legacy("g", &["kv/x"]), "").await;
        assert!(matches!(r, Err(RvError::ErrResponseStatus(409, _))), "{r:?}");
        assert!(store.get_group("g", "").await.unwrap().is_none(), "nothing written");
        let empty = store.set_group(legacy("h", &[]), "").await.unwrap();
        assert_eq!(empty.secrets_format, SECRETS_FORMAT);
    }

    #[test]
    fn a_newer_secrets_format_is_refused_and_an_absent_one_is_0() {
        let old = decode_group(br#"{"name":"g","secrets":["kv/x"]}"#).unwrap();
        assert_eq!((old.secrets_format, old.legacy_list(), old.own_list()), (0, &["kv/x".to_string()][..], &[][..]));
        assert!(decode_group(br#"{"name":"g","secrets_format":2}"#).is_err());
    }

    #[test]
    fn the_legacy_key_strips_the_second_segment_and_a_name_is_kept() {
        assert_eq!(ResourceGroupStore::legacy_secret_key("/kv/data/x/").as_deref(), Some("kv/x"));
        assert_eq!(ResourceGroupStore::legacy_secret_key("secret/data/data/x").as_deref(), Some("secret/data/x"));
        assert_eq!(ResourceGroupStore::legacy_secret_key("a/b/data/x").as_deref(), Some("a/b/data/x"));
        assert_eq!(ResourceGroupStore::checked_secret_name("/kv/data/x/").as_deref(), Some("kv/data/x"));
        assert_eq!(ResourceGroupStore::checked_secret_name("kv/../x"), None);
    }

    /// A kept pre-T507 member is filed in the kept index under its pre-T507
    /// key, matched by the old rule, and can only be removed by a write.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn a_kept_member_matches_by_the_old_rule_and_can_only_be_removed() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("rg_t507_kept").await;
        let store = ResourceGroupStore::new(&core).await.unwrap();
        store.unmark_secret_names_for_test().await.unwrap();
        store.set_group(legacy("g", &["team/kv/data/z", "kv/x"]), "").await.unwrap();
        let from = vec!["kv/x".to_string(), "team/kv/data/z".to_string()];
        let (own, kept) = (vec!["kv/x".to_string()], vec!["team/kv/data/z".to_string()]);
        assert!(store.convert_record("g", "", &from, &own, &kept).await.unwrap());
        store.mark_secret_names().await.unwrap();
        assert_eq!(store.groups_for_kept_secret("team/kv/data/z", "").await.unwrap(), ["g"], "its route");
        assert!(store.groups_for_kept_secret("team/kv/metadata/z", "").await.unwrap().is_empty(), "not another");
        assert!(store.groups_for_secret_name("team/kv/data/z", "").await.unwrap().is_empty(), "not an own name");

        let g = store.get_group("g", "").await.unwrap().unwrap();
        let added = ResourceGroupEntry { secrets_legacy_kept: vec!["kv/new".into()], ..g.clone() };
        let r = store.set_group(added, "").await;
        assert!(matches!(r, Err(RvError::ErrResponseStatus(400, _))), "{r:?}");
        let regrouped = ResourceGroupEntry {
            secrets: vec!["kv/x".into(), "team/kv/z".into()],
            secrets_legacy_kept: Vec::new(),
            ..g
        };
        store.set_group(regrouped, "").await.unwrap();
        assert!(store.groups_for_kept_secret("team/kv/data/z", "").await.unwrap().is_empty(), "removed");
        assert_eq!(store.groups_for_secret_name("team/kv/z", "").await.unwrap(), ["g"], "by own name now");
    }

    /// The migration's repair adds what a converted record lacks and reports
    /// records still format 0; it never deletes an entry.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn repair_adds_missing_entries_and_reports_unconverted_records() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("rg_t507_repair").await;
        let store = ResourceGroupStore::new(&core).await.unwrap();
        store.unmark_secret_names_for_test().await.unwrap();
        store.set_group(legacy("old", &["kv/a"]), "").await.unwrap();
        store.set_group(legacy("conv", &["kv/b"]), "").await.unwrap();
        let b = vec!["kv/b".to_string()];
        assert!(store.convert_record("conv", "", &b, &b, &[]).await.unwrap());
        // A racing writer lost the entry; a stray one is left alone.
        let name_index = store.view("", Keyspace::SecretNameIndex);
        name_index.delete(&ResourceGroupStore::secret_index_key("kv/b")).await.unwrap();
        store.add_to_secret_index(Keyspace::SecretNameIndex, "kv/stray", "conv", "").await.unwrap();
        assert_eq!(store.repair_converted("").await.unwrap(), ["old"]);
        assert_eq!(store.groups_for_secret_name("kv/b", "").await.unwrap(), ["conv"], "added back");
        assert_eq!(store.groups_for_secret_name("kv/stray", "").await.unwrap(), ["conv"], "never deleted");
    }

    /// `reindex` never empties a live index: an entry that is right is not
    /// rewritten, a wrong one is rewritten in place, a stale one deleted last.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn reindex_rewrites_in_place_and_deletes_stale_entries_last() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("rg_t507_reindex").await;
        let store = ResourceGroupStore::new(&core).await.unwrap();
        store.set_group(entry("g", &["web1"], &["kv/x"], &[]), "").await.unwrap();
        store.set_group(entry("h", &[], &["kv/x"], &[]), "").await.unwrap();
        let view = store.view("", Keyspace::SecretNameIndex);
        let key = ResourceGroupStore::secret_index_key("kv/x");
        // Drift a reader would see: `h` missing on kv/x, a stale kv/gone.
        view.put(&StorageEntry { key: key.clone(), value: serde_json::to_vec(&["g"]).unwrap() }).await.unwrap();
        store.add_to_secret_index(Keyspace::SecretNameIndex, "kv/gone", "g", "").await.unwrap();
        store.reindex("").await.unwrap();
        assert_eq!(store.groups_for_secret_name("kv/x", "").await.unwrap(), ["g", "h"]);
        assert!(store.groups_for_secret_name("kv/gone", "").await.unwrap().is_empty());
        assert_eq!(store.groups_for_resource("web1", "").await.unwrap(), ["g"], "other indexes rebuilt too");
    }
}
