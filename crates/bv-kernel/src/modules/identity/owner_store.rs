//! Owner store for ownership-aware ACL rules.
//!
//! Records the entity_id that created each KV secret and each
//! resource, so `scopes = ["owner"]` policy rules can check whether
//! the caller owns the target at authorize time. See
//! `features/per-user-scoping.md`.
//!
//! Kept separate from the KV and resource payload layouts so existing
//! tests and on-disk formats are not affected. Storage:
//!
//!   sys/owner/kv/<b64url(full-path)>    -> OwnerRecord
//!   sys/owner/resource/<resource-name>  -> OwnerRecord
//!
//! A KV record is keyed on `<ns>/<mount>/<name>`, derived once by the policy
//! layer (`policy::kv_target`) or the client endpoints; the KV methods here
//! take that key as given and never transform it (T499). base64url keeps the
//! `/` characters out of the BarrierView key segment.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::kernel_api::VaultCtx;
use crate::{
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

const KV_OWNER_SUB_PATH: &str = "owner/kv/";
const RESOURCE_OWNER_SUB_PATH: &str = "owner/resource/";
const FILE_OWNER_SUB_PATH: &str = "owner/file/";
/// Namespaced owner records live in their own sub-views, keyed by
/// `b64url("<ns>/<name>")`. A separate keyspace (rather than a `<ns>/`-prefixed
/// key in the legacy views) is deliberate: it leaves every existing root record
/// byte-identical, and it makes a root name and a tenant name structurally
/// incapable of colliding — a bare lowercase resource name and a base64url
/// blob cannot be confused for one another when they never share a view.
const NS_RESOURCE_OWNER_SUB_PATH: &str = "owner/ns-resource/";
const NS_FILE_OWNER_SUB_PATH: &str = "owner/ns-file/";
/// The store's own bookkeeping (the T499 datafix marker and its plan), apart
/// from every record keyspace.
const META_SUB_PATH: &str = "owner/meta/";
const KV_KEY_SPLIT_MARKER: &str = "kv-key-split-version";
/// T499 datafix version; a bumped value runs the pass again on the next unseal.
pub const KV_KEY_SPLIT_VERSION: u32 = 1;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OwnerRecord {
    pub entity_id: String,
    pub created_at: String,
}

pub struct OwnerStore {
    kv_view: Arc<BarrierView>,
    resource_view: Arc<BarrierView>,
    file_view: Arc<BarrierView>,
    ns_resource_view: Arc<BarrierView>,
    ns_file_view: Arc<BarrierView>,
    meta_view: Arc<BarrierView>,
    /// Cached once the T499 datafix marker is seen: KV keys are
    /// `<mount><name>`. Until then every caller derives the pre-T499 key.
    kv_keys_split: AtomicBool,
}

#[maybe_async::maybe_async]
impl OwnerStore {
    pub async fn new(core: &dyn VaultCtx) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.system_view() else {
            return Err(RvError::ErrBarrierSealed);
        };

        let kv_view = Arc::new(system_view.new_sub_view(KV_OWNER_SUB_PATH));
        let resource_view = Arc::new(system_view.new_sub_view(RESOURCE_OWNER_SUB_PATH));
        let file_view = Arc::new(system_view.new_sub_view(FILE_OWNER_SUB_PATH));
        let ns_resource_view = Arc::new(system_view.new_sub_view(NS_RESOURCE_OWNER_SUB_PATH));
        let ns_file_view = Arc::new(system_view.new_sub_view(NS_FILE_OWNER_SUB_PATH));
        let meta_view = Arc::new(system_view.new_sub_view(META_SUB_PATH));

        Ok(Arc::new(Self {
            kv_view,
            resource_view,
            file_view,
            ns_resource_view,
            ns_file_view,
            meta_view,
            kv_keys_split: AtomicBool::new(false),
        }))
    }

    /// Namespace-scope a resource name, file id, or asset-group name for owner
    /// and share lookups: `Some("<ns>/<name>")` in a namespace, `Some(name)` at
    /// root.
    ///
    /// The name-keyed analogue of [`canonicalize_kv_path_scoped`]. Resource,
    /// file, and asset-group records live in a single global store keyed on the
    /// bare name, so without this a resource called `db1` in namespace
    /// `dti/esi` and one called `db1` at root share one owner record and one
    /// set of shares — a share granted on either would unlock both. Root
    /// (`ns_path` empty or `None`) returns the bare lowercased name, so every
    /// pre-existing record and caller is unaffected.
    ///
    /// Returns `None` for a name that is empty, contains `/`, or contains `..`
    /// — the same validation the store methods applied inline before, hoisted
    /// here so a caller cannot smuggle a second path segment past the scoping
    /// and land on another namespace's key.
    ///
    /// Accepts an already-scoped name idempotently: a value that starts with
    /// `<ns>/` is returned unchanged, so passing a scoped key back through is
    /// safe (mirrors `canonicalize_kv_path_scoped`).
    ///
    /// [`canonicalize_kv_path_scoped`]: Self::canonicalize_kv_path_scoped
    pub fn scope_target_name(name: &str, ns_path: Option<&str>) -> Option<String> {
        let ns = ns_path.map(|n| n.trim().trim_matches('/')).filter(|n| !n.is_empty());
        let raw = name.trim().to_lowercase();
        // Idempotence: already carries this namespace's prefix.
        if let Some(n) = ns {
            let prefix = format!("{}/", n.to_lowercase());
            if let Some(rest) = raw.strip_prefix(&prefix) {
                return Self::scope_target_name(rest, ns_path);
            }
        }
        if raw.is_empty() || raw.contains('/') || raw.contains("..") {
            return None;
        }
        Some(match ns {
            Some(n) => format!("{}/{}", n.to_lowercase(), raw),
            None => raw,
        })
    }

    /// Inverse of [`scope_target_name`](Self::scope_target_name) for a key
    /// expected to belong to `ns_path`: the bare name, or `None` when the key
    /// is another namespace's (or malformed). Never falls back to root.
    pub fn unscope_target_name(key: &str, ns_path: Option<&str>) -> Option<String> {
        let raw = key.trim().to_lowercase();
        let bare = match ns_path.map(|n| n.trim().trim_matches('/')).filter(|n| !n.is_empty()) {
            Some(n) => raw.strip_prefix(&format!("{}/", n.to_lowercase()))?.to_string(),
            None => raw,
        };
        if bare.is_empty() || bare.contains('/') || bare.contains("..") {
            return None;
        }
        Some(bare)
    }

    /// Split a (possibly namespace-scoped) target key into the view that holds
    /// it and the key within that view. Root keys keep the legacy bare-name
    /// layout; namespaced keys are base64url'd into the `ns-*` views so the
    /// `/` separator never becomes a nested BarrierView path segment.
    fn target_slot<'a>(
        legacy: &'a Arc<BarrierView>,
        scoped: &'a Arc<BarrierView>,
        key: &str,
    ) -> Option<(&'a Arc<BarrierView>, String)> {
        let k = key.trim().to_lowercase();
        if k.is_empty() || k.contains("..") {
            return None;
        }
        if k.contains('/') {
            Some((scoped, URL_SAFE_NO_PAD.encode(k.as_bytes())))
        } else {
            Some((legacy, k))
        }
    }

    /// The pre-T499 KV canonicalizer: strips a `data`/`metadata` segment at
    /// index 1 whatever the mount. Not idempotent (`secret/data/x` is a key
    /// and a request path); only [`Self::legacy_kv_key`] still uses it.
    pub fn canonicalize_kv_path(raw: &str) -> Option<String> {
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

    /// Namespace-scoped canonical KV owner key: `<ns>/<mount>/<key>`.
    ///
    /// Owner records are stored in a single global store, so the key must
    /// carry the namespace to keep two namespaces that both hold, say,
    /// `secret/github` distinct. This normalizes the *two* path forms that
    /// reach the owner store into one canonical string:
    ///
    /// * **Request paths** (post-`rewrite_request_for_namespace`) arrive
    ///   namespace-prefixed and with the KV v2 `data`/`metadata` infix,
    ///   e.g. `dti/esi/secret/data/github`.
    /// * **Client paths** (the base64url the GUI sends to `identity/owner/*`
    ///   and `identity/share/*`) arrive mount-relative with no namespace and
    ///   no infix, e.g. `secret/github`.
    ///
    /// `ns_path` is the active namespace (`req.namespace_path`), or `None`
    /// for root. We strip a leading `ns_path` if the raw path already carries
    /// it, canonicalize the mount-relative remainder with the existing
    /// [`canonicalize_kv_path`] (which strips the `data`/`metadata` infix at
    /// index 1), then re-prepend `ns_path`. For root (`None`) this is
    /// identical to `canonicalize_kv_path`, so existing root data and callers
    /// are unaffected.
    ///
    /// [`canonicalize_kv_path`]: Self::canonicalize_kv_path
    pub fn canonicalize_kv_path_scoped(raw: &str, ns_path: Option<&str>) -> Option<String> {
        let trimmed = raw.trim().trim_matches('/');
        let ns = ns_path.map(|n| n.trim().trim_matches('/')).filter(|n| !n.is_empty());
        let rel = match ns {
            Some(n) => trimmed.strip_prefix(&format!("{n}/")).unwrap_or(trimmed),
            None => trimmed,
        };
        let rel_canon = Self::canonicalize_kv_path(rel)?;
        Some(match ns {
            Some(n) => format!("{n}/{rel_canon}"),
            None => rel_canon,
        })
    }

    fn kv_key(canonical: &str) -> String {
        URL_SAFE_NO_PAD.encode(canonical.as_bytes())
    }

    /// Whether the T499 datafix has completed: its replicated marker, cached
    /// once seen, so every node switches when whichever node ran it is done.
    /// Until then each call reads the marker. An unreadable or garbled marker
    /// is an error, and callers refuse rather than use the pre-T499 keys.
    pub async fn kv_keys_split(&self) -> Result<bool, RvError> {
        if self.kv_keys_split.load(Ordering::Acquire) {
            return Ok(true);
        }
        let Some(entry) = self.meta_view.get(KV_KEY_SPLIT_MARKER).await? else {
            return Ok(false);
        };
        let done = serde_json::from_slice::<u32>(&entry.value)? >= KV_KEY_SPLIT_VERSION;
        if done {
            self.kv_keys_split.store(true, Ordering::Release);
        }
        Ok(done)
    }

    /// Record that the datafix completed and switch to `<mount><name>`.
    pub(crate) async fn mark_kv_keys_split(&self) -> Result<(), RvError> {
        let value = serde_json::to_vec(&KV_KEY_SPLIT_VERSION)?;
        self.meta_view.put(&StorageEntry { key: KV_KEY_SPLIT_MARKER.to_string(), value }).await?;
        self.kv_keys_split.store(true, Ordering::Release);
        Ok(())
    }

    /// The datafix's own state under `owner/meta/<key>` (its persisted plan).
    pub(crate) async fn meta_get(&self, key: &str) -> Result<Option<Vec<u8>>, RvError> {
        Ok(self.meta_view.get(key).await?.map(|e| e.value))
    }

    pub(crate) async fn meta_put(&self, key: &str, value: Vec<u8>) -> Result<(), RvError> {
        self.meta_view.put(&StorageEntry { key: key.to_string(), value }).await
    }

    pub(crate) async fn meta_delete(&self, key: &str) -> Result<(), RvError> {
        self.meta_view.delete(key).await
    }

    /// Test support: back to pre-T499 keys, marker gone, as before the datafix.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn unsplit_kv_keys_for_test(&self) -> Result<(), RvError> {
        self.meta_view.delete(KV_KEY_SPLIT_MARKER).await?;
        self.kv_keys_split.store(false, Ordering::Release);
        Ok(())
    }

    /// Test support: a garbled marker, which every reader must refuse.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn garble_kv_key_split_marker_for_test(&self) -> Result<(), RvError> {
        self.kv_keys_split.store(false, Ordering::Release);
        self.meta_view.put(&StorageEntry { key: KV_KEY_SPLIT_MARKER.to_string(), value: b"garbled".to_vec() }).await
    }

    /// A KV owner/share key as stored: whitespace and `/` trimmed, refused
    /// when empty or holding a `..` segment. Never strips anything else, so a
    /// key passed back in is returned unchanged.
    pub fn checked_kv_key(key: &str) -> Option<String> {
        let k = key.trim().trim_matches('/');
        (!k.is_empty() && !k.split('/').any(|s| s == "..")).then(|| k.to_string())
    }

    /// The key every release before T499 used for a KV request path: the
    /// scoped canonical path, canonicalized a second time by the store. Kept
    /// for non-KV paths, for the datafix, and until the datafix has run.
    pub fn legacy_kv_key(path: &str, ns_path: Option<&str>) -> Option<String> {
        Self::canonicalize_kv_path(&Self::canonicalize_kv_path_scoped(path, ns_path)?)
    }

    /// [`Self::client_kv_key`] for a write (an owner record, a share): while the
    /// T499 switch is pending (`!split`), a name whose key moves at the switch
    /// is refused with [`Self::moving_key_refusal`] (T511), since a record
    /// written under the old key could be left behind or read as another's.
    pub fn client_kv_key_for_write(path: &str, ns_path: Option<&str>, split: bool) -> Result<Option<String>, RvError> {
        if !split && Self::client_kv_key(path, ns_path, false) != Self::client_kv_key(path, ns_path, true) {
            return Err(Self::moving_key_refusal());
        }
        Ok(Self::client_kv_key(path, ns_path, split))
    }

    /// The 503 for an owner or share change to a KV secret whose key moves when
    /// the pending T499 datafix completes (T511): retriable once it has.
    pub fn moving_key_refusal() -> RvError {
        RvError::ErrResponseStatus(
            503,
            "this KV secret's owner and share key changes when the pending KV key-split datafix completes, so \
             writes, deletes, owner changes and shares on it are refused until a pass completes (at unseal, or by \
             its background retry) (docs/api.md, \"KV key-split datafix pending\")"
                .to_string(),
        )
    }

    /// The key of a secret a client names as `<mount>/<name>` (the owner,
    /// share and `sys/kv-owner` endpoints): `<ns>/<mount>/<name>` verbatim once
    /// `split`, so a stored key passed back resolves to itself; the pre-T499
    /// key before the datafix. A leading `<ns>/` is accepted as already scoped.
    pub fn client_kv_key(path: &str, ns_path: Option<&str>, split: bool) -> Option<String> {
        if !split {
            return Self::legacy_kv_key(path, ns_path);
        }
        let trimmed = path.trim().trim_matches('/');
        let key = match ns_path.map(|n| n.trim().trim_matches('/')).filter(|n| !n.is_empty()) {
            Some(n) if trimmed.starts_with(&format!("{n}/")) => trimmed.to_string(),
            Some(n) => format!("{n}/{trimmed}"),
            None => trimmed.to_string(),
        };
        Self::checked_kv_key(&key)
    }

    /// Return the owner of the KV secret keyed `key`, or `None` if it has no
    /// owner record (legacy secrets predating this feature, or writes by
    /// callers with no entity_id).
    pub async fn get_kv_owner(&self, key: &str) -> Result<Option<OwnerRecord>, RvError> {
        let Some(canonical) = Self::checked_kv_key(key) else {
            return Ok(None);
        };
        let key = Self::kv_key(&canonical);
        let Some(raw) = self.kv_view.get(&key).await? else {
            return Ok(None);
        };
        let rec: OwnerRecord = serde_json::from_slice(&raw.value).unwrap_or_default();
        if rec.entity_id.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rec))
        }
    }

    /// Whether `entity_id` owns any KV secret under `prefix` — a
    /// canonical path with a trailing `/` (`"dti/esi/secret/trend/"`).
    /// Answers "is this folder worth listing?" for the scope-filtered
    /// LIST pass. Keys in the KV owner view are base64url of the
    /// canonical path, so the prefix test needs no read: only the
    /// candidates that decode under `prefix` are fetched.
    pub async fn has_owned_kv_under(&self, prefix: &str, entity_id: &str) -> Result<bool, RvError> {
        if prefix.is_empty() || entity_id.trim().is_empty() {
            return Ok(false);
        }
        for key in self.kv_view.list("").await? {
            let key = key.trim_end_matches('/');
            let Ok(raw) = URL_SAFE_NO_PAD.decode(key.as_bytes()) else {
                continue;
            };
            let Ok(canonical) = String::from_utf8(raw) else {
                continue;
            };
            if !canonical.starts_with(prefix) {
                continue;
            }
            if let Some(rec) = self.get_kv_owner(&canonical).await? {
                if rec.entity_id == entity_id {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Record `entity_id` as the owner of `path` *only if no owner
    /// entry exists yet*. Silently no-ops when the secret is already
    /// owned — prevents a subsequent write from "stealing" ownership.
    /// Silent on empty `entity_id` (root-token writes, or any path
    /// where the caller lacks entity metadata) so existing tests don't
    /// start stamping unknown owners.
    pub async fn record_kv_owner_if_absent(&self, key: &str, entity_id: &str) -> Result<(), RvError> {
        if entity_id.is_empty() {
            return Ok(());
        }
        let Some(canonical) = Self::checked_kv_key(key) else {
            return Ok(());
        };
        let key = Self::kv_key(&canonical);
        // Treat a record with an empty entity_id as "absent" — older
        // server versions could leave such ghost entries from writes
        // by callers whose auth metadata lacked entity_id. `get_kv_owner`
        // surfaces those as "Unowned" to the GUI, and the user-facing
        // promise is that the next authenticated write captures
        // ownership, so we overwrite them here.
        if let Some(raw) = self.kv_view.get(&key).await? {
            let existing: OwnerRecord = serde_json::from_slice(&raw.value).unwrap_or_default();
            if !existing.entity_id.is_empty() {
                return Ok(());
            }
        }
        let rec = OwnerRecord { entity_id: entity_id.to_string(), created_at: Utc::now().to_rfc3339() };
        let value = serde_json::to_vec(&rec)?;
        self.kv_view.put(&StorageEntry { key, value }).await
    }

    /// Drop the owner record for `path`. Called on KV delete so a
    /// later write by a different caller correctly captures new
    /// ownership.
    /// Unconditionally set the owner of a KV secret, overwriting any
    /// existing owner record. Used by the admin ownership-transfer
    /// endpoint — callers who want "first write wins" semantics must
    /// use `record_kv_owner_if_absent` instead.
    pub async fn set_kv_owner(&self, key: &str, entity_id: &str) -> Result<(), RvError> {
        let Some(canonical) = Self::checked_kv_key(key) else {
            return Err(crate::bv_error_string!("invalid KV path"));
        };
        let entity_id = entity_id.trim();
        if entity_id.is_empty() {
            return Err(crate::bv_error_string!("entity_id is required"));
        }
        let key = Self::kv_key(&canonical);
        let rec = OwnerRecord { entity_id: entity_id.to_string(), created_at: Utc::now().to_rfc3339() };
        let value = serde_json::to_vec(&rec)?;
        self.kv_view.put(&StorageEntry { key, value }).await
    }

    /// Write `rec` under the KV key `key` as it is, `created_at` included.
    /// Migration support only (the T499 datafix copies records verbatim).
    pub(crate) async fn put_kv_owner_record(&self, key: &str, rec: &OwnerRecord) -> Result<(), RvError> {
        let canonical = Self::checked_kv_key(key).ok_or_else(|| crate::bv_error_string!("invalid KV key"))?;
        self.kv_view.put(&StorageEntry { key: Self::kv_key(&canonical), value: serde_json::to_vec(rec)? }).await
    }

    pub async fn forget_kv_owner(&self, key: &str) -> Result<(), RvError> {
        let Some(canonical) = Self::checked_kv_key(key) else {
            return Ok(());
        };
        let key = Self::kv_key(&canonical);
        self.kv_view.delete(&key).await
    }

    /// Test-only: plant a raw record with an empty `entity_id` to
    /// simulate a "ghost" owner row from an older server version.
    /// Used by the regression test in `identity_tests` that verifies
    /// `record_kv_owner_if_absent` overwrites such rows.
    ///
    /// Not `#[cfg(test)]`: that test lives in `bastion_vault::engine_tests`
    /// now (it needs a vault built by the assembly layer, or `get_module`
    /// sees two `TypeId`s for the same type), and `test` does not cross a
    /// crate boundary. Gated on the fixture feature that consumer enables.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn plant_kv_ghost_for_test(&self, key: &str) -> Result<(), RvError> {
        let canonical = Self::checked_kv_key(key).expect("valid kv key");
        let key = Self::kv_key(&canonical);
        let rec = OwnerRecord { entity_id: String::new(), created_at: String::new() };
        let value = serde_json::to_vec(&rec)?;
        self.kv_view.put(&StorageEntry { key, value }).await
    }

    /// Resolve the (view, key) slot for a resource owner record. `resource` is
    /// either a bare root name or a `<ns>/<name>` key from
    /// [`scope_target_name`](Self::scope_target_name).
    fn resource_slot(&self, resource: &str) -> Option<(&Arc<BarrierView>, String)> {
        Self::target_slot(&self.resource_view, &self.ns_resource_view, resource)
    }

    pub async fn get_resource_owner(&self, resource: &str) -> Result<Option<OwnerRecord>, RvError> {
        let Some((view, key)) = self.resource_slot(resource) else {
            return Ok(None);
        };
        let Some(raw) = view.get(&key).await? else {
            return Ok(None);
        };
        let rec: OwnerRecord = serde_json::from_slice(&raw.value).unwrap_or_default();
        if rec.entity_id.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rec))
        }
    }

    pub async fn record_resource_owner_if_absent(&self, resource: &str, entity_id: &str) -> Result<(), RvError> {
        if entity_id.is_empty() {
            return Ok(());
        }
        let Some((view, key)) = self.resource_slot(resource) else {
            return Ok(());
        };
        if let Some(raw) = view.get(&key).await? {
            let existing: OwnerRecord = serde_json::from_slice(&raw.value).unwrap_or_default();
            if !existing.entity_id.is_empty() {
                return Ok(());
            }
        }
        let rec = OwnerRecord { entity_id: entity_id.to_string(), created_at: Utc::now().to_rfc3339() };
        let value = serde_json::to_vec(&rec)?;
        view.put(&StorageEntry { key, value }).await
    }

    /// Unconditional overwrite of a resource owner record. Mirror of
    /// `set_kv_owner`.
    pub async fn set_resource_owner(&self, resource: &str, entity_id: &str) -> Result<(), RvError> {
        let Some((view, key)) = self.resource_slot(resource) else {
            return Err(crate::bv_error_string!("invalid resource name"));
        };
        let entity_id = entity_id.trim();
        if entity_id.is_empty() {
            return Err(crate::bv_error_string!("entity_id is required"));
        }
        let rec = OwnerRecord { entity_id: entity_id.to_string(), created_at: Utc::now().to_rfc3339() };
        let value = serde_json::to_vec(&rec)?;
        view.put(&StorageEntry { key, value }).await
    }

    pub async fn forget_resource_owner(&self, resource: &str) -> Result<(), RvError> {
        let Some((view, key)) = self.resource_slot(resource) else {
            return Ok(());
        };
        view.delete(&key).await
    }

    // ── File ownership (parallel to kv/resource) ──────────────────
    //
    // File IDs are server-assigned UUIDs (see `src/modules/files/`);
    // they are never operator-supplied and always fit the `[^/]+`
    // shape already enforced by the route pattern. The owner key is
    // therefore the id itself at root, or `<ns>/<id>` in a namespace.

    /// Resolve the (view, key) slot for a file owner record. `id` is either a
    /// bare root uuid or a `<ns>/<uuid>` key from
    /// [`scope_target_name`](Self::scope_target_name).
    fn file_slot(&self, id: &str) -> Option<(&Arc<BarrierView>, String)> {
        Self::target_slot(&self.file_view, &self.ns_file_view, id)
    }

    pub async fn get_file_owner(&self, id: &str) -> Result<Option<OwnerRecord>, RvError> {
        let Some((view, key)) = self.file_slot(id) else {
            return Ok(None);
        };
        let Some(raw) = view.get(&key).await? else {
            return Ok(None);
        };
        let rec: OwnerRecord = serde_json::from_slice(&raw.value).unwrap_or_default();
        if rec.entity_id.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rec))
        }
    }

    pub async fn record_file_owner_if_absent(&self, id: &str, entity_id: &str) -> Result<(), RvError> {
        if entity_id.is_empty() {
            return Ok(());
        }
        let Some((view, key)) = self.file_slot(id) else {
            return Ok(());
        };
        if let Some(raw) = view.get(&key).await? {
            let existing: OwnerRecord = serde_json::from_slice(&raw.value).unwrap_or_default();
            if !existing.entity_id.is_empty() {
                return Ok(());
            }
        }
        let rec = OwnerRecord { entity_id: entity_id.to_string(), created_at: Utc::now().to_rfc3339() };
        let value = serde_json::to_vec(&rec)?;
        view.put(&StorageEntry { key, value }).await
    }

    pub async fn set_file_owner(&self, id: &str, entity_id: &str) -> Result<(), RvError> {
        let Some((view, key)) = self.file_slot(id) else {
            return Err(crate::bv_error_string!("invalid file id"));
        };
        let entity_id = entity_id.trim();
        if entity_id.is_empty() {
            return Err(crate::bv_error_string!("entity_id is required"));
        }
        let rec = OwnerRecord { entity_id: entity_id.to_string(), created_at: Utc::now().to_rfc3339() };
        let value = serde_json::to_vec(&rec)?;
        view.put(&StorageEntry { key, value }).await
    }

    pub async fn forget_file_owner(&self, id: &str) -> Result<(), RvError> {
        let Some((view, key)) = self.file_slot(id) else {
            return Ok(());
        };
        view.delete(&key).await
    }

    /// Every bare (pre-namespace-scoping) resource owner key on disk.
    ///
    /// Migration support only — see `identity::ns_scope_migrate`. Reads the
    /// *legacy* view, so it never returns a namespaced record (those live in
    /// `ns_resource_view` under a base64url key).
    pub async fn list_legacy_resource_owners(&self) -> Result<Vec<String>, RvError> {
        Ok(self
            .resource_view
            .list("")
            .await?
            .into_iter()
            .map(|k| k.trim_end_matches('/').to_string())
            .filter(|k| !k.is_empty())
            .collect())
    }
}

#[cfg(test)]
mod scoped_key_tests {
    use super::OwnerStore;

    // Root namespace (ns_path = None) must be byte-identical to the
    // legacy `canonicalize_kv_path` so existing root records and callers
    // are untouched.
    #[test]
    fn root_matches_legacy_canonicalization() {
        for raw in ["secret/data/github", "secret/metadata/github", "secret/github"] {
            assert_eq!(
                OwnerStore::canonicalize_kv_path_scoped(raw, None),
                OwnerStore::canonicalize_kv_path(raw),
                "scoped(None) must equal legacy for {raw:?}",
            );
        }
    }

    // `unscope_target_name` inverts `scope_target_name` for the namespace the
    // key belongs to, and refuses another namespace's key instead of guessing.
    #[test]
    fn unscope_inverts_scope_and_refuses_foreign_keys() {
        for ns in [None, Some("dti/esi"), Some("Dti/Esi")] {
            let key = OwnerStore::scope_target_name("Prod", ns).unwrap();
            assert_eq!(OwnerStore::unscope_target_name(&key, ns).as_deref(), Some("prod"), "{ns:?}");
        }
        assert_eq!(OwnerStore::unscope_target_name("dti/esi/prod", None), None);
        assert_eq!(OwnerStore::unscope_target_name("prod", Some("dti/esi")), None);
        assert_eq!(OwnerStore::unscope_target_name("dti/other/prod", Some("dti/esi")), None);
        assert_eq!(OwnerStore::unscope_target_name("dti/esi/a/b", Some("dti/esi")), None);
    }

    // The two path forms that reach the owner store in a child namespace
    // must canonicalize to the SAME key. This is the core of the
    // "unowned in a non-root namespace" fix: the write path arrives
    // namespace-prefixed and with the KV v2 `data` infix, while the GUI
    // owner/share read arrives mount-relative.
    #[test]
    fn child_ns_write_and_read_forms_agree() {
        let ns = Some("dti/esi");
        // Write path (rewritten, with `data` infix).
        let write = OwnerStore::canonicalize_kv_path_scoped("dti/esi/secret/data/github", ns);
        // GUI read path (mount-relative b64-decoded, no infix, no ns).
        let read = OwnerStore::canonicalize_kv_path_scoped("secret/github", ns);
        assert_eq!(write, Some("dti/esi/secret/github".to_string()));
        assert_eq!(read, write, "write and read forms must key identically");
    }

    // `metadata` infix (LIST / delete paths) normalizes the same way.
    #[test]
    fn child_ns_metadata_infix_stripped() {
        let ns = Some("dti/esi");
        assert_eq!(
            OwnerStore::canonicalize_kv_path_scoped("dti/esi/secret/metadata/a/b", ns),
            Some("dti/esi/secret/a/b".to_string()),
        );
    }

    // A nested namespace (multi-segment ns_path) is preserved as a whole
    // and not confused with the mount segment.
    #[test]
    fn nested_ns_prefix_preserved() {
        let ns = Some("a/b/c");
        assert_eq!(
            OwnerStore::canonicalize_kv_path_scoped("a/b/c/secret/data/k", ns),
            Some("a/b/c/secret/k".to_string()),
        );
        // And the mount-relative read form lands on the same key.
        assert_eq!(OwnerStore::canonicalize_kv_path_scoped("secret/k", ns), Some("a/b/c/secret/k".to_string()),);
    }

    // Two distinct namespaces holding the same mount-relative secret get
    // distinct keys — the isolation property that a global owner store
    // otherwise lacks.
    #[test]
    fn distinct_namespaces_do_not_collide() {
        let a = OwnerStore::canonicalize_kv_path_scoped("secret/github", Some("team-a"));
        let b = OwnerStore::canonicalize_kv_path_scoped("secret/github", Some("team-b"));
        assert_ne!(a, b);
    }

    // Idempotence: re-scoping an already-scoped key is a no-op.
    #[test]
    fn already_scoped_key_is_idempotent() {
        let ns = Some("dti/esi");
        let once = OwnerStore::canonicalize_kv_path_scoped("dti/esi/secret/data/github", ns).unwrap();
        assert_eq!(OwnerStore::canonicalize_kv_path_scoped(&once, ns), Some(once.clone()),);
        assert_eq!(OwnerStore::canonicalize_kv_path(&once), Some(once));
    }

    // T499: the pre-T499 key canonicalized twice, so `data/x` keyed as `x`
    // at root and a namespace named `team/data` keyed as `team`.
    #[test]
    fn the_legacy_key_is_the_double_canonicalized_one() {
        assert_eq!(OwnerStore::legacy_kv_key("secret/data/data/x", None).as_deref(), Some("secret/x"));
        assert_eq!(OwnerStore::legacy_kv_key("secret/data/x", None).as_deref(), Some("secret/x"));
        let ns = Some("team/data");
        assert_eq!(OwnerStore::legacy_kv_key("team/data/secret/data/x", ns).as_deref(), Some("team/secret/x"));
        assert_eq!(OwnerStore::legacy_kv_key("secret/a/../b", None), None);
    }

    // T511: which client names (`<mount>/<name>`) an owner or share write
    // refuses while the switch is pending, as `docs/api.md` lists them.
    #[test]
    fn the_client_names_that_move_at_the_switch() {
        let cases = [
            ("secret/x", None, false),
            ("secret/data/x", None, true),
            ("secret/metadata", None, true),
            ("secret/database/x", None, false),
            ("secret/data/x", Some("team"), true),
            ("secret/x", Some("team"), false),
            ("team/kv/data/x", None, false),
            ("secret/x", Some("team/data"), true),
            ("apps/data/x", None, true),
            ("data/x", Some("team"), true),
            ("apps/data/x", Some("team"), true),
            ("data/x", Some("a/b"), false),
            ("a/b/data/x", None, false),
        ];
        for (path, ns, moves) in cases {
            let refused = OwnerStore::client_kv_key_for_write(path, ns, false).is_err();
            assert_eq!(refused, moves, "{path} in {ns:?}");
            assert!(OwnerStore::client_kv_key_for_write(path, ns, true).is_ok(), "never once split: {path}");
        }
    }

    // T499: a client key is the secret's `<ns>/<mount>/<name>` verbatim, and a
    // key passed back in comes back unchanged, for every name.
    #[test]
    fn a_client_key_is_a_fixed_point() {
        for ns in [None, Some("dti/esi"), Some("team/data")] {
            for path in ["secret/x", "secret/data/x", "secret/metadata/data/x", "kv/team/data/x"] {
                let key = OwnerStore::client_kv_key(path, ns, true).unwrap();
                let want = ns.map(|n| format!("{n}/{path}")).unwrap_or_else(|| path.to_string());
                assert_eq!(key, want, "{ns:?} {path}");
                assert_eq!(OwnerStore::client_kv_key(&key, ns, true), Some(key.clone()), "{ns:?} {path}");
                assert_eq!(OwnerStore::checked_kv_key(&key), Some(key.clone()));
            }
        }
        assert_eq!(OwnerStore::client_kv_key("secret/data/x", None, false).as_deref(), Some("secret/x"));
        for bad in ["", "/", "secret/../x", " .. "] {
            assert_eq!(OwnerStore::client_kv_key(bad, None, true), None, "{bad:?}");
            assert_eq!(OwnerStore::checked_kv_key(bad), None, "{bad:?}");
        }
    }
}
