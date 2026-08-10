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
//! Canonicalization for KV paths mirrors the resource-group store:
//! the KV-v2 `data/` / `metadata/` segment at position 1 is stripped
//! so the owner of `secret/foo/bar` is keyed the same whether the
//! write came in as v1 or v2. base64url encoding keeps the `/`
//! characters out of the BarrierView key segment.

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    core::Core,
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
}

#[maybe_async::maybe_async]
impl OwnerStore {
    pub async fn new(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };

        let kv_view = Arc::new(system_view.new_sub_view(KV_OWNER_SUB_PATH));
        let resource_view = Arc::new(system_view.new_sub_view(RESOURCE_OWNER_SUB_PATH));
        let file_view = Arc::new(system_view.new_sub_view(FILE_OWNER_SUB_PATH));
        let ns_resource_view = Arc::new(system_view.new_sub_view(NS_RESOURCE_OWNER_SUB_PATH));
        let ns_file_view = Arc::new(system_view.new_sub_view(NS_FILE_OWNER_SUB_PATH));

        Ok(Arc::new(Self { kv_view, resource_view, file_view, ns_resource_view, ns_file_view }))
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

    /// Canonicalize a KV secret path for owner lookup/storage. Matches
    /// `ResourceGroupStore::canonicalize_secret_path` so a secret's
    /// owner and its asset-group membership key on the same identity.
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
        if canonical.is_empty() { None } else { Some(canonical) }
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
            Some(n) => trimmed
                .strip_prefix(&format!("{n}/"))
                .unwrap_or(trimmed),
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

    /// Return the owner of a KV secret, or `None` if it has no owner
    /// record (legacy secrets predating this feature, or writes by
    /// callers with no entity_id).
    pub async fn get_kv_owner(&self, path: &str) -> Result<Option<OwnerRecord>, RvError> {
        let Some(canonical) = Self::canonicalize_kv_path(path) else {
            return Ok(None);
        };
        let key = Self::kv_key(&canonical);
        let Some(raw) = self.kv_view.get(&key).await? else {
            return Ok(None);
        };
        let rec: OwnerRecord = serde_json::from_slice(&raw.value).unwrap_or_default();
        if rec.entity_id.is_empty() { Ok(None) } else { Ok(Some(rec)) }
    }

    /// Record `entity_id` as the owner of `path` *only if no owner
    /// entry exists yet*. Silently no-ops when the secret is already
    /// owned — prevents a subsequent write from "stealing" ownership.
    /// Silent on empty `entity_id` (root-token writes, or any path
    /// where the caller lacks entity metadata) so existing tests don't
    /// start stamping unknown owners.
    pub async fn record_kv_owner_if_absent(
        &self,
        path: &str,
        entity_id: &str,
    ) -> Result<(), RvError> {
        if entity_id.is_empty() {
            return Ok(());
        }
        let Some(canonical) = Self::canonicalize_kv_path(path) else {
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
        let rec = OwnerRecord {
            entity_id: entity_id.to_string(),
            created_at: Utc::now().to_rfc3339(),
        };
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
    pub async fn set_kv_owner(
        &self,
        path: &str,
        entity_id: &str,
    ) -> Result<(), RvError> {
        let Some(canonical) = Self::canonicalize_kv_path(path) else {
            return Err(crate::bv_error_string!("invalid KV path"));
        };
        let entity_id = entity_id.trim();
        if entity_id.is_empty() {
            return Err(crate::bv_error_string!("entity_id is required"));
        }
        let key = Self::kv_key(&canonical);
        let rec = OwnerRecord {
            entity_id: entity_id.to_string(),
            created_at: Utc::now().to_rfc3339(),
        };
        let value = serde_json::to_vec(&rec)?;
        self.kv_view.put(&StorageEntry { key, value }).await
    }

    pub async fn forget_kv_owner(&self, path: &str) -> Result<(), RvError> {
        let Some(canonical) = Self::canonicalize_kv_path(path) else {
            return Ok(());
        };
        let key = Self::kv_key(&canonical);
        self.kv_view.delete(&key).await
    }

    /// Test-only: plant a raw record with an empty `entity_id` to
    /// simulate a "ghost" owner row from an older server version.
    /// Used by the regression test in `identity_tests` that verifies
    /// `record_kv_owner_if_absent` overwrites such rows.
    #[cfg(test)]
    pub async fn plant_kv_ghost_for_test(&self, path: &str) -> Result<(), RvError> {
        let canonical = Self::canonicalize_kv_path(path).expect("valid kv path");
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

    pub async fn get_resource_owner(
        &self,
        resource: &str,
    ) -> Result<Option<OwnerRecord>, RvError> {
        let Some((view, key)) = self.resource_slot(resource) else {
            return Ok(None);
        };
        let Some(raw) = view.get(&key).await? else {
            return Ok(None);
        };
        let rec: OwnerRecord = serde_json::from_slice(&raw.value).unwrap_or_default();
        if rec.entity_id.is_empty() { Ok(None) } else { Ok(Some(rec)) }
    }

    pub async fn record_resource_owner_if_absent(
        &self,
        resource: &str,
        entity_id: &str,
    ) -> Result<(), RvError> {
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
        let rec = OwnerRecord {
            entity_id: entity_id.to_string(),
            created_at: Utc::now().to_rfc3339(),
        };
        let value = serde_json::to_vec(&rec)?;
        view.put(&StorageEntry { key, value }).await
    }

    /// Unconditional overwrite of a resource owner record. Mirror of
    /// `set_kv_owner`.
    pub async fn set_resource_owner(
        &self,
        resource: &str,
        entity_id: &str,
    ) -> Result<(), RvError> {
        let Some((view, key)) = self.resource_slot(resource) else {
            return Err(crate::bv_error_string!("invalid resource name"));
        };
        let entity_id = entity_id.trim();
        if entity_id.is_empty() {
            return Err(crate::bv_error_string!("entity_id is required"));
        }
        let rec = OwnerRecord {
            entity_id: entity_id.to_string(),
            created_at: Utc::now().to_rfc3339(),
        };
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
        if rec.entity_id.is_empty() { Ok(None) } else { Ok(Some(rec)) }
    }

    pub async fn record_file_owner_if_absent(
        &self,
        id: &str,
        entity_id: &str,
    ) -> Result<(), RvError> {
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
        let rec = OwnerRecord {
            entity_id: entity_id.to_string(),
            created_at: Utc::now().to_rfc3339(),
        };
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
        let rec = OwnerRecord {
            entity_id: entity_id.to_string(),
            created_at: Utc::now().to_rfc3339(),
        };
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
        assert_eq!(
            OwnerStore::canonicalize_kv_path_scoped("secret/k", ns),
            Some("a/b/c/secret/k".to_string()),
        );
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

    // Idempotence: feeding an already-scoped key back through must be a
    // no-op, since downstream store methods re-run `canonicalize_kv_path`
    // internally on whatever we hand them.
    #[test]
    fn already_scoped_key_is_idempotent() {
        let ns = Some("dti/esi");
        let once = OwnerStore::canonicalize_kv_path_scoped("dti/esi/secret/data/github", ns).unwrap();
        // Re-scoping the canonical form, and running the plain canonicalizer
        // that the store methods apply internally, both leave it unchanged.
        assert_eq!(
            OwnerStore::canonicalize_kv_path_scoped(&once, ns),
            Some(once.clone()),
        );
        assert_eq!(OwnerStore::canonicalize_kv_path(&once), Some(once));
    }
}
