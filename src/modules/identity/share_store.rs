//! Share store for explicit access grants on KV secrets and resources.
//!
//! Implements the `SecretShare` record consumed by ownership-aware ACL
//! rules with `scopes = ["shared"]`. A share grants a specific entity
//! (the *grantee*) a subset of capabilities on a single target secret
//! or resource. See `features/per-user-scoping.md` §5 for design.
//!
//! Storage layout (all under the system barrier view):
//!
//!   sys/sharing/primary/<target_hash>/<grantee>   -> SecretShare JSON
//!   sys/sharing/by-grantee/<grantee>/<target_hash> -> { kind, path }
//!
//! `target_hash` is `base64url("<kind>|<canonical_path>")` so both
//! reverse-lookup directions are O(1) and the path is recoverable for
//! audit tooling.
//!
//! Canonicalization: KV paths use the same canonicalizer as `OwnerStore`
//! (KV-v2 `data/` / `metadata/` segments are stripped) so the share on
//! `secret/foo/bar` keys identically whether a grantee reads it via v1
//! or v2. Resource names are lowercased.

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    bv_error_string,
    core::Core,
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

use super::owner_store::OwnerStore;

const SHARE_PRIMARY_SUB_PATH: &str = "sharing/primary/";
const SHARE_BY_GRANTEE_SUB_PATH: &str = "sharing/by-grantee/";
/// Append-only audit trail for share grants, revocations, and
/// cascade-revokes triggered by target deletion. Keyed by
/// `<20-digit-nanos>` so a natural sort yields chronological order;
/// the aggregator in the system backend walks this flat view.
const SHARE_HISTORY_SUB_PATH: &str = "sharing/history/";

/// Target object for a share — a KV secret (by logical path) or a
/// resource (by resource name).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShareTargetKind {
    KvSecret,
    Resource,
    /// Share is against an asset group (a named collection of KV
    /// secrets and resources). At authorize time the evaluator
    /// expands an asset-group share to every current member of the
    /// group, so sharing a bundle scales without per-object grants.
    /// The `target_path` is the group name (lowercased, canonical).
    AssetGroup,
    /// Share is against a file resource (see `src/modules/files/`).
    /// The `target_path` is the server-assigned UUID.
    File,
}

impl ShareTargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ShareTargetKind::KvSecret => "kv-secret",
            ShareTargetKind::Resource => "resource",
            ShareTargetKind::AssetGroup => "asset-group",
            ShareTargetKind::File => "file",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "kv-secret" | "kv" => Some(ShareTargetKind::KvSecret),
            "resource" => Some(ShareTargetKind::Resource),
            "asset-group" | "group" => Some(ShareTargetKind::AssetGroup),
            "file" => Some(ShareTargetKind::File),
            _ => None,
        }
    }
}

/// Explicit share grant. `capabilities` is the subset of operations the
/// grantee may perform on the target — intersection with the policy
/// rule's own capability list is the effective grant.
///
/// `expires_at` is optional RFC3339; when set and in the past, the
/// share is treated as inert by the evaluator and all list/get helpers
/// below filter it out.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretShare {
    pub target_kind: String,
    pub target_path: String,
    pub grantee_entity_id: String,
    pub granted_by_entity_id: String,
    pub capabilities: Vec<String>,
    pub granted_at: String,
    #[serde(default)]
    pub expires_at: String,
}

impl SecretShare {
    /// True when the share has a non-empty `expires_at` and the
    /// timestamp has already passed. Unparseable timestamps are treated
    /// as "not expired" so a malformed record is not silently dropped
    /// from the audit trail — the evaluator errs on the side of
    /// surfacing it.
    pub fn is_expired(&self) -> bool {
        if self.expires_at.is_empty() {
            return false;
        }
        match chrono::DateTime::parse_from_rfc3339(&self.expires_at) {
            Ok(exp) => exp.with_timezone(&Utc) < Utc::now(),
            Err(_) => false,
        }
    }
}

/// One row in the share audit trail. Captures enough state to
/// reconstruct a grant/revoke decision after the fact, including
/// who performed it and which capabilities were involved.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShareHistoryEntry {
    pub ts: String,
    /// `entity_id` of the caller that triggered the event. Empty
    /// for `cascade-revoke` events driven by target deletion when
    /// the underlying request has no resolved entity (root token).
    pub actor_entity_id: String,
    /// `"grant" | "revoke" | "cascade-revoke"`. `grant` covers both
    /// create and update (both go through `set_share`); distinguish
    /// the two by the presence of prior history for the same
    /// `(target, grantee)` pair.
    pub op: String,
    pub target_kind: String,
    pub target_path: String,
    pub grantee_entity_id: String,
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub expires_at: String,
}

pub struct ShareStore {
    primary_view: Arc<BarrierView>,
    by_grantee_view: Arc<BarrierView>,
    history_view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl ShareStore {
    pub async fn new(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };

        let primary_view = Arc::new(system_view.new_sub_view(SHARE_PRIMARY_SUB_PATH));
        let by_grantee_view = Arc::new(system_view.new_sub_view(SHARE_BY_GRANTEE_SUB_PATH));
        let history_view = Arc::new(system_view.new_sub_view(SHARE_HISTORY_SUB_PATH));

        Ok(Arc::new(Self {
            primary_view,
            by_grantee_view,
            history_view,
        }))
    }

    /// Canonicalize a share target's path. Uses the same rules as
    /// `OwnerStore::canonicalize_kv_path` for KV paths so the share on
    /// `secret/foo/bar` matches whether the grantee hits v1 or v2.
    /// Resource names are lowercased and must not contain `/`.
    pub fn canonicalize(kind: ShareTargetKind, raw: &str) -> Option<String> {
        match kind {
            ShareTargetKind::KvSecret => OwnerStore::canonicalize_kv_path(raw),
            ShareTargetKind::Resource => {
                let k = raw.trim().to_lowercase();
                if k.is_empty() || k.contains('/') {
                    None
                } else {
                    Some(k)
                }
            }
            ShareTargetKind::AssetGroup => {
                // Mirror ResourceGroupStore::sanitize_name: lowercase,
                // trim, reject empties and `/` or `..`.
                let k = raw.trim().to_lowercase();
                if k.is_empty() || k.contains('/') || k.contains("..") {
                    None
                } else {
                    Some(k)
                }
            }
            ShareTargetKind::File => {
                // File ids are server-assigned UUIDs; treat any
                // non-empty, slash-free string as canonical so operator
                // tooling that posts lower/upper-cased or dashless
                // forms still matches stored records consistently.
                let k = raw.trim().to_lowercase();
                if k.is_empty() || k.contains('/') {
                    None
                } else {
                    Some(k)
                }
            }
        }
    }

    /// Base64url(no-pad) of `<kind>|<canonical_path>`. Deterministic
    /// and reversible — audit tooling can decode for display.
    pub fn target_hash(kind: ShareTargetKind, canonical: &str) -> String {
        let raw = format!("{}|{}", kind.as_str(), canonical);
        URL_SAFE_NO_PAD.encode(raw.as_bytes())
    }

    fn primary_key(target_hash: &str, grantee: &str) -> String {
        format!("{target_hash}/{grantee}")
    }

    fn by_grantee_key(grantee: &str, target_hash: &str) -> String {
        format!("{grantee}/{target_hash}")
    }

    /// Upsert a share. Validates inputs, canonicalizes the target, and
    /// writes both the primary and by-grantee records. Capabilities
    /// are normalized (trimmed, lowercased, deduped, non-empty).
    pub async fn set_share(&self, mut share: SecretShare) -> Result<SecretShare, RvError> {
        let kind = ShareTargetKind::parse(&share.target_kind)
            .ok_or_else(|| bv_error_string!(format!("invalid share target_kind: {}", share.target_kind)))?;
        let canonical = Self::canonicalize(kind, &share.target_path)
            .ok_or_else(|| bv_error_string!("invalid share target_path"))?;
        let grantee = share.grantee_entity_id.trim().to_string();
        if grantee.is_empty() {
            return Err(bv_error_string!("share grantee_entity_id is required"));
        }
        share.target_kind = kind.as_str().to_string();
        share.target_path = canonical.clone();
        share.grantee_entity_id = grantee.clone();
        share.capabilities = normalize_capabilities(share.capabilities);
        if share.capabilities.is_empty() {
            return Err(bv_error_string!(
                "share must grant at least one capability (read, list, update, delete)"
            ));
        }
        if share.granted_at.is_empty() {
            share.granted_at = Utc::now().to_rfc3339();
        }

        let target_hash = Self::target_hash(kind, &canonical);
        let primary_key = Self::primary_key(&target_hash, &grantee);
        let value = serde_json::to_vec(&share)?;
        self.primary_view
            .put(&StorageEntry { key: primary_key, value })
            .await?;

        let pointer = ShareByGranteePointer {
            target_kind: share.target_kind.clone(),
            target_path: canonical.clone(),
        };
        let p_key = Self::by_grantee_key(&grantee, &target_hash);
        let p_value = serde_json::to_vec(&pointer)?;
        self.by_grantee_view
            .put(&StorageEntry { key: p_key, value: p_value })
            .await?;

        // Audit: append a history row for the grant. History failures
        // must not fail the write — the admin audit page is a
        // convenience, not a block on share operations.
        let hist = ShareHistoryEntry {
            ts: Utc::now().to_rfc3339(),
            actor_entity_id: share.granted_by_entity_id.clone(),
            op: "grant".to_string(),
            target_kind: share.target_kind.clone(),
            target_path: share.target_path.clone(),
            grantee_entity_id: share.grantee_entity_id.clone(),
            capabilities: share.capabilities.clone(),
            expires_at: share.expires_at.clone(),
        };
        let _ = self.append_history(hist).await;

        Ok(share)
    }

    pub async fn get_share(
        &self,
        kind: ShareTargetKind,
        target_path: &str,
        grantee: &str,
    ) -> Result<Option<SecretShare>, RvError> {
        let Some(canonical) = Self::canonicalize(kind, target_path) else {
            return Ok(None);
        };
        let grantee = grantee.trim();
        if grantee.is_empty() {
            return Ok(None);
        }
        let target_hash = Self::target_hash(kind, &canonical);
        let key = Self::primary_key(&target_hash, grantee);
        let Some(raw) = self.primary_view.get(&key).await? else {
            return Ok(None);
        };
        let share: SecretShare = serde_json::from_slice(&raw.value)?;
        Ok(Some(share))
    }

    /// Remove a single share. Removes both the primary record and the
    /// by-grantee pointer. Idempotent — missing records are not errors.
    pub async fn delete_share(
        &self,
        kind: ShareTargetKind,
        target_path: &str,
        grantee: &str,
    ) -> Result<(), RvError> {
        self.delete_share_audited(kind, target_path, grantee, "", "revoke").await
    }

    /// Same as `delete_share` but carries an actor `entity_id` (for
    /// audit logging) and lets the caller tag the event op — used by
    /// `cascade_delete_target` to distinguish explicit revokes from
    /// automatic cascade-revokes triggered by target deletion.
    pub async fn delete_share_audited(
        &self,
        kind: ShareTargetKind,
        target_path: &str,
        grantee: &str,
        actor_entity_id: &str,
        op: &str,
    ) -> Result<(), RvError> {
        let Some(canonical) = Self::canonicalize(kind, target_path) else {
            return Ok(());
        };
        let grantee = grantee.trim();
        if grantee.is_empty() {
            return Ok(());
        }
        let target_hash = Self::target_hash(kind, &canonical);

        // Snapshot the share before deletion so the audit row can
        // record which capabilities were revoked. A missing record
        // (already deleted) is not an error — we still drop the
        // by-grantee pointer and omit the audit entry.
        let pk = Self::primary_key(&target_hash, grantee);
        let prior: Option<SecretShare> = match self.primary_view.get(&pk).await? {
            Some(raw) => serde_json::from_slice(&raw.value).ok(),
            None => None,
        };

        self.primary_view.delete(&pk).await?;
        let bg = Self::by_grantee_key(grantee, &target_hash);
        self.by_grantee_view.delete(&bg).await?;

        if let Some(prior) = prior {
            let hist = ShareHistoryEntry {
                ts: Utc::now().to_rfc3339(),
                actor_entity_id: actor_entity_id.to_string(),
                op: op.to_string(),
                target_kind: prior.target_kind,
                target_path: prior.target_path,
                grantee_entity_id: prior.grantee_entity_id,
                capabilities: prior.capabilities,
                expires_at: prior.expires_at,
            };
            let _ = self.append_history(hist).await;
        }
        Ok(())
    }

    /// Return every share on `target`, newest first (by `granted_at`).
    /// Expired entries are still returned — callers decide whether to
    /// hide them. The evaluator skips expired shares at allow time.
    pub async fn list_shares_for_target(
        &self,
        kind: ShareTargetKind,
        target_path: &str,
    ) -> Result<Vec<SecretShare>, RvError> {
        let Some(canonical) = Self::canonicalize(kind, target_path) else {
            return Ok(Vec::new());
        };
        let target_hash = Self::target_hash(kind, &canonical);
        let prefix = format!("{target_hash}/");
        let keys = self.primary_view.list(&prefix).await?;
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            let full = format!("{prefix}{k}");
            if let Some(raw) = self.primary_view.get(&full).await? {
                if let Ok(share) = serde_json::from_slice::<SecretShare>(&raw.value) {
                    out.push(share);
                }
            }
        }
        out.sort_by(|a, b| b.granted_at.cmp(&a.granted_at));
        Ok(out)
    }

    /// Return every target shared with `grantee`. The pointer carries
    /// the kind+path; caller can load the full record via `get_share`.
    pub async fn list_shares_for_grantee(
        &self,
        grantee: &str,
    ) -> Result<Vec<ShareByGranteePointer>, RvError> {
        let grantee = grantee.trim();
        if grantee.is_empty() {
            return Ok(Vec::new());
        }
        let prefix = format!("{grantee}/");
        let keys = self.by_grantee_view.list(&prefix).await?;
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            let full = format!("{prefix}{k}");
            if let Some(raw) = self.by_grantee_view.get(&full).await? {
                if let Ok(ptr) = serde_json::from_slice::<ShareByGranteePointer>(&raw.value) {
                    out.push(ptr);
                }
            }
        }
        Ok(out)
    }

    /// Capabilities the grantee has on the target via any non-expired
    /// share. Used by the ACL evaluator to answer the `shared` scope
    /// check in a single lookup. Empty when nothing matches.
    pub async fn shared_capabilities(
        &self,
        kind: ShareTargetKind,
        target_path: &str,
        grantee: &str,
    ) -> Result<Vec<String>, RvError> {
        let Some(share) = self.get_share(kind, target_path, grantee).await? else {
            return Ok(Vec::new());
        };
        if share.is_expired() {
            return Ok(Vec::new());
        }
        Ok(share.capabilities.clone())
    }

    /// Drop every share on `target`. Called from `PolicyStore::post_route`
    /// on successful delete of a KV secret or a resource so dangling
    /// share rows do not outlive the target. Failures are logged by
    /// the caller; returning `Err` does not block the delete.
    pub async fn cascade_delete_target(
        &self,
        kind: ShareTargetKind,
        target_path: &str,
    ) -> Result<usize, RvError> {
        self.cascade_delete_target_audited(kind, target_path, "").await
    }

    /// Same as `cascade_delete_target` but carries the actor
    /// `entity_id` of the caller whose delete triggered the cascade.
    /// Each removed share is recorded as a `cascade-revoke` event in
    /// the audit trail.
    pub async fn cascade_delete_target_audited(
        &self,
        kind: ShareTargetKind,
        target_path: &str,
        actor_entity_id: &str,
    ) -> Result<usize, RvError> {
        let shares = self.list_shares_for_target(kind, target_path).await?;
        let count = shares.len();
        for s in shares {
            self.delete_share_audited(
                kind,
                &s.target_path,
                &s.grantee_entity_id,
                actor_entity_id,
                "cascade-revoke",
            )
            .await?;
        }
        Ok(count)
    }

    /// Append an audit entry to the share-history sub-view. Keyed by
    /// `<20-digit-nanos>` (from `hist_seq`) so `list_all_history`
    /// returns rows in chronological order with a plain sort.
    pub async fn append_history(&self, entry: ShareHistoryEntry) -> Result<(), RvError> {
        let key = hist_seq();
        let value = serde_json::to_vec(&entry)?;
        self.history_view.put(&StorageEntry { key, value }).await
    }

    /// Full share audit trail, newest-first. Consumed by the admin
    /// audit aggregator in the system backend.
    pub async fn list_all_history(&self) -> Result<Vec<ShareHistoryEntry>, RvError> {
        let mut keys = self.history_view.get_keys().await?;
        keys.sort();
        keys.reverse();
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            if let Some(raw) = self.history_view.get(&k).await? {
                if let Ok(e) = serde_json::from_slice::<ShareHistoryEntry>(&raw.value) {
                    out.push(e);
                }
            }
        }
        Ok(out)
    }
}

/// Monotonic-ish 20-digit zero-padded nanoseconds since UNIX epoch,
/// used as history keys so `get_keys` + sort yields chronological
/// order. Mirrors the helper in other history stores.
fn hist_seq() -> String {
    let n = Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_else(|| Utc::now().timestamp_millis() * 1_000_000);
    format!("{:020}", n.max(0) as u128)
}

/// Pointer record written under `sys/sharing/by-grantee/<grantee>/<target_hash>`.
/// Carries just enough to reload the primary record; kept separate from
/// `SecretShare` so listing "what is shared with me?" is a single
/// prefix scan without deserializing every full share.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShareByGranteePointer {
    pub target_kind: String,
    pub target_path: String,
}

/// Normalize a capabilities list: trim each entry, lowercase, drop
/// empties, dedup, reject anything outside the allowed subset. Order
/// is preserved on the first occurrence.
fn normalize_capabilities(caps: Vec<String>) -> Vec<String> {
    const ALLOWED: &[&str] = &["read", "list", "update", "delete", "create"];
    let mut out: Vec<String> = Vec::new();
    for c in caps {
        let c = c.trim().to_lowercase();
        if c.is_empty() || !ALLOWED.contains(&c.as_str()) {
            continue;
        }
        if !out.iter().any(|x| x == &c) {
            out.push(c);
        }
    }
    out
}
