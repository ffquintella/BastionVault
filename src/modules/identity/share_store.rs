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
}

impl ShareTargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ShareTargetKind::KvSecret => "kv-secret",
            ShareTargetKind::Resource => "resource",
            ShareTargetKind::AssetGroup => "asset-group",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "kv-secret" | "kv" => Some(ShareTargetKind::KvSecret),
            "resource" => Some(ShareTargetKind::Resource),
            "asset-group" | "group" => Some(ShareTargetKind::AssetGroup),
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

pub struct ShareStore {
    primary_view: Arc<BarrierView>,
    by_grantee_view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl ShareStore {
    pub async fn new(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };

        let primary_view = Arc::new(system_view.new_sub_view(SHARE_PRIMARY_SUB_PATH));
        let by_grantee_view = Arc::new(system_view.new_sub_view(SHARE_BY_GRANTEE_SUB_PATH));

        Ok(Arc::new(Self { primary_view, by_grantee_view }))
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
        let Some(canonical) = Self::canonicalize(kind, target_path) else {
            return Ok(());
        };
        let grantee = grantee.trim();
        if grantee.is_empty() {
            return Ok(());
        }
        let target_hash = Self::target_hash(kind, &canonical);
        let pk = Self::primary_key(&target_hash, grantee);
        self.primary_view.delete(&pk).await?;
        let bg = Self::by_grantee_key(grantee, &target_hash);
        self.by_grantee_view.delete(&bg).await?;
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
        let shares = self.list_shares_for_target(kind, target_path).await?;
        let count = shares.len();
        for s in shares {
            self.delete_share(kind, &s.target_path, &s.grantee_entity_id).await?;
        }
        Ok(count)
    }
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
