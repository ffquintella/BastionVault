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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OwnerRecord {
    pub entity_id: String,
    pub created_at: String,
}

pub struct OwnerStore {
    kv_view: Arc<BarrierView>,
    resource_view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl OwnerStore {
    pub async fn new(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };

        let kv_view = Arc::new(system_view.new_sub_view(KV_OWNER_SUB_PATH));
        let resource_view = Arc::new(system_view.new_sub_view(RESOURCE_OWNER_SUB_PATH));

        Ok(Arc::new(Self { kv_view, resource_view }))
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
        if self.kv_view.get(&key).await?.is_some() {
            return Ok(());
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

    pub async fn get_resource_owner(
        &self,
        resource: &str,
    ) -> Result<Option<OwnerRecord>, RvError> {
        let key = resource.trim().to_lowercase();
        if key.is_empty() || key.contains('/') {
            return Ok(None);
        }
        let Some(raw) = self.resource_view.get(&key).await? else {
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
        let key = resource.trim().to_lowercase();
        if key.is_empty() || key.contains('/') {
            return Ok(());
        }
        if self.resource_view.get(&key).await?.is_some() {
            return Ok(());
        }
        let rec = OwnerRecord {
            entity_id: entity_id.to_string(),
            created_at: Utc::now().to_rfc3339(),
        };
        let value = serde_json::to_vec(&rec)?;
        self.resource_view.put(&StorageEntry { key, value }).await
    }

    /// Unconditional overwrite of a resource owner record. Mirror of
    /// `set_kv_owner`.
    pub async fn set_resource_owner(
        &self,
        resource: &str,
        entity_id: &str,
    ) -> Result<(), RvError> {
        let key = resource.trim().to_lowercase();
        if key.is_empty() || key.contains('/') {
            return Err(crate::bv_error_string!("invalid resource name"));
        }
        let entity_id = entity_id.trim();
        if entity_id.is_empty() {
            return Err(crate::bv_error_string!("entity_id is required"));
        }
        let rec = OwnerRecord {
            entity_id: entity_id.to_string(),
            created_at: Utc::now().to_rfc3339(),
        };
        let value = serde_json::to_vec(&rec)?;
        self.resource_view.put(&StorageEntry { key, value }).await
    }

    pub async fn forget_resource_owner(&self, resource: &str) -> Result<(), RvError> {
        let key = resource.trim().to_lowercase();
        if key.is_empty() || key.contains('/') {
            return Ok(());
        }
        self.resource_view.delete(&key).await
    }
}
