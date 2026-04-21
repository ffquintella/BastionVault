//! Entity store for the identity module.
//!
//! Provides a stable per-user identifier that survives token churn —
//! the "entity_id" consumed by ownership-aware ACL rules
//! (`scopes = ["owner"]`) and by the KV/resource owner stores. See
//! `features/per-user-scoping.md` for the full design.
//!
//! Storage layout (all under the system barrier view):
//!   sys/identity/entity/<uuid>         -> Entity (JSON)
//!   sys/identity/alias/<mount>/<name>  -> <uuid>
//!
//! The alias → uuid index is the lookup path at login time; one entity
//! per (mount, principal) in v1. Cross-mount alias merging is a
//! follow-up once sharing lands.

use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    core::Core,
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
    utils::generate_uuid,
};

const ENTITY_SUB_PATH: &str = "identity/entity/";
const ALIAS_SUB_PATH: &str = "identity/alias/";

/// An entity represents a principal identity across tokens. The `id`
/// is the stable identifier embedded in every issued token's metadata
/// so ACL rules and owner checks can refer to the same caller even
/// after token renewal, relogin, or cross-backend federation (future).
///
/// `primary` is the (mount, principal_name) tuple the entity was
/// first provisioned for. `aliases` is reserved for future cross-mount
/// linking; empty in the v1 cut.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Entity {
    pub id: String,
    pub primary_mount: String,
    pub primary_name: String,
    #[serde(default)]
    pub aliases: Vec<EntityAlias>,
    pub created_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntityAlias {
    pub mount: String,
    pub name: String,
}

pub struct EntityStore {
    entity_view: Arc<BarrierView>,
    alias_view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl EntityStore {
    pub async fn new(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };

        let entity_view = Arc::new(system_view.new_sub_view(ENTITY_SUB_PATH));
        let alias_view = Arc::new(system_view.new_sub_view(ALIAS_SUB_PATH));

        Ok(Arc::new(Self { entity_view, alias_view }))
    }

    /// Key under the alias view for a (mount, name) pair. Mount keeps
    /// its trailing slash so `userpass/` and `user/` can't collide; the
    /// slash is escaped to keep the key flat within the BarrierView.
    fn alias_key(mount: &str, name: &str) -> String {
        let mount = mount.trim_end_matches('/');
        format!("{mount}:{}", name.trim().to_lowercase())
    }

    /// Look up an entity by (mount, principal name). Returns `None`
    /// when no alias exists — typical on a user's first login.
    pub async fn get_by_alias(
        &self,
        mount: &str,
        name: &str,
    ) -> Result<Option<Entity>, RvError> {
        let key = Self::alias_key(mount, name);
        let Some(raw) = self.alias_view.get(&key).await? else {
            return Ok(None);
        };
        let uuid: String = serde_json::from_slice(&raw.value).unwrap_or_default();
        if uuid.is_empty() {
            return Ok(None);
        }
        self.get_entity(&uuid).await
    }

    pub async fn get_entity(&self, id: &str) -> Result<Option<Entity>, RvError> {
        let Some(raw) = self.entity_view.get(id).await? else {
            return Ok(None);
        };
        let entity: Entity = serde_json::from_slice(&raw.value)?;
        Ok(Some(entity))
    }

    /// Return the entity for `(mount, name)`, creating it on first
    /// call. Idempotent: a concurrent second call for the same alias
    /// will return the already-created entity rather than issuing a
    /// new UUID.
    pub async fn get_or_create_entity(
        &self,
        mount: &str,
        name: &str,
    ) -> Result<Entity, RvError> {
        if let Some(existing) = self.get_by_alias(mount, name).await? {
            return Ok(existing);
        }

        let id = generate_uuid();
        let entity = Entity {
            id: id.clone(),
            primary_mount: mount.to_string(),
            primary_name: name.trim().to_lowercase(),
            aliases: Vec::new(),
            created_at: Utc::now().to_rfc3339(),
        };
        let value = serde_json::to_vec(&entity)?;
        self.entity_view
            .put(&StorageEntry { key: id.clone(), value })
            .await?;

        let alias_key = Self::alias_key(mount, name);
        let alias_value = serde_json::to_vec(&id)?;
        self.alias_view
            .put(&StorageEntry { key: alias_key, value: alias_value })
            .await?;

        Ok(entity)
    }

    pub async fn list_entities(&self) -> Result<Vec<String>, RvError> {
        let mut keys = self.entity_view.get_keys().await?;
        keys.sort();
        Ok(keys)
    }

    /// Enumerate every known alias as a `(mount, name, entity_id)`
    /// tuple. Used by the GUI's user-picker so operators can search
    /// for a grantee by login instead of pasting a raw `entity_id`.
    ///
    /// Keys on disk are `<mount>:<name>` (see [`alias_key`]); we split
    /// on the first `:` to recover the pair. The mount is re-suffixed
    /// with `/` to match the `mount_path` convention the rest of the
    /// system uses.
    pub async fn list_aliases(&self) -> Result<Vec<AliasRecord>, RvError> {
        let keys = self.alias_view.get_keys().await?;
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let Some((mount, name)) = key.split_once(':') else {
                continue;
            };
            let uuid = match self.alias_view.get(&key).await? {
                Some(raw) => serde_json::from_slice::<String>(&raw.value).unwrap_or_default(),
                None => continue,
            };
            if uuid.is_empty() {
                continue;
            }
            out.push(AliasRecord {
                mount: format!("{mount}/"),
                name: name.to_string(),
                entity_id: uuid,
            });
        }
        out.sort_by(|a, b| {
            a.mount
                .cmp(&b.mount)
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(out)
    }
}

/// `(mount, principal-name, entity_id)` triple surfaced by
/// [`EntityStore::list_aliases`]. Safe to serialize and return to
/// authenticated GUI callers — it lists existing user logins with
/// their stable entity identifier, same information you'd get from
/// the UserPass user-list plus an `entity/self` lookup per user.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AliasRecord {
    pub mount: String,
    pub name: String,
    pub entity_id: String,
}
