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

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
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
// Multi-tenancy: per-namespace alias keyspace. Entity *records* stay in the
// flat `identity/entity/<uuid>` keyspace (UUIDs are globally unique, so the many
// `get_entity(id)` callers need no namespace context); only the alias index is
// partitioned so the same external principal (`userpass/alice`) maps to a
// *different* entity in each namespace. Root keeps the legacy alias keyspace.
//   identity-ns/<b64url(ns_path)>/alias/<mount>/<name> -> <uuid>
const IDENTITY_NS_SUB_PATH: &str = "identity-ns/";

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
    /// Multi-tenancy: the namespace this entity belongs to (`""` = root).
    /// An entity in one namespace is distinct from one in another even when
    /// both alias the same external principal. Legacy records read as root.
    #[serde(default)]
    pub namespace: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntityAlias {
    pub mount: String,
    pub name: String,
}

pub struct EntityStore {
    entity_view: Arc<BarrierView>,
    alias_view: Arc<BarrierView>,
    /// Retained so per-namespace alias sub-views can be derived on demand.
    system_view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl EntityStore {
    pub async fn new(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };

        let entity_view = Arc::new(system_view.new_sub_view(ENTITY_SUB_PATH));
        let alias_view = Arc::new(system_view.new_sub_view(ALIAS_SUB_PATH));

        Ok(Arc::new(Self { entity_view, alias_view, system_view }))
    }

    /// Barrier sub-view holding a namespace's alias index. Root returns the
    /// legacy alias view; a non-root namespace gets its own keyspace.
    fn alias_view_for(&self, ns_path: &str) -> Arc<BarrierView> {
        if ns_path.is_empty() {
            return self.alias_view.clone();
        }
        let b64 = URL_SAFE_NO_PAD.encode(ns_path.as_bytes());
        Arc::new(
            self.system_view
                .new_sub_view(&format!("{IDENTITY_NS_SUB_PATH}{b64}/alias/")),
        )
    }

    /// Storage key under the alias view for a `(mount, name)` pair.
    /// Uses `/` as the separator so the underlying physical backend
    /// can round-trip it on every OS. An earlier revision used `:`
    /// which — because NTFS treats `:` as an alternate-data-stream
    /// marker — silently broke the key layout on Windows file
    /// backends: writes succeeded but `read_dir` only returned the
    /// pre-`:` prefix, so `list_aliases` saw zero entries.
    ///
    /// The mount's trailing `/` is dropped so `userpass/` and
    /// `userpass` map to the same storage subtree.
    fn alias_key(mount: &str, name: &str) -> String {
        let mount = mount.trim_end_matches('/');
        format!("{mount}/{}", name.trim().to_lowercase())
    }

    /// Look up an entity by (mount, principal name). Returns `None`
    /// when no alias exists — typical on a user's first login.
    pub async fn get_by_alias(
        &self,
        mount: &str,
        name: &str,
    ) -> Result<Option<Entity>, RvError> {
        self.get_by_alias_ns(mount, name, "").await
    }

    /// Namespace-scoped alias lookup. Root delegates to the legacy keyspace.
    pub async fn get_by_alias_ns(
        &self,
        mount: &str,
        name: &str,
        ns_path: &str,
    ) -> Result<Option<Entity>, RvError> {
        let key = Self::alias_key(mount, name);
        let Some(raw) = self.alias_view_for(ns_path).get(&key).await? else {
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
        self.get_or_create_entity_ns(mount, name, "").await
    }

    /// Namespace-scoped get-or-create. The alias lives in the namespace's own
    /// keyspace and the new entity record is tagged with `ns_path`, so the same
    /// external principal resolves to a distinct entity per namespace. Root
    /// (`ns_path == ""`) is byte-for-byte the legacy behaviour.
    pub async fn get_or_create_entity_ns(
        &self,
        mount: &str,
        name: &str,
        ns_path: &str,
    ) -> Result<Entity, RvError> {
        if let Some(existing) = self.get_by_alias_ns(mount, name, ns_path).await? {
            return Ok(existing);
        }

        let id = generate_uuid();
        let entity = Entity {
            id: id.clone(),
            primary_mount: mount.to_string(),
            primary_name: name.trim().to_lowercase(),
            aliases: Vec::new(),
            created_at: Utc::now().to_rfc3339(),
            namespace: ns_path.to_string(),
        };
        let value = serde_json::to_vec(&entity)?;
        self.entity_view
            .put(&StorageEntry { key: id.clone(), value })
            .await?;

        let alias_key = Self::alias_key(mount, name);
        let alias_value = serde_json::to_vec(&id)?;
        self.alias_view_for(ns_path)
            .put(&StorageEntry { key: alias_key, value: alias_value })
            .await?;

        Ok(entity)
    }

    /// Remove the `(mount, name)` → `entity_id` lookup entry. The
    /// entity record itself stays — share records and ownership
    /// data still reference it, so wiping it would vaporise audit
    /// trails. Callers use this when deleting the underlying
    /// principal (userpass user, AppRole role) so the alias
    /// disappears from the GUI user-picker immediately.
    ///
    /// Idempotent: missing keys are not errors.
    pub async fn forget_alias(&self, mount: &str, name: &str) -> Result<(), RvError> {
        self.forget_alias_ns(mount, name, "").await
    }

    /// Namespace-scoped alias removal.
    pub async fn forget_alias_ns(&self, mount: &str, name: &str, ns_path: &str) -> Result<(), RvError> {
        let key = Self::alias_key(mount, name);
        self.alias_view_for(ns_path).delete(&key).await
    }

    pub async fn list_entities(&self) -> Result<Vec<String>, RvError> {
        let mut keys = self.entity_view.get_keys().await?;
        keys.sort();
        Ok(keys)
    }

    /// Entity UUIDs belonging to `ns_path` (`""` = root). Filters the flat
    /// entity keyspace by each record's `namespace` tag.
    pub async fn list_entities_ns(&self, ns_path: &str) -> Result<Vec<String>, RvError> {
        let keys = self.entity_view.get_keys().await?;
        let mut out = Vec::new();
        for id in keys {
            if let Some(e) = self.get_entity(&id).await? {
                if e.namespace == ns_path {
                    out.push(id);
                }
            }
        }
        out.sort();
        Ok(out)
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
        self.list_aliases_ns("").await
    }

    /// Namespace-scoped alias enumeration for the GUI user-picker.
    pub async fn list_aliases_ns(&self, ns_path: &str) -> Result<Vec<AliasRecord>, RvError> {
        let view = self.alias_view_for(ns_path);
        let keys = view.get_keys().await?;
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            // Keys are stored as `<mount>/<name>`. `get_keys` returns
            // the recursively-walked leaf paths, so `key` already
            // contains the full `<mount>/<name>` form.
            let Some((mount, name)) = key.split_once('/') else {
                continue;
            };
            let uuid = match view.get(&key).await? {
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
