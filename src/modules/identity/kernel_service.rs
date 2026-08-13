//! `IdentityModule` as the vault's [`IdentityService`].
//!
//! The engine-facing half of the identity module: five stores' worth of API
//! narrowed to the eight operations engines actually perform. Everything here
//! forwards; the moment a method does more than translate and delegate, the
//! abstraction has drifted and the logic belongs in a store.
//!
//! Two shapes recur and both are deliberate:
//!
//! * **`None` store is not an error.** The stores are created in
//!   `Module::init`, at unseal. A call that lands before that (or on a build
//!   with no identity module at all) reports "nothing found", the same answer
//!   the old `get_module(...).and_then(|m| m.entity_store())` chain produced.
//!   Read paths return empty; the two write paths that cannot be silently
//!   skipped say so in their own docs.
//! * **Ownership bookkeeping absorbs the namespace scoping.** Callers used to
//!   compute `OwnerStore::scope_target_name(name, ns)` themselves, which meant
//!   the file and resource engines both knew how owner records are keyed. The
//!   scoping now happens on this side of the boundary.

use std::sync::Arc;

use crate::{
    errors::RvError,
    kernel_api::identity::{
        AliasRef, EntityProfile, GroupKind as ApiGroupKind, IdentityService, ObjectKind,
        UserAuditRecord,
    },
};

use super::{
    entity_store::Entity, group_store::GroupKind, owner_store::OwnerStore,
    share_store::ShareTargetKind, user_audit_store::UserAuditEntry, IdentityModule,
};

impl From<ApiGroupKind> for GroupKind {
    fn from(k: ApiGroupKind) -> Self {
        match k {
            ApiGroupKind::User => GroupKind::User,
            ApiGroupKind::App => GroupKind::App,
        }
    }
}

impl From<GroupKind> for ApiGroupKind {
    fn from(k: GroupKind) -> Self {
        match k {
            GroupKind::User => ApiGroupKind::User,
            GroupKind::App => ApiGroupKind::App,
        }
    }
}

impl From<Entity> for EntityProfile {
    fn from(e: Entity) -> Self {
        EntityProfile {
            id: e.id,
            primary_name: e.primary_name,
            aliases: e
                .aliases
                .into_iter()
                .map(|a| AliasRef { mount: a.mount, name: a.name })
                .collect(),
        }
    }
}

/// The share-store target kind for an [`ObjectKind`].
fn share_kind(kind: ObjectKind) -> ShareTargetKind {
    match kind {
        ObjectKind::File => ShareTargetKind::File,
        ObjectKind::Resource => ShareTargetKind::Resource,
    }
}

#[maybe_async::maybe_async]
impl IdentityService for IdentityModule {
    async fn entity_id_for_alias(
        &self,
        mount: &str,
        name: &str,
        ns_path: &str,
    ) -> Result<Option<String>, RvError> {
        let Some(store) = self.entity_store() else {
            return Ok(None);
        };
        Ok(store.get_by_alias_ns(mount, name, ns_path).await?.map(|e| e.id))
    }

    async fn ensure_entity_id(
        &self,
        mount: &str,
        name: &str,
        ns_path: &str,
    ) -> Result<String, RvError> {
        let store = self
            .entity_store()
            .ok_or_else(|| crate::bv_error_string!("identity entity store not initialised"))?;
        Ok(store.get_or_create_entity_ns(mount, name, ns_path).await?.id)
    }

    async fn forget_alias(&self, mount: &str, name: &str) -> Result<(), RvError> {
        let Some(store) = self.entity_store() else {
            return Ok(());
        };
        store.forget_alias(mount, name).await
    }

    async fn entity_profile(&self, entity_id: &str) -> Result<Option<EntityProfile>, RvError> {
        let Some(store) = self.entity_store() else {
            return Ok(None);
        };
        Ok(store.get_entity(entity_id).await?.map(EntityProfile::from))
    }

    async fn expand_group_policies(
        &self,
        kind: ApiGroupKind,
        member: &str,
        direct: &[String],
        ns_path: &str,
    ) -> Result<Vec<String>, RvError> {
        let Some(store) = self.group_store() else {
            // No group store: the caller's direct policies are the whole
            // answer. Group membership can only ever add, so this is the
            // fail-closed direction.
            return Ok(direct.to_vec());
        };
        store.expand_policies_ns(kind.into(), member, direct, ns_path).await
    }

    async fn group_members(
        &self,
        kind: ApiGroupKind,
        name: &str,
        ns_path: &str,
    ) -> Result<Vec<String>, RvError> {
        let Some(store) = self.group_store() else {
            return Ok(Vec::new());
        };
        Ok(store
            .get_group_ns(kind.into(), name, ns_path)
            .await?
            .map(|g| g.members)
            .unwrap_or_default())
    }

    async fn list_entity_ids(&self, ns_path: &str) -> Result<Vec<String>, RvError> {
        let Some(store) = self.entity_store() else {
            return Ok(Vec::new());
        };
        store.list_entities_ns(ns_path).await
    }

    async fn record_user_audit(&self, entry: UserAuditRecord) -> Result<(), RvError> {
        let Some(store) = self.user_audit_store() else {
            return Ok(());
        };
        store
            .append(UserAuditEntry {
                ts: entry.ts,
                actor_entity_id: entry.actor_entity_id,
                op: entry.op,
                mount: entry.mount,
                target: entry.target,
                details: entry.details,
            })
            .await
    }

    async fn record_owner_if_absent(
        &self,
        kind: ObjectKind,
        name: &str,
        ns_path: Option<&str>,
        actor: &str,
    ) -> Result<(), RvError> {
        if actor.is_empty() {
            return Ok(());
        }
        let Some(store) = self.owner_store() else {
            return Ok(());
        };
        // Namespace-scope the key so an object created inside a namespace
        // neither stamps nor collides with a root owner record — this must
        // match what `post_route` and the ACL resolution path look up.
        let Some(key) = OwnerStore::scope_target_name(name, ns_path) else {
            return Ok(());
        };
        match kind {
            ObjectKind::File => store.record_file_owner_if_absent(&key, actor).await,
            ObjectKind::Resource => store.record_resource_owner_if_absent(&key, actor).await,
        }
    }

    async fn rename_object(
        &self,
        kind: ObjectKind,
        old_name: &str,
        new_name: &str,
        ns_path: Option<&str>,
        actor: &str,
    ) {
        // Owner and share records are keyed `<ns>/<name>` inside a namespace,
        // so a rename must move the namespace's own records and never touch a
        // root object that happens to share the name.
        let old_key =
            OwnerStore::scope_target_name(old_name, ns_path).unwrap_or_else(|| old_name.to_string());
        let new_key =
            OwnerStore::scope_target_name(new_name, ns_path).unwrap_or_else(|| new_name.to_string());

        // The two stores are moved independently: they are created together at
        // unseal, but one of them being absent must not silently skip the
        // other's records.
        if let Some(share_store) = self.share_store() {
            if let Err(e) =
                share_store.rename_target(share_kind(kind), &old_key, &new_key, actor).await
            {
                log::warn!("share rename failed for {kind:?} '{old_name}' -> '{new_name}': {e}");
            }
        }

        let Some(owner_store) = self.owner_store() else {
            return;
        };
        let existing = match kind {
            ObjectKind::File => owner_store.get_file_owner(&old_key).await,
            ObjectKind::Resource => owner_store.get_resource_owner(&old_key).await,
        };
        match existing {
            Ok(Some(rec)) if !rec.entity_id.is_empty() => {
                let moved = match kind {
                    ObjectKind::File => owner_store.set_file_owner(&new_key, &rec.entity_id).await,
                    ObjectKind::Resource => {
                        owner_store.set_resource_owner(&new_key, &rec.entity_id).await
                    }
                };
                match moved {
                    Ok(()) => {
                        // Only forget the old record once the new one is
                        // durable: the reverse order can leave an object with
                        // no owner at all, which silently widens access.
                        let _ = match kind {
                            ObjectKind::File => owner_store.forget_file_owner(&old_key).await,
                            ObjectKind::Resource => {
                                owner_store.forget_resource_owner(&old_key).await
                            }
                        };
                    }
                    Err(e) => log::warn!(
                        "owner rename failed for {kind:?} '{old_name}' -> '{new_name}': {e}"
                    ),
                }
            }
            Ok(_) => {}
            Err(e) => {
                log::warn!("owner lookup failed for {kind:?} '{old_name}' during rename: {e}")
            }
        }
    }
}

/// Publish the identity module as the vault's identity service.
pub fn register(module: Arc<IdentityModule>, services: &crate::kernel_api::KernelServices) {
    services.set_identity(module);
}
