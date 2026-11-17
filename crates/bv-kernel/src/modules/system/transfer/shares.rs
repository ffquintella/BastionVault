//! Which shares of a transferred item can be re-created in the destination.
//!
//! Implements "Share validation" in `features/cross-namespace-copy-move.md`.
//! The planner only reads the entity and group stores; the caller writes
//! [`SharePlan::keep`] and reports [`SharePlan::dropped`].

use serde::Serialize;

use crate::{
    errors::RvError,
    kernel_api::namespace::normalize_path,
    modules::identity::{
        entity_store::grantee_namespaces, EntityStore, GroupKind, GroupStore, SecretShare, ShareGranteeKind,
    },
};

/// The entity grantee does not exist or is not usable in the destination.
pub const CODE_GRANTEE_NOT_IN_DESTINATION: &str = "grantee-not-in-destination";
/// No group of the grantee's name and kind exists in the destination.
pub const CODE_GROUP_NOT_IN_DESTINATION: &str = "group-not-in-destination";
/// The caller may not grant shares in the destination, so none is written.
pub const CODE_CANNOT_GRANT: &str = "cannot-grant";
/// The share had already expired; an inert grant is not re-created.
pub const CODE_SHARE_EXPIRED: &str = "share-expired";
/// The record's `grantee_kind` is none the share store writes.
pub const CODE_UNKNOWN_GRANTEE_KIND: &str = "unknown-grantee-kind";

/// One share left behind. `subject` is the grantee (entity id or group name);
/// `message` names only the grantee and the capability names, never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShareWarning {
    pub code: String,
    pub subject: String,
    pub message: String,
}

/// Shares to re-create unchanged (the caller re-keys them to the destination)
/// and one warning per share left behind, both in the source order.
#[derive(Debug, Clone, Default)]
pub struct SharePlan {
    pub keep: Vec<SecretShare>,
    pub dropped: Vec<ShareWarning>,
}

/// Split `source` into the shares the destination namespace can carry and the
/// ones it cannot. `dest_ns` is a namespace path (`""` = root). Never writes;
/// a storage error is returned rather than read as "grantee missing".
#[maybe_async::maybe_async]
pub async fn plan_shares(
    source: Vec<SecretShare>,
    dest_ns: &str,
    caller_may_grant: bool,
    entities: &EntityStore,
    groups: &GroupStore,
) -> Result<SharePlan, RvError> {
    let dest = normalize_path(dest_ns)?;
    let mut plan = SharePlan::default();
    // Without the grant right nothing is looked up: the warnings must not tell
    // such a caller which grantees exist in the destination.
    if !caller_may_grant {
        let reason = "the caller may not grant shares in the destination namespace";
        plan.dropped = source.iter().map(|share| warning(CODE_CANNOT_GRANT, share, reason)).collect();
        return Ok(plan);
    }

    let mut user_groups: Option<Vec<String>> = None;
    let mut app_groups: Option<Vec<String>> = None;
    for share in source {
        let grantee = share.grantee_entity_id.trim();
        let dropped = if share.is_expired() {
            Some(warning(CODE_SHARE_EXPIRED, &share, "it has expired"))
        } else {
            match ShareGranteeKind::parse(&share.grantee_kind) {
                None => Some(warning(CODE_UNKNOWN_GRANTEE_KIND, &share, "its grantee kind is not recognised")),
                Some(ShareGranteeKind::Entity) => (!entity_usable_in(entities, grantee, &dest).await?).then(|| {
                    let reason = "the entity is not usable in the destination namespace";
                    warning(CODE_GRANTEE_NOT_IN_DESTINATION, &share, reason)
                }),
                Some(kind @ (ShareGranteeKind::GroupUser | ShareGranteeKind::GroupApp)) => {
                    let (group_kind, cache) = if kind == ShareGranteeKind::GroupApp {
                        (GroupKind::App, &mut app_groups)
                    } else {
                        (GroupKind::User, &mut user_groups)
                    };
                    if cache.is_none() {
                        *cache = Some(groups.list_groups_ns(group_kind, &dest).await?);
                    }
                    // Group names are stored lower-cased (`GroupStore::sanitize_name`).
                    let wanted = grantee.to_lowercase();
                    let exists = cache.as_ref().is_some_and(|names| names.contains(&wanted));
                    (!exists).then(|| {
                        let reason = "no such group exists in the destination namespace";
                        warning(CODE_GROUP_NOT_IN_DESTINATION, &share, reason)
                    })
                }
            }
        };
        match dropped {
            Some(w) => plan.dropped.push(w),
            None => plan.keep.push(share),
        }
    }
    Ok(plan)
}

/// Whether entity `id` exists and the grantee picker would offer it in `dest`:
/// its namespace is one [`grantee_namespaces`] lists for `dest`.
#[maybe_async::maybe_async]
async fn entity_usable_in(entities: &EntityStore, id: &str, dest: &str) -> Result<bool, RvError> {
    if id.is_empty() {
        return Ok(false);
    }
    let entity = match entities.get_entity(id).await {
        Ok(found) => found,
        // An id that is not a valid storage key (`..`, leading `/`) names no entity.
        Err(RvError::ErrBarrierKeySanityCheckFailed) => None,
        Err(e) => return Err(e),
    };
    let visible = grantee_namespaces(dest);
    Ok(entity.is_some_and(|e| visible.contains(&e.namespace.trim().trim_matches('/'))))
}

/// The warning for one share left behind: the grantee, its capability names
/// and `reason`, nothing read from the target.
fn warning(code: &str, share: &SecretShare, reason: &str) -> ShareWarning {
    let subject = share.grantee_entity_id.trim().to_string();
    let grantee = match ShareGranteeKind::parse(&share.grantee_kind) {
        Some(ShareGranteeKind::Entity) => format!("entity {subject}"),
        Some(ShareGranteeKind::GroupUser) => format!("user group {subject}"),
        Some(ShareGranteeKind::GroupApp) => format!("app group {subject}"),
        None => format!("grantee {subject}"),
    };
    let message = format!("share for {grantee} ({}) not re-created: {reason}", share.capabilities.join(", "));
    ShareWarning { code: code.to_string(), subject, message }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::Value;

    use super::*;
    use crate::{kernel_api::VaultCtx, modules::identity::GroupEntry, test_utils::new_unseal_test_bastion_vault};

    const FUTURE: &str = "2999-01-01T00:00:00Z";
    const PAST: &str = "2000-01-01T00:00:00Z";

    #[maybe_async::maybe_async]
    async fn stores(core: &dyn VaultCtx) -> (Arc<EntityStore>, Arc<GroupStore>) {
        (EntityStore::new(core).await.unwrap(), GroupStore::new(core).await.unwrap())
    }

    #[maybe_async::maybe_async]
    async fn entity_in(entities: &EntityStore, name: &str, ns: &str) -> String {
        entities.get_or_create_entity_ns("userpass/", name, ns).await.unwrap().id
    }

    #[maybe_async::maybe_async]
    async fn group_in(groups: &GroupStore, kind: GroupKind, name: &str, ns: &str) {
        let entry = GroupEntry { name: name.to_string(), ..Default::default() };
        groups.set_group_ns(kind, entry, ns).await.unwrap();
    }

    fn share(kind: ShareGranteeKind, grantee: &str, caps: &[&str]) -> SecretShare {
        SecretShare {
            target_kind: "resource".to_string(),
            target_path: "src/db1".to_string(),
            grantee_kind: kind.as_str().to_string(),
            grantee_entity_id: grantee.to_string(),
            granted_by_entity_id: "owner-entity".to_string(),
            capabilities: caps.iter().map(|c| c.to_string()).collect(),
            granted_at: "2026-11-01T00:00:00Z".to_string(),
            expires_at: String::new(),
        }
    }

    fn json(shares: &[SecretShare]) -> Vec<Value> {
        shares.iter().map(|s| serde_json::to_value(s).unwrap()).collect()
    }

    fn codes(plan: &SharePlan) -> Vec<(&str, &str)> {
        plan.dropped.iter().map(|w| (w.code.as_str(), w.subject.as_str())).collect()
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn entity_in_destination_is_kept() {
        let (_bv, core, _root) = new_unseal_test_bastion_vault("transfer_shares_entity_in_destination").await;
        let (entities, groups) = stores(&core).await;
        let alice = entity_in(&entities, "alice", "dst").await;
        let source = vec![share(ShareGranteeKind::Entity, &alice, &["read"])];

        let plan = plan_shares(source.clone(), "dst", true, &entities, &groups).await.unwrap();
        assert_eq!(json(&plan.keep), json(&source));
        assert!(plan.dropped.is_empty(), "{:?}", plan.dropped);

        // The destination path is normalized as every namespace path is.
        let plan = plan_shares(source.clone(), "/dst/", true, &entities, &groups).await.unwrap();
        assert_eq!(plan.keep.len(), 1);
        assert!(plan_shares(source, "dst/../x", true, &entities, &groups).await.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn entity_from_root_is_kept_for_namespaced_destination() {
        let (_bv, core, _root) = new_unseal_test_bastion_vault("transfer_shares_entity_from_root").await;
        let (entities, groups) = stores(&core).await;
        let bob = entity_in(&entities, "bob", "").await;
        let source = vec![share(ShareGranteeKind::Entity, &bob, &["read", "list"])];

        for dest in ["dst", "dst/child", ""] {
            let plan = plan_shares(source.clone(), dest, true, &entities, &groups).await.unwrap();
            assert_eq!(json(&plan.keep), json(&source), "{dest:?}");
            assert!(plan.dropped.is_empty(), "{dest:?}: {:?}", plan.dropped);
        }
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn entity_from_sibling_namespace_is_dropped() {
        let (_bv, core, _root) = new_unseal_test_bastion_vault("transfer_shares_entity_from_sibling").await;
        let (entities, groups) = stores(&core).await;
        let carol = entity_in(&entities, "carol", "sib").await;
        let parent = entity_in(&entities, "dora", "dst").await;
        let source = vec![
            share(ShareGranteeKind::Entity, &carol, &["read", "connect"]),
            share(ShareGranteeKind::Entity, "no-such-entity", &["read"]),
            share(ShareGranteeKind::Entity, "../escape", &["read"]),
            share(ShareGranteeKind::Entity, "", &["read"]),
        ];

        let plan = plan_shares(source, "dst", true, &entities, &groups).await.unwrap();
        assert!(plan.keep.is_empty(), "{:?}", plan.keep);
        let want = CODE_GRANTEE_NOT_IN_DESTINATION;
        assert_eq!(codes(&plan), [(want, carol.as_str()), (want, "no-such-entity"), (want, "../escape"), (want, "")]);
        let message = &plan.dropped[0].message;
        assert!(message.contains(&carol) && message.contains("read, connect"), "{message}");

        // The picker shows a namespace its own aliases and root's only: an
        // intermediate ancestor is as isolated as a sibling, and so is a
        // namespace's entity at root.
        let source = vec![share(ShareGranteeKind::Entity, &parent, &["read"])];
        for dest in ["dst/child", ""] {
            let plan = plan_shares(source.clone(), dest, true, &entities, &groups).await.unwrap();
            assert!(plan.keep.is_empty(), "{dest:?}");
            assert_eq!(codes(&plan), [(want, parent.as_str())], "{dest:?}");
        }
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn group_missing_in_destination_is_dropped() {
        let (_bv, core, _root) = new_unseal_test_bastion_vault("transfer_shares_group_missing").await;
        let (entities, groups) = stores(&core).await;
        group_in(&groups, GroupKind::User, "eng", "dst").await;
        group_in(&groups, GroupKind::App, "ci", "dst").await;
        let source = vec![
            share(ShareGranteeKind::GroupUser, "eng", &["read"]),
            share(ShareGranteeKind::GroupUser, "Eng", &["list"]),
            share(ShareGranteeKind::GroupApp, "ci", &["read"]),
            share(ShareGranteeKind::GroupUser, "ops", &["read", "update"]),
            // A user group does not satisfy an app-group share of its name.
            share(ShareGranteeKind::GroupApp, "eng", &["read"]),
        ];

        let plan = plan_shares(source.clone(), "dst", true, &entities, &groups).await.unwrap();
        assert_eq!(json(&plan.keep), json(&source[..3]));
        let want = CODE_GROUP_NOT_IN_DESTINATION;
        assert_eq!(codes(&plan), [(want, "ops"), (want, "eng")]);
        let message = &plan.dropped[0].message;
        assert!(message.contains("ops") && message.contains("read, update"), "{message}");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn no_grant_right_drops_all_with_reason() {
        let (_bv, core, _root) = new_unseal_test_bastion_vault("transfer_shares_no_grant_right").await;
        let (entities, groups) = stores(&core).await;
        let alice = entity_in(&entities, "alice", "dst").await;
        group_in(&groups, GroupKind::User, "eng", "dst").await;
        let mut expired = share(ShareGranteeKind::Entity, &alice, &["list"]);
        expired.expires_at = PAST.to_string();
        let source = vec![
            share(ShareGranteeKind::Entity, &alice, &["read", "connect"]),
            share(ShareGranteeKind::GroupUser, "eng", &["read"]),
            expired,
        ];

        let plan = plan_shares(source, "dst", false, &entities, &groups).await.unwrap();
        assert!(plan.keep.is_empty(), "{:?}", plan.keep);
        let want = CODE_CANNOT_GRANT;
        assert_eq!(codes(&plan), [(want, alice.as_str()), (want, "eng"), (want, alice.as_str())]);
        let message = &plan.dropped[0].message;
        assert!(message.contains("grant") && message.contains("read, connect"), "{message}");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn capabilities_unchanged_including_connect() {
        let (_bv, core, _root) = new_unseal_test_bastion_vault("transfer_shares_capabilities_unchanged").await;
        let (entities, groups) = stores(&core).await;
        let alice = entity_in(&entities, "alice", "dst").await;
        group_in(&groups, GroupKind::App, "ci", "dst").await;
        let mut timed = share(ShareGranteeKind::Entity, &alice, &["connect", "read", "sql_select"]);
        timed.expires_at = FUTURE.to_string();
        let source = vec![timed, share(ShareGranteeKind::GroupApp, "ci", &["connect"])];

        let plan = plan_shares(source.clone(), "dst", true, &entities, &groups).await.unwrap();
        assert_eq!(json(&plan.keep), json(&source), "every field, capability order and expiry included");
        assert_eq!(plan.keep[0].capabilities, ["connect", "read", "sql_select"]);
        assert_eq!(plan.keep[0].expires_at, FUTURE);
        assert_eq!(plan.keep[1].capabilities, ["connect"]);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn expired_share_is_dropped_with_code() {
        let (_bv, core, _root) = new_unseal_test_bastion_vault("transfer_shares_expired").await;
        let (entities, groups) = stores(&core).await;
        let alice = entity_in(&entities, "alice", "dst").await;
        group_in(&groups, GroupKind::User, "eng", "dst").await;
        let mut expired_entity = share(ShareGranteeKind::Entity, &alice, &["read"]);
        expired_entity.expires_at = PAST.to_string();
        let mut expired_group = share(ShareGranteeKind::GroupUser, "eng", &["list"]);
        expired_group.expires_at = PAST.to_string();
        let live = share(ShareGranteeKind::Entity, &alice, &["list"]);
        let source = vec![expired_entity, live.clone(), expired_group];

        let plan = plan_shares(source, "dst", true, &entities, &groups).await.unwrap();
        assert_eq!(json(&plan.keep), json(&[live]));
        assert_eq!(codes(&plan), [(CODE_SHARE_EXPIRED, alice.as_str()), (CODE_SHARE_EXPIRED, "eng")]);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn unknown_grantee_kind_is_dropped() {
        let (_bv, core, _root) = new_unseal_test_bastion_vault("transfer_shares_unknown_kind").await;
        let (entities, groups) = stores(&core).await;
        let alice = entity_in(&entities, "alice", "dst").await;
        let mut odd = share(ShareGranteeKind::Entity, &alice, &["read"]);
        odd.grantee_kind = "robot".to_string();

        let plan = plan_shares(vec![odd], "dst", true, &entities, &groups).await.unwrap();
        assert!(plan.keep.is_empty(), "{:?}", plan.keep);
        assert_eq!(codes(&plan), [(CODE_UNKNOWN_GRANTEE_KIND, alice.as_str())]);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn planner_does_not_mutate_inputs() {
        let (_bv, core, _root) = new_unseal_test_bastion_vault("transfer_shares_no_mutation").await;
        let (entities, groups) = stores(&core).await;
        let alice = entity_in(&entities, "alice", "dst").await;
        let bob = entity_in(&entities, "bob", "").await;
        let carol = entity_in(&entities, "carol", "sib").await;
        group_in(&groups, GroupKind::User, "eng", "dst").await;

        #[maybe_async::maybe_async]
        async fn snapshot(entities: &EntityStore, groups: &GroupStore) -> Value {
            let mut out = vec![serde_json::to_value(entities.list_entities().await.unwrap()).unwrap()];
            for ns in ["", "dst", "sib"] {
                out.push(serde_json::to_value(entities.list_aliases_ns(ns).await.unwrap()).unwrap());
                for kind in [GroupKind::User, GroupKind::App] {
                    for name in groups.list_groups_ns(kind, ns).await.unwrap() {
                        let entry = groups.get_group_ns(kind, &name, ns).await.unwrap();
                        out.push(serde_json::to_value(entry).unwrap());
                    }
                }
            }
            Value::Array(out)
        }

        let before = snapshot(&entities, &groups).await;
        let source = vec![
            share(ShareGranteeKind::Entity, &alice, &["read"]),
            share(ShareGranteeKind::Entity, &bob, &["read", "connect"]),
            share(ShareGranteeKind::Entity, &carol, &["read"]),
            share(ShareGranteeKind::GroupUser, "eng", &["list"]),
            share(ShareGranteeKind::GroupApp, "ops", &["list"]),
        ];
        let plan = plan_shares(source.clone(), "dst", true, &entities, &groups).await.unwrap();

        assert_eq!(json(&plan.keep), json(&[source[0].clone(), source[1].clone(), source[3].clone()]));
        assert_eq!(plan.dropped.len(), 2);
        assert_eq!(snapshot(&entities, &groups).await, before, "the planner wrote to a store");
        // Keeping root's entity must not pre-provision bob's entity in `dst`:
        // that is the writer's job, not the planner's.
        assert!(entities.get_by_alias_ns("userpass/", "bob", "dst").await.unwrap().is_none());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn same_named_group_in_other_namespace_does_not_count() {
        let (_bv, core, _root) = new_unseal_test_bastion_vault("transfer_shares_same_named_group").await;
        let (entities, groups) = stores(&core).await;
        group_in(&groups, GroupKind::User, "eng", "").await;
        group_in(&groups, GroupKind::User, "eng", "sib").await;
        group_in(&groups, GroupKind::User, "ops", "dst").await;
        let source = vec![
            share(ShareGranteeKind::GroupUser, "eng", &["read"]),
            share(ShareGranteeKind::GroupUser, "ops", &["read"]),
        ];

        let plan = plan_shares(source.clone(), "dst", true, &entities, &groups).await.unwrap();
        assert_eq!(json(&plan.keep), json(&source[1..]));
        assert_eq!(codes(&plan), [(CODE_GROUP_NOT_IN_DESTINATION, "eng")]);

        // Root's and the sibling's own `eng` do count there; `dst`'s `ops`
        // does not reach its child.
        for dest in ["", "sib"] {
            let plan = plan_shares(source.clone(), dest, true, &entities, &groups).await.unwrap();
            assert_eq!(json(&plan.keep), json(&source[..1]), "{dest:?}");
        }
        let plan = plan_shares(source, "dst/child", true, &entities, &groups).await.unwrap();
        assert!(plan.keep.is_empty());
    }
}
