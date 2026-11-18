//! A deleted principal's entity aliases are forgotten in every namespace
//! (T522): a principal re-created under the same name is a new entity at root
//! and in every namespace, the old entities keep their records for an
//! operator, and their plugin data goes only once no alias anywhere names them.

use std::{collections::HashMap, sync::Arc};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};

use crate::{
    core::Core,
    errors::RvError,
    kernel_api::VaultCtx,
    logical::{Operation, Request, Response},
    modules::identity::{EntityStore, ShareGranteeKind, ShareStore},
    storage::{Storage, StorageEntry},
    test_utils::new_unseal_test_bastion_vault,
};

const PW: &str = "correct-horse-1";
/// The namespace every test logs in to besides root.
const NS: &str = "dst";

async fn send(
    core: &Arc<Core>,
    token: &str,
    op: Operation,
    path: &str,
    ns: Option<&str>,
    body: Value,
) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = op;
    req.client_token = token.to_string();
    req.body = body.as_object().cloned();
    if let Some(ns) = ns {
        req.headers = Some(HashMap::from([("x-bastionvault-namespace".to_string(), ns.to_string())]));
    }
    core.handle_request(&mut req).await
}

/// A vault with namespace `dst` and the auth mounts `(path, type)`.
async fn vault(name: &str, mounts: &[(&str, &str)]) -> (crate::BastionVault, Arc<Core>, String) {
    let (bvault, core, root) = new_unseal_test_bastion_vault(name).await;
    send(&core, &root, Operation::Write, &format!("sys/namespaces/{NS}"), None, json!({})).await.unwrap();
    for (path, kind) in mounts {
        let body = json!({ "type": kind });
        send(&core, &root, Operation::Write, &format!("sys/auth/{path}"), None, body).await.unwrap();
    }
    core.approle_require_machine().store(false, std::sync::atomic::Ordering::Relaxed);
    (bvault, core, root)
}

async fn create_user(core: &Arc<Core>, root: &str, mount: &str, name: &str) {
    let body = json!({ "password": PW, "token_policies": "default" });
    send(core, root, Operation::Write, &format!("auth/{mount}/users/{name}"), None, body).await.unwrap();
}

async fn delete(core: &Arc<Core>, root: &str, path: &str) -> Option<Response> {
    send(core, root, Operation::Delete, path, None, json!({})).await.unwrap()
}

/// A userpass login to `ns` (`None`: root): `(token, entity_id)`, or `None`
/// when the login is refused.
async fn login(core: &Arc<Core>, mount: &str, name: &str, ns: Option<&str>) -> Option<(String, String)> {
    let path = format!("auth/{mount}/login/{name}");
    let auth = send(core, "", Operation::Write, &path, ns, json!({ "password": PW })).await.ok().flatten()?.auth?;
    let entity = auth.metadata.get("entity_id").cloned().unwrap_or_default();
    assert!(!entity.is_empty(), "a userpass login carries an entity id");
    Some((auth.client_token, entity))
}

async fn entity(core: &Arc<Core>, mount: &str, name: &str, ns: Option<&str>) -> String {
    login(core, mount, name, ns).await.unwrap_or_else(|| panic!("{name} logs in to {mount} in {ns:?}")).1
}

/// The entity the alias `(alias_mount, name)` names at root and in `dst`.
async fn aliases(core: &Arc<Core>, alias_mount: &str, name: &str) -> (Option<String>, Option<String>) {
    let store = EntityStore::new(core.as_ref()).await.unwrap();
    let root = store.get_by_alias_ns(alias_mount, name, "").await.unwrap().map(|e| e.id);
    let ns = store.get_by_alias_ns(alias_mount, name, NS).await.unwrap().map(|e| e.id);
    (root, ns)
}

/// Write an alias straight into `dst`'s alias index: the state an earlier
/// root-only delete left behind, or a second alias naming `entity`.
async fn plant_ns_alias(core: &Arc<Core>, alias_dir: &str, name: &str, entity: &str) {
    let key = format!("identity-ns/{}/alias/{alias_dir}/{name}", URL_SAFE_NO_PAD.encode(NS));
    let value = serde_json::to_vec(entity).unwrap();
    core.system_view().expect("unsealed").put(&StorageEntry { key, value }).await.unwrap();
}

/// Copy a user record between two userpass mounts' storage: a duplicate made
/// before T500 refused one.
async fn plant_copy(core: &Arc<Core>, from: &str, to: &str, name: &str) {
    let src = core.router().matching_view(&format!("auth/{from}/")).unwrap().expect("source mount");
    let dst = core.router().matching_view(&format!("auth/{to}/")).unwrap().expect("destination mount");
    let entry = src.get(&format!("user/{name}")).await.unwrap().expect("a record to copy");
    dst.put(&entry).await.unwrap();
}

/// AppRole role `name` on `mount`: its role id.
async fn create_role(core: &Arc<Core>, root: &str, mount: &str, name: &str) -> String {
    let path = format!("auth/{mount}/role/{name}");
    send(core, root, Operation::Write, &path, None, json!({ "policies": "default" })).await.unwrap();
    let read = send(core, root, Operation::Read, &format!("{path}/role-id"), None, json!({})).await.unwrap();
    read.unwrap().data.unwrap()["role_id"].as_str().unwrap().to_string()
}

/// An AppRole login to `ns` with a fresh secret id: its entity id.
async fn role_entity(core: &Arc<Core>, root: &str, mount: &str, name: &str, ns: Option<&str>) -> String {
    let path = format!("auth/{mount}/role/{name}");
    let read = send(core, root, Operation::Read, &format!("{path}/role-id"), None, json!({})).await.unwrap();
    let role_id = read.unwrap().data.unwrap()["role_id"].as_str().unwrap().to_string();
    let made = send(core, root, Operation::Write, &format!("{path}/secret-id"), None, json!({})).await.unwrap();
    let secret_id = made.unwrap().data.unwrap()["secret_id"].as_str().unwrap().to_string();
    let body = json!({ "role_id": role_id, "secret_id": secret_id });
    let resp = send(core, "", Operation::Write, &format!("auth/{mount}/login"), ns, body).await.unwrap().unwrap();
    resp.auth.unwrap().metadata.get("entity_id").cloned().expect("an AppRole login carries an entity id")
}

/// Resource `name` in `ns`, made `entity`'s through the admin owner transfer,
/// and shared with it for reading.
async fn own_and_share(core: &Arc<Core>, root: &str, ns: Option<&str>, name: &str, entity: &str) {
    let meta = json!({ "type": "server", "hostname": "h.example" });
    send(core, root, Operation::Write, &format!("resources/resources/{name}"), ns, meta).await.unwrap();
    let transfer = json!({ "resource": name, "new_owner_entity_id": entity });
    send(core, root, Operation::Write, "sys/resource-owner/transfer", ns, transfer).await.unwrap();
    let path = format!("identity/sharing/by-target/resource/{}/{entity}", URL_SAFE_NO_PAD.encode(name));
    let grant = json!({ "grantee_kind": "entity", "capabilities": ["read"] });
    send(core, root, Operation::Write, &path, ns, grant).await.unwrap();
}

async fn owner(core: &Arc<Core>, root: &str, ns: Option<&str>, name: &str) -> String {
    let path = format!("identity/owner/resource/{name}");
    let read = send(core, root, Operation::Read, &path, ns, json!({})).await.unwrap().unwrap();
    read.data.unwrap()["entity_id"].as_str().unwrap().to_string()
}

/// What `identity/sharing/for-me` lists for `token` in `ns`, as JSON text.
async fn shared_with(core: &Arc<Core>, token: &str, ns: Option<&str>) -> String {
    let listed = send(core, token, Operation::List, "identity/sharing/for-me", ns, json!({})).await.unwrap();
    serde_json::to_string(&listed.and_then(|r| r.data)).unwrap()
}

async fn entity_shares(core: &Arc<Core>, entity: &str) -> usize {
    let store = ShareStore::new(core.as_ref()).await.unwrap();
    store.list_shares_for_grantee_kinded(ShareGranteeKind::Entity, entity).await.unwrap().len()
}

fn plugin_key(entity: &str) -> String {
    format!("core/plugins/t522-probe/data/entity/{entity}/accounts/a/meta")
}

/// Entity-scoped plugin data for `entity`, where the purge looks for it.
async fn plant_plugin_data(core: &Arc<Core>, entity: &str) {
    let entry = StorageEntry { key: plugin_key(entity), value: b"{}".to_vec() };
    core.barrier.as_storage().put(&entry).await.unwrap();
}

async fn has_plugin_data(core: &Arc<Core>, entity: &str) -> bool {
    core.barrier.as_storage().get(&plugin_key(entity)).await.unwrap().is_some()
}

/// The bug: a user deleted and re-created under the same name logged in to a
/// namespace as the old entity there, with its ownership and shares. Now both
/// logins are new entities that see none of it, and the old entities keep
/// their records, unchanged, for an operator to transfer.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_recreated_user_is_a_new_entity_at_root_and_in_every_namespace() {
    let (_vault, core, root) = vault("t522_userpass_recreate", &[("userpass", "userpass")]).await;
    create_user(&core, &root, "userpass", "carol").await;
    let (old_root_token, old_root) = login(&core, "userpass", "carol", None).await.unwrap();
    let (old_ns_token, old_ns) = login(&core, "userpass", "carol", Some(NS)).await.unwrap();
    assert_ne!(old_root, old_ns, "one entity per namespace");
    own_and_share(&core, &root, None, "srv1", &old_root).await;
    own_and_share(&core, &root, Some(NS), "srv2", &old_ns).await;
    assert!(shared_with(&core, &old_root_token, None).await.contains("srv1"), "control: the root share shows");
    assert!(shared_with(&core, &old_ns_token, Some(NS)).await.contains("srv2"), "control: the dst share shows");

    delete(&core, &root, "auth/userpass/users/carol").await;
    create_user(&core, &root, "userpass", "carol").await;
    let (new_ns_token, new_ns) = login(&core, "userpass", "carol", Some(NS)).await.unwrap();
    let (new_root_token, new_root) = login(&core, "userpass", "carol", None).await.unwrap();
    assert_ne!(new_ns, old_ns, "the re-created user's dst login is a new entity");
    assert_ne!(new_root, old_root, "the re-created user's root login is a new entity");
    assert!(![&old_root, &old_ns].contains(&&new_ns) && ![&old_root, &old_ns].contains(&&new_root));
    assert!(!shared_with(&core, &new_root_token, None).await.contains("srv1"), "no inherited root share");
    assert!(!shared_with(&core, &new_ns_token, Some(NS)).await.contains("srv2"), "no inherited dst share");
    assert_eq!((entity_shares(&core, &new_root).await, entity_shares(&core, &new_ns).await), (0, 0));

    assert_eq!(owner(&core, &root, None, "srv1").await, old_root, "the old root owner record stays");
    assert_eq!(owner(&core, &root, Some(NS), "srv2").await, old_ns, "the old dst owner record stays");
    assert_eq!((entity_shares(&core, &old_root).await, entity_shares(&core, &old_ns).await), (1, 1));
    let entities = EntityStore::new(core.as_ref()).await.unwrap();
    for old in [&old_root, &old_ns] {
        assert!(entities.get_entity(old).await.unwrap().is_some(), "the old entity record stays");
    }
}

/// A deleted AppRole role is forgotten in every namespace the same way.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_recreated_approle_role_is_a_new_entity_at_root_and_in_every_namespace() {
    let (_vault, core, root) = vault("t522_approle_recreate", &[("approle", "approle")]).await;
    create_role(&core, &root, "approle", "svc").await;
    let old_root = role_entity(&core, &root, "approle", "svc", None).await;
    let old_ns = role_entity(&core, &root, "approle", "svc", Some(NS)).await;
    own_and_share(&core, &root, Some(NS), "srv2", &old_ns).await;

    delete(&core, &root, "auth/approle/role/svc").await;
    assert_eq!(aliases(&core, "approle/", "svc").await, (None, None), "forgotten at root and in dst");
    create_role(&core, &root, "approle", "svc").await;
    let new_ns = role_entity(&core, &root, "approle", "svc", Some(NS)).await;
    let new_root = role_entity(&core, &root, "approle", "svc", None).await;
    assert_ne!(new_ns, old_ns, "the re-created role's dst login is a new entity");
    assert_ne!(new_root, old_root, "the re-created role's root login is a new entity");
    assert_eq!(entity_shares(&core, &new_ns).await, 0, "no inherited share");
    assert_eq!(owner(&core, &root, Some(NS), "srv2").await, old_ns, "the old owner record stays");
}

/// T500's keeping rule holds in every namespace: while another userpass mount
/// still holds the name, deleting one holder keeps the aliases the other logs
/// in as, at root and in `dst`; deleting the last holder forgets them all.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_name_another_mount_holds_keeps_its_aliases_in_every_namespace() {
    let (_vault, core, root) = vault("t522_keep_rule", &[("up1", "userpass"), ("up2", "userpass")]).await;
    create_user(&core, &root, "up1", "carol").await;
    plant_copy(&core, "up1", "up2", "carol").await;
    let shared_root = entity(&core, "up1", "carol", None).await;
    let shared_ns = entity(&core, "up1", "carol", Some(NS)).await;
    assert_eq!(entity(&core, "up2", "carol", Some(NS)).await, shared_ns, "the planted duplicate shares dst's entity");

    delete(&core, &root, "auth/up2/users/carol").await;
    let kept = (Some(shared_root.clone()), Some(shared_ns.clone()));
    assert_eq!(aliases(&core, "userpass/", "carol").await, kept, "kept at root and in dst");
    assert_eq!(entity(&core, "up1", "carol", None).await, shared_root, "up1's carol keeps its root entity");
    assert_eq!(entity(&core, "up1", "carol", Some(NS)).await, shared_ns, "and its dst entity");

    delete(&core, &root, "auth/up1/users/carol").await;
    assert_eq!(aliases(&core, "userpass/", "carol").await, (None, None), "the last holder's delete forgets all");
    create_user(&core, &root, "up1", "carol").await;
    assert_ne!(entity(&core, "up1", "carol", Some(NS)).await, shared_ns, "a re-created last holder is new in dst");
    assert_ne!(entity(&core, "up1", "carol", None).await, shared_root, "and at root");
}

/// Disabling a userpass mount forgets its users' aliases in every namespace,
/// keeps those of a name another userpass mount still holds, and leaves other
/// mounts' users alone. A name re-created on another mount is a new entity.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn disabling_a_userpass_mount_forgets_its_users_aliases_everywhere() {
    let (_vault, core, root) = vault("t522_disable_userpass", &[("up1", "userpass"), ("up2", "userpass")]).await;
    create_user(&core, &root, "up1", "carol").await;
    create_user(&core, &root, "up1", "erin").await;
    create_user(&core, &root, "up2", "dave").await;
    plant_copy(&core, "up1", "up2", "erin").await;
    let carol = (entity(&core, "up1", "carol", None).await, entity(&core, "up1", "carol", Some(NS)).await);
    let erin = (entity(&core, "up1", "erin", None).await, entity(&core, "up1", "erin", Some(NS)).await);
    let dave = (entity(&core, "up2", "dave", None).await, entity(&core, "up2", "dave", Some(NS)).await);

    let answer = delete(&core, &root, "sys/auth/up1").await;
    assert!(answer.and_then(|r| r.data).is_none(), "a complete forget warns of nothing");
    assert_eq!(aliases(&core, "userpass/", "carol").await, (None, None), "carol is forgotten everywhere");
    assert_eq!(aliases(&core, "userpass/", "erin").await, (Some(erin.0.clone()), Some(erin.1.clone())));
    assert_eq!((entity(&core, "up2", "erin", None).await, entity(&core, "up2", "erin", Some(NS)).await), erin);
    assert_eq!((entity(&core, "up2", "dave", None).await, entity(&core, "up2", "dave", Some(NS)).await), dave);

    create_user(&core, &root, "up2", "carol").await;
    assert_ne!(entity(&core, "up2", "carol", Some(NS)).await, carol.1, "carol re-created on up2 is new in dst");
    assert_ne!(entity(&core, "up2", "carol", None).await, carol.0, "and at root");
}

/// Disabling an AppRole mount forgets its roles' aliases in every namespace.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn disabling_an_approle_mount_forgets_its_roles_aliases_everywhere() {
    let (_vault, core, root) = vault("t522_disable_approle", &[("ar1", "approle"), ("ar2", "approle")]).await;
    create_role(&core, &root, "ar1", "svc").await;
    create_role(&core, &root, "ar2", "other").await;
    let svc_root = role_entity(&core, &root, "ar1", "svc", None).await;
    let svc_ns = role_entity(&core, &root, "ar1", "svc", Some(NS)).await;
    let other_ns = role_entity(&core, &root, "ar2", "other", Some(NS)).await;
    assert_eq!(aliases(&core, "approle/", "svc").await, (Some(svc_root), Some(svc_ns.clone())));

    delete(&core, &root, "sys/auth/ar1").await;
    assert_eq!(aliases(&core, "approle/", "svc").await, (None, None), "svc is forgotten everywhere");
    assert_eq!(aliases(&core, "approle/", "other").await.1, Some(other_ns), "ar2's role is untouched");
    create_role(&core, &root, "ar2", "svc").await;
    assert_ne!(role_entity(&core, &root, "ar2", "svc", Some(NS)).await, svc_ns, "svc re-created on ar2 is new");
}

/// AppRole keeps T500's rule too: a role name another AppRole mount holds logs
/// in as the same entities, so deleting one of them keeps the aliases, and so
/// does disabling its mount; deleting the last holder forgets them all.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn an_approle_name_another_mount_holds_keeps_its_aliases() {
    let (_vault, core, root) = vault("t522_approle_keep", &[("ar1", "approle"), ("ar2", "approle")]).await;
    create_role(&core, &root, "ar1", "svc").await;
    create_role(&core, &root, "ar2", "svc").await;
    let shared = role_entity(&core, &root, "ar1", "svc", Some(NS)).await;
    assert_eq!(role_entity(&core, &root, "ar2", "svc", Some(NS)).await, shared, "one entity for the name");

    delete(&core, &root, "auth/ar2/role/svc").await;
    assert_eq!(aliases(&core, "approle/", "svc").await.1, Some(shared.clone()), "kept while ar1 holds svc");
    create_role(&core, &root, "ar2", "svc").await;
    delete(&core, &root, "sys/auth/ar2").await;
    assert_eq!(role_entity(&core, &root, "ar1", "svc", Some(NS)).await, shared, "ar1's svc keeps its entity");

    delete(&core, &root, "auth/ar1/role/svc").await;
    assert_eq!(aliases(&core, "approle/", "svc").await, (None, None), "the last holder's delete forgets all");
}

/// The plugin data of a forgotten entity is purged only once no alias in any
/// namespace names it: an entity a `dst` alias still reaches keeps its data
/// (the root-only check purged it), one nothing reaches loses it. Deleting a
/// name no mount holds forgets its leftover aliases, the documented remedy.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn plugin_data_is_purged_only_when_no_namespace_alias_reaches_the_entity() {
    let (_vault, core, root) = vault("t522_purge", &[("userpass", "userpass")]).await;
    create_user(&core, &root, "userpass", "carol").await;
    let carol_root = entity(&core, "userpass", "carol", None).await;
    let carol_ns = entity(&core, "userpass", "carol", Some(NS)).await;
    plant_plugin_data(&core, &carol_root).await;
    plant_plugin_data(&core, &carol_ns).await;
    plant_ns_alias(&core, "userpass", "dave", &carol_root).await;
    assert_eq!(aliases(&core, "userpass/", "dave").await, (None, Some(carol_root.clone())), "control: planted");

    delete(&core, &root, "auth/userpass/users/carol").await;
    assert!(has_plugin_data(&core, &carol_root).await, "a dst alias still reaches the root entity: kept");
    assert!(!has_plugin_data(&core, &carol_ns).await, "nothing reaches the dst entity: purged");

    delete(&core, &root, "auth/userpass/users/dave").await;
    assert_eq!(aliases(&core, "userpass/", "dave").await, (None, None), "dave's leftover alias is forgotten");
    assert!(!has_plugin_data(&core, &carol_root).await, "now nothing reaches the root entity: purged");
}

/// A leftover namespace alias of a name no mount holds (what a pre-T522
/// delete left) is cleared by deleting that name again, for AppRole too.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn deleting_a_missing_principal_clears_its_leftover_aliases() {
    let (_vault, core, root) = vault("t522_leftover", &[("userpass", "userpass"), ("approle", "approle")]).await;
    let stale = EntityStore::new(core.as_ref()).await.unwrap().get_or_create_entity_ns("userpass/", "x", NS).await;
    let stale = stale.unwrap().id;
    plant_ns_alias(&core, "userpass", "olduser", &stale).await;
    plant_ns_alias(&core, "approle", "oldrole", &stale).await;
    assert_eq!(aliases(&core, "userpass/", "olduser").await, (None, Some(stale.clone())), "control: planted");
    assert_eq!(aliases(&core, "approle/", "oldrole").await, (None, Some(stale.clone())), "control: planted");

    delete(&core, &root, "auth/userpass/users/olduser").await;
    delete(&core, &root, "auth/approle/role/oldrole").await;
    assert_eq!(aliases(&core, "userpass/", "olduser").await, (None, None));
    assert_eq!(aliases(&core, "approle/", "oldrole").await, (None, None));
}

/// A password reset or an update is not a delete: the user keeps its entity
/// at root and in every namespace.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_password_reset_or_update_keeps_the_entity_everywhere() {
    let (_vault, core, root) = vault("t522_update_keeps", &[("userpass", "userpass")]).await;
    create_user(&core, &root, "userpass", "carol").await;
    let before = (entity(&core, "userpass", "carol", None).await, entity(&core, "userpass", "carol", Some(NS)).await);

    let reset = json!({ "password": PW });
    send(&core, &root, Operation::Write, "auth/userpass/users/carol/password", None, reset).await.unwrap();
    create_user(&core, &root, "userpass", "carol").await;
    let after = (entity(&core, "userpass", "carol", None).await, entity(&core, "userpass", "carol", Some(NS)).await);
    assert_eq!(after, before, "the same entities at root and in dst");
}
