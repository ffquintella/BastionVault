//! One AppRole role name, one AppRole mount (T533), as T500 is for userpass.
//!
//! An AppRole login names its entity `("approle/", role, namespace)` whatever
//! mount it came through, so two mounts holding one role name would be one
//! principal, sharing its ownership and shares. A role name another AppRole
//! mount holds is refused.

use std::sync::Arc;

use serde_json::{json, Value};

use super::userpass_mounts::race;
use crate::{
    core::Core,
    errors::RvError,
    kernel_api::VaultCtx,
    logical::{Operation, Request, Response},
    modules::{
        credential::approle::{
            role_mounts::{find_duplicate_role_names, report_duplicate_role_names, DuplicateRoleName},
            AppRoleModule,
        },
        identity::EntityStore,
    },
    storage::Storage,
    test_utils::{new_unseal_test_bastion_vault, test_write_api},
};

#[maybe_async::maybe_async]
async fn send(
    core: &Arc<Core>,
    token: &str,
    op: Operation,
    path: &str,
    body: Value,
) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = op;
    req.client_token = token.to_string();
    req.body = body.as_object().cloned();
    core.handle_request(&mut req).await
}

#[maybe_async::maybe_async]
async fn enable(core: &Arc<Core>, root: &str, mount: &str) {
    let body = json!({ "type": "approle" }).as_object().cloned();
    test_write_api(core.as_ref(), root, &format!("sys/auth/{mount}"), true, body).await.unwrap();
}

#[maybe_async::maybe_async]
async fn create(core: &Arc<Core>, root: &str, mount: &str, name: &str) -> Result<Option<Response>, RvError> {
    send(core, root, Operation::Write, &format!("auth/{mount}/role/{name}"), json!({ "policies": "default" })).await
}

/// The refusal: a 409 naming the role and no mount.
fn assert_refused(result: Result<Option<Response>, RvError>, name: &str) {
    match result {
        Err(RvError::ErrResponseStatus(409, msg)) => {
            assert!(msg.contains(&format!("'{name}'")), "names the role: {msg}");
            assert!(msg.contains("another approle mount"), "says another mount holds it: {msg}");
            assert!(!msg.contains("ar1") && !msg.contains("auth/"), "names no mount: {msg}");
        }
        other => panic!("expected a 409 refusal for {name}, got {other:?}"),
    }
}

/// A second mount refuses a role name the first holds, in any letter case;
/// it writes nothing and the first mount's role is untouched.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_second_mount_refuses_a_role_name_the_first_holds() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("approle_mounts_refuse").await;
    enable(&core, &root, "ar1").await;
    enable(&core, &root, "ar2").await;
    create(&core, &root, "ar1", "web").await.unwrap();

    assert_refused(create(&core, &root, "ar2", "web").await, "web");
    assert_refused(create(&core, &root, "ar2", "Web").await, "web");

    let read = send(&core, &root, Operation::Read, "auth/ar2/role/web", json!({})).await.unwrap();
    assert!(read.is_none(), "ar2 holds no web: {read:?}");
    let listed = send(&core, &root, Operation::List, "auth/ar2/role", json!({})).await.unwrap();
    let keys = listed.and_then(|r| r.data).and_then(|d| d.get("keys").cloned()).unwrap_or(json!([]));
    assert_eq!(keys, json!([]), "ar2 lists no role");
    let held = send(&core, &root, Operation::Read, "auth/ar1/role/web", json!({})).await.unwrap();
    assert!(held.is_some(), "ar1 still holds web");
}

/// Updating a role on the mount that holds it is unchanged while other
/// AppRole mounts exist, and different names on two mounts are both created.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn the_same_role_on_its_own_mount_still_updates() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("approle_mounts_update").await;
    enable(&core, &root, "ar1").await;
    enable(&core, &root, "ar2").await;
    create(&core, &root, "ar1", "web").await.unwrap();
    create(&core, &root, "ar2", "batch").await.unwrap();

    let update = json!({ "token_policies": "default,ops" });
    send(&core, &root, Operation::Write, "auth/ar1/role/web", update).await.unwrap();
    let read = send(&core, &root, Operation::Read, "auth/ar1/role/web", json!({})).await.unwrap().unwrap();
    assert_eq!(read.data.unwrap()["token_policies"], json!(["default", "ops"]), "the update applied");
}

/// A refused creation provisions nothing: no record and no entity or alias.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_refused_role_creation_provisions_no_entity() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("approle_mounts_no_entity").await;
    enable(&core, &root, "ar1").await;
    enable(&core, &root, "ar2").await;
    create(&core, &root, "ar1", "web").await.unwrap();
    let store = EntityStore::new(core.as_ref()).await.unwrap();
    store.forget_alias("approle/", "web").await.unwrap();
    let before = store.list_entities().await.unwrap();

    assert_refused(create(&core, &root, "ar2", "web").await, "web");
    assert!(store.get_by_alias("approle/", "web").await.unwrap().is_none(), "no alias was provisioned");
    assert_eq!(store.list_entities().await.unwrap(), before, "no entity was created");
}

/// Copy role `name` between two AppRole mounts' storage, as a duplicate made
/// before T533 would be: its record and its role-id index entry.
pub(super) async fn plant_role_copy(core: &Arc<Core>, from: &str, to: &str, name: &str) {
    let src = core.router().matching_view(&format!("auth/{from}/")).unwrap().expect("source mount");
    let dst = core.router().matching_view(&format!("auth/{to}/")).unwrap().expect("destination mount");
    dst.put(&src.get(&format!("role/{name}")).await.unwrap().expect("a role to copy")).await.unwrap();
    for key in src.list("role_id/").await.unwrap() {
        let entry = src.get(&format!("role_id/{key}")).await.unwrap().unwrap();
        let index: Value = serde_json::from_slice(&entry.value).unwrap();
        if index["name"] == json!(name) {
            dst.put(&entry).await.unwrap();
        }
    }
}

/// Wait up to 10 s for the AppRole module's next duplicate-scan result.
async fn next_scan(core: &Arc<Core>) -> Option<Vec<DuplicateRoleName>> {
    let module = core.module_manager().get_module::<AppRoleModule>("approle").expect("approle module");
    for _ in 0..500 {
        if let Some(found) = module.take_last_duplicate_scan() {
            return Some(found);
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    None
}

/// Duplicates that predate the refusal are found by mount path and never
/// undone; the unseal runs the scan in the background and completes.
#[tokio::test]
async fn pre_existing_duplicate_roles_are_reported_and_unseal_completes() {
    use crate::{
        core::SealConfig,
        test_utils::{init_test_bastion_vault, new_test_bastion_vault, unseal_test_bastion_vault},
    };

    let bvault = new_test_bastion_vault("approle_mounts_scan");
    let init = init_test_bastion_vault(&bvault, &SealConfig { secret_shares: 3, secret_threshold: 2 }).await;
    let keys: Vec<&[u8]> = init.secret_shares.iter().take(2).map(|k| k.as_slice()).collect();
    assert!(unseal_test_bastion_vault(&bvault, &keys).await);
    let (core, root) = (bvault.core.load().clone(), init.root_token.clone());
    assert_eq!(next_scan(&core).await, Some(vec![]), "the first unseal's scan found nothing");

    for mount in ["ar1", "ar2", "ar3"] {
        enable(&core, &root, mount).await;
    }
    for (mount, name) in [("ar1", "web"), ("ar1", "etl"), ("ar2", "batch")] {
        create(&core, &root, mount, name).await.unwrap();
    }
    plant_role_copy(&core, "ar1", "ar2", "web").await;
    plant_role_copy(&core, "ar1", "ar3", "web").await;
    plant_role_copy(&core, "ar1", "ar2", "etl").await;

    let expected = vec![
        DuplicateRoleName { name: "etl".into(), mounts: vec!["auth/ar1/".into(), "auth/ar2/".into()] },
        DuplicateRoleName {
            name: "web".into(),
            mounts: vec!["auth/ar1/".into(), "auth/ar2/".into(), "auth/ar3/".into()],
        },
    ];
    assert_eq!(find_duplicate_role_names(core.as_ref()).await.unwrap(), expected);
    assert_eq!(report_duplicate_role_names(core.as_ref()).await, Some(expected.clone()));

    core.seal().await.unwrap();
    assert!(unseal_test_bastion_vault(&bvault, &keys).await, "an unseal with duplicates completes");
    assert_eq!(next_scan(&core).await, Some(expected.clone()), "the unseal ran the scan and found both");
    assert_eq!(find_duplicate_role_names(core.as_ref()).await.unwrap(), expected, "nothing was undone");
    let held = send(&core, &root, Operation::Read, "auth/ar3/role/web", json!({})).await.unwrap();
    assert!(held.is_some(), "the planted duplicate is still there");
}

/// Two creations of one role name on two mounts at the same moment admit one
/// (T530's serialisation): the other is refused with the 409.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn simultaneous_role_creations_on_two_mounts_admit_one() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("approle_mounts_race").await;
    enable(&core, &root, "ar1").await;
    enable(&core, &root, "ar2").await;

    for name in ["web", "batch", "etl"] {
        let body = json!({ "policies": "default" });
        let requests = [(format!("auth/ar1/role/{name}"), body.clone()), (format!("auth/ar2/role/{name}"), body)];
        let outcomes = tokio::task::block_in_place(|| race(&core, &root, &requests));
        assert_eq!(outcomes.iter().filter(|o| o.is_ok()).count(), 1, "exactly one creation of {name}: {outcomes:?}");
        let refused = outcomes.iter().find_map(|o| o.clone().err()).expect("one refusal");
        assert_eq!(refused.0, 409, "{name}: {refused:?}");
    }
}
