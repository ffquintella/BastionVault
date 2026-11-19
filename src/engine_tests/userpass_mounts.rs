//! One username, one userpass mount (T500).
//!
//! A userpass login names its entity `("userpass/", username, namespace)`
//! whatever mount it came through, so two mounts holding one username would be
//! one principal. A username another userpass mount holds is refused.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::{
    core::Core,
    errors::RvError,
    kernel_api::VaultCtx,
    logical::{Auth, Operation, Request, Response},
    modules::{
        credential::userpass::{
            username_mounts::{find_duplicate_usernames, report_duplicate_usernames, DuplicateUsername},
            UserPassModule,
        },
        identity::EntityStore,
    },
    storage::Storage,
    test_utils::{new_unseal_test_bastion_vault, test_write_api},
};

const PW: &str = "correct-horse-1";

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
    let body = json!({ "type": "userpass" }).as_object().cloned();
    test_write_api(core.as_ref(), root, &format!("sys/auth/{mount}"), true, body).await.unwrap();
}

#[maybe_async::maybe_async]
async fn create(core: &Arc<Core>, root: &str, mount: &str, name: &str, pw: &str) -> Result<Option<Response>, RvError> {
    send(core, root, Operation::Write, &format!("auth/{mount}/users/{name}"), json!({ "password": pw })).await
}

/// The token a password login mints, or `None` when it is refused.
#[maybe_async::maybe_async]
async fn login(core: &Arc<Core>, mount: &str, name: &str, pw: &str) -> Option<Auth> {
    let path = format!("auth/{mount}/login/{name}");
    let resp = send(core, "", Operation::Write, &path, json!({ "password": pw })).await;
    resp.ok().flatten().and_then(|r| r.auth)
}

#[maybe_async::maybe_async]
async fn entity_of(core: &Arc<Core>, mount: &str, name: &str) -> String {
    let auth = login(core, mount, name, PW).await.unwrap_or_else(|| panic!("{name} logs in to {mount}"));
    auth.metadata.get("entity_id").cloned().expect("a userpass login carries an entity id")
}

/// Copy a user record from one mount's storage to another's, as a duplicate
/// made before the refusal existed would be.
#[maybe_async::maybe_async]
async fn plant_copy(core: &Arc<Core>, from: &str, to: &str, name: &str) {
    let src = core.router().matching_view(&format!("auth/{from}/")).unwrap().expect("source mount");
    let dst = core.router().matching_view(&format!("auth/{to}/")).unwrap().expect("destination mount");
    let entry = src.get(&format!("user/{name}")).await.unwrap().expect("a record to copy");
    dst.put(&entry).await.unwrap();
}

/// The refusal: a 409 naming the username and no other mount.
fn assert_refused(result: Result<Option<Response>, RvError>, name: &str) {
    match result {
        Err(RvError::ErrResponseStatus(409, msg)) => {
            assert!(msg.contains(&format!("'{name}'")), "names the username: {msg}");
            assert!(msg.contains("another userpass mount"), "says another mount holds it: {msg}");
            assert!(!msg.contains("up1") && !msg.contains("auth/"), "names no mount: {msg}");
        }
        other => panic!("expected a 409 refusal for {name}, got {other:?}"),
    }
}

/// A second mount refuses a username the first holds, in any letter case;
/// it writes nothing and the first mount's user is untouched.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_second_mount_refuses_a_username_the_first_holds() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("userpass_mounts_refuse").await;
    enable(&core, &root, "up1").await;
    enable(&core, &root, "up2").await;
    create(&core, &root, "up1", "carol", PW).await.unwrap();

    assert_refused(create(&core, &root, "up2", "carol", PW).await, "carol");
    assert_refused(create(&core, &root, "up2", "Carol", PW).await, "carol");

    let read = send(&core, &root, Operation::Read, "auth/up2/users/carol", json!({})).await.unwrap();
    assert!(read.is_none(), "up2 holds no carol: {read:?}");
    let listed = send(&core, &root, Operation::List, "auth/up2/users", json!({})).await.unwrap();
    let keys = listed.and_then(|r| r.data).and_then(|d| d.get("keys").cloned()).unwrap_or(json!([]));
    assert_eq!(keys, json!([]), "up2 lists no user");
    assert!(login(&core, "up2", "carol", PW).await.is_none(), "carol cannot log in to up2");
    assert!(login(&core, "up1", "carol", PW).await.is_some(), "carol still logs in to up1");
}

/// Updating a user in the mount that holds it is unchanged while other
/// userpass mounts exist: the user route and the password route both update.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn the_same_username_in_the_same_mount_still_updates() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("userpass_mounts_update").await;
    enable(&core, &root, "up1").await;
    enable(&core, &root, "up2").await;
    create(&core, &root, "up1", "carol", "first-pw-1").await.unwrap();

    let update = json!({ "password": "second-pw-2", "token_policies": "default" });
    send(&core, &root, Operation::Write, "auth/up1/users/carol", update).await.unwrap();
    assert!(login(&core, "up1", "carol", "second-pw-2").await.is_some(), "the update applied");
    assert!(login(&core, "up1", "carol", "first-pw-1").await.is_none(), "the old password is gone");

    let reset = json!({ "password": PW });
    send(&core, &root, Operation::Write, "auth/up1/users/carol/password", reset).await.unwrap();
    assert!(login(&core, "up1", "carol", PW).await.is_some(), "the password route updates too");
}

/// Different usernames in two mounts are two principals with two entities.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn different_usernames_in_two_mounts_are_two_principals() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("userpass_mounts_distinct").await;
    enable(&core, &root, "up1").await;
    enable(&core, &root, "up2").await;
    create(&core, &root, "up1", "carol", PW).await.unwrap();
    create(&core, &root, "up2", "dave", PW).await.unwrap();

    let carol = entity_of(&core, "up1", "carol").await;
    let dave = entity_of(&core, "up2", "dave").await;
    assert_ne!(carol, dave, "two users, two entities");
}

/// There is no rename route: renaming is creating the new name. Taking a name
/// another mount holds is refused by the user and the password route alike,
/// and the user being renamed stays as it was.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_rename_into_a_name_another_mount_holds_is_refused() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("userpass_mounts_rename").await;
    enable(&core, &root, "up1").await;
    enable(&core, &root, "up2").await;
    create(&core, &root, "up1", "carol", PW).await.unwrap();
    create(&core, &root, "up2", "dave", PW).await.unwrap();

    assert_refused(create(&core, &root, "up2", "carol", PW).await, "carol");
    let reset = json!({ "password": PW });
    assert_refused(send(&core, &root, Operation::Write, "auth/up2/users/carol/password", reset).await, "carol");
    assert!(login(&core, "up2", "dave", PW).await.is_some(), "dave is untouched");
    assert!(login(&core, "up2", "carol", PW).await.is_none(), "up2 has no carol");
}

/// A refused creation provisions nothing: no record, no entity, no alias.
/// carol's root alias is removed first, as for a user created before
/// creation pre-provisioned one, so a provisioning refusal would show.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_refused_creation_provisions_no_entity() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("userpass_mounts_no_entity").await;
    enable(&core, &root, "up1").await;
    enable(&core, &root, "up2").await;
    create(&core, &root, "up1", "carol", PW).await.unwrap();
    let store = EntityStore::new(core.as_ref()).await.unwrap();
    store.forget_alias("userpass/", "carol").await.unwrap();
    let before = store.list_entities().await.unwrap();

    assert_refused(create(&core, &root, "up2", "carol", PW).await, "carol");
    assert!(store.get_by_alias("userpass/", "carol").await.unwrap().is_none(), "no alias was provisioned");
    assert_eq!(store.list_entities().await.unwrap(), before, "no entity was created");
}

/// Two mounts holding one username from before the refusal stay as they are,
/// and deleting one of them keeps the entity the other still logs in as.
/// Deleting the last holder still forgets the alias, as before.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn deleting_one_of_two_duplicates_keeps_the_survivors_entity() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("userpass_mounts_delete_dup").await;
    enable(&core, &root, "up1").await;
    enable(&core, &root, "up2").await;
    create(&core, &root, "up1", "carol", PW).await.unwrap();
    plant_copy(&core, "up1", "up2", "carol").await;
    let shared = entity_of(&core, "up1", "carol").await;
    assert_eq!(entity_of(&core, "up2", "carol").await, shared, "the planted duplicate shares the entity");

    send(&core, &root, Operation::Delete, "auth/up2/users/carol", json!({})).await.unwrap();
    assert!(login(&core, "up2", "carol", PW).await.is_none(), "up2's carol is gone");
    assert_eq!(entity_of(&core, "up1", "carol").await, shared, "up1's carol keeps its entity");

    send(&core, &root, Operation::Delete, "auth/up1/users/carol", json!({})).await.unwrap();
    create(&core, &root, "up1", "carol", PW).await.unwrap();
    assert_ne!(entity_of(&core, "up1", "carol").await, shared, "a recreated last holder is a new principal");
}

/// Wait up to 10 s for the userpass module's next duplicate-scan result.
async fn next_scan(core: &Arc<Core>) -> Option<Vec<DuplicateUsername>> {
    let module = core.module_manager().get_module::<UserPassModule>("userpass").expect("userpass module");
    for _ in 0..500 {
        if let Some(found) = module.take_last_duplicate_scan() {
            return Some(found);
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    None
}

/// Duplicates that predate the refusal are found by mount path and never
/// undone. The unseal itself runs the scan (in the background) and completes:
/// a seal and unseal reports the planted duplicates, and every holder still
/// logs in after it.
#[tokio::test]
async fn pre_existing_duplicates_are_reported_and_unseal_completes() {
    use crate::{
        core::SealConfig,
        test_utils::{init_test_bastion_vault, new_test_bastion_vault, unseal_test_bastion_vault},
    };

    let bvault = new_test_bastion_vault("userpass_mounts_scan");
    let init = init_test_bastion_vault(&bvault, &SealConfig { secret_shares: 3, secret_threshold: 2 }).await;
    let keys: Vec<&[u8]> = init.secret_shares.iter().take(2).map(|k| k.as_slice()).collect();
    assert!(unseal_test_bastion_vault(&bvault, &keys).await);
    let (core, root) = (bvault.core.load().clone(), init.root_token.clone());
    assert_eq!(next_scan(&core).await, Some(vec![]), "the first unseal's scan found nothing");

    for mount in ["up1", "up2", "up3"] {
        enable(&core, &root, mount).await;
    }
    for (mount, name) in [("up1", "carol"), ("up1", "erin"), ("up2", "frank")] {
        create(&core, &root, mount, name, PW).await.unwrap();
    }
    plant_copy(&core, "up1", "up2", "carol").await;
    plant_copy(&core, "up1", "up3", "carol").await;
    plant_copy(&core, "up1", "up2", "erin").await;

    let expected = vec![
        DuplicateUsername {
            username: "carol".into(),
            mounts: vec!["auth/up1/".into(), "auth/up2/".into(), "auth/up3/".into()],
        },
        DuplicateUsername { username: "erin".into(), mounts: vec!["auth/up1/".into(), "auth/up2/".into()] },
    ];
    assert_eq!(find_duplicate_usernames(core.as_ref()).await.unwrap(), expected);
    assert_eq!(report_duplicate_usernames(core.as_ref()).await, Some(expected.clone()));

    core.seal().await.unwrap();
    assert!(unseal_test_bastion_vault(&bvault, &keys).await, "an unseal with duplicates completes");
    assert_eq!(next_scan(&core).await, Some(expected.clone()), "the unseal ran the scan and found both");
    for mount in ["up1", "up2", "up3"] {
        assert!(login(&core, mount, "carol", PW).await.is_some(), "carol still logs in to {mount}");
    }
    assert_eq!(find_duplicate_usernames(core.as_ref()).await.unwrap(), expected, "nothing was undone");
}

/// A mixed-case record left by the pre-T500 password route (`user/Carol`) is
/// not counted as a duplicate, and `sys/raw` removes it by the mount's uuid
/// read from `sys/raw/core/auth`, leaving `carol` alone: the documented step.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_stray_mixed_case_record_is_removed_through_sys_raw() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("userpass_mounts_stray_record").await;
    enable(&core, &root, "up1").await;
    enable(&core, &root, "up2").await;
    create(&core, &root, "up1", "carol", PW).await.unwrap();
    let view = core.router().matching_view("auth/up2/").unwrap().expect("up2");
    let record = core.router().matching_view("auth/up1/").unwrap().unwrap().get("user/carol").await.unwrap().unwrap();
    view.put(&crate::storage::StorageEntry { key: "user/Carol".into(), value: record.value }).await.unwrap();
    assert_eq!(find_duplicate_usernames(core.as_ref()).await.unwrap(), vec![], "a stray record is no duplicate");

    let raw = send(&core, &root, Operation::Read, "sys/raw/core/auth", json!({})).await.unwrap().unwrap();
    let table: Value = serde_json::from_str(raw.data.unwrap()["value"].as_str().unwrap()).unwrap();
    let uuid = table["entries"]["up2/"]["uuid"].as_str().expect("the auth table names up2's uuid").to_string();
    send(&core, &root, Operation::Delete, &format!("sys/raw/auth/{uuid}/user/Carol"), json!({})).await.unwrap();
    assert!(view.get("user/Carol").await.unwrap().is_none(), "the stray record is gone");
    assert!(login(&core, "up1", "carol", PW).await.is_some(), "carol on up1 is untouched");
}

/// What a raced request came to: `Ok` or `(status, message)`, so it can cross
/// back from its thread whatever the error type holds.
pub(super) type Outcome = Result<(), (u16, String)>;

fn outcome(result: Result<Option<Response>, RvError>) -> Outcome {
    match result {
        Ok(_) => Ok(()),
        Err(RvError::ErrResponseStatus(status, msg)) => Err((status, msg)),
        Err(e) => Err((0, e.to_string())),
    }
}

/// Send each `(path, body)` write as root on its own OS thread and runtime,
/// released together, so the handlers really run at the same time; the
/// outcomes come back in request order.
pub(super) fn race(core: &Arc<Core>, token: &str, requests: &[(String, Value)]) -> Vec<Outcome> {
    let start = std::sync::Barrier::new(requests.len());
    std::thread::scope(|scope| {
        let threads: Vec<_> = requests
            .iter()
            .map(|(path, body)| {
                let (core, start) = (core.clone(), &start);
                scope.spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
                    start.wait();
                    outcome(rt.block_on(send(&core, token, Operation::Write, path, body.clone())))
                })
            })
            .collect();
        threads.into_iter().map(|t| t.join().expect("a raced request panicked")).collect()
    })
}

/// Two creations of one username on two mounts at the same moment admit one
/// (T530), by the user route and by the password route: the other is refused
/// with T500's 409 and writes nothing, so no mount pair holds the name twice.
/// Before T530 the check of the other mounts and the write were not
/// serialised, and the bcrypt hash between them let both pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn simultaneous_creations_of_one_name_on_two_mounts_admit_one() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("userpass_mounts_race").await;
    enable(&core, &root, "up1").await;
    enable(&core, &root, "up2").await;

    for (name, second_route) in [("carol", "auth/up2/users/carol"), ("dave", "auth/up2/users/dave/password")] {
        let requests = [
            (format!("auth/up1/users/{name}"), json!({ "password": PW })),
            (second_route.to_string(), json!({ "password": PW })),
        ];
        let outcomes = tokio::task::block_in_place(|| race(&core, &root, &requests));
        assert_eq!(outcomes.iter().filter(|o| o.is_ok()).count(), 1, "exactly one creation of {name}: {outcomes:?}");
        let refused = outcomes.iter().find_map(|o| o.clone().err()).expect("one refusal");
        assert_eq!(refused.0, 409, "{name}: {refused:?}");
        assert!(refused.1.contains("another userpass mount"), "{name}: {refused:?}");
    }
    assert_eq!(find_duplicate_usernames(core.as_ref()).await.unwrap(), vec![], "no name is held twice");
}

/// A password reset naming the user in another letter case updates the
/// user's own record: it used to write a second record under the mixed-case
/// key, leaving the real one, and its old password, in place.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_password_reset_in_another_case_updates_the_user() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("userpass_mounts_reset_case").await;
    enable(&core, &root, "up1").await;
    create(&core, &root, "up1", "carol", "old-pw-1").await.unwrap();

    let reset = json!({ "password": PW });
    send(&core, &root, Operation::Write, "auth/up1/users/Carol/password", reset).await.unwrap();
    assert!(login(&core, "up1", "carol", PW).await.is_some(), "the new password works");
    assert!(login(&core, "up1", "carol", "old-pw-1").await.is_none(), "the old password is refused");
    let listed = send(&core, &root, Operation::List, "auth/up1/users", json!({})).await.unwrap();
    let keys = listed.and_then(|r| r.data).and_then(|d| d.get("keys").cloned());
    assert_eq!(keys, Some(json!(["carol"])), "one record");
}
