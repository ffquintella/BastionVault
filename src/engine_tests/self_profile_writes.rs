//! A self-service profile write never re-creates a deleted userpass user
//! (T531).
//!
//! `sys/identity/profile/self/{password,contact}` read the caller's record,
//! change it and write it back. A user deleted between the read and the write
//! used to be put back whole, re-created in its mount without T500's check.

use std::{sync::Arc, time::Duration};

use serde_json::{json, Value};

use crate::{
    core::Core,
    errors::RvError,
    kernel_api::VaultCtx,
    logical::{Operation, Request, Response},
    modules::credential::userpass::user_lock::lock_user_record,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
    test_utils::{new_unseal_test_bastion_vault, test_write_api},
};

const PW: &str = "correct-horse-1";
const NEW_PW: &str = "battery-staple-2";
const PASSWORD: &str = "sys/identity/profile/self/password";
const CONTACT: &str = "sys/identity/profile/self/contact";

#[maybe_async::maybe_async]
async fn send(core: &Core, token: &str, path: &str, body: Value) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = body.as_object().cloned();
    core.handle_request(&mut req).await
}

/// A vault with userpass mount `up1` holding carol: carol's token and the
/// mount's storage.
async fn carol(name: &str) -> (crate::BastionVault, Arc<Core>, String, String, Arc<BarrierView>) {
    let (bvault, core, root) = new_unseal_test_bastion_vault(name).await;
    let body = json!({ "type": "userpass" }).as_object().cloned();
    test_write_api(core.as_ref(), &root, "sys/auth/up1", true, body).await.unwrap();
    send(&core, &root, "auth/up1/users/carol", json!({ "password": PW, "email": "carol@example.com" })).await.unwrap();
    let login = send(&core, "", "auth/up1/login/carol", json!({ "password": PW })).await.unwrap();
    let token = login.and_then(|r| r.auth).expect("carol logs in").client_token;
    let view = core.router().matching_view("auth/up1/").unwrap().expect("up1");
    (bvault, core, root, token, view)
}

/// Run a self-service write as `token` on its own thread and runtime, so the
/// test can change the record while the handler is between its read and its
/// write. Returns `Ok` or the error's `(status, message)`.
fn spawn_write(
    core: &Arc<Core>,
    token: &str,
    path: &'static str,
    body: Value,
) -> std::thread::JoinHandle<Result<(), (u16, String)>> {
    let (core, token) = (core.clone(), token.to_string());
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        match rt.block_on(send(&core, &token, path, body)) {
            Ok(_) => Ok(()),
            Err(RvError::ErrResponseStatus(status, msg)) => Err((status, msg)),
            Err(e) => Err((0, e.to_string())),
        }
    })
}

/// Start a self-service write, let it read carol's record, then run `meddle`
/// on the record while the write waits on carol's record lock, which the
/// test holds as a concurrent delete or update would: the write re-reads
/// after it, whatever the bcrypt timing. Returns the write's outcome.
async fn write_while_meddling(
    core: &Arc<Core>,
    token: &str,
    view: &Arc<BarrierView>,
    path: &'static str,
    body: Value,
    meddle: Option<Value>,
) -> Result<(), (u16, String)> {
    let held = lock_user_record(view.as_ref(), "carol").await.unwrap();
    let write = spawn_write(core, token, path, body);
    tokio::time::sleep(Duration::from_millis(200)).await;
    match meddle {
        None => view.delete("user/carol").await.unwrap(),
        Some(record) => {
            let value = serde_json::to_vec(&record).unwrap();
            view.put(&StorageEntry { key: "user/carol".into(), value }).await.unwrap();
        }
    }
    drop(held);
    tokio::task::block_in_place(|| write.join().unwrap())
}

async fn stored(view: &BarrierView) -> Option<Value> {
    view.get("user/carol").await.unwrap().map(|e| serde_json::from_slice(&e.value).unwrap())
}

/// A user deleted while their own password change verifies and hashes is not
/// put back: the change answers 404 and the record stays gone. Before T531
/// the stale record was written back after the delete, re-creating the user.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_user_deleted_during_a_self_password_change_is_not_recreated() {
    let (_bvault, core, _root, token, view) = carol("self_profile_deleted_password").await;

    let body = json!({ "current_password": PW, "new_password": NEW_PW });
    let result = write_while_meddling(&core, &token, &view, PASSWORD, body, None).await;
    assert!(matches!(result, Err((404, _))), "the change is refused as a missing user: {result:?}");
    assert!(stored(&view).await.is_none(), "carol was not re-created");
}

/// The contact write re-reads too: deleted meanwhile is 404 with nothing put
/// back; disabled meanwhile is 403 and the account stays disabled, its
/// contact details untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_self_contact_change_rereads_the_record_under_the_lock() {
    let (_bvault, core, _root, token, view) = carol("self_profile_contact_lock").await;
    let original = stored(&view).await.expect("carol");

    let result = write_while_meddling(&core, &token, &view, CONTACT, json!({ "phone": "+1 555 0100" }), None).await;
    assert!(matches!(result, Err((404, _))), "deleted meanwhile: {result:?}");
    assert!(stored(&view).await.is_none(), "carol was not re-created");

    let value = serde_json::to_vec(&original).unwrap();
    view.put(&StorageEntry { key: "user/carol".into(), value }).await.unwrap();
    let mut disabled = original.clone();
    disabled["disabled"] = json!(true);
    let body = json!({ "email": "carol@corp.example" });
    let result = write_while_meddling(&core, &token, &view, CONTACT, body, Some(disabled)).await;
    assert!(matches!(result, Err((403, _))), "disabled meanwhile: {result:?}");
    let after = stored(&view).await.expect("carol");
    assert_eq!((after["disabled"].clone(), after["email"].clone()), (json!(true), json!("carol@example.com")));
}

/// An administrator's password reset made while a self-service change ran
/// wins: the change answers 409 and the reset password stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admin_reset_during_a_self_password_change_wins() {
    let (_bvault, core, _root, token, view) = carol("self_profile_admin_reset").await;
    let mut reset = stored(&view).await.expect("carol");
    // Any other hash: the change refuses on the mismatch, before verifying it.
    reset["password_hash"] = json!("$2b$04$an-administrator-reset-the-password-meanwhile");

    let body = json!({ "current_password": PW, "new_password": NEW_PW });
    let result = write_while_meddling(&core, &token, &view, PASSWORD, body, Some(reset.clone())).await;
    assert!(matches!(result, Err((409, _))), "{result:?}");
    assert_eq!(stored(&view).await.unwrap()["password_hash"], reset["password_hash"], "the reset stays");
}

/// Without interference both writes still apply.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn self_service_writes_still_apply() {
    let (_bvault, core, _root, token, view) = carol("self_profile_apply").await;
    send(&core, &token, CONTACT, json!({ "phone": "+1 555 0199" })).await.unwrap();
    send(&core, &token, PASSWORD, json!({ "current_password": PW, "new_password": NEW_PW })).await.unwrap();
    let after = stored(&view).await.expect("carol");
    assert_eq!((after["phone"].clone(), after["email"].clone()), (json!("+1 555 0199"), json!("carol@example.com")));
    let login = send(&core, "", "auth/up1/login/carol", json!({ "password": NEW_PW })).await.unwrap();
    assert!(login.and_then(|r| r.auth).is_some(), "the new password logs in");
}
