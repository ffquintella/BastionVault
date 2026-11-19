//! Userpass's own read-modify-writes never re-create a deleted user or undo
//! an administrator's change (T544).
//!
//! The failed-login counter, the counter reset, unlock, passkey registration
//! and the passkey sign counters read `user/<name>`, ran bcrypt or a passkey
//! check, and wrote the whole record back over whatever had happened since.

use std::{sync::Arc, thread::JoinHandle, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

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
const LOGIN: &str = "auth/up1/login/carol";
const RP_ID: &str = "localhost";
const ORIGIN: &str = "https://localhost";
/// Time for a request to read the record and reach bcrypt or the record
/// lock; a debug-build bcrypt takes longer.
const PAUSE: Duration = Duration::from_millis(300);

/// What a request ended with, reduced to what can cross a thread.
#[derive(Debug)]
struct Outcome {
    token: Option<String>,
    error: Option<String>,
}

impl Outcome {
    fn of(result: Result<Option<Response>, RvError>) -> Self {
        match result {
            Ok(Some(resp)) => Outcome {
                token: resp.auth.as_ref().map(|a| a.client_token.clone()),
                error: resp.data.as_ref().and_then(|d| d.get("error")).and_then(|v| v.as_str()).map(String::from),
            },
            Ok(None) => Outcome { token: None, error: None },
            Err(e) => Outcome { token: None, error: Some(e.to_string()) },
        }
    }

    fn error_contains(&self, text: &str) -> bool {
        self.error.as_deref().is_some_and(|e| e.contains(text))
    }
}

#[maybe_async::maybe_async]
async fn send(core: &Core, token: &str, op: Operation, path: &str, body: Value) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = op;
    req.client_token = token.to_string();
    req.body = body.as_object().cloned();
    core.handle_request(&mut req).await
}

/// Run a request on its own thread and runtime, so the test can act while
/// the handler is between its read and its write.
fn spawn(core: &Arc<Core>, token: &str, op: Operation, path: &str, body: Value) -> JoinHandle<Outcome> {
    let (core, token, path) = (core.clone(), token.to_string(), path.to_string());
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        Outcome::of(rt.block_on(send(&core, &token, op, &path, body)))
    })
}

/// A vault with userpass mount `up1` holding carol, and the mount's storage.
async fn carol(name: &str) -> (crate::BastionVault, Arc<Core>, String, Arc<BarrierView>) {
    let (bvault, core, root) = new_unseal_test_bastion_vault(name).await;
    let body = json!({ "type": "userpass" }).as_object().cloned();
    test_write_api(core.as_ref(), &root, "sys/auth/up1", true, body).await.unwrap();
    send(&core, &root, Operation::Write, "auth/up1/users/carol", json!({ "password": PW })).await.unwrap();
    let view = core.router().matching_view("auth/up1/").unwrap().expect("up1");
    (bvault, core, root, view)
}

async fn stored(view: &BarrierView) -> Option<Value> {
    view.get("user/carol").await.unwrap().map(|e| serde_json::from_slice(&e.value).unwrap())
}

async fn put(view: &BarrierView, record: &Value) {
    let value = serde_json::to_vec(record).unwrap();
    view.put(&StorageEntry { key: "user/carol".into(), value }).await.unwrap();
}

/// Start a request while the test holds carol's record lock, as a concurrent
/// delete or administrator write would; after [`PAUSE`] delete carol's record
/// (`meddle` `None`) or replace it, then release the lock.
async fn while_meddling(
    core: &Arc<Core>,
    view: &Arc<BarrierView>,
    token: &str,
    path: &str,
    body: Value,
    meddle: Option<&Value>,
) -> Outcome {
    let held = lock_user_record(view.as_ref(), "carol").await.unwrap();
    let request = spawn(core, token, Operation::Write, path, body);
    tokio::time::sleep(PAUSE).await;
    match meddle {
        None => view.delete("user/carol").await.unwrap(),
        Some(record) => put(view, record).await,
    }
    drop(held);
    tokio::task::block_in_place(|| request.join().unwrap())
}

/// A failed login that loses the race to a delete does not put carol back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_login_racing_a_delete_does_not_recreate_the_user() {
    let (_bvault, core, _root, view) = carol("up_writes_failed_delete").await;

    let outcome = while_meddling(&core, &view, "", LOGIN, json!({ "password": "wrong" }), None).await;
    assert!(outcome.token.is_none(), "{outcome:?}");
    assert!(stored(&view).await.is_none(), "carol was not re-created: {outcome:?}");
}

/// A disable and a password reset made while a failed login runs bcrypt both
/// stay; the attempt is counted on the record as it is now.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_login_racing_a_disable_and_a_reset_keeps_both() {
    let (_bvault, core, _root, view) = carol("up_writes_failed_disable").await;
    let mut changed = stored(&view).await.expect("carol");
    changed["disabled"] = json!(true);
    changed["password_hash"] = json!("$2b$04$an-administrator-reset-the-password-meanwhile");

    let outcome = while_meddling(&core, &view, "", LOGIN, json!({ "password": "wrong" }), Some(&changed)).await;
    assert_eq!(outcome.error.as_deref(), Some("invalid username or password"), "{outcome:?}");
    let after = stored(&view).await.expect("carol");
    assert_eq!(after["disabled"], json!(true), "the disable stays");
    assert_eq!(after["password_hash"], changed["password_hash"], "the reset stays");
    assert_eq!(after["failed_login_count"], json!(1), "the attempt is counted");
}

/// A correct password whose counter reset races a delete or a disable mints
/// no token, and the record stays as the administrator left it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_successful_login_racing_a_delete_or_disable_is_refused() {
    let (_bvault, core, _root, view) = carol("up_writes_success").await;
    let wrong = send(&core, "", Operation::Write, LOGIN, json!({ "password": "wrong" })).await.unwrap();
    assert!(wrong.and_then(|r| r.auth).is_none());
    let original = stored(&view).await.expect("carol");
    assert_eq!(original["failed_login_count"], json!(1), "a counter for the success to reset");

    let outcome = while_meddling(&core, &view, "", LOGIN, json!({ "password": PW }), None).await;
    assert!(outcome.token.is_none(), "no token for a deleted user: {outcome:?}");
    assert!(stored(&view).await.is_none(), "carol was not re-created");

    put(&view, &original).await;
    let mut disabled = original.clone();
    disabled["disabled"] = json!(true);
    let outcome = while_meddling(&core, &view, "", LOGIN, json!({ "password": PW }), Some(&disabled)).await;
    assert!(outcome.token.is_none(), "no token for a disabled user: {outcome:?}");
    assert!(outcome.error_contains("disabled"), "{outcome:?}");
    assert_eq!(stored(&view).await.expect("carol")["disabled"], json!(true), "the disable stays");

    put(&view, &original).await;
    let ok = send(&core, "", Operation::Write, LOGIN, json!({ "password": PW })).await.unwrap();
    assert!(ok.and_then(|r| r.auth).is_some(), "undisturbed, the login succeeds");
    assert_eq!(stored(&view).await.expect("carol")["failed_login_count"], json!(0), "and resets the counter");
}

/// Unlock and the passkey removal wait for carol's record lock, refuse a user
/// deleted meanwhile without re-creating it, and keep a disable made meanwhile.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_record_writes_wait_for_the_record_lock() {
    let (_bvault, core, root, view) = carol("up_writes_admin").await;
    let mut locked = stored(&view).await.expect("carol");
    locked["locked_until"] = json!(crate::modules::credential::userpass::path_users::now_secs() + 600);

    for (op, path) in
        [(Operation::Write, "auth/up1/users/carol/unlock"), (Operation::Delete, "auth/up1/users/carol/fido2")]
    {
        put(&view, &locked).await;
        let held = lock_user_record(view.as_ref(), "carol").await.unwrap();
        let request = spawn(&core, &root, op, path, json!({}));
        tokio::time::sleep(PAUSE).await;
        assert!(!request.is_finished(), "{path} waits for carol's record lock");
        view.delete("user/carol").await.unwrap();
        drop(held);
        let outcome = tokio::task::block_in_place(|| request.join().unwrap());
        assert!(stored(&view).await.is_none(), "{path} did not re-create carol: {outcome:?}");

        put(&view, &locked).await;
        let mut disabled = locked.clone();
        disabled["disabled"] = json!(true);
        let held = lock_user_record(view.as_ref(), "carol").await.unwrap();
        let request = spawn(&core, &root, op, path, json!({}));
        tokio::time::sleep(PAUSE).await;
        put(&view, &disabled).await;
        drop(held);
        let outcome = tokio::task::block_in_place(|| request.join().unwrap());
        assert!(outcome.error.is_none(), "{path}: {outcome:?}");
        assert_eq!(stored(&view).await.expect("carol")["disabled"], json!(true), "{path} keeps the disable");
    }
    put(&view, &locked).await;
    let unlock = send(&core, &root, Operation::Write, "auth/up1/users/carol/unlock", json!({})).await;
    assert!(unlock.is_ok());
    assert_eq!(stored(&view).await.expect("carol")["locked_until"], json!(0), "an undisturbed unlock applies");
}

/// The lock is per name: unauthenticated failed logins for one user never
/// wait on another user's record lock.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_login_does_not_wait_for_another_users_lock() {
    let (_bvault, core, root, view) = carol("up_writes_per_name").await;
    send(&core, &root, Operation::Write, "auth/up1/users/dave", json!({ "password": PW })).await.unwrap();

    let held = lock_user_record(view.as_ref(), "dave").await.unwrap();
    let request = spawn(&core, "", Operation::Write, LOGIN, json!({ "password": "wrong" }));
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while !request.is_finished() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(request.is_finished(), "carol's failed login waited for dave's lock");
    assert_eq!(stored(&view).await.expect("carol")["failed_login_count"], json!(1));
    drop(held);
}

/// A software Ed25519 authenticator: enough of WebAuthn to register a passkey
/// and sign assertions the relying party verifies.
struct Authenticator {
    key: SigningKey,
    cred_id: Vec<u8>,
    counter: u32,
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

impl Authenticator {
    fn new() -> Self {
        Self { key: SigningKey::from_bytes(&[7u8; 32]), cred_id: b"bv-t544-credential".to_vec(), counter: 0 }
    }

    fn auth_data(flags: u8, counter: u32) -> Vec<u8> {
        let mut data = Sha256::digest(RP_ID.as_bytes()).as_slice().to_vec();
        data.push(flags);
        data.extend_from_slice(&counter.to_be_bytes());
        data
    }

    fn client_data(ty: &str, challenge: &str) -> Vec<u8> {
        json!({ "type": ty, "challenge": challenge, "origin": ORIGIN }).to_string().into_bytes()
    }

    /// A `none` attestation: CBOR `{"fmt": "none", "attStmt": {}, "authData": ..}`
    /// with an OKP/EdDSA/Ed25519 COSE key, encoded by hand.
    fn attestation(&self, challenge: &str) -> String {
        let mut auth_data = Self::auth_data(0x41, 0);
        auth_data.extend_from_slice(&[0u8; 16]);
        auth_data.extend_from_slice(&(self.cred_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&self.cred_id);
        auth_data.extend_from_slice(&[0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20]);
        auth_data.extend_from_slice(self.key.verifying_key().as_bytes());
        let mut object = vec![0xa3, 0x63];
        object.extend_from_slice(b"fmt");
        object.push(0x64);
        object.extend_from_slice(b"none");
        object.push(0x67);
        object.extend_from_slice(b"attStmt");
        object.extend_from_slice(&[0xa0, 0x68]);
        object.extend_from_slice(b"authData");
        object.extend_from_slice(&[0x58, u8::try_from(auth_data.len()).unwrap()]);
        object.extend_from_slice(&auth_data);
        let client_data = Self::client_data("webauthn.create", challenge);
        json!({
            "id": b64(&self.cred_id), "rawId": b64(&self.cred_id), "type": "public-key",
            "response": { "clientDataJSON": b64(&client_data), "attestationObject": b64(&object) }
        })
        .to_string()
    }

    /// An assertion over `challenge` with the next signature counter.
    fn assertion(&mut self, challenge: &str) -> String {
        self.counter += 1;
        let auth_data = Self::auth_data(0x01, self.counter);
        let client_data = Self::client_data("webauthn.get", challenge);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(Sha256::digest(&client_data).as_slice());
        let signature = self.key.sign(&signed).to_bytes();
        json!({
            "id": b64(&self.cred_id), "rawId": b64(&self.cred_id), "type": "public-key",
            "response": {
                "clientDataJSON": b64(&client_data), "authenticatorData": b64(&auth_data), "signature": b64(&signature)
            }
        })
        .to_string()
    }
}

fn challenge_of(resp: Option<Response>, pointer: &str) -> String {
    let data = Value::Object(resp.and_then(|r| r.data).expect("a challenge"));
    data.pointer(pointer).and_then(|v| v.as_str()).expect("challenge").to_string()
}

async fn configure_fido2(core: &Core, root: &str) {
    let config = json!({ "rp_id": RP_ID, "rp_origin": ORIGIN, "rp_name": "t544" });
    send(core, root, Operation::Write, "auth/up1/fido2/config", config).await.unwrap();
}

async fn register(core: &Core, root: &str, key: &Authenticator) {
    let begin = send(core, root, Operation::Write, "auth/up1/fido2/register/begin", json!({ "username": "carol" }));
    let challenge = challenge_of(begin.await.unwrap(), "/publicKey/challenge");
    let body = json!({ "username": "carol", "credential": key.attestation(&challenge) });
    send(core, root, Operation::Write, "auth/up1/fido2/register/complete", body).await.unwrap();
}

/// The body of a passkey login for carol, its challenge already issued.
async fn passkey_login_body(core: &Core, key: &mut Authenticator) -> Value {
    let begin = send(core, "", Operation::Write, "auth/up1/fido2/login/begin", json!({ "username": "carol" }));
    let challenge = challenge_of(begin.await.unwrap(), "/publicKey/challenge");
    json!({ "username": "carol", "credential": key.assertion(&challenge) })
}

fn stored_sign_count(record: &Value) -> u64 {
    let passkeys: Value = serde_json::from_str(record["credentials_json"].as_str().unwrap()).unwrap();
    passkeys[0]["sign_count"].as_u64().unwrap()
}

/// A passkey registration racing a delete does not re-create carol; one
/// racing a disable adds the key and keeps the disable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_passkey_registration_racing_a_delete_or_disable_keeps_the_admin_change() {
    let (_bvault, core, root, view) = carol("up_writes_fido2_register").await;
    configure_fido2(&core, &root).await;
    let key = Authenticator::new();
    let original = stored(&view).await.expect("carol");
    const COMPLETE: &str = "auth/up1/fido2/register/complete";

    let begin = send(&core, &root, Operation::Write, "auth/up1/fido2/register/begin", json!({ "username": "carol" }));
    let challenge = challenge_of(begin.await.unwrap(), "/publicKey/challenge");
    let body = json!({ "username": "carol", "credential": key.attestation(&challenge) });
    let outcome = while_meddling(&core, &view, &root, COMPLETE, body, None).await;
    assert!(outcome.error_contains("not found"), "{outcome:?}");
    assert!(stored(&view).await.is_none(), "carol was not re-created");

    put(&view, &original).await;
    let mut disabled = original.clone();
    disabled["disabled"] = json!(true);
    let begin = send(&core, &root, Operation::Write, "auth/up1/fido2/register/begin", json!({ "username": "carol" }));
    let challenge = challenge_of(begin.await.unwrap(), "/publicKey/challenge");
    let body = json!({ "username": "carol", "credential": key.attestation(&challenge) });
    let outcome = while_meddling(&core, &view, &root, COMPLETE, body, Some(&disabled)).await;
    assert!(outcome.error.is_none(), "{outcome:?}");
    let after = stored(&view).await.expect("carol");
    assert_eq!((after["disabled"].clone(), after["fido2_enabled"].clone()), (json!(true), json!(true)));
}

/// A passkey login is refused, and nothing is written back, when carol is
/// deleted or disabled meanwhile, or the key's counter moved past the
/// assertion meanwhile (a concurrent use or a clone).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_passkey_login_racing_a_delete_disable_or_newer_counter_is_refused() {
    let (_bvault, core, root, view) = carol("up_writes_fido2_login").await;
    configure_fido2(&core, &root).await;
    let mut key = Authenticator::new();
    register(&core, &root, &key).await;
    let original = stored(&view).await.expect("carol");
    const COMPLETE: &str = "auth/up1/fido2/login/complete";

    let body = passkey_login_body(&core, &mut key).await;
    let outcome = while_meddling(&core, &view, "", COMPLETE, body, None).await;
    assert!(outcome.token.is_none(), "no token for a deleted user: {outcome:?}");
    assert!(stored(&view).await.is_none(), "carol was not re-created");

    put(&view, &original).await;
    let mut disabled = original.clone();
    disabled["disabled"] = json!(true);
    let body = passkey_login_body(&core, &mut key).await;
    let outcome = while_meddling(&core, &view, "", COMPLETE, body, Some(&disabled)).await;
    assert!(outcome.token.is_none() && outcome.error_contains("disabled"), "{outcome:?}");
    assert_eq!(stored(&view).await.expect("carol"), disabled, "nothing written over the disable");

    put(&view, &original).await;
    let body = passkey_login_body(&core, &mut key).await;
    let mut advanced = original.clone();
    let mut passkeys: Value = serde_json::from_str(original["credentials_json"].as_str().unwrap()).unwrap();
    passkeys[0]["sign_count"] = json!(key.counter);
    advanced["credentials_json"] = json!(passkeys.to_string());
    let outcome = while_meddling(&core, &view, "", COMPLETE, body, Some(&advanced)).await;
    assert!(outcome.token.is_none() && outcome.error_contains("counter"), "{outcome:?}");
    assert_eq!(stored_sign_count(&stored(&view).await.expect("carol")), u64::from(key.counter));

    let body = passkey_login_body(&core, &mut key).await;
    let ok = send(&core, "", Operation::Write, COMPLETE, body).await.unwrap();
    assert!(ok.and_then(|r| r.auth).is_some(), "undisturbed, the passkey login succeeds");
    assert_eq!(stored_sign_count(&stored(&view).await.expect("carol")), u64::from(key.counter), "counter stored");
}

/// A passkey step-up racing a delete or a disable is refused and writes
/// nothing back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_passkey_step_up_racing_a_delete_or_disable_is_refused() {
    let (_bvault, core, root, view) = carol("up_writes_fido2_step_up").await;
    let policy = r#"path "auth/up1/v2/step-up/*" { capabilities = ["update"] }"#;
    send(&core, &root, Operation::Write, "sys/policy/step-up", json!({ "policy": policy })).await.unwrap();
    let grant = json!({ "policies": "step-up" });
    send(&core, &root, Operation::Write, "auth/up1/users/carol", grant).await.unwrap();
    configure_fido2(&core, &root).await;
    let mut key = Authenticator::new();
    register(&core, &root, &key).await;
    let body = passkey_login_body(&core, &mut key).await;
    let login = send(&core, "", Operation::Write, "auth/up1/fido2/login/complete", body).await.unwrap();
    let token = login.and_then(|r| r.auth).expect("carol signs in with her passkey").client_token;
    let original = stored(&view).await.expect("carol");
    const VERIFY: &str = "auth/up1/v2/step-up/verify";

    let mut disabled = original.clone();
    disabled["disabled"] = json!(true);
    for meddle in [None, Some(&disabled)] {
        put(&view, &original).await;
        let begin = send(&core, &token, Operation::Write, "auth/up1/v2/step-up/begin", json!({}));
        let challenge = challenge_of(begin.await.unwrap(), "/fido2/publicKey/challenge");
        let body = json!({ "method": "fido2", "credential": key.assertion(&challenge) });
        let outcome = while_meddling(&core, &view, &token, VERIFY, body, meddle).await;
        assert!(outcome.error.is_some(), "the step-up is refused: {outcome:?}");
        assert_eq!(stored(&view).await.as_ref(), meddle, "nothing written back");
    }
}
