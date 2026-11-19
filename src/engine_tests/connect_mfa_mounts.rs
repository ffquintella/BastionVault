//! Connect-MFA step-up runs on the userpass mount the token logged in through
//! (T532).
//!
//! A userpass token's `mount_path` is the literal `userpass/` whatever mount
//! minted it, so the step-up of a second mount's user used to go to
//! `auth/userpass/`: it failed where that mount has no such user, and checked
//! the other principal's factors where a pre-T500 duplicate lives there.

use std::{sync::Arc, time::SystemTime};

use serde_json::{json, Value};

use crate::{
    core::Core,
    errors::RvError,
    kernel_api::VaultCtx,
    logical::{Operation, Request, Response},
    modules::totp::{crypto, policy::Algorithm},
    storage::{Storage, StorageEntry},
    test_utils::{new_unseal_test_bastion_vault, test_mount_api},
};

const PW: &str = "correct-horse-1";
const DAVE_SEED: [u8; 20] = [0x5a; 20];
const ERIN_SEED: [u8; 20] = [0x3c; 20];

const BEGIN: &str = "resources/v2/connect/mfa/begin";
const VERIFY: &str = "resources/v2/connect/mfa/verify";
const AUTHORIZE: &str = "resources/v2/connect/authorize";

/// Connect to `db`, run its MFA ceremony, and call the step-up routes of both
/// userpass mounts directly.
const POLICY: &str = r#"
    path "resources/v2/connect/mfa/begin"   { capabilities = ["update"] }
    path "resources/v2/connect/mfa/verify"  { capabilities = ["update"] }
    path "resources/v2/connect/authorize"   { capabilities = ["update"] }
    path "resources/secrets/db/*"           { capabilities = ["connect"] }
    path "auth/userpass/v2/step-up/begin"   { capabilities = ["update"] }
    path "auth/corp/v2/step-up/begin"       { capabilities = ["update"] }
"#;

fn totp_now(seed: &[u8]) -> String {
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    crypto::totp(seed, now, Algorithm::Sha1, 6, 30)
}

#[maybe_async::maybe_async]
async fn send(core: &Core, token: &str, op: Operation, path: &str, body: Value) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = op;
    req.client_token = token.to_string();
    req.body = body.as_object().cloned();
    core.handle_request(&mut req).await
}

async fn write(core: &Core, token: &str, path: &str, body: Value) -> Result<Option<Response>, RvError> {
    send(core, token, Operation::Write, path, body).await
}

fn data(resp: Option<Response>) -> serde_json::Map<String, Value> {
    resp.and_then(|r| r.data).unwrap_or_default()
}

/// A vault with the root userpass mount `userpass/` and a second one,
/// `corp/`; a TOTP engine holding a key per user; and resource `db` whose
/// `p_gated` profile requires MFA. erin is a user of `userpass/`, dave of
/// `corp/`, each with their own TOTP key.
async fn rig(name: &str) -> (crate::BastionVault, Arc<Core>, String) {
    let (bvault, core, root) = new_unseal_test_bastion_vault(name).await;
    for mount in ["userpass", "corp"] {
        write(&core, &root, &format!("sys/auth/{mount}"), json!({ "type": "userpass" })).await.unwrap();
    }
    test_mount_api(core.as_ref(), &root, "totp", "totp").await;
    for (key, seed) in [("dave-key", &DAVE_SEED), ("erin-key", &ERIN_SEED)] {
        let body = json!({
            "generate": false, "key": crypto::otpauth::encode_secret(seed), "digits": 6, "period": 30,
            "algorithm": "SHA1", "issuer": "BastionVault", "account_name": key,
        });
        write(&core, &root, &format!("totp/keys/{key}"), body).await.unwrap();
    }
    write(&core, &root, "sys/policy/mfa-user", json!({ "policy": POLICY })).await.unwrap();
    write(&core, &root, "resources/secrets/db/ssh", json!({ "username": "deploy", "password": "hunter2" }))
        .await
        .unwrap();
    let resource = json!({
        "name": "db", "type": "server", "os_type": "linux", "hostname": "db.internal",
        "connection_profiles": [{
            "id": "p_gated", "name": "Break-glass", "protocol": "ssh", "username": "root",
            "require_mfa": true, "credential_source": { "kind": "secret", "secret_id": "ssh" },
        }],
    });
    write(&core, &root, "resources/resources/db", resource).await.unwrap();
    for (mount, user, key) in [("userpass", "erin", "erin-key"), ("corp", "dave", "dave-key")] {
        let body = json!({ "password": PW, "policies": "mfa-user", "totp_key": key });
        write(&core, &root, &format!("auth/{mount}/users/{user}"), body).await.unwrap();
    }
    (bvault, core, root)
}

async fn login(core: &Core, mount: &str, user: &str) -> String {
    let resp = write(core, "", &format!("auth/{mount}/login/{user}"), json!({ "password": PW })).await.unwrap();
    resp.and_then(|r| r.auth).unwrap_or_else(|| panic!("{user} logs in to {mount}")).client_token
}

/// The ceremony end to end as `token`: begin offers TOTP, a wrong code mints
/// nothing, the right one mints a ticket, and the ticket opens the profile.
async fn step_up_and_connect(core: &Core, token: &str, seed: &[u8]) {
    let target = json!({ "resource": "db", "profile_id": "p_gated" });
    let begun = data(write(core, token, BEGIN, target.clone()).await.expect("begin"));
    assert_eq!(begun["methods"], json!(["totp"]), "{begun:?}");

    let wrong = json!({ "resource": "db", "profile_id": "p_gated", "method": "totp", "totp_code": "000000" });
    assert!(write(core, token, VERIFY, wrong).await.is_err(), "a wrong code mints nothing");
    let right = json!({ "resource": "db", "profile_id": "p_gated", "method": "totp", "totp_code": totp_now(seed) });
    let minted = data(write(core, token, VERIFY, right).await.expect("verify"));
    let ticket = minted["connect_ticket"].as_str().expect("a connect ticket").to_string();

    let open = json!({ "resource": "db", "profile_id": "p_gated", "connect_ticket": ticket });
    write(core, token, AUTHORIZE, open).await.expect("the ticket opens the gated profile");
}

/// A user of a second userpass mount steps up against that mount's record
/// and factors, and the ticket it mints opens the gated profile.
#[tokio::test]
async fn a_second_mounts_user_steps_up_on_its_own_mount() {
    let (_bvault, core, _root) = rig("connect_mfa_second_mount").await;
    let dave = login(&core, "corp", "dave").await;
    step_up_and_connect(&core, &dave, &DAVE_SEED).await;
}

/// The root mount's users are unchanged.
#[tokio::test]
async fn the_root_mounts_user_steps_up_as_before() {
    let (_bvault, core, _root) = rig("connect_mfa_root_mount").await;
    let erin = login(&core, "userpass", "erin").await;
    step_up_and_connect(&core, &erin, &ERIN_SEED).await;
}

/// With a pre-T500 duplicate of dave on `userpass/` (no TOTP key), dave of
/// `corp/` still steps up with his own factor, never the duplicate's; and the
/// step-up routes of a mount his token did not log in through refuse him.
#[tokio::test]
async fn a_duplicate_on_the_root_mount_lends_no_factors() {
    let (_bvault, core, _root) = rig("connect_mfa_duplicate").await;
    let corp = core.router().matching_view("auth/corp/").unwrap().expect("corp");
    let root_mount = core.router().matching_view("auth/userpass/").unwrap().expect("userpass");
    let record = corp.get("user/dave").await.unwrap().expect("dave on corp");
    let mut planted: Value = serde_json::from_slice(&record.value).unwrap();
    planted["totp_key"] = json!("");
    let value = serde_json::to_vec(&planted).unwrap();
    root_mount.put(&StorageEntry { key: "user/dave".into(), value }).await.unwrap();

    let dave = login(&core, "corp", "dave").await;
    step_up_and_connect(&core, &dave, &DAVE_SEED).await;

    let own = data(write(&core, &dave, "auth/corp/v2/step-up/begin", json!({})).await.expect("own mount"));
    assert_eq!(own["methods"], json!(["totp"]), "{own:?}");
    match write(&core, &dave, "auth/userpass/v2/step-up/begin", json!({})).await {
        Err(RvError::ErrResponseStatus(403, msg)) => assert!(msg.contains("logged in through"), "{msg}"),
        other => panic!("another mount's step-up must refuse dave's token, got {other:?}"),
    }
}
