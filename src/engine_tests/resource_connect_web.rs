//! End-to-end tests for `resources/v2/connect/web/{launch,totp,result,close}`
//! (features/web-application-connect.md, T96 Phase 2).
//!
//! They stand up a whole vault, so they live here rather than in
//! `bv-engine-resource`, whose own tests cover the recipe parser, the exposure
//! policy, TOTP and the launch-record state machine without one.

use serde_json::{json, Map, Value};

use crate::errors::RvError;
use crate::kernel_api::VaultCtx;
use crate::logical::{Operation, Request};
use crate::modules::resource::connect_mfa::{ConnectMfaTicketStore, TicketBinding};
use crate::modules::resource::connect_web::{
    launch_store::{
        launch_key, CallerIdentity, LdapCheckout, WebLaunchRecord, WebLaunchStore, LAUNCH_PREFIX, LAUNCH_RECORD_VERSION,
    },
    recipe::recipe_hash,
    totp::{code_at, TotpParams},
};
use crate::storage::{barrier_view::BarrierView, Storage, StorageEntry};
use crate::test_utils::{new_unseal_test_bastion_vault, test_write_api};

const LOGIN_PASSWORD: &str = "hunter22XX!";
/// The application's admin password stored on the resource. Searched for in
/// the barrier to prove the launch record never holds it.
const APP_PASSWORD: &str = "fw-admin-pw-7d1c9";
/// RFC 6238's SHA1 test key ("12345678901234567890") in base32.
const APP_SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

const LAUNCH: &str = "resources/v2/connect/web/launch";
const TOTP: &str = "resources/v2/connect/web/totp";
const RESULT: &str = "resources/v2/connect/web/result";
const CLOSE: &str = "resources/v2/connect/web/close";

/// A connect-only operator: may call the web-connect endpoints and connect to
/// `fw01`, and may not read its secrets.
const CONNECT_ONLY: &str = r#"
    path "resources/v2/connect/web/*" { capabilities = ["create", "update"] }
    path "resources/secrets/fw01/*"   { capabilities = ["connect"] }
"#;

/// Write through the full pipeline without printing the response (it carries
/// credentials). Errors come back as `(status, message)`.
async fn call(core: &dyn VaultCtx, token: &str, path: &str, body: Value) -> Result<Map<String, Value>, (u16, String)> {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = body.as_object().cloned();
    match core.handle_request(&mut req).await {
        Ok(resp) => Ok(resp.and_then(|r| r.data).unwrap_or_default()),
        Err(RvError::ErrResponseStatus(s, m)) => Err((s, m)),
        Err(RvError::ErrPermissionDenied) => Err((403, "permission denied".into())),
        Err(e) => Err((0, e.to_string())),
    }
}

/// Assert a refusal by status and code prefix.
fn refused(r: Result<Map<String, Value>, (u16, String)>, status: u16, code: &str) {
    match r {
        Ok(d) => panic!("expected {status} {code}, got success with keys {:?}", d.keys().collect::<Vec<_>>()),
        Err((s, m)) => {
            assert_eq!(s, status, "status for `{code}`: {m}");
            assert!(m.starts_with(code), "expected code `{code}`, got `{m}`");
        }
    }
}

async fn root_write(core: &dyn VaultCtx, root: &str, path: &str, body: Value) {
    test_write_api(core, root, path, true, body.as_object().cloned()).await.unwrap();
}

/// A userpass user at `userpass/` (the mount the connect-MFA gate accepts)
/// carrying `policy_hcl`; returns its token.
async fn userpass_user(core: &dyn VaultCtx, root: &str, user: &str, policy_hcl: &str) -> String {
    // Mounted on the first call; later calls get "path already in use",
    // which is the expected outcome, so the result is not asserted.
    let _ = call(core, root, "sys/auth/userpass", json!({ "type": "userpass" })).await;
    root_write(core, root, &format!("sys/policy/p-{user}"), json!({ "policy": policy_hcl })).await;
    root_write(
        core,
        root,
        &format!("auth/userpass/users/{user}"),
        json!({ "password": LOGIN_PASSWORD, "token_policies": format!("p-{user}"), "ttl": 0 }),
    )
    .await;
    let mut req = Request::new(format!("auth/userpass/login/{user}"));
    req.operation = Operation::Write;
    req.body = json!({ "password": LOGIN_PASSWORD }).as_object().cloned();
    core.handle_request(&mut req).await.unwrap().unwrap().auth.unwrap().client_token
}

fn recipe(with_totp: bool) -> Value {
    let mut steps = vec![json!({
        "when_url": "https://fw01.example.com/login*",
        "actions": [
            { "fill": "#user", "value": "username" },
            { "fill": "#pass", "value": "password" },
            { "submit": "form" }
        ]
    })];
    if with_totp {
        steps.push(json!({
            "when_url": "https://fw01.example.com/2fa*",
            "actions": [ { "fill": "#otp", "value": "totp" }, { "submit": "form" } ]
        }));
    }
    json!({ "version": 1, "steps": steps, "success_when": { "url": "https://fw01.example.com/ng/*" } })
}

fn web_profile(id: &str, recipe: Value, credential_source: Value) -> Value {
    json!({
        "id": id,
        "name": id,
        "protocol": "web",
        "credential_source": credential_source,
        "web": {
            "start_url": "https://fw01.example.com/login",
            "allowed_origins": [],
            "login_mode": "form",
            "recipe": recipe
        }
    })
}

fn secret_source() -> Value {
    json!({ "kind": "secret", "secret_id": "admin" })
}

/// `fw01`, a `web_application` with the given profiles and extra metadata,
/// plus its admin secret.
async fn seed_fw01(core: &dyn VaultCtx, root: &str, profiles: Vec<Value>, extra: Value) {
    let mut meta = json!({ "name": "fw01", "type": "web_application", "connection_profiles": profiles });
    for (k, v) in extra.as_object().cloned().unwrap_or_default() {
        meta[k] = v;
    }
    root_write(core, root, "resources/resources/fw01", meta).await;
    root_write(
        core,
        root,
        "resources/secrets/fw01/admin",
        json!({ "username": "admin", "password": APP_PASSWORD, "totp_seed": APP_SEED }),
    )
    .await;
}

fn launch_body(profile_id: &str, recipe: &Value) -> Value {
    json!({ "resource": "fw01", "profile_id": profile_id, "recipe_hash": recipe_hash(recipe).unwrap() })
}

/// Every value stored under the launch-record prefix, as text.
async fn launch_records_text(core: &dyn VaultCtx) -> String {
    let view = BarrierView::new(core.barrier().clone(), "");
    let mut out = String::new();
    for k in view.list(LAUNCH_PREFIX).await.unwrap() {
        if let Some(e) = view.get(&format!("{LAUNCH_PREFIX}{k}")).await.unwrap() {
            out.push_str(&String::from_utf8_lossy(&e.value));
        }
    }
    out
}

fn plausible_totp(code: &str) -> bool {
    let key = b"12345678901234567890";
    let now = chrono::Utc::now().timestamp() as u64;
    [now - 30, now, now + 30].iter().any(|t| code_at(key, TotpParams::default(), *t).code.as_str() == code)
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn form_launch_is_connect_only_and_its_lifecycle_is_single_use() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_web_connect_lifecycle").await;
    let r = recipe(true);
    seed_fw01(&core, &root, vec![web_profile("p_web", r.clone(), secret_source())], json!({})).await;
    let alice = userpass_user(&core, &root, "alice", CONNECT_ONLY).await;

    // Connect-only: alice cannot read the secret herself …
    let mut read = Request::new("resources/secrets/fw01/admin");
    read.operation = Operation::Read;
    read.client_token = alice.clone();
    assert!(core.handle_request(&mut read).await.is_err(), "connect-only must not read the secret");

    // … the recipe hash is mandatory and must match the stored recipe …
    let mut no_hash = launch_body("p_web", &r);
    no_hash.as_object_mut().unwrap().remove("recipe_hash");
    refused(call(&core, &alice, LAUNCH, no_hash).await, 400, "recipe_hash_required");
    let mut stale = launch_body("p_web", &r);
    stale["recipe_hash"] = json!(recipe_hash(&recipe(false)).unwrap());
    refused(call(&core, &alice, LAUNCH, stale).await, 409, "recipe_hash_mismatch");

    // … and yet the launch releases exactly what the recipe fills.
    let bundle = call(&core, &alice, LAUNCH, launch_body("p_web", &r)).await.unwrap();
    let cred = bundle["credential"].as_object().unwrap();
    assert_eq!(cred["username"], json!("admin"));
    assert_eq!(cred["password"], json!(APP_PASSWORD));
    assert!(plausible_totp(cred["totp"].as_str().unwrap()), "a current RFC 6238 code");
    assert!(cred.contains_key("totp_valid_until"));
    let text = serde_json::to_string(&bundle).unwrap();
    assert!(!text.contains(APP_SEED), "the TOTP seed never leaves the server");
    assert_eq!(bundle["login_mode"], json!("form"));
    assert_eq!(bundle["exposure"], json!("dom"));
    assert_eq!(bundle["recipe_hash"], json!(recipe_hash(&r).unwrap()));
    assert_eq!(bundle["totp_refresh_steps"], json!([1]));
    assert_eq!(bundle["mfa_method"], Value::Null);
    let launch_id = bundle["launch_id"].as_str().unwrap().to_string();

    // The record is keyed by hash and holds no credential.
    let stored = launch_records_text(&core).await;
    assert!(stored.contains("\"recipe_hash\""));
    for secret in [APP_PASSWORD, APP_SEED, launch_id.as_str()] {
        assert!(!stored.contains(secret), "the launch record must not hold `{secret}`");
    }

    // TOTP: one refresh per TOTP step, only for TOTP steps.
    refused(call(&core, &alice, TOTP, json!({ "launch_id": launch_id, "step": 0 })).await, 400, "totp_step_invalid");
    let fresh = call(&core, &alice, TOTP, json!({ "launch_id": launch_id, "step": 1 })).await.unwrap();
    assert!(plausible_totp(fresh["totp"].as_str().unwrap()));
    assert_eq!(fresh["totp_refresh_steps"], json!([]));
    refused(call(&core, &alice, TOTP, json!({ "launch_id": launch_id, "step": 1 })).await, 409, "totp_step_used");

    // Result: once; a repeat is idempotent, a different outcome a conflict.
    refused(
        call(&core, &alice, RESULT, json!({ "launch_id": launch_id, "outcome": "done" })).await,
        400,
        "invalid_outcome",
    );
    let res =
        call(&core, &alice, RESULT, json!({ "launch_id": launch_id, "outcome": "success", "step": 1 })).await.unwrap();
    assert_eq!(res["already_recorded"], json!(false));
    let res =
        call(&core, &alice, RESULT, json!({ "launch_id": launch_id, "outcome": "success", "step": 1 })).await.unwrap();
    assert_eq!(res["already_recorded"], json!(true));
    refused(
        call(&core, &alice, RESULT, json!({ "launch_id": launch_id, "outcome": "aborted:origin" })).await,
        409,
        "result_conflict",
    );

    // Close: idempotent, and nothing works on the launch afterwards.
    let closed = call(&core, &alice, CLOSE, json!({ "launch_id": launch_id })).await.unwrap();
    assert_eq!(closed["already_closed"], json!(false));
    assert_eq!(closed["ldap_checkin"], json!("not_applicable"));
    let again = call(&core, &alice, CLOSE, json!({ "launch_id": launch_id })).await.unwrap();
    assert_eq!(again["already_closed"], json!(true));
    refused(call(&core, &alice, TOTP, json!({ "launch_id": launch_id, "step": 1 })).await, 409, "launch_closed");
    refused(
        call(&core, &alice, RESULT, json!({ "launch_id": launch_id, "outcome": "success" })).await,
        409,
        "launch_closed",
    );
    refused(call(&core, &alice, CLOSE, json!({ "launch_id": "never-issued" })).await, 404, "launch_unknown");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn launch_refuses_profiles_and_callers_it_cannot_serve() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_web_connect_refusals").await;
    let r = recipe(true);
    let mut open = web_profile("p_open", r.clone(), json!({ "kind": "none" }));
    open["web"]["login_mode"] = json!("open");
    let ssh = json!({ "id": "p_ssh", "name": "ssh", "protocol": "ssh", "credential_source": secret_source() });
    let no_totp_source = web_profile(
        "p_ldap",
        r.clone(),
        json!({ "kind": "ldap", "ldap_mount": "openldap", "bind_mode": "library_set", "library_set": "web-admins" }),
    );
    let mut bad_recipe = web_profile("p_bad", r.clone(), secret_source());
    bad_recipe["web"]["recipe"]["steps"][0]["actions"][0]["value"] = json!("hunter2");
    seed_fw01(
        &core,
        &root,
        vec![open, ssh, no_totp_source, bad_recipe, web_profile("p_web", r.clone(), secret_source())],
        json!({}),
    )
    .await;

    refused(call(&core, &root, LAUNCH, launch_body("p_ssh", &r)).await, 400, "wrong_protocol");
    refused(call(&core, &root, LAUNCH, launch_body("p_open", &r)).await, 400, "wrong_login_mode");
    refused(call(&core, &root, LAUNCH, launch_body("p_ldap", &r)).await, 422, "totp_not_configured");
    refused(call(&core, &root, LAUNCH, launch_body("p_bad", &r)).await, 422, "invalid_recipe");
    refused(call(&core, &root, LAUNCH, launch_body("p_missing", &r)).await, 404, "profile_not_found");

    // A caller who may hit the endpoint but holds no connect grant on fw01.
    let bob = userpass_user(
        &core,
        &root,
        "bob",
        r#"path "resources/v2/connect/web/*" { capabilities = ["create", "update"] }"#,
    )
    .await;
    refused(call(&core, &bob, LAUNCH, launch_body("p_web", &r)).await, 403, "permission denied");

    // A recipe that fills `totp` when the secret has no seed.
    root_write(&core, &root, "resources/secrets/fw01/admin", json!({ "username": "admin", "password": APP_PASSWORD }))
        .await;
    refused(call(&core, &root, LAUNCH, launch_body("p_web", &r)).await, 422, "totp_not_configured");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn exposure_and_heuristic_policy_are_enforced_at_both_tiers() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_web_connect_exposure").await;
    let r = recipe(false);
    let auto = json!({ "version": 1, "steps": "auto", "success_when": { "selector": "#dashboard" } });
    let profiles = || {
        vec![
            web_profile("p_web", recipe(false), secret_source()),
            web_profile(
                "p_auto",
                json!({ "version": 1, "steps": "auto", "success_when": { "selector": "#dashboard" } }),
                secret_source(),
            ),
        ]
    };

    // No tier set: form is allowed, heuristics are not.
    seed_fw01(&core, &root, profiles(), json!({})).await;
    assert!(call(&core, &root, LAUNCH, launch_body("p_web", &r)).await.is_ok());
    refused(call(&core, &root, LAUNCH, launch_body("p_auto", &auto)).await, 403, "heuristic_not_allowed");

    // Type tier caps below `dom`.
    root_write(&core, &root, "resources/config/types", json!({ "web_application": { "id": "web_application", "fields": [], "connect": { "web_exposure_max": "handler" } } })).await;
    refused(call(&core, &root, LAUNCH, launch_body("p_web", &r)).await, 403, "exposure_cap_exceeded");

    // Type tier allows `dom`; the resource tier caps at `isolated` — the stricter wins.
    root_write(&core, &root, "resources/config/types", json!({ "web_application": { "id": "web_application", "fields": [], "connect": { "web_exposure_max": "dom" } } })).await;
    seed_fw01(&core, &root, profiles(), json!({ "web_exposure_max": "isolated" })).await;
    refused(call(&core, &root, LAUNCH, launch_body("p_web", &r)).await, 403, "exposure_cap_exceeded");

    // An unrecognised cap fails closed instead of reading as unset.
    seed_fw01(&core, &root, profiles(), json!({ "web_exposure_max": "everything" })).await;
    refused(call(&core, &root, LAUNCH, launch_body("p_web", &r)).await, 422, "exposure_policy_invalid");

    // Heuristic fill enabled on the resource …
    seed_fw01(&core, &root, profiles(), json!({ "allow_heuristic_fill": true })).await;
    let b = call(&core, &root, LAUNCH, launch_body("p_auto", &auto)).await.unwrap();
    assert_eq!(b["heuristic"], json!(true));
    // … but an explicit `false` on the type beats it.
    root_write(&core, &root, "resources/config/types", json!({ "web_application": { "id": "web_application", "fields": [], "connect": { "allow_heuristic_fill": false } } })).await;
    refused(call(&core, &root, LAUNCH, launch_body("p_auto", &auto)).await, 403, "heuristic_not_allowed");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_gated_launch_burns_its_mfa_ticket() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_web_connect_mfa").await;
    let r = recipe(false);
    let mut gated = web_profile("p_gated", r.clone(), secret_source());
    gated["require_mfa"] = json!(true);
    seed_fw01(&core, &root, vec![gated, web_profile("p_web", r.clone(), secret_source())], json!({})).await;
    let alice = userpass_user(&core, &root, "alice", CONNECT_ONLY).await;

    refused(call(&core, &alice, LAUNCH, launch_body("p_gated", &r)).await, 403, "mfa_required");

    let store = ConnectMfaTicketStore::new(&core).unwrap();
    let binding = |profile_id: &str| TicketBinding {
        mount: "userpass/".into(),
        principal: "alice".into(),
        namespace: String::new(),
        resource: "fw01".into(),
        profile_id: profile_id.into(),
    };

    // A ticket minted for another profile is refused (and burnt).
    let (other, _) = store.mint(&binding("p_web"), "totp").await.unwrap();
    let mut body = launch_body("p_gated", &r);
    body["connect_ticket"] = json!(other);
    assert!(call(&core, &alice, LAUNCH, body).await.is_err());

    let (ticket, _) = store.mint(&binding("p_gated"), "totp").await.unwrap();
    let mut body = launch_body("p_gated", &r);
    body["connect_ticket"] = json!(ticket);
    let bundle = call(&core, &alice, LAUNCH, body.clone()).await.unwrap();
    assert_eq!(bundle["mfa_method"], json!("totp"));
    // Spent.
    assert!(call(&core, &alice, LAUNCH, body).await.is_err(), "a ticket redeems exactly one launch");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_launch_id_is_bound_to_its_principal_and_login_window() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_web_connect_binding").await;
    let r = recipe(true);
    seed_fw01(&core, &root, vec![web_profile("p_web", r.clone(), secret_source())], json!({})).await;
    let alice = userpass_user(&core, &root, "alice", CONNECT_ONLY).await;
    let mallory = userpass_user(&core, &root, "mallory", CONNECT_ONLY).await;

    let bundle = call(&core, &alice, LAUNCH, launch_body("p_web", &r)).await.unwrap();
    let launch_id = bundle["launch_id"].as_str().unwrap().to_string();

    // Another principal — with the very same grants — cannot use it.
    refused(
        call(&core, &mallory, TOTP, json!({ "launch_id": launch_id, "step": 1 })).await,
        403,
        "launch_binding_mismatch",
    );
    refused(
        call(&core, &mallory, RESULT, json!({ "launch_id": launch_id, "outcome": "success" })).await,
        403,
        "launch_binding_mismatch",
    );
    refused(call(&core, &mallory, CLOSE, json!({ "launch_id": launch_id })).await, 403, "launch_binding_mismatch");

    // Past the login window no TOTP is issued, but the session can still close.
    let view = BarrierView::new(core.barrier().clone(), "");
    let key = launch_key(&launch_id);
    let mut record: WebLaunchRecord = serde_json::from_slice(&view.get(&key).await.unwrap().unwrap().value).unwrap();
    record.login_expires_at_ms = chrono::Utc::now().timestamp_millis() - 1;
    view.put(&StorageEntry { key, value: serde_json::to_vec(&record).unwrap() }).await.unwrap();
    refused(call(&core, &alice, TOTP, json!({ "launch_id": launch_id, "step": 1 })).await, 410, "launch_expired");
    assert!(call(&core, &alice, CLOSE, json!({ "launch_id": launch_id })).await.is_ok());
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn totp_is_refused_on_a_launch_without_it() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_web_connect_no_totp").await;
    let r = recipe(false);
    seed_fw01(&core, &root, vec![web_profile("p_web", r.clone(), secret_source())], json!({})).await;
    let alice = userpass_user(&core, &root, "alice", CONNECT_ONLY).await;
    let bundle = call(&core, &alice, LAUNCH, launch_body("p_web", &r)).await.unwrap();
    assert!(!bundle["credential"].as_object().unwrap().contains_key("totp"), "nothing the recipe does not fill");
    let launch_id = bundle["launch_id"].as_str().unwrap();
    refused(call(&core, &alice, TOTP, json!({ "launch_id": launch_id, "step": 0 })).await, 409, "totp_not_configured");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn default_account_source_releases_the_callers_own_username_only() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_web_connect_default_account").await;
    let username_only = json!({
        "version": 1,
        "steps": [ { "when_url": "https://fw01.example.com/login*",
                     "actions": [ { "fill": "#user", "value": "username" } ] } ],
        "success_when": { "selector": "#dashboard" }
    });
    seed_fw01(
        &core,
        &root,
        vec![web_profile("p_da", username_only.clone(), json!({ "kind": "default-account" }))],
        json!({}),
    )
    .await;
    let alice = userpass_user(&core, &root, "alice", CONNECT_ONLY).await;

    // Resolved as alice: she has no default account yet.
    refused(call(&core, &alice, LAUNCH, launch_body("p_da", &username_only)).await, 422, "credential_unavailable");

    call(
        &core,
        &alice,
        "sys/identity/default-account/self",
        json!({ "linux": "alice.ops", "windows_password": "win-pw-1" }),
    )
    .await
    .unwrap();
    let bundle = call(&core, &alice, LAUNCH, launch_body("p_da", &username_only)).await.unwrap();
    assert_eq!(bundle["credential"], json!({ "username": "alice.ops" }));
    assert!(!serde_json::to_string(&bundle).unwrap().contains("win-pw-1"));
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn close_reports_a_failed_ldap_checkin_and_retries_it() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_web_connect_ldap_close").await;
    let alice = userpass_user(&core, &root, "alice", CONNECT_ONLY).await;

    // A launch that checked an account out of a mount which no longer
    // answers. No LDAP server is needed to prove close reaches for it.
    let now = chrono::Utc::now().timestamp_millis();
    let record = WebLaunchRecord {
        v: LAUNCH_RECORD_VERSION,
        caller: CallerIdentity { mount: "userpass/".into(), principal: "alice".into(), namespace: String::new() },
        resource: "fw01".into(),
        profile_id: "p_ldap".into(),
        recipe_hash: "sha256:00".into(),
        login_mode: "form".into(),
        exposure: "dom".into(),
        credential_kind: "ldap".into(),
        mfa_method: None,
        issued_at_ms: now,
        login_expires_at_ms: now + 60_000,
        step_count: 1,
        totp: None,
        ldap: Some(LdapCheckout {
            mount: "gone-ldap/".into(),
            library_set: "web-admins".into(),
            account: "svc-web-1".into(),
            lease_id: "ldap-library-x".into(),
            checked_in: false,
        }),
        result: None,
        closed_at_ms: None,
    };
    let store = WebLaunchStore::new(&*core);
    let launch_id = store.create(&record).await.unwrap();

    refused(call(&core, &alice, CLOSE, json!({ "launch_id": launch_id })).await, 502, "ldap_checkin_failed");
    let caller = CallerIdentity { mount: "userpass/".into(), principal: "alice".into(), namespace: String::new() };
    let (_, after) = store.load(&launch_id, &caller).await.unwrap();
    assert!(after.closed_at_ms.is_some(), "the close itself is recorded");
    assert!(!after.ldap.as_ref().unwrap().checked_in, "the check-in stays pending");
    // A repeated close retries rather than reporting success it did not earn.
    refused(call(&core, &alice, CLOSE, json!({ "launch_id": launch_id })).await, 502, "ldap_checkin_failed");
}

// ── Rustion transport policy ───────────────────────────────────────

/// Mint a connect-MFA ticket for alice on `fw01`'s `profile_id`.
async fn alice_ticket(core: &dyn VaultCtx, profile_id: &str) -> String {
    let store = ConnectMfaTicketStore::new(core).unwrap();
    let binding = TicketBinding {
        mount: "userpass/".into(),
        principal: "alice".into(),
        namespace: String::new(),
        resource: "fw01".into(),
        profile_id: profile_id.into(),
    };
    store.mint(&binding, "totp").await.unwrap().0
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn rustion_required_refuses_before_the_ticket_or_the_credential() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_web_connect_transport").await;
    let r = recipe(false);
    let mut gated = web_profile("p_gated", r.clone(), secret_source());
    gated["require_mfa"] = json!(true);
    seed_fw01(&core, &root, vec![gated, web_profile("p_web", r.clone(), secret_source())], json!({})).await;
    let alice = userpass_user(&core, &root, "alice", CONNECT_ONLY).await;

    // `rustion-required` on the resource tier.
    root_write(&core, &root, "rustion/policy/resource/fw01", json!({ "transport": "rustion-required" })).await;
    let ticket = alice_ticket(&core, "p_gated").await;
    let mut body = launch_body("p_gated", &r);
    body["connect_ticket"] = json!(ticket);
    refused(call(&core, &alice, LAUNCH, body.clone()).await, 403, "transport_policy");
    refused(call(&core, &alice, LAUNCH, launch_body("p_web", &r)).await, 403, "transport_policy");
    assert!(launch_records_text(&core).await.is_empty(), "no launch, so no credential, was recorded");

    // `rustion-preferred` is allowed — and the refused launch did not burn
    // the ticket: the same one redeems now.
    root_write(&core, &root, "rustion/policy/resource/fw01", json!({ "transport": "rustion-preferred" })).await;
    let bundle = call(&core, &alice, LAUNCH, body).await.unwrap();
    assert_eq!(bundle["mfa_method"], json!("totp"));
    assert_eq!(bundle["credential"]["password"], json!(APP_PASSWORD));

    // `direct` is allowed.
    root_write(&core, &root, "rustion/policy/resource/fw01", json!({ "transport": "direct" })).await;
    assert!(call(&core, &alice, LAUNCH, launch_body("p_web", &r)).await.is_ok());

    // A lock violation refuses even though the effective transport
    // (`rustion-preferred`) on its own would be allowed: global locks the
    // floor, and the resource tier's `direct` now breaks it.
    root_write(&core, &root, "rustion/policy/global", json!({ "transport": "rustion-preferred", "lock": true })).await;
    match call(&core, &alice, LAUNCH, launch_body("p_web", &r)).await {
        Err((403, m)) => assert!(m.starts_with("transport_policy: rustion policy lock violation"), "{m}"),
        other => {
            panic!("expected a lock-violation refusal, got {:?}", other.map(|d| d.keys().cloned().collect::<Vec<_>>()))
        }
    }
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn an_unreadable_transport_policy_fails_closed() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_web_connect_transport_error").await;
    let r = recipe(false);
    seed_fw01(&core, &root, vec![web_profile("p_web", r.clone(), secret_source())], json!({})).await;

    // A resource-tier record Rustion cannot decode.
    let view = core.system_view().unwrap().new_sub_view("rustion/policy/resource/");
    view.put(&StorageEntry { key: "fw01".into(), value: b"{ not json".to_vec() }).await.unwrap();
    refused(call(&core, &root, LAUNCH, launch_body("p_web", &r)).await, 503, "transport_policy_unavailable");
    assert!(launch_records_text(&core).await.is_empty());
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn no_rustion_mount_means_no_transport_policy() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_web_connect_no_rustion").await;
    let r = recipe(false);
    seed_fw01(&core, &root, vec![web_profile("p_web", r.clone(), secret_source())], json!({})).await;

    let mut unmount = Request::new("sys/mounts/rustion");
    unmount.operation = Operation::Delete;
    unmount.client_token = root.clone();
    core.handle_request(&mut unmount).await.unwrap();

    // Pinned: with no `rustion/` mount no Rustion policy can exist, so the
    // launch is not refused for transport.
    let bundle = call(&core, &root, LAUNCH, launch_body("p_web", &r)).await.unwrap();
    assert_eq!(bundle["credential"]["password"], json!(APP_PASSWORD));
}
