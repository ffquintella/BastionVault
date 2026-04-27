//! SSH Secret Engine — Phase 2 (OTP mode) integration test.
//!
//! End-to-end: mount the engine, create an OTP role with a CIDR list,
//! mint an OTP, look it up, verify it (success), verify again (failure
//! — single-use), and exercise the negative paths around CIDR /
//! username enforcement.

use std::{collections::HashMap, env, fs};

use bastion_vault::{
    core::{Core, SealConfig},
    logical::{Operation, Request},
    storage, BastionVault,
};
use go_defer::defer;
use serde_json::{json, Map, Value};

#[maybe_async::maybe_async]
async fn write(
    core: &Core,
    token: &str,
    path: &str,
    body: Map<String, Value>,
) -> Option<Map<String, Value>> {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(body);
    let resp = core.handle_request(&mut req).await.expect("write failed");
    resp.and_then(|r| r.data)
}

#[maybe_async::maybe_async]
async fn write_err(
    core: &Core,
    token: &str,
    path: &str,
    body: Map<String, Value>,
) -> bastion_vault::errors::RvError {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(body);
    core.handle_request(&mut req)
        .await
        .err()
        .expect("expected write to fail")
}

#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn test_ssh_phase2_otp_end_to_end() {
    let dir = env::temp_dir().join("bastion_vault_ssh_phase2");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    defer! ( let _ = fs::remove_dir_all(&dir); );

    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert(
        "path".into(),
        Value::String(dir.to_string_lossy().into_owned()),
    );
    let backend = storage::new_backend("file", &conf).unwrap();
    let bvault = BastionVault::new(backend, None).unwrap();
    let core = bvault.core.load();
    let seal = SealConfig { secret_shares: 5, secret_threshold: 3 };
    let init = bvault.init(&seal).await.unwrap();
    for i in 0..seal.secret_threshold {
        bvault.unseal(&[&init.secret_shares[i as usize]]).await.unwrap();
    }
    let token = init.root_token.clone();

    // Mount.
    let mount_body = json!({"type": "ssh"}).as_object().unwrap().clone();
    write(&core, &token, "sys/mounts/ssh/", mount_body).await;

    // OTP role: 10.0.0.0/24 except .42, default user alice.
    let role_body = json!({
        "key_type": "otp",
        "default_user": "alice",
        "cidr_list": "10.0.0.0/24",
        "exclude_cidr_list": "10.0.0.42/32",
        "port": 2222,
        "ttl": "1m"
    })
    .as_object()
    .unwrap()
    .clone();
    write(&core, &token, "ssh/roles/otp-prod", role_body).await;

    // Negative: an OTP role without cidr_list should be rejected.
    let bad_role = json!({"key_type": "otp", "default_user": "bob"})
        .as_object()
        .unwrap()
        .clone();
    let err = write_err(&core, &token, "ssh/roles/otp-empty", bad_role).await;
    assert!(
        format!("{err}").contains("cidr_list"),
        "missing cidr_list should be flagged: {err}"
    );

    // Mint an OTP for an in-range IP. The helper would receive `key`
    // and POST it back; we drive both sides here.
    let creds_body = json!({"ip": "10.0.0.5"}).as_object().unwrap().clone();
    let creds = write(&core, &token, "ssh/creds/otp-prod", creds_body)
        .await
        .expect("creds returned no data");
    let otp = creds["key"].as_str().unwrap().to_string();
    assert_eq!(creds["username"].as_str().unwrap(), "alice");
    assert_eq!(creds["ip"].as_str().unwrap(), "10.0.0.5");
    assert_eq!(creds["port"].as_i64().unwrap(), 2222);
    // 40 hex chars = 160 bits of entropy.
    assert_eq!(otp.len(), 40);
    assert!(otp.chars().all(|c| c.is_ascii_hexdigit()));

    // Lookup surfaces the role for a matching (ip, username).
    let lookup = write(
        &core,
        &token,
        "ssh/lookup",
        json!({"ip": "10.0.0.5", "username": "alice"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await
    .expect("lookup data");
    let roles: Vec<String> = lookup["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(roles, vec!["otp-prod".to_string()]);

    // Lookup against an excluded IP returns empty.
    let lookup_excluded = write(
        &core,
        &token,
        "ssh/lookup",
        json!({"ip": "10.0.0.42"}).as_object().unwrap().clone(),
    )
    .await
    .expect("lookup data");
    let excl_roles: Vec<String> = lookup_excluded["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(excl_roles.is_empty(), "exclusion didn't take effect");

    // Negative: out-of-range IP rejected at creds time.
    let bad_ip = write_err(
        &core,
        &token,
        "ssh/creds/otp-prod",
        json!({"ip": "192.168.1.5"}).as_object().unwrap().clone(),
    )
    .await;
    assert!(
        format!("{bad_ip}").contains("cidr_list"),
        "out-of-range IP should be rejected: {bad_ip}"
    );

    // Verify (success).
    let verify_resp = write(
        &core,
        &token,
        "ssh/verify",
        json!({"otp": otp}).as_object().unwrap().clone(),
    )
    .await
    .expect("verify data");
    assert_eq!(verify_resp["username"].as_str().unwrap(), "alice");
    assert_eq!(verify_resp["ip"].as_str().unwrap(), "10.0.0.5");
    assert_eq!(verify_resp["role_name"].as_str().unwrap(), "otp-prod");
    assert_eq!(verify_resp["port"].as_i64().unwrap(), 2222);

    // Verify again (single-use enforcement).
    let replay = write_err(
        &core,
        &token,
        "ssh/verify",
        json!({"otp": otp}).as_object().unwrap().clone(),
    )
    .await;
    assert!(
        format!("{replay}").contains("invalid or expired"),
        "replay must fail: {replay}"
    );

    // Negative: bogus OTP also fails (and doesn't leak whether it
    // was ever valid).
    let unknown = write_err(
        &core,
        &token,
        "ssh/verify",
        json!({"otp": "not-a-real-otp"}).as_object().unwrap().clone(),
    )
    .await;
    assert!(
        format!("{unknown}").contains("invalid or expired"),
        "unknown otp must fail: {unknown}"
    );
}
