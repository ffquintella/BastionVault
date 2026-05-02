//! Cert-lifecycle renewal scheduler — Phase L6 of the PKI
//! key-management + lifecycle initiative. See
//! [features/pki-key-management-and-lifecycle.md].
//!
//! Coverage:
//! 1. `enabled = true` with no `client_token` is rejected at config
//!    write time.
//! 2. With config disabled, `run_cert_lifecycle_pass` is a no-op for
//!    a fresh target (state stays unset).
//! 3. With config enabled + a never-issued target,
//!    `run_cert_lifecycle_pass` fires the renewal, populates state,
//!    and writes the bundle to the target's address.
//! 4. With a healthy in-window target, a second pass does NOT fire
//!    (the L4 NotAfter clamp keeps `current_not_after` in the future
//!    relative to `renew_before`).
//! 5. Failure path: pointing the target at a non-existent address
//!    increments `failure_count`, sets `last_error`, and pushes
//!    `next_attempt_unix` into the future per the backoff config.
//!    A second pass *before* the backoff expires is a no-op.

use std::{collections::HashMap, env, fs, sync::Arc};

use bastion_vault::{
    core::{Core, SealConfig},
    logical::{Operation, Request},
    modules::cert_lifecycle::scheduler::run_cert_lifecycle_pass,
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
) -> Result<Option<Map<String, Value>>, String> {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(body);
    core.handle_request(&mut req)
        .await
        .map(|r| r.and_then(|x| x.data))
        .map_err(|e| format!("{e:?}"))
}

#[maybe_async::maybe_async]
async fn read(core: &Core, token: &str, path: &str) -> Map<String, Value> {
    let mut req = Request::new(path);
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await.unwrap_or_else(|e| panic!("read {path}: {e:?}"));
    resp.and_then(|r| r.data).unwrap_or_else(|| panic!("read {path}: empty response"))
}

fn boot() -> (BastionVault, std::path::PathBuf) {
    use rand::RngExt;
    let n: u32 = rand::rng().random();
    let dir = env::temp_dir().join(format!("bastion_vault_cert_lifecycle_sched_{n:08x}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));
    let backend = storage::new_backend("file", &conf).unwrap();
    let bvault = BastionVault::new(backend, None).unwrap();
    (bvault, dir)
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_cert_lifecycle_scheduler_l6() {
    let (bvault, dir) = boot();
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core_arc: Arc<Core> = bvault.core.load_full();
    let core: &Core = &core_arc;
    let seal = SealConfig { secret_shares: 5, secret_threshold: 3 };
    let init = bvault.init(&seal).await.unwrap();
    for i in 0..seal.secret_threshold {
        bvault.unseal(&[&init.secret_shares[i as usize]]).await.unwrap();
    }
    let token = init.root_token.clone();

    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone())
        .await.expect("mount pki");
    write(&core, &token, "sys/mounts/cert-lifecycle/",
        json!({"type": "cert-lifecycle"}).as_object().unwrap().clone(),
    ).await.expect("mount cert-lifecycle");
    write(&core, &token, "pki/root/generate/internal",
        json!({"common_name": "L6 Root", "key_type": "ec", "ttl": "8760h"}).as_object().unwrap().clone(),
    ).await.expect("root");
    write(&core, &token, "pki/roles/web",
        json!({
            "ttl": "168h", "max_ttl": "720h", "key_type": "ec",
            "allow_any_name": true, "server_flag": true, "client_flag": true,
        }).as_object().unwrap().clone(),
    ).await.expect("role");

    // ── 1. Config validation: enabled without token rejected ─────────
    let bad = write(&core, &token, "cert-lifecycle/scheduler/config",
        json!({"enabled": true}).as_object().unwrap().clone(),
    ).await;
    assert!(bad.is_err(), "enabled=true without token must reject: {bad:?}");

    // Set config disabled. Pass should be a no-op.
    let happy_dir = dir.join("happy");
    fs::create_dir_all(&happy_dir).unwrap();
    let happy_str = happy_dir.to_string_lossy().into_owned();
    write(&core, &token, "cert-lifecycle/targets/happy",
        json!({
            "role_ref": "web",
            "common_name": "happy.example.com",
            "address": &happy_str,
            "renew_before": "1h",
        }).as_object().unwrap().clone(),
    ).await.expect("write happy target");

    // ── 2. Disabled scheduler does nothing ───────────────────────────
    run_cert_lifecycle_pass(&core_arc, None).await.expect("disabled pass");
    let s0 = read(&core, &token, "cert-lifecycle/state/happy").await;
    assert_eq!(s0["current_serial"].as_str().unwrap(), "");

    // Configure scheduler with the root token (any valid token works).
    write(&core, &token, "cert-lifecycle/scheduler/config",
        json!({
            "enabled": true,
            "client_token": token.clone(),
            "tick_interval_seconds": 30,
            "base_backoff_seconds": 60,
            "max_backoff_seconds": 3600,
        }).as_object().unwrap().clone(),
    ).await.expect("write scheduler config");

    // Confirm `client_token` is not echoed by the read endpoint.
    let cfg_read = read(&core, &token, "cert-lifecycle/scheduler/config").await;
    assert_eq!(cfg_read["enabled"].as_bool().unwrap(), true);
    assert_eq!(cfg_read["client_token_set"].as_bool().unwrap(), true);
    assert!(cfg_read.get("client_token").is_none());

    // ── 3. Enabled + due target → fires ──────────────────────────────
    run_cert_lifecycle_pass(&core_arc, None).await.expect("first pass");
    let s1 = read(&core, &token, "cert-lifecycle/state/happy").await;
    assert!(!s1["current_serial"].as_str().unwrap().is_empty(),
        "first pass should populate current_serial; state={s1:?}");
    assert!(s1["last_renewal"].as_u64().unwrap() > 0);
    assert_eq!(s1["last_error"].as_str().unwrap(), "");
    assert_eq!(s1["failure_count"].as_u64().unwrap(), 0);
    assert!(s1["next_attempt"].as_u64().unwrap() > 0,
        "scheduler must populate next_attempt; state={s1:?}");

    // Files written.
    assert!(happy_dir.join("cert.pem").exists());
    assert!(happy_dir.join("key.pem").exists());
    assert!(happy_dir.join("chain.pem").exists());
    let serial1 = s1["current_serial"].as_str().unwrap().to_string();

    // ── 4. Healthy in-window target → second pass is a no-op ─────────
    // Re-run the pass. The target is healthy and not yet inside the
    // `renew_before` window, AND `next_attempt_unix` is in the future,
    // so `is_due` should return false → no new cert.
    let last_fired = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    run_cert_lifecycle_pass(&core_arc, Some(last_fired.clone())).await.expect("second pass");
    let s2 = read(&core, &token, "cert-lifecycle/state/happy").await;
    assert_eq!(s2["current_serial"].as_str().unwrap(), serial1,
        "second pass must not re-renew a healthy target");

    // ── 5. Failure path: invalid address → backoff ───────────────────
    let bogus_dir = dir.join("nope-does-not-exist");
    let bogus_str = bogus_dir.to_string_lossy().into_owned();
    write(&core, &token, "cert-lifecycle/targets/sad",
        json!({
            "role_ref": "web",
            "common_name": "sad.example.com",
            "address": &bogus_str,
            "renew_before": "1h",
        }).as_object().unwrap().clone(),
    ).await.expect("write sad target");

    run_cert_lifecycle_pass(&core_arc, None).await.expect("failing pass");
    let s_sad = read(&core, &token, "cert-lifecycle/state/sad").await;
    assert_eq!(s_sad["current_serial"].as_str().unwrap(), "",
        "failing renew must not set current_serial");
    assert_eq!(s_sad["failure_count"].as_u64().unwrap(), 1);
    assert!(s_sad["last_error"].as_str().unwrap().contains("delivery failed")
            || s_sad["last_error"].as_str().unwrap().contains("issuance failed"),
        "expected meaningful last_error, got {:?}", s_sad["last_error"]);
    let next1 = s_sad["next_attempt"].as_u64().unwrap();
    assert!(next1 > 0, "backoff must populate next_attempt");

    // Second pass before backoff expires → still failure_count=1, no
    // additional attempt recorded (next_attempt_unix is in the
    // future → is_due rejects).
    let last_fired2 = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    run_cert_lifecycle_pass(&core_arc, Some(last_fired2)).await.expect("backoff pass");
    let s_sad2 = read(&core, &token, "cert-lifecycle/state/sad").await;
    assert_eq!(s_sad2["failure_count"].as_u64().unwrap(), 1,
        "in-backoff target must not retry");
}
