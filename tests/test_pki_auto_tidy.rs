//! PKI Secret Engine — Phase 4.1 (auto-tidy scheduler) integration test.
//!
//! Drives the scheduler deterministically via
//! [`bastion_vault::modules::pki::scheduler::run_pki_tidy_pass`] rather than
//! waiting on the real 30 s tick. Asserts that:
//!
//! - With `auto-tidy.enabled=false`, a sweep does not fire (status remains
//!   default, `source` empty).
//! - With `auto-tidy.enabled=true` and a fresh `last_fired` map, the next
//!   pass fires immediately and `tidy/status.source = "auto"`.
//! - Within the interval window, a second pass with the *same* `last_fired`
//!   map does not re-fire (status timestamp unchanged).

use std::{collections::HashMap, env, fs, sync::Arc, thread, time::Duration};

use bastion_vault::{
    core::{Core, SealConfig},
    logical::{Operation, Request},
    modules::pki::scheduler,
    storage, BastionVault,
};
use go_defer::defer;
use serde_json::{json, Map, Value};
use tokio::sync::Mutex;

#[maybe_async::maybe_async]
async fn write(core: &Core, token: &str, path: &str, body: Map<String, Value>) -> Option<Map<String, Value>> {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(body);
    let resp = core.handle_request(&mut req).await.expect("write failed");
    resp.and_then(|r| r.data)
}

#[maybe_async::maybe_async]
async fn read(core: &Core, token: &str, path: &str) -> Option<Map<String, Value>> {
    let mut req = Request::new(path);
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await.expect("read failed");
    resp.and_then(|r| r.data)
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_pki_phase4_1_auto_tidy_scheduler() {
    let dir = env::temp_dir().join("bastion_vault_pki_phase4_1_auto_tidy");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    defer! ( let _ = fs::remove_dir_all(&dir); );

    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));
    let backend = storage::new_backend("file", &conf).unwrap();
    let bvault = BastionVault::new(backend, None).unwrap();
    let core = bvault.core.load();
    let seal = SealConfig { secret_shares: 5, secret_threshold: 3 };
    let init = bvault.init(&seal).await.unwrap();
    for i in 0..seal.secret_threshold {
        bvault.unseal(&[&init.secret_shares[i as usize]]).await.unwrap();
    }
    let token = init.root_token.clone();

    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone()).await;

    write(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({"common_name": "auto-tidy-root.example.com", "key_type": "ec", "ttl": "8760h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;

    write(
        &core,
        &token,
        "pki/roles/short",
        json!({
            "ttl": "1s",
            "max_ttl": "10s",
            "key_type": "ec",
            "allow_any_name": true,
            "server_flag": true,
            "not_before_duration": 1
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await;

    let issued = write(
        &core,
        &token,
        "pki/issue/short",
        json!({"common_name": "x.example.com", "ttl": "1s"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await
    .unwrap();
    let serial = issued["serial_number"].as_str().unwrap().to_string();
    assert!(!serial.is_empty());

    // Wait past NotAfter so the cert is sweep-eligible.
    thread::sleep(Duration::from_secs(3));

    // ── Case 1: auto-tidy disabled → scheduler must not fire ──────────
    // Default (no config written yet) is `enabled=false`. Verify the
    // tidy-status remains default after a pass.
    let core_arc: Arc<Core> = bvault.core.load_full();
    let last_fired = Arc::new(Mutex::new(HashMap::new()));
    scheduler::run_pki_tidy_pass(&core_arc, Some(last_fired.clone()))
        .await
        .expect("tidy pass must not error when disabled");

    let status = read(&core, &token, "pki/tidy-status").await.unwrap();
    assert_eq!(
        status["last_run_at_unix"].as_u64().unwrap(),
        0,
        "scheduler must not fire when auto-tidy is disabled"
    );

    // ── Case 2: enable auto-tidy, force the first fire ─────────────────
    write(
        &core,
        &token,
        "pki/config/auto-tidy",
        json!({
            "enabled": true,
            "interval": "1h",
            "tidy_cert_store": true,
            "tidy_revoked_certs": true,
            "safety_buffer": "0s"
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await;

    // Fresh `last_fired` map ⇒ the first sighting of this mount this pass
    // fires immediately (matches the scheduler's "first sighting after
    // process start" semantics).
    let last_fired = Arc::new(Mutex::new(HashMap::new()));
    scheduler::run_pki_tidy_pass(&core_arc, Some(last_fired.clone()))
        .await
        .expect("tidy pass must succeed when enabled");

    let status = read(&core, &token, "pki/tidy-status").await.unwrap();
    let first_run_at = status["last_run_at_unix"].as_u64().unwrap();
    assert!(first_run_at > 0, "scheduler must fire when auto-tidy is enabled");
    assert_eq!(status["source"].as_str().unwrap(), "auto");
    assert_eq!(status["certs_deleted"].as_u64().unwrap(), 1, "the expired cert should have been swept");

    // ── Case 3: same `last_fired`, interval is 1h → no re-fire ─────────
    // Reuse the *same* last_fired map so the scheduler sees "already
    // fired recently" and skips. We confirm by re-reading tidy-status:
    // the timestamp should be unchanged.
    scheduler::run_pki_tidy_pass(&core_arc, Some(last_fired.clone()))
        .await
        .expect("second pass must succeed even when no fire is due");

    let status = read(&core, &token, "pki/tidy-status").await.unwrap();
    assert_eq!(
        status["last_run_at_unix"].as_u64().unwrap(),
        first_run_at,
        "scheduler must not re-fire within the interval window"
    );
}
