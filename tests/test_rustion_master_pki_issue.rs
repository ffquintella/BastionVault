//! Integration test: `rustion/master/issue` must round-trip through
//! the configured PKI engine for both halves (Ed25519 + ML-DSA-65),
//! and the serial it surfaces in `current_serial` must address a real
//! cert in the PKI engine's storage.
//!
//! This is the end-to-end counterpart to the in-tree unit tests in
//! `src/modules/rustion/master.rs`, which use a `FakeIssuer`. Those
//! cover the state machine; this one closes the loop by spinning a
//! real Core, mounting a real PKI engine, and asserting the master
//! store actually consults it.

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
async fn read(core: &Core, token: &str, path: &str) -> Option<Map<String, Value>> {
    let mut req = Request::new(path);
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await.expect("read failed");
    resp.and_then(|r| r.data)
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn rustion_master_issue_routes_through_pki_engine() {
    let dir = env::temp_dir().join("bastion_vault_rustion_master_pki_issue");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    defer! ( let _ = fs::remove_dir_all(&dir); );

    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));
    let backend = storage::new_backend("file", &conf).unwrap();

    let bvault = BastionVault::new(backend, None).unwrap();
    let core = bvault.core.load();
    let seal = SealConfig { secret_shares: 1, secret_threshold: 1 };
    let init = bvault.init(&seal).await.unwrap();
    bvault.unseal(&[&init.secret_shares[0]]).await.unwrap();
    let token = init.root_token.clone();

    // Mount one PKI engine and stand up two roots — one classical
    // (Ed25519) and one PQC (ML-DSA-65) — so each role lives under
    // its own issuer. The mixed-chain guard inside `pki/issue` would
    // otherwise refuse a PQC leaf on a classical CA.
    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone())
        .await;
    let ed_root = write(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({
            "common_name": "rustion-master-ed25519-root",
            "key_type": "ed25519",
            "ttl": "8760h",
            "issuer_name": "ed25519-root"
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await
    .unwrap();
    assert!(ed_root["certificate"].as_str().unwrap().contains("BEGIN CERTIFICATE"));
    let pqc_root = write(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({
            "common_name": "rustion-master-mldsa65-root",
            "key_type": "ml-dsa-65",
            "ttl": "8760h",
            "issuer_name": "mldsa65-root"
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await
    .unwrap();
    assert!(pqc_root["certificate"].as_str().unwrap().contains("BEGIN CERTIFICATE"));

    // Pin each role to its matching issuer so the engine's
    // mixed-chain guard doesn't reject the leaf.
    write(
        &core,
        &token,
        "pki/roles/rustion-master-ed25519",
        json!({
            "ttl": "1h",
            "max_ttl": "2h",
            "key_type": "ed25519",
            "allow_any_name": true,
            "client_flag": true,
            "server_flag": false,
            "issuer_ref": "ed25519-root"
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await;
    write(
        &core,
        &token,
        "pki/roles/rustion-master-mldsa65",
        json!({
            "ttl": "1h",
            "max_ttl": "2h",
            "key_type": "ml-dsa-65",
            "allow_any_name": true,
            "client_flag": true,
            "server_flag": false,
            "issuer_ref": "mldsa65-root"
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await;

    // Point the rustion master at both roles.
    write(
        &core,
        &token,
        "rustion/master/config",
        json!({
            "pki_mount": "pki/",
            "pki_role": "rustion-master-ed25519",
            "pki_role_pqc": "rustion-master-mldsa65",
            "default_ttl_secs": 3600
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await;
    let cfg = read(&core, &token, "rustion/master/config").await.unwrap();
    assert_eq!(cfg["pki_role"].as_str().unwrap(), "rustion-master-ed25519");
    assert_eq!(cfg["pki_role_pqc"].as_str().unwrap(), "rustion-master-mldsa65");
    assert!(cfg["configured"].as_bool().unwrap_or(false));

    // Issue. Both halves must mint through the engine; the surfaced
    // serial must address a real cert in the PKI engine's storage.
    let issued = write(&core, &token, "rustion/master/issue", Map::new())
        .await
        .expect("issue should succeed");
    let serial = issued["serial"].as_str().unwrap().to_string();
    assert!(!serial.is_empty(), "issue must surface a serial");
    assert!(issued["rotated"].as_bool() == Some(false));

    // The Ed25519 serial round-trips through the PKI engine: fetching
    // the cert by serial via the engine returns the same blob. This is
    // the smoking-gun assertion — the only way `current_serial` lines
    // up with an entry under `pki/cert/<serial>` is if the master
    // store actually went through `pki/issue/...`.
    let fetched = read(&core, &token, &format!("pki/cert/{serial}"))
        .await
        .unwrap_or_else(|| panic!("PKI engine has no cert under serial {serial}"));
    let cert_pem = fetched["certificate"].as_str().unwrap();
    assert!(cert_pem.contains("BEGIN CERTIFICATE"));

    // pubkey export still works.
    let export = read(&core, &token, "rustion/master/pubkey").await.unwrap();
    assert!(export["issued"].as_bool().unwrap());
    assert!(export["ed25519_pem"].as_str().unwrap().contains("BVRG ED25519 PUBLIC KEY"));
    assert!(export["mldsa65_pem"].as_str().unwrap().contains("BVRG ML-DSA-65 PUBLIC KEY"));
    assert_eq!(export["current_serial"].as_str().unwrap(), serial);

    // Rotate cuts over to a fresh hybrid pair, also through the
    // engine. The new serial must again resolve to a cert in PKI
    // storage, and must differ from the original.
    let rotated = write(&core, &token, "rustion/master/rotate", Map::new())
        .await
        .expect("rotate should succeed");
    let new_serial = rotated["serial"].as_str().unwrap().to_string();
    assert_ne!(new_serial, serial, "rotate must mint a new serial");
    assert!(rotated["rotated"].as_bool() == Some(true));
    let fetched_new = read(&core, &token, &format!("pki/cert/{new_serial}"))
        .await
        .unwrap_or_else(|| panic!("PKI engine has no cert under rotated serial {new_serial}"));
    assert!(fetched_new["certificate"].as_str().unwrap().contains("BEGIN CERTIFICATE"));
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn rustion_master_issue_refuses_without_pqc_role_configured() {
    let dir = env::temp_dir().join("bastion_vault_rustion_master_pki_issue_no_pqc");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    defer! ( let _ = fs::remove_dir_all(&dir); );

    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));
    let backend = storage::new_backend("file", &conf).unwrap();

    let bvault = BastionVault::new(backend, None).unwrap();
    let core = bvault.core.load();
    let seal = SealConfig { secret_shares: 1, secret_threshold: 1 };
    let init = bvault.init(&seal).await.unwrap();
    bvault.unseal(&[&init.secret_shares[0]]).await.unwrap();
    let token = init.root_token.clone();

    // Configure the rustion master with *only* pki_mount + pki_role,
    // leaving pki_role_pqc unset. `issue` must refuse before touching
    // the PKI engine.
    write(
        &core,
        &token,
        "rustion/master/config",
        json!({
            "pki_mount": "pki/",
            "pki_role": "ignored-since-mount-not-real"
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await;

    let mut req = Request::new("rustion/master/issue");
    req.operation = Operation::Write;
    req.client_token = token.clone();
    req.body = Some(Map::new());
    let resp = core.handle_request(&mut req).await;
    // The handler maps the master-store error into a Response with a
    // non-2xx status; either an Err or a response carrying the
    // configuration complaint is acceptable.
    let surfaced = match resp {
        Err(e) => format!("{e:?}"),
        Ok(Some(r)) => format!("{:?}", r.data),
        Ok(None) => "no response".to_string(),
    };
    assert!(
        surfaced.contains("pki_role_pqc"),
        "issue without pki_role_pqc must complain about it, got: {surfaced}"
    );
}
