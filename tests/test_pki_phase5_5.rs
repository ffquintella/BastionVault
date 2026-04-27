//! PKI Secret Engine — Phase 5.5: per-issuer usage flags.
//!
//! Vault's `usage` field on issuers (`issuing-certificates`,
//! `crl-signing`, `ocsp-signing`) lets an operator dedicate one issuer
//! to issuing leaves and another to CRL signing — useful when an
//! offline-root design wants the root visible online for CRL purposes
//! only, or when separated-duties policy says one issuer must never
//! sign leaves.
//!
//! Coverage:
//!
//! 1. **Default = all enabled** — a freshly-created issuer has every
//!    usage on. Existing Phase 1–5.4 issuers (no `usages_by_id` entry)
//!    inherit the same default via the legacy migration shim.
//!
//! 2. **Lock to `issuing-certificates` only** — issue a leaf works,
//!    revoke a leaf signed by *that* issuer fails because the rebuild
//!    can't sign the CRL.
//!
//! 3. **Lock to `crl-signing` only** — issuing fails up-front;
//!    revoking a leaf works (CRL signing path exercises the issuer).
//!
//! 4. **Round-trip** — set usages, read them back, confirm the
//!    response carries the explicit list and *only* the listed values.
//!
//! 5. **Empty usage set rejected** — at least one usage must be
//!    enabled, since an issuer with no usages can never be invoked.

use std::{collections::HashMap, env, fs};

use bastion_vault::{
    core::{Core, SealConfig},
    logical::{Operation, Request},
    storage, BastionVault,
};
use go_defer::defer;
use serde_json::{json, Map, Value};

#[maybe_async::maybe_async]
async fn write(core: &Core, token: &str, path: &str, body: Map<String, Value>) -> Option<Map<String, Value>> {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(body);
    let resp = core.handle_request(&mut req).await.unwrap_or_else(|e| panic!("write {path}: {e:?}"));
    resp.and_then(|r| r.data)
}

#[maybe_async::maybe_async]
async fn write_ok(core: &Core, token: &str, path: &str, body: Map<String, Value>) -> Map<String, Value> {
    write(core, token, path, body).await.expect("response had no data")
}

#[maybe_async::maybe_async]
async fn write_err(core: &Core, token: &str, path: &str, body: Map<String, Value>) -> bool {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(body);
    core.handle_request(&mut req).await.is_err()
}

#[maybe_async::maybe_async]
async fn read(core: &Core, token: &str, path: &str) -> Map<String, Value> {
    let mut req = Request::new(path);
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await.unwrap_or_else(|e| panic!("read {path}: {e:?}"));
    resp.and_then(|r| r.data).expect("read had no data")
}

fn boot(name: &str) -> (BastionVault, std::path::PathBuf) {
    let dir = env::temp_dir().join(format!("bastion_vault_pki_phase5_5_{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));
    let backend = storage::new_backend("file", &conf).unwrap();
    let bvault = BastionVault::new(backend, None).unwrap();
    (bvault, dir)
}

async fn unseal(bvault: &BastionVault) -> String {
    let seal = SealConfig { secret_shares: 5, secret_threshold: 3 };
    let init = bvault.init(&seal).await.unwrap();
    for i in 0..seal.secret_threshold {
        bvault.unseal(&[&init.secret_shares[i as usize]]).await.unwrap();
    }
    init.root_token.clone()
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_phase5_5_default_usages_all_enabled() {
    let (bvault, dir) = boot("default_usages");
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let token = unseal(&bvault).await;
    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone()).await;

    write(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({"common_name": "Root", "key_type": "ec", "ttl": "8760h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;

    let issuer = read(&core, &token, "pki/issuer/default").await;
    let usages: Vec<String> = issuer["usage"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let mut sorted = usages.clone();
    sorted.sort();
    assert_eq!(
        sorted,
        vec!["crl-signing".to_string(), "issuing-certificates".to_string(), "ocsp-signing".to_string()],
        "freshly-created issuer must default to all usages enabled"
    );
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_phase5_5_issuing_only_blocks_crl_signing() {
    let (bvault, dir) = boot("issuing_only");
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let token = unseal(&bvault).await;
    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone()).await;

    write(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({"common_name": "Root", "key_type": "ec", "ttl": "8760h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    write(
        &core,
        &token,
        "pki/roles/web",
        json!({"ttl": "24h", "key_type": "ec", "allow_any_name": true, "server_flag": true})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;

    // Lock the default issuer to issuing-only.
    write(
        &core,
        &token,
        "pki/issuer/default",
        json!({"usage": "issuing-certificates"}).as_object().unwrap().clone(),
    )
    .await;

    // Issuance still works.
    let issued = write_ok(
        &core,
        &token,
        "pki/issue/web",
        json!({"common_name": "leaf.example.com"}).as_object().unwrap().clone(),
    )
    .await;
    let serial = issued["serial_number"].as_str().unwrap().to_string();

    // CRL signing now fails — the rebuild path is gated, and revoke
    // calls into rebuild after flipping the cert's `revoked_at_unix`.
    let rejected = write_err(
        &core,
        &token,
        "pki/revoke",
        json!({"serial_number": serial}).as_object().unwrap().clone(),
    )
    .await;
    assert!(
        rejected,
        "revoke must fail when the signing issuer's `crl-signing` usage is disabled"
    );

    // Reading the CRL also fails (rebuild on demand → gated).
    let mut req = Request::new("pki/crl");
    req.operation = Operation::Read;
    req.client_token = token.clone();
    assert!(
        core.handle_request(&mut req).await.is_err(),
        "pki/crl read must fail when the default issuer cannot sign CRLs"
    );
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_phase5_5_crl_only_blocks_issuance() {
    let (bvault, dir) = boot("crl_only");
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let token = unseal(&bvault).await;
    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone()).await;

    write(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({"common_name": "Root", "key_type": "ec", "ttl": "8760h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    write(
        &core,
        &token,
        "pki/roles/web",
        json!({"ttl": "24h", "key_type": "ec", "allow_any_name": true, "server_flag": true})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;

    // Lock the default issuer to crl-signing only.
    write(
        &core,
        &token,
        "pki/issuer/default",
        json!({"usage": "crl-signing"}).as_object().unwrap().clone(),
    )
    .await;

    // Issuance must fail.
    assert!(
        write_err(
            &core,
            &token,
            "pki/issue/web",
            json!({"common_name": "leaf.example.com"}).as_object().unwrap().clone(),
        )
        .await,
        "pki/issue must fail when the default issuer's `issuing-certificates` usage is off"
    );

    // CRL read still works (rebuild path gated only on crl-signing,
    // which IS enabled).
    let crl = read(&core, &token, "pki/crl").await;
    assert!(crl["crl"].as_str().unwrap().contains("BEGIN X509 CRL"));
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_phase5_5_round_trip_and_empty_rejection() {
    let (bvault, dir) = boot("round_trip");
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let token = unseal(&bvault).await;
    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone()).await;
    write(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({"common_name": "Root", "key_type": "ec", "ttl": "8760h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;

    // Round-trip: set explicit set, read it back.
    write(
        &core,
        &token,
        "pki/issuer/default",
        json!({"usage": "issuing-certificates,crl-signing"}).as_object().unwrap().clone(),
    )
    .await;
    let issuer = read(&core, &token, "pki/issuer/default").await;
    let mut usages: Vec<String> = issuer["usage"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    usages.sort();
    assert_eq!(
        usages,
        vec!["crl-signing".to_string(), "issuing-certificates".to_string()],
        "Read must reflect exactly the usages set by Write (no implicit ocsp-signing)"
    );

    // Empty-set rejection.
    assert!(
        write_err(
            &core,
            &token,
            "pki/issuer/default",
            // An empty `usage` field with no `issuer_name` is a no-op
            // request — error rather than silent success.
            json!({"usage": ""}).as_object().unwrap().clone(),
        )
        .await,
        "empty no-op write must error"
    );
}
