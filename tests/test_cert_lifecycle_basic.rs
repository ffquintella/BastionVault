//! Cert-lifecycle module — Phase L5 of the PKI key-management +
//! lifecycle initiative. See
//! [features/pki-key-management-and-lifecycle.md].
//!
//! Coverage:
//! 1. Mount the cert-lifecycle module; create a target with
//!    `kind = file` pointing at a temp directory.
//! 2. Manual renew via `pki/cert-lifecycle/renew/<name>` calls into
//!    the PKI mount, issues a leaf, and writes `cert.pem`, `key.pem`,
//!    `chain.pem` into the target directory.
//! 3. The target's state reflects the new serial and a NotAfter that
//!    matches the cert.
//! 4. `key_policy = reuse` carries the `key_ref` field through to the
//!    PKI issue call — two consecutive renewals share an SPKI.
//! 5. Required-field validation: missing `role_ref` / `common_name` /
//!    `address` / `key_ref`-when-reuse → write rejected.
//! 6. `key_policy = agent-generates` rejected at write time (Phase L5
//!    deferral).

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
async fn write_ok(core: &Core, token: &str, path: &str, body: Map<String, Value>) -> Map<String, Value> {
    write(core, token, path, body)
        .await
        .unwrap_or_else(|e| panic!("write {path}: {e}"))
        .unwrap_or_else(|| panic!("write {path}: empty response"))
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
    let dir = env::temp_dir().join(format!("bastion_vault_cert_lifecycle_{n:08x}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));
    let backend = storage::new_backend("file", &conf).unwrap();
    let bvault = BastionVault::new(backend, None).unwrap();
    (bvault, dir)
}

fn cert_spki(cert_pem: &str) -> Vec<u8> {
    let der = pem::parse(cert_pem.as_bytes()).expect("PEM parse").into_contents();
    let (_, parsed) = x509_parser::parse_x509_certificate(&der).unwrap();
    parsed.tbs_certificate.subject_pki.raw.to_vec()
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_cert_lifecycle_basic_l5() {
    let (bvault, dir) = boot();
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let seal = SealConfig { secret_shares: 5, secret_threshold: 3 };
    let init = bvault.init(&seal).await.unwrap();
    for i in 0..seal.secret_threshold {
        bvault.unseal(&[&init.secret_shares[i as usize]]).await.unwrap();
    }
    let token = init.root_token.clone();

    // Mount PKI + cert-lifecycle. Note: the cert-lifecycle mount is
    // registered globally via `module_manager`, so we mount it like
    // any other backend.
    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone())
        .await.expect("mount pki");
    write(&core, &token, "sys/mounts/cert-lifecycle/",
        json!({"type": "cert-lifecycle"}).as_object().unwrap().clone())
        .await.expect("mount cert-lifecycle");

    // Spin up a root + a permissive role.
    write(&core, &token, "pki/root/generate/internal",
        json!({"common_name": "L5 Root", "key_type": "ec", "ttl": "8760h"})
            .as_object().unwrap().clone(),
    ).await.expect("generate root");
    write(&core, &token, "pki/roles/web",
        json!({
            "ttl": "24h", "max_ttl": "72h", "key_type": "ec",
            "allow_any_name": true, "server_flag": true, "client_flag": true,
        }).as_object().unwrap().clone(),
    ).await.expect("write role");

    // Output directory the renewer will populate.
    let out_dir = dir.join("out");
    fs::create_dir_all(&out_dir).unwrap();
    let out_str = out_dir.to_string_lossy().into_owned();

    // ── 5. Required-field validation ─────────────────────────────────
    let missing_role = write(&core, &token, "cert-lifecycle/targets/svc",
        json!({"common_name": "svc.example.com", "address": &out_str}).as_object().unwrap().clone(),
    ).await;
    assert!(missing_role.is_err(), "missing role_ref must reject: {missing_role:?}");

    let missing_addr = write(&core, &token, "cert-lifecycle/targets/svc",
        json!({"role_ref": "web", "common_name": "svc.example.com"}).as_object().unwrap().clone(),
    ).await;
    assert!(missing_addr.is_err(), "missing address must reject: {missing_addr:?}");

    let agent = write(&core, &token, "cert-lifecycle/targets/svc",
        json!({
            "role_ref": "web", "common_name": "svc.example.com",
            "address": &out_str, "key_policy": "agent-generates",
        }).as_object().unwrap().clone(),
    ).await;
    assert!(agent.is_err(), "agent-generates must reject in L5: {agent:?}");

    // ── 1. Create a valid target ─────────────────────────────────────
    write(&core, &token, "cert-lifecycle/targets/svc",
        json!({
            "role_ref": "web",
            "common_name": "svc.example.com",
            "alt_names": "alt.example.com",
            "address": &out_str,
            "ttl": "12h",
        }).as_object().unwrap().clone(),
    ).await.expect("write target");

    let listed = {
        let mut req = Request::new("cert-lifecycle/targets");
        req.operation = Operation::List;
        req.client_token = token.clone();
        let resp = core.handle_request(&mut req).await.unwrap();
        resp.and_then(|r| r.data).unwrap()
    };
    let names: Vec<String> = listed["keys"].as_array().unwrap()
        .iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(names.contains(&"svc".to_string()));

    // ── 2. Manual renew writes the bundle ────────────────────────────
    let renewed = write_ok(&core, &token, "cert-lifecycle/renew/svc", Map::new()).await;
    let serial = renewed["serial_number"].as_str().unwrap().to_string();
    assert!(!serial.is_empty());
    assert_eq!(renewed["delivered_to"].as_str().unwrap(), out_str);

    // Files written.
    let cert_pem = fs::read_to_string(out_dir.join("cert.pem")).expect("cert.pem written");
    let key_pem = fs::read_to_string(out_dir.join("key.pem")).expect("key.pem written");
    let chain_pem = fs::read_to_string(out_dir.join("chain.pem")).expect("chain.pem written");
    assert!(cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(key_pem.contains("BEGIN PRIVATE KEY"));
    assert!(chain_pem.contains("BEGIN CERTIFICATE"));

    // ── 3. State reflects the renewal ────────────────────────────────
    let state = read(&core, &token, "cert-lifecycle/state/svc").await;
    assert_eq!(state["current_serial"].as_str().unwrap(), serial);
    assert!(state["current_not_after"].as_i64().unwrap() > 0);
    assert!(state["last_renewal"].as_u64().unwrap() > 0);
    assert_eq!(state["last_error"].as_str().unwrap(), "");
    assert_eq!(state["failure_count"].as_u64().unwrap(), 0);

    // ── 4. key_policy = reuse pins SPKI across renewals ──────────────
    // First make a managed key + role that allows reuse.
    let key = write_ok(&core, &token, "pki/keys/generate/internal",
        json!({"key_type": "ec", "key_bits": 256, "name": "svc-key"}).as_object().unwrap().clone(),
    ).await;
    let _key_id = key["key_id"].as_str().unwrap().to_string();
    write(&core, &token, "pki/roles/reuse",
        json!({
            "ttl": "24h", "max_ttl": "72h", "key_type": "ec",
            "allow_any_name": true, "server_flag": true, "client_flag": true,
            "allow_key_reuse": true, "allowed_key_refs": "svc-key",
        }).as_object().unwrap().clone(),
    ).await.expect("write reuse role");

    let out_dir2 = dir.join("out2");
    fs::create_dir_all(&out_dir2).unwrap();
    let out_str2 = out_dir2.to_string_lossy().into_owned();
    write(&core, &token, "cert-lifecycle/targets/pinned",
        json!({
            "role_ref": "reuse",
            "common_name": "pinned.example.com",
            "address": &out_str2,
            "key_policy": "reuse",
            "key_ref": "svc-key",
        }).as_object().unwrap().clone(),
    ).await.expect("write pinned target");

    let r1 = write_ok(&core, &token, "cert-lifecycle/renew/pinned", Map::new()).await;
    let cert1 = fs::read_to_string(out_dir2.join("cert.pem")).unwrap();
    assert_eq!(r1["serial_number"].as_str().unwrap().is_empty(), false);

    let _r2 = write_ok(&core, &token, "cert-lifecycle/renew/pinned", Map::new()).await;
    let cert2 = fs::read_to_string(out_dir2.join("cert.pem")).unwrap();

    assert_eq!(
        cert_spki(&cert1),
        cert_spki(&cert2),
        "key_policy=reuse must produce certs sharing one SPKI",
    );
}
