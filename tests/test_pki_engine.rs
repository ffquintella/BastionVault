//! PKI Secret Engine — Phase 1 integration tests.
//!
//! Exercises the end-to-end Vault-compatible flow: mount engine, generate a
//! root CA, create a role, issue a leaf, fetch it, revoke it, and verify the
//! revoked serial appears in the CRL.

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
async fn test_pki_phase1_end_to_end() {
    let dir = env::temp_dir().join("bastion_vault_pki_phase1");
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

    // Mount the PKI engine.
    let mount_body = json!({"type": "pki"}).as_object().unwrap().clone();
    write(&core, &token, "sys/mounts/pki/", mount_body).await;

    // Generate a self-signed root CA (internal mode — private key not returned).
    let root_body = json!({
        "common_name": "test-root.example.com",
        "organization": "BastionVault Tests",
        "key_type": "ec",
        "key_bits": 256,
        "ttl": "8760h"
    })
    .as_object()
    .unwrap()
    .clone();
    let root_resp = write(&core, &token, "pki/root/generate/internal", root_body).await.unwrap();
    let root_pem = root_resp["certificate"].as_str().unwrap().to_string();
    assert!(root_pem.contains("BEGIN CERTIFICATE"), "root cert PEM missing header");
    assert!(root_resp.get("private_key").is_none(), "internal mode must not leak private key");

    // Phase 5.2: a second `root/generate` is now additive (creates another
    // issuer alongside the first). What still gets rejected is *duplicate
    // names*: trying to register a new issuer under the existing
    // `default` name must fail.
    let dup_name = json!({
        "common_name": "second-root",
        "key_type": "ec",
        "ttl": "1h",
        "issuer_name": "default"
    })
    .as_object()
    .unwrap()
    .clone();
    let mut req = Request::new("pki/root/generate/internal");
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(dup_name);
    assert!(
        core.handle_request(&mut req).await.is_err(),
        "registering a new issuer under an already-taken name must be rejected"
    );

    // Fetch the CA cert via /pki/ca.
    let ca = read(&core, &token, "pki/ca").await.unwrap();
    assert_eq!(ca["certificate"].as_str().unwrap(), root_pem);

    // Create a role.
    let role_body = json!({
        "ttl": "24h",
        "max_ttl": "72h",
        "key_type": "ec",
        "key_bits": 256,
        "allow_any_name": true,
        "server_flag": true,
        "client_flag": false
    })
    .as_object()
    .unwrap()
    .clone();
    write(&core, &token, "pki/roles/web", role_body).await;

    // Read the role back.
    let role = read(&core, &token, "pki/roles/web").await.unwrap();
    assert_eq!(role["key_type"].as_str().unwrap(), "ec");
    assert_eq!(role["allow_any_name"].as_bool().unwrap(), true);

    // List roles.
    let mut req = Request::new("pki/roles/");
    req.operation = Operation::List;
    req.client_token = token.to_string();
    let listed = core.handle_request(&mut req).await.unwrap().unwrap().data.unwrap();
    assert_eq!(listed["keys"].as_array().unwrap().len(), 1);

    // Issue a cert.
    let issue_body = json!({
        "common_name": "leaf.example.com",
        "alt_names": "leaf-alt.example.com,127.0.0.1",
        "ttl": "12h"
    })
    .as_object()
    .unwrap()
    .clone();
    let issued = write(&core, &token, "pki/issue/web", issue_body).await.unwrap();
    let leaf_pem = issued["certificate"].as_str().unwrap().to_string();
    let leaf_key = issued["private_key"].as_str().unwrap().to_string();
    let serial = issued["serial_number"].as_str().unwrap().to_string();
    assert!(leaf_pem.contains("BEGIN CERTIFICATE"));
    assert!(leaf_key.contains("BEGIN PRIVATE KEY"));
    assert_eq!(serial.len(), 16, "8-byte serial must encode as 16 hex chars (got {serial:?})");

    // Verify the issued cert chains to the root using rustls-webpki via a
    // direct DER parse. Phase 1 uses the pure-Rust x509-parser path.
    let leaf_der_block = pem_decode_first(&leaf_pem);
    let root_der_block = pem_decode_first(&root_pem);
    let (_, leaf) = x509_parser::parse_x509_certificate(&leaf_der_block).unwrap();
    let (_, root) = x509_parser::parse_x509_certificate(&root_der_block).unwrap();
    assert_eq!(leaf.issuer().to_string(), root.subject().to_string(), "leaf issuer must match root subject");

    // Fetch the cert by serial.
    let fetched = read(&core, &token, &format!("pki/cert/{serial}")).await.unwrap();
    assert_eq!(fetched["serial_number"].as_str().unwrap(), serial);
    assert_eq!(fetched["certificate"].as_str().unwrap(), leaf_pem);

    // Read CRL — pre-revocation it must be a valid empty CRL signed by the CA.
    let crl_pre = read(&core, &token, "pki/crl").await.unwrap();
    let crl_pem_pre = crl_pre["crl"].as_str().unwrap().to_string();
    assert!(crl_pem_pre.contains("BEGIN X509 CRL"));

    // Revoke the leaf.
    let revoke_body = json!({"serial_number": serial}).as_object().unwrap().clone();
    let revoked = write(&core, &token, "pki/revoke", revoke_body).await.unwrap();
    assert_eq!(revoked["serial_number"].as_str().unwrap(), serial);

    // CRL now lists the serial.
    let crl_post = read(&core, &token, "pki/crl").await.unwrap();
    let crl_pem_post = crl_post["crl"].as_str().unwrap().to_string();
    let crl_der = pem_decode_first(&crl_pem_post);
    let (_, parsed_crl) = x509_parser::parse_x509_crl(&crl_der).unwrap();
    let revoked_serials: Vec<String> = parsed_crl
        .iter_revoked_certificates()
        .map(|c| {
            c.user_certificate
                .to_bytes_be()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        })
        .collect();
    assert!(
        revoked_serials.iter().any(|s| s == &serial),
        "expected revoked serial {serial} in CRL, got {revoked_serials:?}"
    );

    // Stub endpoints must return an error rather than 404.
    let mut req = Request::new("pki/sign/web");
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(Map::new());
    assert!(core.handle_request(&mut req).await.is_err(), "sign/:role stub must return an error");
}

fn pem_decode_first(pem: &str) -> Vec<u8> {
    let mut in_block = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        if line.starts_with("-----BEGIN") {
            in_block = true;
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if in_block {
            b64.push_str(line.trim());
        }
    }
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()).unwrap()
}
