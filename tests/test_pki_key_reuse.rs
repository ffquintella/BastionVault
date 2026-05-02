//! PKI managed key reuse on issue/sign — Phase L2 of the
//! key-management + lifecycle initiative. See
//! [features/pki-key-management-and-lifecycle.md].
//!
//! Coverage:
//! 1. Default-secure: a role with `allow_key_reuse = false` rejects
//!    `key_ref` outright.
//! 2. Allow-list enforcement: with `allow_key_reuse = true` and
//!    `allowed_key_refs = [A]`, pinning `B` is rejected; pinning `A`
//!    succeeds.
//! 3. Renewal preserves SPKI: two consecutive `pki/issue` calls with
//!    `key_ref = A` produce two distinct certs that share one
//!    SubjectPublicKeyInfo (the managed key's). Confirmed via
//!    `x509-parser`.
//! 4. Reference tracking: after issuance, `pki/key/A` reports
//!    `cert_ref_count = 2` and `DELETE pki/key/A` is rejected.
//! 5. CSR/key SPKI mismatch on `pki/sign/:role` with `key_ref` is a
//!    hard error.
//! 6. Algorithm mismatch (RSA managed key on EC role) is rejected.

use std::{collections::HashMap, env, fs};

use bastion_vault::{
    core::{Core, SealConfig},
    logical::{Operation, Request},
    storage, BastionVault,
};
use go_defer::defer;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
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

#[maybe_async::maybe_async]
async fn delete_req(core: &Core, token: &str, path: &str) -> Result<(), String> {
    let mut req = Request::new(path);
    req.operation = Operation::Delete;
    req.client_token = token.to_string();
    core.handle_request(&mut req).await.map(|_| ()).map_err(|e| format!("{e:?}"))
}

fn boot() -> (BastionVault, std::path::PathBuf) {
    use rand::RngExt;
    let n: u32 = rand::rng().random();
    let dir = env::temp_dir().join(format!("bastion_vault_pki_key_reuse_{n:08x}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));
    let backend = storage::new_backend("file", &conf).unwrap();
    let bvault = BastionVault::new(backend, None).unwrap();
    (bvault, dir)
}

/// Decode the first PEM block of `pem_text` to DER bytes.
fn pem_first_der(pem_text: &str) -> Vec<u8> {
    pem::parse(pem_text.as_bytes())
        .expect("PEM parse failed")
        .into_contents()
}

/// Pull the SubjectPublicKeyInfo DER out of an X.509 cert PEM.
fn cert_spki(cert_pem: &str) -> Vec<u8> {
    let der = pem_first_der(cert_pem);
    let (_, parsed) = x509_parser::parse_x509_certificate(&der).expect("X.509 parse");
    parsed.tbs_certificate.subject_pki.raw.to_vec()
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_pki_key_reuse_l2() {
    let (bvault, dir) = boot();
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let seal = SealConfig { secret_shares: 5, secret_threshold: 3 };
    let init = bvault.init(&seal).await.unwrap();
    for i in 0..seal.secret_threshold {
        bvault.unseal(&[&init.secret_shares[i as usize]]).await.unwrap();
    }
    let token = init.root_token.clone();
    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone())
        .await
        .expect("mount pki");

    // Generate a root + a base role.
    write(
        &core, &token, "pki/root/generate/internal",
        json!({"common_name": "L2 Root", "key_type": "ec", "ttl": "8760h"}).as_object().unwrap().clone(),
    ).await.expect("root generate").expect("root response had no data");

    // Three managed keys: A and B are EC, C is RSA (used to verify the
    // algorithm-mismatch gate against an EC role).
    let key_a = write_ok(
        &core, &token, "pki/keys/generate/internal",
        json!({"key_type": "ec", "key_bits": 256, "name": "key-a"}).as_object().unwrap().clone(),
    ).await;
    let id_a = key_a["key_id"].as_str().unwrap().to_string();
    let key_b = write_ok(
        &core, &token, "pki/keys/generate/internal",
        json!({"key_type": "ec", "key_bits": 256, "name": "key-b"}).as_object().unwrap().clone(),
    ).await;
    let id_b = key_b["key_id"].as_str().unwrap().to_string();
    let _key_c = write_ok(
        &core, &token, "pki/keys/generate/internal",
        json!({"key_type": "rsa", "key_bits": 2048, "name": "key-c-rsa"}).as_object().unwrap().clone(),
    ).await;

    // ── 1. allow_key_reuse=false rejects key_ref ────────────────────
    write(
        &core, &token, "pki/roles/closed",
        json!({
            "ttl": "24h", "max_ttl": "72h", "key_type": "ec",
            "allow_any_name": true, "server_flag": true, "client_flag": true,
        }).as_object().unwrap().clone(),
    ).await.expect("write closed role");
    let blocked = write(
        &core, &token, "pki/issue/closed",
        json!({"common_name": "leaf.example.com", "key_ref": id_a.clone()})
            .as_object().unwrap().clone(),
    ).await;
    assert!(blocked.is_err(), "key_ref must be rejected on closed role: {blocked:?}");

    // ── 2. allow-list narrows reuse to specific keys ────────────────
    write(
        &core, &token, "pki/roles/reuse",
        json!({
            "ttl": "24h", "max_ttl": "72h", "key_type": "ec",
            "allow_any_name": true, "server_flag": true, "client_flag": true,
            "allow_key_reuse": true,
            "allowed_key_refs": "key-a",
        }).as_object().unwrap().clone(),
    ).await.expect("write reuse role");
    // key-b not on allow-list → reject
    let blocked_b = write(
        &core, &token, "pki/issue/reuse",
        json!({"common_name": "leaf.example.com", "key_ref": id_b.clone()})
            .as_object().unwrap().clone(),
    ).await;
    assert!(blocked_b.is_err(), "off-allow-list key must be rejected: {blocked_b:?}");

    // ── 3. Renewal preserves SPKI ───────────────────────────────────
    let issued1 = write_ok(
        &core, &token, "pki/issue/reuse",
        json!({"common_name": "renew.example.com", "key_ref": "key-a"})
            .as_object().unwrap().clone(),
    ).await;
    let cert1_pem = issued1["certificate"].as_str().unwrap().to_string();
    let serial1 = issued1["serial_number"].as_str().unwrap().to_string();
    assert_eq!(issued1["key_id"].as_str().unwrap(), id_a);

    let issued2 = write_ok(
        &core, &token, "pki/issue/reuse",
        json!({"common_name": "renew.example.com", "key_ref": id_a.clone()})
            .as_object().unwrap().clone(),
    ).await;
    let cert2_pem = issued2["certificate"].as_str().unwrap().to_string();
    let serial2 = issued2["serial_number"].as_str().unwrap().to_string();

    assert_ne!(serial1, serial2, "two renewals must have distinct serials");
    assert_eq!(
        cert_spki(&cert1_pem),
        cert_spki(&cert2_pem),
        "renewals pinned to one managed key must share SubjectPublicKeyInfo"
    );

    // ── 4. Reference tracking: key-a now bound to two certs ─────────
    let key_a_after = read(&core, &token, "pki/key/key-a").await;
    assert_eq!(key_a_after["cert_ref_count"], 2);

    // Delete is refused while refs are non-empty.
    let del = delete_req(&core, &token, "pki/key/key-a").await;
    assert!(del.is_err(), "delete must refuse while key is bound: {del:?}");

    // ── 5. sign/:role with mismatched CSR/key is rejected ───────────
    // Build a fresh local CSR (its SPKI does NOT match key-a, since the
    // engine never returned key-a's private key).
    let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params =
        CertificateParams::new(vec!["mismatch.example.com".to_string()]).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "mismatch.example.com");
    params.distinguished_name = dn;
    let csr = params.serialize_request(&kp).unwrap();
    let csr_pem = csr.pem().unwrap();

    let mismatch = write(
        &core, &token, "pki/sign/reuse",
        json!({"csr": csr_pem, "key_ref": "key-a"}).as_object().unwrap().clone(),
    ).await;
    assert!(mismatch.is_err(), "CSR/key SPKI mismatch must be rejected: {mismatch:?}");

    // ── 6. Algorithm-class mismatch is rejected ─────────────────────
    let alg_mismatch = write(
        &core, &token, "pki/issue/reuse",
        json!({"common_name": "leaf.example.com", "key_ref": "key-c-rsa"})
            .as_object().unwrap().clone(),
    ).await;
    assert!(alg_mismatch.is_err(), "RSA key on EC role must be rejected: {alg_mismatch:?}");

    // ── 7. Without key_ref, legacy fresh-key path still works ───────
    let fresh = write_ok(
        &core, &token, "pki/issue/reuse",
        json!({"common_name": "fresh.example.com"}).as_object().unwrap().clone(),
    ).await;
    assert!(fresh.get("key_id").is_none(), "fresh issue must not echo key_id");
    assert!(fresh["private_key"].as_str().unwrap().contains("BEGIN PRIVATE KEY"));
}
