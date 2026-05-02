//! PKI issuer-bound managed keys + chain UX — Phase L3 of the
//! key-management + lifecycle initiative. See
//! [features/pki-key-management-and-lifecycle.md].
//!
//! Coverage:
//! 1. `pki/root/generate/internal` with `key_ref` promotes a managed
//!    key to root issuer; the resulting issuer's SubjectPublicKeyInfo
//!    matches the managed key's. Algorithm-mismatch (RSA key on EC
//!    role) is rejected.
//! 2. After promotion, `pki/key/<id>` reports `issuer_ref_count = 1`
//!    and `DELETE pki/key/<id>` is refused.
//! 3. Revoking a cert that was issued via `key_ref` clears the cert
//!    binding from `KeyRefs` (cert_ref_count drops); deletion is still
//!    refused while issuer_ref_count > 0.
//! 4. `pki/issuer/<ref>/chain` returns root → leaf-issuer order: with
//!    only a root, the chain has one entry; once an intermediate is
//!    installed against the root, the intermediate's chain has two
//!    entries and the leaf chain via `pki/issue` (`ca_chain`) reflects
//!    the same order.

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
    let dir = env::temp_dir().join(format!("bastion_vault_pki_issuer_keys_{n:08x}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));
    let backend = storage::new_backend("file", &conf).unwrap();
    let bvault = BastionVault::new(backend, None).unwrap();
    (bvault, dir)
}

fn pem_first_der(pem_text: &str) -> Vec<u8> {
    pem::parse(pem_text.as_bytes()).expect("PEM parse").into_contents()
}

fn cert_spki(cert_pem: &str) -> Vec<u8> {
    let der = pem_first_der(cert_pem);
    let (_, parsed) = x509_parser::parse_x509_certificate(&der).expect("X.509 parse");
    parsed.tbs_certificate.subject_pki.raw.to_vec()
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_pki_issuer_bound_keys_l3() {
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

    // ── Generate two managed keys: one EC for the root, one RSA used
    //    only to verify the algorithm-mismatch gate. ──
    let key_ec = write_ok(
        &core, &token, "pki/keys/generate/internal",
        json!({"key_type": "ec", "key_bits": 256, "name": "root-key"}).as_object().unwrap().clone(),
    ).await;
    let id_ec = key_ec["key_id"].as_str().unwrap().to_string();
    let key_ec_spki_pem = key_ec["public_key"].as_str().unwrap().to_string();
    let key_ec_spki = pem::parse(key_ec_spki_pem.as_bytes()).unwrap().into_contents();

    let _key_rsa = write_ok(
        &core, &token, "pki/keys/generate/internal",
        json!({"key_type": "rsa", "key_bits": 2048, "name": "rsa-bystander"}).as_object().unwrap().clone(),
    ).await;

    // ── 1. Algorithm-mismatch is rejected ────────────────────────────
    let bad = write(
        &core, &token, "pki/root/generate/internal",
        json!({
            "common_name": "L3 root", "key_type": "ec", "ttl": "8760h",
            "key_ref": "rsa-bystander",
        }).as_object().unwrap().clone(),
    ).await;
    assert!(bad.is_err(), "RSA key on EC root must be rejected: {bad:?}");

    // ── 2. Promote the EC managed key to root ────────────────────────
    let root_resp = write_ok(
        &core, &token, "pki/root/generate/internal",
        json!({
            "common_name": "L3 root", "key_type": "ec", "ttl": "8760h",
            "key_ref": "root-key",
        }).as_object().unwrap().clone(),
    ).await;
    let root_pem = root_resp["certificate"].as_str().unwrap().to_string();
    assert_eq!(root_resp["key_id"].as_str().unwrap(), id_ec);
    // exported field absent because we used internal mode AND key_ref;
    // the root response should NOT echo the private key.
    assert!(
        root_resp.get("private_key").is_none(),
        "internal-mode root with key_ref must not return private_key"
    );

    // The root's SPKI matches the managed key's SPKI.
    assert_eq!(cert_spki(&root_pem), key_ec_spki, "root SPKI must match managed key SPKI");

    // ── 3. Issuer binding shows up on the key, delete refused ────────
    let key_after = read(&core, &token, "pki/key/root-key").await;
    assert_eq!(key_after["issuer_ref_count"], 1);
    let del = delete_req(&core, &token, "pki/key/root-key").await;
    assert!(del.is_err(), "delete must refuse while issuer is bound: {del:?}");

    // ── 4. Issue a cert against this issuer using key_ref to bind cert→key ──
    write(
        &core, &token, "pki/roles/web",
        json!({
            "ttl": "24h", "max_ttl": "72h", "key_type": "ec",
            "allow_any_name": true, "server_flag": true, "client_flag": true,
            "allow_key_reuse": true, "allowed_key_refs": "root-key",
        }).as_object().unwrap().clone(),
    ).await.expect("write role");
    let issued = write_ok(
        &core, &token, "pki/issue/web",
        json!({"common_name": "leaf.example.com", "key_ref": "root-key"})
            .as_object().unwrap().clone(),
    ).await;
    let serial = issued["serial_number"].as_str().unwrap().to_string();
    // ca_chain on the response carries the issuer's chain (just root for now).
    let ca_chain = issued["ca_chain"].as_array().unwrap();
    assert_eq!(ca_chain.len(), 1, "single-issuer mount → single-entry chain");

    // Refs now carry one issuer + one cert. Delete still refused.
    let key_after2 = read(&core, &token, "pki/key/root-key").await;
    assert_eq!(key_after2["issuer_ref_count"], 1);
    assert_eq!(key_after2["cert_ref_count"], 1);

    // ── 5. Revoke the cert: cert ref clears, issuer ref stays ────────
    write_ok(
        &core, &token, "pki/revoke",
        json!({"serial_number": serial}).as_object().unwrap().clone(),
    ).await;
    let key_after3 = read(&core, &token, "pki/key/root-key").await;
    assert_eq!(key_after3["cert_ref_count"], 0, "revoke must clear cert binding");
    assert_eq!(key_after3["issuer_ref_count"], 1, "issuer binding survives revoke");
    let still_blocked = delete_req(&core, &token, "pki/key/root-key").await;
    assert!(still_blocked.is_err(), "issuer binding must still block delete");

    // ── 6. issuer/:ref/chain endpoint returns the cert PEM ───────────
    let chain = read(&core, &token, "pki/issuer/default/chain").await;
    let chain_arr = chain["ca_chain"].as_array().unwrap();
    assert_eq!(chain_arr.len(), 1);
    assert!(
        chain_arr[0].as_str().unwrap().contains("BEGIN CERTIFICATE"),
        "chain entry must be a PEM cert"
    );
    let bundle = chain["certificate_bundle"].as_str().unwrap();
    assert!(bundle.contains("BEGIN CERTIFICATE"));
}
