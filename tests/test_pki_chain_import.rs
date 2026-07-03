//! `pki/config/ca` chain import — multi-cert bundles and key-less
//! (trust/chain-only) issuers.
//!
//! Coverage:
//! 1. **Key + full chain in one paste** — `int_key + int_cert + root_cert`
//!    imports the intermediate as a signing issuer and the root as a
//!    key-less trust anchor; issuance chains leaf → int → root.
//! 2. **Certs-only trust import** — a chain with no private key imports
//!    every CA as a key-less issuer, sets no default, and cannot sign.
//! 3. **Key/cert mismatch** — a key matching none of the pasted certs is
//!    rejected (was the confusing "pem bundle is invalid" 500).
//! 4. **Leaf in the bundle** — a non-CA cert is rejected with a pointer
//!    to `pki/certs/import`.
//! 5. **Idempotent re-import** — a cert already present (by serial) is
//!    skipped rather than colliding.

use std::{collections::HashMap, env, fs};

use bastion_vault::{
    core::{Core, SealConfig},
    logical::{Operation, Request},
    storage, BastionVault,
};
use go_defer::defer;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use serde_json::{json, Map, Value};

#[maybe_async::maybe_async]
async fn write(core: &Core, token: &str, path: &str, body: Map<String, Value>) -> Result<Option<Map<String, Value>>, String> {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(body);
    core.handle_request(&mut req).await.map(|r| r.and_then(|x| x.data)).map_err(|e| format!("{e:?}"))
}

#[maybe_async::maybe_async]
async fn write_ok(core: &Core, token: &str, path: &str, body: Map<String, Value>) -> Map<String, Value> {
    write(core, token, path, body).await.unwrap_or_else(|e| panic!("write {path}: {e}")).unwrap_or_default()
}

#[maybe_async::maybe_async]
async fn list(core: &Core, token: &str, path: &str) -> Map<String, Value> {
    let mut req = Request::new(path);
    req.operation = Operation::List;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await.unwrap_or_else(|e| panic!("list {path}: {e:?}"));
    resp.and_then(|r| r.data).unwrap_or_default()
}

fn boot() -> (BastionVault, std::path::PathBuf, String) {
    use rand::RngExt;
    let n: u32 = rand::rng().random();
    let dir = env::temp_dir().join(format!("bv_pki_chain_import_{n:08x}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));
    let backend = storage::new_backend("file", &conf).unwrap();
    let bvault = BastionVault::new(backend, None).unwrap();
    (bvault, dir, String::new())
}

/// (root_pem, root_kp_pem, int_pem, int_kp_pem, root_issuer for signing leaves)
fn build_chain() -> (String, String, String, String, Issuer<'static, KeyPair>) {
    let root_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let root_kp_pem = root_kp.serialize_pem();
    let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut root_dn = DistinguishedName::new();
    root_dn.push(DnType::CommonName, "Chain Test Root");
    root_params.distinguished_name = root_dn;
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root_cert = root_params.self_signed(&root_kp).unwrap();
    let root_pem = root_cert.pem();
    let root_issuer = Issuer::from_ca_cert_pem(&root_pem, root_kp).unwrap();

    let int_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let int_kp_pem = int_kp.serialize_pem();
    let mut int_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut int_dn = DistinguishedName::new();
    int_dn.push(DnType::CommonName, "Chain Test Intermediate");
    int_params.distinguished_name = int_dn;
    int_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    int_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let int_cert = int_params.signed_by(&int_kp, &root_issuer).unwrap();
    let int_pem = int_cert.pem();

    (root_pem, root_kp_pem, int_pem, int_kp_pem, root_issuer)
}

#[maybe_async::maybe_async]
async fn setup() -> (BastionVault, std::path::PathBuf, String) {
    let (bvault, dir, _) = boot();
    let seal = SealConfig { secret_shares: 5, secret_threshold: 3 };
    let init = bvault.init(&seal).await.unwrap();
    for i in 0..seal.secret_threshold {
        bvault.unseal(&[&init.secret_shares[i as usize]]).await.unwrap();
    }
    let token = init.root_token.clone();
    (bvault, dir, token)
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_config_ca_key_plus_chain() {
    let (bvault, dir, token) = setup().await;
    defer!( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let (root_pem, _root_kp_pem, int_pem, int_kp_pem, _ri) = build_chain();
    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone()).await.unwrap();

    // key(int) + int cert + root cert in one paste.
    let bundle = format!("{int_kp_pem}{int_pem}{root_pem}");
    let resp = write_ok(&core, &token, "pki/config/ca", json!({"pem_bundle": bundle}).as_object().unwrap().clone()).await;
    assert_eq!(resp["imported_issuers"].as_array().unwrap().len(), 2, "two issuers imported");
    assert_eq!(resp["imported_keys"].as_array().unwrap().len(), 1, "one signing issuer (int)");
    let chain = resp["chain"].as_array().unwrap();
    let signing = chain.iter().find(|e| e["has_key"].as_bool().unwrap()).unwrap();
    assert_eq!(signing["common_name"], "Chain Test Intermediate");
    let keyless = chain.iter().find(|e| e["keyless"].as_bool().unwrap()).unwrap();
    assert_eq!(keyless["common_name"], "Chain Test Root");
    assert!(keyless["self_signed"].as_bool().unwrap(), "root is self-signed");

    // Two issuers show in the registry.
    let issuers = list(&core, &token, "pki/issuers").await;
    assert_eq!(issuers["keys"].as_array().unwrap().len(), 2);

    // Issue a leaf: the default (int) signs, chain resolves int → root.
    write_ok(&core, &token, "pki/roles/web",
        json!({"ttl": "24h", "key_type": "ec", "allow_any_name": true, "server_flag": true}).as_object().unwrap().clone()).await;
    let issued = write_ok(&core, &token, "pki/issue/web",
        json!({"common_name": "leaf.example.com", "ttl": "12h"}).as_object().unwrap().clone()).await;
    let ca_chain = issued["ca_chain"].as_array().unwrap();
    assert_eq!(ca_chain.len(), 2, "leaf chains through int up to root");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_config_ca_certs_only_trust_import() {
    let (bvault, dir, token) = setup().await;
    defer!( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let (root_pem, _root_kp_pem, int_pem, _int_kp_pem, _ri) = build_chain();
    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone()).await.unwrap();

    // No private key at all — both CAs import as trust anchors.
    let bundle = format!("{int_pem}{root_pem}");
    let resp = write_ok(&core, &token, "pki/config/ca", json!({"pem_bundle": bundle}).as_object().unwrap().clone()).await;
    assert_eq!(resp["imported_issuers"].as_array().unwrap().len(), 2);
    assert!(resp["imported_keys"].as_array().unwrap().is_empty(), "no signing issuer without a key");

    // With no signing issuer and no default pointer, issuance must fail.
    write_ok(&core, &token, "pki/roles/web",
        json!({"ttl": "24h", "key_type": "ec", "allow_any_name": true, "server_flag": true}).as_object().unwrap().clone()).await;
    let err = write(&core, &token, "pki/issue/web",
        json!({"common_name": "leaf.example.com"}).as_object().unwrap().clone()).await;
    assert!(err.is_err(), "cannot issue from a trust-only mount");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_config_ca_key_mismatch_rejected() {
    let (bvault, dir, token) = setup().await;
    defer!( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let (root_pem, _root_kp_pem, _int_pem, int_kp_pem, _ri) = build_chain();
    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone()).await.unwrap();

    // Root cert + intermediate's key: the key matches neither pasted cert.
    let bundle = format!("{root_pem}{int_kp_pem}");
    let err = write(&core, &token, "pki/config/ca", json!({"pem_bundle": bundle}).as_object().unwrap().clone()).await;
    assert!(err.is_err(), "key matching no cert in the bundle must be rejected");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_config_ca_leaf_rejected() {
    let (bvault, dir, token) = setup().await;
    defer!( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let (_root_pem, _root_kp_pem, _int_pem, _int_kp_pem, root_issuer) = build_chain();
    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone()).await.unwrap();

    // A non-CA leaf, signed by the root.
    let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let leaf_kp_pem = leaf_kp.serialize_pem();
    let mut leaf_params = CertificateParams::new(vec!["leaf.example.com".to_string()]).unwrap();
    leaf_params.is_ca = IsCa::NoCa;
    let leaf_cert = leaf_params.signed_by(&leaf_kp, &root_issuer).unwrap();
    let bundle = format!("{}{leaf_kp_pem}", leaf_cert.pem());
    let err = write(&core, &token, "pki/config/ca", json!({"pem_bundle": bundle}).as_object().unwrap().clone()).await;
    assert!(err.is_err(), "a leaf cert must be rejected by config/ca");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_config_ca_idempotent_reimport() {
    let (bvault, dir, token) = setup().await;
    defer!( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let (root_pem, root_kp_pem, int_pem, int_kp_pem, _ri) = build_chain();
    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone()).await.unwrap();

    // First: import the root with its key (signing root).
    let root_bundle = format!("{root_pem}{root_kp_pem}");
    write_ok(&core, &token, "pki/config/ca", json!({"pem_bundle": root_bundle}).as_object().unwrap().clone()).await;

    // Then: import int(key) + int + root. Root is already present (by
    // serial) → skipped; only the intermediate is newly imported.
    let chain_bundle = format!("{int_kp_pem}{int_pem}{root_pem}");
    let resp = write_ok(&core, &token, "pki/config/ca", json!({"pem_bundle": chain_bundle}).as_object().unwrap().clone()).await;
    assert_eq!(resp["imported_issuers"].as_array().unwrap().len(), 1, "only the intermediate is new");
    let chain = resp["chain"].as_array().unwrap();
    let root_entry = chain.iter().find(|e| e["self_signed"].as_bool().unwrap()).unwrap();
    assert!(root_entry["skipped"].as_bool().unwrap(), "root skipped as already present");

    // Registry has exactly two issuers (root once, int once).
    let issuers = list(&core, &token, "pki/issuers").await;
    assert_eq!(issuers["keys"].as_array().unwrap().len(), 2);
}
