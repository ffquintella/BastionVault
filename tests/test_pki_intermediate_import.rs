//! Confirm the PKI engine accepts intermediate emitters via
//! `pki/config/ca` (not just self-signed roots), and that the chain
//! walk + `ca_chain` on issue responses correctly link an
//! externally-built intermediate up to its imported root.
//!
//! Coverage:
//! 1. Import a root via `config/ca`. Root issues a leaf — chain has
//!    one entry (the root itself).
//! 2. Build an intermediate externally (rcgen, signed by the root),
//!    import it via `config/ca` under a separate `issuer_name`.
//! 3. `pki/issuer/<intermediate>/chain` returns the intermediate +
//!    the root in that order (length 2).
//! 4. Issuance pinned to the intermediate (`issuer_ref`) returns a
//!    `ca_chain` of length 2 and the leaf cert's Issuer DN matches
//!    the intermediate's Subject DN.
//! 5. A leaf cert (no BasicConstraints CA flag) is rejected by
//!    `config/ca` with a clear message — the engine refuses to
//!    promote a leaf to issuer status.

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
    core.handle_request(&mut req).await.map(|r| r.and_then(|x| x.data)).map_err(|e| format!("{e:?}"))
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
    let dir = env::temp_dir().join(format!("bastion_vault_pki_intermediate_import_{n:08x}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));
    let backend = storage::new_backend("file", &conf).unwrap();
    let bvault = BastionVault::new(backend, None).unwrap();
    (bvault, dir)
}

fn cert_subject(cert_pem: &str) -> String {
    let der = pem::parse(cert_pem.as_bytes()).unwrap().into_contents();
    let (_, p) = x509_parser::parse_x509_certificate(&der).unwrap();
    p.tbs_certificate.subject.to_string()
}

fn cert_issuer(cert_pem: &str) -> String {
    let der = pem::parse(cert_pem.as_bytes()).unwrap().into_contents();
    let (_, p) = x509_parser::parse_x509_certificate(&der).unwrap();
    p.tbs_certificate.issuer.to_string()
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_pki_intermediate_import_end_to_end() {
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

    // ── Build a root externally with rcgen ────────────────────────────
    let root_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    // Snapshot the keypair PEM BEFORE moving root_kp into the Issuer
    // wrapper (rcgen 0.14 takes ownership of the signing key).
    let root_kp_pem = root_kp.serialize_pem();
    let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut root_dn = DistinguishedName::new();
    root_dn.push(DnType::CommonName, "Test Root External");
    root_params.distinguished_name = root_dn;
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root_cert = root_params.self_signed(&root_kp).unwrap();
    let root_pem = root_cert.pem();
    let root_subject = cert_subject(&root_pem);
    // Reconstruct the issuer handle for signing the intermediate +
    // a leaf later in the test. `Issuer::from_ca_cert_pem` consumes
    // its signing key, but we already grabbed `root_kp_pem`.
    let root_issuer = Issuer::from_ca_cert_pem(&root_pem, root_kp).unwrap();

    // ── Build an intermediate signed by the root ──────────────────────
    let int_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let int_kp_pem = int_kp.serialize_pem();
    let mut int_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut int_dn = DistinguishedName::new();
    int_dn.push(DnType::CommonName, "Test Intermediate External");
    int_params.distinguished_name = int_dn;
    int_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    int_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let int_cert = int_params.signed_by(&int_kp, &root_issuer).unwrap();
    let int_pem = int_cert.pem();
    let int_subject = cert_subject(&int_pem);

    // ── Import root via config/ca ─────────────────────────────────────
    let root_bundle = format!("{root_pem}{root_kp_pem}");
    let root_resp = write_ok(
        &core, &token, "pki/config/ca",
        json!({"pem_bundle": root_bundle, "issuer_name": "external-root"})
            .as_object().unwrap().clone(),
    ).await;
    let root_id = root_resp["issuer_id"].as_str().unwrap().to_string();
    assert!(!root_id.is_empty());

    // ── Import intermediate via config/ca ─────────────────────────────
    let int_bundle = format!("{int_pem}{int_kp_pem}");
    let int_resp = write_ok(
        &core, &token, "pki/config/ca",
        json!({"pem_bundle": int_bundle, "issuer_name": "external-intermediate"})
            .as_object().unwrap().clone(),
    ).await;
    let int_id = int_resp["issuer_id"].as_str().unwrap().to_string();
    assert!(!int_id.is_empty());
    assert_ne!(root_id, int_id);

    // ── Chain walk: intermediate's chain should be [intermediate, root] ──
    let chain = read(&core, &token, "pki/issuer/external-intermediate/chain").await;
    let chain_arr = chain["ca_chain"].as_array().unwrap();
    assert_eq!(
        chain_arr.len(),
        2,
        "intermediate chain must include the root once it's imported alongside; got {}",
        chain_arr.len(),
    );
    assert_eq!(
        cert_subject(chain_arr[0].as_str().unwrap()),
        int_subject,
        "chain[0] must be the leaf-issuer (intermediate)",
    );
    assert_eq!(
        cert_subject(chain_arr[1].as_str().unwrap()),
        root_subject,
        "chain[1] must be the root",
    );

    // The root-only chain should still be length 1.
    let root_chain = read(&core, &token, "pki/issuer/external-root/chain").await;
    assert_eq!(root_chain["ca_chain"].as_array().unwrap().len(), 1);

    // ── Issue a leaf pinned to the intermediate ──────────────────────
    write(
        &core, &token, "pki/roles/web",
        json!({
            "ttl": "24h", "max_ttl": "72h", "key_type": "ec",
            "allow_any_name": true, "server_flag": true, "client_flag": true,
        }).as_object().unwrap().clone(),
    ).await.expect("write role");

    let issued = write_ok(
        &core, &token, "pki/issue/web",
        json!({
            "common_name": "leaf.example.com",
            "issuer_ref": "external-intermediate",
        }).as_object().unwrap().clone(),
    ).await;

    let leaf_pem = issued["certificate"].as_str().unwrap().to_string();
    assert_eq!(
        cert_issuer(&leaf_pem),
        int_subject,
        "leaf must be signed by the intermediate",
    );
    let issued_chain = issued["ca_chain"].as_array().unwrap();
    assert_eq!(
        issued_chain.len(),
        2,
        "ca_chain on issue response must include intermediate + root",
    );

    // ── Leaf certs are rejected by config/ca ──────────────────────────
    // Build a non-CA leaf signed by the root and try to import it as
    // an issuer. `root_issuer` is still live from the intermediate
    // signing step above — rcgen's `Issuer` is reusable across calls.
    let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let leaf_kp_pem = leaf_kp.serialize_pem();
    let mut leaf_params = CertificateParams::new(vec!["leaf-cant-import.example.com".to_string()]).unwrap();
    let mut leaf_dn = DistinguishedName::new();
    leaf_dn.push(DnType::CommonName, "leaf-cant-import.example.com");
    leaf_params.distinguished_name = leaf_dn;
    let leaf_cert = leaf_params.signed_by(&leaf_kp, &root_issuer).unwrap();
    let leaf_bundle = format!("{}{leaf_kp_pem}", leaf_cert.pem());
    let blocked = write(
        &core, &token, "pki/config/ca",
        json!({"pem_bundle": leaf_bundle, "issuer_name": "should-not-land"})
            .as_object().unwrap().clone(),
    ).await;
    assert!(
        blocked.is_err(),
        "leaf cert (BasicConstraints.cA=false) must be rejected by config/ca: {blocked:?}",
    );
}
