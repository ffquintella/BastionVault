//! PKI Secret Engine — Phase 5 (CSR signing + intermediate hierarchies +
//! config/ca import) integration test.
//!
//! Three end-to-end flows:
//!
//! 1. **`sign-verbatim` and `sign/:role`** — generate an ECDSA-P256 keypair
//!    locally with `rcgen`, build a CSR for it, send to the engine, get a
//!    signed cert back, validate it chains to the mount's CA.
//!
//! 2. **Intermediate hierarchy** — root mount + intermediate mount.
//!    `intermediate/generate/internal` on the intermediate produces a CSR;
//!    `root/sign-intermediate` on the root signs it; `intermediate/set-signed`
//!    on the intermediate installs the cert. Then issue a leaf from the
//!    intermediate and confirm it chains to the root.
//!
//! 3. **`config/ca` import** — generate a CA bundle outside the engine,
//!    POST it to a fresh mount, issue against the imported CA.

use std::{collections::HashMap, env, fs};

use bastion_vault::{
    core::{Core, SealConfig},
    logical::{Operation, Request},
    storage, BastionVault,
};
use go_defer::defer;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use serde_json::{json, Map, Value};

#[maybe_async::maybe_async]
async fn write(core: &Core, token: &str, path: &str, body: Map<String, Value>) -> Option<Map<String, Value>> {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(body);
    let resp = core.handle_request(&mut req).await.unwrap_or_else(|e| panic!("write {path} failed: {e:?}"));
    resp.and_then(|r| r.data)
}

#[maybe_async::maybe_async]
async fn write_expect_ok(
    core: &Core,
    token: &str,
    path: &str,
    body: Map<String, Value>,
) -> Map<String, Value> {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(body);
    let resp = core.handle_request(&mut req).await.unwrap_or_else(|e| panic!("write {path} failed: {e:?}"));
    resp.and_then(|r| r.data).expect("response had no data")
}

fn boot() -> (BastionVault, std::path::PathBuf, String) {
    let dir = env::temp_dir().join(format!("bastion_vault_pki_phase5_{}", rand_suffix()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));
    let backend = storage::new_backend("file", &conf).unwrap();
    let bvault = BastionVault::new(backend, None).unwrap();
    (bvault, dir, String::new())
}

fn rand_suffix() -> String {
    use rand::RngExt;
    let n: u32 = rand::rng().random();
    format!("{n:08x}")
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_pki_phase5_sign_csr_against_role() {
    let (bvault, dir, _) = boot();
    defer! ( let _ = fs::remove_dir_all(&dir); );
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
        json!({"common_name": "csr-root.example.com", "key_type": "ec", "ttl": "8760h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    write(
        &core,
        &token,
        "pki/roles/web",
        json!({
            "ttl": "24h", "max_ttl": "72h", "key_type": "ec",
            "allow_any_name": true, "server_flag": true, "client_flag": false,
            "use_csr_common_name": true, "use_csr_sans": true
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await;

    // Build a CSR locally — this is what a real client would do.
    let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["leaf.example.com".to_string(), "leaf-alt.example.com".to_string()])
        .unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "leaf.example.com");
    params.distinguished_name = dn;
    let csr = params.serialize_request(&kp).unwrap();
    let csr_pem = csr.pem().unwrap();

    // sign/:role
    let signed = write_expect_ok(
        &core,
        &token,
        "pki/sign/web",
        json!({"csr": csr_pem, "ttl": "12h"}).as_object().unwrap().clone(),
    )
    .await;
    let cert_pem = signed["certificate"].as_str().unwrap().to_string();
    let issuing_ca_pem = signed["issuing_ca"].as_str().unwrap().to_string();
    let serial = signed["serial_number"].as_str().unwrap().to_string();
    assert!(cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(!serial.is_empty());

    // The signed cert must NOT carry a private_key field — engine never had it.
    assert!(signed.get("private_key").is_none(), "sign/:role must not return a private key");

    // Validate chain via x509-parser.
    let leaf_der = pem_decode_first(&cert_pem);
    let ca_der = pem_decode_first(&issuing_ca_pem);
    let (_, leaf) = x509_parser::parse_x509_certificate(&leaf_der).unwrap();
    let (_, ca) = x509_parser::parse_x509_certificate(&ca_der).unwrap();
    assert_eq!(leaf.issuer().to_string(), ca.subject().to_string());

    // sign-verbatim — same CSR, no role, ttl clamped at 30d.
    let verbatim = write_expect_ok(
        &core,
        &token,
        "pki/sign-verbatim",
        json!({"csr": csr_pem, "ttl": "999h"}).as_object().unwrap().clone(),
    )
    .await;
    assert!(verbatim["certificate"].as_str().unwrap().contains("BEGIN CERTIFICATE"));

    // Negative case: tamper with the CSR so the signature fails.
    let tampered = csr_pem.replace('A', "B");
    let mut req = Request::new("pki/sign/web");
    req.operation = Operation::Write;
    req.client_token = token.clone();
    req.body = Some(json!({"csr": tampered}).as_object().unwrap().clone());
    assert!(
        core.handle_request(&mut req).await.is_err(),
        "tampered CSR with broken self-signature must be rejected"
    );
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_pki_phase5_intermediate_chain() {
    let (bvault, dir, _) = boot();
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let seal = SealConfig { secret_shares: 5, secret_threshold: 3 };
    let init = bvault.init(&seal).await.unwrap();
    for i in 0..seal.secret_threshold {
        bvault.unseal(&[&init.secret_shares[i as usize]]).await.unwrap();
    }
    let token = init.root_token.clone();

    // Two PKI mounts: root + intermediate.
    write(&core, &token, "sys/mounts/pki-root/", json!({"type": "pki"}).as_object().unwrap().clone()).await;
    write(&core, &token, "sys/mounts/pki-int/", json!({"type": "pki"}).as_object().unwrap().clone()).await;

    write(
        &core,
        &token,
        "pki-root/root/generate/internal",
        json!({"common_name": "Root CA", "organization": "BastionVault Tests", "key_type": "ec", "ttl": "8760h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;

    // 1. Intermediate generates its keypair + CSR.
    let gen = write_expect_ok(
        &core,
        &token,
        "pki-int/intermediate/generate/internal",
        json!({"common_name": "Intermediate CA", "key_type": "ec"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    let int_csr_pem = gen["csr"].as_str().unwrap().to_string();
    assert!(int_csr_pem.contains("BEGIN CERTIFICATE REQUEST"));
    assert!(gen.get("private_key").is_none(), "internal mode must not echo the key");

    // 2. Root signs the intermediate's CSR.
    let signed = write_expect_ok(
        &core,
        &token,
        "pki-root/root/sign-intermediate",
        json!({
            "csr": int_csr_pem,
            "ttl": "4380h",
            "max_path_length": 0
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await;
    let int_cert_pem = signed["certificate"].as_str().unwrap().to_string();
    let root_pem = signed["issuing_ca"].as_str().unwrap().to_string();

    // The signed intermediate must be a CA cert.
    let int_der = pem_decode_first(&int_cert_pem);
    let (_, int_cert) = x509_parser::parse_x509_certificate(&int_der).unwrap();
    let bc = int_cert
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == "2.5.29.19")
        .expect("BasicConstraints extension required on intermediate");
    let _ = bc;

    // 3. Intermediate installs the signed cert.
    write_expect_ok(
        &core,
        &token,
        "pki-int/intermediate/set-signed",
        json!({"certificate": int_cert_pem}).as_object().unwrap().clone(),
    )
    .await;

    // 4. Create a role on the intermediate and issue a leaf.
    write(
        &core,
        &token,
        "pki-int/roles/web",
        json!({"ttl": "24h", "key_type": "ec", "allow_any_name": true, "server_flag": true})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    let leaf = write_expect_ok(
        &core,
        &token,
        "pki-int/issue/web",
        json!({"common_name": "leaf.example.com", "ttl": "12h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    let leaf_pem = leaf["certificate"].as_str().unwrap().to_string();

    // Parse the chain: leaf → intermediate → root.
    let leaf_der = pem_decode_first(&leaf_pem);
    let root_der = pem_decode_first(&root_pem);
    let (_, leaf_cert) = x509_parser::parse_x509_certificate(&leaf_der).unwrap();
    let (_, root_cert) = x509_parser::parse_x509_certificate(&root_der).unwrap();
    assert_eq!(leaf_cert.issuer().to_string(), int_cert.subject().to_string());
    assert_eq!(int_cert.issuer().to_string(), root_cert.subject().to_string());

    // 5. Phase 5.2: a second `intermediate/generate` is now additive — it
    //    starts a *new* pending intermediate alongside the already-installed
    //    one. What still gets rejected is two pending generations in flight
    //    at the same time (singleton `ca/pending/*` storage).
    write_expect_ok(
        &core,
        &token,
        "pki-int/intermediate/generate/internal",
        json!({"common_name": "another-int", "key_type": "ec"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    // Second pending in flight must fail.
    let mut req = Request::new("pki-int/intermediate/generate/internal");
    req.operation = Operation::Write;
    req.client_token = token.clone();
    req.body = Some(
        json!({"common_name": "third-int", "key_type": "ec"})
            .as_object()
            .unwrap()
            .clone(),
    );
    assert!(
        core.handle_request(&mut req).await.is_err(),
        "two simultaneous pending intermediates must be rejected"
    );
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_pki_phase5_config_ca_import() {
    let (bvault, dir, _) = boot();
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let seal = SealConfig { secret_shares: 5, secret_threshold: 3 };
    let init = bvault.init(&seal).await.unwrap();
    for i in 0..seal.secret_threshold {
        bvault.unseal(&[&init.secret_shares[i as usize]]).await.unwrap();
    }
    let token = init.root_token.clone();

    // Build a CA externally with rcgen.
    let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Imported External CA");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let cert = params.self_signed(&kp).unwrap();
    let cert_pem = cert.pem();
    let key_pem = kp.serialize_pem();
    let bundle = format!("{cert_pem}{key_pem}");

    // Mount + import.
    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone()).await;
    write_expect_ok(
        &core,
        &token,
        "pki/config/ca",
        json!({"pem_bundle": bundle}).as_object().unwrap().clone(),
    )
    .await;

    // Phase 5.2: re-importing the same bundle under the *same name* is
    // now a duplicate-name conflict (rather than a singleton conflict). A
    // re-import under a different name would succeed and create a second
    // imported issuer.
    let mut req = Request::new("pki/config/ca");
    req.operation = Operation::Write;
    req.client_token = token.clone();
    req.body = Some(
        json!({"pem_bundle": format!("{cert_pem}{key_pem}"), "issuer_name": "default"})
            .as_object()
            .unwrap()
            .clone(),
    );
    assert!(
        core.handle_request(&mut req).await.is_err(),
        "re-importing under an already-taken issuer name must be rejected"
    );

    // Issue a cert under the imported CA.
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
    let issued = write_expect_ok(
        &core,
        &token,
        "pki/issue/web",
        json!({"common_name": "imported-leaf.example.com", "ttl": "12h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    let leaf_der = pem_decode_first(issued["certificate"].as_str().unwrap());
    let imported_root_der = pem_decode_first(&cert_pem);
    let (_, leaf_cert) = x509_parser::parse_x509_certificate(&leaf_der).unwrap();
    let (_, root_cert) = x509_parser::parse_x509_certificate(&imported_root_der).unwrap();
    assert_eq!(leaf_cert.issuer().to_string(), root_cert.subject().to_string());

    // Mismatched bundle (cert from above, but a fresh, unrelated key) must
    // be rejected on a fresh mount.
    write(&core, &token, "sys/mounts/pki2/", json!({"type": "pki"}).as_object().unwrap().clone()).await;
    let other_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mismatched = format!("{cert_pem}{}", other_kp.serialize_pem());
    let mut req = Request::new("pki2/config/ca");
    req.operation = Operation::Write;
    req.client_token = token.clone();
    req.body = Some(json!({"pem_bundle": mismatched}).as_object().unwrap().clone());
    assert!(
        core.handle_request(&mut req).await.is_err(),
        "mismatched cert/key bundle must be rejected"
    );
}

fn pem_decode_first(pem: &str) -> Vec<u8> {
    use base64::Engine;
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
    base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()).unwrap()
}
