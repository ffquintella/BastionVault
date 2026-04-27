//! PKI Secret Engine — Phase 5.3: PKCS#8 envelope for ML-DSA + RSA generation.
//!
//! Two coupled deliverables, one test file:
//!
//! 1. **PKCS#8 PrivateKeyInfo for ML-DSA private keys.** Caller-facing
//!    output (the `private_key` field on `pki/issue` and
//!    `pki/intermediate/generate/exported`) was the engine's internal
//!    `BV PQC SIGNER` envelope until 5.3. Now it's a standard PKCS#8
//!    PEM with the IETF-lamps OID and the 32-byte seed wrapped in an
//!    inner OCTET STRING. The test:
//!    - issues a leaf under an ML-DSA-65 mount,
//!    - asserts the returned `private_key` is `-----BEGIN PRIVATE KEY-----`,
//!    - decodes the PKCS#8 manually, finds the inner OCTET STRING, and
//!      runs the seed back through `fips204` to confirm it matches the
//!      cert's SubjectPublicKeyInfo.
//!
//! 2. **RSA generation via rcgen.** Until 5.3, `key_type = "rsa"` was
//!    accepted at role-write time but rejected at signer-creation time
//!    because rcgen+ring can't generate RSA keypairs. 5.3 plugs the
//!    `rsa` crate's generator → PKCS#8 → `rcgen::KeyPair::from_pem_and_sign_algo`.
//!    The test generates an RSA-2048 root, issues a leaf, verifies the
//!    chain chains, and sanity-checks the `signatureAlgorithm` OID is
//!    `sha256WithRSAEncryption` (RSA-2048 → SHA-256, per Phase 5.3's
//!    bit-size→hash convention).

use std::{collections::HashMap, env, fs};

use base64::Engine;
use bastion_vault::{
    core::{Core, SealConfig},
    logical::{Operation, Request},
    storage, BastionVault,
};
use bv_crypto::{MlDsa65Provider, ML_DSA_65_PUBLIC_KEY_LEN};
use go_defer::defer;
use serde_json::{json, Map, Value};

const ML_DSA_65_OID: &str = "2.16.840.1.101.3.4.3.18";
const SHA256_WITH_RSA_OID: &str = "1.2.840.113549.1.1.11";

#[maybe_async::maybe_async]
async fn write(core: &Core, token: &str, path: &str, body: Map<String, Value>) -> Option<Map<String, Value>> {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(body);
    let resp = core
        .handle_request(&mut req)
        .await
        .unwrap_or_else(|e| panic!("write {path} failed: {e:?}"));
    resp.and_then(|r| r.data)
}

fn boot(name: &str) -> (BastionVault, std::path::PathBuf) {
    let dir = env::temp_dir().join(format!("bastion_vault_pki_phase5_3_{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));
    let backend = storage::new_backend("file", &conf).unwrap();
    let bvault = BastionVault::new(backend, None).unwrap();
    (bvault, dir)
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_pki_phase5_3_pqc_pkcs8_envelope() {
    let (bvault, dir) = boot("pqc_pkcs8");
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
        json!({"common_name": "PQC Root", "key_type": "ml-dsa-65", "ttl": "8760h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    write(
        &core,
        &token,
        "pki/roles/web",
        json!({"ttl": "24h", "key_type": "ml-dsa-65", "allow_any_name": true, "server_flag": true})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;

    let issued = write(
        &core,
        &token,
        "pki/issue/web",
        json!({"common_name": "leaf.example.com", "ttl": "12h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await
    .unwrap();
    let cert_pem = issued["certificate"].as_str().unwrap();
    let key_pem = issued["private_key"].as_str().unwrap();

    // (1) Format check.
    assert!(
        key_pem.contains("BEGIN PRIVATE KEY"),
        "Phase 5.3: PQC private key must be a PKCS#8 PEM, got: {}",
        key_pem.lines().next().unwrap_or("<empty>"),
    );
    assert!(!key_pem.contains("BV PQC SIGNER"), "PKCS#8 output must not carry the storage envelope label");

    // (2) Algorithm-OID check inside the PKCS#8.
    let der = pem_decode_block(key_pem, "PRIVATE KEY");
    use x509_cert::der::{Decode, asn1::OctetString};
    let info = pkcs8::PrivateKeyInfo::from_der(&der).expect("parse PKCS#8");
    assert_eq!(
        info.algorithm.oid.to_string(),
        ML_DSA_65_OID,
        "PKCS#8 AlgorithmIdentifier OID must be ML-DSA-65"
    );

    // (3) The 32-byte seed inside the OCTET STRING, run back through
    // fips204, must regenerate the same public key the cert advertises.
    let inner = OctetString::from_der(info.private_key).expect("inner OCTET STRING");
    let seed = inner.as_bytes();
    assert_eq!(seed.len(), 32, "ML-DSA-65 PKCS#8 contains a 32-byte seed");

    let kp = MlDsa65Provider.keypair_from_seed(seed).expect("regenerate keypair from seed");
    assert_eq!(kp.public_key().len(), ML_DSA_65_PUBLIC_KEY_LEN);

    let cert_der = pem_decode_block(cert_pem, "CERTIFICATE");
    let cert = x509_cert::Certificate::from_der(&cert_der).expect("parse cert");
    let cert_pk = cert.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes();
    assert_eq!(
        cert_pk,
        kp.public_key(),
        "PQC cert's SPKI key must match the seed-regenerated public key — proves PKCS#8 round-trip is lossless"
    );
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_pki_phase5_3_rsa_root_and_issue() {
    let (bvault, dir) = boot("rsa_root");
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let seal = SealConfig { secret_shares: 5, secret_threshold: 3 };
    let init = bvault.init(&seal).await.unwrap();
    for i in 0..seal.secret_threshold {
        bvault.unseal(&[&init.secret_shares[i as usize]]).await.unwrap();
    }
    let token = init.root_token.clone();
    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone()).await;

    // Phase 5.3: RSA-2048 root generation now works (was rejected with
    // ErrPkiKeyTypeInvalid before this phase). Use a long TTL because RSA
    // keygen is slow and we don't want to do it twice.
    let root = write(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({"common_name": "RSA Root", "key_type": "rsa", "key_bits": 2048, "ttl": "8760h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await
    .unwrap();
    let root_pem = root["certificate"].as_str().unwrap().to_string();

    let root_der = pem_decode_block(&root_pem, "CERTIFICATE");
    use x509_cert::der::Decode;
    let root_cert = x509_cert::Certificate::from_der(&root_der).expect("parse root");
    assert_eq!(
        root_cert.signature_algorithm.oid.to_string(),
        SHA256_WITH_RSA_OID,
        "RSA-2048 root must be signed with sha256WithRSAEncryption (Phase 5.3 bit-size→hash convention)",
    );

    write(
        &core,
        &token,
        "pki/roles/web",
        json!({
            "ttl": "24h",
            "key_type": "rsa",
            "key_bits": 2048,
            "allow_any_name": true,
            "server_flag": true
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await;

    let issued = write(
        &core,
        &token,
        "pki/issue/web",
        json!({"common_name": "rsa-leaf.example.com", "ttl": "12h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await
    .unwrap();
    let leaf_pem = issued["certificate"].as_str().unwrap();
    let leaf_key = issued["private_key"].as_str().unwrap();

    // Caller-facing leaf private key is also PKCS#8 (this is the
    // classical-RSA path; rcgen produces PKCS#8 PEM by default for
    // classical keys, so the API output here is the same shape it has
    // been since Phase 1 — the test pins it down anyway so a future
    // refactor doesn't silently regress).
    assert!(leaf_key.contains("BEGIN PRIVATE KEY"), "RSA leaf private key in PKCS#8 form");

    let leaf_der = pem_decode_block(leaf_pem, "CERTIFICATE");
    let leaf_cert = x509_cert::Certificate::from_der(&leaf_der).expect("parse leaf");
    assert_eq!(
        leaf_cert.signature_algorithm.oid.to_string(),
        SHA256_WITH_RSA_OID,
        "RSA-2048 leaf signed with sha256WithRSAEncryption"
    );

    // Chain: leaf.issuer == root.subject.
    assert_eq!(leaf_cert.tbs_certificate.issuer.to_string(), root_cert.tbs_certificate.subject.to_string());
}

fn pem_decode_block(pem: &str, label: &str) -> Vec<u8> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let begin_idx = pem.find(&begin).expect("BEGIN block missing");
    let body_start = pem[begin_idx..].find('\n').map(|i| begin_idx + i + 1).expect("PEM body");
    let body_end = begin_idx + pem[begin_idx..].find(&end).expect("END block missing");
    let body: String = pem[body_start..body_end].chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(body.as_bytes()).expect("base64 PEM body")
}
