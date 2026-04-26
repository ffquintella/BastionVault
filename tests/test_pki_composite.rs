//! PKI Secret Engine — Phase 3 (composite / hybrid) preview tests.
//!
//! This test only compiles and runs when the `pki_pqc_composite` feature is
//! on:  `cargo test --features pki_pqc_composite --test test_pki_composite`.
//!
//! What it asserts:
//! - Composite role + composite root issue end-to-end and the cert's
//!   `signatureAlgorithm` carries the IETF lamps draft OID
//!   `2.16.840.1.114027.80.8.1.28` (id-MLDSA65-ECDSA-P256-SHA512).
//! - The leaf's composite signature parses as `SEQUENCE { BIT STRING,
//!   BIT STRING }` and *each half* verifies independently:
//!   - the PQ half against the CA's ML-DSA-65 sub-key, using `fips204` directly
//!   - the classical half against the CA's ECDSA-P256 sub-key, using `p256`
//!   This proves both halves are real, signed-by-the-CA bits — not just
//!   well-formed DER.
//! - The CRL signed by a composite CA carries the composite OID and lists the
//!   revoked serial.
//! - Mixed-chain rejection: a composite role on a classical CA fails.

#![cfg(feature = "pki_pqc_composite")]

use std::{collections::HashMap, env, fs};

use base64::Engine;
use bastion_vault::{
    core::{Core, SealConfig},
    logical::{Operation, Request},
    storage, BastionVault,
};
use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier as MlDsaVerifier},
};
use go_defer::defer;
use p256::ecdsa::{signature::Verifier as EcdsaVerifier, Signature as EcdsaSig, VerifyingKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use x509_cert::{
    crl::CertificateList,
    der::{Decode, Encode},
    Certificate,
};

const COMPOSITE_OID: &str = "2.16.840.1.114027.80.8.1.28";
const ML_DSA_65_PK_LEN: usize = 1952;
const ML_DSA_65_SIG_LEN: usize = 3309;

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
async fn test_pki_phase3_composite_end_to_end() {
    let dir = env::temp_dir().join("bastion_vault_pki_phase3_composite");
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
    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone()).await;

    // Generate a composite root.
    let root_resp = write(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({
            "common_name": "composite-root.example.com",
            "key_type": "ecdsa-p256+ml-dsa-65",
            "ttl": "8760h"
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await
    .unwrap();
    let root_pem = root_resp["certificate"].as_str().unwrap().to_string();

    // Parse and confirm OID.
    let root_der = pem_decode_first(&root_pem);
    let root_cert = Certificate::from_der(&root_der).expect("parse root");
    assert_eq!(
        root_cert.signature_algorithm.oid.to_string(),
        COMPOSITE_OID,
        "root cert must be signed with composite OID"
    );

    // Composite SPKI is a DER SEQUENCE of two BIT STRINGs (PQ then classical).
    // Pull them apart.
    let spki_bits = root_cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let (pq_pk, classical_pk) = parse_two_bitstring_seq(spki_bits);
    assert_eq!(pq_pk.len(), ML_DSA_65_PK_LEN, "PQ half is 1952-byte ML-DSA-65 raw pk");
    assert_eq!(classical_pk.len(), 65, "classical half is 65-byte SEC1 uncompressed P-256 point");

    // Verify both halves of the root self-signature.
    verify_composite_self_signature(&root_cert, &pq_pk, &classical_pk);

    // Create a composite role.
    write(
        &core,
        &token,
        "pki/roles/composite-web",
        json!({
            "ttl": "24h",
            "key_type": "ecdsa-p256+ml-dsa-65",
            "key_bits": 0,
            "allow_any_name": true,
            "server_flag": true,
            "client_flag": false
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await;

    // Issue a leaf.
    let issued = write(
        &core,
        &token,
        "pki/issue/composite-web",
        json!({
            "common_name": "composite-leaf.example.com",
            "alt_names": "composite-leaf-alt.example.com,127.0.0.1",
            "ttl": "12h"
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await
    .unwrap();
    let leaf_pem = issued["certificate"].as_str().unwrap().to_string();
    let leaf_serial = issued["serial_number"].as_str().unwrap().to_string();

    let leaf_der = pem_decode_first(&leaf_pem);
    let leaf_cert = Certificate::from_der(&leaf_der).expect("parse leaf");
    assert_eq!(leaf_cert.signature_algorithm.oid.to_string(), COMPOSITE_OID);
    assert_eq!(
        leaf_cert.tbs_certificate.issuer.to_string(),
        root_cert.tbs_certificate.subject.to_string()
    );

    // Both halves of the leaf signature verify under the matching halves of
    // the root's composite public key.
    verify_composite_chain_signature(&leaf_cert, &pq_pk, &classical_pk);

    // Revoke + CRL OID + revoked-serial check.
    write(&core, &token, "pki/revoke", json!({"serial_number": leaf_serial}).as_object().unwrap().clone()).await;
    let crl_resp = read(&core, &token, "pki/crl").await.unwrap();
    let crl_pem = crl_resp["crl"].as_str().unwrap();
    let crl_der = pem_decode_first(crl_pem);
    let crl = CertificateList::from_der(&crl_der).expect("parse CRL");
    assert_eq!(crl.signature_algorithm.oid.to_string(), COMPOSITE_OID);
    let revoked: Vec<String> = crl
        .tbs_cert_list
        .revoked_certificates
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|r| {
            r.serial_number
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        })
        .collect();
    assert!(
        revoked.iter().any(|s| s == &leaf_serial),
        "revoked serial {leaf_serial} expected in CRL, got {revoked:?}"
    );

    // Mixed-chain rejection: a classical role cannot run on a composite CA.
    write(
        &core,
        &token,
        "pki/roles/classical-web",
        json!({"ttl": "24h", "key_type": "ec", "allow_any_name": true})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    let mut req = Request::new("pki/issue/classical-web");
    req.operation = Operation::Write;
    req.client_token = token.clone();
    req.body = Some(json!({"common_name": "no.example.com"}).as_object().unwrap().clone());
    assert!(
        core.handle_request(&mut req).await.is_err(),
        "classical role on composite CA must be rejected (mixed-chain)"
    );
}

/// Parse a DER-encoded `SEQUENCE { BIT STRING, BIT STRING }` and return both
/// halves as raw byte slices. Reads only what the test needs — any
/// length-encoding edge case fails the test rather than hiding a bug.
fn parse_two_bitstring_seq(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Outer SEQUENCE.
    assert_eq!(der[0], 0x30, "outer must be SEQUENCE");
    let (outer_len, outer_off) = parse_length(&der[1..]);
    let body = &der[1 + outer_off..1 + outer_off + outer_len];
    // First BIT STRING.
    let (first, rest) = take_bitstring(body);
    // Second BIT STRING.
    let (second, _) = take_bitstring(rest);
    (first.to_vec(), second.to_vec())
}

fn take_bitstring(der: &[u8]) -> (&[u8], &[u8]) {
    assert_eq!(der[0], 0x03, "BIT STRING tag");
    let (len, off) = parse_length(&der[1..]);
    let total = 1 + off + len;
    // Skip the leading "unused bits" byte.
    let payload = &der[1 + off + 1..1 + off + len];
    (payload, &der[total..])
}

fn parse_length(b: &[u8]) -> (usize, usize) {
    if b[0] & 0x80 == 0 {
        return (b[0] as usize, 1);
    }
    let n = (b[0] & 0x7f) as usize;
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | b[1 + i] as usize;
    }
    (len, 1 + n)
}

fn verify_composite_self_signature(cert: &Certificate, pq_pk: &[u8], classical_pk: &[u8]) {
    let tbs_der = cert.tbs_certificate.to_der().unwrap();
    let sig_bytes = cert.signature.raw_bytes();
    let (pq_sig, classical_sig) = parse_two_bitstring_seq(sig_bytes);
    verify_pq_half(&tbs_der, pq_pk, &pq_sig);
    verify_classical_half(&tbs_der, classical_pk, &classical_sig);
}

fn verify_composite_chain_signature(leaf: &Certificate, ca_pq_pk: &[u8], ca_classical_pk: &[u8]) {
    let tbs_der = leaf.tbs_certificate.to_der().unwrap();
    let sig_bytes = leaf.signature.raw_bytes();
    let (pq_sig, classical_sig) = parse_two_bitstring_seq(sig_bytes);
    verify_pq_half(&tbs_der, ca_pq_pk, &pq_sig);
    verify_classical_half(&tbs_der, ca_classical_pk, &classical_sig);
}

/// Reproduce the engine's prehash and verify the ML-DSA-65 half. Must stay
/// in sync with `composite::bv_prehash` — the constant below is the source
/// of truth in the test, the engine has the matching constant in
/// `src/modules/pki/composite.rs`. If we ever change the prehash without
/// bumping the OID, this test will fail and force a synchronised update.
fn verify_pq_half(msg: &[u8], pk_bytes: &[u8], sig: &[u8]) {
    assert_eq!(sig.len(), ML_DSA_65_SIG_LEN);
    let prehashed = bv_prehash_v0(msg);
    let pk_arr: [u8; ML_DSA_65_PK_LEN] = pk_bytes.try_into().unwrap();
    let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_arr).unwrap();
    let sig_arr: [u8; ML_DSA_65_SIG_LEN] = sig.try_into().unwrap();
    assert!(
        pk.verify(&prehashed, &sig_arr, &[]),
        "PQ half (ML-DSA-65) of composite signature must verify"
    );
}

fn verify_classical_half(msg: &[u8], pk_bytes: &[u8], sig: &[u8]) {
    let prehashed = bv_prehash_v0(msg);
    // ECDSA verifying key from SEC1 uncompressed.
    let vk = VerifyingKey::from_sec1_bytes(pk_bytes).unwrap();
    let sig = EcdsaSig::from_der(sig).unwrap();
    vk.verify(&prehashed, &sig).expect("classical half (ECDSA-P256) of composite signature must verify");
}

fn bv_prehash_v0(msg: &[u8]) -> Vec<u8> {
    const DOMAIN: &[u8] = b"BastionVault-PKI-Composite-v0/MLDSA65+ECDSAP256/v0";
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(msg);
    h.finalize().to_vec()
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
    base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()).unwrap()
}
