//! PKI Secret Engine — Phase 2 (PQC / ML-DSA) integration tests.
//!
//! Mirrors the Phase 1 end-to-end shape but with `key_type = "ml-dsa-65"` for
//! both root CA and role. Verifies that:
//!
//! - the issued cert's `signatureAlgorithm` carries the ML-DSA-65 OID,
//! - the leaf signature actually verifies under the CA's ML-DSA-65 public
//!   key (round-tripped via `fips204` directly so we exercise our own DER
//!   path, not someone else's verifier),
//! - the issued CRL has the same OID and revoked serials show up.
//! - mixed-chain issuance (PQC role on classical CA) is rejected.
//! - role-create rejects `key_bits != 0` on a PQC role.

use std::{collections::HashMap, env, fs};

use base64::Engine;
use bastion_vault::{
    core::{Core, SealConfig},
    logical::{Operation, Request},
    storage, BastionVault,
};
use bv_crypto::{MlDsa65Provider, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN};
use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};
use go_defer::defer;
use serde_json::{json, Map, Value};
use x509_cert::{
    crl::CertificateList,
    der::{Decode, Encode},
    Certificate,
};

const ML_DSA_65_OID: &str = "2.16.840.1.101.3.4.3.18";

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
async fn test_pki_phase2_ml_dsa_65_end_to_end() {
    let dir = env::temp_dir().join("bastion_vault_pki_phase2_pqc");
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

    // Generate an ML-DSA-65 root.
    let root_resp = write(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({
            "common_name": "pqc-root.example.com",
            "key_type": "ml-dsa-65",
            "ttl": "8760h"
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await
    .unwrap();
    let root_pem = root_resp["certificate"].as_str().unwrap().to_string();
    assert!(root_pem.contains("BEGIN CERTIFICATE"));

    // Parse the root, confirm its signatureAlgorithm OID is ML-DSA-65.
    let root_der = pem_decode_first(&root_pem);
    let root_cert = Certificate::from_der(&root_der).expect("parse root cert");
    assert_eq!(
        root_cert.signature_algorithm.oid.to_string(),
        ML_DSA_65_OID,
        "root cert must be signed with ML-DSA-65"
    );
    assert_eq!(root_cert.tbs_certificate.subject_public_key_info.algorithm.oid.to_string(), ML_DSA_65_OID);
    let root_pk_bytes = root_cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes()
        .to_vec();
    assert_eq!(root_pk_bytes.len(), ML_DSA_65_PUBLIC_KEY_LEN, "ML-DSA-65 raw pk is 1952 bytes");
    // Verify the root's self-signature using fips204 directly. This
    // exercises our own TBS DER path: if we encoded TBS wrong, the
    // signature won't verify.
    {
        let pk_arr: [u8; ML_DSA_65_PUBLIC_KEY_LEN] = root_pk_bytes.clone().try_into().unwrap();
        let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_arr).unwrap();
        let sig_bytes = root_cert.signature.raw_bytes();
        assert_eq!(sig_bytes.len(), ML_DSA_65_SIGNATURE_LEN);
        let sig_arr: [u8; ML_DSA_65_SIGNATURE_LEN] = sig_bytes.try_into().unwrap();
        let tbs_der = root_cert.tbs_certificate.to_der().unwrap();
        assert!(pk.verify(&tbs_der, &sig_arr, &[]), "root self-signature must verify");
    }

    // Create a PQC role.
    write(
        &core,
        &token,
        "pki/roles/pqc-web",
        json!({
            "ttl": "24h",
            "key_type": "ml-dsa-65",
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

    // Reject `key_bits != 0` on a PQC role at write time.
    let mut req = Request::new("pki/roles/pqc-bad");
    req.operation = Operation::Write;
    req.client_token = token.clone();
    req.body = Some(json!({"key_type": "ml-dsa-65", "key_bits": 2048}).as_object().unwrap().clone());
    assert!(
        core.handle_request(&mut req).await.is_err(),
        "ml-dsa role with key_bits != 0 must be rejected"
    );

    // Issue a leaf.
    let issued = write(
        &core,
        &token,
        "pki/issue/pqc-web",
        json!({
            "common_name": "pqc-leaf.example.com",
            "alt_names": "pqc-leaf-alt.example.com,127.0.0.1",
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
    let leaf_key_envelope = issued["private_key"].as_str().unwrap();
    assert!(leaf_key_envelope.contains("BEGIN BV PQC SIGNER"), "PQC private key uses storage envelope");

    let leaf_der = pem_decode_first(&leaf_pem);
    let leaf_cert = Certificate::from_der(&leaf_der).expect("parse leaf");
    assert_eq!(leaf_cert.signature_algorithm.oid.to_string(), ML_DSA_65_OID);
    assert_eq!(
        leaf_cert.tbs_certificate.subject_public_key_info.algorithm.oid.to_string(),
        ML_DSA_65_OID,
        "leaf key OID matches role"
    );
    // Leaf chain check: issuer DN matches root subject DN.
    assert_eq!(
        leaf_cert.tbs_certificate.issuer.to_string(),
        root_cert.tbs_certificate.subject.to_string()
    );
    // And the leaf signature verifies under the root's public key.
    {
        let pk_arr: [u8; ML_DSA_65_PUBLIC_KEY_LEN] = root_pk_bytes.clone().try_into().unwrap();
        let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_arr).unwrap();
        let sig: [u8; ML_DSA_65_SIGNATURE_LEN] = leaf_cert.signature.raw_bytes().try_into().unwrap();
        let tbs_der = leaf_cert.tbs_certificate.to_der().unwrap();
        assert!(pk.verify(&tbs_der, &sig, &[]), "leaf signature must verify under root pk");
    }

    // Revoke + CRL parses and lists the serial.
    write(&core, &token, "pki/revoke", json!({"serial_number": leaf_serial}).as_object().unwrap().clone()).await;
    let crl_resp = read(&core, &token, "pki/crl").await.unwrap();
    let crl_pem = crl_resp["crl"].as_str().unwrap();
    let crl_der = pem_decode_first(crl_pem);
    let crl = CertificateList::from_der(&crl_der).expect("parse CRL");
    assert_eq!(crl.signature_algorithm.oid.to_string(), ML_DSA_65_OID);
    let revoked_serials: Vec<String> = crl
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
        revoked_serials.iter().any(|s| s == &leaf_serial),
        "expected revoked serial {leaf_serial} in CRL, got {revoked_serials:?}"
    );

    // Mixed-chain rejection: classical role cannot run on PQC CA.
    write(
        &core,
        &token,
        "pki/roles/classical-web",
        json!({
            "ttl": "24h",
            "key_type": "ec",
            "allow_any_name": true,
            "server_flag": true
        })
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
        "classical role on PQC CA must be rejected (mixed-chain default-secure)"
    );

    // Sanity: silence the unused MlDsa65Provider warning in this test by
    // exercising it once. This also doubles as an assertion that the
    // signature size pulled from the dependency matches our DER expectation.
    let kp = MlDsa65Provider.generate_keypair().unwrap();
    let sig = MlDsa65Provider.sign(kp.secret_seed(), b"abc", &[]).unwrap();
    assert_eq!(sig.len(), ML_DSA_65_SIGNATURE_LEN);
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
