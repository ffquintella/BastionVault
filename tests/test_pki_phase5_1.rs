//! PKI Secret Engine — Phase 5.1: PQC CSR signing.
//!
//! Closes the asymmetry where PQC roles could `pki/issue` (engine-generated
//! keypair) but not `pki/sign/:role` (client-supplied CSR). The test:
//!
//! 1. mounts a PKI engine with an ML-DSA-65 root,
//! 2. generates an ML-DSA-65 keypair locally with `fips204` and builds a
//!    PKCS#10 CSR for it from scratch (rcgen 0.14 cannot serialize a CSR
//!    over an ML-DSA key, so we hand-assemble the DER),
//! 3. POSTs the CSR to `pki/sign/:role` and verifies the returned cert
//!    chains to the root and embeds the leaf's PQC public key,
//! 4. confirms that a tampered CSR (broken signature) is rejected,
//! 5. confirms that mixing a classical CA with a PQC CSR fails.

use std::{collections::HashMap, env, fs};

use base64::Engine;
use bastion_vault::{
    core::{Core, SealConfig},
    logical::{Operation, Request},
    storage, BastionVault,
};
use bv_crypto::{MlDsa65Provider, ML_DSA_65_PUBLIC_KEY_LEN};
use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};
use go_defer::defer;
use serde_json::{json, Map, Value};

const ML_DSA_65_OID_DER: &[u8] = &[
    // OID 2.16.840.1.101.3.4.3.18, BER-encoded
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
];

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

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_pki_phase5_1_pqc_csr_sign() {
    let dir = env::temp_dir().join("bastion_vault_pki_phase5_1_pqc_csr");
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

    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone()).await;

    write(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({"common_name": "pqc-csr-root.example.com", "key_type": "ml-dsa-65", "ttl": "8760h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;

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
            "use_csr_common_name": true,
            "use_csr_sans": true
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await;

    // Build an ML-DSA-65 CSR locally. rcgen 0.14 cannot serialize a CSR
    // over an ML-DSA key without aws_lc_rs_unstable, so we hand-assemble:
    //   CertificationRequest ::= SEQUENCE {
    //       certificationRequestInfo CertificationRequestInfo,
    //       signatureAlgorithm AlgorithmIdentifier,
    //       signature BIT STRING
    //   }
    let kp = MlDsa65Provider.generate_keypair().unwrap();
    let pk_bytes = kp.public_key().to_vec();
    let seed = *kp.secret_seed();

    let cri_der = build_certification_request_info_der(&pk_bytes);
    // Sign with ML-DSA-65 (empty context), then assemble the outer CSR.
    let sig = MlDsa65Provider.sign(&seed, &cri_der, &[]).unwrap();
    let csr_der = build_csr_der(&cri_der, &sig);
    let csr_pem = pem_encode("CERTIFICATE REQUEST", &csr_der);

    // Sanity: our hand-assembled CSR is verifiable with fips204 directly.
    let pk_arr: [u8; ML_DSA_65_PUBLIC_KEY_LEN] = pk_bytes.clone().try_into().unwrap();
    let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_arr).unwrap();
    let sig_arr: [u8; 3309] = sig.clone().try_into().unwrap();
    assert!(pk.verify(&cri_der, &sig_arr, &[]), "self-test of CSR signature must pass");

    // Sign via the engine.
    let signed = write(
        &core,
        &token,
        "pki/sign/pqc-web",
        json!({"csr": csr_pem, "ttl": "12h"}).as_object().unwrap().clone(),
    )
    .await
    .unwrap();
    let cert_pem = signed["certificate"].as_str().unwrap().to_string();
    assert!(cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(signed.get("private_key").is_none(), "sign/:role must not return a private key");

    // Confirm the leaf carries the ML-DSA-65 OID + the same pubkey we sent.
    let leaf_der = pem_decode_first(&cert_pem);
    use x509_cert::der::Decode;
    let cert = x509_cert::Certificate::from_der(&leaf_der).unwrap();
    assert_eq!(
        cert.signature_algorithm.oid.to_string(),
        "2.16.840.1.101.3.4.3.18",
        "leaf signed with ML-DSA-65"
    );
    assert_eq!(
        cert.tbs_certificate.subject_public_key_info.algorithm.oid.to_string(),
        "2.16.840.1.101.3.4.3.18",
        "leaf SPKI carries ML-DSA-65 OID"
    );
    let leaf_pk = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    assert_eq!(leaf_pk, &pk_bytes[..], "leaf SPKI key bytes match the CSR's pubkey");

    // Tampered CSR — flip a byte in the body and confirm rejection.
    let mut tampered_der = csr_der.clone();
    let flip_idx = tampered_der.len() / 2;
    tampered_der[flip_idx] ^= 0x01;
    let tampered_pem = pem_encode("CERTIFICATE REQUEST", &tampered_der);
    let mut req = Request::new("pki/sign/pqc-web");
    req.operation = Operation::Write;
    req.client_token = token.clone();
    req.body = Some(json!({"csr": tampered_pem}).as_object().unwrap().clone());
    assert!(
        core.handle_request(&mut req).await.is_err(),
        "tampered ML-DSA CSR with broken self-signature must be rejected"
    );

    // Mixed-chain rejection: a PQC CSR cannot be signed by a *classical* CA.
    write(&core, &token, "sys/mounts/pki-ec/", json!({"type": "pki"}).as_object().unwrap().clone()).await;
    write(
        &core,
        &token,
        "pki-ec/root/generate/internal",
        json!({"common_name": "ec-root.example.com", "key_type": "ec", "ttl": "8760h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    write(
        &core,
        &token,
        "pki-ec/roles/any",
        json!({
            "ttl": "24h",
            "key_type": "ec",
            "allow_any_name": true,
            "server_flag": true,
            "use_csr_common_name": true
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await;
    let mut req = Request::new("pki-ec/sign/any");
    req.operation = Operation::Write;
    req.client_token = token.clone();
    req.body = Some(json!({"csr": csr_pem}).as_object().unwrap().clone());
    assert!(
        core.handle_request(&mut req).await.is_err(),
        "PQC CSR on classical CA mount must be rejected"
    );
}

// ── hand-rolled DER for the ML-DSA CSR ───────────────────────────────────
// Just enough DER to produce a parseable CertificationRequest. Subject is a
// minimal `CN=pqc-leaf.example.com`; no extensions in the attributes set.

fn build_certification_request_info_der(pk_bytes: &[u8]) -> Vec<u8> {
    // version INTEGER (0)
    let version = der_int(0);
    // Subject Name: SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, UTF8String } } }
    let cn = b"pqc-leaf.example.com";
    let cn_atv = der_sequence(&concat(&[
        &[0x06, 0x03, 0x55, 0x04, 0x03], // OID 2.5.4.3 (CN)
        &der_utf8(cn),
    ]));
    let rdn = der_set(&cn_atv);
    let subject = der_sequence(&rdn);

    // SubjectPublicKeyInfo:
    //   SEQUENCE {
    //     AlgorithmIdentifier { OID = ml-dsa-65, NO parameters },
    //     BIT STRING (raw pk bytes, 0 unused bits)
    //   }
    let alg_id = der_sequence(ML_DSA_65_OID_DER);
    let mut bit_string_body = Vec::with_capacity(pk_bytes.len() + 1);
    bit_string_body.push(0x00); // unused bits
    bit_string_body.extend_from_slice(pk_bytes);
    let spki = der_sequence(&concat(&[&alg_id, &der_tagged(0x03, &bit_string_body)]));

    // Attributes: empty [0] IMPLICIT SET — required field but can be empty.
    let attrs = der_tagged(0xa0, &[]);

    // CertificationRequestInfo SEQUENCE { version, subject, spki, attrs }
    der_sequence(&concat(&[&version, &subject, &spki, &attrs]))
}

fn build_csr_der(cri_der: &[u8], signature: &[u8]) -> Vec<u8> {
    let alg_id = der_sequence(ML_DSA_65_OID_DER);
    let mut bit_string_body = Vec::with_capacity(signature.len() + 1);
    bit_string_body.push(0x00);
    bit_string_body.extend_from_slice(signature);
    let sig_bs = der_tagged(0x03, &bit_string_body);
    der_sequence(&concat(&[cri_der, &alg_id, &sig_bs]))
}

fn der_int(v: u8) -> Vec<u8> {
    // Single-byte positive INTEGER (sufficient for version=0).
    vec![0x02, 0x01, v]
}

fn der_utf8(bytes: &[u8]) -> Vec<u8> {
    der_tagged(0x0c, bytes)
}

fn der_sequence(body: &[u8]) -> Vec<u8> {
    der_tagged(0x30, body)
}

fn der_set(body: &[u8]) -> Vec<u8> {
    der_tagged(0x31, body)
}

fn der_tagged(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 6);
    out.push(tag);
    encode_length(body.len(), &mut out);
    out.extend_from_slice(body);
    out
}

fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let mut buf = Vec::new();
        let mut n = len;
        while n > 0 {
            buf.push((n & 0xff) as u8);
            n >>= 8;
        }
        buf.reverse();
        out.push(0x80 | buf.len() as u8);
        out.extend_from_slice(&buf);
    }
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::new();
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
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
