//! `issuer/<ref>/renew` over the real HTTP boundary (`/v2`), T455.
//!
//! Renewal re-issues an issuer's CA certificate for the same key and
//! subject. See `crates/bv-engine-pki/src/issuer_renew.rs`.

use std::{thread, time::Duration};

use serde_json::{json, Map, Value};

use crate::test_utils::TestHttpServer;

fn obj(v: Value) -> Option<Map<String, Value>> {
    v.as_object().cloned()
}

/// A server with PKI mounts at each of `mounts`, PKI calls on `/v2`.
async fn boot(name: &str, mounts: &[&str]) -> TestHttpServer {
    let mut server = TestHttpServer::new(name, false).await;
    server.token = server.root_token.clone();
    for mount in mounts {
        let (status, body) = server.write(&format!("sys/mounts/{mount}/"), obj(json!({"type": "pki"})), None).unwrap();
        assert!(status < 300, "mount {mount} failed: {body}");
    }
    server.url_prefix = server.url_prefix.replace("/v1", "/v2");
    server
}

fn ok(server: &TestHttpServer, path: &str, body: Value) -> Value {
    let (status, got) = server.write(path, obj(body), None).unwrap();
    assert_eq!(status, 200, "{path} failed: {got}");
    got["data"].clone()
}

fn read(server: &TestHttpServer, path: &str) -> Value {
    let (status, got) = server.read(path, None).unwrap();
    assert_eq!(status, 200, "{path} failed: {got}");
    got["data"].clone()
}

fn der(pem_str: &str) -> Vec<u8> {
    pem::parse(pem_str.as_bytes()).expect("PEM").into_contents()
}

/// (subject DER, SPKI DER, serial hex, notBefore, notAfter, issuer DER).
fn facts(pem_str: &str) -> (Vec<u8>, Vec<u8>, String, i64, i64, Vec<u8>) {
    let der = der(pem_str);
    let (_, cert) = x509_parser::parse_x509_certificate(&der).expect("certificate");
    let tbs = &cert.tbs_certificate;
    (
        tbs.subject.as_raw().to_vec(),
        tbs.subject_pki.raw.to_vec(),
        tbs.raw_serial().iter().map(|b| format!("{b:02x}")).collect(),
        tbs.validity.not_before.timestamp(),
        tbs.validity.not_after.timestamp(),
        tbs.issuer.as_raw().to_vec(),
    )
}

fn verifies_under(cert_pem: &str, ca_pem: &str) {
    let (cert_der, ca_der) = (der(cert_pem), der(ca_pem));
    let (_, cert) = x509_parser::parse_x509_certificate(&cert_der).unwrap();
    let (_, ca) = x509_parser::parse_x509_certificate(&ca_der).unwrap();
    cert.verify_signature(Some(ca.public_key())).expect("signature verifies under the CA key");
}

fn str_of(v: &Value, key: &str) -> String {
    v[key].as_str().unwrap_or_else(|| panic!("`{key}` missing in {v}")).to_string()
}

/// The user's report: an issuer whose certificate has expired cannot sign;
/// renewal brings it back with the same key, subject, id, name, default
/// pointer and usages, and keeps the old certificate.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn pki_renew_brings_back_an_expired_root_without_changing_what_it_is() {
    let server = boot("pki_issuer_renew_root", &["pki"]).await;
    ok(
        &server,
        "pki/root/generate/internal",
        json!({"common_name": "Renew Root", "key_type": "ec", "ttl": "3s", "issuer_name": "fgv-root"}),
    );
    server.write("pki/issuer/fgv-root", obj(json!({"usage": "issuing-certificates,crl-signing"})), None).unwrap();
    let role = json!({"ttl": "1h", "max_ttl": "24h", "key_type": "ec", "allow_any_name": true, "server_flag": true});
    server.write("pki/roles/web", obj(role), None).unwrap();
    let before = read(&server, "pki/issuer/fgv-root");
    let old_pem = str_of(&before, "certificate");

    thread::sleep(Duration::from_secs(4));
    let (status, body) = server.write("pki/issue/web", obj(json!({"common_name": "a.example.com"})), None).unwrap();
    assert_eq!(status, 400, "an expired issuer must refuse to issue: {body}");

    let renewed = ok(&server, "pki/issuer/fgv-root/renew", json!({"ttl": "8760h"}));
    let new_pem = str_of(&renewed, "certificate");
    let (old_subject, old_spki, old_serial, _, old_not_after, _) = facts(&old_pem);
    let (new_subject, new_spki, new_serial, new_not_before, new_not_after, new_issuer) = facts(&new_pem);
    assert_eq!(new_subject, old_subject, "same subject");
    assert_eq!(new_issuer, new_subject, "still self-signed");
    assert_eq!(new_spki, old_spki, "same key");
    assert_ne!(new_serial, old_serial, "new serial");
    assert!(new_not_after > old_not_after + 3600, "fresh validity");
    assert!((new_not_after - new_not_before - (8760 * 3600 + 30)).abs() <= 5, "ttl honoured");
    verifies_under(&new_pem, &new_pem);
    assert_eq!(str_of(&renewed, "serial_number"), new_serial);
    assert_eq!(str_of(&renewed, "previous_serial_number"), old_serial);
    assert_eq!(str_of(&renewed, "signed_by"), "self");
    assert_eq!(renewed["ttl_clamped"], json!(false));

    let after = read(&server, "pki/issuer/fgv-root");
    for field in ["issuer_id", "issuer_name", "key_id", "key_type", "common_name", "ca_kind", "usage", "is_default"] {
        assert_eq!(after[field], before[field], "`{field}` must survive renewal");
    }
    assert_eq!(after["certificate"], json!(new_pem));
    assert_eq!(after["not_after"], json!(new_not_after));
    assert_eq!(read(&server, "pki/config/issuers")["default_name"], json!("fgv-root"));

    // Issuance works again and chains to the renewed certificate.
    let leaf = ok(&server, "pki/issue/web", json!({"common_name": "a.example.com"}));
    verifies_under(&str_of(&leaf, "certificate"), &new_pem);
    assert_eq!(read(&server, "pki/issuer/fgv-root/chain")["ca_chain"], json!([new_pem]));

    // CRLs are still signed by the issuer and name it.
    ok(&server, "pki/revoke", json!({"serial_number": str_of(&leaf, "serial_number")}));
    let crl_pem = str_of(&read(&server, "pki/issuer/fgv-root/crl"), "crl");
    let crl_der = der(&crl_pem);
    let (_, crl) = x509_parser::parse_x509_crl(&crl_der).expect("CRL parses");
    let root_der = der(&new_pem);
    let (_, root) = x509_parser::parse_x509_certificate(&root_der).unwrap();
    crl.verify_signature(root.public_key()).expect("CRL verifies under the renewed root");
    assert_eq!(crl.tbs_cert_list.issuer.as_raw(), root.tbs_certificate.subject.as_raw());
    assert_eq!(crl.iter_revoked_certificates().count(), 1);

    // The replaced certificate is kept.
    let history = read(&server, "pki/issuer/fgv-root/history");
    let certs = history["certificates"].as_array().expect("certificates array");
    assert_eq!(certs.len(), 1, "{history}");
    assert_eq!(certs[0]["serial_number"], json!(old_serial));
    assert_eq!(certs[0]["certificate"], json!(old_pem));
    assert_eq!(certs[0]["replaced_by_serial_number"], json!(new_serial));

    // A second renewal keeps both, oldest first, and defaults to the span.
    let again = ok(&server, "pki/issuer/fgv-root/renew", json!({}));
    let (_, again_spki, _, nb, na, _) = facts(&str_of(&again, "certificate"));
    assert_eq!(again_spki, old_spki);
    assert!((na - nb - (new_not_after - new_not_before)).abs() <= 1, "empty ttl keeps the validity span");
    let history = read(&server, "pki/issuer/fgv-root/history");
    let serials: Vec<_> =
        history["certificates"].as_array().unwrap().iter().map(|c| c["serial_number"].clone()).collect();
    assert_eq!(serials, vec![json!(old_serial), json!(new_serial)]);
}

/// The field case: an RSA root imported with its key (`ca_kind = imported`).
/// Re-importing the original bundle afterwards must not register the old
/// certificate as a second issuer.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn pki_renew_an_imported_rsa_root_and_keep_reimport_idempotent() {
    let server = boot("pki_issuer_renew_imported", &["pki-src", "pki"]).await;
    let exported = ok(
        &server,
        "pki-src/root/generate/exported",
        json!({"common_name": "fgv-root-ca-v1", "key_type": "rsa", "key_bits": 2048, "ttl": "720h"}),
    );
    let bundle = format!("{}\n{}", str_of(&exported, "certificate"), str_of(&exported, "private_key"));
    ok(&server, "pki/config/ca", json!({"pem_bundle": bundle, "issuer_name": "fgv-root-ca-v1"}));
    let before = read(&server, "pki/issuer/fgv-root-ca-v1");
    assert_eq!(before["ca_kind"], json!("imported"));

    let renewed = ok(&server, "pki/issuer/fgv-root-ca-v1/renew", json!({"ttl": "87600h"}));
    let (old_subject, old_spki, ..) = facts(&str_of(&before, "certificate"));
    let (new_subject, new_spki, ..) = facts(&str_of(&renewed, "certificate"));
    assert_eq!((new_subject, new_spki), (old_subject, old_spki));
    verifies_under(&str_of(&renewed, "certificate"), &str_of(&renewed, "certificate"));
    let after = read(&server, "pki/issuer/fgv-root-ca-v1");
    assert_eq!(after["ca_kind"], json!("imported"));
    assert_eq!(after["key_id"], before["key_id"]);

    // Re-importing the original bundle finds the issuer by its old serial.
    ok(&server, "pki/config/ca", json!({"pem_bundle": bundle}));
    let (_, list) = server.list("pki/issuers", None).unwrap();
    assert_eq!(list["data"]["keys"].as_array().unwrap().len(), 1, "no duplicate issuer: {list}");
}

/// Trust anchors (no key) are refused, and nothing about them changes.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn pki_renew_refuses_a_keyless_trust_anchor() {
    let server = boot("pki_issuer_renew_keyless", &["pki-src", "pki"]).await;
    let root = ok(&server, "pki-src/root/generate/internal", json!({"common_name": "Upstream Root", "ttl": "720h"}));
    ok(&server, "pki/config/ca", json!({"pem_bundle": str_of(&root, "certificate")}));
    let (_, list) = server.list("pki/issuers", None).unwrap();
    let id = list["data"]["keys"][0].as_str().unwrap().to_string();
    let before = read(&server, &format!("pki/issuer/{id}"));

    let (status, body) = server.write(&format!("pki/issuer/{id}/renew"), obj(json!({"ttl": "8760h"})), None).unwrap();
    assert_eq!(status, 400, "{body}");
    assert!(body.to_string().contains("trust/chain-only"), "the refusal must say why: {body}");
    assert_eq!(read(&server, &format!("pki/issuer/{id}"))["certificate"], before["certificate"]);
    assert_eq!(read(&server, &format!("pki/issuer/{id}/history"))["certificates"], json!([]));
}

/// An intermediate whose parent is on the same mount is re-signed by that
/// parent, clamped to its lifetime; one whose parent is elsewhere is
/// refused with a 409 naming the parent.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn pki_renew_an_intermediate_through_its_parent_or_refuse() {
    let server = boot("pki_issuer_renew_intermediate", &["pki", "pki-int"]).await;
    let root = ok(
        &server,
        "pki/root/generate/internal",
        json!({"common_name": "Renew Root", "key_type": "ec", "ttl": "8760h", "issuer_name": "root"}),
    );
    let root_pem = str_of(&root, "certificate");

    // Same-mount intermediate.
    let csr = ok(&server, "pki/intermediate/generate/internal", json!({"common_name": "Renew Issuing CA"}));
    let signed = ok(
        &server,
        "pki/root/sign-intermediate",
        json!({"csr": str_of(&csr, "csr"), "issuer_ref": "root", "ttl": "720h"}),
    );
    ok(
        &server,
        "pki/intermediate/set-signed",
        json!({"certificate": str_of(&signed, "certificate"), "issuer_name": "int"}),
    );
    let before = read(&server, "pki/issuer/int");

    let renewed = ok(&server, "pki/issuer/int/renew", json!({"ttl": "17520h"}));
    let new_pem = str_of(&renewed, "certificate");
    assert_eq!(str_of(&renewed, "signed_by"), "root");
    assert_eq!(renewed["ttl_clamped"], json!(true), "two years under a one-year root: {renewed}");
    let (old_subject, old_spki, old_serial, ..) = facts(&str_of(&before, "certificate"));
    let (new_subject, new_spki, new_serial, _, new_not_after, new_issuer) = facts(&new_pem);
    let (root_subject, _, _, _, root_not_after, _) = facts(&root_pem);
    assert_eq!((new_subject, new_spki), (old_subject, old_spki));
    assert_ne!(new_serial, old_serial);
    assert_eq!(new_issuer, root_subject);
    assert!(new_not_after <= root_not_after, "never outlives its parent");
    verifies_under(&new_pem, &root_pem);
    assert_eq!(read(&server, "pki/issuer/int/chain")["ca_chain"], json!([new_pem, root_pem]));

    let role = json!({"ttl": "1h", "key_type": "ec", "allow_any_name": true, "server_flag": true});
    server.write("pki/roles/web", obj(role), None).unwrap();
    let leaf = ok(&server, "pki/issue/web", json!({"common_name": "b.example.com", "issuer_ref": "int"}));
    verifies_under(&str_of(&leaf, "certificate"), &new_pem);

    // Parent on another mount: explicit refusal.
    let csr = ok(&server, "pki-int/intermediate/generate/internal", json!({"common_name": "Remote Issuing CA"}));
    let signed = ok(&server, "pki/root/sign-intermediate", json!({"csr": str_of(&csr, "csr"), "issuer_ref": "root"}));
    ok(&server, "pki-int/intermediate/set-signed", json!({"certificate": str_of(&signed, "certificate")}));
    let (status, body) = server.write("pki-int/issuer/default/renew", obj(json!({})), None).unwrap();
    assert_eq!(status, 409, "{body}");
    assert!(body.to_string().contains("not an issuer on this mount"), "the refusal must name the cause: {body}");
}
