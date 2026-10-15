//! Role option `manage_private_key` over the real HTTP boundary (`/v2`).
//!
//! A role with the option keeps every leaf key `pki/issue/:role` generates
//! as an exportable managed key bound to the cert; a role without it keeps
//! the old "key only in the response" behaviour. See `issue_cert` in
//! `crates/bv-engine-pki/src/path_issue.rs`.

use serde_json::{json, Map, Value};

use crate::test_utils::TestHttpServer;

fn obj(v: Value) -> Option<Map<String, Value>> {
    v.as_object().cloned()
}

/// Vault with a PKI mount and an EC root, PKI calls switched to `/v2`.
async fn boot(name: &str) -> TestHttpServer {
    let mut server = TestHttpServer::new(name, false).await;
    server.token = server.root_token.clone();
    server.write("sys/mounts/pki/", obj(json!({"type": "pki"})), None).unwrap();
    server.url_prefix = server.url_prefix.replace("/v1", "/v2");
    let (status, root) = server
        .write(
            "pki/root/generate/internal",
            obj(json!({"common_name": "Managed Key Root", "key_type": "ec", "ttl": "8760h"})),
            None,
        )
        .unwrap();
    assert_eq!(status, 200, "root generate failed: {root}");
    server
}

fn write_role(server: &TestHttpServer, name: &str, extra: Value) -> (u16, Value) {
    let mut body = json!({"ttl": "24h", "key_type": "ec", "allow_any_name": true, "server_flag": true});
    for (k, v) in extra.as_object().expect("extra is an object") {
        body[k] = v.clone();
    }
    server.write(&format!("pki/roles/{name}"), obj(body), None).unwrap()
}

fn key_ids(server: &TestHttpServer) -> Vec<String> {
    let (status, got) = server.list("pki/keys", None).unwrap();
    assert_eq!(status, 200, "list keys failed: {got}");
    got["data"]["keys"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

fn cert_spki(cert_pem: &str) -> (Vec<u8>, Vec<u8>) {
    let der = pem::parse(cert_pem.as_bytes()).expect("cert PEM").into_contents();
    let (_, cert) = x509_parser::parse_x509_certificate(&der).expect("cert DER");
    let spki = cert.public_key();
    (spki.raw.to_vec(), spki.subject_public_key.data.to_vec())
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn pki_managed_role_keeps_binds_and_exports_the_issued_key() {
    let server = boot("pki_managed_role_keeps").await;
    let (status, got) = write_role(&server, "managed", json!({"manage_private_key": true}));
    assert!(status < 300, "managed role write failed: {got}");
    let (_, role) = server.read("pki/roles/managed", None).unwrap();
    assert_eq!(role["data"]["manage_private_key"], json!(true), "role read must carry the option: {role}");

    let keys_before = key_ids(&server);
    let (status, issued) = server
        .write("pki/issue/managed", obj(json!({"common_name": "managed.example.com", "ttl": "12h"})), None)
        .unwrap();
    assert_eq!(status, 200, "issue failed: {issued}");
    let data = &issued["data"];
    let serial = data["serial_number"].as_str().expect("serial").to_string();
    let key_id =
        data["key_id"].as_str().unwrap_or_else(|| panic!("managed issue must return key_id: {issued}")).to_string();
    let issued_key_pem = data["private_key"].as_str().expect("private_key stays in the response (compat)").to_string();
    let cert_pem = data["certificate"].as_str().expect("certificate").to_string();
    let (spki_der, spki_point) = cert_spki(&cert_pem);

    // Exactly one new managed key, the one returned.
    let keys_after = key_ids(&server);
    assert_eq!(keys_after.len(), keys_before.len() + 1, "one key per issuance");
    assert!(keys_after.contains(&key_id), "{key_id} must be listed: {keys_after:?}");

    // The key entry: named after role + serial, exportable, bound to the cert,
    // and its public half is the cert's SubjectPublicKeyInfo.
    let (status, key) = server.read(&format!("pki/key/{key_id}"), None).unwrap();
    assert_eq!(status, 200, "key read failed: {key}");
    let k = &key["data"];
    assert_eq!(k["name"].as_str(), Some(format!("managed-{serial}").as_str()), "{key}");
    assert_eq!(k["exportable"], json!(true), "{key}");
    assert_eq!(k["exported"], json!(true), "the key left the vault in the issue response: {key}");
    assert_eq!(k["source"], json!("generated"), "{key}");
    assert_eq!(k["cert_ref_count"], json!(1), "the issued serial must be in the key's refs: {key}");
    let stored_spki = pem::parse(k["public_key"].as_str().expect("public_key").as_bytes()).expect("SPKI PEM");
    assert_eq!(stored_spki.contents(), spki_der.as_slice(), "managed key must be the cert's key");

    // The cert record carries the binding.
    let (_, cert) = server.read(&format!("pki/cert/{serial}"), None).unwrap();
    assert_eq!(cert["data"]["key_id"].as_str(), Some(key_id.as_str()), "{cert}");

    // Export with the private key: it is the issued key and matches the cert.
    let (status, exported) = server
        .write(&format!("pki/cert/{serial}/export"), obj(json!({"format": "pem", "include_private_key": true})), None)
        .unwrap();
    assert_eq!(status, 200, "export with key failed: {exported}");
    assert_eq!(exported["data"]["includes_private_key"], json!(true), "{exported}");
    let blocks = pem::parse_many(exported["data"]["body"].as_str().expect("body").as_bytes()).expect("PEM bundle");
    let key_block = blocks.iter().find(|p| p.tag() == "PRIVATE KEY").expect("bundle must carry the private key");
    let issued_block = pem::parse(issued_key_pem.as_bytes()).expect("issued key PEM");
    assert_eq!(key_block.contents(), issued_block.contents(), "export must return the key issued with the cert");
    let kp = rcgen::KeyPair::try_from(key_block.contents()).expect("exported PKCS#8 parses");
    assert_eq!(kp.public_key_raw(), spki_point.as_slice(), "exported key must match the cert's public key");

    let (status, p12) = server
        .write(
            &format!("pki/cert/{serial}/export"),
            obj(json!({"format": "pkcs12", "include_private_key": true, "password": "correct horse battery"})),
            None,
        )
        .unwrap();
    assert_eq!(status, 200, "pkcs12 export with key failed: {p12}");
    assert_eq!(p12["data"]["includes_private_key"], json!(true), "{p12}");

    // Bound: delete refuses until the cert is revoked.
    let (status, del) = server.delete(&format!("pki/key/{key_id}"), None, None).unwrap();
    assert!(status >= 400, "delete must refuse while the cert is bound: {del}");
    assert!(del.to_string().contains("bound to"), "refusal must say why: {del}");
    let (status, rev) = server.write("pki/revoke", obj(json!({"serial_number": serial})), None).unwrap();
    assert_eq!(status, 200, "revoke failed: {rev}");
    let (status, del) = server.delete(&format!("pki/key/{key_id}"), None, None).unwrap();
    assert!(status < 300, "delete must succeed once the binding is gone: {del}");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn pki_unmanaged_role_still_stores_no_key() {
    let server = boot("pki_unmanaged_role").await;
    let (status, got) = write_role(&server, "plain", json!({}));
    assert!(status < 300, "role write failed: {got}");
    let (_, role) = server.read("pki/roles/plain", None).unwrap();
    assert_eq!(role["data"]["manage_private_key"], json!(false), "default is closed: {role}");

    let keys_before = key_ids(&server);
    let (status, issued) =
        server.write("pki/issue/plain", obj(json!({"common_name": "plain.example.com", "ttl": "12h"})), None).unwrap();
    assert_eq!(status, 200, "issue failed: {issued}");
    assert!(issued["data"].get("key_id").is_none(), "no managed key, no key_id: {issued}");
    assert!(issued["data"]["private_key"].as_str().is_some(), "{issued}");
    assert_eq!(key_ids(&server), keys_before, "an unmanaged role must not store the leaf key");

    let serial = issued["data"]["serial_number"].as_str().expect("serial").to_string();
    let (status, exported) = server
        .write(&format!("pki/cert/{serial}/export"), obj(json!({"format": "pem", "include_private_key": true})), None)
        .unwrap();
    assert!(status >= 400, "no bound key, nothing to export: {exported}");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn pki_role_refuses_manage_private_key_with_no_store() {
    let server = boot("pki_managed_no_store").await;
    let (status, got) = write_role(&server, "contradictory", json!({"manage_private_key": true, "no_store": true}));
    assert_eq!(status, 400, "manage_private_key + no_store must be a 400: {got}");
    assert!(got.to_string().contains("no_store"), "error must name no_store: {got}");

    // Either flag alone is fine. (A 404 has no JSON body for the helper to
    // parse, so the refused role's absence is checked through LIST.)
    let (status, got) = write_role(&server, "managed-only", json!({"manage_private_key": true}));
    assert!(status < 300, "manage_private_key alone must be accepted: {got}");
    let (status, got) = write_role(&server, "no-store-only", json!({"no_store": true}));
    assert!(status < 300, "no_store alone must be accepted: {got}");
    let (status, roles) = server.list("pki/roles", None).unwrap();
    assert_eq!(status, 200, "list roles failed: {roles}");
    let names: Vec<&str> = roles["data"]["keys"].as_array().expect("keys").iter().filter_map(|v| v.as_str()).collect();
    assert!(!names.contains(&"contradictory"), "the refused role must not be stored: {names:?}");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn pki_managed_role_leaves_pinned_and_csr_issuance_unchanged() {
    let server = boot("pki_managed_pinned_csr").await;
    let (status, got) = write_role(&server, "both", json!({"manage_private_key": true, "allow_key_reuse": true}));
    assert!(status < 300, "role write failed: {got}");
    let (status, key) =
        server.write("pki/keys/generate/internal", obj(json!({"key_type": "ec", "name": "pinned"})), None).unwrap();
    assert_eq!(status, 200, "key generate failed: {key}");
    let pinned_id = key["data"]["key_id"].as_str().expect("key_id").to_string();

    // A pinned key is already managed: no second key, the pin is the binding.
    let keys_before = key_ids(&server);
    let (status, issued) = server
        .write("pki/issue/both", obj(json!({"common_name": "pinned.example.com", "key_ref": "pinned"})), None)
        .unwrap();
    assert_eq!(status, 200, "pinned issue failed: {issued}");
    assert_eq!(issued["data"]["key_id"].as_str(), Some(pinned_id.as_str()), "{issued}");
    assert_eq!(key_ids(&server), keys_before, "pinning must not mint another key");

    // CSR-based signing never holds the key, so the option does not apply.
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
    let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["csr.example.com".to_string()]).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "csr.example.com");
    params.distinguished_name = dn;
    let csr_pem = params.serialize_request(&kp).unwrap().pem().unwrap();
    let (status, signed) = server.write("pki/sign/both", obj(json!({"csr": csr_pem})), None).unwrap();
    assert_eq!(status, 200, "sign failed: {signed}");
    assert!(signed["data"].get("key_id").is_none(), "sign/:role must not bind a key: {signed}");
    assert_eq!(key_ids(&server), keys_before, "sign/:role must not store a key");
}
