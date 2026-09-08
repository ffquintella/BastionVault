//! `pki/cert/<serial>/export` over the real HTTP boundary.
//!
//! These tests exist because the format knob used to be silently dropped
//! on the way in. `bv-server::logical_routes` only parses a request body
//! for POST/PUT and only lifts the `env`/`version` query keys into
//! `Request::data`, so a `GET .../export` reaches the engine with no
//! `format`, `include_private_key`, `mode` or `password` at all — and the
//! engine's own defaults hand back a plaintext PEM. The GUI asked for
//! PKCS#12 over GET and got a PEM bundle with no error anywhere.
//!
//! The fix is that both export routes accept `Write`, so a parameterised
//! export travels in a body the HTTP layer actually reads. `Read` stays
//! wired for the parameterless default (PEM, public material only) so
//! read-only export policies keep working.
//!
//! Driven through `TestHttpServer` on purpose: an in-process
//! `core.handle_request` test cannot see this class of bug, because the
//! embedded backend sets `Request::body` for reads and the HTTP one does
//! not. See `crates/bv-engine-pki/src/path_export.rs`.

use serde_json::{json, Map, Value};

use crate::test_utils::TestHttpServer;

fn obj(v: Value) -> Option<Map<String, Value>> {
    v.as_object().cloned()
}

/// Stand up a vault with a PKI mount, a root CA, a permissive role and
/// one issued leaf. Returns the server and the leaf's serial.
async fn boot_with_leaf(name: &str) -> (TestHttpServer, String) {
    let mut server = TestHttpServer::new(name, false).await;
    server.token = server.root_token.clone();

    server
        .write("sys/mounts/pki/", obj(json!({"type": "pki"})), None)
        .unwrap();
    server
        .write(
            "pki/root/generate/internal",
            obj(json!({
                "common_name": "Export Test Root",
                "key_type": "ec",
                "ttl": "8760h"
            })),
            None,
        )
        .unwrap();
    server
        .write(
            "pki/roles/web",
            obj(json!({
                "ttl": "24h",
                "key_type": "ec",
                "allow_any_name": true,
                "server_flag": true
            })),
            None,
        )
        .unwrap();
    let (status, issued) = server
        .write(
            "pki/issue/web",
            obj(json!({"common_name": "leaf.example.com", "ttl": "12h"})),
            None,
        )
        .unwrap();
    assert_eq!(status, 200, "issue failed: {issued}");
    let serial = issued["data"]["serial_number"]
        .as_str()
        .unwrap_or_else(|| panic!("issue response has no serial_number: {issued}"))
        .to_string();
    (server, serial)
}

#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn pki_export_pkcs12_needs_a_post_to_keep_its_format() {
    let (server, serial) = boot_with_leaf("pki_export_pkcs12_post").await;
    let path = format!("pki/cert/{serial}/export");

    // The bug: PKCS#12 asked for over GET. The body never reaches the
    // engine, so the export silently degrades to a plaintext PEM.
    let (status, got) = server.read(&path, None).unwrap();
    assert_eq!(status, 200, "GET export failed: {got}");
    assert_eq!(
        got["data"]["format"].as_str(),
        Some("pem"),
        "a parameterless GET is the PEM default: {got}"
    );

    // The fix: the same request as a POST keeps its format.
    let (status, got) = server
        .write(
            &path,
            obj(json!({"format": "pkcs12", "password": "correct horse battery"})),
            None,
        )
        .unwrap();
    assert_eq!(status, 200, "POST pkcs12 export failed: {got}");
    let data = &got["data"];
    assert_eq!(
        data["format"].as_str(),
        Some("pkcs12"),
        "POST must honour format=pkcs12: {got}"
    );
    assert_eq!(
        data["filename_extension"].as_str(),
        Some("p12"),
        "pkcs12 export must suggest a .p12 file: {got}"
    );
    assert_eq!(
        data["body_encoding"].as_str(),
        Some("base64"),
        "pkcs12 is raw DER and must ship base64: {got}"
    );

    // And the payload really is a PKCS#12 PFX, not a PEM in disguise:
    // DER SEQUENCE tag, and no PEM armour anywhere in the bytes.
    use base64::Engine as _;
    let der = base64::engine::general_purpose::STANDARD
        .decode(data["body"].as_str().expect("body is a string"))
        .expect("body decodes as base64");
    assert_eq!(der.first(), Some(&0x30), "PFX must start with a DER SEQUENCE");
    assert!(
        !String::from_utf8_lossy(&der).contains("BEGIN CERTIFICATE"),
        "pkcs12 body must not be a PEM bundle"
    );
}

#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn pki_export_pkcs12_without_a_password_is_refused() {
    let (server, serial) = boot_with_leaf("pki_export_pkcs12_nopass").await;
    let (status, got) = server
        .write(
            &format!("pki/cert/{serial}/export"),
            obj(json!({"format": "pkcs12"})),
            None,
        )
        .unwrap();
    assert_ne!(
        status, 200,
        "an unencrypted PKCS#12 must be refused, not silently downgraded: {got}"
    );
}

#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn pki_export_pkcs7_over_post_is_certs_only() {
    let (server, serial) = boot_with_leaf("pki_export_pkcs7_post").await;
    let (status, got) = server
        .write(
            &format!("pki/cert/{serial}/export"),
            obj(json!({"format": "pkcs7"})),
            None,
        )
        .unwrap();
    assert_eq!(status, 200, "POST pkcs7 export failed: {got}");
    assert_eq!(got["data"]["format"].as_str(), Some("pkcs7"), "{got}");
    assert_eq!(
        got["data"]["body_encoding"].as_str(),
        Some("utf8"),
        "PEM-armoured PKCS#7 ships as text: {got}"
    );
    assert_eq!(
        got["data"]["includes_private_key"].as_bool(),
        Some(false),
        "PKCS#7 has no key slot: {got}"
    );
}

#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn pki_export_issuer_pkcs12_over_post() {
    let (server, _serial) = boot_with_leaf("pki_export_issuer_pkcs12").await;
    let (status, issuers) = server.list("pki/issuers", None).unwrap();
    assert_eq!(status, 200, "list issuers failed: {issuers}");
    let issuer_ref = issuers["data"]["keys"][0]
        .as_str()
        .unwrap_or_else(|| panic!("no issuers listed: {issuers}"))
        .to_string();

    let (status, got) = server
        .write(
            &format!("pki/issuer/{issuer_ref}/export"),
            obj(json!({"format": "pkcs12", "password": "correct horse battery"})),
            None,
        )
        .unwrap();
    assert_eq!(status, 200, "POST issuer pkcs12 export failed: {got}");
    assert_eq!(got["data"]["format"].as_str(), Some("pkcs12"), "{got}");
    assert_eq!(
        got["data"]["includes_private_key"].as_bool(),
        Some(false),
        "the issuer route never emits a private key: {got}"
    );
}

#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn pki_export_pkcs12_carries_an_exportable_managed_key() {
    let mut server = TestHttpServer::new("pki_export_pkcs12_key", false).await;
    server.token = server.root_token.clone();

    server
        .write("sys/mounts/pki/", obj(json!({"type": "pki"})), None)
        .unwrap();
    server
        .write(
            "pki/root/generate/internal",
            obj(json!({
                "common_name": "Export Test Root",
                "key_type": "ec",
                "ttl": "8760h"
            })),
            None,
        )
        .unwrap();

    // A managed key minted `exportable=true` — the only kind the export
    // route will hand back outside `mode=backup`.
    let (status, key) = server
        .write(
            "pki/keys/generate/internal",
            obj(json!({
                "key_type": "ec",
                "name": "leaf-key",
                "exportable": true
            })),
            None,
        )
        .unwrap();
    assert_eq!(status, 200, "key generate failed: {key}");
    let key_id = key["data"]["key_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no key_id in {key}"))
        .to_string();

    server
        .write(
            "pki/roles/pinned",
            obj(json!({
                "ttl": "24h",
                "key_type": "ec",
                "allow_any_name": true,
                "server_flag": true,
                "allow_key_reuse": true
            })),
            None,
        )
        .unwrap();
    let (status, issued) = server
        .write(
            "pki/issue/pinned",
            obj(json!({
                "common_name": "pinned.example.com",
                "ttl": "12h",
                "key_ref": key_id
            })),
            None,
        )
        .unwrap();
    assert_eq!(status, 200, "issue with key_ref failed: {issued}");
    let serial = issued["data"]["serial_number"]
        .as_str()
        .unwrap_or_else(|| panic!("no serial_number in {issued}"))
        .to_string();

    let (status, got) = server
        .write(
            &format!("pki/cert/{serial}/export"),
            obj(json!({
                "format": "pkcs12",
                "include_private_key": true,
                "password": "correct horse battery"
            })),
            None,
        )
        .unwrap();
    assert_eq!(status, 200, "pkcs12 export with key failed: {got}");
    assert_eq!(got["data"]["format"].as_str(), Some("pkcs12"), "{got}");
    assert_eq!(
        got["data"]["includes_private_key"].as_bool(),
        Some(true),
        "{got}"
    );

    use base64::Engine as _;
    let der = base64::engine::general_purpose::STANDARD
        .decode(got["data"]["body"].as_str().expect("body is a string"))
        .expect("body decodes as base64");
    assert_eq!(der.first(), Some(&0x30), "PFX must start with a DER SEQUENCE");
    assert!(
        !String::from_utf8_lossy(&der).contains("BEGIN"),
        "pkcs12 body must not carry PEM armour"
    );
}

/// The policy contract the sample `pki-exporter` role documents: `read`
/// alone gets the default PEM, and a parameterised export needs `update`
/// because it is a POST. An operator whose export policy predates that
/// gets a clean 403, not a silent PEM.
#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn pki_export_post_requires_the_update_capability() {
    let (server, serial) = boot_with_leaf("pki_export_acl").await;
    let root = server.root_token.clone();

    for (name, caps) in [
        ("export-read", r#"["read"]"#),
        ("export-write", r#"["read", "update"]"#),
    ] {
        let policy = format!(
            r#"
path "pki/cert/+/export" {{
  capabilities = {caps}
}}
"#
        );
        let (status, got) = server
            .write(
                &format!("sys/policies/acl/{name}"),
                obj(json!({ "policy": policy })),
                Some(&root),
            )
            .unwrap();
        assert!(status < 300, "fixture: {name} must save, got {status}: {got}");
    }

    server
        .write("sys/auth/pass", obj(json!({"type": "userpass"})), Some(&root))
        .unwrap();
    for (user, policy) in [("reader", "export-read"), ("writer", "export-write")] {
        server
            .write(
                &format!("auth/pass/users/{user}"),
                obj(json!({
                    "password": "hunter22XX!",
                    "token_policies": policy,
                    "ttl": 0
                })),
                Some(&root),
            )
            .unwrap();
    }
    let login = |user: &str| -> String {
        server
            .write(
                &format!("auth/pass/login/{user}"),
                obj(json!({"password": "hunter22XX!"})),
                None,
            )
            .unwrap()
            .1
            .get("auth")
            .and_then(|a| a.get("client_token"))
            .and_then(|v| v.as_str())
            .expect("login returns a token")
            .to_string()
    };
    let reader = login("reader");
    let writer = login("writer");
    let path = format!("pki/cert/{serial}/export");
    let pkcs12 = || obj(json!({"format": "pkcs12", "password": "correct horse battery"}));

    // `read` still gets the parameterless PEM.
    let (status, got) = server.read(&path, Some(&reader)).unwrap();
    assert_eq!(status, 200, "read capability must still GET the PEM: {got}");
    assert_eq!(got["data"]["format"].as_str(), Some("pem"), "{got}");

    // …but not the POST.
    let (status, _) = server.write(&path, pkcs12(), Some(&reader)).unwrap();
    assert_eq!(
        status, 403,
        "a POST export without `update` must be refused, not downgraded"
    );

    // With `update` it goes through.
    let (status, got) = server.write(&path, pkcs12(), Some(&writer)).unwrap();
    assert_eq!(status, 200, "update capability must allow the POST: {got}");
    assert_eq!(got["data"]["format"].as_str(), Some("pkcs12"), "{got}");
}
