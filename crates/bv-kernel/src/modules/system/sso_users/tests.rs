use serde_json::{json, Value};

use crate::modules::credential::login_audit_store::sso_users::{SsoLogin, SsoUserStore};
use crate::test_utils::TestHttpServer;

/// What a successful OIDC/SAML callback writes, without an IdP.
#[maybe_async::maybe_async]
async fn seed(server: &TestHttpServer, mount: &str, name: &str, email: Option<&str>) {
    let store = SsoUserStore::from_core(server.core.as_ref()).unwrap();
    let login = SsoLogin::new(mount, mount.trim_end_matches('/'), name, "default", "sub-1", email).unwrap();
    store.record_login(&login).await.unwrap();
}

/// Sys responses carry their payload either top-level or under `data`.
fn data(v: &Value) -> &Value {
    v.get("data").filter(|d| d.is_object()).unwrap_or(v)
}

fn body(v: Value) -> Option<serde_json::Map<String, Value>> {
    v.as_object().cloned()
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_sso_user_directory_routes() {
    let mut server = TestHttpServer::new("test_sso_user_directory_routes", true).await;
    let root = server.root_token.clone();
    server.token = root.clone();
    server.url_prefix = server.url_prefix.trim_end_matches("/v1").to_string();

    seed(&server, "oidc/", "felipe.quintella@fgv.br", Some("felipe.quintella@fgv.br")).await;
    seed(&server, "saml/", "bob", None).await;

    let (s, r) = server.read("v2/sys/sso/users", Some(&root)).unwrap();
    assert_eq!(s, 200, "{r:?}");
    let d = data(&r);
    assert_eq!(d["total"], json!(2), "{r:?}");
    assert_eq!(d["keys"], json!(["oidc/felipe.quintella@fgv.br", "saml/bob"]));
    assert_eq!(d["records"][0]["email_source"], json!("idp"));
    assert_eq!(d["records"][0]["login_count"], json!(1));
    assert!(d["records"][0].get("version").is_none(), "version stays internal: {r:?}");

    let (s, r) = server.list("v2/sys/sso/users", Some(&root)).unwrap();
    assert_eq!(s, 200, "{r:?}");
    assert_eq!(data(&r)["keys"], json!(["oidc/felipe.quintella@fgv.br", "saml/bob"]));

    let one = "v2/sys/sso/users/oidc/felipe.quintella@fgv.br";
    let (s, r) = server.read(one, Some(&root)).unwrap();
    assert_eq!(s, 200, "{r:?}");
    assert_eq!(data(&r)["username"], json!("felipe.quintella@fgv.br"));
    assert_eq!(data(&r)["mount"], json!("oidc/"));

    let (s, r) = server.write(one, body(json!({ "email": "felipe@corp.example" })), Some(&root)).unwrap();
    assert_eq!(s, 200, "{r:?}");
    assert_eq!(data(&r)["email"], json!("felipe@corp.example"));
    assert_eq!(data(&r)["email_source"], json!("admin"));

    let (s, r) = server.write(one, body(json!({ "email": "not-an-address" })), Some(&root)).unwrap();
    assert_eq!(s, 400, "{r:?}");
    let (s, r) = server.write("v2/sys/sso/users/oidc/nobody", body(json!({ "email": "" })), Some(&root)).unwrap();
    assert_eq!(s, 404, "only principals that have logged in can be edited: {r:?}");

    // A namespace-scoped request is refused: the directory spans every tenant.
    let (s, r) = server.write("v1/sys/namespaces/t1", body(json!({})), Some(&root)).unwrap();
    assert!((200..300).contains(&s), "ns create: {s} {r:?}");
    let (s, r) = server
        .request_with_headers("GET", "v2/sys/sso/users", None, Some(&root), None, &[("X-BastionVault-Namespace", "t1")])
        .unwrap();
    assert!((400..500).contains(&s), "namespace-scoped listing must be refused: {s} {r:?}");

    let (s, r) = server.delete(one, None, Some(&root)).unwrap();
    assert!((200..300).contains(&s), "delete: {s} {r:?}");
    let (s, _) = server.delete(one, None, Some(&root)).unwrap();
    assert_eq!(s, 404, "second delete");
    let (s, _) = server.read(one, Some(&root)).unwrap();
    assert_eq!(s, 404, "read after delete");
    let (_, r) = server.read("v2/sys/sso/users", Some(&root)).unwrap();
    assert_eq!(data(&r)["keys"], json!(["saml/bob"]));
}

/// The directory is policy-gated like `auth/<mount>/users-info`, and a
/// directory record is never a credential: a userpass login under the same
/// name must fail.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_sso_user_directory_gating_and_no_userpass_login() {
    let mut server = TestHttpServer::new("test_sso_user_directory_gating", true).await;
    let root = server.root_token.clone();
    server.token = root.clone();
    server.url_prefix = server.url_prefix.trim_end_matches("/v1").to_string();

    seed(&server, "oidc/", "ssobob", Some("ssobob@example.com")).await;

    let (s, r) = server.write("v1/sys/auth/userpass", body(json!({ "type": "userpass" })), Some(&root)).unwrap();
    assert!((200..300).contains(&s), "mount userpass: {s} {r:?}");
    let policy = r#"path "sys/sso/users" { capabilities = ["read", "list"] }"#;
    let (s, r) =
        server.write("v1/sys/policies/acl/sso-dir-reader", body(json!({ "policy": policy })), Some(&root)).unwrap();
    assert!((200..300).contains(&s), "policy: {s} {r:?}");
    for (user, policies) in [("reader", "sso-dir-reader"), ("plain", "default")] {
        let (s, r) = server
            .write(
                &format!("v1/auth/userpass/users/{user}"),
                body(json!({ "password": "hunter22XX!", "token_policies": policies })),
                Some(&root),
            )
            .unwrap();
        assert!((200..300).contains(&s), "user {user}: {s} {r:?}");
    }
    let login = |user: &str| -> String {
        let (s, r) = server
            .write(&format!("v1/auth/userpass/login/{user}"), body(json!({ "password": "hunter22XX!" })), None)
            .unwrap();
        assert_eq!(s, 200, "login {user}: {r:?}");
        r["auth"]["client_token"].as_str().unwrap().to_string()
    };
    let plain = login("plain");
    let reader = login("reader");

    let (s, r) = server.read("v2/sys/sso/users", Some(&plain)).unwrap();
    assert_eq!(s, 403, "no grant, no directory: {r:?}");
    let (s, r) = server.read("v2/sys/sso/users", Some(&reader)).unwrap();
    assert_eq!(s, 200, "{r:?}");
    assert_eq!(data(&r)["keys"], json!(["oidc/ssobob"]));
    let (s, r) =
        server.write("v2/sys/sso/users/oidc/ssobob", body(json!({ "email": "x@example.com" })), Some(&reader)).unwrap();
    assert_eq!(s, 403, "read grant does not cover edits: {r:?}");
    let (s, r) = server.delete("v2/sys/sso/users/oidc/ssobob", None, Some(&reader)).unwrap();
    assert_eq!(s, 403, "read grant does not cover removal: {r:?}");

    // Regression: the SSO record is passwordless and lives outside the
    // userpass mount, so no password authenticates `ssobob` there. (A
    // rejected userpass login may answer 200 with an `error` body; the
    // property is that no token is issued.)
    for password in ["hunter22XX!", "", "ssobob@example.com"] {
        let (_, r) =
            server.write("v1/auth/userpass/login/ssobob", body(json!({ "password": password })), None).unwrap();
        let token = r.get("auth").and_then(|a| a.get("client_token")).and_then(Value::as_str).unwrap_or("");
        assert!(token.is_empty(), "userpass login as an SSO principal must not issue a token: {r:?}");
    }
    let (_, r) = server.list("v1/auth/userpass/users", Some(&root)).unwrap();
    let keys = data(&r)["keys"].as_array().cloned().unwrap_or_default();
    assert!(!keys.contains(&json!("ssobob")), "the SSO record is not a userpass user: {r:?}");
}
