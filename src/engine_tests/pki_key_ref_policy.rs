//! `pki/issue/:role` with a `key_ref` the role refuses.
//!
//! A role-policy refusal used to surface as a bare HTTP 500 "PKI key
//! operation is invalid." — indistinguishable from an engine fault and
//! silent about which knob was missing. Each refusal must now be a 400
//! that names the cause. See `resolve_pinned_key` in
//! `crates/bv-engine-pki/src/path_issue.rs`.

use serde_json::{json, Map, Value};

use crate::test_utils::TestHttpServer;

fn obj(v: Value) -> Option<Map<String, Value>> {
    v.as_object().cloned()
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn pki_issue_key_ref_refusals_are_actionable_400s() {
    let mut server = TestHttpServer::new("pki_key_ref_policy", false).await;
    server.token = server.root_token.clone();

    server.write("sys/mounts/pki/", obj(json!({"type": "pki"})), None).unwrap();
    server
        .write(
            "pki/root/generate/internal",
            obj(json!({"common_name": "KeyRef Root", "key_type": "ec", "ttl": "8760h"})),
            None,
        )
        .unwrap();
    let (status, key) = server
        .write("pki/keys/generate/internal", obj(json!({"key_type": "ec", "name": "pinned-key"})), None)
        .unwrap();
    assert_eq!(status, 200, "key generate failed: {key}");

    let base_role = json!({"ttl": "24h", "key_type": "ec", "allow_any_name": true, "server_flag": true});
    let issue = json!({"common_name": "leaf.example.com", "key_ref": "pinned-key"});

    // Role without `allow_key_reuse`.
    server.write("pki/roles/no-reuse", obj(base_role.clone()), None).unwrap();
    let (status, body) = server.write("pki/issue/no-reuse", obj(issue.clone()), None).unwrap();
    assert_eq!(status, 400, "no-reuse role must refuse with 400: {body}");
    assert!(body.to_string().contains("allow_key_reuse"), "error must name allow_key_reuse: {body}");

    // Role with reuse on but an allow-list that excludes the key.
    let mut listed = base_role.clone();
    listed["allow_key_reuse"] = json!(true);
    listed["allowed_key_refs"] = json!("some-other-key");
    server.write("pki/roles/listed", obj(listed), None).unwrap();
    let (status, body) = server.write("pki/issue/listed", obj(issue.clone()), None).unwrap();
    assert_eq!(status, 400, "allow-list miss must refuse with 400: {body}");
    assert!(body.to_string().contains("allowed_key_refs"), "error must name allowed_key_refs: {body}");

    // Unknown key reference.
    let mut open = base_role.clone();
    open["allow_key_reuse"] = json!(true);
    server.write("pki/roles/open", obj(open), None).unwrap();
    let (status, body) =
        server.write("pki/issue/open", obj(json!({"common_name": "leaf.example.com", "key_ref": "nope"})), None).unwrap();
    assert_eq!(status, 400, "unknown key_ref must refuse with 400: {body}");
    assert!(body.to_string().contains("does not resolve"), "error must say the key is unknown: {body}");

    // Algorithm mismatch: RSA role, EC key.
    let mut rsa = base_role.clone();
    rsa["key_type"] = json!("rsa");
    rsa["key_bits"] = json!(2048);
    rsa["allow_key_reuse"] = json!(true);
    server.write("pki/roles/rsa", obj(rsa), None).unwrap();
    let (status, body) = server.write("pki/issue/rsa", obj(issue.clone()), None).unwrap();
    assert_eq!(status, 400, "algorithm mismatch must refuse with 400: {body}");
    assert!(body.to_string().contains("does not match the role"), "error must name the mismatch: {body}");

    // The happy path still issues.
    let (status, body) = server.write("pki/issue/open", obj(issue), None).unwrap();
    assert_eq!(status, 200, "allowed key_ref must issue: {body}");
}
