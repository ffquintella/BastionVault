//! `pki/tidy` releases the managed-key binding of every cert it sweeps.
//!
//! Tidy used to delete expired cert records without touching the bound
//! key's refs file, so the key stayed "bound" to serials that no longer
//! existed and `DELETE pki/key/<ref>` refused it unless `force=true`. See
//! `run_tidy_inner` in `crates/bv-engine-pki/src/path_tidy.rs`. Covers both
//! `key_ref`-pinned leaves and leaves of a `manage_private_key` role.

use std::{thread, time::Duration};

use serde_json::{json, Map, Value};

use crate::test_utils::TestHttpServer;

fn obj(v: Value) -> Option<Map<String, Value>> {
    v.as_object().cloned()
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn pki_tidy_releases_key_refs_so_key_delete_needs_no_force() {
    let mut server = TestHttpServer::new("pki_tidy_key_refs", false).await;
    server.token = server.root_token.clone();

    server.write("sys/mounts/pki/", obj(json!({"type": "pki"})), None).unwrap();
    server
        .write(
            "pki/root/generate/internal",
            obj(json!({"common_name": "Tidy Root", "key_type": "ec", "ttl": "8760h"})),
            None,
        )
        .unwrap();
    let (status, body) =
        server.write("pki/keys/generate/internal", obj(json!({"key_type": "ec", "name": "tidy-key"})), None).unwrap();
    assert_eq!(status, 200, "key generate failed: {body}");
    let (status, body) =
        server.write("pki/keys/generate/internal", obj(json!({"key_type": "ec", "name": "live-key"})), None).unwrap();
    assert_eq!(status, 200, "key generate failed: {body}");

    let role = json!({
        "ttl": "1s", "max_ttl": "24h", "key_type": "ec", "allow_any_name": true,
        "server_flag": true, "not_before_duration": 1, "allow_key_reuse": true
    });
    server.write("pki/roles/short", obj(role), None).unwrap();

    // Two expiring leaves on one key, one long-lived leaf on another.
    for cn in ["a.example.com", "b.example.com"] {
        let (status, body) = server
            .write("pki/issue/short", obj(json!({"common_name": cn, "ttl": "1s", "key_ref": "tidy-key"})), None)
            .unwrap();
        assert_eq!(status, 200, "issue {cn} failed: {body}");
    }
    let (status, body) = server
        .write(
            "pki/issue/short",
            obj(json!({"common_name": "live.example.com", "ttl": "1h", "key_ref": "live-key"})),
            None,
        )
        .unwrap();
    assert_eq!(status, 200, "issue live leaf failed: {body}");

    // Bound and unexpired: the key must still refuse a plain delete.
    let (status, body) = server.delete("pki/key/tidy-key", None, None).unwrap();
    assert_ne!(status, 204, "bound key must refuse delete before tidy: {body}");
    assert!(body.to_string().contains("bound to 2 certificate"), "refusal must name the bindings: {body}");

    thread::sleep(Duration::from_secs(3));

    let (status, body) =
        server.write("pki/tidy", obj(json!({"tidy_cert_store": true, "safety_buffer": "0s"})), None).unwrap();
    assert_eq!(status, 200, "tidy failed: {body}");
    assert_eq!(body["data"]["certs_deleted"].as_u64(), Some(2), "only the two expired leaves go: {body}");

    // Tidy released the swept serials but left the key itself in place.
    let (status, body) = server.read("pki/key/tidy-key", None).unwrap();
    assert_eq!(status, 200, "tidy must not delete the key itself: {body}");

    // ... so a plain delete now succeeds, with no force.
    let (status, body) = server.delete("pki/key/tidy-key", None, None).unwrap();
    assert!(status == 200 || status == 204, "delete without force must succeed after tidy: {status} {body}");
    // A read of a missing key is a bodyless 404 the test client cannot
    // parse; a second delete names the absence instead.
    let (_, body) = server.delete("pki/key/tidy-key", None, None).unwrap();
    assert!(body.to_string().contains("no managed key found"), "key must be gone after delete: {body}");

    // The unexpired leaf kept its binding: that key still refuses.
    let (status, body) = server.delete("pki/key/live-key", None, None).unwrap();
    assert!(body.to_string().contains("bound to 1 certificate"), "live binding must survive tidy: {status} {body}");
}

/// Same sweep for a `manage_private_key` role (T142), where every leaf the
/// role issues keeps its own bound managed key.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn pki_tidy_releases_manage_private_key_bindings() {
    let mut server = TestHttpServer::new("pki_tidy_managed_role_refs", false).await;
    server.token = server.root_token.clone();

    server.write("sys/mounts/pki/", obj(json!({"type": "pki"})), None).unwrap();
    server
        .write(
            "pki/root/generate/internal",
            obj(json!({"common_name": "Tidy Root", "key_type": "ec", "ttl": "8760h"})),
            None,
        )
        .unwrap();
    let role = json!({
        "ttl": "1s", "max_ttl": "24h", "key_type": "ec", "allow_any_name": true,
        "server_flag": true, "not_before_duration": 1, "manage_private_key": true
    });
    let (status, body) = server.write("pki/roles/managed", obj(role), None).unwrap();
    assert!(status < 300, "managed role write failed: {body}");

    let (status, issued) =
        server.write("pki/issue/managed", obj(json!({"common_name": "m.example.com", "ttl": "1s"})), None).unwrap();
    assert_eq!(status, 200, "issue failed: {issued}");
    let key_id = issued["data"]["key_id"].as_str().expect("managed issue returns key_id").to_string();

    let (_, key) = server.read(&format!("pki/key/{key_id}"), None).unwrap();
    assert_eq!(key["data"]["cert_ref_count"], json!(1), "issued leaf must be bound: {key}");

    thread::sleep(Duration::from_secs(3));

    let (status, body) =
        server.write("pki/tidy", obj(json!({"tidy_cert_store": true, "safety_buffer": "0s"})), None).unwrap();
    assert_eq!(status, 200, "tidy failed: {body}");
    assert_eq!(body["data"]["certs_deleted"].as_u64(), Some(1), "{body}");

    // The key survives tidy with no bindings left ...
    let (status, key) = server.read(&format!("pki/key/{key_id}"), None).unwrap();
    assert_eq!(status, 200, "tidy must not delete the managed key: {key}");
    assert_eq!(key["data"]["cert_ref_count"], json!(0), "tidy must release the binding: {key}");

    // ... and deletes without force.
    let (status, body) = server.delete(&format!("pki/key/{key_id}"), None, None).unwrap();
    assert!(status < 300, "delete without force must succeed after tidy: {status} {body}");
}
