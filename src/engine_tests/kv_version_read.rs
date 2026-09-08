//! Versioned kv-v2 reads over the real HTTP boundary.
//!
//! `bv-server::logical_routes` parses a JSON request body only for POST/PUT.
//! For a GET it lifts *only* the allowlisted `env` and `version` query keys
//! into `Request::data` (`bv_logical::util::parse_query_allowlist`). So a
//! version selector sent as a GET *body* — which is what the GUI's
//! `read_secret_version` used to do — never reaches the KV engine at all, and
//! `handle_data_read` falls back to `meta.current_version`: the caller asks
//! for version 1 and silently gets version 3, with no error anywhere.
//!
//! The fix is that the GUI appends `?version=<n>` to the path, the same
//! `path?selector` convention the `?env=<name>` KV selector already uses
//! (`build_url_with` in `bv-client`, `split_path_query` on the embedded path).
//!
//! Driven through `TestHttpServer` on purpose: an in-process
//! `core.handle_request` test cannot see this class of bug, because the
//! embedded backend sets `Request::body` for reads and the HTTP one does not.
//! Same reasoning as `src/engine_tests/pki_export.rs`.

use serde_json::{json, Map, Value};

use crate::test_utils::TestHttpServer;

fn obj(v: Value) -> Option<Map<String, Value>> {
    v.as_object().cloned()
}

/// Stand up a vault with a kv-v2 mount at `secret/` holding three versions
/// of `secret/data/app`, whose payloads are distinguishable per version.
async fn boot_with_three_versions(name: &str) -> TestHttpServer {
    let mut server = TestHttpServer::new(name, false).await;
    server.token = server.root_token.clone();

    server
        .write("sys/mounts/secret/", obj(json!({"type": "kv-v2"})), None)
        .unwrap();

    for v in 1..=3 {
        let (status, got) = server
            .write(
                "secret/data/app",
                obj(json!({"data": {"which": format!("v{v}")}})),
                None,
            )
            .unwrap();
        assert_eq!(status, 200, "write v{v} failed: {got}");
    }

    server
}

/// The regression: a versioned read must return the version it asked for.
#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn kv_v2_versioned_read_honours_the_version_query_param() {
    let server = boot_with_three_versions("kv_v2_versioned_read_query").await;

    // A parameterless GET is the latest version — the baseline the buggy
    // body-on-GET read silently degraded to.
    let (status, got) = server.read("secret/data/app", None).unwrap();
    assert_eq!(status, 200, "plain read failed: {got}");
    assert_eq!(got["data"]["data"]["which"].as_str(), Some("v3"), "{got}");
    assert_eq!(got["data"]["metadata"]["version"].as_u64(), Some(3), "{got}");

    // Each historical version is reachable by query selector, and the
    // returned payload really is that version's — not the newest one.
    for v in 1..=3u64 {
        let (status, got) = server
            .read(&format!("secret/data/app?version={v}"), None)
            .unwrap();
        assert_eq!(status, 200, "versioned read v{v} failed: {got}");
        assert_eq!(
            got["data"]["metadata"]["version"].as_u64(),
            Some(v),
            "?version={v} must report version {v}: {got}"
        );
        assert_eq!(
            got["data"]["data"]["which"].as_str(),
            Some(format!("v{v}").as_str()),
            "?version={v} must return v{v}'s payload, not the latest: {got}"
        );
    }
}

/// The bug itself, pinned so it cannot come back: the *body* form of the
/// same request is dropped by the HTTP layer and yields the latest version.
/// Any future GUI code that sends `version` in a GET body is therefore
/// wrong, however plausible it reads.
#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn kv_v2_version_in_a_get_body_is_dropped_by_the_http_layer() {
    let server = boot_with_three_versions("kv_v2_version_get_body").await;

    let (status, got) = server
        .request("GET", "secret/data/app", obj(json!({"version": 1})), None, None)
        .unwrap();
    assert_eq!(status, 200, "GET-with-body read failed: {got}");
    assert_eq!(
        got["data"]["metadata"]["version"].as_u64(),
        Some(3),
        "a GET body is not parsed by logical_routes, so this must return the \
         latest version — if it ever returns 1, the body-on-GET path was added \
         back and `read_secret_version`'s query selector is no longer the only \
         thing keeping it correct: {got}"
    );
}

/// `?version=0` is the documented "latest" sentinel in the KV handler
/// (`get_version_from_request` returns 0 when absent), and a non-numeric
/// version is dropped by the allowlist rather than erroring — both resolve
/// to the current version instead of 404-ing.
#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn kv_v2_version_zero_and_garbage_resolve_to_latest() {
    let server = boot_with_three_versions("kv_v2_version_edge").await;

    for selector in ["version=0", "version=latest"] {
        let (status, got) = server
            .read(&format!("secret/data/app?{selector}"), None)
            .unwrap();
        assert_eq!(status, 200, "read with ?{selector} failed: {got}");
        assert_eq!(
            got["data"]["metadata"]["version"].as_u64(),
            Some(3),
            "?{selector} must resolve to the current version: {got}"
        );
    }
}

/// A version that does not exist must fail loudly rather than fall back to
/// the latest — the whole point of the fix is that a version selector is
/// never silently ignored.
#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn kv_v2_unknown_version_is_not_silently_the_latest() {
    let server = boot_with_three_versions("kv_v2_version_unknown").await;

    let (status, got) = server.read("secret/data/app?version=99", None).unwrap();
    assert_eq!(
        status, 404,
        "a nonexistent version must 404, not silently serve the latest: {got}"
    );
    assert!(
        got["data"]["metadata"]["version"].as_u64().is_none(),
        "a 404 must carry no version payload: {got}"
    );
}
