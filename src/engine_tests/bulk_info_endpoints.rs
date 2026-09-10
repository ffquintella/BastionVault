//! The `<list>-info` bulk-metadata endpoints, over the real HTTP boundary.
//!
//! Each of these replaces a "list the names, then read every one" client
//! loop — `1 + N` requests, or `1 + 2N` where a row needed two records — and
//! that shape is what trips the server's own per-IP abuse guard on a normal
//! page load. See `features/client-request-efficiency.md`.
//!
//! Driven through `TestHttpServer` rather than `core.handle_request` for two
//! reasons. The cursor and page size travel as *query parameters*, which
//! only reach an engine if `bv_logical`'s allowlist lifts them, and the
//! `-info` paths sit beside item patterns that would happily match a nested
//! `/info` — both are properties of the HTTP path, invisible to an
//! in-process test that sets `Request::data` directly.

use serde_json::{json, Map, Value};

use crate::test_utils::TestHttpServer;

fn obj(v: Value) -> Option<Map<String, Value>> {
    v.as_object().cloned()
}

/// Assert a setup write succeeded.
///
/// These routes answer a successful write with either `200` and a body or
/// `204` and nothing, depending on whether the handler has anything to
/// return. Both are success; anything else is a broken fixture, and saying
/// so here beats a later assertion failing on an empty listing.
fn assert_written(result: Result<(u16, Value), bv_errors::RvError>, what: &str) {
    let (status, body) = result.unwrap_or_else(|e| panic!("{what}: request failed: {e}"));
    assert!(
        status == 200 || status == 204,
        "{what}: write returned {status}: {body}"
    );
}

/// The response's data map.
///
/// Logical routes answer with a `{"data": {...}}` envelope; the `/v1/sys`
/// shims answer with the data map at the top level. `bv-client`'s
/// `JsonResponse::from_json` normalizes both (an object with no `data` key is
/// taken as the data map itself), so a client never sees the difference —
/// tests reading raw HTTP do.
fn data_of(body: &Value) -> &Value {
    match body.get("data") {
        Some(d) => d,
        None => body,
    }
}

/// Assert the page envelope every one of these endpoints returns.
fn assert_envelope(body: &Value, expect_total: u64, expect_len: usize) {
    let data = data_of(body);
    assert_eq!(data["total"].as_u64(), Some(expect_total), "total: {body}");
    assert_eq!(
        data["records"].as_array().map(|a| a.len()),
        Some(expect_len),
        "record count: {body}"
    );
    assert_eq!(
        data["keys"].as_array().map(|a| a.len()),
        Some(expect_len),
        "one key per record: {body}"
    );
}

// ── SSH roles ────────────────────────────────────────────────────────

#[actix_rt::test]
async fn ssh_roles_info_returns_configs_in_one_request() {
    let mut server = TestHttpServer::new("ssh_roles_info", false).await;
    server.token = server.root_token.clone();
    server.write("sys/mounts/ssh/", obj(json!({"type": "ssh"})), None).unwrap();
    server
        .write("ssh/config/ca", obj(json!({"generate_signing_key": true})), None)
        .unwrap();
    for name in ["alpha", "bravo", "charlie"] {
        assert_written(
            server.write(
                &format!("ssh/roles/{name}"),
                obj(json!({
                    "key_type": "ca",
                    "cert_type": "user",
                    "allowed_users": "*",
                    "ttl": "30m"
                })),
                None,
            ),
            &format!("role {name}"),
        );
    }

    let (status, body) = server.read("ssh/roles-info", None).unwrap();
    assert_eq!(status, 200, "roles-info failed: {body}");
    assert_envelope(&body, 3, 3);

    // The GUI filters the CA and OTP tabs by `key_type`, which is the whole
    // reason it was reading every role.
    for rec in body["data"]["records"].as_array().unwrap() {
        assert!(!rec["name"].as_str().unwrap().is_empty(), "row carries its name: {rec}");
        assert_eq!(rec["key_type"].as_str(), Some("ca"), "{rec}");
    }
}

#[actix_rt::test]
async fn ssh_roles_info_does_not_shadow_a_role_named_info() {
    // The reason these endpoints are `roles-info` and not `roles/info`: the
    // item pattern `roles/(?P<name>\w[\w-]*\w)` matches `roles/info`, so the
    // nested form would have made `info` an unaddressable role name.
    let mut server = TestHttpServer::new("ssh_roles_info_name", false).await;
    server.token = server.root_token.clone();
    server.write("sys/mounts/ssh/", obj(json!({"type": "ssh"})), None).unwrap();
    server
        .write("ssh/config/ca", obj(json!({"generate_signing_key": true})), None)
        .unwrap();
    server
        .write(
            "ssh/roles/info",
            obj(json!({"key_type": "ca", "cert_type": "user", "allowed_users": "*", "ttl": "30m"})),
            None,
        )
        .unwrap();

    // The role is still readable at its own path…
    let (status, body) = server.read("ssh/roles/info", None).unwrap();
    assert_eq!(status, 200, "a role named `info` stays addressable: {body}");
    assert_eq!(body["data"]["cert_type"].as_str(), Some("user"));

    // …and the bulk endpoint lists it rather than being shadowed by it.
    let (status, body) = server.read("ssh/roles-info", None).unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["data"]["records"][0]["name"].as_str(), Some("info"));
}

// ── Certificate lifecycle: targets + state in one row ────────────────

#[actix_rt::test]
async fn cert_lifecycle_targets_info_merges_target_and_state() {
    // The largest saving of any of these: the page needed a target read and
    // a state read per row, so `1 + 2N` requests became one.
    let mut server = TestHttpServer::new("cl_targets_info", false).await;
    server.token = server.root_token.clone();
    server
        .write("sys/mounts/cert-lifecycle/", obj(json!({"type": "cert-lifecycle"})), None)
        .unwrap();

    for name in ["web-a", "web-b"] {
        assert_written(
            server.write(
                &format!("cert-lifecycle/targets/{name}"),
                obj(json!({
                    "kind": "file",
                    "address": "/tmp",
                    "pki_mount": "pki",
                    "role_ref": "web",
                    "common_name": format!("{name}.example.com")
                })),
                None,
            ),
            &format!("target {name}"),
        );
    }

    let (status, body) = server.read("cert-lifecycle/targets-info", None).unwrap();
    assert_eq!(status, 200, "targets-info failed: {body}");
    assert_envelope(&body, 2, 2);

    for rec in body["data"]["records"].as_array().unwrap() {
        assert_eq!(rec["kind"].as_str(), Some("file"), "{rec}");
        assert!(rec["common_name"].as_str().unwrap().ends_with(".example.com"), "{rec}");
        // The state half is nested rather than flattened: both records carry
        // a `name`, and callers hand the state to code expecting
        // `state/<name>`'s shape.
        let state = &rec["state"];
        assert!(state.is_object(), "state is present even when never renewed: {rec}");
        assert_eq!(state["failure_count"].as_u64(), Some(0), "{state}");
        assert_eq!(state["current_serial"].as_str(), Some(""), "{state}");
    }
}

#[actix_rt::test]
async fn cert_lifecycle_targets_info_agrees_with_the_single_reads() {
    let mut server = TestHttpServer::new("cl_targets_info_parity", false).await;
    server.token = server.root_token.clone();
    server
        .write("sys/mounts/cert-lifecycle/", obj(json!({"type": "cert-lifecycle"})), None)
        .unwrap();
    server
        .write(
            "cert-lifecycle/targets/only",
            obj(json!({
                "kind": "file",
                "address": "/tmp",
                "pki_mount": "pki",
                "role_ref": "web",
                "common_name": "only.example.com",
                "renew_before": "72h"
            })),
            None,
        )
        .unwrap();

    let (_, target) = server.read("cert-lifecycle/targets/only", None).unwrap();
    let (_, state) = server.read("cert-lifecycle/state/only", None).unwrap();
    let (_, page) = server.read("cert-lifecycle/targets-info", None).unwrap();
    let row = &page["data"]["records"][0];

    for field in ["name", "kind", "address", "pki_mount", "role_ref", "common_name", "renew_before"]
    {
        assert_eq!(
            row[field], target["data"][field],
            "`{field}` diverges between targets-info and targets/<name>"
        );
    }
    for field in ["current_serial", "current_not_after", "last_error", "failure_count"] {
        assert_eq!(
            row["state"][field], state["data"][field],
            "`{field}` diverges between targets-info and state/<name>"
        );
    }
}

// ── UserPass users ───────────────────────────────────────────────────

#[actix_rt::test]
async fn userpass_users_info_carries_flags_and_key_counts_without_secrets() {
    // The admin page needed the disabled / locked / MFA flags *and* the
    // FIDO2 key count for every account: two reads per user. Both come off
    // the same stored record.
    let mut server = TestHttpServer::new("userpass_users_info", false).await;
    server.token = server.root_token.clone();
    server
        .write("sys/auth/userpass/", obj(json!({"type": "userpass"})), None)
        .unwrap();
    for name in ["alice", "bob"] {
        assert_written(
            server.write(
                &format!("auth/userpass/users/{name}"),
                obj(json!({"password": "correct-horse-battery-staple", "policies": "default"})),
                None,
            ),
            &format!("user {name}"),
        );
    }

    let (status, body) = server.read("auth/userpass/users-info", None).unwrap();
    assert_eq!(status, 200, "users-info failed: {body}");
    assert_envelope(&body, 2, 2);

    for rec in body["data"]["records"].as_array().unwrap() {
        // The two computed fields the client would otherwise derive, plus
        // the FIDO2 count that used to cost a second request per user.
        assert_eq!(rec["locked"].as_bool(), Some(false), "{rec}");
        assert_eq!(rec["registered_keys"].as_u64(), Some(0), "{rec}");

        // The projection is shared with the single read precisely so this
        // cannot regress: a bulk listing is the easiest place to leak
        // credential material by forgetting a redaction.
        assert!(rec.get("password_hash").is_none(), "password hash leaked: {rec}");
        assert!(rec.get("credentials_json").is_none(), "key material leaked: {rec}");
    }
}

#[actix_rt::test]
async fn userpass_users_info_matches_the_single_user_read() {
    let mut server = TestHttpServer::new("userpass_users_info_parity", false).await;
    server.token = server.root_token.clone();
    server
        .write("sys/auth/userpass/", obj(json!({"type": "userpass"})), None)
        .unwrap();
    assert_written(
        server.write(
            "auth/userpass/users/carol",
            // `ttl` is seconds, not a duration string — a string here is a
            // 400 the write helper reports rather than raises.
            obj(json!({
                "password": "correct-horse-battery-staple",
                "policies": "default",
                "ttl": 3600
            })),
            None,
        ),
        "user carol",
    );

    let (_, single) = server.read("auth/userpass/users/carol", None).unwrap();
    let (_, page) = server.read("auth/userpass/users-info", None).unwrap();
    assert_eq!(
        page["data"]["records"][0], single["data"],
        "the bulk projection must be the single read's, field for field"
    );
}

// ── Namespaces ───────────────────────────────────────────────────────

#[actix_rt::test]
async fn namespaces_info_returns_child_records_in_one_request() {
    let mut server = TestHttpServer::new("namespaces_info", false).await;
    server.token = server.root_token.clone();
    for name in ["tenant-a", "tenant-b"] {
        assert_written(
            server.write(
                &format!("sys/namespaces/{name}"),
                obj(json!({"max_mounts": 5})),
                None,
            ),
            &format!("namespace {name}"),
        );
    }

    let (status, body) = server.read("sys/namespaces-info", None).unwrap();
    assert_eq!(status, 200, "namespaces-info failed: {body}");
    assert_envelope(&body, 2, 2);

    for rec in data_of(&body)["records"].as_array().unwrap() {
        assert!(rec["path"].as_str().unwrap().starts_with("tenant-"), "{rec}");
        assert!(!rec["uuid"].as_str().unwrap_or("").is_empty(), "{rec}");
        assert_eq!(rec["quotas"]["max_mounts"].as_u64(), Some(5), "{rec}");
    }
}

#[actix_rt::test]
async fn namespaces_info_matches_the_per_path_read() {
    let mut server = TestHttpServer::new("namespaces_info_parity", false).await;
    server.token = server.root_token.clone();
    server
        .write("sys/namespaces/solo", obj(json!({"max_leases": 12})), None)
        .unwrap();

    let (_, single) = server.read("sys/namespaces/solo", None).unwrap();
    let (_, page) = server.read("sys/namespaces-info", None).unwrap();
    assert_eq!(
        data_of(&page)["records"][0],
        *data_of(&single),
        "the bulk projection must be the per-path read's, field for field"
    );
}

// ── PKI: pending CSRs and the sign-request queue ─────────────────────

#[actix_rt::test]
async fn pki_csr_info_omits_the_csr_bodies() {
    let mut server = TestHttpServer::new("pki_csr_info", false).await;
    server.token = server.root_token.clone();
    server.write("sys/mounts/pki/", obj(json!({"type": "pki"})), None).unwrap();
    server
        .write(
            "pki/root/generate/internal",
            obj(json!({"common_name": "CSR Info Root", "key_type": "ec", "ttl": "8760h"})),
            None,
        )
        .unwrap();
    server
        .write(
            "pki/roles/web",
            obj(json!({"ttl": "24h", "key_type": "ec", "allow_any_name": true})),
            None,
        )
        .unwrap();

    let mut ids = Vec::new();
    for i in 0..2 {
        let (status, body) = server
            .write(
                "pki/csr/generate",
                obj(json!({"role": "web", "common_name": format!("csr{i}.example.com")})),
                None,
            )
            .unwrap();
        assert_eq!(status, 200, "csr generate failed: {body}");
        ids.push(body["data"]["csr_id"].as_str().unwrap().to_string());
    }

    let (status, body) = server.read("pki/csr-info", None).unwrap();
    assert_eq!(status, 200, "csr-info failed: {body}");
    assert_envelope(&body, 2, 2);

    for rec in body["data"]["records"].as_array().unwrap() {
        assert!(ids.contains(&rec["csr_id"].as_str().unwrap().to_string()), "{rec}");
        assert_eq!(rec["role"].as_str(), Some("web"), "{rec}");
        assert!(rec["common_name"].as_str().unwrap().starts_with("csr"), "{rec}");
        // The PEM is only needed by the row's copy action, which reads the
        // single record on demand; one per row was most of the payload.
        assert!(rec.get("csr").is_none(), "summary must omit the CSR body: {rec}");
    }
}

#[actix_rt::test]
async fn pki_sign_request_info_reuses_the_single_reads_summary() {
    let mut server = TestHttpServer::new("pki_sr_info", false).await;
    server.token = server.root_token.clone();
    server.write("sys/mounts/pki/", obj(json!({"type": "pki"})), None).unwrap();
    server
        .write(
            "pki/root/generate/internal",
            obj(json!({"common_name": "SR Info Root", "key_type": "ec", "ttl": "8760h"})),
            None,
        )
        .unwrap();
    server
        .write(
            "pki/roles/web",
            obj(json!({"ttl": "24h", "key_type": "ec", "allow_any_name": true})),
            None,
        )
        .unwrap();
    // A CSR to import: generate one through the outgoing flow and reuse it.
    let (_, generated) = server
        .write(
            "pki/csr/generate",
            obj(json!({"role": "web", "common_name": "inbound.example.com"})),
            None,
        )
        .unwrap();
    let csr_pem = generated["data"]["csr"].as_str().unwrap().to_string();

    let (status, imported) = server
        .write(
            "pki/sign-request/import",
            obj(json!({"csr": csr_pem, "requester": "ops@example.com"})),
            None,
        )
        .unwrap();
    assert_eq!(status, 200, "import failed: {imported}");
    let id = imported["data"]["request_id"].as_str().unwrap().to_string();

    let (_, single) = server.read(&format!("pki/sign-request/{id}"), None).unwrap();
    let (status, page) = server.read("pki/sign-request-info", None).unwrap();
    assert_eq!(status, 200, "sign-request-info failed: {page}");
    assert_envelope(&page, 1, 1);

    let row = &page["data"]["records"][0];
    assert_eq!(row["status"].as_str(), Some("pending"), "{row}");
    // Same projection as the single read, minus the artefact bodies it adds.
    for (field, value) in single["data"].as_object().unwrap() {
        if field == "csr" || field == "certificate" {
            assert!(row.get(field).is_none(), "`{field}` must not be in the summary: {row}");
            continue;
        }
        assert_eq!(row[field], *value, "`{field}` diverges from the single read");
    }
}

// ── Shared pagination contract ───────────────────────────────────────

#[actix_rt::test]
async fn every_info_endpoint_shares_one_cursor_contract() {
    // The client's paging helper is written once, so the endpoints have to
    // agree: same envelope, same clamping, same refusal of a bad cursor.
    let mut server = TestHttpServer::new("info_cursor_contract", false).await;
    server.token = server.root_token.clone();
    server.write("sys/mounts/ssh/", obj(json!({"type": "ssh"})), None).unwrap();
    server
        .write("ssh/config/ca", obj(json!({"generate_signing_key": true})), None)
        .unwrap();
    server
        .write("sys/auth/userpass/", obj(json!({"type": "userpass"})), None)
        .unwrap();
    for i in 0..5 {
        server
            .write(
                &format!("ssh/roles/role-{i}"),
                obj(json!({"key_type": "ca", "cert_type": "user", "allowed_users": "*", "ttl": "30m"})),
                None,
            )
            .unwrap();
        server
            .write(
                &format!("auth/userpass/users/user-{i}"),
                obj(json!({"password": "correct-horse-battery-staple"})),
                None,
            )
            .unwrap();
    }

    for path in ["ssh/roles-info", "auth/userpass/users-info"] {
        // Walk in pages of 2 and check every key is seen exactly once.
        let mut seen: Vec<String> = Vec::new();
        let mut cursor = String::new();
        for _ in 0..10 {
            let url = match cursor.is_empty() {
                true => format!("{path}?limit=2"),
                false => format!("{path}?limit=2&after={cursor}"),
            };
            let (status, body) = server.read(&url, None).unwrap();
            assert_eq!(status, 200, "{path} page failed: {body}");
            assert_eq!(body["data"]["total"].as_u64(), Some(5), "{path}: {body}");
            for k in body["data"]["keys"].as_array().unwrap() {
                seen.push(k.as_str().unwrap().to_string());
            }
            cursor = body["data"]["next"].as_str().unwrap().to_string();
            if cursor.is_empty() {
                break;
            }
        }
        assert!(cursor.is_empty(), "{path}: paging failed to terminate");
        let mut sorted = seen.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(seen.len(), 5, "{path}: saw {} keys, expected 5", seen.len());
        assert_eq!(sorted.len(), 5, "{path}: a key was served twice");

        // An absurd page size is clamped, not honoured.
        let (status, body) = server.read(&format!("{path}?limit=999999"), None).unwrap();
        assert_eq!(status, 200, "{path}: {body}");
        assert_eq!(body["data"]["records"].as_array().unwrap().len(), 5, "{path}");

        // A cursor past the end is an empty, non-truncated final page —
        // not an error, and not a rewind to the beginning.
        let (status, body) = server.read(&format!("{path}?after=zzzzzzzz"), None).unwrap();
        assert_eq!(status, 200, "{path}: {body}");
        assert!(body["data"]["records"].as_array().unwrap().is_empty(), "{path}: {body}");
        assert_eq!(body["data"]["truncated"].as_bool(), Some(false), "{path}");
    }
}
