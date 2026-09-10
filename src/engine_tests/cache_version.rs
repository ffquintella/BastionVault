//! `sys/cache/version` — the cross-client cache-invalidation channel.
//!
//! A client can invalidate its own cache when it writes; it cannot know that
//! another operator, or the same operator's CLI, changed something behind its
//! back. This endpoint is that signal: every successful mutating request bumps
//! a per-mount epoch, and a client long-polls the epochs it cares about. See
//! `features/client-request-efficiency.md`.
//!
//! Driven through `TestHttpServer` because everything interesting here is a
//! property of the HTTP layer: the `topics` query parameter only arrives if the
//! sys shim lifts it, the `ETag` / `If-None-Match` pair only exists at that
//! level, and the epoch is bumped by `Core::handle_request`, which an
//! in-process `core.handle_request` test *would* exercise but without the
//! shim's authorization path.

use serde_json::{json, Map, Value};

use crate::test_utils::TestHttpServer;

fn obj(v: Value) -> Option<Map<String, Value>> {
    v.as_object().cloned()
}

/// The `/v1/sys` shims answer with the data map at the top level rather than
/// inside a `data` envelope; `bv-client` normalizes both.
fn data_of(body: &Value) -> &Value {
    match body.get("data") {
        Some(d) => d,
        None => body,
    }
}

fn epoch(body: &Value, topic: &str) -> Option<u64> {
    data_of(body)["topics"][topic].as_u64()
}

/// A vault with a PKI mount and one issued certificate, so there is something
/// to write to.
async fn boot(name: &str) -> TestHttpServer {
    let mut server = TestHttpServer::new(name, false).await;
    server.token = server.root_token.clone();
    server.write("sys/mounts/pki/", obj(json!({"type": "pki"})), None).unwrap();
    server
        .write(
            "pki/root/generate/internal",
            obj(json!({"common_name": "Epoch Test Root", "key_type": "ec", "ttl": "8760h"})),
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
    server
}

#[actix_rt::test]
async fn a_write_bumps_its_mount_and_a_read_does_not() {
    let server = boot("cache_version_bump").await;

    let (status, before) = server.read("sys/cache/version?topics=pki/", None).unwrap();
    assert_eq!(status, 200, "cache/version failed: {before}");
    let start = epoch(&before, "pki/").expect("pki/ reported");

    // A read must not move the counter — otherwise every client's poll would
    // invalidate every other client's cache.
    server.read("pki/certs-info", None).unwrap();
    let (_, after_read) = server.read("sys/cache/version?topics=pki/", None).unwrap();
    assert_eq!(epoch(&after_read, "pki/"), Some(start), "a read moved the epoch");

    let (status, issued) = server
        .write(
            "pki/issue/web",
            obj(json!({"common_name": "leaf.example.com", "ttl": "12h"})),
            None,
        )
        .unwrap();
    assert_eq!(status, 200, "issue failed: {issued}");

    let (_, after_write) = server.read("sys/cache/version?topics=pki/", None).unwrap();
    assert!(
        epoch(&after_write, "pki/").unwrap() > start,
        "a write must move its mount's epoch: {after_write}"
    );
}

#[actix_rt::test]
async fn a_write_to_one_mount_leaves_another_alone() {
    // The whole point of per-topic epochs: a PKI write must not make every
    // client drop its policy or SSH listings too.
    let server = boot("cache_version_isolation").await;
    server.write("sys/mounts/ssh/", obj(json!({"type": "ssh"})), None).unwrap();

    let (_, before) = server
        .read("sys/cache/version?topics=pki/,ssh/", None)
        .unwrap();
    let ssh_start = epoch(&before, "ssh/").expect("ssh/ reported");

    server
        .write(
            "pki/issue/web",
            obj(json!({"common_name": "leaf.example.com", "ttl": "12h"})),
            None,
        )
        .unwrap();

    let (_, after) = server
        .read("sys/cache/version?topics=pki/,ssh/", None)
        .unwrap();
    assert!(epoch(&after, "pki/").unwrap() > epoch(&before, "pki/").unwrap());
    assert_eq!(epoch(&after, "ssh/"), Some(ssh_start), "ssh/ moved on a pki write");
}

#[actix_rt::test]
async fn the_endpoint_reports_only_the_topics_it_was_given() {
    // No enumeration: a caller learns about mount names it supplied and
    // nothing else, so the channel cannot be used to discover mounts.
    let server = boot("cache_version_no_enumerate").await;
    server
        .write(
            "pki/issue/web",
            obj(json!({"common_name": "leaf.example.com", "ttl": "12h"})),
            None,
        )
        .unwrap();

    let (_, body) = server.read("sys/cache/version?topics=ssh/", None).unwrap();
    let topics = data_of(&body)["topics"].as_object().expect("topics map");
    assert_eq!(topics.len(), 1, "only the asked-for topic: {body}");
    assert!(topics.contains_key("ssh/"), "{body}");
    assert!(!topics.contains_key("pki/"), "an unrequested mount was disclosed: {body}");

    // With no topics named, there is nothing to report — but the aggregate
    // version is still there for a watcher to compare.
    let (status, body) = server.read("sys/cache/version", None).unwrap();
    assert_eq!(status, 200, "{body}");
    assert!(data_of(&body)["topics"].as_object().unwrap().is_empty(), "{body}");
    assert!(data_of(&body)["version"].as_u64().is_some(), "{body}");
}

#[actix_rt::test]
async fn a_topic_the_caller_cannot_read_is_omitted_not_zeroed() {
    // A counter is not secret material, but it is an activity signal: "the
    // payroll mount was written to 40 times this hour" is worth refusing to a
    // caller who cannot read that mount. Omission rather than a zero, because
    // a zero is a claim about the mount and an absent key is not.
    let server = boot("cache_version_authz").await;
    server
        .write("sys/mounts/secret-payroll/", obj(json!({"type": "kv"})), None)
        .unwrap();
    server
        .write("sys/auth/userpass/", obj(json!({"type": "userpass"})), None)
        .unwrap();
    // A policy granting read on `pki/` only.
    server
        .write(
            "sys/policy/pki-only",
            obj(json!({
                "policy": "path \"pki/*\" { capabilities = [\"read\", \"list\"] }\n\
                           path \"sys/cache/version\" { capabilities = [\"read\"] }\n"
            })),
            None,
        )
        .unwrap();
    server
        .write(
            "auth/userpass/users/limited",
            obj(json!({"password": "correct-horse-battery-staple", "policies": "pki-only"})),
            None,
        )
        .unwrap();
    let (status, login) = server
        .write(
            "auth/userpass/login/limited",
            obj(json!({"password": "correct-horse-battery-staple"})),
            None,
        )
        .unwrap();
    assert_eq!(status, 200, "login failed: {login}");
    let token = login["auth"]["client_token"].as_str().expect("token").to_string();

    let (status, body) = server
        .read(
            "sys/cache/version?topics=pki/,secret-payroll/",
            Some(&token),
        )
        .unwrap();
    assert_eq!(status, 200, "{body}");
    let topics = data_of(&body)["topics"].as_object().expect("topics map");
    assert!(topics.contains_key("pki/"), "a readable mount is reported: {body}");
    assert!(
        !topics.contains_key("secret-payroll/"),
        "an unreadable mount's activity was disclosed: {body}"
    );
}

#[actix_rt::test]
async fn the_etag_is_stable_until_something_changes() {
    let server = boot("cache_version_etag").await;

    let (status, first) = server
        .request("GET", "sys/cache/version?topics=pki/", None, None, None)
        .unwrap();
    assert_eq!(status, 200, "{first}");

    // A matching `If-None-Match` short-circuits to 304 — a client polling a
    // quiet vault costs a header exchange, not a body.
    let version = data_of(&first)["version"].as_u64().unwrap();
    let (status, _) = server
        .request_with_headers(
            "GET",
            "sys/cache/version?topics=pki/",
            None,
            None,
            None,
            &[("If-None-Match", &format!("\"{version}\""))],
        )
        .unwrap();
    assert_eq!(status, 304, "an unchanged registry must answer 304");

    // After a write the same conditional request returns a body again.
    server
        .write(
            "pki/issue/web",
            obj(json!({"common_name": "leaf.example.com", "ttl": "12h"})),
            None,
        )
        .unwrap();
    let (status, body) = server
        .request_with_headers(
            "GET",
            "sys/cache/version?topics=pki/",
            None,
            None,
            None,
            &[("If-None-Match", &format!("\"{version}\""))],
        )
        .unwrap();
    assert_eq!(status, 200, "a changed registry must answer with a body");
    assert!(data_of(&body)["version"].as_u64().unwrap() > version);
}

#[actix_rt::test]
async fn a_login_deliberately_does_not_bump_its_auth_mount() {
    // A login touches the stored user record (the failed-attempt counter), but
    // bumping on it would wake every watcher on every sign-in and turn a login
    // storm into a refetch storm. The cost is a `failed_login_count` that can
    // lag by one cache TTL in an admin listing; the alternative costs more.
    let mut server = TestHttpServer::new("cache_version_login", false).await;
    server.token = server.root_token.clone();
    server
        .write("sys/auth/userpass/", obj(json!({"type": "userpass"})), None)
        .unwrap();
    server
        .write(
            "auth/userpass/users/dana",
            obj(json!({"password": "correct-horse-battery-staple"})),
            None,
        )
        .unwrap();

    let (_, before) = server
        .read("sys/cache/version?topics=auth/userpass/", None)
        .unwrap();
    let start = epoch(&before, "auth/userpass/").expect("reported");

    server
        .write(
            "auth/userpass/login/dana",
            obj(json!({"password": "correct-horse-battery-staple"})),
            None,
        )
        .unwrap();

    let (_, after) = server
        .read("sys/cache/version?topics=auth/userpass/", None)
        .unwrap();
    assert_eq!(epoch(&after, "auth/userpass/"), Some(start), "a login bumped its mount");

    // A genuine user write still does.
    server
        .write(
            "auth/userpass/users/eve",
            obj(json!({"password": "correct-horse-battery-staple"})),
            None,
        )
        .unwrap();
    let (_, after_write) = server
        .read("sys/cache/version?topics=auth/userpass/", None)
        .unwrap();
    assert!(
        epoch(&after_write, "auth/userpass/").unwrap() > start,
        "a user write must bump its auth mount: {after_write}"
    );
}
