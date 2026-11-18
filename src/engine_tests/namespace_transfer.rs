//! `sys/namespace-transfer/{copy|move}` (T494): one resource or KV secret
//! copied or moved from namespace `src` to `dst` through the real router, with
//! real tokens, policies and namespace bindings. Every test asserts the status
//! and what was, or was not, written on each side.

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Value};

use super::kernel_policy_deny::{write, write_policy};
use crate::{
    audit::entry::AuditEntry,
    core::Core,
    errors::RvError,
    logical::{Connection, Operation, Request, Response},
    modules::namespace::{ns_assignment::NsAssignmentStore, NamespaceModule, NAMESPACE_MODULE_NAME},
    test_utils::new_unseal_test_bastion_vault,
};

/// Shares, asset-group membership and attached files (Task 4b).
mod relations;

/// A token born in a namespace running the transfer there (T513).
mod namespace_born;

const PASSWORD: &str = "hunter22XX!";

/// Full rights on resources and KV in `src` and `dst`, the transfer route and
/// owner reads: everything a copy or a move can need.
const MOVER: &str = r#"
path "sys/namespace-transfer/*" { capabilities = ["update"] }
path "identity/owner/*" { capabilities = ["read"] }
path "src/resources/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "dst/resources/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "src/secret/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "dst/secret/*" { capabilities = ["create", "read", "update", "delete", "list"] }
"#;

async fn send(
    core: &Arc<Core>,
    token: &str,
    op: Operation,
    path: &str,
    ns: Option<&str>,
    body: Value,
) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = op;
    req.client_token = token.to_string();
    req.body = body.as_object().cloned();
    if let Some(ns) = ns {
        req.headers = Some(HashMap::from([("x-bastionvault-namespace".to_string(), ns.to_string())]));
    }
    core.handle_request(&mut req).await
}

/// A vault with namespaces `src` and `dst` (each seeded with `resources/` and
/// `secret/`) and userpass at `auth/userpass/`.
async fn vault(name: &str) -> (crate::BastionVault, Arc<Core>, String) {
    let (bvault, core, root) = new_unseal_test_bastion_vault(name).await;
    write(&core, &root, "sys/namespaces/src", json!({})).await;
    write(&core, &root, "sys/namespaces/dst", json!({})).await;
    write(&core, &root, "sys/auth/userpass", json!({ "type": "userpass" })).await;
    (bvault, core, root)
}

/// A userpass user carrying `policies` plus `default`: `(token, entity_id)`.
/// `assigned` lets it operate in root, `src` and `dst` (a namespace
/// assignment); without it the token works at root only.
async fn user(core: &Arc<Core>, root: &str, name: &str, policies: &str, assigned: bool) -> (String, String) {
    let namespaces: &[&str] = if assigned { &["", "src", "dst"] } else { &[] };
    user_in(core, root, name, policies, namespaces).await
}

/// [`user`], assigned to exactly `namespaces` (none: root only).
async fn user_in(core: &Arc<Core>, root: &str, name: &str, policies: &str, namespaces: &[&str]) -> (String, String) {
    let body = json!({ "password": PASSWORD, "token_policies": format!("{policies},default"), "ttl": 0 });
    write(core, root, &format!("auth/userpass/users/{name}"), body).await;
    if !namespaces.is_empty() {
        let ns_store = core
            .module_manager()
            .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
            .and_then(|m| m.store())
            .expect("namespace store");
        let namespaces = namespaces.iter().map(|n| n.to_string()).collect();
        NsAssignmentStore::new(core.as_ref()).unwrap().set(&ns_store, "userpass/", name, namespaces).await.unwrap();
    }
    let mut req = Request::new(format!("auth/userpass/login/{name}"));
    req.operation = Operation::Write;
    req.body = json!({ "password": PASSWORD }).as_object().cloned();
    let auth = core.handle_request(&mut req).await.unwrap().unwrap().auth.unwrap();
    let entity = auth.metadata.get("entity_id").cloned().unwrap_or_default();
    assert!(!entity.is_empty(), "a userpass login carries an entity id");
    (auth.client_token, entity)
}

async fn transfer(core: &Arc<Core>, token: &str, op: &str, body: Value) -> Result<Option<Response>, RvError> {
    send(core, token, Operation::Write, &format!("sys/namespace-transfer/{op}"), None, body).await
}

fn status(r: &Result<Option<Response>, RvError>) -> u16 {
    match r {
        Ok(_) => 200,
        Err(RvError::ErrResponseStatus(s, _)) => *s,
        Err(e) => e.response_status(),
    }
}

fn message(r: &Result<Option<Response>, RvError>) -> String {
    match r {
        Ok(_) => String::new(),
        Err(RvError::ErrResponseStatus(_, m)) => m.clone(),
        Err(e) => e.to_string(),
    }
}

/// The response data of a transfer that must have succeeded.
fn result(r: Result<Option<Response>, RvError>) -> Value {
    match r {
        Ok(resp) => Value::Object(resp.and_then(|r| r.data).expect("a transfer answers with data")),
        Err(e) => panic!("expected success, got {e:?}"),
    }
}

fn codes(result: &Value) -> Vec<String> {
    result["warnings"].as_array().unwrap().iter().map(|w| w["code"].as_str().unwrap().to_string()).collect()
}

fn body(kind: &str, mount: &str, from: (&str, &str), to: (&str, &str), extra: Value) -> Value {
    let mut b = json!({
        "kind": kind,
        "source": { "namespace": from.0, "mount": mount, "path": from.1 },
        "destination": { "namespace": to.0, "mount": mount, "path": to.1 },
    });
    if let Value::Object(extra) = extra {
        b.as_object_mut().unwrap().extend(extra);
    }
    b
}

/// A resource transfer from `src` to `dst`.
fn resource(from: &str, to: &str, extra: Value) -> Value {
    body("resource", "resources", ("src", from), ("dst", to), extra)
}

/// A KV secret transfer from `src` to `dst`.
fn kv(from: &str, to: &str, extra: Value) -> Value {
    body("kv-secret", "secret", ("src", from), ("dst", to), extra)
}

/// Read `path` in `ns` as `token`: the data, or `None` when nothing is there.
async fn get(core: &Arc<Core>, token: &str, ns: Option<&str>, path: &str) -> Option<Value> {
    send(core, token, Operation::Read, path, ns, json!({})).await.unwrap().and_then(|r| r.data).map(Value::Object)
}

/// `srv1`-style resource: a record written twice (create, update) and two
/// secrets, `login` with versions 1 and 2 and `api` with version 1.
async fn seed_resource(core: &Arc<Core>, token: &str, ns: Option<&str>, name: &str) {
    for host in ["h1.example", "h2.example"] {
        let meta = json!({ "type": "server", "hostname": host });
        send(core, token, Operation::Write, &format!("resources/resources/{name}"), ns, meta).await.unwrap();
    }
    for (key, value) in [("login", "pw-1"), ("login", "pw-2"), ("api", "tok-1")] {
        let path = format!("resources/secrets/{name}/{key}");
        send(core, token, Operation::Write, &path, ns, json!({ "value": value })).await.unwrap();
    }
}

async fn resource_exists(core: &Arc<Core>, root: &str, ns: &str, name: &str) -> bool {
    get(core, root, Some(ns), &format!("resources/resources/{name}")).await.is_some()
}

async fn resource_owner(core: &Arc<Core>, root: &str, ns: &str, name: &str) -> String {
    let owner = get(core, root, Some(ns), &format!("identity/owner/resource/{name}")).await.unwrap();
    owner["entity_id"].as_str().unwrap().to_string()
}

/// History entries of a resource, oldest first.
async fn history(core: &Arc<Core>, root: &str, ns: &str, name: &str) -> Vec<Value> {
    let h = get(core, root, Some(ns), &format!("resources/resources/{name}/history")).await.unwrap();
    let mut entries = h["entries"].as_array().unwrap().clone();
    entries.reverse();
    entries
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn copy_resource_carries_secrets_versions_history() {
    let (_bvault, core, root) = vault("ns_transfer_copy_resource").await;
    seed_resource(&core, &root, Some("src"), "srv1").await;

    let out = result(transfer(&core, &root, "copy", resource("srv1", "srv1", json!({}))).await);
    assert_eq!(out["transferred"], json!({ "secrets": 2, "versions": 3, "history": 2, "shares": 0 }), "{out}");
    assert_eq!(out["dry_run"], json!(false));
    assert_eq!(out["destination"], json!({ "namespace": "dst", "mount": "resources", "path": "srv1" }));
    assert!(!out.to_string().contains("pw-"), "the response never carries a secret value: {out}");

    let record = get(&core, &root, Some("dst"), "resources/resources/srv1").await.expect("record copied");
    assert_eq!(record["hostname"], json!("h2.example"));
    for (n, value) in [(1, "pw-1"), (2, "pw-2")] {
        let v = get(&core, &root, Some("dst"), &format!("resources/secrets/srv1/login/version/{n}")).await.unwrap();
        assert_eq!(v["data"]["value"], json!(value), "login version {n}");
    }
    let current = get(&core, &root, Some("dst"), "resources/secrets/srv1/login").await.unwrap();
    assert_eq!(current["value"], json!("pw-2"));
    let api = get(&core, &root, Some("dst"), "resources/secrets/srv1/api").await.unwrap();
    assert_eq!(api["value"], json!("tok-1"));

    let origin = get(&core, &root, Some("src"), "resources/secrets/srv1/login/history").await.unwrap();
    let copied = get(&core, &root, Some("dst"), "resources/secrets/srv1/login/history").await.unwrap();
    assert_eq!(copied["versions"], origin["versions"], "version authors, times and operations are preserved");

    let src_hist = history(&core, &root, "src", "srv1").await;
    let dst_hist = history(&core, &root, "dst", "srv1").await;
    assert_eq!(dst_hist.len(), src_hist.len() + 1, "{dst_hist:?}");
    assert_eq!(dst_hist[..src_hist.len()], src_hist[..], "origin history arrives unchanged");
    let arrival = dst_hist.last().unwrap();
    assert_eq!(arrival["op"], json!("transfer-in"));
    assert!(arrival["changed_fields"].as_array().unwrap().contains(&json!("origin: src/resources/srv1")), "{arrival}");

    assert!(resource_exists(&core, &root, "src", "srv1").await, "a copy leaves the source");
    assert!(get(&core, &root, Some("src"), "resources/secrets/srv1/login").await.is_some());
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn copy_kv_secret_carries_all_versions_and_flags() {
    let (_bvault, core, root) = vault("ns_transfer_copy_kv").await;
    let src = Some("src");
    send(&core, &root, Operation::Write, "secret/data/team/db", src, json!({ "data": { "v": "one" } })).await.unwrap();
    let with_env = json!({ "data": { "v": "two", "host": "db" }, "envs": { "prod": { "host": "db.prod" } } });
    send(&core, &root, Operation::Write, "secret/data/team/db", src, with_env).await.unwrap();
    send(&core, &root, Operation::Write, "secret/data/team/db", src, json!({ "data": { "v": "three" } }))
        .await
        .unwrap();
    send(&core, &root, Operation::Write, "secret/destroy/team/db", src, json!({ "versions": [1] })).await.unwrap();

    let out = result(transfer(&core, &root, "copy", kv("team/db", "team/db", json!({}))).await);
    assert_eq!(out["transferred"], json!({ "secrets": 1, "versions": 3, "history": 0, "shares": 0 }), "{out}");
    assert_eq!(out["destination"]["path"], json!("team/db"));
    let warnings = out["warnings"].as_array().unwrap();
    let env = warnings.iter().find(|w| w["code"] == json!("kv-environment-overrides-normalized"));
    let env = env.unwrap_or_else(|| panic!("environments are flagged: {out}"));
    assert_eq!(env["subject"], json!("src/secret/team/db"));
    let text = env["message"].as_str().unwrap();
    assert!(text.contains("prod") && !text.contains("db.prod"), "names environments, never values: {text}");

    let from = get(&core, &root, src, "secret/metadata/team/db").await.unwrap();
    let to = get(&core, &root, Some("dst"), "secret/metadata/team/db").await.unwrap();
    assert_eq!(to["versions"], from["versions"], "numbers, times, authors and the destroyed flag are preserved");
    assert_eq!(to["current_version"], json!(3));
    assert_eq!(to["created_time"], from["created_time"]);
    assert_eq!(to["versions"]["1"]["destroyed"], json!(true));

    let read = |version: u64, env: Option<&str>| {
        let core = core.clone();
        let root = root.clone();
        let mut b = json!({ "version": version });
        if let Some(env) = env {
            b["env"] = json!(env);
        }
        async move { send(&core, &root, Operation::Read, "secret/data/team/db", Some("dst"), b).await }
    };
    let v2 = read(2, None).await.unwrap().unwrap().data.unwrap();
    assert_eq!(v2["data"], json!({ "v": "two", "host": "db" }));
    let v2_prod = read(2, Some("prod")).await.unwrap().unwrap().data.unwrap();
    assert_eq!(v2_prod["data"], json!({ "v": "two", "host": "db.prod" }), "environment overrides are carried");
    let v3_prod = read(3, Some("prod")).await.unwrap().unwrap().data.unwrap();
    assert_eq!(v3_prod["data"], json!({ "v": "three", "host": "db.prod" }), "the env carried forward to v3 too");
    assert!(matches!(read(1, None).await, Err(RvError::ErrModuleKvV2VersionDestroyed)));
    assert!(get(&core, &root, src, "secret/metadata/team/db").await.is_some(), "a copy leaves the source");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn move_deletes_source_only_after_verified_copy() {
    let (_bvault, core, root) = vault("ns_transfer_move").await;
    seed_resource(&core, &root, Some("src"), "srv1").await;
    send(&core, &root, Operation::Write, "secret/data/team/db", Some("src"), json!({ "data": { "v": "x" } }))
        .await
        .unwrap();

    let out = result(transfer(&core, &root, "move", resource("srv1", "srv1", json!({}))).await);
    assert_eq!(out["transferred"]["versions"], json!(3));
    assert!(resource_exists(&core, &root, "dst", "srv1").await, "the copy is in place");
    let login = get(&core, &root, Some("dst"), "resources/secrets/srv1/login").await.unwrap();
    assert_eq!(login["value"], json!("pw-2"));
    assert!(!resource_exists(&core, &root, "src", "srv1").await, "the source record is gone");
    assert!(get(&core, &root, Some("src"), "resources/secrets/srv1/login").await.is_none(), "and its secrets");

    result(transfer(&core, &root, "move", kv("team/db", "team/db", json!({}))).await);
    assert!(get(&core, &root, Some("dst"), "secret/metadata/team/db").await.is_some());
    assert!(get(&core, &root, Some("src"), "secret/metadata/team/db").await.is_none(), "the source secret is gone");
}

/// Regression: an ordinary delete leaves empty directories on the local file
/// backend, which list as `name/`; the import must not read them as leftover
/// data, or a resource could never be moved back to where it came from.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn move_back_to_a_vacated_name() {
    let (_bvault, core, root) = vault("ns_transfer_move_back").await;
    seed_resource(&core, &root, Some("src"), "srv1").await;

    result(transfer(&core, &root, "move", resource("srv1", "srv1", json!({}))).await);
    assert!(!resource_exists(&core, &root, "src", "srv1").await);
    let back = body("resource", "resources", ("dst", "srv1"), ("src", "srv1"), json!({}));
    let out = result(transfer(&core, &root, "move", back).await);
    assert_eq!(out["destination"], json!({ "namespace": "src", "mount": "resources", "path": "srv1" }));
    let login = get(&core, &root, Some("src"), "resources/secrets/srv1/login").await.unwrap();
    assert_eq!(login["value"], json!("pw-2"));
    assert!(!resource_exists(&core, &root, "dst", "srv1").await);
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn move_requires_delete_on_origin_and_probes_before_writing() {
    let (_bvault, core, root) = vault("ns_transfer_move_needs_delete").await;
    seed_resource(&core, &root, Some("src"), "srv1").await;
    let policy = r#"
        path "sys/namespace-transfer/*" { capabilities = ["update"] }
        path "src/resources/*" { capabilities = ["read", "list"] }
        path "dst/resources/*" { capabilities = ["create", "read", "update", "list"] }
    "#;
    write_policy(&core, &root, "no-delete", policy).await;
    let (token, _) = user(&core, &root, "copier", "no-delete", true).await;

    let r = transfer(&core, &token, "move", resource("srv1", "srv1", json!({}))).await;
    assert_eq!(status(&r), 403, "{r:?}");
    assert!(message(&r).contains("delete"), "names the missing right: {}", message(&r));
    assert!(!resource_exists(&core, &root, "dst", "srv1").await, "refused before anything was written");
    assert!(resource_exists(&core, &root, "src", "srv1").await, "the source is untouched");

    let r = transfer(&core, &token, "move", resource("srv1", "srv1", json!({ "dry_run": true }))).await;
    assert_eq!(status(&r), 403, "a dry run probes the same right: {r:?}");

    result(transfer(&core, &token, "copy", resource("srv1", "srv1", json!({}))).await);
    assert!(resource_exists(&core, &root, "dst", "srv1").await, "the same caller may copy");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn read_denied_on_one_secret_refuses_everything() {
    let (_bvault, core, root) = vault("ns_transfer_read_denied").await;
    seed_resource(&core, &root, Some("src"), "srv1").await;
    let policy = r#"
        path "sys/namespace-transfer/*" { capabilities = ["update"] }
        path "src/resources/*" { capabilities = ["read", "list"] }
        path "src/resources/secrets/srv1/api*" { capabilities = ["deny"] }
        path "dst/resources/*" { capabilities = ["create", "read", "update", "list"] }
    "#;
    write_policy(&core, &root, "partial-read", policy).await;
    let (token, _) = user(&core, &root, "reader", "partial-read", true).await;

    let r = transfer(&core, &token, "copy", resource("srv1", "srv1", json!({}))).await;
    assert_eq!(status(&r), 403, "{r:?}");
    assert!(!message(&r).contains("tok-1") && !message(&r).contains("pw-"), "{}", message(&r));
    assert!(!resource_exists(&core, &root, "dst", "srv1").await, "nothing is written");
    assert!(get(&core, &root, Some("dst"), "resources/secrets/srv1/login").await.is_none());
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn write_denied_on_destination_refuses() {
    let (_bvault, core, root) = vault("ns_transfer_write_denied").await;
    seed_resource(&core, &root, Some("src"), "srv1").await;
    let policy = r#"
        path "sys/namespace-transfer/*" { capabilities = ["update"] }
        path "src/resources/*" { capabilities = ["read", "list"] }
        path "dst/resources/*" { capabilities = ["read", "list"] }
    "#;
    write_policy(&core, &root, "read-only-dst", policy).await;
    let (token, _) = user(&core, &root, "viewer", "read-only-dst", true).await;

    for dry_run in [false, true] {
        let r = transfer(&core, &token, "copy", resource("srv1", "srv1", json!({ "dry_run": dry_run }))).await;
        assert_eq!(status(&r), 403, "dry_run {dry_run}: {r:?}");
    }
    assert!(!resource_exists(&core, &root, "dst", "srv1").await);
    assert!(get(&core, &root, Some("dst"), "resources/secrets/srv1/login").await.is_none());
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn collision_refuse_409() {
    let (_bvault, core, root) = vault("ns_transfer_collision").await;
    seed_resource(&core, &root, Some("src"), "srv1").await;
    let existing = json!({ "type": "server", "hostname": "existing.example" });
    send(&core, &root, Operation::Write, "resources/resources/srv1", Some("dst"), existing).await.unwrap();

    for extra in [json!({}), json!({ "on_conflict": "refuse" }), json!({ "dry_run": true })] {
        let r = transfer(&core, &root, "copy", resource("srv1", "srv1", extra.clone())).await;
        assert_eq!(status(&r), 409, "{extra}: {r:?}");
        assert!(message(&r).contains("srv1"), "names the path: {}", message(&r));
    }
    let record = get(&core, &root, Some("dst"), "resources/resources/srv1").await.unwrap();
    assert_eq!(record["hostname"], json!("existing.example"), "the destination is untouched");
    assert!(get(&core, &root, Some("dst"), "resources/secrets/srv1/login").await.is_none());
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn rename_probes_free_name_via_refuse_imports() {
    let (_bvault, core, root) = vault("ns_transfer_rename").await;
    seed_resource(&core, &root, Some("src"), "srv1").await;
    for name in ["srv1", "srv1-2"] {
        let existing = json!({ "type": "server", "hostname": format!("{name}.example") });
        send(&core, &root, Operation::Write, &format!("resources/resources/{name}"), Some("dst"), existing)
            .await
            .unwrap();
    }

    let dry = result(
        transfer(&core, &root, "copy", resource("srv1", "srv1", json!({ "on_conflict": "rename", "dry_run": true })))
            .await,
    );
    assert_eq!(dry["destination"]["path"], json!("srv1-3"), "{dry}");
    assert!(!resource_exists(&core, &root, "dst", "srv1-3").await, "a dry run writes nothing");

    let out =
        result(transfer(&core, &root, "copy", resource("srv1", "srv1", json!({ "on_conflict": "rename" }))).await);
    assert_eq!(out["destination"]["path"], json!("srv1-3"), "{out}");
    assert!(codes(&out).contains(&"renamed".to_string()), "{out}");
    let copied = get(&core, &root, Some("dst"), "resources/resources/srv1-3").await.unwrap();
    assert_eq!(copied["hostname"], json!("h2.example"));
    // The third attempt sent the same bundle as the first: secrets and history intact.
    let login = get(&core, &root, Some("dst"), "resources/secrets/srv1-3/login").await.unwrap();
    assert_eq!(login["value"], json!("pw-2"));
    let api = get(&core, &root, Some("dst"), "resources/secrets/srv1-3/api").await.unwrap();
    assert_eq!(api["value"], json!("tok-1"));
    let arrived = history(&core, &root, "dst", "srv1-3").await;
    assert_eq!(arrived.len(), history(&core, &root, "src", "srv1").await.len() + 1, "{arrived:?}");
    for name in ["srv1", "srv1-2"] {
        let kept = get(&core, &root, Some("dst"), &format!("resources/resources/{name}")).await.unwrap();
        assert_eq!(kept["hostname"], json!(format!("{name}.example")), "{name} untouched");
    }

    send(&core, &root, Operation::Write, "secret/data/team/db", Some("src"), json!({ "data": { "v": "src" } }))
        .await
        .unwrap();
    send(&core, &root, Operation::Write, "secret/data/team/db", Some("dst"), json!({ "data": { "v": "dst" } }))
        .await
        .unwrap();
    let out =
        result(transfer(&core, &root, "copy", kv("team/db", "team/db", json!({ "on_conflict": "rename" }))).await);
    assert_eq!(out["destination"]["path"], json!("team/db-2"), "{out}");
    let kept = get(&core, &root, Some("dst"), "secret/data/team/db").await.unwrap();
    assert_eq!(kept["data"]["v"], json!("dst"));
    let copied = get(&core, &root, Some("dst"), "secret/data/team/db-2").await.unwrap();
    assert_eq!(copied["data"]["v"], json!("src"));
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn overwrite_deletes_destination_then_imports_and_needs_delete() {
    let (_bvault, core, root) = vault("ns_transfer_overwrite").await;
    seed_resource(&core, &root, Some("src"), "srv1").await;
    let dst = Some("dst");
    let existing = json!({ "type": "server", "hostname": "existing.example" });
    send(&core, &root, Operation::Write, "resources/resources/srv1", dst, existing).await.unwrap();
    send(&core, &root, Operation::Write, "resources/secrets/srv1/old", dst, json!({ "value": "old-1" })).await.unwrap();
    let policy = r#"
        path "sys/namespace-transfer/*" { capabilities = ["update"] }
        path "src/resources/*" { capabilities = ["read", "list"] }
        path "dst/resources/*" { capabilities = ["create", "read", "update", "list"] }
    "#;
    write_policy(&core, &root, "no-dst-delete", policy).await;
    let (token, _) = user(&core, &root, "writer", "no-dst-delete", true).await;

    for dry_run in [true, false] {
        let r = transfer(
            &core,
            &token,
            "copy",
            resource("srv1", "srv1", json!({ "on_conflict": "overwrite", "dry_run": dry_run })),
        )
        .await;
        assert_eq!(status(&r), 403, "dry_run {dry_run}: {r:?}");
        assert!(message(&r).contains("delete"), "names the missing right: {}", message(&r));
    }
    let record = get(&core, &root, dst, "resources/resources/srv1").await.unwrap();
    assert_eq!(record["hostname"], json!("existing.example"), "untouched without delete");
    assert!(get(&core, &root, dst, "resources/secrets/srv1/old").await.is_some());

    let dry = result(
        transfer(
            &core,
            &root,
            "copy",
            resource("srv1", "srv1", json!({ "on_conflict": "overwrite", "dry_run": true })),
        )
        .await,
    );
    assert!(codes(&dry).contains(&"destination-replaced".to_string()), "{dry}");
    assert!(get(&core, &root, dst, "resources/secrets/srv1/old").await.is_some(), "a dry run deletes nothing");

    let out =
        result(transfer(&core, &root, "copy", resource("srv1", "srv1", json!({ "on_conflict": "overwrite" }))).await);
    assert!(codes(&out).contains(&"destination-replaced".to_string()), "{out}");
    let record = get(&core, &root, dst, "resources/resources/srv1").await.unwrap();
    assert_eq!(record["hostname"], json!("h2.example"));
    assert!(
        get(&core, &root, dst, "resources/secrets/srv1/old").await.is_none(),
        "the replaced item's secrets are gone"
    );
    let login = get(&core, &root, dst, "resources/secrets/srv1/login").await.unwrap();
    assert_eq!(login["value"], json!("pw-2"));
    let ops: Vec<Value> = history(&core, &root, "dst", "srv1").await.into_iter().map(|e| e["op"].clone()).collect();
    assert!(ops.contains(&json!("delete")), "the overwrite is an ordinary delete: {ops:?}");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn owner_is_caller_and_origin_owner_in_history() {
    let (_bvault, core, root) = vault("ns_transfer_owner").await;
    write_policy(&core, &root, "mover", MOVER).await;
    let (alice, alice_id) = user(&core, &root, "alice", "mover", true).await;
    let (bob, bob_id) = user(&core, &root, "bob", "mover", true).await;
    seed_resource(&core, &alice, Some("src"), "srv1").await;
    assert_eq!(resource_owner(&core, &root, "src", "srv1").await, alice_id);

    let out = result(transfer(&core, &bob, "copy", resource("srv1", "srv1", json!({}))).await);
    assert!(!codes(&out).contains(&"origin-owner-unreadable".to_string()), "{out}");
    assert_eq!(resource_owner(&core, &root, "dst", "srv1").await, bob_id, "the caller owns the copy");
    assert_eq!(resource_owner(&core, &root, "src", "srv1").await, alice_id, "the source keeps its owner");

    let arrival = history(&core, &root, "dst", "srv1").await.pop().unwrap();
    assert_eq!(arrival["op"], json!("transfer-in"));
    assert_eq!(arrival["user"], json!("bob"));
    let fields = arrival["changed_fields"].as_array().unwrap();
    assert!(fields.contains(&json!(format!("origin_owner: {alice_id}"))), "{arrival}");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn dry_run_writes_nothing_and_reports_counts() {
    let (_bvault, core, root) = vault("ns_transfer_dry_run").await;
    seed_resource(&core, &root, Some("src"), "srv1").await;

    let dry = result(transfer(&core, &root, "move", resource("srv1", "srv1", json!({ "dry_run": true }))).await);
    assert_eq!(dry["dry_run"], json!(true));
    assert_eq!(dry["transferred"], json!({ "secrets": 2, "versions": 3, "history": 2, "shares": 0 }), "{dry}");
    assert_eq!(dry["destination"]["path"], json!("srv1"));
    assert!(!resource_exists(&core, &root, "dst", "srv1").await, "nothing is written");
    assert!(get(&core, &root, Some("dst"), "resources/secrets/srv1/login").await.is_none());
    assert!(resource_exists(&core, &root, "src", "srv1").await, "a dry-run move deletes nothing");
    assert_eq!(history(&core, &root, "src", "srv1").await.len(), 2, "nor appends to the source history");

    let real = result(transfer(&core, &root, "copy", resource("srv1", "srv1", json!({}))).await);
    assert_eq!(real["transferred"], dry["transferred"], "the dry run predicts the counts");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn audit_entries_in_both_namespaces() {
    let (_bvault, core, root) = vault("ns_transfer_audit").await;
    seed_resource(&core, &root, Some("src"), "srv1").await;
    let log_path = {
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        std::env::temp_dir().join(format!("bv-namespace-transfer-{nanos}.log"))
    };
    let device = json!({ "type": "file", "options": { "file_path": log_path.display().to_string() } });
    write(&core, &root, "sys/audit/primary", device).await;

    result(transfer(&core, &root, "copy", resource("srv1", "srv1", json!({}))).await);

    let body = tokio::fs::read_to_string(&log_path).await.unwrap();
    let _ = tokio::fs::remove_file(&log_path).await;
    let entries: Vec<AuditEntry> = body.lines().map(|l| serde_json::from_str(l).expect("valid entry")).collect();
    let seen = |op: &str, prefix: &str| {
        entries.iter().any(|e| e.request.operation == op && e.request.path.starts_with(prefix))
    };
    assert!(seen("write", "sys/namespace-transfer/copy"), "the transfer itself is audited");
    assert!(seen("read", "src/resources/secrets/srv1/login/version/"), "the origin namespace sees each read");
    assert!(seen("write", "dst/resources/v2/transfer/import/srv1"), "the destination namespace sees the write");
    assert!(!body.contains("pw-1") && !body.contains("tok-1"), "no secret value in the clear");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn token_not_valid_in_destination_namespace_refuses() {
    let (_bvault, core, root) = vault("ns_transfer_binding").await;
    seed_resource(&core, &root, None, "srv0").await;
    let policy = r#"
        path "sys/namespace-transfer/*" { capabilities = ["update"] }
        path "resources/*" { capabilities = ["create", "read", "update", "delete", "list"] }
        path "dst/resources/*" { capabilities = ["create", "read", "update", "delete", "list"] }
    "#;
    write_policy(&core, &root, "root-bound", policy).await;
    let (token, _) = user(&core, &root, "rooted", "root-bound", false).await;
    get(&core, &token, None, "resources/resources/srv0").await.expect("the caller reads the source at root");

    // Answered as a namespace that does not exist (T503).
    let request = body("resource", "resources", ("", "srv0"), ("dst", "srv0"), json!({}));
    for op in ["copy", "move"] {
        let r = transfer(&core, &token, op, request.clone()).await;
        assert_eq!(status(&r), 400, "{op}: {r:?}");
        let unseen = "namespace 'dst' has no resource mount 'resources/' the caller can see";
        assert!(message(&r).contains(unseen), "{op}: {}", message(&r));
    }
    assert!(!resource_exists(&core, &root, "dst", "srv0").await, "nothing is written");
    assert!(get(&core, &root, None, "resources/resources/srv0").await.is_some(), "the source is untouched");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn soft_deleted_kv_versions_become_destroyed_with_warning() {
    let (_bvault, core, root) = vault("ns_transfer_soft_deleted").await;
    let src = Some("src");
    for v in ["one", "two", "three"] {
        send(&core, &root, Operation::Write, "secret/data/team/x", src, json!({ "data": { "v": v } })).await.unwrap();
    }
    send(&core, &root, Operation::Delete, "secret/data/team/x", src, json!({ "versions": [2] })).await.unwrap();
    let before = get(&core, &root, src, "secret/metadata/team/x").await.unwrap();
    let deleted_at = before["versions"]["2"]["deletion_time"].clone();
    assert_ne!(deleted_at, json!(""), "version 2 is soft-deleted at the source");

    let out = result(transfer(&core, &root, "copy", kv("team/x", "team/x", json!({}))).await);
    let warning =
        out["warnings"].as_array().unwrap().iter().find(|w| w["code"] == json!("deleted-version-not-recoverable"));
    let warning = warning.unwrap_or_else(|| panic!("a warning names the version: {out}"));
    assert!(warning["subject"].as_str().unwrap().contains('2'), "{warning}");
    assert!(!codes(&out).contains(&"kv-environment-overrides-normalized".to_string()), "no environments: {out}");

    let to = get(&core, &root, Some("dst"), "secret/metadata/team/x").await.unwrap();
    assert_eq!(to["versions"]["2"]["destroyed"], json!(true));
    assert_eq!(to["versions"]["2"]["deletion_time"], deleted_at, "the deletion time is kept");
    let r = send(&core, &root, Operation::Read, "secret/data/team/x", Some("dst"), json!({ "version": 2 })).await;
    assert!(matches!(r, Err(RvError::ErrModuleKvV2VersionDestroyed)), "{r:?}");
    let v3 = send(&core, &root, Operation::Read, "secret/data/team/x", Some("dst"), json!({ "version": 3 })).await;
    assert_eq!(v3.unwrap().unwrap().data.unwrap()["data"]["v"], json!("three"));

    let after = get(&core, &root, src, "secret/metadata/team/x").await.unwrap();
    assert_eq!(after["versions"], before["versions"], "the source is never undeleted");
    let text = warning["message"].as_str().unwrap();
    assert!(!text.contains("the move deletes"), "a copy keeps the source's recoverable version: {text}");
}

/// Regression (final review): on a move, the warning for a soft-deleted
/// version says the move deletes its only recoverable copy.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn moving_a_soft_deleted_kv_version_says_the_move_loses_it() {
    let (_bvault, core, root) = vault("ns_transfer_soft_deleted_move").await;
    let src = Some("src");
    for v in ["one", "two"] {
        send(&core, &root, Operation::Write, "secret/data/team/x", src, json!({ "data": { "v": v } })).await.unwrap();
    }
    send(&core, &root, Operation::Delete, "secret/data/team/x", src, json!({ "versions": [1] })).await.unwrap();

    let out = result(transfer(&core, &root, "move", kv("team/x", "team/x", json!({}))).await);
    let warnings = out["warnings"].as_array().unwrap();
    let warning = warnings.iter().find(|w| w["code"] == json!("deleted-version-not-recoverable"));
    let text = warning.unwrap_or_else(|| panic!("a warning names the version: {out}"))["message"].as_str().unwrap();
    assert!(text.contains("the move deletes the only recoverable copy of this version"), "{text}");
    assert!(get(&core, &root, src, "secret/metadata/team/x").await.is_none(), "the move deleted the source");
}

/// Regression (final review): a token bound to CIDRs is refused before any
/// step, with a message naming the binding, instead of the misleading 403 of
/// the first sub-request (which carries no client address).
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_cidr_bound_token_is_refused_up_front() {
    let (_bvault, core, root) = vault("ns_transfer_cidr_bound").await;
    seed_resource(&core, &root, Some("src"), "srv1").await;
    write_policy(&core, &root, "mover", MOVER).await;
    let body = json!({
        "password": PASSWORD, "token_policies": "mover,default", "ttl": 0, "token_bound_cidrs": ["10.0.0.0/24"]
    });
    write(&core, &root, "auth/userpass/users/bound", body).await;
    let ns_store = core
        .module_manager()
        .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
        .and_then(|m| m.store())
        .expect("namespace store");
    let namespaces = vec![String::new(), "src".to_string(), "dst".to_string()];
    NsAssignmentStore::new(core.as_ref()).unwrap().set(&ns_store, "userpass/", "bound", namespaces).await.unwrap();
    let mut login = Request::new("auth/userpass/login/bound");
    login.operation = Operation::Write;
    login.body = json!({ "password": PASSWORD }).as_object().cloned();
    let token = core.handle_request(&mut login).await.unwrap().unwrap().auth.unwrap().client_token;

    let mut req = Request::new("sys/namespace-transfer/copy");
    req.operation = Operation::Write;
    req.client_token = token;
    req.body = resource("srv1", "srv1", json!({})).as_object().cloned();
    req.connection = Some(Connection { peer_addr: "10.0.0.7:41222".to_string(), ..Default::default() });
    let r = core.handle_request(&mut req).await;
    assert_eq!(status(&r), 403, "{r:?}");
    assert!(message(&r).contains("tokens bound to CIDRs cannot run namespace transfers"), "{}", message(&r));
    assert!(!resource_exists(&core, &root, "dst", "srv1").await, "nothing is written");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn over_1000_secrets_refused_before_any_write() {
    let (_bvault, core, root) = vault("ns_transfer_secret_cap").await;
    let src = Some("src");
    let meta = json!({ "type": "server", "hostname": "big.example" });
    send(&core, &root, Operation::Write, "resources/resources/big", src, meta).await.unwrap();
    for i in 0..1001 {
        let path = format!("resources/secrets/big/k{i}");
        send(&core, &root, Operation::Write, &path, src, json!({ "value": "v" })).await.unwrap();
    }

    for extra in [json!({}), json!({ "dry_run": true })] {
        let r = transfer(&core, &root, "copy", resource("big", "big", extra.clone())).await;
        assert_eq!(status(&r), 400, "{extra}: {r:?}");
        assert!(message(&r).contains("1000"), "names the limit: {}", message(&r));
    }
    assert!(!resource_exists(&core, &root, "dst", "big").await, "nothing is written");
    assert!(get(&core, &root, Some("dst"), "resources/secrets/big/k0").await.is_none());
}

/// Full rights everywhere under `src` (including `src/sub`) and `dst`.
const EVERYWHERE: &str = r#"
path "sys/namespace-transfer/*" { capabilities = ["update"] }
path "identity/owner/*" { capabilities = ["read"] }
path "src/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "dst/*" { capabilities = ["create", "read", "update", "delete", "list"] }
"#;

/// What must survive a refused transfer of `srv1` / `team/db` in `ns`.
async fn source_state(core: &Arc<Core>, root: &str, ns: &str) -> Value {
    let ns = Some(ns);
    json!({
        "record": get(core, root, ns, "resources/resources/srv1").await,
        "versions": get(core, root, ns, "resources/secrets/srv1/login/history").await,
        "owner": get(core, root, ns, "identity/owner/resource/srv1").await,
        "kv": get(core, root, ns, "secret/metadata/team/db").await,
        "kv_value": get(core, root, ns, "secret/data/team/db").await.map(|d| d["data"].clone()),
    })
}

/// Regression (aliasing): a namespace written into the mount reaches the same
/// mount as the namespace field (`{ns: "src", mount: "secret"}` is
/// `{ns: "", mount: "src/secret"}`; `{ns: "src", mount: "sub/secret"}` is
/// `{ns: "src/sub", mount: "secret"}`). Every spelling of the source as its
/// own destination is a 400 before anything is read, for copy and move, with
/// and without overwrite, and the source keeps its record, versions and owner.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn aliased_locations_are_the_same_item_and_refused() {
    let (_bvault, core, root) = vault("ns_transfer_aliases").await;
    write(&core, &root, "sys/namespaces/src/sub", json!({})).await;
    write_policy(&core, &root, "everywhere", EVERYWHERE).await;
    let (alice, alice_id) = user(&core, &root, "alice", "everywhere", true).await;
    for ns in ["src", "src/sub"] {
        seed_resource(&core, &alice, Some(ns), "srv1").await;
        let kv = json!({ "data": { "v": "S3CRET" } });
        send(&core, &alice, Operation::Write, "secret/data/team/db", Some(ns), kv).await.unwrap();
        assert_eq!(resource_owner(&core, &root, ns, "srv1").await, alice_id);
    }
    let before = [source_state(&core, &root, "src").await, source_state(&core, &root, "src/sub").await];

    let spellings = [
        (("src", "{m}"), ("", "src/{m}")),
        (("src", "sub/{m}"), ("src/sub", "{m}")),
        (("", "src/sub/{m}"), ("src/sub", "{m}")),
    ];
    for (kind, mount, path) in [("resource", "resources", "srv1"), ("kv-secret", "secret", "team/db")] {
        for (a, b) in spellings {
            let a = (a.0, a.1.replace("{m}", mount));
            let b = (b.0, b.1.replace("{m}", mount));
            for (from, to) in [(&a, &b), (&b, &a)] {
                for (op, extra) in [
                    ("copy", json!({})),
                    ("copy", json!({ "on_conflict": "overwrite" })),
                    ("move", json!({})),
                    ("move", json!({ "on_conflict": "overwrite" })),
                    ("move", json!({ "on_conflict": "overwrite", "dry_run": true })),
                ] {
                    let mut req = json!({
                        "kind": kind,
                        "source": { "namespace": from.0, "mount": from.1, "path": path },
                        "destination": { "namespace": to.0, "mount": to.1, "path": path },
                    });
                    req.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
                    for token in [&root, &alice] {
                        let r = transfer(&core, token, op, req.clone()).await;
                        assert_eq!(status(&r), 400, "{op} {req}: {r:?}");
                        assert!(message(&r).contains("same item"), "{}", message(&r));
                    }
                }
            }
        }
    }
    let after = [source_state(&core, &root, "src").await, source_state(&core, &root, "src/sub").await];
    assert_eq!(after, before, "the source keeps its record, versions, owner and value");
    assert!(before[0]["record"].is_object() && before[0]["kv"].is_object(), "{}", before[0]);
}

/// A mount must be a mount of the kind's engine in its own namespace, and may
/// not carry a namespace prefix; a missing namespace is answered as a mount
/// the caller cannot see (400, T503). Nothing is read or written.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_mount_must_be_of_the_kind_and_not_carry_a_namespace() {
    let (_bvault, core, root) = vault("ns_transfer_mount_checks").await;
    seed_resource(&core, &root, Some("src"), "srv1").await;
    send(&core, &root, Operation::Write, "secret/data/team/db", Some("src"), json!({ "data": { "v": "x" } }))
        .await
        .unwrap();

    let cases = [
        (body("resource", "secret", ("src", "srv1"), ("dst", "srv1"), json!({})), 400, "kv-v2 mount"),
        (body("kv-secret", "resources", ("src", "team/db"), ("dst", "team/db"), json!({})), 400, "resource mount"),
        (body("resource", "nope", ("src", "srv1"), ("dst", "srv1"), json!({})), 400, "has no resource mount 'nope/'"),
        (
            json!({
                "kind": "kv-secret",
                "source": { "namespace": "", "mount": "src/secret", "path": "team/db" },
                "destination": { "namespace": "dst", "mount": "secret", "path": "team/db" },
            }),
            400,
            "starts with namespace 'src'",
        ),
        (
            json!({
                "kind": "resource",
                "source": { "namespace": "src", "mount": "resources", "path": "srv1" },
                "destination": { "namespace": "", "mount": "dst/resources", "path": "srv1" },
            }),
            400,
            "starts with namespace 'dst'",
        ),
        (
            body("resource", "resources", ("src", "srv1"), ("missing", "srv1"), json!({})),
            400,
            "namespace 'missing' has no resource mount 'resources/' the caller can see",
        ),
    ];
    for (req, code, needle) in cases {
        for op in ["copy", "move"] {
            let r = transfer(&core, &root, op, req.clone()).await;
            assert_eq!(status(&r), code, "{op} {req}: {r:?}");
            assert!(message(&r).contains(needle), "{needle}: {}", message(&r));
        }
    }
    assert!(!resource_exists(&core, &root, "dst", "srv1").await, "nothing is written");
    assert!(get(&core, &root, Some("dst"), "secret/metadata/team/db").await.is_none());
    assert!(resource_exists(&core, &root, "src", "srv1").await);
    assert!(get(&core, &root, Some("src"), "secret/metadata/team/db").await.is_some());
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn kv_overwrite_replaces_the_destination() {
    let (_bvault, core, root) = vault("ns_transfer_kv_overwrite").await;
    send(&core, &root, Operation::Write, "secret/data/team/db", Some("src"), json!({ "data": { "v": "src" } }))
        .await
        .unwrap();
    for v in ["dst-1", "dst-2"] {
        send(&core, &root, Operation::Write, "secret/data/team/db", Some("dst"), json!({ "data": { "v": v } }))
            .await
            .unwrap();
    }

    let out =
        result(transfer(&core, &root, "copy", kv("team/db", "team/db", json!({ "on_conflict": "overwrite" }))).await);
    assert!(codes(&out).contains(&"destination-replaced".to_string()), "{out}");
    let value = get(&core, &root, Some("dst"), "secret/data/team/db").await.unwrap();
    assert_eq!(value["data"]["v"], json!("src"));
    let meta = get(&core, &root, Some("dst"), "secret/metadata/team/db").await.unwrap();
    assert_eq!(meta["current_version"], json!(1), "the replaced secret's versions are gone: {meta}");
    assert_eq!(meta["versions"].as_object().unwrap().len(), 1);
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn kv_move_requires_delete_on_origin() {
    let (_bvault, core, root) = vault("ns_transfer_kv_move_needs_delete").await;
    send(&core, &root, Operation::Write, "secret/data/team/db", Some("src"), json!({ "data": { "v": "x" } }))
        .await
        .unwrap();
    let policy = r#"
        path "sys/namespace-transfer/*" { capabilities = ["update"] }
        path "src/secret/*" { capabilities = ["read", "list"] }
        path "dst/secret/*" { capabilities = ["create", "read", "update", "list"] }
    "#;
    write_policy(&core, &root, "kv-no-delete", policy).await;
    let (token, _) = user(&core, &root, "kv-copier", "kv-no-delete", true).await;

    let r = transfer(&core, &token, "move", kv("team/db", "team/db", json!({}))).await;
    assert_eq!(status(&r), 403, "{r:?}");
    assert!(message(&r).contains("delete") && message(&r).contains("secret/metadata/team/db"), "{}", message(&r));
    assert!(get(&core, &root, Some("dst"), "secret/metadata/team/db").await.is_none(), "nothing written");
    assert!(get(&core, &root, Some("src"), "secret/metadata/team/db").await.is_some(), "source untouched");
}

/// `rename` moves past a taken name (409) but stops at the first name the
/// ACL refuses, and writes nothing.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn rename_stops_on_a_403() {
    let (_bvault, core, root) = vault("ns_transfer_rename_403").await;
    seed_resource(&core, &root, Some("src"), "srv1").await;
    let existing = json!({ "type": "server", "hostname": "existing.example" });
    send(&core, &root, Operation::Write, "resources/resources/srv1", Some("dst"), existing).await.unwrap();
    let policy = r#"
        path "sys/namespace-transfer/*" { capabilities = ["update"] }
        path "src/resources/*" { capabilities = ["read", "list"] }
        path "dst/resources/*" { capabilities = ["create", "read", "update", "list"] }
        path "dst/resources/resources/srv1-2" { capabilities = ["deny"] }
    "#;
    write_policy(&core, &root, "no-srv1-2", policy).await;
    let (token, _) = user(&core, &root, "renamer", "no-srv1-2", true).await;

    let r = transfer(&core, &token, "copy", resource("srv1", "srv1", json!({ "on_conflict": "rename" }))).await;
    assert_eq!(status(&r), 403, "{r:?}");
    for name in ["srv1-2", "srv1-3"] {
        assert!(!resource_exists(&core, &root, "dst", name).await, "{name} is not written");
    }
    let kept = get(&core, &root, Some("dst"), "resources/resources/srv1").await.unwrap();
    assert_eq!(kept["hostname"], json!("existing.example"));
}

/// Regression: the brokered-credential gate's 409 is the destination refusing
/// the content, not a taken name. `rename` and `overwrite` surface it as is
/// and delete nothing for it; an overwrite of an existing item checks the gate
/// before its delete (T498), so the destination stays. Pins the gate code.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_gate_refusal_is_never_read_as_a_collision() {
    let (_bvault, core, root) = vault("ns_transfer_gate").await;
    let src = Some("src");
    let meta = json!({ "type": "server", "hostname": "h.example" });
    send(&core, &root, Operation::Write, "resources/resources/srv1", src, meta).await.unwrap();
    send(&core, &root, Operation::Write, "resources/secrets/srv1/login", src, json!({ "password": "pw-1" }))
        .await
        .unwrap();
    write(&core, &root, "ssh-broker/policy/type/server", json!({ "login_class": "brokered" })).await;

    for mode in ["refuse", "rename", "overwrite"] {
        let r = transfer(&core, &root, "copy", resource("srv1", "srv1", json!({ "on_conflict": mode }))).await;
        assert_eq!(status(&r), 409, "{mode}: {r:?}");
        let m = message(&r);
        assert!(m.contains("brokered_resource_no_static_credential"), "{mode}: the gate's own reason: {m}");
        assert!(!m.contains("no free name") && !m.contains("DELETE") && !m.contains("pw-1"), "{mode}: {m}");
    }
    for name in ["srv1", "srv1-2"] {
        assert!(!resource_exists(&core, &root, "dst", name).await, "{name}: nothing written");
    }

    let existing = json!({ "type": "server", "hostname": "existing.example" });
    send(&core, &root, Operation::Write, "resources/resources/srv1", Some("dst"), existing).await.unwrap();
    for dry_run in [false, true] {
        let extra = json!({ "on_conflict": "overwrite", "dry_run": dry_run });
        let r = transfer(&core, &root, "copy", resource("srv1", "srv1", extra)).await;
        let kept = get(&core, &root, Some("dst"), "resources/resources/srv1").await;
        assert_eq!(kept.map(|k| k["hostname"].clone()), Some(json!("existing.example")), "dry_run {dry_run}: {r:?}");
        assert_eq!(status(&r), 409, "dry_run {dry_run}: {r:?}");
        let m = message(&r);
        assert!(m.starts_with("brokered_resource_no_static_credential"), "the gate's own reason: {m}");
        assert!(m.contains("nothing was deleted") && !m.contains("DELETE of") && !m.contains("pw-1"), "{m}");
    }
    assert!(resource_exists(&core, &root, "src", "srv1").await, "the source is untouched");

    // The check refuses only what the import would: no static credential, no refusal.
    let meta = json!({ "type": "server", "hostname": "h2.example" });
    send(&core, &root, Operation::Write, "resources/resources/srv2", src, meta).await.unwrap();
    send(&core, &root, Operation::Write, "resources/secrets/srv2/api", src, json!({ "token": "tok-1" })).await.unwrap();
    let out =
        result(transfer(&core, &root, "copy", resource("srv2", "srv1", json!({ "on_conflict": "overwrite" }))).await);
    assert!(codes(&out).contains(&"destination-replaced".to_string()), "{out}");
    let replaced = get(&core, &root, Some("dst"), "resources/resources/srv1").await.unwrap();
    assert_eq!(replaced["hostname"], json!("h2.example"));
}

/// The agent-access type gate through the overwrite's pre-delete check
/// (T498, `check_only`): the source's type consents to agent sessions and its
/// profile opts in, the destination's type has not consented. The check
/// refuses with the gate's own code before the overwrite's delete, so the
/// destination is untouched; a refuse-mode copy meets the same gate. Once the
/// destination's type consents the overwrite goes through and the profile
/// arrives.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn an_agent_access_refusal_is_checked_before_an_overwrite_deletes() {
    const PIN: &str = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";
    let (_bvault, core, root) = vault("ns_transfer_agent_gate").await;
    let allow = json!({ "server": { "connect": { "agent_sessions_max": "allow" } } });
    send(&core, &root, Operation::Write, "resources/config/types", Some("src"), allow.clone()).await.unwrap();
    let profile = json!({
        "id": "p_agent", "name": "agent", "protocol": "ssh", "username": "ops", "agent_access": "allow",
        "credential_source": { "kind": "secret", "secret_id": "login" }, "host_key_pin": PIN,
    });
    let agent = json!({ "type": "server", "hostname": "agent.example", "connection_profiles": [profile] });
    send(&core, &root, Operation::Write, "resources/resources/srv1", Some("src"), agent).await.unwrap();
    // The destination's `srv1` is a plain record: the type there has not opted in.
    let plain = json!({ "type": "server", "hostname": "plain.example" });
    send(&core, &root, Operation::Write, "resources/resources/srv1", Some("dst"), plain).await.unwrap();
    let secret = json!({ "password": "pw-1" });
    send(&core, &root, Operation::Write, "resources/secrets/srv1/login", Some("dst"), secret).await.unwrap();

    for dry_run in [false, true] {
        let extra = json!({ "on_conflict": "overwrite", "dry_run": dry_run });
        let r = transfer(&core, &root, "copy", resource("srv1", "srv1", extra)).await;
        assert_eq!(status(&r), 403, "dry_run {dry_run}: {r:?}");
        let m = message(&r);
        assert!(m.starts_with("mcp_session_profile_not_agent_enabled"), "dry_run {dry_run}: the gate's own code: {m}");
        assert!(m.contains("nothing was deleted") && !m.contains("DELETE of") && !m.contains("pw-1"), "{m}");
        let kept = get(&core, &root, Some("dst"), "resources/resources/srv1").await.expect("the destination stays");
        assert_eq!(kept["hostname"], json!("plain.example"), "dry_run {dry_run}: untouched");
        let login = get(&core, &root, Some("dst"), "resources/secrets/srv1/login").await;
        assert_eq!(login.expect("its secret stays")["password"], json!("pw-1"), "dry_run {dry_run}");
    }
    assert!(resource_exists(&core, &root, "src", "srv1").await, "the source is untouched");

    // A name taken nowhere meets the same gate on a plain import: nothing written.
    let r = transfer(&core, &root, "copy", resource("srv1", "srv2", json!({}))).await;
    assert_eq!(status(&r), 403, "{r:?}");
    assert!(message(&r).starts_with("mcp_session_profile_not_agent_enabled"), "{}", message(&r));
    assert!(!resource_exists(&core, &root, "dst", "srv2").await, "nothing written");

    send(&core, &root, Operation::Write, "resources/config/types", Some("dst"), allow).await.unwrap();
    let extra = json!({ "on_conflict": "overwrite" });
    let out = result(transfer(&core, &root, "copy", resource("srv1", "srv1", extra)).await);
    assert!(codes(&out).contains(&"destination-replaced".to_string()), "{out}");
    let replaced = get(&core, &root, Some("dst"), "resources/resources/srv1").await.unwrap();
    assert_eq!(replaced["hostname"], json!("agent.example"), "the overwrite ran once the type consented");
    assert_eq!(replaced["connection_profiles"][0]["agent_access"], json!("allow"));
}

/// A root sign-in assigned to the namespaces copies a root resource into one
/// and moves a namespace's resource out to root: each arrival has its secret
/// versions, history and the caller as owner; the copy leaves its source and
/// the move removes it.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_root_caller_transfers_into_and_out_of_a_namespace() {
    let (_bvault, core, root) = vault("ns_transfer_root_in_out").await;
    seed_resource(&core, &root, None, "srv1").await;
    seed_resource(&core, &root, Some("src"), "srv2").await;
    let policy = format!(
        "{MOVER}\npath \"resources/*\" {{ capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"] }}\n"
    );
    write_policy(&core, &root, "root-and-ns", &policy).await;
    let (token, entity) = user(&core, &root, "mover", "root-and-ns", true).await;

    let into = body("resource", "resources", ("", "srv1"), ("dst", "srv1"), json!({}));
    let out = result(transfer(&core, &token, "copy", into).await);
    assert_eq!(out["transferred"], json!({ "secrets": 2, "versions": 3, "history": 2, "shares": 0 }), "{out}");
    let login = get(&core, &root, Some("dst"), "resources/secrets/srv1/login/version/1").await.unwrap();
    assert_eq!(login["data"]["value"], json!("pw-1"));
    let arrival = history(&core, &root, "dst", "srv1").await;
    assert_eq!(arrival.last().unwrap()["op"], json!("transfer-in"), "{arrival:?}");
    assert_eq!(resource_owner(&core, &root, "dst", "srv1").await, entity, "the caller owns the copy");
    assert!(get(&core, &root, None, "resources/resources/srv1").await.is_some(), "a copy leaves the root source");

    let out_of = body("resource", "resources", ("src", "srv2"), ("", "srv2"), json!({}));
    let out = result(transfer(&core, &token, "move", out_of).await);
    assert_eq!(out["destination"], json!({ "namespace": "", "mount": "resources", "path": "srv2" }), "{out}");
    let at_root = get(&core, &root, None, "resources/resources/srv2").await.expect("the record arrived at root");
    assert_eq!(at_root["hostname"], json!("h2.example"));
    let login = get(&core, &root, None, "resources/secrets/srv2/login").await.unwrap();
    assert_eq!(login["value"], json!("pw-2"));
    let owner = get(&core, &root, None, "identity/owner/resource/srv2").await.unwrap();
    assert_eq!(owner["entity_id"], json!(entity), "the caller owns the moved item");
    let arrival = get(&core, &root, None, "resources/resources/srv2/history").await.unwrap();
    assert_eq!(arrival["entries"][0]["op"], json!("transfer-in"), "{arrival}");
    assert!(!resource_exists(&core, &root, "src", "srv2").await, "a move removes the namespace source");
    assert!(get(&core, &root, Some("src"), "resources/secrets/srv2/login").await.is_none(), "and its secrets");
}

/// What `bvault transfer --namespace` sends: the same request with the
/// namespace header set. A caller assigned to the namespaces whose policy
/// grants the route runs the transfer in `src`, the header names the active
/// namespace for the rights check and the result is the usual one.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn the_route_runs_with_the_namespace_header_set() {
    let (_bvault, core, root) = vault("ns_transfer_header").await;
    seed_resource(&core, &root, Some("src"), "srv1").await;
    write_policy(&core, &root, "mover", MOVER).await;
    let (token, entity) = user(&core, &root, "mover", "mover", true).await;

    let b = resource("srv1", "srv1", json!({}));
    let r = send(&core, &token, Operation::Write, "sys/namespace-transfer/copy", Some("src"), b).await;
    let out = result(r);
    assert_eq!(out["transferred"]["versions"], json!(3), "{out}");
    assert_eq!(resource_owner(&core, &root, "dst", "srv1").await, entity, "the caller owns the copy");
    assert!(resource_exists(&core, &root, "src", "srv1").await, "a copy leaves the source");

    // The same grant held by a token that may not operate in `src` is refused
    // as a namespace it cannot see (T503's 400), with nothing written.
    let (outsider, _) = user(&core, &root, "outsider", "mover", false).await;
    let b = resource("srv1", "srv1-b", json!({}));
    let r = send(&core, &outsider, Operation::Write, "sys/namespace-transfer/copy", Some("src"), b).await;
    assert_eq!(status(&r), 400, "{r:?}");
    assert!(message(&r).contains("the caller can see"), "{}", message(&r));
    assert!(!resource_exists(&core, &root, "dst", "srv1-b").await, "nothing written");
}

/// Regression (aliasing, ruling J): a mount in namespace `a` named `a/secret/`
/// is listed as a mount, but the router reads `a/secret/...` as already
/// qualified and serves it from `a`'s `secret/`. So `{a, a/secret}` and
/// `{a, secret}` are one item with different scopes; a mount that starts with
/// its own namespace path is refused before anything is read.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_mount_named_after_its_own_namespace_is_refused() {
    let (_bvault, core, root) = vault("ns_transfer_self_prefixed_mount").await;
    write(&core, &root, "sys/namespaces/a", json!({})).await;
    send(&core, &root, Operation::Write, "sys/mounts/a/secret/", Some("a"), json!({ "type": "kv-v2" })).await.unwrap();
    let ns = Some("a");
    send(&core, &root, Operation::Write, "secret/data/team/db", ns, json!({ "data": { "v": "only-copy" } }))
        .await
        .unwrap();
    let aliased = get(&core, &root, ns, "a/secret/data/team/db").await.expect("the alias reaches the secret");
    assert_eq!(aliased["data"]["v"], json!("only-copy"), "precondition: both spellings are one item");

    let snapshot = || async {
        json!({
            "meta": get(&core, &root, ns, "secret/metadata/team/db").await,
            "value": get(&core, &root, ns, "secret/data/team/db").await.map(|d| d["data"].clone()),
        })
    };
    let before = snapshot().await;
    let normal = ("a", "secret");
    let alias = ("a", "a/secret");
    for (from, to) in [(alias, normal), (normal, alias)] {
        for (op, extra) in [("copy", json!({})), ("move", json!({ "on_conflict": "overwrite" }))] {
            let mut req = body("kv-secret", "", (from.0, "team/db"), (to.0, "team/db"), extra);
            req["source"]["mount"] = json!(from.1);
            req["destination"]["mount"] = json!(to.1);
            let r = transfer(&core, &root, op, req.clone()).await;
            assert_eq!(status(&r), 400, "{op} {req}: {r:?}");
            assert!(message(&r).contains("must not start with its own namespace path"), "{}", message(&r));
        }
    }
    assert_eq!(snapshot().await, before, "the source is intact");
}

/// Regression (T503): a caller allowed on the route whose token may not
/// operate in a namespace gets one answer whether it exists or not, as source
/// or destination, whether or not its policy names the namespace's paths. A
/// caller who may use the namespace (root) still learns about a bad mount.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_namespace_without_rights_answers_alike_whether_it_exists() {
    let (_bvault, core, root) = vault("ns_transfer_namespace_existence").await;
    seed_resource(&core, &root, None, "srv0").await;
    let names_tenant = r#"
        path "sys/namespace-transfer/*" { capabilities = ["update"] }
        path "resources/*" { capabilities = ["create", "read", "update", "delete", "list"] }
        path "tenant-x/resources/*" { capabilities = ["create", "read", "update", "delete", "list"] }
    "#;
    write_policy(&core, &root, "names-tenant", names_tenant).await;
    // No assignment: the token works at root only, though its policy names
    // tenant-x's paths.
    let (bound_away, _) = user_in(&core, &root, "away", "names-tenant", &[]).await;
    let ask = |token: String, to_ns: bool, ns: &'static str| {
        let core = core.clone();
        async move {
            let request = match to_ns {
                true => body("resource", "resources", ("", "srv0"), (ns, "srv0"), json!({})),
                false => body("resource", "resources", (ns, "srv1"), ("", "srv9"), json!({})),
            };
            let r = transfer(&core, &token, "copy", request).await;
            (status(&r), message(&r))
        }
    };

    let mut missing = Vec::new();
    for to_ns in [true, false] {
        missing.push(ask(bound_away.clone(), to_ns, "tenant-x").await);
    }
    write(&core, &root, "sys/namespaces/tenant-x", json!({})).await;
    seed_resource(&core, &root, Some("tenant-x"), "srv0").await;
    seed_resource(&core, &root, Some("tenant-x"), "srv1").await;
    for (to_ns, missing) in [true, false].into_iter().zip(missing) {
        let existing = ask(bound_away.clone(), to_ns, "tenant-x").await;
        assert_eq!(existing, missing, "may not operate there, as destination {to_ns}: existing vs missing");
        assert_eq!(existing.0, 400, "{existing:?}");
        assert!(existing.1.contains("namespace 'tenant-x' has no resource mount 'resources/'"), "{existing:?}");
    }

    // No grant there at all, and no right to operate there; tenant-y never
    // exists. (A token that may operate in a namespace may learn it exists.)
    let root_only = r#"
        path "sys/namespace-transfer/*" { capabilities = ["update"] }
        path "resources/*" { capabilities = ["create", "read", "update", "delete", "list"] }
    "#;
    write_policy(&core, &root, "root-only", root_only).await;
    let (no_grant, _) = user_in(&core, &root, "nogrant", "root-only", &[]).await;
    for to_ns in [true, false] {
        let existing = ask(no_grant.clone(), to_ns, "tenant-x").await;
        let missing = ask(no_grant.clone(), to_ns, "tenant-y").await;
        assert_eq!(existing.0, missing.0, "no grant, as destination {to_ns}: {existing:?} vs {missing:?}");
        assert_eq!(existing.1.replace("tenant-x", "N"), missing.1.replace("tenant-y", "N"), "destination {to_ns}");
    }

    // Root may use tenant-x: it is told the mount runs another engine.
    let mut wrong_engine = body("resource", "resources", ("", "srv0"), ("tenant-x", "srv0"), json!({}));
    wrong_engine["destination"]["mount"] = json!("secret");
    let r = transfer(&core, &root, "copy", wrong_engine).await;
    assert_eq!(status(&r), 400, "{r:?}");
    assert!(message(&r).contains("is a kv-v2 mount, not the resource mount"), "{}", message(&r));
    assert!(get(&core, &root, None, "resources/resources/srv9").await.is_none(), "nothing is written");
    let kept = get(&core, &root, Some("tenant-x"), "resources/resources/srv0").await.unwrap();
    assert_eq!(kept["hostname"], json!("h2.example"), "tenant-x's item is untouched");
}

/// While the KV key switch is pending (T511), a move whose source key moves
/// at the switch could not delete its source, so it is refused before the
/// import, dry run included, and nothing is written; a copy of the same
/// secret works, and once the switch is done the move does too.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_move_whose_source_key_moves_is_refused_before_it_writes_while_the_switch_is_pending() {
    use crate::modules::identity::kv_key_split_migrate;

    let (_bvault, core, root) = vault("ns_transfer_pending_key_switch").await;
    write(&core, &root, "secret/data/data/x", json!({ "data": { "v": "kv-1" } })).await;
    kv_key_split_migrate::reset_for_test(core.as_ref()).await.unwrap();
    let moving = |to: &str, extra: Value| body("kv-secret", "secret", ("", "data/x"), ("dst", to), extra);

    let dry = transfer(&core, &root, "move", moving("x", json!({ "dry_run": true }))).await;
    assert_eq!(status(&dry), 503, "the dry run reports the refusal: {dry:?}");
    let r = transfer(&core, &root, "move", moving("x", json!({}))).await;
    assert_eq!(status(&r), 503, "{r:?}");
    assert!(message(&r).contains("nothing was written"), "{}", message(&r));
    assert!(get(&core, &root, Some("dst"), "secret/data/x").await.is_none(), "the destination is untouched");
    assert!(get(&core, &root, None, "secret/data/data/x").await.is_some(), "the source is untouched");

    let out = result(transfer(&core, &root, "copy", moving("x", json!({}))).await);
    assert_eq!(out["transferred"]["versions"], json!(1), "a copy deletes nothing: {out}");
    assert!(get(&core, &root, Some("dst"), "secret/data/x").await.is_some());

    kv_key_split_migrate::run_if_needed(core.as_ref()).await.unwrap();
    let out = result(transfer(&core, &root, "move", moving("y", json!({}))).await);
    assert_eq!(out["destination"]["path"], json!("y"), "{out}");
    assert!(get(&core, &root, None, "secret/data/data/x").await.is_none(), "the move deleted its source");
}
