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
    logical::{Operation, Request, Response},
    modules::namespace::{ns_assignment::NsAssignmentStore, NamespaceModule, NAMESPACE_MODULE_NAME},
    test_utils::new_unseal_test_bastion_vault,
};

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
    let body = json!({ "password": PASSWORD, "token_policies": format!("{policies},default"), "ttl": 0 });
    write(core, root, &format!("auth/userpass/users/{name}"), body).await;
    if assigned {
        let ns_store = core
            .module_manager()
            .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
            .and_then(|m| m.store())
            .expect("namespace store");
        let namespaces = vec![String::new(), "src".to_string(), "dst".to_string()];
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

    let request = body("resource", "resources", ("", "srv0"), ("dst", "srv0"), json!({}));
    for op in ["copy", "move"] {
        let r = transfer(&core, &token, op, request.clone()).await;
        assert_eq!(status(&r), 403, "{op}: {r:?}");
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
/// not carry a namespace prefix; a missing namespace is a 404. Nothing is
/// read or written.
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
        (body("resource", "nope", ("src", "srv1"), ("dst", "srv1"), json!({})), 400, "not a mount"),
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
        (body("resource", "resources", ("src", "srv1"), ("missing", "srv1"), json!({})), 404, "no such namespace"),
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
/// and delete nothing for it; an overwrite of an existing item whose import
/// then fails on it says the destination was deleted. Pins the gate code.
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
    let r = transfer(&core, &root, "copy", resource("srv1", "srv1", json!({ "on_conflict": "overwrite" }))).await;
    assert_eq!(status(&r), 409, "{r:?}");
    let m = message(&r);
    assert!(m.contains("DELETE of dst/resources/srv1") && m.contains("import then failed"), "{m}");
    assert!(m.contains("brokered_resource_no_static_credential") && !m.contains("rename"), "{m}");
    assert!(!resource_exists(&core, &root, "dst", "srv1").await, "the overwrite's delete did run");
    assert!(resource_exists(&core, &root, "src", "srv1").await, "the source is untouched");
}
