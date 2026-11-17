//! The transfer import routes are authorized as the item they write (T494).
//!
//! `<kv-mount>/v2/transfer/import/<path>` and `resources/v2/transfer/import/<name>`
//! go through `Core::handle_request` with real tokens and policies, so the
//! ACL, owner, share and asset-group resolution in `post_auth` and the owner
//! stamp in `post_route` run exactly as in production.

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Value};

use super::kernel_policy_deny::{write, write_policy};
use crate::{
    core::Core,
    errors::RvError,
    logical::{Operation, Request, Response},
    modules::{
        identity::{IdentityModule, SecretShare, ShareStore},
        namespace::{NamespaceModule, NamespaceQuotas, NAMESPACE_MODULE_NAME},
    },
    test_utils::{new_unseal_test_bastion_vault, test_read_api},
};

const PASSWORD: &str = "hunter22XX!";

/// A userpass user on `auth/pass/` carrying `policies`: `(token, entity_id)`.
async fn login(core: &Arc<Core>, root: &str, name: &str, policies: &str) -> (String, String) {
    write(
        core,
        root,
        &format!("auth/pass/users/{name}"),
        json!({ "password": PASSWORD, "token_policies": policies, "ttl": 0 }),
    )
    .await;
    let mut req = Request::new(format!("auth/pass/login/{name}"));
    req.operation = Operation::Write;
    req.body = json!({ "password": PASSWORD }).as_object().cloned();
    let auth = core.handle_request(&mut req).await.unwrap().unwrap().auth.unwrap();
    let entity = auth.metadata.get("entity_id").cloned().unwrap_or_default();
    assert!(!entity.is_empty(), "a userpass login carries an entity id");
    (auth.client_token, entity)
}

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

async fn import(core: &Arc<Core>, token: &str, path: &str, body: Value) -> Result<Option<Response>, RvError> {
    send(core, token, Operation::Write, path, None, body).await
}

fn kv_bundle() -> Value {
    json!({
        "versions": [{ "version": 1, "created_time": "2025-01-01T00:00:00Z", "data": { "v": "imported" } }],
        "current": 1
    })
}

/// A resource bundle carrying one version of a secret under each of `keys`.
fn resource_bundle(keys: &[&str]) -> Value {
    let version = json!({ "version": 1, "created_time": "2025-01-01T00:00:00Z", "data": { "token": "t-S3CRET" } });
    let secrets: Vec<Value> = keys.iter().map(|k| json!({ "key": k, "current": 1, "versions": [version] })).collect();
    json!({
        "meta": { "type": "server", "hostname": "h.example" },
        "secrets": secrets,
        "history": [],
        "origin": "elsewhere/resources/x"
    })
}

fn with_conflict(mut body: Value, mode: &str) -> Value {
    body["on_conflict"] = json!(mode);
    body
}

fn denied(r: Result<Option<Response>, RvError>, what: &str) {
    match r {
        Err(RvError::ErrPermissionDenied) => {}
        other => panic!("{what}: expected 403, got {other:?}"),
    }
}

/// The value a KV v2 secret holds now, read as root.
async fn kv_value(core: &Arc<Core>, root: &str, path: &str) -> Option<Value> {
    let resp = test_read_api(core.as_ref(), root, &format!("secret/data/{path}"), true).await.unwrap()?;
    resp.data.and_then(|d| d.get("data").and_then(|d| d.get("v")).cloned())
}

async fn kv_owner(core: &Arc<Core>, key: &str) -> Option<String> {
    let module = core.module_manager().get_module::<IdentityModule>("identity").expect("identity module");
    module.owner_store().expect("owner store").get_kv_owner(key).await.unwrap().map(|r| r.entity_id)
}

async fn resource_owner(core: &Arc<Core>, name: &str) -> Option<String> {
    let module = core.module_manager().get_module::<IdentityModule>("identity").expect("identity module");
    module.owner_store().expect("owner store").get_resource_owner(name).await.unwrap().map(|r| r.entity_id)
}

const KV_WRITER: &str = r#"
path "secret/*" { capabilities = ["create", "read", "update"] }
path "secret/restricted/*" { capabilities = ["deny"] }
"#;

const RESOURCE_WRITER: &str = r#"
path "resources/*" { capabilities = ["create", "read", "update", "list"] }
path "resources/resources/locked" { capabilities = ["deny"] }
"#;

/// A deny on the real KV path blocks the import; the same grant elsewhere
/// still imports, and the item lands only where it was allowed.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn kv_import_honours_a_deny_on_the_real_path() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("kv_import_honours_a_deny").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    write_policy(&core, &root, "kv-writer", KV_WRITER).await;
    let (token, _) = login(&core, &root, "writer", "kv-writer").await;

    let r = import(&core, &token, "secret/v2/transfer/import/restricted/x", kv_bundle()).await;
    denied(r, "import under a denied prefix");
    assert_eq!(kv_value(&core, &root, "restricted/x").await, None, "nothing written");

    import(&core, &token, "secret/v2/transfer/import/open/x", kv_bundle()).await.unwrap();
    assert_eq!(kv_value(&core, &root, "open/x").await, Some(json!("imported")));
}

/// The resource import is checked on `resources/resources/<name>`, with the
/// name trimmed and lower-cased exactly as the engine stores it.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn resource_import_honours_a_deny_on_the_real_path() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("resource_import_honours_a_deny").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    write_policy(&core, &root, "res-writer", RESOURCE_WRITER).await;
    let (token, entity) = login(&core, &root, "writer", "res-writer").await;

    for name in ["locked", "LOCKED", " locked", "Locked "] {
        let r = import(&core, &token, &format!("resources/v2/transfer/import/{name}"), resource_bundle(&[])).await;
        denied(r, &format!("import as {name:?}"));
    }
    assert!(test_read_api(core.as_ref(), &root, "resources/resources/locked", true).await.unwrap().is_none());

    import(&core, &token, "resources/v2/transfer/import/free", resource_bundle(&[])).await.unwrap();
    assert_eq!(resource_owner(&core, "free").await, Some(entity), "the importer owns the real item");
}

/// `standard-user` (owner/shared scopes): another user's item is refused by
/// the ACL itself, and a new item is owned by the importer under its real
/// key, with no stray owner record at the import route.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn kv_import_under_owner_scopes_checks_and_stamps_the_real_item() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("kv_import_owner_scopes").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    let (alice, alice_id) = login(&core, &root, "alice", "standard-user").await;
    let (bob, bob_id) = login(&core, &root, "bob", "standard-user").await;

    let body = json!({ "data": { "v": "alice's" } });
    send(&core, &alice, Operation::Write, "secret/data/team/a-secret", None, body).await.unwrap();
    assert_eq!(kv_owner(&core, "secret/team/a-secret").await, Some(alice_id.clone()));

    let r = import(&core, &bob, "secret/v2/transfer/import/team/a-secret", kv_bundle()).await;
    denied(r, "bob importing onto alice's secret");
    assert_eq!(kv_value(&core, &root, "team/a-secret").await, Some(json!("alice's")), "untouched");

    import(&core, &bob, "secret/v2/transfer/import/team/b-new", kv_bundle()).await.unwrap();
    assert_eq!(kv_owner(&core, "secret/team/b-new").await, Some(bob_id), "bob owns the real item");
    assert_eq!(kv_owner(&core, "secret/v2/transfer/import/team/b-new").await, None, "no stray record");
    let read = |token: String| {
        let core = core.clone();
        async move { send(&core, &token, Operation::Read, "secret/data/team/b-new", None, json!({})).await }
    };
    assert!(read(bob.clone()).await.is_ok(), "the owner reads what they imported");
    denied(read(alice.clone()).await, "alice reading bob's import");
}

/// `rename` and `overwrite` are refused with a 400 on both import routes, for
/// an occupied and a free name alike, and nothing is written or stamped.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn rename_and_overwrite_are_refused_on_both_import_routes() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("import_refuses_rename").await;
    write(&core, &root, "secret/data/team/taken", json!({ "data": { "v": "kept" } })).await;
    write(&core, &root, "resources/resources/taken", json!({ "type": "server", "hostname": "kept" })).await;

    for mode in ["rename", "overwrite"] {
        for (path, body) in [
            ("secret/v2/transfer/import/team/taken", kv_bundle()),
            ("secret/v2/transfer/import/team/free", kv_bundle()),
            ("resources/v2/transfer/import/taken", resource_bundle(&["login"])),
            ("resources/v2/transfer/import/free", resource_bundle(&["login"])),
        ] {
            match import(&core, &root, path, with_conflict(body, mode)).await {
                Err(RvError::ErrResponseStatus(400, m)) => assert!(m.contains("on_conflict must be refuse"), "{m}"),
                other => panic!("{mode} {path}: expected 400, got {other:?}"),
            }
        }
    }
    assert_eq!(kv_value(&core, &root, "team/taken").await, Some(json!("kept")));
    for path in ["team/taken-2", "team/free"] {
        assert_eq!(kv_value(&core, &root, path).await, None, "{path}");
    }
    for name in ["taken-2", "free"] {
        let read = test_read_api(core.as_ref(), &root, &format!("resources/resources/{name}"), true).await.unwrap();
        assert!(read.is_none(), "{name}");
        assert_eq!(resource_owner(&core, name).await, None, "{name}");
    }
    assert_eq!(kv_owner(&core, "secret/team/free").await, None);
}

/// `standard-user` on resources: refused onto another user's resource,
/// and the importer owns a new one.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn resource_import_under_owner_scopes_checks_and_stamps_the_real_item() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("resource_import_owner_scopes").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    let (alice, alice_id) = login(&core, &root, "alice", "standard-user").await;
    let (bob, bob_id) = login(&core, &root, "bob", "standard-user").await;

    let meta = json!({ "type": "server", "hostname": "alice.example" });
    send(&core, &alice, Operation::Write, "resources/resources/alice-srv", None, meta).await.unwrap();
    assert_eq!(resource_owner(&core, "alice-srv").await, Some(alice_id));

    for name in ["alice-srv", "ALICE-SRV"] {
        let r = import(&core, &bob, &format!("resources/v2/transfer/import/{name}"), resource_bundle(&[])).await;
        denied(r, &format!("bob importing onto alice's resource as {name:?}"));
    }
    let read = test_read_api(core.as_ref(), &root, "resources/resources/alice-srv", true).await.unwrap().unwrap();
    assert_eq!(read.data.unwrap()["hostname"], json!("alice.example"), "untouched");

    import(&core, &bob, "resources/v2/transfer/import/bob-srv", resource_bundle(&[])).await.unwrap();
    assert_eq!(resource_owner(&core, "bob-srv").await, Some(bob_id));
    send(&core, &bob, Operation::Read, "resources/resources/bob-srv", None, json!({})).await.unwrap();
}

/// A policy limited to one prefix imports there and nowhere else.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn kv_import_follows_a_path_limited_policy() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("kv_import_path_limited").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    write_policy(&core, &root, "team-a", "path \"secret/team-a/*\" { capabilities = [\"create\", \"update\"] }\n")
        .await;
    let (token, _) = login(&core, &root, "teamer", "team-a").await;

    import(&core, &token, "secret/v2/transfer/import/team-a/db", kv_bundle()).await.unwrap();
    assert_eq!(kv_value(&core, &root, "team-a/db").await, Some(json!("imported")));

    denied(import(&core, &token, "secret/v2/transfer/import/team-b/db", kv_bundle()).await, "team-b");
    assert_eq!(kv_value(&core, &root, "team-b/db").await, None);
}

/// A share-scoped grant is resolved on the real item: a share on
/// `secret/team/planned` lets the grantee import exactly there.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn kv_import_resolves_shares_on_the_real_item() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("kv_import_resolves_shares").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    let policy = "path \"secret/*\" {\n  capabilities = [\"create\", \"update\"]\n  scopes = [\"shared\"]\n}\n";
    write_policy(&core, &root, "share-only", policy).await;
    let (bob, bob_id) = login(&core, &root, "bob", "share-only").await;

    let shares = ShareStore::new(&core).await.unwrap();
    let share = SecretShare {
        target_kind: "kv-secret".into(),
        target_path: "secret/team/planned".into(),
        grantee_kind: String::new(),
        grantee_entity_id: bob_id.clone(),
        granted_by_entity_id: "root".into(),
        capabilities: vec!["update".into()],
        granted_at: String::new(),
        expires_at: String::new(),
    };
    shares.set_share(share).await.unwrap();

    import(&core, &bob, "secret/v2/transfer/import/team/planned", kv_bundle()).await.unwrap();
    assert_eq!(kv_owner(&core, "secret/team/planned").await, Some(bob_id));
    denied(import(&core, &bob, "secret/v2/transfer/import/team/other", kv_bundle()).await, "no share there");
}

/// A `groups`-gated grant is resolved on the real item's asset-group
/// membership, not on the route's.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn kv_import_resolves_asset_groups_on_the_real_item() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("kv_import_resolves_groups").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    write(&core, &root, "resource-group/groups/club", json!({ "secrets": "secret/team/in-club" })).await;
    let policy = "path \"secret/*\" {\n  capabilities = [\"create\", \"update\"]\n  groups = [\"club\"]\n}\n";
    write_policy(&core, &root, "club-writer", policy).await;
    let (token, _) = login(&core, &root, "member", "club-writer").await;

    import(&core, &token, "secret/v2/transfer/import/team/in-club", kv_bundle()).await.unwrap();
    assert_eq!(kv_value(&core, &root, "team/in-club").await, Some(json!("imported")));
    denied(import(&core, &token, "secret/v2/transfer/import/team/outside", kv_bundle()).await, "not in club");
}

/// A KV name that reads as a sub-command (`data/x`) is checked through
/// `data/<name>`, as its normal write is, and owned the way that write is.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn kv_import_of_a_sub_command_shaped_name_uses_its_data_path() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("kv_import_sub_command_name").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    let policy = r#"
        path "secret/data/data/*" {
            capabilities = ["create", "read", "update"]
            scopes = ["owner"]
        }
    "#;
    write_policy(&core, &root, "nested", policy).await;
    let (token, _) = login(&core, &root, "nested", "nested").await;
    let (other, _) = login(&core, &root, "other", "nested").await;

    import(&core, &token, "secret/v2/transfer/import/data/x", kv_bundle()).await.unwrap();
    assert_eq!(kv_value(&core, &root, "data/x").await, Some(json!("imported")));
    send(&core, &token, Operation::Read, "secret/data/data/x", None, json!({})).await.unwrap();
    denied(send(&core, &other, Operation::Read, "secret/data/data/x", None, json!({})).await, "not the owner");
    assert_eq!(kv_owner(&core, "secret/v2/transfer/import/data/x").await, None, "no stray record");
}

/// `sys/capabilities-self` on an import route reports the real item's
/// capabilities, so it predicts what the import will be allowed to do.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn capabilities_self_reports_the_real_targets_capabilities() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("capabilities_self_import_route").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    write_policy(&core, &root, "kv-writer", KV_WRITER).await;
    write_policy(&core, &root, "res-writer", RESOURCE_WRITER).await;
    let (token, _) = login(&core, &root, "writer", "kv-writer,res-writer,default").await;

    let paths = [
        "secret/v2/transfer/import/restricted/x",
        "secret/v2/transfer/import/open/x",
        "resources/v2/transfer/import/locked",
        "resources/v2/transfer/import/free",
    ];
    let resp = send(&core, &token, Operation::Write, "sys/capabilities-self", None, json!({ "paths": paths }))
        .await
        .unwrap()
        .unwrap();
    let caps = resp.data.unwrap()["capabilities"].clone();
    assert_eq!(caps[paths[0]], json!(["deny"]), "{caps}");
    assert_eq!(caps[paths[2]], json!(["deny"]), "{caps}");
    for open in [paths[1], paths[3]] {
        let got: Vec<&str> = caps[open].as_array().unwrap().iter().filter_map(Value::as_str).collect();
        assert!(got.contains(&"create") && got.contains(&"update"), "{open}: {caps}");
    }
}

/// Inside a namespace the import is checked against `<ns>/<mount>/<path>` and
/// the owner record is keyed there, as a normal write in that namespace.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn kv_import_in_a_namespace_uses_the_namespaced_real_path() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("kv_import_in_a_namespace").await;
    let ns = Some("tenant-a");
    let store = core
        .module_manager()
        .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
        .and_then(|m| m.store())
        .expect("namespace store");
    store.create("tenant-a", NamespaceQuotas::default(), false).await.unwrap();
    send(&core, &root, Operation::Write, "sys/mounts/secret/", ns, json!({ "type": "kv-v2" })).await.unwrap();
    let policy = r#"
        path "tenant-a/secret/*" { capabilities = ["create", "read", "update"] }
        path "tenant-a/secret/restricted/*" { capabilities = ["deny"] }
    "#;
    send(&core, &root, Operation::Write, "sys/policy/ns-writer", ns, json!({ "policy": policy })).await.unwrap();
    let body = json!({ "policies": ["ns-writer"], "child_visible": false, "ttl": "1h" });
    let created = send(&core, &root, Operation::Write, "auth/token/create", ns, body).await.unwrap().unwrap();
    let token = created.auth.unwrap().client_token;

    let r = send(&core, &token, Operation::Write, "secret/v2/transfer/import/restricted/x", ns, kv_bundle()).await;
    denied(r, "namespaced import under a denied prefix");

    send(&core, &token, Operation::Write, "secret/v2/transfer/import/open/x", ns, kv_bundle()).await.unwrap();
    let read = send(&core, &root, Operation::Read, "secret/data/open/x", ns, json!({})).await.unwrap().unwrap();
    assert_eq!(read.data.unwrap()["data"]["v"], json!("imported"));
    assert!(kv_owner(&core, "tenant-a/secret/open/x").await.is_some(), "owner keyed on the namespaced real path");
    assert_eq!(kv_owner(&core, "tenant-a/secret/v2/transfer/import/open/x").await, None, "no stray record");
}

/// At API version 2 a kv-v2 mount reads `v2/transfer/import/<p>` as a secret
/// name (the router prepends `data/`), so that request is an ordinary write
/// authorized on its own path. Pins the router rule the mapping mirrors.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn api_v2_kv_write_to_the_import_shape_is_an_ordinary_secret() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("api_v2_kv_import_shape").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    write_policy(&core, &root, "literal", "path \"secret/v2/*\" { capabilities = [\"create\", \"update\"] }\n").await;
    write_policy(&core, &root, "real", "path \"secret/x\" { capabilities = [\"create\", \"update\"] }\n").await;
    let (literal, _) = login(&core, &root, "literal", "literal").await;
    let (real, _) = login(&core, &root, "real", "real").await;

    let v2_write = |token: String| {
        let core = core.clone();
        async move {
            let mut req = Request::new("secret/v2/transfer/import/x");
            req.operation = Operation::Write;
            req.api_version = 2;
            req.client_token = token;
            req.body = json!({ "data": { "v": "plain" } }).as_object().cloned();
            core.handle_request(&mut req).await
        }
    };
    denied(v2_write(real).await, "a grant on the would-be import target");
    v2_write(literal).await.unwrap();
    assert_eq!(kv_value(&core, &root, "v2/transfer/import/x").await, Some(json!("plain")));
    assert_eq!(kv_value(&core, &root, "x").await, None, "the import route was not reached");
}
