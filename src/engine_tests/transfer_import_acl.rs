//! The transfer import routes are authorized as the item they write (T494).
//!
//! `<kv-mount>/v2/transfer/import/<path>` and `resources/v2/transfer/import/<name>`
//! go through `Core::handle_request` with real tokens and policies, marked as
//! the transfer marks its own imports, so the ACL, owner, share and asset-group
//! resolution in `post_auth` and the owner stamp in `post_route` run exactly as
//! in production. Unmarked calls are refused (the regression tests at the end).

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Value};

use super::kernel_policy_deny::{write, write_policy};
use crate::{
    core::Core,
    errors::RvError,
    logical::{handler::Handler, Operation, Request, Response},
    modules::{
        identity::{IdentityModule, SecretShare, ShareStore},
        namespace::{NamespaceModule, NamespaceQuotas, NAMESPACE_MODULE_NAME},
        policy::PolicyModule,
    },
    test_utils::{new_unseal_test_bastion_vault, test_read_api, TestHttpServer},
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
    send_as(core, token, op, path, ns, body, false).await
}

/// [`send`], marked as the transfer's own import when `internal`.
async fn send_as(
    core: &Arc<Core>,
    token: &str,
    op: Operation,
    path: &str,
    ns: Option<&str>,
    body: Value,
    internal: bool,
) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = op;
    req.client_token = token.to_string();
    req.body = body.as_object().cloned();
    if let Some(ns) = ns {
        req.headers = Some(HashMap::from([("x-bastionvault-namespace".to_string(), ns.to_string())]));
    }
    if internal {
        req.mark_internal_transfer_import();
    }
    core.handle_request(&mut req).await
}

/// An import as the transfer sends it: marked as its own.
async fn import(core: &Arc<Core>, token: &str, path: &str, body: Value) -> Result<Option<Response>, RvError> {
    send_as(core, token, Operation::Write, path, None, body, true).await
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

    import(&core, &bob, "resources/v2/transfer/import/bob-srv", resource_bundle(&["login"])).await.unwrap();
    assert_eq!(resource_owner(&core, "bob-srv").await, Some(bob_id));
    send(&core, &bob, Operation::Read, "resources/resources/bob-srv", None, json!({})).await.unwrap();
    send(&core, &bob, Operation::Read, "resources/secrets/bob-srv/login", None, json!({})).await.unwrap();
}

/// Each secret a resource import carries is authorized as its normal write,
/// `resources/secrets/<name>/<key>`: a deny there blocks the import, while a
/// bundle with no secrets is unaffected.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn resource_import_honours_a_deny_on_its_secret_paths() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("resource_import_secret_deny").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    let policy = r#"
        path "resources/*" { capabilities = ["create", "read", "update", "list"] }
        path "resources/secrets/*" { capabilities = ["deny"] }
    "#;
    write_policy(&core, &root, "no-secrets", policy).await;
    let (token, _) = login(&core, &root, "inventory", "no-secrets").await;

    let r = import(&core, &token, "resources/v2/transfer/import/srv-a", resource_bundle(&["login"])).await;
    denied(r, "a resource carrying a secret under a secrets deny");
    assert!(test_read_api(core.as_ref(), &root, "resources/resources/srv-a", true).await.unwrap().is_none());
    assert!(test_read_api(core.as_ref(), &root, "resources/secrets/srv-a/login", true).await.unwrap().is_none());

    import(&core, &token, "resources/v2/transfer/import/srv-b", resource_bundle(&[])).await.unwrap();
}

/// Write on the resource record alone does not cover its secrets: every key
/// needs a grant on `resources/secrets/<name>/<key>`, the name normalized as
/// the engine stores it.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn resource_import_needs_write_on_every_secret_path() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("resource_import_secret_grant").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    let policy = r#"
        path "resources/resources/*" { capabilities = ["create", "read", "update"] }
        path "resources/secrets/srv-ok/*" { capabilities = ["create", "update"] }
    "#;
    write_policy(&core, &root, "records", policy).await;
    let (token, _) = login(&core, &root, "records", "records").await;

    for name in ["srv-ko", " SRV-KO"] {
        let r =
            import(&core, &token, &format!("resources/v2/transfer/import/{name}"), resource_bundle(&["login"])).await;
        denied(r, &format!("{name:?}: secrets with no grant"));
    }
    assert!(test_read_api(core.as_ref(), &root, "resources/resources/srv-ko", true).await.unwrap().is_none());

    let r = import(&core, &token, "resources/v2/transfer/import/SRV-OK", resource_bundle(&["login", "api"])).await;
    r.unwrap();
    let read = test_read_api(core.as_ref(), &root, "resources/secrets/srv-ok/api", true).await.unwrap().unwrap();
    assert_eq!(read.data.unwrap()["token"], json!("t-S3CRET"));
    import(&core, &token, "resources/v2/transfer/import/srv-plain", resource_bundle(&[])).await.unwrap();
}

/// A `secrets` list the policy layer cannot read is refused with a 400 that
/// names the field and never echoes a value; nothing is written.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn resource_import_with_a_malformed_secret_list_fails_closed() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("resource_import_malformed_secrets").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    write_policy(&core, &root, "res-writer", RESOURCE_WRITER).await;
    let (token, _) = login(&core, &root, "writer", "res-writer").await;

    let version = json!({ "version": 1, "created_time": "2025-01-01T00:00:00Z", "data": { "p": "S3CRET-v" } });
    for secrets in [
        json!("S3CRET-not-a-list"),
        json!(null),
        json!(["S3CRET-not-an-object"]),
        json!([{ "key": 42, "current": 1, "versions": [version] }]),
        json!([{ "current": 1, "versions": [version] }]),
    ] {
        let mut body = resource_bundle(&[]);
        body["secrets"] = secrets.clone();
        match import(&core, &token, "resources/v2/transfer/import/srv-m", body).await {
            Err(RvError::ErrResponseStatus(400, m)) => assert!(!m.contains("S3CRET"), "{secrets}: {m}"),
            other => panic!("{secrets}: expected 400, got {other:?}"),
        }
    }
    assert!(test_read_api(core.as_ref(), &root, "resources/resources/srv-m", true).await.unwrap().is_none());
}

/// More secrets than the cap are a 400 naming the limit, from the policy
/// layer before any per-secret check, and nothing is written.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn resource_import_over_the_secret_cap_is_refused() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("resource_import_secret_cap").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    write_policy(&core, &root, "res-writer", RESOURCE_WRITER).await;
    let (token, _) = login(&core, &root, "writer", "res-writer").await;

    let keys: Vec<String> = (0..1001).map(|i| format!("k{i}")).collect();
    let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
    for caller in [&token, &root] {
        match import(&core, caller, "resources/v2/transfer/import/srv-big", resource_bundle(&keys)).await {
            Err(RvError::ErrResponseStatus(400, m)) => assert!(m.contains("1000"), "{m}"),
            other => panic!("expected 400, got {other:?}"),
        }
    }
    assert!(test_read_api(core.as_ref(), &root, "resources/resources/srv-big", true).await.unwrap().is_none());
    assert!(test_read_api(core.as_ref(), &root, "resources/secrets/srv-big/k0", true).await.unwrap().is_none());
}

/// A caller with no write on the record is refused before its `secrets` list
/// is read: a malformed or oversized list still answers 403, not 400.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn resource_import_checks_the_record_before_reading_the_secret_list() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("resource_import_record_first").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    let policy = "path \"resources/secrets/*\" { capabilities = [\"create\", \"update\"] }\n";
    write_policy(&core, &root, "secrets-only", policy).await;
    let (token, _) = login(&core, &root, "outsider", "secrets-only").await;

    let keys: Vec<String> = (0..1001).map(|i| format!("k{i}")).collect();
    let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
    for secrets in [json!("S3CRET-not-a-list"), json!([{ "key": 7 }]), resource_bundle(&keys)["secrets"].clone()] {
        let mut body = resource_bundle(&[]);
        body["secrets"] = secrets;
        denied(import(&core, &token, "resources/v2/transfer/import/srv-x", body).await, "no write on the record");
    }
}

/// The policy layer's cap is the engine's own, so neither can drift.
#[test]
fn the_policy_layers_secret_cap_is_the_engines() {
    assert_eq!(crate::modules::policy::TRANSFER_IMPORT_MAX_SECRETS, crate::modules::resource::IMPORT_MAX_SECRETS);
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

    let restricted = "secret/v2/transfer/import/restricted/x";
    let r = send_as(&core, &token, Operation::Write, restricted, ns, kv_bundle(), true).await;
    denied(r, "namespaced import under a denied prefix");

    send_as(&core, &token, Operation::Write, "secret/v2/transfer/import/open/x", ns, kv_bundle(), true).await.unwrap();
    let read = send(&core, &root, Operation::Read, "secret/data/open/x", ns, json!({})).await.unwrap().unwrap();
    assert_eq!(read.data.unwrap()["data"]["v"], json!("imported"));
    assert!(kv_owner(&core, "tenant-a/secret/open/x").await.is_some(), "owner keyed on the namespaced real path");
    assert_eq!(kv_owner(&core, "tenant-a/secret/v2/transfer/import/open/x").await, None, "no stray record");
    let unmarked = send(&core, &token, Operation::Write, "secret/v2/transfer/import/open/y", ns, kv_bundle()).await;
    unknown_route(unmarked, "an unmarked import inside a namespace");
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

/// A request at `api_version` that nothing marked as the transfer's own.
async fn direct(
    core: &Arc<Core>,
    token: &str,
    path: &str,
    api_version: u8,
    body: Value,
) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.api_version = api_version;
    req.client_token = token.to_string();
    req.body = body.as_object().cloned();
    core.handle_request(&mut req).await
}

fn unknown_route(r: Result<Option<Response>, RvError>, what: &str) {
    match r {
        Err(RvError::ErrLogicalPathUnsupported) => {}
        other => panic!("{what}: expected the unknown-route 404, got {other:?}"),
    }
}

/// How many history entries the resource `name` has, read as root.
async fn history_len(core: &Arc<Core>, root: &str, name: &str) -> usize {
    let path = format!("resources/resources/{name}/history");
    let resp = test_read_api(core.as_ref(), root, &path, true).await.unwrap();
    resp.and_then(|r| r.data).and_then(|d| d.get("entries").and_then(Value::as_array).map(Vec::len)).unwrap_or(0)
}

/// A resource bundle whose history and version author name someone else.
fn forged_resource_bundle() -> Value {
    let mut body = resource_bundle(&["login"]);
    body["history"] = json!([{ "ts": "2020-01-01T00:00:00Z", "user": "alice", "op": "create", "changed_fields": [] }]);
    body["secrets"][0]["versions"][0]["username"] = json!("alice");
    body["origin_owner"] = json!("someone-else");
    body
}

/// Regression (T494 final review): the import routes are internal. A request
/// the transfer did not mark is the unknown route's 404 for a caller allowed
/// to write there (`writer`, root), at API v1 and v2, so no forged history,
/// origin or version author is written and no owner stamped. A caller with
/// no grant gets the unknown route's 403 (the tests below).
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_direct_import_is_refused_as_an_unknown_route() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("direct_import_unknown_route").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    write_policy(&core, &root, "kv-writer", KV_WRITER).await;
    write_policy(&core, &root, "res-writer", RESOURCE_WRITER).await;
    let (writer, _) = login(&core, &root, "writer", "kv-writer,res-writer").await;

    let mut kv_forged = kv_bundle();
    kv_forged["versions"][0]["username"] = json!("alice");
    kv_forged["versions"][0]["operation"] = json!("create");
    for token in [&writer, &root] {
        for (path, api, body) in [
            ("secret/v2/transfer/import/open/x", 1, kv_forged.clone()),
            ("resources/v2/transfer/import/free", 1, forged_resource_bundle()),
            ("resources/v2/transfer/import/free", 2, forged_resource_bundle()),
        ] {
            unknown_route(direct(&core, token, path, api, body).await, &format!("{path} at v{api}"));
        }
    }
    assert_eq!(kv_value(&core, &root, "open/x").await, None, "nothing written");
    assert_eq!(kv_owner(&core, "secret/open/x").await, None, "no owner stamped");
    assert!(test_read_api(core.as_ref(), &root, "resources/resources/free", true).await.unwrap().is_none());
    assert_eq!(resource_owner(&core, "free").await, None, "no owner stamped");
    assert_eq!(history_len(&core, &root, "free").await, 0, "no history entry");

    // The transfer's own import of the same names succeeds, so the refused calls
    // left nothing behind (leftover KV version data would answer 409).
    import(&core, &root, "secret/v2/transfer/import/open/x", kv_bundle()).await.unwrap();
    import(&core, &root, "resources/v2/transfer/import/free", resource_bundle(&[])).await.unwrap();
    assert_eq!(history_len(&core, &root, "free").await, 1, "only the transfer-in entry");
}

/// Regression: a direct import answers the same 404 whether the item exists
/// (and belongs to someone else) or not, so it tells the caller nothing.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_direct_import_answers_alike_whether_or_not_the_item_exists() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("direct_import_no_existence_oracle").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    let (alice, alice_id) = login(&core, &root, "alice", "standard-user").await;
    let (bob, _) = login(&core, &root, "bob", "standard-user").await;
    send(&core, &alice, Operation::Write, "secret/data/team/a-secret", None, json!({ "data": { "v": "alice's" } }))
        .await
        .unwrap();
    let meta = json!({ "type": "server", "hostname": "alice.example" });
    send(&core, &alice, Operation::Write, "resources/resources/alice-srv", None, meta).await.unwrap();

    for (taken, free, body) in [
        ("secret/v2/transfer/import/team/a-secret", "secret/v2/transfer/import/team/b-new", kv_bundle()),
        ("resources/v2/transfer/import/alice-srv", "resources/v2/transfer/import/bob-srv", forged_resource_bundle()),
    ] {
        unknown_route(direct(&core, &bob, taken, 1, body.clone()).await, taken);
        unknown_route(direct(&core, &bob, free, 1, body).await, free);
    }
    assert_eq!(kv_value(&core, &root, "team/a-secret").await, Some(json!("alice's")), "untouched");
    assert_eq!(kv_value(&core, &root, "team/b-new").await, None);
    assert_eq!(kv_owner(&core, "secret/team/b-new").await, None);
    assert_eq!(resource_owner(&core, "alice-srv").await, Some(alice_id), "still alice's");
    assert_eq!(resource_owner(&core, "bob-srv").await, None);
    assert_eq!(history_len(&core, &root, "alice-srv").await, 1, "only alice's own create");
}

/// Regression over real HTTP: neither import route is reachable from a client
/// (`/v1` and `/v2`, root token), while a transfer through
/// `/v2/sys/namespace-transfer/copy`, which marks its own imports, still works.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn the_import_routes_are_not_reachable_over_http() {
    let mut server = TestHttpServer::new("import_routes_not_over_http", false).await;
    server.token = server.root_token.clone();
    let obj = |v: Value| v.as_object().cloned();
    let v1 = server.url_prefix.clone();
    let v2 = v1.replace("/v1", "/v2");

    for (prefix, path, body) in [
        (&v1, "secret/v2/transfer/import/open/x", kv_bundle()),
        (&v1, "resources/v2/transfer/import/free", forged_resource_bundle()),
        (&v2, "resources/v2/transfer/import/free", forged_resource_bundle()),
    ] {
        server.url_prefix = prefix.clone();
        let (status, resp) = server.write(path, obj(body), None).unwrap();
        assert_eq!(status, 404, "{prefix}/{path}: {resp}");
    }
    server.url_prefix = v1.clone();
    let (core, root) = (server.core.clone(), server.root_token.clone());
    assert_eq!(kv_value(&core, &root, "open/x").await, None, "nothing written");
    assert!(test_read_api(core.as_ref(), &root, "resources/resources/free", true).await.unwrap().is_none());
    assert_eq!(history_len(&core, &root, "free").await, 0, "no history entry");

    for ns in ["src", "dst"] {
        assert_eq!(server.write(&format!("sys/namespaces/{ns}"), obj(json!({})), None).unwrap().0, 200);
    }
    let meta = obj(json!({ "type": "server", "hostname": "h.example" }));
    let header = [("X-BastionVault-Namespace", "src")];
    let (status, resp) =
        server.request_with_headers("POST", "resources/resources/srv1", meta, None, None, &header).unwrap();
    assert!(status < 300, "{resp}");
    server.url_prefix = v2;
    let copy = json!({
        "kind": "resource",
        "source": { "namespace": "src", "mount": "resources", "path": "srv1" },
        "destination": { "namespace": "dst", "mount": "resources", "path": "srv1" },
    });
    let (status, resp) = server.write("sys/namespace-transfer/copy", obj(copy), None).unwrap();
    assert_eq!(status, 200, "the transfer marks its own imports: {resp}");
    server.url_prefix = v1;
    let header = [("X-BastionVault-Namespace", "dst")];
    let (status, resp) =
        server.request_with_headers("GET", "resources/resources/srv1", None, None, None, &header).unwrap();
    assert_eq!(status, 200, "the copy arrived: {resp}");
}

/// A direct write's whole answer, `<status>: <error text>`, so two compare.
fn answer(r: Result<Option<Response>, RvError>) -> String {
    match r {
        Ok(_) => "200: written".to_string(),
        Err(RvError::ErrResponseStatus(status, message)) => format!("{status}: {message}"),
        Err(e) => format!("{}: {e}", e.response_status()),
    }
}

/// The import route under `mount` answers `token` exactly as an unknown route
/// beside it in the same mount and namespace does, with status `expected`.
async fn import_answers_like_an_unknown_route(
    core: &Arc<Core>,
    (who, token): (&str, &str),
    ns: Option<&str>,
    mount: &str,
    name: &str,
    expected: u16,
) {
    let body = if mount.ends_with("resources") { forged_resource_bundle() } else { kv_bundle() };
    let import = format!("{mount}/v2/transfer/import/{name}");
    let import = answer(send(core, token, Operation::Write, &import, ns, body.clone()).await);
    let unknown = format!("{mount}/no-such-route/{name}");
    let unknown = answer(send(core, token, Operation::Write, &unknown, ns, body).await);
    let what = format!("{who}: {mount}/.../{name} in {ns:?}");
    assert_eq!(import, unknown, "{what}: the import answers like an unknown route");
    assert!(import.starts_with(&format!("{expected}:")), "{what}: expected {expected}, {import}");
}

/// Regression (T494 final review, Ruling P): a token with no grant on the
/// import path gets the 403 any unknown route there gives it, whether the
/// mount is a kv-v2 or resource mount or does not exist and whether the item
/// exists, so the answer tells it nothing about mounts or items.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_direct_import_without_a_grant_is_refused_alike_on_any_mount() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("direct_import_no_grant_alike").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    write_policy(&core, &root, "elsewhere", "path \"other/*\" { capabilities = [\"create\", \"update\"] }\n").await;
    let (nobody, _) = login(&core, &root, "nobody", "elsewhere").await;
    write(&core, &root, "secret/data/taken", json!({ "data": { "v": "root's" } })).await;
    write(&core, &root, "resources/resources/taken", json!({ "type": "server", "hostname": "h.example" })).await;

    for mount in ["secret", "resources", "nomount"] {
        for name in ["taken", "free"] {
            import_answers_like_an_unknown_route(&core, ("nobody", &nobody), None, mount, name, 403).await;
            let path = format!("{mount}/v2/transfer/import/{name}");
            denied(direct(&core, &nobody, &path, 2, forged_resource_bundle()).await, &format!("{path} at v2"));
        }
    }
    assert_eq!(kv_value(&core, &root, "free").await, None, "nothing written");
    assert_eq!(kv_value(&core, &root, "taken").await, Some(json!("root's")), "untouched");
    assert!(test_read_api(core.as_ref(), &root, "resources/resources/free", true).await.unwrap().is_none());
    assert_eq!(history_len(&core, &root, "taken").await, 1, "only root's own create");
}

/// Regression (T494 final review, Ruling P): a token bound elsewhere, whether
/// to a sibling namespace or to root without the right to operate in the
/// target namespace (though its policy names paths there), is refused there
/// as on any unknown route, for existing and missing mounts alike.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_token_bound_elsewhere_is_refused_alike_on_any_mount_of_a_namespace() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("direct_import_bound_elsewhere").await;
    for ns in ["tenant-a", "tenant-b"] {
        write(&core, &root, &format!("sys/namespaces/{ns}"), json!({})).await;
    }
    let a = Some("tenant-a");
    send(&core, &root, Operation::Write, "secret/data/taken", a, json!({ "data": { "v": "a's" } })).await.unwrap();
    let meta = json!({ "type": "server", "hostname": "h.example" });
    send(&core, &root, Operation::Write, "resources/resources/taken", a, meta).await.unwrap();

    let wide = json!({ "policy": "path \"tenant-b/*\" { capabilities = [\"create\", \"read\", \"update\"] }" });
    let b = Some("tenant-b");
    send(&core, &root, Operation::Write, "sys/policy/b-wide", b, wide).await.unwrap();
    let body = json!({ "policies": ["b-wide"], "child_visible": false, "ttl": "1h" });
    let created = send(&core, &root, Operation::Write, "auth/token/create", b, body).await.unwrap().unwrap();
    let sibling = created.auth.unwrap().client_token;

    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    let into_a = "path \"tenant-a/*\" { capabilities = [\"create\", \"read\", \"update\"] }\n";
    write_policy(&core, &root, "names-tenant-a", into_a).await;
    let (outsider, _) = login(&core, &root, "outsider", "names-tenant-a").await;

    for token in [("sibling", sibling.as_str()), ("outsider", outsider.as_str())] {
        for mount in ["secret", "resources", "nomount"] {
            for name in ["taken", "free"] {
                import_answers_like_an_unknown_route(&core, token, a, mount, name, 403).await;
            }
        }
    }
    let read = send(&core, &root, Operation::Read, "secret/data/free", a, json!({})).await.unwrap();
    assert!(read.is_none(), "nothing written");
    let read = send(&core, &root, Operation::Read, "resources/resources/free", a, json!({})).await.unwrap();
    assert!(read.is_none(), "nothing written");
}

/// Regression (T494 final review, Ruling P): a token allowed to write there
/// gets the unknown-route 404 on existing and missing mounts alike (as on any
/// unknown route there), writes nothing and stamps no owner or history; the
/// transfer's own import of the same names then succeeds.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_direct_import_with_a_grant_is_an_unknown_route_on_any_mount() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("direct_import_with_grant_alike").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    write_policy(&core, &root, "kv-writer", KV_WRITER).await;
    write_policy(&core, &root, "res-writer", RESOURCE_WRITER).await;
    write_policy(&core, &root, "nomount", "path \"nomount/*\" { capabilities = [\"create\", \"update\"] }\n").await;
    let (writer, _) = login(&core, &root, "writer", "kv-writer,res-writer,nomount").await;
    write(&core, &root, "secret/data/taken", json!({ "data": { "v": "root's" } })).await;
    write(&core, &root, "resources/resources/taken", json!({ "type": "server", "hostname": "h.example" })).await;

    for mount in ["secret", "resources", "nomount"] {
        for name in ["taken", "free"] {
            import_answers_like_an_unknown_route(&core, ("writer", &writer), None, mount, name, 404).await;
        }
    }
    assert_eq!(kv_value(&core, &root, "free").await, None, "nothing written");
    assert_eq!(kv_owner(&core, "secret/free").await, None, "no owner stamped");
    assert_eq!(kv_value(&core, &root, "taken").await, Some(json!("root's")), "untouched");
    assert!(test_read_api(core.as_ref(), &root, "resources/resources/free", true).await.unwrap().is_none());
    assert_eq!(resource_owner(&core, "free").await, None, "no owner stamped");
    assert_eq!(history_len(&core, &root, "free").await, 0, "no history entry");
    assert_eq!(history_len(&core, &root, "taken").await, 1, "only root's own create");

    import(&core, &writer, "secret/v2/transfer/import/free", kv_bundle()).await.unwrap();
    import(&core, &writer, "resources/v2/transfer/import/free", resource_bundle(&[])).await.unwrap();
    assert_eq!(kv_value(&core, &root, "free").await, Some(json!("imported")));
    assert_eq!(history_len(&core, &root, "free").await, 1, "only the transfer-in entry");
}

/// Seam (T502): appends `-other` to the name a marked import answers with, as
/// an engine bug would, ahead of the policy store's `post_route`.
struct AnswerAnotherName;

#[maybe_async::maybe_async]
impl Handler for AnswerAnotherName {
    fn name(&self) -> String {
        "test-answer-another-name".to_string()
    }

    async fn post_route(&self, req: &mut Request, resp: &mut Option<Response>) -> Result<(), RvError> {
        let data = resp.as_mut().and_then(|r| r.data.as_mut()).filter(|_| req.is_internal_transfer_import());
        if let Some(data) = data {
            for field in ["path", "name"] {
                if let Some(Value::String(name)) = data.get_mut(field) {
                    name.push_str("-other");
                }
            }
        }
        Ok(())
    }
}

/// Put [`AnswerAnotherName`] in the pipeline right before the policy store.
async fn answer_another_name(core: &Arc<Core>) {
    let module = core.module_manager().get_module::<PolicyModule>("policy").expect("policy module");
    let store: Arc<dyn Handler> = module.policy_store.load_full();
    core.delete_handler(store.clone()).unwrap();
    core.add_handler(Arc::new(AnswerAnotherName)).unwrap();
    core.add_handler(store).unwrap();
}

/// Regression (T502): an import whose answer names another item than the one
/// the ACL checked fails with a 500 that names the item and says it was
/// written without an owner record, and nothing is stamped; the transfer
/// passes that answer on. Unreachable with today's engines: the seam fakes it.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn an_import_answering_another_name_fails_and_names_the_unowned_item() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("import_answers_another_name").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    write_policy(&core, &root, "kv-writer", KV_WRITER).await;
    write_policy(&core, &root, "res-writer", RESOURCE_WRITER).await;
    let (writer, _) = login(&core, &root, "writer", "kv-writer,res-writer").await;
    answer_another_name(&core).await;

    for (path, item, answered, body) in [
        ("secret/v2/transfer/import/team/db", "secret/team/db", "team/db-other", kv_bundle()),
        ("resources/v2/transfer/import/srv1", "resources/resources/srv1", "srv1-other", resource_bundle(&["login"])),
    ] {
        match import(&core, &writer, path, body).await {
            Err(RvError::ErrResponseStatus(500, m)) => {
                assert!(m.contains(&format!("{item} was written")) && m.contains(answered), "{path}: {m}");
                assert!(m.contains("no owner record") && !m.contains("S3CRET"), "{path}: {m}");
            }
            other => panic!("{path}: expected 500, got {other:?}"),
        }
    }
    assert_eq!(kv_value(&core, &root, "team/db").await, Some(json!("imported")), "the engine wrote it");
    for key in ["secret/team/db", "secret/team/db-other"] {
        assert_eq!(kv_owner(&core, key).await, None, "{key}: no owner stamped");
    }
    assert!(test_read_api(core.as_ref(), &root, "resources/resources/srv1", true).await.unwrap().is_some());
    for name in ["srv1", "srv1-other"] {
        assert_eq!(resource_owner(&core, name).await, None, "{name}: no owner stamped");
    }

    let copy = json!({
        "kind": "kv-secret",
        "source": { "namespace": "", "mount": "secret", "path": "team/db" },
        "destination": { "namespace": "", "mount": "secret", "path": "team/copy" },
    });
    match send(&core, &root, Operation::Write, "sys/namespace-transfer/copy", None, copy).await {
        Err(RvError::ErrResponseStatus(500, m)) => {
            assert!(m.contains("secret/team/copy was written") && m.contains("no owner record"), "{m}");
        }
        other => panic!("the transfer: expected 500, got {other:?}"),
    }
    assert_eq!(kv_owner(&core, "secret/team/copy").await, None, "no owner stamped");
}
