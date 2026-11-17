//! A KV secret's owner and share key is derived once (T499).
//!
//! The policy layer and the owner store each stripped a `data`/`metadata`
//! segment, so a secret named `data/x` keyed as `x`: its writer was stamped
//! owner of an unowned `x` and passed the owner scope on it. These drive real
//! tokens through `Core::handle_request` on both API versions.

use std::{collections::HashMap, sync::Arc};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};

use super::kernel_policy_deny::{write, write_policy};
use crate::{
    core::Core,
    errors::RvError,
    logical::{Operation, Request, Response},
    modules::identity::IdentityModule,
    test_utils::new_unseal_test_bastion_vault,
};

const PASSWORD: &str = "hunter22XX!";

/// A userpass user on `auth/pass/` carrying `policies`: `(token, entity_id)`.
pub(super) async fn login(core: &Arc<Core>, root: &str, name: &str, policies: &str) -> (String, String) {
    let body = json!({ "password": PASSWORD, "token_policies": policies, "ttl": 0 });
    write(core, root, &format!("auth/pass/users/{name}"), body).await;
    let mut req = Request::new(format!("auth/pass/login/{name}"));
    req.operation = Operation::Write;
    req.body = json!({ "password": PASSWORD }).as_object().cloned();
    let auth = core.handle_request(&mut req).await.unwrap().unwrap().auth.unwrap();
    let entity = auth.metadata.get("entity_id").cloned().unwrap_or_default();
    assert!(!entity.is_empty(), "a userpass login carries an entity id");
    (auth.client_token, entity)
}

/// One request as `token` at API version `api`, optionally in namespace `ns`.
pub(super) async fn send(
    core: &Arc<Core>,
    token: &str,
    api: u8,
    op: Operation,
    path: &str,
    ns: Option<&str>,
    body: Value,
) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = op;
    req.api_version = api;
    req.client_token = token.to_string();
    req.body = body.as_object().cloned();
    if let Some(ns) = ns {
        req.headers = Some(HashMap::from([("x-bastionvault-namespace".to_string(), ns.to_string())]));
    }
    core.handle_request(&mut req).await
}

pub(super) fn is_denied(r: &Result<Option<Response>, RvError>) -> bool {
    matches!(r, Err(RvError::ErrPermissionDenied) | Err(RvError::ErrResponseStatus(403, _)))
}

/// The HTTP status a request ends with (200 for success).
pub(super) fn status(r: &Result<Option<Response>, RvError>) -> u16 {
    match r {
        Ok(_) => 200,
        Err(RvError::ErrResponseStatus(s, _)) => *s,
        Err(e) => e.response_status(),
    }
}

fn denied(r: Result<Option<Response>, RvError>, what: &str) {
    assert!(is_denied(&r), "{what}: expected 403, got {r:?}");
}

fn allowed(r: Result<Option<Response>, RvError>, what: &str) -> Option<Response> {
    match r {
        Ok(resp) => resp,
        Err(e) => panic!("{what}: expected success, got {e:?}"),
    }
}

fn data(v: &str) -> Value {
    json!({ "data": { "v": v } })
}

/// The value of KV v2 secret `name` on `secret/`, read as root.
async fn value(core: &Arc<Core>, root: &str, name: &str) -> Option<Value> {
    let resp = send(core, root, 1, Operation::Read, &format!("secret/data/{name}"), None, json!({})).await.ok()??;
    resp.data.and_then(|d| d.get("data").and_then(|d| d.get("v")).cloned())
}

pub(super) async fn owner_store(core: &Arc<Core>) -> Arc<crate::modules::identity::OwnerStore> {
    let module = core.module_manager().get_module::<IdentityModule>("identity").expect("identity module");
    module.owner_store().expect("owner store")
}

pub(super) async fn kv_owner(core: &Arc<Core>, key: &str) -> Option<String> {
    owner_store(core).await.get_kv_owner(key).await.unwrap().map(|r| r.entity_id)
}

/// A secret written by root and then left without an owner record, as a
/// secret written before per-user scoping existed is.
async fn legacy_unowned(core: &Arc<Core>, root: &str, name: &str) {
    allowed(send(core, root, 1, Operation::Write, &format!("secret/data/{name}"), None, data("legacy")).await, "seed");
    owner_store(core).await.forget_kv_owner(&format!("secret/{name}")).await.unwrap();
    assert_eq!(kv_owner(core, &format!("secret/{name}")).await, None);
}

/// Grant `grantee` read on the KV secret `target` (`<mount><name>`) as `token`.
async fn share_read(core: &Arc<Core>, token: &str, target: &str, grantee: &str) -> Result<Option<Response>, RvError> {
    let path = format!("identity/sharing/by-target/kv-secret/{}/{grantee}", URL_SAFE_NO_PAD.encode(target));
    send(core, token, 1, Operation::Write, &path, None, json!({ "grantee_kind": "entity", "capabilities": ["read"] }))
        .await
}

async fn vault(name: &str) -> (crate::BastionVault, Arc<Core>, String) {
    let (bvault, core, root) = new_unseal_test_bastion_vault(name).await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    (bvault, core, root)
}

/// The reported exploit, on both write routes: a standard user writing a
/// secret named `data/x` is not stamped owner of the unowned legacy `x`, and
/// cannot read it afterwards.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_secret_named_data_x_does_not_capture_an_unowned_x() {
    let (_bvault, core, root) = vault("data_x_does_not_capture_x").await;
    let (bob, bob_id) = login(&core, &root, "bob", "standard-user").await;

    for api in [1u8, 2] {
        let x = format!("legacy-{api}");
        legacy_unowned(&core, &root, &x).await;

        // `secret/data/data/<x>` is the secret `data/<x>` at both API versions.
        let own = format!("secret/data/data/{x}");
        allowed(send(&core, &bob, api, Operation::Write, &own, None, data("bob's")).await, "bob writes data/x");
        assert_eq!(kv_owner(&core, &format!("secret/{x}")).await, None, "api {api}: x stays unowned");
        assert_eq!(kv_owner(&core, &format!("secret/data/{x}")).await, Some(bob_id.clone()), "api {api}");

        let read_x = send(&core, &bob, 1, Operation::Read, &format!("secret/data/{x}"), None, json!({})).await;
        denied(read_x, &format!("api {api}: bob reading x through data/"));
        let read_x = send(&core, &bob, 2, Operation::Read, &format!("secret/{x}"), None, json!({})).await;
        denied(read_x, &format!("api {api}: bob reading x through the short form"));
        let meta = send(&core, &bob, api, Operation::Read, &format!("secret/metadata/{x}"), None, json!({})).await;
        denied(meta, &format!("api {api}: bob reading x's metadata"));
        allowed(send(&core, &bob, api, Operation::Read, &own, None, json!({})).await, "bob reads his own data/x");
        assert_eq!(value(&core, &root, &x).await, Some(json!("legacy")), "x untouched");
    }
}

/// `x` and `data/x` have owners of their own: either may be created after the
/// other by someone else, and deleting one leaves the other's owner alone.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn x_and_data_x_have_independent_owners() {
    let (_bvault, core, root) = vault("x_and_data_x_independent").await;
    let (alice, alice_id) = login(&core, &root, "alice", "secret-author").await;
    let (bob, bob_id) = login(&core, &root, "bob", "secret-author").await;
    let (carol, _) = login(&core, &root, "carol", "standard-user").await;

    allowed(send(&core, &bob, 1, Operation::Write, "secret/data/data/x", None, data("bob's")).await, "bob: data/x");
    allowed(send(&core, &alice, 2, Operation::Write, "secret/x", None, data("alice's")).await, "alice: x after it");
    assert_eq!(kv_owner(&core, "secret/x").await, Some(alice_id.clone()));
    assert_eq!(kv_owner(&core, "secret/data/x").await, Some(bob_id));

    denied(send(&core, &bob, 2, Operation::Write, "secret/x", None, data("bob over x")).await, "bob writing x");
    denied(send(&core, &alice, 1, Operation::Read, "secret/data/data/x", None, json!({})).await, "alice: data/x");

    // Deleting `data/x` (every version, through metadata/) forgets its owner
    // and shares only: `x` stays alice's, so carol's first write is refused.
    allowed(send(&core, &bob, 1, Operation::Delete, "secret/metadata/data/x", None, json!({})).await, "bob deletes");
    assert_eq!(kv_owner(&core, "secret/data/x").await, None);
    assert_eq!(kv_owner(&core, "secret/x").await, Some(alice_id));
    denied(send(&core, &carol, 2, Operation::Write, "secret/x", None, data("carol's")).await, "carol over x");
    assert_eq!(value(&core, &root, "x").await, Some(json!("alice's")));
}

/// A share on one of the two secrets reaches that secret only, whichever
/// route the grantee reads through.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_share_reaches_only_the_secret_it_names() {
    let (_bvault, core, root) = vault("share_names_one_secret").await;
    let sharer = r#"path "identity/sharing/by-target/*" { capabilities = ["create", "update", "read", "list"] }"#;
    write_policy(&core, &root, "sharer", sharer).await;
    let (alice, _) = login(&core, &root, "alice", "standard-user,default,sharer").await;
    let (bob, _) = login(&core, &root, "bob", "standard-user,default,sharer").await;
    let (carol, carol_id) = login(&core, &root, "carol", "standard-user,default").await;
    let (dave, dave_id) = login(&core, &root, "dave", "standard-user,default").await;

    allowed(send(&core, &bob, 1, Operation::Write, "secret/data/data/x", None, data("bob's")).await, "bob: data/x");
    allowed(send(&core, &alice, 1, Operation::Write, "secret/data/x", None, data("alice's")).await, "alice: x");

    allowed(share_read(&core, &alice, "secret/x", &carol_id).await, "alice shares x with carol");
    allowed(share_read(&core, &bob, "secret/data/x", &dave_id).await, "bob shares data/x with dave");
    denied(share_read(&core, &bob, "secret/x", &dave_id).await, "bob sharing alice's x");

    for api in [1u8, 2] {
        let x = if api == 1 { "secret/data/x" } else { "secret/x" };
        allowed(send(&core, &carol, api, Operation::Read, x, None, json!({})).await, "carol reads x");
        denied(send(&core, &carol, api, Operation::Read, "secret/data/data/x", None, json!({})).await, "carol: data/x");
        allowed(send(&core, &dave, api, Operation::Read, "secret/data/data/x", None, json!({})).await, "dave: data/x");
        denied(send(&core, &dave, api, Operation::Read, x, None, json!({})).await, "dave reads x");
    }
}

/// Asset-group membership of one secret is not membership of the other.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn asset_group_membership_names_one_secret() {
    let (_bvault, core, root) = vault("group_names_one_secret").await;
    allowed(send(&core, &root, 1, Operation::Write, "secret/data/x", None, data("x")).await, "seed x");
    allowed(send(&core, &root, 1, Operation::Write, "secret/data/data/x", None, data("data/x")).await, "seed data/x");
    write(&core, &root, "resource-group/groups/plain", json!({ "secrets": "secret/x" })).await;
    write(&core, &root, "resource-group/groups/nested", json!({ "secrets": "secret/data/data/x" })).await;
    for group in ["plain", "nested"] {
        let hcl = format!("path \"secret/*\" {{\n  capabilities = [\"read\"]\n  groups = [\"{group}\"]\n}}\n");
        write_policy(&core, &root, &format!("in-{group}"), &hcl).await;
    }
    let (erin, _) = login(&core, &root, "erin", "in-plain").await;
    let (frank, _) = login(&core, &root, "frank", "in-nested").await;

    for api in [1u8, 2] {
        let x = if api == 1 { "secret/data/x" } else { "secret/x" };
        allowed(send(&core, &erin, api, Operation::Read, x, None, json!({})).await, "erin reads x");
        denied(send(&core, &erin, api, Operation::Read, "secret/data/data/x", None, json!({})).await, "erin: data/x");
        allowed(send(&core, &frank, api, Operation::Read, "secret/data/data/x", None, json!({})).await, "frank");
        denied(send(&core, &frank, api, Operation::Read, x, None, json!({})).await, "frank reads x");
    }
}

/// `destroy/` and `undelete/` act on the secret they name, so its owner gate
/// applies: before T499 they were keyed as a secret named `destroy/<name>`,
/// unowned, and any standard user passed the first-write carve-out.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn destroy_and_undelete_are_gated_by_the_secrets_owner() {
    let (_bvault, core, root) = vault("destroy_owner_gate").await;
    let (alice, _) = login(&core, &root, "alice", "standard-user").await;
    let (bob, _) = login(&core, &root, "bob", "standard-user").await;
    allowed(send(&core, &alice, 1, Operation::Write, "secret/data/x", None, data("alice's")).await, "alice: x");

    for api in [1u8, 2] {
        for route in ["destroy", "undelete"] {
            let path = format!("secret/{route}/x");
            let r = send(&core, &bob, api, Operation::Write, &path, None, json!({ "versions": [1] })).await;
            denied(r, &format!("api {api}: bob on {path}"));
        }
    }
    assert_eq!(kv_owner(&core, "secret/destroy/x").await, None, "no stray owner record");
    assert_eq!(value(&core, &root, "x").await, Some(json!("alice's")), "version 1 not destroyed");
    let r = send(&core, &alice, 2, Operation::Write, "secret/destroy/x", None, json!({ "versions": [1] })).await;
    allowed(r, "the owner destroys her own version");
}

/// The owner of `x` keeps full use of it on every route of both versions.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn the_owner_of_x_keeps_every_route() {
    let (_bvault, core, root) = vault("owner_keeps_routes").await;
    let (alice, alice_id) = login(&core, &root, "alice", "secret-author").await;
    allowed(send(&core, &alice, 2, Operation::Write, "secret/team/x", None, data("1")).await, "v2 create");
    assert_eq!(kv_owner(&core, "secret/team/x").await, Some(alice_id));
    allowed(send(&core, &alice, 1, Operation::Write, "secret/data/team/x", None, data("2")).await, "v1 update");
    allowed(send(&core, &alice, 1, Operation::Read, "secret/data/team/x", None, json!({})).await, "v1 read");
    allowed(send(&core, &alice, 2, Operation::Read, "secret/team/x", None, json!({})).await, "v2 read");
    allowed(send(&core, &alice, 2, Operation::Read, "secret/metadata/team/x", None, json!({})).await, "metadata");
    let list = allowed(send(&core, &alice, 1, Operation::List, "secret/metadata/team/", None, json!({})).await, "ls");
    let keys = list.and_then(|r| r.data).and_then(|d| d.get("keys").cloned());
    assert_eq!(keys, Some(json!(["x"])), "the owner lists her secret");
    allowed(send(&core, &alice, 2, Operation::Delete, "secret/metadata/team/x", None, json!({})).await, "delete");
}

/// A kv (v1) mount has no `data/` segment at all: its `data/x` is a secret
/// of its own and never keyed as `x`.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_kv_v1_secret_named_data_x_is_not_x() {
    let (_bvault, core, root) = vault("kv_v1_data_x").await;
    write(&core, &root, "sys/mounts/kv/", json!({ "type": "kv" })).await;
    let author = "path \"kv/*\" {\n  capabilities = [\"create\", \"read\", \"update\"]\n  scopes = [\"owner\"]\n}\n";
    write_policy(&core, &root, "kv-author", author).await;
    let (alice, alice_id) = login(&core, &root, "alice", "kv-author").await;
    let (bob, bob_id) = login(&core, &root, "bob", "kv-author").await;

    allowed(send(&core, &bob, 1, Operation::Write, "kv/data/x", None, json!({ "v": "bob's" })).await, "bob: data/x");
    allowed(send(&core, &alice, 1, Operation::Write, "kv/x", None, json!({ "v": "alice's" })).await, "alice: x");
    assert_eq!(kv_owner(&core, "kv/x").await, Some(alice_id));
    assert_eq!(kv_owner(&core, "kv/data/x").await, Some(bob_id));
    denied(send(&core, &bob, 1, Operation::Read, "kv/x", None, json!({})).await, "bob reads x");
    denied(send(&core, &alice, 1, Operation::Read, "kv/data/x", None, json!({})).await, "alice reads data/x");
}

/// A namespace whose second segment is `data` keeps its own keyspace: a
/// secret written in `team/data` is not keyed as `team`'s secret of that name
/// (the second canonicalization stripped the namespace's own `data` segment).
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_namespace_named_data_does_not_capture_its_parents_secret() {
    let (_bvault, core, root) = vault("ns_named_data").await;
    write(&core, &root, "sys/namespaces/team", json!({})).await;
    write(&core, &root, "sys/namespaces/team/data", json!({})).await;
    let ns = Some("team/data");
    let hcl = r#"path "team/data/secret/*" { capabilities = ["create", "read", "update"] }"#;
    allowed(send(&core, &root, 1, Operation::Write, "sys/policy/ns-writer", ns, json!({ "policy": hcl })).await, "p");
    let body = json!({ "policies": ["ns-writer"], "ttl": "1h" });
    let created = allowed(send(&core, &root, 1, Operation::Write, "auth/token/create", ns, body).await, "token");
    let token = created.unwrap().auth.unwrap().client_token;

    allowed(send(&core, &root, 1, Operation::Write, "secret/data/x", Some("team"), data("team's")).await, "seed");
    owner_store(&core).await.forget_kv_owner("team/secret/x").await.unwrap();

    allowed(send(&core, &token, 1, Operation::Write, "secret/data/x", ns, data("mine")).await, "write in team/data");
    assert_eq!(kv_owner(&core, "team/secret/x").await, None, "team's x stays unowned");
    assert!(kv_owner(&core, "team/data/secret/x").await.is_some(), "keyed in its own namespace");
}

/// Pre-T499 records keep their secrets (T499 datafix): a vault holding
/// records under the old, shared keys keeps resolving them before the datafix
/// runs, and after it every existing secret has its own record with the same
/// owner and shares. A second run does nothing.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn the_datafix_keeps_every_existing_secret_with_its_owner_and_shares() {
    use crate::modules::identity::{kv_key_split_migrate, SecretShare};

    let (_bvault, core, root) = vault("kv_key_split_datafix").await;
    write(&core, &root, "sys/mounts/kv/", json!({ "type": "kv" })).await;
    let (alice, alice_id) = login(&core, &root, "alice", "standard-user").await;
    let (bob, bob_id) = login(&core, &root, "bob", "standard-user").await;
    let (carol, carol_id) = login(&core, &root, "carol", "standard-user").await;

    // Secrets as an older release left them: `x`; `data/y` without `y`;
    // `z` and `data/z` both; a kv (v1) `data/w`.
    for path in ["secret/data/x", "secret/data/data/y", "secret/data/z", "secret/data/data/z"] {
        allowed(send(&core, &root, 1, Operation::Write, path, None, data("seed")).await, path);
    }
    allowed(send(&core, &root, 1, Operation::Write, "kv/data/w", None, json!({ "v": "seed" })).await, "kv/data/w");
    let store = owner_store(&core).await;
    for key in ["secret/x", "secret/data/y", "secret/z", "secret/data/z", "kv/data/w"] {
        store.forget_kv_owner(key).await.unwrap();
    }
    // Their records under the keys that release used (canonicalized twice).
    store.set_kv_owner("secret/x", &alice_id).await.unwrap();
    store.set_kv_owner("secret/y", &bob_id).await.unwrap();
    store.set_kv_owner("secret/z", &alice_id).await.unwrap();
    store.set_kv_owner("kv/w", &bob_id).await.unwrap();
    let identity = core.module_manager().get_module::<IdentityModule>("identity").unwrap();
    let share = SecretShare {
        target_kind: "kv-secret".into(),
        target_path: "secret/y".into(),
        grantee_kind: "entity".into(),
        grantee_entity_id: carol_id.clone(),
        granted_by_entity_id: bob_id.clone(),
        capabilities: vec!["read".into()],
        granted_at: String::new(),
        expires_at: String::new(),
    };
    identity.share_store().unwrap().set_share(share).await.unwrap();

    // Before the datafix the old keys still decide, for the old owners.
    kv_key_split_migrate::reset_for_test(core.as_ref()).await.unwrap();
    store.unsplit_kv_keys_for_test().await.unwrap();
    let reads = |token: String, path: &'static str| {
        let core = core.clone();
        async move { send(&core, &token, 1, Operation::Read, path, None, json!({})).await }
    };
    allowed(reads(bob.clone(), "secret/data/data/y").await, "legacy: bob reads data/y");
    allowed(reads(carol.clone(), "secret/data/data/y").await, "legacy: carol's share on data/y");

    let report = kv_key_split_migrate::run_if_needed(core.as_ref()).await.unwrap();
    assert!(!report.skipped && store.kv_keys_split().await.unwrap(), "{report:?}");
    let counts = (report.owners_copied, report.shares_copied, report.replaced, report.shared_pairs);
    assert_eq!(counts, (3, 1, 0, 1), "z and data/z shared a record: {report:?}");

    assert_eq!(kv_owner(&core, "secret/x").await, Some(alice_id.clone()), "x unchanged");
    assert_eq!(kv_owner(&core, "secret/data/y").await, Some(bob_id.clone()), "data/y keeps bob");
    assert_eq!(kv_owner(&core, "secret/y").await, Some(bob_id.clone()), "the old record is not removed");
    assert_eq!(kv_owner(&core, "secret/z").await, Some(alice_id.clone()));
    assert_eq!(kv_owner(&core, "secret/data/z").await, Some(alice_id.clone()), "data/z keeps alice");
    assert_eq!(kv_owner(&core, "kv/data/w").await, Some(bob_id.clone()), "kv data/w keeps bob");

    allowed(reads(bob.clone(), "secret/data/data/y").await, "split: bob reads data/y");
    allowed(reads(carol.clone(), "secret/data/data/y").await, "split: carol's share on data/y");
    allowed(reads(alice.clone(), "secret/data/z").await, "alice reads z");
    allowed(reads(alice.clone(), "secret/data/data/z").await, "alice reads data/z");
    denied(reads(carol.clone(), "secret/data/x").await, "the share on data/y is not one on x");

    let again = kv_key_split_migrate::run_if_needed(core.as_ref()).await.unwrap();
    assert!(again.skipped, "{again:?}");
}

/// A KV path with an empty segment (`secret/data//x`, `secret//x`, `kv//x`)
/// or a trailing `/` on anything but a list names a different secret than
/// its trimmed form, so it gets no key at all: refused before anything is
/// written or stamped, for every caller (review fix round 1, T499).
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn an_ambiguous_kv_path_is_refused_and_stamps_nothing() {
    let (_bvault, core, root) = vault("ambiguous_kv_path").await;
    write(&core, &root, "sys/mounts/kv/", json!({ "type": "kv" })).await;
    let author =
        "path \"kv/*\" {\n  capabilities = [\"create\", \"read\", \"update\", \"list\"]\n  scopes = [\"owner\"]\n}\n";
    write_policy(&core, &root, "kv-author", author).await;
    let (bob, _) = login(&core, &root, "bob", "standard-user,kv-author").await;
    legacy_unowned(&core, &root, "x").await;
    allowed(send(&core, &root, 1, Operation::Write, "kv/x", None, json!({ "v": "legacy" })).await, "seed kv/x");
    owner_store(&core).await.forget_kv_owner("kv/x").await.unwrap();

    let cases: [(u8, &str); 12] = [
        (1, "secret/data//x"),
        (2, "secret/data//x"),
        (2, "secret//x"),
        (1, "secret/data/x/"),
        (2, "secret/x/"),
        (1, "secret/data/x//"),
        (1, "/secret/data//x"),
        (1, "kv//x"),
        (1, "kv/x/"),
        (1, "/kv//x"),
        (1, "secret/data/x "),
        (2, "secret/ x"),
    ];
    for (api, path) in cases {
        let body = if path.contains("kv/") { json!({ "v": "bob's" }) } else { data("bob's") };
        let r = send(&core, &bob, api, Operation::Write, path, None, body).await;
        assert_eq!(status(&r), 400, "api {api} {path}: {r:?}");
    }
    assert_eq!(kv_owner(&core, "secret/x").await, None, "x stays unowned");
    assert_eq!(kv_owner(&core, "kv/x").await, None, "kv/x stays unowned");
    assert_eq!(value(&core, &root, "x").await, Some(json!("legacy")));
    let listed = |path: &'static str| {
        let (core, root) = (core.clone(), root.clone());
        async move {
            let r = send(&core, &root, 1, Operation::List, path, None, json!({})).await.unwrap();
            r.and_then(|r| r.data).and_then(|d| d.get("keys").cloned()).unwrap_or_default()
        }
    };
    assert_eq!(listed("secret/metadata/").await, json!(["x"]), "no `/x` or `x/` secret was written");
    assert_eq!(listed("kv/").await, json!(["x"]), "no kv `/x` or `x/` secret was written");

    // A list keeps its one trailing `/`.
    allowed(send(&core, &bob, 1, Operation::List, "secret/metadata/", None, json!({})).await, "bob lists");
    allowed(send(&core, &bob, 1, Operation::List, "kv/", None, json!({})).await, "bob lists kv");
}

/// The same refusal inside a namespace, where the key carries the namespace.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn an_ambiguous_kv_path_is_refused_in_a_namespace() {
    let (_bvault, core, root) = vault("ambiguous_kv_path_ns").await;
    write(&core, &root, "sys/namespaces/team", json!({})).await;
    let ns = Some("team");
    let hcl = r#"path "team/secret/*" { capabilities = ["create", "read", "update", "list"] }"#;
    allowed(send(&core, &root, 1, Operation::Write, "sys/policy/ns-writer", ns, json!({ "policy": hcl })).await, "p");
    let body = json!({ "policies": ["ns-writer"], "ttl": "1h" });
    let created = allowed(send(&core, &root, 1, Operation::Write, "auth/token/create", ns, body).await, "token");
    let token = created.unwrap().auth.unwrap().client_token;
    for (api, path) in [(1u8, "secret/data//x"), (2, "secret//x"), (1, "secret/data/x/")] {
        let r = send(&core, &token, api, Operation::Write, path, ns, data("mine")).await;
        assert_eq!(status(&r), 400, "api {api} {path} in team: {r:?}");
    }
    assert_eq!(kv_owner(&core, "team/secret/x").await, None, "nothing stamped on team's x");
    allowed(send(&core, &token, 1, Operation::Write, "secret/data/x", ns, data("mine")).await, "the real path");
    assert!(kv_owner(&core, "team/secret/x").await.is_some());
}

/// Plant the pre-T499 state of `name` (an existing secret on `secret/`): its
/// new-key record removed, `old` holding `owner`.
async fn plant_old_owner(core: &Arc<Core>, root: &str, name: &str, old: &str, owner: &str) {
    let path = format!("secret/data/{name}");
    allowed(send(core, root, 1, Operation::Write, &path, None, data("seed")).await, "seed");
    let store = owner_store(core).await;
    store.forget_kv_owner(&format!("secret/{name}")).await.unwrap();
    store.set_kv_owner(old, owner).await.unwrap();
}

/// For an existing secret the old key's record wins over whatever sits at its
/// new key: a record there was never written by this release's derivation
/// while the switch was off, so it is stale (review fix round 1).
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn the_datafix_gives_an_existing_secret_its_old_keys_record() {
    use crate::modules::identity::kv_key_split_migrate;
    let (_bvault, core, root) = vault("datafix_old_record_wins").await;
    plant_old_owner(&core, &root, "data/y", "secret/y", "ent-bob").await;
    owner_store(&core).await.set_kv_owner("secret/data/y", "ent-eve").await.unwrap();
    kv_key_split_migrate::reset_for_test(core.as_ref()).await.unwrap();
    owner_store(&core).await.unsplit_kv_keys_for_test().await.unwrap();
    let report = kv_key_split_migrate::run_if_needed(core.as_ref()).await.unwrap();
    assert_eq!(report.replaced, 1, "{report:?}");
    assert_eq!(kv_owner(&core, "secret/data/y").await.as_deref(), Some("ent-bob"), "the old key's owner");
    assert_eq!(kv_owner(&core, "secret/y").await.as_deref(), Some("ent-bob"));
}

/// A chain: `data/x` and `data/data/x` both exist; each takes the record its
/// own old key held, though `data/x`'s new key is `data/data/x`'s old key.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn the_datafix_follows_a_chain_of_nested_names() {
    use crate::modules::identity::kv_key_split_migrate;
    let (_bvault, core, root) = vault("datafix_chain").await;
    plant_old_owner(&core, &root, "data/x", "secret/x", "ent-alice").await;
    plant_old_owner(&core, &root, "data/data/x", "secret/data/x", "ent-carol").await;
    kv_key_split_migrate::reset_for_test(core.as_ref()).await.unwrap();
    owner_store(&core).await.unsplit_kv_keys_for_test().await.unwrap();
    kv_key_split_migrate::run_if_needed(core.as_ref()).await.unwrap();
    assert_eq!(kv_owner(&core, "secret/data/x").await.as_deref(), Some("ent-alice"), "data/x");
    assert_eq!(kv_owner(&core, "secret/data/data/x").await.as_deref(), Some("ent-carol"), "data/data/x");
}

/// A namespace named `team/data`: its secrets' old keys dropped the
/// namespace's own `data` segment; the datafix copies them to the full key.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn the_datafix_splits_a_namespace_named_data() {
    use crate::modules::identity::kv_key_split_migrate;
    let (_bvault, core, root) = vault("datafix_ns_named_data").await;
    write(&core, &root, "sys/namespaces/team", json!({})).await;
    write(&core, &root, "sys/namespaces/team/data", json!({})).await;
    let seed = send(&core, &root, 1, Operation::Write, "secret/data/x", Some("team/data"), data("seed")).await;
    allowed(seed, "seed x in team/data");
    let store = owner_store(&core).await;
    store.forget_kv_owner("team/data/secret/x").await.unwrap();
    store.set_kv_owner("team/secret/x", "ent-bob").await.unwrap();
    kv_key_split_migrate::reset_for_test(core.as_ref()).await.unwrap();
    store.unsplit_kv_keys_for_test().await.unwrap();
    kv_key_split_migrate::run_if_needed(core.as_ref()).await.unwrap();
    assert_eq!(kv_owner(&core, "team/data/secret/x").await.as_deref(), Some("ent-bob"));
}

/// A mount table that cannot be read fails the pass: no marker, the switch
/// stays off and the old keys keep deciding, so nothing is skipped silently.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_datafix_that_cannot_read_a_mount_table_sets_no_marker() {
    use crate::{kernel_api::VaultCtx, modules::identity::kv_key_split_migrate, storage::StorageEntry};
    let (_bvault, core, root) = vault("datafix_unreadable_table").await;
    let created =
        allowed(send(&core, &root, 1, Operation::Write, "sys/namespaces/broken", None, json!({})).await, "ns");
    let uuid = created.unwrap().data.unwrap()["uuid"].as_str().unwrap().to_string();
    let (bob, bob_id) = login(&core, &root, "bob", "standard-user").await;
    plant_old_owner(&core, &root, "data/y", "secret/y", &bob_id).await;
    let table = crate::modules::namespace::router::namespace_mount_config_path(&uuid);
    let garbage = StorageEntry { key: table, value: b"not a mount table".to_vec() };
    core.barrier().as_storage().put(&garbage).await.unwrap();

    kv_key_split_migrate::reset_for_test(core.as_ref()).await.unwrap();
    let store = owner_store(&core).await;
    store.unsplit_kv_keys_for_test().await.unwrap();
    assert!(kv_key_split_migrate::run_if_needed(core.as_ref()).await.is_err(), "the pass must fail");
    assert!(!store.kv_keys_split().await.unwrap(), "the switch stays off");
    assert_eq!(kv_owner(&core, "secret/data/y").await, None, "nothing half-copied");
    let r = send(&core, &bob, 1, Operation::Read, "secret/data/data/y", None, json!({})).await;
    allowed(r, "the old key still decides");
}

/// The ambiguous-name 400 comes only after the ACL allowed the request and
/// the token's namespace binding held, so a caller without a grant gets the
/// same 403 whether the mount exists and whatever engine it runs (review fix
/// round 2: no mount-name or engine-type oracle).
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn an_ambiguous_path_answers_a_caller_without_a_grant_like_any_path() {
    let (_bvault, core, root) = vault("ambiguous_path_no_oracle").await;
    write(&core, &root, "sys/mounts/kv/", json!({ "type": "kv" })).await;
    write(&core, &root, "sys/namespaces/tenant-a", json!({})).await;
    write(&core, &root, "sys/namespaces/tenant-b", json!({})).await;
    let ns_b = Some("tenant-b");
    let hcl = r#"path "tenant-b/secret/*" { capabilities = ["create", "read", "update"] }"#;
    allowed(send(&core, &root, 1, Operation::Write, "sys/policy/b-writer", ns_b, json!({ "policy": hcl })).await, "p");
    let body = json!({ "policies": ["b-writer"], "ttl": "1h" });
    let created = allowed(send(&core, &root, 1, Operation::Write, "auth/token/create", ns_b, body).await, "token");
    let bound_elsewhere = created.unwrap().auth.unwrap().client_token;
    let (no_grant, _) = login(&core, &root, "nogrant", "default").await;

    let write_as = |token: String, path: &'static str| {
        let core = core.clone();
        async move { status(&send(&core, &token, 1, Operation::Write, path, None, data("w")).await) }
    };
    for (who, token) in [("bound to tenant-b", bound_elsewhere.clone()), ("no grant", no_grant.clone())] {
        let existing = write_as(token.clone(), "tenant-a/secret/data/a//b").await;
        let missing = write_as(token.clone(), "tenant-x/secret/data/a//b").await;
        assert_eq!((existing, missing), (403, 403), "{who}: an existing and a missing mount");
        let kv_v1 = write_as(token.clone(), "kv/config/").await;
        let kv_v2 = write_as(token.clone(), "secret/config/").await;
        assert_eq!((kv_v1, kv_v2), (403, 403), "{who}: a kv and a kv-v2 mount");
    }
    let kv_open = r#"path "kv/*" { capabilities = ["create", "read", "update"] }"#;
    write_policy(&core, &root, "kv-open", kv_open).await;
    let (writer, _) = login(&core, &root, "writer", "kv-open").await;
    assert_eq!(write_as(writer, "kv//x").await, 400, "an allowed caller learns the path is malformed");
    assert_eq!(write_as(root.clone(), "tenant-a/secret/data/a//b").await, 400, "root too");
    assert_eq!(write_as(root.clone(), "kv/config/").await, 400, "root too");
}

/// A pass cut short after saving its plan resumes from that plan, not from a
/// fresh read of keys it may already have rewritten (review fix round 2).
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn the_datafix_resumes_from_its_saved_plan() {
    use crate::modules::identity::kv_key_split_migrate;
    let (_bvault, core, root) = vault("datafix_resume").await;
    plant_old_owner(&core, &root, "data/y", "secret/y", "ent-bob").await;
    kv_key_split_migrate::reset_for_test(core.as_ref()).await.unwrap();
    kv_key_split_migrate::plan_only_for_test(core.as_ref()).await.unwrap();
    // A fresh plan would now copy this record; the saved one copies bob's.
    owner_store(&core).await.set_kv_owner("secret/y", "ent-mallory").await.unwrap();
    let report = kv_key_split_migrate::run_if_needed(core.as_ref()).await.unwrap();
    assert_eq!(report.owners_copied, 1, "{report:?}");
    assert_eq!(kv_owner(&core, "secret/data/y").await.as_deref(), Some("ent-bob"), "the saved plan was applied");
    assert!(kv_key_split_migrate::run_if_needed(core.as_ref()).await.unwrap().skipped, "done, plan gone");
}

/// A garbled T499 marker refuses KV requests with an internal error, for
/// root too, instead of falling back to the pre-T499 keys; requests that name
/// no KV secret are unaffected, except the share endpoints, which read the
/// marker for every share kind; the datafix reports it (review fix round 2).
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn an_unreadable_key_switch_refuses_kv_requests_only() {
    use crate::modules::identity::kv_key_split_migrate;
    let (_bvault, core, root) = vault("garbled_key_switch").await;
    let (bob, _) = login(&core, &root, "bob", "standard-user").await;
    allowed(send(&core, &bob, 1, Operation::Write, "secret/data/mine", None, data("v")).await, "before");
    owner_store(&core).await.garble_kv_key_split_marker_for_test().await.unwrap();

    let r = send(&core, &bob, 1, Operation::Write, "secret/data/mine", None, data("v2")).await;
    assert_eq!(status(&r), 500, "a KV write: {r:?}");
    let r = send(&core, &bob, 2, Operation::Read, "secret/mine", None, json!({})).await;
    assert_eq!(status(&r), 500, "a KV read: {r:?}");
    let r = send(&core, &root, 1, Operation::Read, "secret/data/mine", None, json!({})).await;
    assert_eq!(status(&r), 500, "root's KV read: {r:?}");
    let owner_path = format!("identity/owner/kv/{}", URL_SAFE_NO_PAD.encode("secret/mine"));
    let r = send(&core, &root, 1, Operation::Read, &owner_path, None, json!({})).await;
    assert!(status(&r) >= 500, "the owner endpoint: {r:?}");

    let r = send(&core, &bob, 1, Operation::Read, "auth/token/lookup-self", None, json!({})).await;
    assert_eq!(status(&r), 200, "a non-KV request: {r:?}");
    let r = send(&core, &root, 1, Operation::Write, "sys/policy/unrelated", None, json!({ "policy": "" })).await;
    assert!(status(&r) < 500, "a sys/ write: {r:?}");
    let shares = format!("identity/sharing/by-target/resource/{}", URL_SAFE_NO_PAD.encode("srv1"));
    let r = send(&core, &root, 1, Operation::List, &shares, None, json!({})).await;
    assert!(status(&r) >= 500, "the share endpoints read it for every kind: {r:?}");
    assert!(
        kv_key_split_migrate::run_if_needed(core.as_ref()).await.is_err(),
        "the datafix reports it, unseal logs it"
    );
}

/// The recovery the docs give for a garbled T499 marker: rewrite it as `1`
/// (here through `sys/raw`, a root path), never delete it. KV requests then
/// work again without a restart, and the datafix stays done.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_rewritten_key_switch_marker_recovers_kv_requests() {
    use crate::modules::identity::kv_key_split_migrate;
    let (_bvault, core, root) = vault("rewritten_key_switch").await;
    let (bob, _) = login(&core, &root, "bob", "standard-user").await;
    allowed(send(&core, &bob, 1, Operation::Write, "secret/data/mine", None, data("v")).await, "before");
    owner_store(&core).await.garble_kv_key_split_marker_for_test().await.unwrap();
    let r = send(&core, &bob, 1, Operation::Read, "secret/data/mine", None, json!({})).await;
    assert_eq!(status(&r), 500, "garbled: {r:?}");

    // The barrier key sits under the root tenant's storage prefix.
    let marker = format!("sys/raw/{}sys/owner/meta/kv-key-split-version", core.root_storage_prefix.load());
    allowed(send(&core, &root, 1, Operation::Write, &marker, None, json!({ "value": "1" })).await, "rewrite");
    let r = allowed(send(&core, &bob, 1, Operation::Read, "secret/data/mine", None, json!({})).await, "after");
    assert_eq!(r.and_then(|r| r.data).map(|d| d["data"]["v"].clone()), Some(json!("v")), "bob reads his secret");
    assert!(kv_key_split_migrate::run_if_needed(core.as_ref()).await.unwrap().skipped, "the datafix stays done");
}

/// The ambiguous-name 400 also waits for the token's namespace binding: a
/// root-bound token whose policy names a tenant's paths, but that may not
/// operate in the tenant, gets there the 403 a missing mount gives it, not
/// the 400 root gets (batch-1a review: the binding branch).
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn an_ambiguous_path_where_the_token_may_not_operate_is_a_403() {
    let (_bvault, core, root) = vault("ambiguous_path_binding").await;
    write(&core, &root, "sys/namespaces/tenant-a", json!({})).await;
    let hcl = r#"path "tenant-a/*" { capabilities = ["create", "read", "update", "list"] }"#;
    write_policy(&core, &root, "tenant-a-all", hcl).await;
    let (rooted, _) = login(&core, &root, "rooted", "tenant-a-all").await;

    let existing = send(&core, &rooted, 1, Operation::Write, "tenant-a/secret/data/a//b", None, data("w")).await;
    let missing = send(&core, &rooted, 1, Operation::Write, "tenant-a/nomount/data/a//b", None, data("w")).await;
    assert_eq!(status(&existing), 403, "{existing:?}");
    assert_eq!(format!("{existing:?}"), format!("{missing:?}"), "an existing KV mount and a missing mount");
    let r = send(&core, &root, 1, Operation::Write, "tenant-a/secret/data/a//b", None, data("w")).await;
    assert_eq!(status(&r), 400, "root may operate there: {r:?}");
}
