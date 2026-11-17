//! A KV path that names no secret has no owner, shares or groups (T506).
//!
//! A kv-v2 mount's `config` is not a secret: it had no owner record, so the
//! owner scope's first-write carve-out let any standard user rewrite it, and it
//! was keyed like the secret named `config`, whose owner, shares and asset
//! groups then reached the mount's settings. Real tokens, both API versions.

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};

use super::{
    kernel_policy_deny::{write, write_policy},
    kv_secret_keys::{kv_owner, login, owner_store, send, status},
};
use crate::{core::Core, logical::Operation, test_utils::new_unseal_test_bastion_vault};

const PASSWORD: &str = "hunter22XX!";

async fn vault(name: &str) -> (crate::BastionVault, Arc<Core>, String) {
    let (bvault, core, root) = new_unseal_test_bastion_vault(name).await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    (bvault, core, root)
}

fn data(v: &str) -> Value {
    json!({ "data": { "v": v } })
}

/// `max_versions` of the `secret/` mount in `ns`, as root reads it.
async fn max_versions(core: &Arc<Core>, root: &str, ns: Option<&str>) -> Option<Value> {
    let resp = send(core, root, 1, Operation::Read, "secret/config", ns, json!({})).await.ok()??;
    resp.data.and_then(|d| d.get("max_versions").cloned())
}

/// The status of `token` writing `max_versions` through `secret/config`.
async fn write_config(core: &Arc<Core>, token: &str, api: u8, ns: Option<&str>, max: u64) -> u16 {
    status(&send(core, token, api, Operation::Write, "secret/config", ns, json!({ "max_versions": max })).await)
}

/// The reported exploit: a standard user rewrote `max_versions` of `secret/`
/// and was stamped owner of `secret/config`. Now a 403 that stamps nothing,
/// while the user's first write of a real secret still works.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_standard_user_cannot_rewrite_a_kv_v2_mounts_config() {
    let (_bvault, core, root) = vault("no_secret_config_standard_user").await;
    let (bob, bob_id) = login(&core, &root, "bob", "standard-user").await;

    for api in [1u8, 2] {
        assert_eq!(write_config(&core, &bob, api, None, 1).await, 403, "api {api}: bob writes secret/config");
        let read = send(&core, &bob, api, Operation::Read, "secret/config", None, json!({})).await;
        assert_eq!(status(&read), 403, "api {api}: bob reads secret/config");
    }
    assert_eq!(max_versions(&core, &root, None).await, Some(json!(0)), "the mount's setting is unchanged");
    assert_eq!(kv_owner(&core, "secret/config").await, None, "nothing stamped");

    let first = send(&core, &bob, 1, Operation::Write, "secret/data/x", None, data("bob's")).await;
    assert_eq!(status(&first), 200, "a real first write still passes the carve-out: {first:?}");
    assert_eq!(kv_owner(&core, "secret/x").await, Some(bob_id));
}

/// The secret named `config` shares the mount config's old key. Its owner, a
/// grantee of its share and a member of its asset group reach the secret, and
/// none of them reaches the mount's settings.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn the_secret_named_config_does_not_reach_the_mount_config() {
    let (_bvault, core, root) = vault("no_secret_config_namesake").await;
    let sharer = r#"path "identity/sharing/by-target/*" { capabilities = ["create", "update", "read", "list"] }"#;
    write_policy(&core, &root, "sharer", sharer).await;
    let in_g = "path \"secret/*\" {\n  capabilities = [\"read\", \"update\"]\n  groups = [\"g\"]\n}\n";
    write_policy(&core, &root, "in-g", in_g).await;
    let (bob, bob_id) = login(&core, &root, "bob", "standard-user,default,sharer").await;
    let (carol, carol_id) = login(&core, &root, "carol", "standard-user,default").await;
    let (dave, _) = login(&core, &root, "dave", "in-g").await;

    let own = send(&core, &bob, 1, Operation::Write, "secret/data/config", None, data("bob's")).await;
    assert_eq!(status(&own), 200, "bob creates the secret named config: {own:?}");
    assert_eq!(kv_owner(&core, "secret/config").await, Some(bob_id), "keyed <mount><name>");
    let share = format!("identity/sharing/by-target/kv-secret/{}/{carol_id}", URL_SAFE_NO_PAD.encode("secret/config"));
    let body = json!({ "grantee_kind": "entity", "capabilities": ["read", "update"] });
    assert_eq!(status(&send(&core, &bob, 1, Operation::Write, &share, None, body).await), 200, "bob shares it");
    write(&core, &root, "resource-group/groups/g", json!({ "secrets": "secret/config" })).await;

    for (who, token) in [("owner", &bob), ("grantee", &carol), ("group member", &dave)] {
        let secret = send(&core, token, 1, Operation::Read, "secret/data/config", None, json!({})).await;
        assert_eq!(status(&secret), 200, "{who} reads the secret named config: {secret:?}");
        for api in [1u8, 2] {
            assert_eq!(write_config(&core, token, api, None, 1).await, 403, "{who}: api {api} write");
            let read = send(&core, token, api, Operation::Read, "secret/config", None, json!({})).await;
            assert_eq!(status(&read), 403, "{who}: api {api} read of the mount config");
        }
    }
    assert_eq!(max_versions(&core, &root, None).await, Some(json!(0)), "the mount's setting is unchanged");
}

/// Every kv-v2 path that names no secret refuses the owner scope, at both API
/// versions; a secret named `delete/x` is a secret, and the root list still
/// answers a standard user (LIST waives the scope gate and filters).
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn every_kv_v2_path_that_names_no_secret_refuses_the_owner_scope() {
    let (_bvault, core, root) = vault("no_secret_paths").await;
    let (bob, bob_id) = login(&core, &root, "bob", "standard-user").await;
    let no_secret = [
        (1u8, "secret/config"),
        (2, "secret/config"),
        (1, "secret/configs/x"),
        (2, "secret/configs/x"),
        (1, "secret/data/"),
        (2, "secret/data/"),
        (1, "secret/metadata/"),
        (2, "secret/metadata"),
        (1, "secret/destroy/"),
        (2, "secret/undelete/"),
        (1, "secret/"),
    ];
    for (api, path) in no_secret {
        let r =
            send(&core, &bob, api, Operation::Write, path, None, json!({ "max_versions": 1, "versions": [1] })).await;
        assert_eq!(status(&r), 403, "api {api} Write {path}: {r:?}");
    }
    for key in ["secret", "secret/config", "secret/configs/x", "secret/destroy", "secret/undelete"] {
        assert_eq!(kv_owner(&core, key).await, None, "nothing stamped under {key}");
    }

    let named_delete = send(&core, &bob, 2, Operation::Write, "secret/delete/x", None, data("bob's")).await;
    assert_eq!(status(&named_delete), 200, "api 2 secret/delete/x is the secret delete/x: {named_delete:?}");
    assert_eq!(kv_owner(&core, "secret/delete/x").await, Some(bob_id));
    let list = send(&core, &bob, 1, Operation::List, "secret/metadata/", None, json!({})).await;
    assert_eq!(status(&list), 200, "bob still lists the mount root: {list:?}");
}

/// A kv (v1) mount has no `config` route: `kv/config` is a secret like any
/// other, and its first writer owns it, as before.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_kv_v1_secret_named_config_is_owned_as_before() {
    let (_bvault, core, root) = vault("no_secret_kv_v1").await;
    write(&core, &root, "sys/mounts/kv/", json!({ "type": "kv" })).await;
    let author = "path \"kv/*\" {\n  capabilities = [\"create\", \"read\", \"update\"]\n  scopes = [\"owner\"]\n}\n";
    write_policy(&core, &root, "kv-author", author).await;
    let (alice, alice_id) = login(&core, &root, "alice", "kv-author").await;
    let (bob, _) = login(&core, &root, "bob", "kv-author").await;

    let first = send(&core, &alice, 1, Operation::Write, "kv/config", None, json!({ "v": "alice's" })).await;
    assert_eq!(status(&first), 200, "alice's first write of kv/config: {first:?}");
    assert_eq!(kv_owner(&core, "kv/config").await, Some(alice_id));
    assert_eq!(status(&send(&core, &alice, 1, Operation::Read, "kv/config", None, json!({})).await), 200);
    assert_eq!(status(&send(&core, &bob, 1, Operation::Read, "kv/config", None, json!({})).await), 403);
}

/// A policy without the owner scope still writes the mount's settings, and
/// the write stamps no owner: the key belongs to the secret named `config`,
/// whose first writer still becomes its owner.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn an_admin_still_writes_a_kv_v2_mounts_config_and_owns_nothing() {
    let (_bvault, core, root) = vault("no_secret_config_admin").await;
    let admin = r#"path "secret/*" { capabilities = ["create", "read", "update", "delete", "list"] }"#;
    write_policy(&core, &root, "kv-admin", admin).await;
    let (ada, _) = login(&core, &root, "ada", "kv-admin").await;
    let (bob, bob_id) = login(&core, &root, "bob", "standard-user").await;

    for (api, max) in [(1u8, 3u64), (2, 4)] {
        assert_eq!(write_config(&core, &ada, api, None, max).await, 200, "api {api}: admin writes the config");
        assert_eq!(max_versions(&core, &root, None).await, Some(json!(max)));
    }
    assert_eq!(write_config(&core, &root, 1, None, 5).await, 200, "root writes the config");
    assert_eq!(max_versions(&core, &root, None).await, Some(json!(5)));
    assert_eq!(kv_owner(&core, "secret/config").await, None, "no owner stamped for the mount's settings");

    let own = send(&core, &bob, 1, Operation::Write, "secret/data/config", None, data("bob's")).await;
    assert_eq!(status(&own), 200, "bob creates the secret named config: {own:?}");
    assert_eq!(kv_owner(&core, "secret/config").await, Some(bob_id));
}

/// The same refusal on a namespace's own `secret/` mount, for a user born in
/// the namespace whose owner-scoped policy is authored there.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_namespaced_kv_v2_mounts_config_refuses_the_owner_scope() {
    let (_bvault, core, root) = vault("no_secret_config_ns").await;
    write(&core, &root, "sys/namespaces/team", json!({})).await;
    let ns = Some("team");
    let as_root = |path: &'static str, body: Value| {
        let (core, root) = (core.clone(), root.clone());
        async move { status(&send(&core, &root, 1, Operation::Write, path, ns, body).await) }
    };
    assert_eq!(as_root("sys/auth/teampass", json!({ "type": "userpass" })).await, 200, "userpass in team");
    let hcl =
        "path \"team/secret/*\" {\n  capabilities = [\"create\", \"read\", \"update\"]\n  scopes = [\"owner\"]\n}\n";
    assert_eq!(as_root("sys/policy/team-author", json!({ "policy": hcl })).await, 200, "policy in team");
    let user = json!({ "password": PASSWORD, "token_policies": "team-author", "ttl": 0 });
    assert_eq!(as_root("auth/teampass/users/eve", user).await, 200, "eve in team");
    let login = send(&core, "", 1, Operation::Write, "auth/teampass/login/eve", ns, json!({ "password": PASSWORD }));
    let auth = login.await.unwrap().unwrap().auth.unwrap();
    let eve_id = auth.metadata.get("entity_id").cloned().unwrap_or_default();
    assert!(!eve_id.is_empty(), "a userpass login in team carries an entity id");
    let eve = auth.client_token;

    for api in [1u8, 2] {
        assert_eq!(write_config(&core, &eve, api, ns, 1).await, 403, "api {api}: eve writes team's secret/config");
    }
    assert_eq!(max_versions(&core, &root, ns).await, Some(json!(0)), "team's mount setting is unchanged");
    assert_eq!(kv_owner(&core, "team/secret/config").await, None, "nothing stamped");

    let first = send(&core, &eve, 1, Operation::Write, "secret/data/x", ns, data("eve's")).await;
    assert_eq!(status(&first), 200, "a real first write in team still passes: {first:?}");
    assert_eq!(kv_owner(&core, "team/secret/x").await, Some(eve_id));
    assert_eq!(write_config(&core, &root, 1, ns, 2).await, 200, "root writes team's config");
    assert_eq!(max_versions(&core, &root, ns).await, Some(json!(2)));
}

/// The change is confined to KV mounts: an owner-scoped first write on a
/// resource, and on a path of another engine, is admitted and stamped as before.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn owner_scoped_first_writes_on_other_engines_are_unchanged() {
    let (_bvault, core, root) = vault("no_secret_other_engines").await;
    write(&core, &root, "sys/mounts/transit/", json!({ "type": "transit" })).await;
    let author = "path \"transit/*\" {\n  capabilities = [\"create\", \"update\"]\n  scopes = [\"owner\"]\n}\n";
    write_policy(&core, &root, "transit-author", author).await;
    let (bob, bob_id) = login(&core, &root, "bob", "standard-user,transit-author").await;

    let meta = json!({ "type": "server", "hostname": "bob.example" });
    let srv = send(&core, &bob, 1, Operation::Write, "resources/resources/bob-srv", None, meta).await;
    assert_eq!(status(&srv), 200, "a resource's first write: {srv:?}");
    let owner = owner_store(&core).await.get_resource_owner("bob-srv").await.unwrap().map(|r| r.entity_id);
    assert_eq!(owner, Some(bob_id.clone()));

    let key = send(&core, &bob, 1, Operation::Write, "transit/keys/bob-key", None, json!({})).await;
    assert_eq!(status(&key), 200, "a transit key's first write: {key:?}");
    assert_eq!(kv_owner(&core, "transit/keys/bob-key").await, Some(bob_id), "stamped as before");
}
