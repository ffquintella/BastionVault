//! Shares, asset-group membership and attached files carried by
//! `sys/namespace-transfer/{copy|move}` (T494, Task 4b), through the real
//! router with real tokens. Fixtures that the grant API would re-point (a
//! share naming another namespace's entity) are planted in the share store.

use std::{collections::HashMap, sync::Arc};

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde_json::{json, Value};

use super::{
    body, codes, get, resource, resource_exists, resource_owner, result, seed_resource, send, transfer, user, vault,
    write_policy, MOVER, PASSWORD,
};
use crate::{
    core::Core,
    errors::RvError,
    logical::{Operation, Request, Response},
    modules::identity::{EntityStore, SecretShare, ShareStore, ShareTargetKind},
};

/// MOVER plus every right the relations need: list and grant shares, read
/// and modify asset groups, read files, in both namespaces.
const CARRIER: &str = r#"
path "identity/sharing/by-target/*" { capabilities = ["create", "read", "update", "list"] }
path "src/resource-group/*" { capabilities = ["read", "update", "list"] }
path "dst/resource-group/*" { capabilities = ["read", "update", "list"] }
path "src/files/*" { capabilities = ["read", "list"] }
"#;

async fn grant(
    core: &Arc<Core>,
    token: &str,
    ns: Option<&str>,
    (kind, target): (&str, &str),
    (grantee_kind, grantee): (&str, &str),
    caps: Value,
) -> Result<Option<Response>, RvError> {
    let path = format!("identity/sharing/by-target/{kind}/{}/{grantee}", URL_SAFE_NO_PAD.encode(target));
    send(core, token, Operation::Write, &path, ns, json!({ "grantee_kind": grantee_kind, "capabilities": caps })).await
}

async fn shares_on(core: &Arc<Core>, kind: ShareTargetKind, key: &str) -> Vec<SecretShare> {
    ShareStore::new(core.as_ref()).await.unwrap().list_shares_for_target(kind, key).await.unwrap()
}

fn grantees(shares: &[SecretShare]) -> Vec<String> {
    let mut all: Vec<String> = shares.iter().map(|s| s.grantee_entity_id.clone()).collect();
    all.sort();
    all
}

/// A share written straight into the store: the state a share granted before
/// grantee re-pointing existed, which the grant API can no longer produce.
async fn plant(core: &Arc<Core>, target: &str, entity: &str, caps: &[&str]) {
    let share = SecretShare {
        target_kind: "resource".into(),
        target_path: target.into(),
        grantee_kind: "entity".into(),
        grantee_entity_id: entity.into(),
        capabilities: caps.iter().map(|c| c.to_string()).collect(),
        ..Default::default()
    };
    ShareStore::new(core.as_ref()).await.unwrap().set_share(share).await.unwrap();
}

async fn entity(core: &Arc<Core>, name: &str, ns: &str) -> String {
    EntityStore::new(core.as_ref()).await.unwrap().get_or_create_entity_ns("userpass/", name, ns).await.unwrap().id
}

/// Log the userpass user `name` in to namespace `ns`: `(token, entity_id)`.
async fn login_in(core: &Arc<Core>, name: &str, ns: &str) -> (String, String) {
    let mut req = Request::new(format!("auth/userpass/login/{name}"));
    req.operation = Operation::Write;
    req.body = json!({ "password": PASSWORD }).as_object().cloned();
    req.headers = Some(HashMap::from([("x-bastionvault-namespace".to_string(), ns.to_string())]));
    let auth = core.handle_request(&mut req).await.unwrap().unwrap().auth.unwrap();
    (auth.client_token, auth.metadata.get("entity_id").cloned().unwrap_or_default())
}

async fn user_group(core: &Arc<Core>, root: &str, ns: Option<&str>, name: &str) {
    send(core, root, Operation::Write, &format!("identity/group/user/{name}"), ns, json!({})).await.unwrap();
}

/// Asset group `name` in `ns` with resource `members` and KV `secrets`.
async fn asset_group(core: &Arc<Core>, root: &str, ns: Option<&str>, name: &str, members: &[&str], secrets: &[&str]) {
    let group = json!({ "members": members, "secrets": secrets });
    send(core, root, Operation::Write, &format!("resource-group/groups/{name}"), ns, group).await.unwrap();
}

/// The `field` list (`members`, `secrets`) of asset group `name` as `ns`
/// reads it; `None` when no group of that name resolves there.
async fn group_list(core: &Arc<Core>, root: &str, ns: Option<&str>, name: &str, field: &str) -> Option<Vec<String>> {
    let path = format!("resource-group/groups/{name}");
    let data = send(core, root, Operation::Read, &path, ns, json!({})).await.ok()?.and_then(|r| r.data)?;
    let list = data.get(field).and_then(Value::as_array).cloned().unwrap_or_default();
    Some(list.iter().filter_map(Value::as_str).map(String::from).collect())
}

fn warning<'a>(out: &'a Value, code: &str, subject: &str) -> Option<&'a Value> {
    out["warnings"].as_array().unwrap().iter().find(|w| w["code"] == json!(code) && w["subject"] == json!(subject))
}

/// A transfer of root's `srv1` to `dst`.
fn from_root(extra: Value) -> Value {
    body("resource", "resources", ("", "srv1"), ("dst", "srv1"), extra)
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn copy_keeps_valid_shares_and_drops_invalid_with_warnings() {
    let (_bvault, core, root) = vault("ns_transfer_shares_keep_drop").await;
    seed_resource(&core, &root, None, "srv1").await;
    let (_, carol_root) = user(&core, &root, "carol", "default", true).await;
    user_group(&core, &root, None, "ops").await;
    user_group(&core, &root, Some("dst"), "ops").await;
    user_group(&core, &root, None, "qa").await;
    grant(&core, &root, None, ("resource", "srv1"), ("entity", &carol_root), json!(["read"])).await.unwrap();
    grant(&core, &root, None, ("resource", "srv1"), ("group_user", "ops"), json!(["read", "update"])).await.unwrap();
    grant(&core, &root, None, ("resource", "srv1"), ("group_user", "qa"), json!(["read"])).await.unwrap();
    let erin_src = entity(&core, "erin", "src").await;
    let dana_dst = entity(&core, "dana", "dst").await;
    plant(&core, "srv1", &erin_src, &["read"]).await;
    plant(&core, "srv1", &dana_dst, &["read", "connect"]).await;

    let out = result(transfer(&core, &root, "copy", from_root(json!({}))).await);
    assert_eq!(out["transferred"]["shares"], json!(3), "{out}");
    let dropped = warning(&out, "grantee-not-in-destination", &erin_src).expect("the sibling entity is dropped");
    assert!(dropped["message"].as_str().unwrap().contains("read"), "names the capabilities: {dropped}");
    assert!(warning(&out, "group-not-in-destination", "qa").is_some(), "{out}");
    assert!(!codes(&out).contains(&"all-shares-dropped".to_string()), "{out}");
    assert!(!out.to_string().contains("pw-"), "{out}");

    let carried = shares_on(&core, ShareTargetKind::Resource, "dst/srv1").await;
    let carol_dst = entity(&core, "carol", "dst").await;
    let mut want = vec![carol_dst, dana_dst.clone(), "ops".to_string()];
    want.sort();
    assert_eq!(grantees(&carried), want, "kept shares only, the root entity re-pointed: {carried:?}");
    let ops = carried.iter().find(|s| s.grantee_entity_id == "ops").unwrap();
    assert_eq!(
        (ops.grantee_kind.as_str(), ops.capabilities.clone()),
        ("group_user", vec!["read".into(), "update".into()])
    );
    let dana = carried.iter().find(|s| s.grantee_entity_id == dana_dst).unwrap();
    assert_eq!(dana.capabilities, vec!["read".to_string(), "connect".to_string()]);
    assert_eq!(shares_on(&core, ShareTargetKind::Resource, "srv1").await.len(), 5, "a copy leaves the source's shares");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn all_shares_dropped_summary_warning() {
    let (_bvault, core, root) = vault("ns_transfer_all_shares_dropped").await;
    seed_resource(&core, &root, Some("src"), "srv1").await;
    let (_, carol_root) = user(&core, &root, "carol", "default", true).await;
    user_group(&core, &root, Some("src"), "qa").await;
    // Granted in `src`, the root entity is re-pointed to carol's `src` entity.
    grant(&core, &root, Some("src"), ("resource", "srv1"), ("entity", &carol_root), json!(["read"])).await.unwrap();
    grant(&core, &root, Some("src"), ("resource", "srv1"), ("group_user", "qa"), json!(["read"])).await.unwrap();
    let carol_src = entity(&core, "carol", "src").await;

    let out = result(transfer(&core, &root, "copy", resource("srv1", "srv1", json!({}))).await);
    assert_eq!(out["transferred"]["shares"], json!(0), "{out}");
    assert!(warning(&out, "grantee-not-in-destination", &carol_src).is_some(), "{out}");
    assert!(warning(&out, "group-not-in-destination", "qa").is_some(), "{out}");
    assert!(warning(&out, "all-shares-dropped", "src/resources/srv1").is_some(), "{out}");
    assert!(resource_exists(&core, &root, "dst", "srv1").await, "the item is still copied");
    assert!(shares_on(&core, ShareTargetKind::Resource, "dst/srv1").await.is_empty());
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn caller_without_grant_right_gets_item_but_no_shares() {
    let (_bvault, core, root) = vault("ns_transfer_cannot_grant").await;
    let policy = format!("{MOVER}\npath \"identity/sharing/by-target/*\" {{ capabilities = [\"read\", \"list\"] }}");
    write_policy(&core, &root, "no-grant", &policy).await;
    let (alice, alice_id) = user(&core, &root, "alice", "no-grant", true).await;
    seed_resource(&core, &alice, Some("src"), "srv1").await;
    for ns in ["src", "dst"] {
        user_group(&core, &root, Some(ns), "ops").await;
    }
    grant(&core, &root, Some("src"), ("resource", "srv1"), ("group_user", "ops"), json!(["read"])).await.unwrap();

    for dry_run in [true, false] {
        let out =
            result(transfer(&core, &alice, "copy", resource("srv1", "srv1", json!({ "dry_run": dry_run }))).await);
        assert_eq!(out["transferred"]["shares"], json!(0), "dry_run {dry_run}: {out}");
        assert!(warning(&out, "cannot-grant", "ops").is_some(), "dry_run {dry_run}: {out}");
        assert!(warning(&out, "all-shares-dropped", "src/resources/srv1").is_some(), "dry_run {dry_run}: {out}");
    }
    assert_eq!(resource_owner(&core, &root, "dst", "srv1").await, alice_id, "the item is copied and hers");
    assert!(shares_on(&core, ShareTargetKind::Resource, "dst/srv1").await.is_empty(), "no share is written");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn root_entity_grantee_is_repointed_and_redeemable_in_namespaced_destination() {
    let (_bvault, core, root) = vault("ns_transfer_share_repoint").await;
    // `srv1` is shared with carol; `srv2` is not; `other` lives in `dst` only.
    for name in ["srv1", "srv2"] {
        seed_resource(&core, &root, None, name).await;
    }
    seed_resource(&core, &root, Some("dst"), "other").await;
    let (_, carol_root) = user(&core, &root, "carol", "default", true).await;
    grant(&core, &root, None, ("resource", "srv1"), ("entity", &carol_root), json!(["read"])).await.unwrap();

    result(transfer(&core, &root, "copy", from_root(json!({}))).await);
    let srv2 = body("resource", "resources", ("", "srv2"), ("dst", "srv2"), json!({}));
    result(transfer(&core, &root, "copy", srv2).await);
    // Carol has never logged in to `dst`: her login there resolves to the
    // entity the share was re-pointed to.
    let (carol, carol_dst) = login_in(&core, "carol", "dst").await;
    assert_ne!(carol_dst, carol_root);
    let carried = shares_on(&core, ShareTargetKind::Resource, "dst/srv1").await;
    assert_eq!(grantees(&carried), vec![carol_dst], "{carried:?}");
    let record = get(&core, &carol, Some("dst"), "resources/resources/srv1").await.expect("carol reads via the share");
    assert_eq!(record["hostname"], json!("h2.example"));

    // Negative controls: the access is the carried share's, not the
    // transfer's or the namespace's.
    for name in ["srv2", "other"] {
        let path = format!("resources/resources/{name}");
        let r = send(&core, &carol, Operation::Read, &path, Some("dst"), json!({})).await;
        assert_eq!(super::status(&r), 403, "carol may not read {name}: {r:?}");
    }
}

/// Guard (4b review): a root grantee re-pointed into `dst` cannot land on
/// another principal. Auth mounts live in one global table (`sys/auth` ignores
/// the namespace; `auth/` is header-scoped), and a userpass login names its
/// entity `("userpass/", username, login namespace)` whatever its mount, so
/// the source share's principals are exactly the re-pointed share's.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_repointed_grantee_is_the_same_principal_set_in_the_destination() {
    let (_bvault, core, root) = vault("ns_transfer_repoint_principal").await;
    seed_resource(&core, &root, None, "srv1").await;
    let (_, carol_root) = user(&core, &root, "carol", "default", true).await;

    // No namespace-local `userpass/`: enabling it from `dst` hits the one
    // global table, and a user written from `dst` is root's same record.
    let again =
        send(&core, &root, Operation::Write, "sys/auth/userpass", Some("dst"), json!({ "type": "userpass" })).await;
    assert!(again.is_err(), "the path is taken in the single auth table: {again:?}");
    let reset = json!({ "password": "another22YY!", "token_policies": "default", "ttl": 0 });
    send(&core, &root, Operation::Write, "auth/userpass/users/carol", Some("dst"), reset).await.unwrap();
    let mut login = Request::new("auth/userpass/login/carol");
    login.operation = Operation::Write;
    login.body = json!({ "password": "another22YY!" }).as_object().cloned();
    assert!(core.handle_request(&mut login).await.is_ok(), "the `dst` write changed root's carol");
    send(&core, &root, Operation::Write, "auth/userpass/users/carol", None, json!({ "password": PASSWORD }))
        .await
        .unwrap();

    // A second userpass mount, enabled from `dst`, with its own `carol`: her
    // root login already resolves to the source share's grantee.
    send(&core, &root, Operation::Write, "sys/auth/dstpass", Some("dst"), json!({ "type": "userpass" })).await.unwrap();
    let other = json!({ "password": PASSWORD, "token_policies": "default", "ttl": 0 });
    send(&core, &root, Operation::Write, "auth/dstpass/users/carol", None, other).await.unwrap();
    let mut login = Request::new("auth/dstpass/login/carol");
    login.operation = Operation::Write;
    login.body = json!({ "password": PASSWORD }).as_object().cloned();
    let auth = core.handle_request(&mut login).await.unwrap().unwrap().auth.unwrap();
    assert_eq!(auth.metadata["entity_id"], carol_root, "both mounts' carol already share the source grantee");

    grant(&core, &root, None, ("resource", "srv1"), ("entity", &carol_root), json!(["read"])).await.unwrap();
    result(transfer(&core, &root, "copy", from_root(json!({}))).await);
    let (_, carol_dst) = login_in(&core, "carol", "dst").await;
    let carried = shares_on(&core, ShareTargetKind::Resource, "dst/srv1").await;
    assert_eq!(grantees(&carried), vec![carol_dst], "the entity carol's own `dst` login resolves to");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn share_history_records_copy_and_move_ops() {
    let (_bvault, core, root) = vault("ns_transfer_share_history").await;
    for name in ["srv1", "srv2"] {
        seed_resource(&core, &root, None, name).await;
    }
    user_group(&core, &root, None, "ops").await;
    user_group(&core, &root, Some("dst"), "ops").await;
    for name in ["srv1", "srv2"] {
        grant(&core, &root, None, ("resource", name), ("group_user", "ops"), json!(["read"])).await.unwrap();
    }

    result(transfer(&core, &root, "copy", from_root(json!({}))).await);
    let srv2 = body("resource", "resources", ("", "srv2"), ("dst", "srv2"), json!({}));
    result(transfer(&core, &root, "move", srv2).await);

    let history = ShareStore::new(core.as_ref()).await.unwrap().list_all_history().await.unwrap();
    let ops_on = |target: &str| -> Vec<String> {
        history
            .iter()
            .filter(|h| h.target_path == target && h.grantee_entity_id == "ops")
            .map(|h| h.op.clone())
            .collect()
    };
    assert_eq!(ops_on("dst/srv1"), vec!["copy".to_string()], "{history:?}");
    assert_eq!(ops_on("dst/srv2"), vec!["move".to_string()], "{history:?}");
    assert!(ops_on("srv2").contains(&"cascade-revoke".to_string()), "the move's delete revoked the source's");
    assert!(ops_on("srv1").iter().all(|op| op == "grant"), "a copy leaves the source's share alone");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn move_removes_source_shares_owner_and_group_membership() {
    let (_bvault, core, root) = vault("ns_transfer_move_relations").await;
    write_policy(&core, &root, "carrier", &format!("{MOVER}{CARRIER}")).await;
    let (alice, alice_id) = user(&core, &root, "alice", "carrier", true).await;
    seed_resource(&core, &alice, Some("src"), "srv1").await;
    for ns in ["src", "dst"] {
        user_group(&core, &root, Some(ns), "ops").await;
    }
    asset_group(&core, &root, Some("src"), "web", &["srv1", "other"], &[]).await;
    asset_group(&core, &root, Some("dst"), "web", &["other"], &[]).await;
    grant(&core, &alice, Some("src"), ("resource", "srv1"), ("group_user", "ops"), json!(["read"])).await.unwrap();

    let out = result(transfer(&core, &alice, "move", resource("srv1", "srv1", json!({}))).await);
    assert_eq!(out["transferred"]["shares"], json!(1), "{out}");

    assert!(!resource_exists(&core, &root, "src", "srv1").await);
    assert!(shares_on(&core, ShareTargetKind::Resource, "src/srv1").await.is_empty(), "source shares revoked");
    let owner = get(&core, &root, Some("src"), "identity/owner/resource/srv1").await.unwrap();
    assert_eq!(owner["owned"], json!(false), "the source owner record is gone: {owner}");
    assert_eq!(group_list(&core, &root, Some("src"), "web", "members").await.unwrap(), vec!["other".to_string()]);

    assert_eq!(resource_owner(&core, &root, "dst", "srv1").await, alice_id);
    assert_eq!(grantees(&shares_on(&core, ShareTargetKind::Resource, "dst/srv1").await), vec!["ops".to_string()]);
    let members = group_list(&core, &root, Some("dst"), "web", "members").await.unwrap();
    assert_eq!(members, vec!["other".to_string(), "srv1".to_string()]);
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn group_membership_recreated_only_for_same_named_destination_group_and_caller_may_modify() {
    let (_bvault, core, root) = vault("ns_transfer_groups_recreated").await;
    seed_resource(&core, &root, Some("src"), "srv1").await;
    for name in ["web", "db", "common"] {
        asset_group(&core, &root, Some("src"), name, &["srv1"], &[]).await;
    }
    asset_group(&core, &root, Some("dst"), "web", &["other"], &[]).await;
    // Root's `common` is what `dst` inherits: read-only there, never extended.
    asset_group(&core, &root, None, "common", &["x"], &[]).await;

    let out = result(transfer(&core, &root, "copy", resource("srv1", "srv1", json!({}))).await);
    let members = group_list(&core, &root, Some("dst"), "web", "members").await.unwrap();
    assert_eq!(members, vec!["other".to_string(), "srv1".to_string()], "{out}");
    assert!(warning(&out, "group-membership-dropped", "db").is_some(), "{out}");
    assert!(warning(&out, "group-membership-dropped", "common").is_some(), "{out}");
    assert!(group_list(&core, &root, Some("dst"), "db", "members").await.is_none(), "no group is created");
    let inherited = send(&core, &root, Operation::Read, "resource-group/groups/common", Some("dst"), json!({})).await;
    let inherited = inherited.unwrap().unwrap().data.unwrap();
    assert_eq!(inherited["inherited"], json!(true), "dst still has no `common` of its own: {inherited:?}");
    assert_eq!(group_list(&core, &root, None, "common", "members").await.unwrap(), vec!["x".to_string()]);
    assert_eq!(group_list(&core, &root, Some("src"), "db", "members").await.unwrap(), vec!["srv1".to_string()]);
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn group_membership_dropped_warning_otherwise() {
    let (_bvault, core, root) = vault("ns_transfer_groups_dropped").await;
    seed_resource(&core, &root, Some("src"), "srv1").await;
    asset_group(&core, &root, Some("src"), "web", &["srv1"], &[]).await;
    asset_group(&core, &root, Some("dst"), "web", &["other", "vault1"], &[]).await;
    let read_only = r#"
path "src/resource-group/*" { capabilities = ["read", "list"] }
path "dst/resource-group/*" { capabilities = ["read", "list"] }
"#;
    write_policy(&core, &root, "groups-read-only", &format!("{MOVER}{read_only}")).await;
    let hidden = r#"
path "src/resource-group/*" { capabilities = ["read", "update", "list"] }
path "dst/resource-group/*" { capabilities = ["read", "update", "list"] }
path "dst/resources/resources/vault1" { capabilities = ["deny"] }
"#;
    write_policy(&core, &root, "groups-partial-view", &format!("{MOVER}{hidden}")).await;
    let (gina, _) = user(&core, &root, "gina", "groups-read-only", true).await;
    let (hank, _) = user(&core, &root, "hank", "groups-partial-view", true).await;

    let cases = [(&gina, "srv-g", "may not modify"), (&hank, "srv-h", "cannot see every member")];
    for (token, to, reason) in cases {
        for dry_run in [true, false] {
            let out = result(transfer(&core, token, "copy", resource("srv1", to, json!({ "dry_run": dry_run }))).await);
            let w = warning(&out, "group-membership-dropped", "web").unwrap_or_else(|| panic!("{to}: {out}"));
            let text = w["message"].as_str().unwrap();
            assert!(text.contains(reason), "{to} dry_run {dry_run}: {text}");
            assert!(!text.contains("vault1"), "never names a hidden member: {text}");
        }
        assert!(resource_exists(&core, &root, "dst", to).await, "the item is still copied");
    }
    let members = group_list(&core, &root, Some("dst"), "web", "members").await.unwrap();
    assert_eq!(members, vec!["other".to_string(), "vault1".to_string()], "the group is untouched");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn files_not_transferred_warning_when_not_possible() {
    let (_bvault, core, root) = vault("ns_transfer_files").await;
    seed_resource(&core, &root, Some("src"), "srv1").await;
    let file = json!({ "name": "id.pem", "resource": "srv1", "content_base64": STANDARD.encode("file-bytes") });
    let created = send(&core, &root, Operation::Write, "files/files", Some("src"), file).await.unwrap();
    let id = created.unwrap().data.unwrap()["id"].as_str().unwrap().to_string();
    let attached_to = |core: Arc<Core>, root: String, id: String| async move {
        let meta = get(&core, &root, Some("src"), &format!("files/files/{id}")).await.unwrap();
        meta["resource"].as_str().unwrap().to_string()
    };

    let out = result(transfer(&core, &root, "copy", resource("srv1", "srv1", json!({}))).await);
    let w = warning(&out, "files-not-transferred", "srv1").unwrap_or_else(|| panic!("{out}"));
    assert!(w["message"].as_str().unwrap().contains("1 file"), "{w}");
    assert!(!out.to_string().contains("file-bytes"), "{out}");
    assert_eq!(attached_to(core.clone(), root.clone(), id.clone()).await, "srv1", "the file stays");
    let dst_files = send(&core, &root, Operation::List, "files/files", Some("dst"), json!({})).await.unwrap();
    let dst_files = dst_files.and_then(|r| r.data).and_then(|d| d.get("keys").cloned()).unwrap_or(json!([]));
    assert_eq!(dst_files, json!([]), "no blob is moved");

    // Same namespace: a copy cannot attach one file to two resources...
    let same_ns = |to: &str, extra: Value| body("resource", "resources", ("src", "srv1"), ("src", to), extra);
    let out = result(transfer(&core, &root, "copy", same_ns("srv8", json!({}))).await);
    assert!(warning(&out, "files-not-transferred", "srv1").is_some(), "{out}");
    assert_eq!(attached_to(core.clone(), root.clone(), id.clone()).await, "srv1");
    // ...a move re-points it, after the source is gone.
    let dry = result(transfer(&core, &root, "move", same_ns("srv9", json!({ "dry_run": true }))).await);
    assert!(!codes(&dry).contains(&"files-not-transferred".to_string()), "{dry}");
    let out = result(transfer(&core, &root, "move", same_ns("srv9", json!({}))).await);
    assert!(!codes(&out).contains(&"files-not-transferred".to_string()), "{out}");
    assert_eq!(attached_to(core.clone(), root.clone(), id.clone()).await, "srv9");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn dry_run_reports_share_and_group_warnings_and_writes_nothing() {
    let (_bvault, core, root) = vault("ns_transfer_relations_dry_run").await;
    seed_resource(&core, &root, None, "srv1").await;
    let (_, carol_root) = user(&core, &root, "carol", "default", true).await;
    user_group(&core, &root, None, "qa").await;
    grant(&core, &root, None, ("resource", "srv1"), ("entity", &carol_root), json!(["read"])).await.unwrap();
    grant(&core, &root, None, ("resource", "srv1"), ("group_user", "qa"), json!(["read"])).await.unwrap();
    asset_group(&core, &root, None, "web", &["srv1"], &[]).await;
    asset_group(&core, &root, None, "db", &["srv1"], &[]).await;
    asset_group(&core, &root, Some("dst"), "web", &["other"], &[]).await;
    let history_before = ShareStore::new(core.as_ref()).await.unwrap().list_all_history().await.unwrap().len();

    let dry = result(transfer(&core, &root, "copy", from_root(json!({ "dry_run": true }))).await);
    assert_eq!(dry["transferred"]["shares"], json!(1), "the shares that would be written: {dry}");
    assert!(warning(&dry, "group-not-in-destination", "qa").is_some(), "{dry}");
    assert!(warning(&dry, "group-membership-dropped", "db").is_some(), "{dry}");
    assert!(warning(&dry, "group-membership-dropped", "web").is_none(), "web can take it: {dry}");

    assert!(!resource_exists(&core, &root, "dst", "srv1").await);
    assert!(shares_on(&core, ShareTargetKind::Resource, "dst/srv1").await.is_empty());
    assert_eq!(group_list(&core, &root, Some("dst"), "web", "members").await.unwrap(), vec!["other".to_string()]);
    let history_after = ShareStore::new(core.as_ref()).await.unwrap().list_all_history().await.unwrap().len();
    assert_eq!(history_after, history_before, "no share history either");
    let entities = EntityStore::new(core.as_ref()).await.unwrap();
    assert!(entities.get_by_alias_ns("userpass/", "carol", "dst").await.unwrap().is_none(), "nor a re-pointed entity");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn kv_secret_shares_carried() {
    let (_bvault, core, root) = vault("ns_transfer_kv_shares").await;
    send(&core, &root, Operation::Write, "secret/data/team/db", None, json!({ "data": { "v": "kv-1" } }))
        .await
        .unwrap();
    let (_, carol_root) = user(&core, &root, "carol", "default", true).await;
    grant(&core, &root, None, ("kv-secret", "secret/team/db"), ("entity", &carol_root), json!(["read"])).await.unwrap();
    asset_group(&core, &root, None, "kvg", &[], &["secret/team/db"]).await;
    asset_group(&core, &root, Some("dst"), "kvg", &[], &[]).await;

    let request = body("kv-secret", "secret", ("", "team/db"), ("dst", "team/db"), json!({}));
    let out = result(transfer(&core, &root, "copy", request).await);
    assert_eq!(out["transferred"]["shares"], json!(1), "{out}");
    let secrets = group_list(&core, &root, Some("dst"), "kvg", "secrets").await.unwrap();
    assert_eq!(secrets, vec!["secret/team/db".to_string()], "{out}");

    let (carol, carol_dst) = login_in(&core, "carol", "dst").await;
    let carried = shares_on(&core, ShareTargetKind::KvSecret, "dst/secret/team/db").await;
    assert_eq!(grantees(&carried), vec![carol_dst], "{carried:?}");
    let read = get(&core, &carol, Some("dst"), "secret/data/team/db").await.expect("carol reads via the share");
    assert_eq!(read["data"]["v"], json!("kv-1"));
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn no_share_widens_access() {
    let (_bvault, core, root) = vault("ns_transfer_no_widening").await;
    seed_resource(&core, &root, None, "srv1").await;
    let (_, carol_root) = user(&core, &root, "carol", "default", true).await;
    grant(&core, &root, None, ("resource", "srv1"), ("entity", &carol_root), json!(["read", "connect"])).await.unwrap();

    result(transfer(&core, &root, "copy", from_root(json!({}))).await);
    let (carol, _) = login_in(&core, "carol", "dst").await;
    let carried = shares_on(&core, ShareTargetKind::Resource, "dst/srv1").await;
    assert_eq!(carried.len(), 1);
    assert_eq!(carried[0].capabilities, vec!["read".to_string(), "connect".to_string()], "connect is preserved");

    let path = "resources/resources/srv1";
    assert!(get(&core, &carol, Some("dst"), path).await.is_some(), "read is carried");
    let update = send(&core, &carol, Operation::Write, path, Some("dst"), json!({ "hostname": "evil.example" })).await;
    assert!(update.is_err(), "no update was shared: {update:?}");
    assert!(send(&core, &carol, Operation::Delete, path, Some("dst"), json!({})).await.is_err(), "nor delete");
    let probe = json!({ "paths": [path] });
    let caps = send(&core, &carol, Operation::Write, "sys/capabilities-self", Some("dst"), probe).await.unwrap();
    let caps = caps.unwrap().data.unwrap()["capabilities"][path].clone();
    for missing in ["update", "delete", "create"] {
        assert!(!caps.as_array().unwrap().contains(&json!(missing)), "{missing}: {caps}");
    }
    let record = get(&core, &root, Some("dst"), path).await.unwrap();
    assert_eq!(record["hostname"], json!("h2.example"), "the copy is untouched");
}

/// The relations add no warning when there is nothing to carry.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn nothing_to_carry_adds_no_relation_warning() {
    let (_bvault, core, root) = vault("ns_transfer_no_relations").await;
    seed_resource(&core, &root, Some("src"), "srv1").await;
    let out = result(transfer(&core, &root, "copy", resource("srv1", "srv1", json!({}))).await);
    assert_eq!(codes(&out), vec!["policies-not-carried".to_string()], "{out}");
}
