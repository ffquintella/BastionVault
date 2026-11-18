//! An asset group's KV-secret member is the secret's own name (T507).
//!
//! The group store stripped a `data`/`metadata` second segment from every
//! member and request path whatever the mount, so on a kv (v1) mount the
//! secret `data/x` was the member `x`. These drive real tokens through
//! `Core::handle_request`.

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};

use super::{
    kernel_policy_deny::{write, write_policy},
    kv_secret_keys::{login, send, status},
};
use crate::{
    core::Core,
    kernel_api::VaultCtx,
    logical::Operation,
    modules::resource_group::{secret_name_migrate, ResourceGroupEntry, ResourceGroupModule, ResourceGroupStore},
    storage::{Storage, StorageEntry},
    test_utils::new_unseal_test_bastion_vault,
};

async fn vault(name: &str) -> (crate::BastionVault, Arc<Core>, String) {
    let (bvault, core, root) = new_unseal_test_bastion_vault(name).await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    (bvault, core, root)
}

/// A policy reading (and listing) `prefix*` only for members of `group`.
async fn gated(core: &Arc<Core>, root: &str, name: &str, prefix: &str, group: &str) {
    let hcl = format!("path \"{prefix}*\" {{\n  capabilities = [\"read\", \"list\"]\n  groups = [\"{group}\"]\n}}\n");
    write_policy(core, root, name, &hcl).await;
}

/// `(api version, path)` read as `token` answers `expected`.
async fn reads(core: &Arc<Core>, token: &str, api: u8, path: &str, ns: Option<&str>, expected: u16, who: &str) {
    let r = send(core, token, api, Operation::Read, path, ns, json!({})).await;
    assert_eq!(status(&r), expected, "{who}: api {api} read {path}: {r:?}");
}

/// The kept pre-T507 members of root's group `name`, as root reads them.
async fn kept(core: &Arc<Core>, root: &str, name: &str) -> Vec<String> {
    let path = format!("resource-group/groups/{name}");
    let resp = send(core, root, 1, Operation::Read, &path, None, json!({})).await.unwrap().unwrap();
    serde_json::from_value(resp.data.unwrap()["secrets_legacy_kept"].clone()).unwrap()
}

/// The `secrets` of group `name`, as root reads it.
async fn members(core: &Arc<Core>, root: &str, name: &str, ns: Option<&str>) -> Vec<String> {
    let path = format!("resource-group/groups/{name}");
    let resp = send(core, root, 1, Operation::Read, &path, ns, json!({})).await.unwrap().unwrap();
    let secrets = resp.data.unwrap()["secrets"].clone();
    serde_json::from_value(secrets).unwrap()
}

/// The groups `by-secret` names for `path`, as root.
async fn by_secret(core: &Arc<Core>, root: &str, path: &str, ns: Option<&str>) -> Vec<String> {
    let route = format!("resource-group/by-secret/{}", URL_SAFE_NO_PAD.encode(path));
    let resp = send(core, root, 1, Operation::Read, &route, ns, json!({})).await.unwrap().unwrap();
    serde_json::from_value(resp.data.unwrap()["groups"].clone()).unwrap()
}

async fn seed_kv(core: &Arc<Core>, root: &str, paths: &[&str], ns: Option<&str>) {
    for path in paths {
        let body = if path.contains("/data/") && !path.starts_with("kv/") {
            json!({ "data": { "v": path } })
        } else {
            json!({ "v": path })
        };
        let r = send(core, root, 1, Operation::Write, path, ns, body).await;
        assert_eq!(status(&r), 200, "seed {path}: {r:?}");
    }
}

/// On a kv (v1) mount `data/x` and `metadata/x` are secrets of their own:
/// membership of `x` reaches neither, and theirs does not reach `x`.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn kv_v1_x_and_data_x_have_independent_memberships() {
    let (_bvault, core, root) = vault("t507_kv_v1_independent").await;
    write(&core, &root, "sys/mounts/kv/", json!({ "type": "kv" })).await;
    seed_kv(&core, &root, &["kv/x", "kv/data/x", "kv/metadata/x"], None).await;
    write(&core, &root, "resource-group/groups/gx", json!({ "secrets": "kv/x" })).await;
    write(&core, &root, "resource-group/groups/gd", json!({ "secrets": "kv/data/x" })).await;
    gated(&core, &root, "in-gx", "kv/", "gx").await;
    gated(&core, &root, "in-gd", "kv/", "gd").await;
    let (erin, _) = login(&core, &root, "erin", "in-gx").await;
    let (frank, _) = login(&core, &root, "frank", "in-gd").await;

    reads(&core, &erin, 1, "kv/x", None, 200, "erin (gx)").await;
    reads(&core, &erin, 1, "kv/data/x", None, 403, "erin (gx)").await;
    reads(&core, &erin, 1, "kv/metadata/x", None, 403, "erin (gx)").await;
    reads(&core, &frank, 1, "kv/data/x", None, 200, "frank (gd)").await;
    reads(&core, &frank, 1, "kv/x", None, 403, "frank (gd)").await;
    reads(&core, &frank, 1, "kv/metadata/x", None, 403, "frank (gd)").await;

    assert_eq!(members(&core, &root, "gd", None).await, ["kv/data/x"], "stored as the secret's own name");
    assert_eq!(by_secret(&core, &root, "kv/data/x", None).await, ["gd"]);
    assert_eq!(by_secret(&core, &root, "kv/x", None).await, ["gx"]);
}

/// The same on a kv (v1) mount inside a namespace, with a namespace token.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_namespaced_kv_v1_mount_keys_members_on_their_own_names() {
    let (_bvault, core, root) = vault("t507_ns_kv_v1").await;
    write(&core, &root, "sys/namespaces/team", json!({})).await;
    let ns = Some("team");
    let r = send(&core, &root, 1, Operation::Write, "sys/mounts/kv/", ns, json!({ "type": "kv" })).await;
    assert_eq!(status(&r), 200, "mount: {r:?}");
    seed_kv(&core, &root, &["kv/x", "kv/data/x"], ns).await;
    for (group, member) in [("gx", "kv/x"), ("gd", "kv/data/x")] {
        let path = format!("resource-group/groups/{group}");
        let r = send(&core, &root, 1, Operation::Write, &path, ns, json!({ "secrets": member })).await;
        assert_eq!(status(&r), 200, "group {group}: {r:?}");
    }
    let hcl = "path \"team/kv/*\" {\n  capabilities = [\"read\"]\n  groups = [\"gd\"]\n}\n";
    let r = send(&core, &root, 1, Operation::Write, "sys/policy/in-gd", ns, json!({ "policy": hcl })).await;
    assert_eq!(status(&r), 200, "policy: {r:?}");
    let body = json!({ "policies": ["in-gd"], "ttl": "1h" });
    let created = send(&core, &root, 1, Operation::Write, "auth/token/create", ns, body).await.unwrap();
    let token = created.unwrap().auth.unwrap().client_token;

    reads(&core, &token, 1, "kv/data/x", ns, 200, "a gd member in team").await;
    reads(&core, &token, 1, "kv/x", ns, 403, "a gd member in team").await;
    assert_eq!(members(&core, &root, "gd", ns).await, ["kv/data/x"]);
    assert_eq!(by_secret(&core, &root, "kv/x", ns).await, ["gx"]);
}

/// On a kv-v2 mount a member is the secret's name: `secret/data/x` is the
/// secret `data/x`, reached through `secret/data/data/x`, never `x`.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_kv_v2_member_named_data_x_is_that_secret() {
    let (_bvault, core, root) = vault("t507_kv_v2_data_x").await;
    seed_kv(&core, &root, &["secret/data/x", "secret/data/data/x"], None).await;
    write(&core, &root, "resource-group/groups/gd", json!({ "secrets": "secret/data/x" })).await;
    gated(&core, &root, "in-gd", "secret/", "gd").await;
    let (frank, _) = login(&core, &root, "frank", "in-gd").await;

    for api in [1u8, 2] {
        reads(&core, &frank, api, "secret/data/data/x", None, 200, "frank (gd)").await;
        let x = if api == 1 { "secret/data/x" } else { "secret/x" };
        reads(&core, &frank, api, x, None, 403, "frank (gd)").await;
    }
    // An edit that leaves the member list alone does not re-key it.
    write(&core, &root, "resource-group/groups/gd", json!({ "description": "edited" })).await;
    assert_eq!(members(&core, &root, "gd", None).await, ["secret/data/x"]);
    reads(&core, &frank, 1, "secret/data/data/x", None, 200, "frank after an edit").await;
}

/// A kv-v2 mount with a multi-segment path: the member `team/kv/x` covers
/// the secret `x` through every route, at both API versions.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_multi_segment_kv_v2_member_covers_every_route_of_its_secret() {
    let (_bvault, core, root) = vault("t507_multi_segment").await;
    write(&core, &root, "sys/mounts/team/kv/", json!({ "type": "kv-v2" })).await;
    seed_kv(&core, &root, &["team/kv/data/x", "team/kv/data/y"], None).await;
    write(&core, &root, "resource-group/groups/g", json!({ "secrets": "team/kv/x" })).await;
    gated(&core, &root, "in-g", "team/kv/", "g").await;
    let (erin, _) = login(&core, &root, "erin", "in-g").await;

    reads(&core, &erin, 1, "team/kv/data/x", None, 200, "erin").await;
    reads(&core, &erin, 2, "team/kv/x", None, 200, "erin").await;
    reads(&core, &erin, 1, "team/kv/metadata/x", None, 200, "erin").await;
    reads(&core, &erin, 1, "team/kv/data/y", None, 403, "erin").await;
    assert_eq!(by_secret(&core, &root, "team/kv/x", None).await, ["g"]);
}

/// Deleting the secret `data/x` prunes it from its groups and leaves the
/// membership of `x` alone.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn deleting_data_x_leaves_the_membership_of_x() {
    let (_bvault, core, root) = vault("t507_prune").await;
    write(&core, &root, "sys/mounts/kv/", json!({ "type": "kv" })).await;
    seed_kv(&core, &root, &["kv/x", "kv/data/x"], None).await;
    write(&core, &root, "resource-group/groups/both", json!({ "secrets": "kv/x,kv/data/x" })).await;
    let r = send(&core, &root, 1, Operation::Delete, "kv/data/x", None, json!({})).await;
    assert_eq!(status(&r), 200, "delete: {r:?}");
    assert_eq!(members(&core, &root, "both", None).await, ["kv/x"]);
    assert_eq!(by_secret(&core, &root, "kv/x", None).await, ["both"]);
}

/// A list authorized only by a group-gated rule keeps the entries whose own
/// name is a member: listing `kv/data/` shows `x` (the secret `data/x`) to
/// its group only.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_group_gated_list_filters_on_the_secrets_own_name() {
    let (_bvault, core, root) = vault("t507_list_filter").await;
    write(&core, &root, "sys/mounts/kv/", json!({ "type": "kv" })).await;
    seed_kv(&core, &root, &["kv/x", "kv/data/x"], None).await;
    write(&core, &root, "resource-group/groups/gx", json!({ "secrets": "kv/x" })).await;
    write(&core, &root, "resource-group/groups/gd", json!({ "secrets": "kv/data/x" })).await;
    gated(&core, &root, "in-gx", "kv/", "gx").await;
    gated(&core, &root, "in-gd", "kv/", "gd").await;
    let (erin, _) = login(&core, &root, "erin", "in-gx").await;
    let (frank, _) = login(&core, &root, "frank", "in-gd").await;

    let keys = |token: String| {
        let core = core.clone();
        async move {
            let r = send(&core, &token, 1, Operation::List, "kv/data/", None, json!({})).await;
            let data = r.ok().flatten().and_then(|r| r.data).unwrap_or_default();
            data.get("keys").cloned().unwrap_or(Value::Null)
        }
    };
    assert_eq!(keys(frank).await, json!(["x"]), "data/x is in gd");
    assert_eq!(keys(erin).await, json!([]), "data/x is not in gx");
}

/// A reader who may not read every member sees the others hidden, each
/// probed as the secret it names: `secret/data/x` is the secret `data/x`,
/// so a grant on `x` does not reveal it.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_member_is_shown_only_to_a_reader_of_that_secret() {
    let (_bvault, core, root) = vault("t507_redaction").await;
    seed_kv(&core, &root, &["secret/data/x", "secret/data/data/x"], None).await;
    write(&core, &root, "resource-group/groups/mixed", json!({ "secrets": "secret/x,secret/data/x" })).await;
    let hcl = "path \"secret/data/x\" { capabilities = [\"read\"] }\n\
               path \"resource-group/groups/*\" { capabilities = [\"read\"] }\n";
    write_policy(&core, &root, "reads-x", hcl).await;
    let (erin, _) = login(&core, &root, "erin", "reads-x").await;
    let resp = send(&core, &erin, 1, Operation::Read, "resource-group/groups/mixed", None, json!({})).await;
    let shown: Vec<String> = serde_json::from_value(resp.unwrap().unwrap().data.unwrap()["secrets"].clone()).unwrap();
    assert_eq!(shown, [crate::modules::resource_group::REDACTED_MEMBER, "secret/x"], "data/x hidden, x shown");
}

// ── The T507 migration over records an older release wrote ─────────────

fn store(core: &Arc<Core>) -> Arc<ResourceGroupStore> {
    let module = core.module_manager().get_module::<ResourceGroupModule>("resource-group").unwrap();
    module.store().unwrap()
}

/// The system-view prefix of namespace `ns`'s asset-group scope.
fn scope_prefix(ns: &str) -> String {
    match ns {
        "" => "resource-group/".to_string(),
        ns => format!("resource-group/ns/{}/", URL_SAFE_NO_PAD.encode(ns)),
    }
}

/// Group `name` of namespace `ns` exactly as a release before T507 stored it:
/// no `secrets_format`, the members in the pre-T507 key, each filed in the
/// legacy secret index under that key.
async fn plant_old_group(core: &Arc<Core>, ns: &str, name: &str, secrets: &[&str]) {
    let view = core.system_view().unwrap();
    let prefix = scope_prefix(ns);
    let record = json!({
        "name": name, "description": "", "members": [], "secrets": secrets, "files": [],
        "owner_entity_id": "", "created_at": "", "updated_at": ""
    });
    let value = serde_json::to_vec(&record).unwrap();
    view.put(&StorageEntry { key: format!("{prefix}group/{name}"), value }).await.unwrap();
    for s in secrets {
        let key = format!("{prefix}secret-index/{}", URL_SAFE_NO_PAD.encode(s));
        let mut names: Vec<String> = match view.get(&key).await.unwrap() {
            Some(e) => serde_json::from_slice(&e.value).unwrap(),
            None => Vec::new(),
        };
        names.push(name.to_string());
        names.sort();
        view.put(&StorageEntry { key, value: serde_json::to_vec(&names).unwrap() }).await.unwrap();
    }
}

async fn record(core: &Arc<Core>, ns: &str, name: &str) -> ResourceGroupEntry {
    store(core).get_group(name, ns).await.unwrap().unwrap()
}

/// Existing members keep exactly the access they gave, before the migration
/// (it decides by the old keys and refuses membership changes), and after it:
/// the ambiguous kv (v1) member keeps all three secrets until an operator
/// prunes one, and a new member names one secret only.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn old_members_keep_their_access_before_while_pending_and_after_the_migration() {
    let (_bvault, core, root) = vault("t507_migrate_root").await;
    write(&core, &root, "sys/mounts/kv/", json!({ "type": "kv" })).await;
    write(&core, &root, "sys/mounts/team/kv/", json!({ "type": "kv-v2" })).await;
    seed_kv(&core, &root, &["kv/x", "kv/data/x", "kv/metadata/x", "kv/free"], None).await;
    seed_kv(&core, &root, &["secret/data/data/y", "team/kv/data/z"], None).await;
    // As the old store kept them: g1 from `kv/x` or `kv/data/x` (one key on
    // a kv v1 mount), g2 from `secret/data/data/y`, g3 typed as is.
    secret_name_migrate::reset_for_test(&core).await.unwrap();
    plant_old_group(&core, "", "g1", &["kv/x"]).await;
    plant_old_group(&core, "", "g2", &["secret/data/y"]).await;
    plant_old_group(&core, "", "g3", &["team/kv/data/z"]).await;
    gated(&core, &root, "in-g1", "kv/", "g1").await;
    gated(&core, &root, "in-g2", "secret/", "g2").await;
    gated(&core, &root, "in-g3", "team/kv/", "g3").await;
    let (u1, _) = login(&core, &root, "user-one", "in-g1").await;
    let (u2, _) = login(&core, &root, "user-two", "in-g2").await;
    let (u3, _) = login(&core, &root, "user-three", "in-g3").await;

    // Pending: the old keys decide, every read works as it did.
    for path in ["kv/x", "kv/data/x", "kv/metadata/x"] {
        reads(&core, &u1, 1, path, None, 200, "pending: g1").await;
    }
    reads(&core, &u2, 1, "secret/data/data/y", None, 200, "pending: g2").await;
    reads(&core, &u3, 1, "team/kv/data/z", None, 200, "pending: g3").await;
    reads(&core, &u3, 1, "team/kv/metadata/z", None, 403, "pending: g3 named the data/ route only").await;
    assert_eq!(by_secret(&core, &root, "kv/data/x", None).await, ["g1"], "own name, old key");
    assert_eq!(by_secret(&core, &root, "team/kv/z", None).await, ["g3"]);
    assert_eq!(members(&core, &root, "g1", None).await, ["kv/x"], "shown as stored");

    // Pending: no secret joins or leaves a group; other edits work.
    let w = |body: Value, path: &'static str| {
        let (core, root) = (core.clone(), root.clone());
        async move { status(&send(&core, &root, 1, Operation::Write, path, None, body).await) }
    };
    assert_eq!(w(json!({ "secrets": "kv/x,kv/free" }), "resource-group/groups/g1").await, 503, "an add");
    assert_eq!(w(json!({ "secrets": "" }), "resource-group/groups/g1").await, 503, "a removal");
    assert_eq!(w(json!({ "secrets": "kv/new" }), "resource-group/groups/g9").await, 503, "a new group");
    assert_eq!(w(json!({ "description": "edited" }), "resource-group/groups/g1").await, 200);
    assert_eq!(w(json!({ "secrets": "/kv/x/" }), "resource-group/groups/g1").await, 200, "the list it read");
    assert_eq!(w(json!({ "description": "empty" }), "resource-group/groups/g8").await, 200, "no secrets");
    let del = |path: &'static str| {
        let (core, root) = (core.clone(), root.clone());
        async move { status(&send(&core, &root, 1, Operation::Delete, path, None, json!({})).await) }
    };
    assert_eq!(del("resource-group/groups/g1").await, 503, "a group listing secrets");
    assert_eq!(del("kv/x").await, 503, "a listed secret");
    assert_eq!(del("kv/free").await, 200, "a secret no group lists");
    assert_eq!(record(&core, "", "g1").await.secrets, ["kv/x"], "nothing changed g1's members");

    let report = secret_name_migrate::run_if_needed(&core).await.unwrap();
    assert_eq!(
        (report.groups_converted, report.members_ambiguous, report.members_rekeyed, report.members_kept_legacy),
        (4, 1, 0, 1),
        "{report:?}"
    );
    assert!(store(&core).secret_names().await.unwrap());
    let g1 = record(&core, "", "g1").await;
    assert_eq!(g1.secrets, ["kv/data/x", "kv/metadata/x", "kv/x"], "each secret kv/x reached");
    assert_eq!(g1.legacy_secrets, ["kv/x"], "the old list is kept for rollback");
    assert_eq!(record(&core, "", "g2").await.secrets, ["secret/data/y"], "already its own name");
    let g3 = record(&core, "", "g3").await;
    assert_eq!((g3.secrets, g3.secrets_legacy_kept), (vec![], vec!["team/kv/data/z".to_string()]), "kept");
    assert_eq!(kept(&core, &root, "g3").await, ["team/kv/data/z"], "shown apart from own names");

    // After: nothing lost, nothing gained (Ruling BB).
    for path in ["kv/x", "kv/data/x", "kv/metadata/x"] {
        reads(&core, &u1, 1, path, None, 200, "after: g1").await;
    }
    reads(&core, &u2, 1, "secret/data/data/y", None, 200, "after: g2").await;
    reads(&core, &u3, 1, "team/kv/data/z", None, 200, "after: g3").await;
    reads(&core, &u3, 1, "team/kv/metadata/z", None, 403, "after: g3 still the data/ route only").await;
    assert_eq!(by_secret(&core, &root, "kv/data/x", None).await, ["g1"]);
    assert!(by_secret(&core, &root, "team/kv/z", None).await.is_empty(), "a kept member is no own-name member");

    // An operator regroups g3 by the secret's own name: now every route.
    let regroup = json!({ "secrets": "team/kv/z", "secrets_legacy_kept": "" });
    assert_eq!(w(regroup, "resource-group/groups/g3").await, 200);
    reads(&core, &u3, 1, "team/kv/metadata/z", None, 200, "regrouped: the secret z").await;
    reads(&core, &u3, 2, "team/kv/z", None, 200, "regrouped: the short form too").await;
    let adds = json!({ "secrets_legacy_kept": "team/kv/data/z" });
    assert_eq!(w(adds, "resource-group/groups/g3").await, 400, "a kept member is never added back");

    // An operator prunes the pair: the other members are unaffected.
    assert_eq!(w(json!({ "secrets": "kv/x,kv/metadata/x" }), "resource-group/groups/g1").await, 200);
    reads(&core, &u1, 1, "kv/data/x", None, 403, "pruned").await;
    reads(&core, &u1, 1, "kv/x", None, 200, "kept").await;
    reads(&core, &u1, 1, "kv/metadata/x", None, 200, "kept").await;

    // A new membership of data/x does not grant x.
    assert_eq!(w(json!({ "secrets": "kv/data/x" }), "resource-group/groups/g5").await, 200);
    gated(&core, &root, "in-g5", "kv/", "g5").await;
    let (u5, _) = login(&core, &root, "user-five", "in-g5").await;
    reads(&core, &u5, 1, "kv/data/x", None, 200, "g5").await;
    reads(&core, &u5, 1, "kv/x", None, 403, "g5").await;

    let again = secret_name_migrate::run_if_needed(&core).await.unwrap();
    assert!(again.skipped, "idempotent: {again:?}");
    assert_eq!(record(&core, "", "g1").await.legacy_secrets, ["kv/x"]);
}

/// A pass cut short (a crash after converting some records) resumes: the
/// next run converts the rest, and a converted record is never converted
/// again (its old list would be lost).
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_migration_cut_short_resumes_and_converts_each_record_once() {
    let (_bvault, core, root) = vault("t507_migrate_resume").await;
    write(&core, &root, "sys/mounts/kv/", json!({ "type": "kv" })).await;
    seed_kv(&core, &root, &["kv/x", "kv/data/y"], None).await;
    secret_name_migrate::reset_for_test(&core).await.unwrap();
    plant_old_group(&core, "", "first", &["kv/x"]).await;
    plant_old_group(&core, "", "second", &["kv/y"]).await;

    // A pass that converted `first` and then stopped, as a crash would.
    let mut pass = secret_name_migrate::SecretNameMigration::start(&core).await.unwrap().unwrap();
    assert!(pass.step().await.unwrap());
    drop(pass);
    assert!(!store(&core).secret_names().await.unwrap(), "no marker after a cut-short pass");
    assert_eq!(record(&core, "", "first").await.secrets_format, 1);
    assert_eq!(record(&core, "", "second").await.secrets_format, 0);
    gated(&core, &root, "in-second", "kv/", "second").await;
    let (u, _) = login(&core, &root, "user-second", "in-second").await;
    reads(&core, &u, 1, "kv/data/y", None, 200, "between the two passes").await;

    let report = secret_name_migrate::run_if_needed(&core).await.unwrap();
    assert_eq!((report.groups_converted, report.members_ambiguous), (1, 1), "only the rest: {report:?}");
    let first = record(&core, "", "first").await;
    assert_eq!(
        (first.secrets.clone(), first.legacy_secrets),
        (vec!["kv/data/x".to_string(), "kv/metadata/x".into(), "kv/x".into()], vec!["kv/x".to_string()])
    );
    reads(&core, &u, 1, "kv/data/y", None, 200, "after").await;
    assert!(secret_name_migrate::run_if_needed(&core).await.unwrap().skipped);
}

/// A namespace's records are converted through that namespace's own mount
/// table: there `kv/` is a kv (v1) mount, at root it does not exist.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_namespaced_scope_converts_through_its_own_mounts() {
    let (_bvault, core, root) = vault("t507_migrate_ns").await;
    write(&core, &root, "sys/namespaces/team", json!({})).await;
    let ns = Some("team");
    let r = send(&core, &root, 1, Operation::Write, "sys/mounts/kv/", ns, json!({ "type": "kv" })).await;
    assert_eq!(status(&r), 200, "mount: {r:?}");
    seed_kv(&core, &root, &["kv/data/x"], ns).await;
    secret_name_migrate::reset_for_test(&core).await.unwrap();
    plant_old_group(&core, "team", "g", &["kv/x"]).await;
    plant_old_group(&core, "", "rootg", &["kv/x"]).await;
    let hcl = "path \"team/kv/*\" {\n  capabilities = [\"read\"]\n  groups = [\"g\"]\n}\n";
    let r = send(&core, &root, 1, Operation::Write, "sys/policy/in-g", ns, json!({ "policy": hcl })).await;
    assert_eq!(status(&r), 200, "policy: {r:?}");
    let created =
        send(&core, &root, 1, Operation::Write, "auth/token/create", ns, json!({ "policies": ["in-g"] })).await;
    let token = created.unwrap().unwrap().auth.unwrap().client_token;
    reads(&core, &token, 1, "kv/data/x", ns, 200, "pending, in team").await;

    let report = secret_name_migrate::run_if_needed(&core).await.unwrap();
    assert_eq!((report.members_ambiguous, report.members_kept_legacy), (1, 1), "{report:?}");
    assert_eq!(record(&core, "team", "g").await.secrets, ["kv/data/x", "kv/metadata/x", "kv/x"]);
    let rootg = record(&core, "", "rootg").await;
    assert_eq!(rootg.secrets_legacy_kept, ["kv/x"], "no mount reaches it: kept with the old rule");
    reads(&core, &token, 1, "kv/data/x", ns, 200, "after, in team").await;
    reads(&core, &token, 1, "kv/x", ns, 200, "kv/x is a member too: the gate passes (no such secret)").await;
}

/// A mount table that cannot be read fails the pass: no marker, nothing
/// converted, and the old keys keep deciding.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_migration_that_cannot_read_a_mount_table_sets_no_marker() {
    let (_bvault, core, root) = vault("t507_migrate_unreadable").await;
    write(&core, &root, "sys/mounts/kv/", json!({ "type": "kv" })).await;
    let created = send(&core, &root, 1, Operation::Write, "sys/namespaces/broken", None, json!({})).await;
    let uuid = created.unwrap().unwrap().data.unwrap()["uuid"].as_str().unwrap().to_string();
    let table = crate::modules::namespace::router::namespace_mount_config_path(&uuid);
    let garbage = StorageEntry { key: table, value: b"not a mount table".to_vec() };
    core.barrier().as_storage().put(&garbage).await.unwrap();
    secret_name_migrate::reset_for_test(&core).await.unwrap();
    plant_old_group(&core, "", "g", &["kv/x"]).await;

    assert!(secret_name_migrate::run_if_needed(&core).await.is_err(), "the pass must fail");
    assert!(!store(&core).secret_names().await.unwrap(), "the switch stays off");
    assert_eq!(record(&core, "", "g").await.secrets_format, 0, "nothing converted");
    assert_eq!(by_secret(&core, &root, "kv/data/x", None).await, ["g"], "the old key still decides");
}

/// An unreadable switch marker refuses KV requests (root too) instead of
/// guessing which keys decide; requests that name no KV secret still work.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn an_unreadable_switch_marker_refuses_kv_requests() {
    let (_bvault, core, root) = vault("t507_garbled_marker").await;
    seed_kv(&core, &root, &["secret/data/x"], None).await;
    store(&core).garble_secret_names_marker_for_test().await.unwrap();
    let r = send(&core, &root, 1, Operation::Read, "secret/data/x", None, json!({})).await;
    assert_eq!(status(&r), 500, "root's KV read: {r:?}");
    let r = send(&core, &root, 1, Operation::Read, "auth/token/lookup-self", None, json!({})).await;
    assert_eq!(status(&r), 200, "a non-KV request: {r:?}");
    assert!(secret_name_migrate::run_if_needed(&core).await.is_err(), "the migration reports it");
}

// ── Fix round 1: route-specific members and namespaces seen by path ────

/// A token at root, child-visible, carrying `policies` (it may operate in
/// every namespace below root, as the requests below need).
async fn child_visible_token(core: &Arc<Core>, root: &str, policies: &[&str], ns: Option<&str>) -> String {
    let body = json!({ "policies": policies, "child_visible": true, "ttl": "1h" });
    let created = send(core, root, 1, Operation::Write, "auth/token/create", ns, body).await;
    created.unwrap().unwrap().auth.unwrap().client_token
}

/// Each `(api, path, namespace header)` read as `token`, in order.
async fn decisions(core: &Arc<Core>, token: &str, reqs: &[(u8, &str, Option<&str>)]) -> Vec<u16> {
    let mut out = Vec::new();
    for (api, path, ns) in reqs {
        out.push(status(&send(core, token, *api, Operation::Read, path, *ns, json!({})).await));
    }
    out
}

/// A member a multi-segment kv-v2 mount's lookup matched through one route
/// only keeps exactly that route after the migration (Ruling BB): before T507
/// `team/kv/data/z` gated the `data/` route of `z`, `team/kv/z` its short form.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn route_specific_members_keep_exactly_their_routes() {
    let (_bvault, core, root) = vault("t507_route_specific").await;
    write(&core, &root, "sys/mounts/team/kv/", json!({ "type": "kv-v2" })).await;
    seed_kv(&core, &root, &["team/kv/data/z"], None).await;
    secret_name_migrate::reset_for_test(&core).await.unwrap();
    plant_old_group(&core, "", "by-data", &["team/kv/data/z"]).await;
    plant_old_group(&core, "", "by-short", &["team/kv/z"]).await;
    gated(&core, &root, "in-by-data", "team/kv/", "by-data").await;
    gated(&core, &root, "in-by-short", "team/kv/", "by-short").await;
    let (u_data, _) = login(&core, &root, "user-data", "in-by-data").await;
    let (u_short, _) = login(&core, &root, "user-short", "in-by-short").await;
    let routes = [(1u8, "team/kv/data/z", None), (2, "team/kv/z", None), (1, "team/kv/metadata/z", None)];

    let before = (decisions(&core, &u_data, &routes).await, decisions(&core, &u_short, &routes).await);
    assert_eq!(before, (vec![200, 403, 403], vec![403, 200, 403]), "pending: one route each");
    secret_name_migrate::run_if_needed(&core).await.unwrap();
    let after = (decisions(&core, &u_data, &routes).await, decisions(&core, &u_short, &routes).await);
    assert_eq!(after, before, "after: the same routes, no widening");
}

/// Root's groups see a namespace's mounts by path, as the shared router
/// does: a root member of `team`'s kv-v2 `secret/` (a two-segment mount from
/// root), in its `data/` or short form, and one of `a/b`'s two levels down,
/// keep exactly what they gave; so does a member of `a`'s child `a/b`.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn members_of_namespaced_mounts_seen_by_path_keep_their_access() {
    let (_bvault, core, root) = vault("t507_ns_by_path").await;
    for ns in ["team", "a", "a/b"] {
        write(&core, &root, &format!("sys/namespaces/{ns}"), json!({})).await;
    }
    seed_kv(&core, &root, &["secret/data/x"], Some("team")).await;
    seed_kv(&core, &root, &["secret/data/x"], Some("a/b")).await;
    secret_name_migrate::reset_for_test(&core).await.unwrap();
    plant_old_group(&core, "", "rd", &["team/secret/data/x"]).await;
    plant_old_group(&core, "", "rs", &["team/secret/x"]).await;
    plant_old_group(&core, "", "deep", &["a/b/secret/data/x"]).await;
    plant_old_group(&core, "a", "child", &["b/secret/data/x"]).await;
    for (policy, prefix, group) in [("in-rd", "team/secret/", "rd"), ("in-rs", "team/secret/", "rs")] {
        gated(&core, &root, policy, prefix, group).await;
    }
    gated(&core, &root, "in-deep", "a/b/secret/", "deep").await;
    // A namespace policy may not name a child's paths: a root policy gated on
    // `a`'s group `child`, evaluated against the groups of the request's `a`.
    gated(&core, &root, "in-child", "a/b/secret/", "child").await;
    let rd = child_visible_token(&core, &root, &["in-rd"], None).await;
    let rs = child_visible_token(&core, &root, &["in-rs"], None).await;
    let deep = child_visible_token(&core, &root, &["in-deep"], None).await;
    let child = child_visible_token(&core, &root, &["in-child"], None).await;

    let team = [(1u8, "team/secret/data/x", None), (2, "team/secret/x", None), (1, "team/secret/metadata/x", None)];
    let deep_reqs = [(1u8, "a/b/secret/data/x", None), (1, "a/b/secret/metadata/x", None)];
    let child_reqs = [(1u8, "b/secret/data/x", Some("a")), (1, "b/secret/metadata/x", Some("a"))];
    let all = |core: Arc<Core>| {
        let (rd, rs, deep, child) = (rd.clone(), rs.clone(), deep.clone(), child.clone());
        async move {
            vec![
                decisions(&core, &rd, &team).await,
                decisions(&core, &rs, &team).await,
                decisions(&core, &deep, &deep_reqs).await,
                decisions(&core, &child, &child_reqs).await,
            ]
        }
    };
    let before = all(core.clone()).await;
    assert_eq!(before, [vec![200, 403, 403], vec![403, 200, 403], vec![200, 403], vec![200, 403]], "pending");
    secret_name_migrate::run_if_needed(&core).await.unwrap();
    assert_eq!(all(core.clone()).await, before, "after: nothing lost, nothing widened");
}

/// While the pass runs, and after its marker, a group-gated allow and a
/// group-gated deny keep their decisions after every step, the index the
/// lookups read never loses the members, and the T499 datafix rebuilding
/// the legacy index midway changes nothing (T507 review, fix round 1).
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn decisions_hold_at_every_step_of_the_migration() {
    use crate::modules::identity::kv_key_split_migrate;
    let (_bvault, core, root) = vault("t507_every_step").await;
    write(&core, &root, "sys/mounts/kv/", json!({ "type": "kv" })).await;
    seed_kv(&core, &root, &["kv/x", "kv/y", "kv/data/x"], None).await;
    secret_name_migrate::reset_for_test(&core).await.unwrap();
    for (group, member) in [("a-first", "kv/a"), ("allowg", "kv/x"), ("denyg", "kv/y"), ("z-last", "kv/z")] {
        plant_old_group(&core, "", group, &[member]).await;
    }
    gated(&core, &root, "in-allowg", "kv/", "allowg").await;
    write_policy(&core, &root, "reads-kv", "path \"kv/*\" { capabilities = [\"read\"] }\n").await;
    let hcl = "path \"kv/*\" {\n  capabilities = [\"deny\"]\n  groups = [\"denyg\"]\n}\n";
    write_policy(&core, &root, "denies-denyg", hcl).await;
    let (allowed, _) = login(&core, &root, "user-allow", "in-allowg").await;
    let (denied, _) = login(&core, &root, "user-deny", "reads-kv,denies-denyg").await;
    let check = |when: String| {
        let (core, allowed, denied) = (core.clone(), allowed.clone(), denied.clone());
        async move {
            let allow = decisions(&core, &allowed, &[(1, "kv/x", None), (1, "kv/data/x", None), (1, "kv/y", None)]);
            assert_eq!(allow.await, [200, 200, 403], "the gated allow, {when}");
            let deny = decisions(&core, &denied, &[(1, "kv/y", None), (1, "kv/x", None)]);
            assert_eq!(deny.await, [403, 200], "the gated deny, {when}");
            let s = store(&core);
            let (x, y) = match s.secret_names().await.unwrap() {
                true => (s.groups_for_secret_name("kv/x", "").await, s.groups_for_secret_name("kv/y", "").await),
                false => (s.groups_for_legacy_secret("kv/x", "").await, s.groups_for_legacy_secret("kv/y", "").await),
            };
            assert_eq!((x.unwrap(), y.unwrap()), (vec!["allowg".to_string()], vec!["denyg".to_string()]), "{when}");
        }
    };

    check("before the pass".into()).await;
    let mut pass = secret_name_migrate::SecretNameMigration::start(&core).await.unwrap().unwrap();
    let mut step = 0;
    while pass.step().await.unwrap() {
        step += 1;
        check(format!("after step {step}")).await;
        if step == 2 {
            // The T499 datafix finishing midway rebuilds the legacy index.
            kv_key_split_migrate::reset_for_test(&core).await.unwrap();
            kv_key_split_migrate::run_if_needed(&core).await.unwrap();
            check("after the T499 datafix ran midway".into()).await;
        }
    }
    assert!(store(&core).secret_names().await.unwrap(), "marked");
    assert!(step >= 7, "convert x4, verify, mark, final: {step}");
    assert_eq!(pass.report().members_ambiguous, 4, "{:?}", pass.report());
}

/// A failed T507 pass, with the T499 datafix already done, schedules the
/// background retry, which completes T507 once the cause is gone.
#[tokio::test]
async fn a_failed_asset_group_pass_is_retried_until_it_completes() {
    use std::time::Duration;

    use crate::{kernel_api::pipeline::NsScopeDatafix, modules::identity::IdentityModule};
    let (_bvault, core, _root) = new_unseal_test_bastion_vault("t507_retry").await;
    let identity = core.module_manager().get_module::<IdentityModule>("identity").unwrap();
    identity.kv_split_retry.set_first_delay_for_test(Duration::from_millis(300));
    store(&core).garble_secret_names_marker_for_test().await.unwrap();

    assert!(identity.run_if_needed().await.is_err(), "the T507 pass fails at unseal");
    assert!(identity.kv_split_retry.running(), "a background retry is scheduled");
    for _ in 0..500 {
        if identity.kv_split_retry.failures_for_test() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(identity.kv_split_retry.failures_for_test() >= 1, "a retry failed while the marker was garbled");

    store(&core).unmark_secret_names_for_test().await.unwrap();
    for _ in 0..1000 {
        if store(&core).secret_names().await.unwrap() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(store(&core).secret_names().await.unwrap(), "a later retry completed T507");
    for _ in 0..500 {
        if !identity.kv_split_retry.running() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!identity.kv_split_retry.running(), "and the task ended");
}
