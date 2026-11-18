//! Lifted from `crates/bv-kernel/src/modules/resource_group/mod.rs`.
//!
//! These tests build a whole vault through `test_utils`, then look modules and
//! stores back up by type. That only works where the vault is *constructed* —
//! `bv-kernel`'s own test binary is a separate compilation of the crate from
//! the rlib `bastion_vault` links, so `get_module::<T>()` sees two different
//! `TypeId`s for the same type and every lookup returns `None`. Fifth instance
//! of "tests that could not travel", and the first caused by type identity
//! rather than by a missing dependency. See
//! roadmaps/workspace-decomposition.md § Phase 4.5.

// The parent's import list, written out. A `use super::*` glob sees a module's
// *private* `use` statements only from inside the same crate, so lifting these
// blocks out of `bv-kernel` cost them every name the parent had imported. This
// is the fourth time this decomposition has hit that (Phase 3 § "The alias
// preamble"); the fix is the same one.
#[allow(unused_imports)]
use crate::{
    core::Core,
    errors::RvError,
    kernel_api::VaultCtx,
    logical::{Operation, Request},
    storage::StorageEntry,
};
#[allow(unused_imports)]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
#[allow(unused_imports)]
use serde_json::Value;
#[allow(unused_imports)]
use std::{collections::HashMap, sync::Arc};

use serde_json::json;

use crate::modules::resource_group::*;
use crate::test_utils::{new_unseal_test_bastion_vault, test_delete_api, test_list_api, test_read_api, test_write_api};

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_asset_group_member_redaction_for_non_owner() {
    // Members the caller cannot read are replaced with `<hidden>`
    // on group read, but only for non-owner / non-admin callers.
    // Owners and admins see everything unredacted.
    use serde_json::json as j;
    let (_bvault, core, root_token) =
        new_unseal_test_bastion_vault("test_asset_group_member_redaction_for_non_owner").await;

    // Create a custom policy: lets the caller read asset-group
    // entries AND read KV secrets under `secret/data/ok/*`. That
    // means they can read the group record but not secrets
    // under `secret/data/forbidden/*`.
    let _ = test_write_api(
        &core,
        &root_token,
        "sys/policies/acl/redaction-tester",
        true,
        j!({
            "policy": r#"
                    path "resource-group/groups/*" {
                        capabilities = ["read", "list"]
                    }
                    path "secret/data/ok/*" {
                        capabilities = ["read"]
                    }
                "#
        })
        .as_object()
        .cloned(),
    )
    .await
    .unwrap();

    // Provision a userpass user with the policy.
    let _ =
        test_write_api(&core, &root_token, "sys/auth/pass-r", true, j!({ "type": "userpass" }).as_object().cloned())
            .await;
    let _ = test_write_api(
        &core,
        &root_token,
        "auth/pass-r/users/carol",
        true,
        j!({
            "password": "hunter22XX!",
            "token_policies": "redaction-tester",
            "ttl": 0,
        })
        .as_object()
        .cloned(),
    )
    .await;

    // Root creates an asset group whose `secrets` list has one
    // path Carol can read (`secret/ok/a`) and one she can't
    // (`secret/forbidden/a`). Plus a resource member Carol can't
    // read (no `resources/*` grant in her policy).
    let _ = test_write_api(
        &core,
        &root_token,
        "resource-group/groups/mixed-visibility",
        true,
        j!({
            "description": "mixed",
            "members": "alpha",
            "secrets": "secret/ok/a,secret/forbidden/a",
        })
        .as_object()
        .cloned(),
    )
    .await
    .unwrap();

    // Login as Carol.
    let mut login_req = Request::new("auth/pass-r/login/carol");
    login_req.operation = Operation::Write;
    login_req.body = j!({ "password": "hunter22XX!" }).as_object().cloned();
    let resp = core.handle_request(&mut login_req).await.unwrap().unwrap();
    let carol_token = resp.auth.unwrap().client_token;

    // Sanity: write a KV-v2 entry at secret/data/ok/a and confirm
    // Carol's policy actually grants her Read on it.
    let _ = test_write_api(
        &core,
        &root_token,
        "secret/data/ok/a",
        true,
        j!({ "data": { "v": "hi" } }).as_object().cloned(),
    )
    .await
    .unwrap();
    let _ = test_read_api(&core, &carol_token, "secret/data/ok/a", true).await.unwrap();

    // Carol reads the group: secret/ok/a stays, secret/forbidden/a
    // and the resource member (alpha) become `<hidden>`.
    let resp =
        test_read_api(&core, &carol_token, "resource-group/groups/mixed-visibility", true).await.unwrap().unwrap();
    let body = resp.data.unwrap();
    let members = body.get("members").and_then(|v| v.as_array()).unwrap().clone();
    let secrets = body.get("secrets").and_then(|v| v.as_array()).unwrap().clone();

    assert_eq!(
        members,
        vec![Value::String(REDACTED_MEMBER.to_string())],
        "resource members Carol can't read should be redacted",
    );
    let secrets_strs: Vec<String> = secrets.iter().map(|v| v.as_str().unwrap_or("").to_string()).collect();
    assert!(
        secrets_strs.contains(&"secret/ok/a".to_string()),
        "visible secret should be unredacted, got {secrets_strs:?}",
    );
    assert!(
        secrets_strs.contains(&REDACTED_MEMBER.to_string()),
        "forbidden secret should be redacted, got {secrets_strs:?}",
    );
    assert!(
        !secrets_strs.contains(&"secret/forbidden/a".to_string()),
        "forbidden secret path must not leak: {secrets_strs:?}",
    );

    // Root (admin) reads the same group and sees everything unredacted.
    let resp =
        test_read_api(&core, &root_token, "resource-group/groups/mixed-visibility", true).await.unwrap().unwrap();
    let body = resp.data.unwrap();
    let secrets_strs: Vec<String> = body
        .get("secrets")
        .and_then(|v| v.as_array())
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();
    assert!(secrets_strs.contains(&"secret/ok/a".to_string()));
    assert!(secrets_strs.contains(&"secret/forbidden/a".to_string()));
    assert!(!secrets_strs.contains(&REDACTED_MEMBER.to_string()));
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_asset_group_admin_owner_transfer_roundtrip() {
    let (_bvault, core, root_token) =
        new_unseal_test_bastion_vault("test_asset_group_admin_owner_transfer_roundtrip").await;

    // Root creates the group — owner_entity_id stays empty because
    // the root token has no entity_id metadata.
    let data = json!({ "description": "root-created" }).as_object().cloned();
    let _ = test_write_api(&core, &root_token, "resource-group/groups/bundle-a", true, data).await.unwrap();

    let resp = test_read_api(&core, &root_token, "resource-group/groups/bundle-a", true).await.unwrap().unwrap();
    let body = resp.data.unwrap();
    assert_eq!(
        body.get("owner_entity_id").and_then(|v| v.as_str()).unwrap_or("missing"),
        "",
        "root-created groups start unowned",
    );

    // Admin transfer — populate the owner.
    let xfer = json!({
        "name": "bundle-a",
        "new_owner_entity_id": "ent-owner-1",
    })
    .as_object()
    .cloned();
    let _ = test_write_api(&core, &root_token, "sys/asset-group-owner/transfer", true, xfer).await.unwrap();

    let resp = test_read_api(&core, &root_token, "resource-group/groups/bundle-a", true).await.unwrap().unwrap();
    let body = resp.data.unwrap();
    assert_eq!(body.get("owner_entity_id").and_then(|v| v.as_str()).unwrap_or(""), "ent-owner-1",);

    // A subsequent `set_group` write must not change the owner.
    let update = json!({ "description": "updated description" }).as_object().cloned();
    let _ = test_write_api(&core, &root_token, "resource-group/groups/bundle-a", true, update).await.unwrap();

    let resp = test_read_api(&core, &root_token, "resource-group/groups/bundle-a", true).await.unwrap().unwrap();
    let body = resp.data.unwrap();
    assert_eq!(
        body.get("owner_entity_id").and_then(|v| v.as_str()).unwrap_or(""),
        "ent-owner-1",
        "owner must survive regular writes",
    );
    assert_eq!(body.get("description").and_then(|v| v.as_str()).unwrap_or(""), "updated description",);
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_resource_group_crud() {
    let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_resource_group_crud").await;

    // Create a group with members.
    let data = json!({
        "description": "project phoenix resources",
        "members": "web-01,db-01",
    })
    .as_object()
    .cloned();
    let ret = test_write_api(&core, &root_token, "resource-group/groups/phoenix", true, data).await;
    assert!(ret.is_ok());

    // Read back.
    let resp = test_read_api(&core, &root_token, "resource-group/groups/phoenix", true).await.unwrap().unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["name"], "phoenix");
    assert_eq!(data["description"], "project phoenix resources");
    // Members are canonicalized: lowercased, deduped, sorted.
    assert_eq!(data["members"], json!(["db-01", "web-01"]));
    // No secrets were supplied; the field is present and empty.
    assert_eq!(data["secrets"], json!([] as [String; 0]));

    // List.
    let resp = test_list_api(&core, &root_token, "resource-group/groups", true).await.unwrap().unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["keys"], json!(["phoenix"]));

    // Partial update: description only, members preserved.
    let patch = json!({ "description": "project phoenix (updated)" }).as_object().cloned();
    let _ = test_write_api(&core, &root_token, "resource-group/groups/phoenix", true, patch).await;
    let resp = test_read_api(&core, &root_token, "resource-group/groups/phoenix", true).await.unwrap().unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["description"], "project phoenix (updated)");
    assert_eq!(data["members"], json!(["db-01", "web-01"]));

    // Delete.
    let _ = test_delete_api(&core, &root_token, "resource-group/groups/phoenix", true, None).await;
    let resp = test_read_api(&core, &root_token, "resource-group/groups/phoenix", false).await;
    assert!(resp.is_err());
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_resource_group_reverse_index() {
    let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_resource_group_reverse_index").await;

    // `web-01` lives in two groups.
    let a = json!({ "members": "web-01,db-01" }).as_object().cloned();
    let _ = test_write_api(&core, &root_token, "resource-group/groups/alpha", true, a).await;

    let b = json!({ "members": "web-01,api-01" }).as_object().cloned();
    let _ = test_write_api(&core, &root_token, "resource-group/groups/beta", true, b).await;

    // by-resource lookup returns both group names, sorted.
    let resp = test_read_api(&core, &root_token, "resource-group/by-resource/web-01", true).await.unwrap().unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["groups"], json!(["alpha", "beta"]));

    // `db-01` is only in alpha.
    let resp = test_read_api(&core, &root_token, "resource-group/by-resource/db-01", true).await.unwrap().unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["groups"], json!(["alpha"]));

    // Remove web-01 from alpha -> by-resource should only return beta.
    let patch = json!({ "members": "db-01" }).as_object().cloned();
    let _ = test_write_api(&core, &root_token, "resource-group/groups/alpha", true, patch).await;

    let resp = test_read_api(&core, &root_token, "resource-group/by-resource/web-01", true).await.unwrap().unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["groups"], json!(["beta"]));

    // Delete beta -> web-01 is in no groups; by-resource returns empty.
    let _ = test_delete_api(&core, &root_token, "resource-group/groups/beta", true, None).await;
    let resp = test_read_api(&core, &root_token, "resource-group/by-resource/web-01", true).await.unwrap().unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["groups"], json!([] as [String; 0]));
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_resource_group_rename_resource() {
    let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_resource_group_rename_resource").await;

    // `old01` is a member of two groups; `keep01` sits alongside it in one.
    let a = json!({ "members": "old01,keep01" }).as_object().cloned();
    let _ = test_write_api(&core, &root_token, "resource-group/groups/alpha", true, a).await;
    let b = json!({ "members": "old01" }).as_object().cloned();
    let _ = test_write_api(&core, &root_token, "resource-group/groups/beta", true, b).await;

    let store = core
        .module_manager()
        .get_module::<ResourceGroupModule>("resource-group")
        .and_then(|m| m.store())
        .expect("resource-group store");

    let groups = store.rename_resource("old01", "new01", "").await.unwrap();
    assert_eq!(groups.len(), 2, "old01 belonged to two groups");

    // Reverse index moved: new01 in both groups, old01 in none.
    let resp = test_read_api(&core, &root_token, "resource-group/by-resource/new01", true).await.unwrap().unwrap();
    assert_eq!(resp.data.unwrap()["groups"], json!(["alpha", "beta"]));
    let resp = test_read_api(&core, &root_token, "resource-group/by-resource/old01", true).await.unwrap().unwrap();
    assert_eq!(resp.data.unwrap()["groups"], json!([] as [String; 0]));

    // The primary records list the new member; `keep01` is untouched.
    let resp = test_read_api(&core, &root_token, "resource-group/groups/alpha", true).await.unwrap().unwrap();
    let members = resp.data.unwrap()["members"].as_array().cloned().unwrap();
    assert!(members.contains(&json!("new01")));
    assert!(members.contains(&json!("keep01")));
    assert!(!members.contains(&json!("old01")));
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_resource_group_acl_groups_qualifier() {
    let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_resource_group_acl_groups_qualifier").await;

    // Policy that grants read on any resource, but only when the
    // target resource is a member of the "club" asset-group.
    let gated_hcl = r#"
            path "resources/resources/*" {
                capabilities = ["read"]
                groups = ["club"]
            }
        "#;
    let _ = test_write_api(
        &core,
        &root_token,
        "sys/policy/p-gated",
        true,
        json!({ "policy": gated_hcl }).as_object().cloned(),
    )
    .await;

    // Create two resources as root so there is something to read.
    let _ = test_write_api(
        &core,
        &root_token,
        "resources/resources/alpha",
        true,
        json!({ "type": "server", "hostname": "alpha.local" }).as_object().cloned(),
    )
    .await;
    let _ = test_write_api(
        &core,
        &root_token,
        "resources/resources/beta",
        true,
        json!({ "type": "server", "hostname": "beta.local" }).as_object().cloned(),
    )
    .await;

    // Put alpha in the "club" resource-group; leave beta out.
    let _ = test_write_api(
        &core,
        &root_token,
        "resource-group/groups/club",
        true,
        json!({ "members": "alpha" }).as_object().cloned(),
    )
    .await;

    // Mount userpass and create alice with only the gated policy.
    let _ =
        test_write_api(&core, &root_token, "sys/auth/pass", true, json!({ "type": "userpass" }).as_object().cloned())
            .await;
    let _ = test_write_api(
        &core,
        &root_token,
        "auth/pass/users/alice",
        true,
        json!({
            "password": "hunter22XX!",
            "token_policies": "p-gated",
            "ttl": 0,
        })
        .as_object()
        .cloned(),
    )
    .await;

    // Login as alice.
    let mut login_req = Request::new("auth/pass/login/alice");
    login_req.operation = Operation::Write;
    login_req.body = json!({ "password": "hunter22XX!" }).as_object().cloned();
    let resp = core.handle_request(&mut login_req).await.unwrap().unwrap();
    let token = resp.auth.unwrap().client_token;

    // alpha is in "club" → read allowed.
    let _ = test_read_api(&core, &token, "resources/resources/alpha", true).await;

    // beta is not in "club" → read denied by the `groups` gate.
    let err = test_read_api(&core, &token, "resources/resources/beta", false).await;
    assert!(err.is_err());

    // Move membership: drop alpha, add beta. Membership changes take
    // effect on the next request without re-login — the evaluator
    // resolves asset-groups per post_auth call.
    let _ = test_write_api(
        &core,
        &root_token,
        "resource-group/groups/club",
        true,
        json!({ "members": "beta" }).as_object().cloned(),
    )
    .await;

    let _ = test_read_api(&core, &token, "resources/resources/beta", true).await;
    let err = test_read_api(&core, &token, "resources/resources/alpha", false).await;
    assert!(err.is_err());
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_resource_delete_prunes_from_groups() {
    let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_resource_delete_prunes_from_groups").await;

    // Create resource + group containing it.
    let _ = test_write_api(
        &core,
        &root_token,
        "resources/resources/web-01",
        true,
        json!({ "type": "server" }).as_object().cloned(),
    )
    .await;
    let _ = test_write_api(
        &core,
        &root_token,
        "resource-group/groups/ops",
        true,
        json!({ "members": "web-01,db-01" }).as_object().cloned(),
    )
    .await;

    // Verify before-state: web-01 is listed in the group.
    let resp = test_read_api(&core, &root_token, "resource-group/groups/ops", true).await.unwrap().unwrap();
    assert_eq!(resp.data.unwrap()["members"], json!(["db-01", "web-01"]));

    // Delete the resource. Lifecycle hook must prune it from the group.
    let _ = test_delete_api(&core, &root_token, "resources/resources/web-01", true, None).await;

    let resp = test_read_api(&core, &root_token, "resource-group/groups/ops", true).await.unwrap().unwrap();
    assert_eq!(resp.data.unwrap()["members"], json!(["db-01"]));

    // And the reverse-lookup for the deleted resource is empty.
    let resp = test_read_api(&core, &root_token, "resource-group/by-resource/web-01", true).await.unwrap().unwrap();
    assert_eq!(resp.data.unwrap()["groups"], json!([] as [String; 0]));
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_resource_group_secret_membership_by_own_name() {
    let (_bvault, core, root_token) =
        new_unseal_test_bastion_vault("test_resource_group_secret_membership_by_own_name").await;

    // Group with a mix of resources and secrets. Each secret is its own
    // `<mount>/<name>`, stored as given (T507): on this KV v2 mount
    // `secret/data/foo/bar` is the secret `data/foo/bar`, not `foo/bar`.
    let data = json!({
        "members": "web-01",
        "secrets": "secret/foo/bar,/secret/data/foo/bar/,secret/metadata/baz,secret/baz,secret/baz",
    })
    .as_object()
    .cloned();
    let _ = test_write_api(&core, &root_token, "resource-group/groups/mix", true, data).await;

    let resp = test_read_api(&core, &root_token, "resource-group/groups/mix", true).await.unwrap().unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["members"], json!(["web-01"]));
    // Trimmed, deduped and sorted; nothing stripped.
    assert_eq!(data["secrets"], json!(["secret/baz", "secret/data/foo/bar", "secret/foo/bar", "secret/metadata/baz"]));

    // by-secret reverse lookup. The handler accepts base64url(no-pad).
    fn b64(s: &str) -> String {
        URL_SAFE_NO_PAD.encode(s.as_bytes())
    }

    // Each secret by its own name.
    for name in ["secret/foo/bar", "secret/data/foo/bar", "secret/metadata/baz"] {
        let path = format!("resource-group/by-secret/{}", b64(name));
        let resp = test_read_api(&core, &root_token, &path, true).await.unwrap().unwrap();
        assert_eq!(resp.data.unwrap()["groups"], json!(["mix"]), "{name}");
    }
    // A secret no member names: `metadata/foo/bar` is not `foo/bar`.
    let path = format!("resource-group/by-secret/{}", b64("secret/metadata/foo/bar"));
    let resp = test_read_api(&core, &root_token, &path, true).await.unwrap().unwrap();
    assert_eq!(resp.data.unwrap()["groups"], json!([] as [String; 0]));

    // Unrelated path → empty result.
    let path = format!("resource-group/by-secret/{}", b64("secret/other"));
    let resp = test_read_api(&core, &root_token, &path, true).await.unwrap().unwrap();
    assert_eq!(resp.data.unwrap()["groups"], json!([] as [String; 0]));

    // Removing the secret from the group clears the reverse index.
    let patch = json!({ "secrets": "secret/baz" }).as_object().cloned();
    let _ = test_write_api(&core, &root_token, "resource-group/groups/mix", true, patch).await;
    let path = format!("resource-group/by-secret/{}", b64("secret/foo/bar"));
    let resp = test_read_api(&core, &root_token, &path, true).await.unwrap().unwrap();
    assert_eq!(resp.data.unwrap()["groups"], json!([] as [String; 0]));
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_resource_group_acl_groups_qualifier_kv() {
    let (_bvault, core, root_token) =
        new_unseal_test_bastion_vault("test_resource_group_acl_groups_qualifier_kv").await;

    // Policy granting read on any KV v1 path, gated on membership
    // in asset-group "kv-club". Uses KV-v1 to keep the path shape
    // simple (no v2 `/data/` hop).
    let gated_hcl = r#"
            path "kv/*" {
                capabilities = ["read"]
                groups = ["kv-club"]
            }
        "#;
    let _ = test_write_api(
        &core,
        &root_token,
        "sys/policy/p-gated-kv",
        true,
        json!({ "policy": gated_hcl }).as_object().cloned(),
    )
    .await;

    // Mount KV-v1 at `kv/` and put two values in it.
    let _ =
        test_write_api(&core, &root_token, "sys/mounts/kv/", true, json!({ "type": "kv" }).as_object().cloned()).await;
    let _ = test_write_api(&core, &root_token, "kv/alpha", true, json!({ "v": "1" }).as_object().cloned()).await;
    let _ = test_write_api(&core, &root_token, "kv/beta", true, json!({ "v": "2" }).as_object().cloned()).await;

    // Put kv/alpha (only) in the "kv-club" asset-group.
    let _ = test_write_api(
        &core,
        &root_token,
        "resource-group/groups/kv-club",
        true,
        json!({ "secrets": "kv/alpha" }).as_object().cloned(),
    )
    .await;

    // Create user alice with only the gated policy.
    let _ =
        test_write_api(&core, &root_token, "sys/auth/pass", true, json!({ "type": "userpass" }).as_object().cloned())
            .await;
    let _ = test_write_api(
        &core,
        &root_token,
        "auth/pass/users/alice",
        true,
        json!({
            "password": "hunter22XX!",
            "token_policies": "p-gated-kv",
            "ttl": 0,
        })
        .as_object()
        .cloned(),
    )
    .await;

    // Login as alice.
    let mut login_req = Request::new("auth/pass/login/alice");
    login_req.operation = Operation::Write;
    login_req.body = json!({ "password": "hunter22XX!" }).as_object().cloned();
    let resp = core.handle_request(&mut login_req).await.unwrap().unwrap();
    let token = resp.auth.unwrap().client_token;

    // kv/alpha is in "kv-club" → read allowed.
    let _ = test_read_api(&core, &token, "kv/alpha", true).await;

    // kv/beta is not in any group → gated rule contributes nothing
    // and no other rule applies → denied.
    let err = test_read_api(&core, &token, "kv/beta", false).await;
    assert!(err.is_err());

    // Swap membership: kv/beta joins, kv/alpha leaves.
    let _ = test_write_api(
        &core,
        &root_token,
        "resource-group/groups/kv-club",
        true,
        json!({ "secrets": "kv/beta" }).as_object().cloned(),
    )
    .await;

    let _ = test_read_api(&core, &token, "kv/beta", true).await;
    let err = test_read_api(&core, &token, "kv/alpha", false).await;
    assert!(err.is_err());
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_resource_group_history() {
    let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_resource_group_history").await;

    let create = json!({
        "description": "initial",
        "members": "a,b",
    })
    .as_object()
    .cloned();
    let _ = test_write_api(&core, &root_token, "resource-group/groups/team", true, create).await;

    let update = json!({ "members": "a,b,c" }).as_object().cloned();
    let _ = test_write_api(&core, &root_token, "resource-group/groups/team", true, update).await;

    let resp = test_read_api(&core, &root_token, "resource-group/groups/team/history", true).await.unwrap().unwrap();
    let data = resp.data.unwrap();
    let entries = data["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    // Newest first: the update entry.
    assert_eq!(entries[0]["op"], "update");
    assert_eq!(entries[0]["changed_fields"], json!(["members"]));
    assert_eq!(entries[0]["before"]["members"], json!(["a", "b"]));
    assert_eq!(entries[0]["after"]["members"], json!(["a", "b", "c"]));
    // Oldest last: the create.
    assert_eq!(entries[1]["op"], "create");
}

/// Mounts a KV-v1 engine at `kv/` with `alpha`, `beta` and `gamma`, puts
/// `alpha` and `beta` in asset group `crew`, logs in a userpass user holding
/// only a policy written from `hcl`, and returns the keys that user's LIST of
/// `kv/` comes back with.
async fn list_kv_under_policy(name: &str, hcl: &str) -> Vec<String> {
    let (_bvault, core, root_token) = new_unseal_test_bastion_vault(name).await;

    let _ =
        test_write_api(&core, &root_token, "sys/policy/p-list", true, json!({ "policy": hcl }).as_object().cloned())
            .await;

    // KV-v1 mount with three secrets; two join the crew, one stays out.
    let _ =
        test_write_api(&core, &root_token, "sys/mounts/kv/", true, json!({ "type": "kv" }).as_object().cloned()).await;
    for k in ["alpha", "beta", "gamma"] {
        let _ = test_write_api(&core, &root_token, &format!("kv/{k}"), true, json!({ "v": "x" }).as_object().cloned())
            .await;
    }
    let _ = test_write_api(
        &core,
        &root_token,
        "resource-group/groups/crew",
        true,
        json!({ "secrets": "kv/alpha,kv/beta" }).as_object().cloned(),
    )
    .await;

    // alice gets the policy under test.
    let _ =
        test_write_api(&core, &root_token, "sys/auth/pass", true, json!({ "type": "userpass" }).as_object().cloned())
            .await;
    let _ = test_write_api(
        &core,
        &root_token,
        "auth/pass/users/alice",
        true,
        json!({
            "password": "hunter22XX!",
            "token_policies": "p-list",
            "ttl": 0,
        })
        .as_object()
        .cloned(),
    )
    .await;

    let mut login_req = Request::new("auth/pass/login/alice");
    login_req.operation = Operation::Write;
    login_req.body = json!({ "password": "hunter22XX!" }).as_object().cloned();
    let resp = core.handle_request(&mut login_req).await.unwrap().unwrap();
    let token = resp.auth.unwrap().client_token;

    let resp = test_list_api(&core, &token, "kv/", true).await.unwrap().unwrap();
    let data = resp.data.unwrap();
    data["keys"].as_array().unwrap().iter().filter_map(|v| v.as_str().map(str::to_string)).collect()
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_list_filter_on_groups_gated_list_kv() {
    // Policy grants read+list on kv/*, gated on membership in "crew".
    // The list op can't literally "belong to a group" — the
    // post-route filter narrows the returned keys to group members.
    let gated_hcl = r#"
            path "kv/*" {
                capabilities = ["read", "list"]
                groups = ["crew"]
            }
        "#;
    // Listing kv/ as alice returns only group members — alpha, beta.
    // gamma lives in no group, so it is filtered out.
    let names = list_kv_under_policy("test_list_filter_on_groups_gated_list_kv", gated_hcl).await;
    assert!(names.iter().any(|n| n == "alpha"), "expected alpha in {names:?}");
    assert!(names.iter().any(|n| n == "beta"), "expected beta in {names:?}");
    assert!(!names.iter().any(|n| n == "gamma"), "gamma should be filtered out of {names:?}");
}

/// F7 (T120): the exact rule for `kv/` governs the LIST and withholds `list`;
/// the broader `kv*` prefix rule carries `list` but does not govern. Only the
/// gated rule grants the LIST, so the response stays narrowed to `crew`.
/// Before T120 the non-governing rule lifted the filter and `gamma` leaked.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_list_filter_survives_a_non_governing_list_rule() {
    let hcl = r#"
            path "kv/" {
                capabilities = ["read"]
            }
            path "kv*" {
                capabilities = ["list"]
            }
            path "kv/*" {
                capabilities = ["read", "list"]
                groups = ["crew"]
            }
        "#;
    let names = list_kv_under_policy("test_list_filter_survives_a_non_governing_list_rule", hcl).await;
    assert!(names.iter().any(|n| n == "alpha"), "expected alpha in {names:?}");
    assert!(names.iter().any(|n| n == "beta"), "expected beta in {names:?}");
    assert!(!names.iter().any(|n| n == "gamma"), "gamma leaked through a non-governing rule: {names:?}");
}

/// The governing rule itself granting `list` still lifts the filter: the
/// caller may list everything without the gated rule.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_list_filter_lifted_by_the_governing_rule() {
    let hcl = r#"
            path "kv/" {
                capabilities = ["list"]
            }
            path "kv/*" {
                capabilities = ["read", "list"]
                groups = ["crew"]
            }
        "#;
    let names = list_kv_under_policy("test_list_filter_lifted_by_the_governing_rule", hcl).await;
    assert!(names.iter().any(|n| n == "gamma"), "the governing list grant should return every key: {names:?}");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_kv_delete_prunes_from_groups() {
    let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_kv_delete_prunes_from_groups").await;

    // KV-v1 mount, one secret, and a group containing it.
    let _ =
        test_write_api(&core, &root_token, "sys/mounts/kv/", true, json!({ "type": "kv" }).as_object().cloned()).await;
    let _ = test_write_api(&core, &root_token, "kv/s1", true, json!({ "v": "x" }).as_object().cloned()).await;
    let _ = test_write_api(
        &core,
        &root_token,
        "resource-group/groups/club",
        true,
        json!({ "secrets": "kv/s1,kv/s2" }).as_object().cloned(),
    )
    .await;

    // Precondition: s1 and s2 are both listed as members.
    let resp = test_read_api(&core, &root_token, "resource-group/groups/club", true).await.unwrap().unwrap();
    assert_eq!(resp.data.unwrap()["secrets"], json!(["kv/s1", "kv/s2"]));

    // Delete kv/s1 — the post-route hook prunes it from the group.
    let _ = test_delete_api(&core, &root_token, "kv/s1", true, None).await;

    let resp = test_read_api(&core, &root_token, "resource-group/groups/club", true).await.unwrap().unwrap();
    // kv/s1 is gone; kv/s2 remains (never deleted).
    assert_eq!(resp.data.unwrap()["secrets"], json!(["kv/s2"]));
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_policy_write_warns_on_unknown_groups() {
    let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_policy_write_warns_on_unknown_groups").await;

    // Create one real group so the check can distinguish "unknown"
    // from "no group subsystem present".
    let _ =
        test_write_api(&core, &root_token, "resource-group/groups/real", true, json!({}).as_object().cloned()).await;

    let policy_hcl = r#"
            path "resources/resources/*" {
                capabilities = ["read"]
                groups = ["real", "typo-here", "other-typo"]
            }
        "#;

    // Write the policy. Unknown group names trigger a warning on
    // the response; the write still succeeds.
    let resp = test_write_api(
        &core,
        &root_token,
        "sys/policy/p-typo",
        true,
        json!({ "policy": policy_hcl }).as_object().cloned(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(resp.warnings.len(), 1, "expected one warning, got {:?}", resp.warnings);
    let w = &resp.warnings[0];
    assert!(w.contains("typo-here"), "warning did not mention typo-here: {w}");
    assert!(w.contains("other-typo"), "warning did not mention other-typo: {w}");
    assert!(!w.contains("\"real\""), "warning should not flag the real group: {w}");
}

/// A tenant user who is neither the group's owner nor an admin must see the
/// members their tenant policy lets them read. The redaction probe used to
/// test the bare `resources/resources/<name>`, which no tenant policy can
/// match (tenant rules must carry the `<ns>/` prefix), so every member came
/// back as `<hidden>` and the GUI had no groups to show.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_asset_group_member_redaction_honors_namespace_prefix() {
    use crate::test_utils::test_mount_auth_api;

    let (_bvault, core, root) =
        new_unseal_test_bastion_vault("test_asset_group_member_redaction_honors_namespace_prefix").await;

    async fn ns_req(
        core: &dyn VaultCtx,
        token: &str,
        op: Operation,
        path: &str,
        ns: &str,
        body: Option<serde_json::Map<String, Value>>,
    ) -> Result<Option<crate::logical::Response>, RvError> {
        let mut req = Request::new(path);
        req.operation = op;
        req.client_token = token.to_string();
        req.body = body;
        let mut h = HashMap::new();
        h.insert("x-bastionvault-namespace".to_string(), ns.to_string());
        req.headers = Some(h);
        core.handle_request(&mut req).await
    }

    test_write_api(&core, &root, "sys/namespaces/tenant-a", true, json!({}).as_object().cloned()).await.unwrap();
    // A namespace created through `sys/namespaces` already carries `resources/`
    // and `resource-group/`; mounting either again is `ErrMountPathExist`.
    for name in ["web1", "db1"] {
        ns_req(
            &core,
            &root,
            Operation::Write,
            &format!("resources/resources/{name}"),
            "tenant-a",
            json!({ "name": name, "type": "server", "hostname": "h.example" }).as_object().cloned(),
        )
        .await
        .unwrap();
    }
    ns_req(
        &core,
        &root,
        Operation::Write,
        "resource-group/groups/g",
        "tenant-a",
        json!({ "description": "g", "members": "web1,db1" }).as_object().cloned(),
    )
    .await
    .unwrap();

    // dave may read the group and `web1` only, written the way a tenant
    // policy must be: with the namespace prefix.
    ns_req(
        &core,
        &root,
        Operation::Write,
        "sys/policy/dave-p",
        "tenant-a",
        json!({ "policy": r#"
            path "tenant-a/resource-group/groups/*" { capabilities = ["read", "list"] }
            path "tenant-a/resources/resources/web1" { capabilities = ["read"] }
        "# })
        .as_object()
        .cloned(),
    )
    .await
    .unwrap();
    test_mount_auth_api(&core, &root, "userpass", "userpass").await;
    test_write_api(
        &core,
        &root,
        "auth/userpass/users/dave",
        true,
        json!({ "password": "pw-123456" }).as_object().cloned(),
    )
    .await
    .unwrap();
    ns_req(
        &core,
        &root,
        Operation::Write,
        "identity/group/user/devs",
        "tenant-a",
        json!({ "members": ["dave"], "policies": ["dave-p"] }).as_object().cloned(),
    )
    .await
    .unwrap();

    let mut login = Request::new("auth/userpass/login/dave");
    login.operation = Operation::Write;
    login.body = json!({ "password": "pw-123456" }).as_object().cloned();
    let mut h = HashMap::new();
    h.insert("x-bastionvault-namespace".to_string(), "tenant-a".to_string());
    login.headers = Some(h);
    let dave = core.handle_request(&mut login).await.unwrap().unwrap().auth.unwrap().client_token;

    let body = ns_req(&core, &dave, Operation::Read, "resource-group/groups/g", "tenant-a", None)
        .await
        .unwrap()
        .unwrap()
        .data
        .unwrap();
    let mut members: Vec<String> =
        body["members"].as_array().unwrap().iter().map(|v| v.as_str().unwrap_or("").to_string()).collect();
    members.sort();
    assert_eq!(
        members,
        vec![REDACTED_MEMBER.to_string(), "web1".to_string()],
        "web1 is readable through the tenant policy and must show; db1 is not and must stay hidden",
    );

    // Listing: dave is neither owner nor grantee, but reads a member, so the
    // group is listed. Before, the list was empty and the GUI had no groups.
    let listed = ns_req(&core, &dave, Operation::List, "resource-group/groups/", "tenant-a", None)
        .await
        .unwrap()
        .unwrap()
        .data
        .unwrap();
    assert_eq!(listed["keys"], json!(["g"]), "a caller who reads a member must see the group");

    // eve may list and read groups but reads no member: nothing to show, and
    // the group name must not leak to her.
    ns_req(
        &core,
        &root,
        Operation::Write,
        "sys/policy/eve-p",
        "tenant-a",
        json!({ "policy": r#"
            path "tenant-a/resource-group/groups/*" { capabilities = ["read", "list"] }
        "# })
        .as_object()
        .cloned(),
    )
    .await
    .unwrap();
    test_write_api(
        &core,
        &root,
        "auth/userpass/users/eve",
        true,
        json!({ "password": "pw-123456" }).as_object().cloned(),
    )
    .await
    .unwrap();
    ns_req(
        &core,
        &root,
        Operation::Write,
        "identity/group/user/others",
        "tenant-a",
        json!({ "members": ["eve"], "policies": ["eve-p"] }).as_object().cloned(),
    )
    .await
    .unwrap();
    let mut login = Request::new("auth/userpass/login/eve");
    login.operation = Operation::Write;
    login.body = json!({ "password": "pw-123456" }).as_object().cloned();
    let mut h = HashMap::new();
    h.insert("x-bastionvault-namespace".to_string(), "tenant-a".to_string());
    login.headers = Some(h);
    let eve = core.handle_request(&mut login).await.unwrap().unwrap().auth.unwrap().client_token;
    let listed = ns_req(&core, &eve, Operation::List, "resource-group/groups/", "tenant-a", None).await;
    let keys = listed.ok().flatten().and_then(|r| r.data).and_then(|d| d.get("keys").cloned());
    assert!(
        keys.map(|k| k.as_array().map(|a| a.is_empty()).unwrap_or(true)).unwrap_or(true),
        "a caller who reads no member must not see the group",
    );
}

// ── namespace-scoped asset groups ──────────────────────────────────────────

/// One request in namespace `ns` (`""` = root, no header).
#[maybe_async::maybe_async]
async fn ns_call(
    core: &dyn VaultCtx,
    token: &str,
    op: Operation,
    path: &str,
    ns: &str,
    body: Option<serde_json::Map<String, Value>>,
) -> Result<Option<crate::logical::Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = op;
    req.client_token = token.to_string();
    req.body = body;
    if !ns.is_empty() {
        req.headers = Some(HashMap::from([("x-bastionvault-namespace".to_string(), ns.to_string())]));
    }
    core.handle_request(&mut req).await
}

/// The group names a LIST in `ns` returns (empty on a denied or empty list).
#[maybe_async::maybe_async]
async fn listed_groups(core: &dyn VaultCtx, token: &str, ns: &str) -> Vec<String> {
    let resp = ns_call(core, token, Operation::List, "resource-group/groups/", ns, None).await;
    let keys = resp.ok().flatten().and_then(|r| r.data).and_then(|d| d.get("keys").cloned());
    keys.and_then(|k| k.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

/// `by-resource/<name>` in `ns`, as a list of group names.
#[maybe_async::maybe_async]
async fn groups_of_resource(core: &dyn VaultCtx, token: &str, ns: &str, resource: &str) -> Vec<String> {
    let path = format!("resource-group/by-resource/{resource}");
    let data = ns_call(core, token, Operation::Read, &path, ns, None).await.unwrap().unwrap().data.unwrap();
    data["groups"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect()
}

#[maybe_async::maybe_async]
async fn read_in(
    core: &dyn VaultCtx,
    token: &str,
    ns: &str,
    path: &str,
) -> Result<Option<crate::logical::Response>, RvError> {
    ns_call(core, token, Operation::Read, path, ns, None).await
}

#[maybe_async::maybe_async]
async fn make_namespaces(core: &dyn VaultCtx, root: &str, paths: &[&str]) {
    for p in paths {
        test_write_api(core, root, &format!("sys/namespaces/{p}"), true, json!({}).as_object().cloned()).await.unwrap();
    }
}

#[maybe_async::maybe_async]
async fn put_group(core: &dyn VaultCtx, token: &str, ns: &str, name: &str, members: &str) {
    let body = json!({ "description": name, "members": members }).as_object().cloned();
    ns_call(core, token, Operation::Write, &format!("resource-group/groups/{name}"), ns, body).await.unwrap();
}

/// The reported leak: a group created in `dti/importacao/test02` showed in
/// every namespace. A group is visible in its namespace and descendants only;
/// root's groups are visible everywhere (root is every namespace's ancestor).
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_asset_group_visible_in_own_namespace_and_descendants_only() {
    let (_bvault, core, root) =
        new_unseal_test_bastion_vault("test_asset_group_visible_in_own_namespace_and_descendants_only").await;
    make_namespaces(&core, &root, &["tenant-a", "tenant-a/child", "tenant-b"]).await;

    put_group(&core, &root, "tenant-a", "ga", "web1").await;
    put_group(&core, &root, "", "rootg", "web1").await;

    assert_eq!(listed_groups(&core, &root, "tenant-a").await, vec!["ga", "rootg"]);
    assert_eq!(listed_groups(&core, &root, "tenant-a/child").await, vec!["ga", "rootg"]);
    assert_eq!(listed_groups(&core, &root, "tenant-b").await, vec!["rootg"], "sibling must not see ga");
    assert_eq!(listed_groups(&core, &root, "").await, vec!["rootg"], "parent (root) must not see ga");

    let (ga, rootg) = ("resource-group/groups/ga", "resource-group/groups/rootg");
    let own = read_in(&core, &root, "tenant-a", ga).await.unwrap().unwrap().data.unwrap();
    assert_eq!((own["namespace"].as_str(), own["inherited"].as_bool()), (Some("tenant-a"), Some(false)));
    let child = read_in(&core, &root, "tenant-a/child", ga).await.unwrap().unwrap().data.unwrap();
    assert_eq!((child["namespace"].as_str(), child["inherited"].as_bool()), (Some("tenant-a"), Some(true)));
    assert!(read_in(&core, &root, "tenant-b", ga).await.is_err(), "a sibling's group must not be readable");
    assert!(read_in(&core, &root, "", ga).await.is_err(), "a child's group must not be readable from root");
    let inherited_root = read_in(&core, &root, "tenant-b", rootg).await.unwrap().unwrap().data.unwrap();
    assert_eq!((inherited_root["namespace"].as_str(), inherited_root["inherited"].as_bool()), (Some(""), Some(true)));

    // The path-prefix form reaches tenant-a's mount without a namespace on
    // the request; it must be refused, not silently act on root's groups.
    let prefixed = test_write_api(
        &core,
        &root,
        "tenant-a/resource-group/groups/sneaky",
        false,
        json!({ "members": "web1" }).as_object().cloned(),
    )
    .await;
    assert!(prefixed.is_err());
    assert_eq!(listed_groups(&core, &root, "").await, vec!["rootg"], "no root group may appear");
}

/// The same resource name in root and in a namespace must not collide in the
/// member index, nor in the ACL `groups` qualifier built from it.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_asset_group_member_index_is_per_namespace() {
    use crate::test_utils::test_mount_auth_api;

    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_asset_group_member_index_is_per_namespace").await;
    make_namespaces(&core, &root, &["tenant-a"]).await;
    for ns in ["", "tenant-a"] {
        for name in ["db1", "db2"] {
            let body = json!({ "name": name, "type": "server", "hostname": "h.example" }).as_object().cloned();
            ns_call(&core, &root, Operation::Write, &format!("resources/resources/{name}"), ns, body).await.unwrap();
        }
    }
    // One group name, two namespaces, different members.
    put_group(&core, &root, "", "g", "db1").await;
    put_group(&core, &root, "tenant-a", "g", "db2").await;

    assert_eq!(groups_of_resource(&core, &root, "", "db1").await, vec!["g"]);
    assert!(groups_of_resource(&core, &root, "", "db2").await.is_empty());
    assert!(groups_of_resource(&core, &root, "tenant-a", "db1").await.is_empty(), "root's g holds root's db1");
    assert_eq!(groups_of_resource(&core, &root, "tenant-a", "db2").await, vec!["g"]);

    // A tenant user whose only read grant is gated by `groups = ["g"]`.
    ns_call(
        &core,
        &root,
        Operation::Write,
        "sys/policy/g-reader",
        "tenant-a",
        json!({ "policy": r#"
            path "tenant-a/resources/resources/*" {
                capabilities = ["read"]
                groups = ["g"]
            }
        "# })
        .as_object()
        .cloned(),
    )
    .await
    .unwrap();
    test_mount_auth_api(&core, &root, "userpass", "userpass").await;
    let user = json!({ "password": "pw-123456" }).as_object().cloned();
    test_write_api(&core, &root, "auth/userpass/users/gina", true, user).await.unwrap();
    let grp = json!({ "members": ["gina"], "policies": ["g-reader"] }).as_object().cloned();
    ns_call(&core, &root, Operation::Write, "identity/group/user/readers", "tenant-a", grp).await.unwrap();
    let login_body = json!({ "password": "pw-123456" }).as_object().cloned();
    let login = ns_call(&core, "", Operation::Write, "auth/userpass/login/gina", "tenant-a", login_body).await;
    let gina = login.unwrap().unwrap().auth.unwrap().client_token;

    let db2 = read_in(&core, &gina, "tenant-a", "resources/resources/db2").await;
    assert!(db2.is_ok(), "tenant db2 is in tenant-a's g: {db2:?}");
    let db1 = read_in(&core, &gina, "tenant-a", "resources/resources/db1").await;
    assert!(db1.is_err(), "tenant db1 is only named by root's g, which is not tenant-a's g");

    // Reindexing one scope leaves the other's index intact.
    ns_call(&core, &root, Operation::Write, "resource-group/reindex", "tenant-a", None).await.unwrap();
    assert_eq!(groups_of_resource(&core, &root, "", "db1").await, vec!["g"]);
    assert_eq!(groups_of_resource(&core, &root, "tenant-a", "db2").await, vec!["g"]);
}

/// Records written before scopes existed sit at the bare legacy keys and must
/// read as root groups, with no migration.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_legacy_bare_key_asset_group_reads_as_root() {
    use crate::storage::Storage;

    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_legacy_bare_key_asset_group_reads_as_root").await;
    make_namespaces(&core, &root, &["tenant-a"]).await;
    let legacy = json!({ "name": "old-g", "members": ["web9"], "secrets": [], "owner_entity_id": "" });
    let system_view = core.system_view().expect("unsealed");
    let entry = StorageEntry { key: "resource-group/group/old-g".into(), value: serde_json::to_vec(&legacy).unwrap() };
    system_view.put(&entry).await.unwrap();

    let data = test_read_api(&core, &root, "resource-group/groups/old-g", true).await.unwrap().unwrap().data.unwrap();
    assert_eq!((data["namespace"].as_str(), data["inherited"].as_bool()), (Some(""), Some(false)));
    assert_eq!(data["members"], json!(["web9"]));
    assert_eq!(listed_groups(&core, &root, "").await, vec!["old-g"]);
    assert_eq!(listed_groups(&core, &root, "tenant-a").await, vec!["old-g"], "root groups are inherited");

    // The legacy root index rebuilds in place.
    test_write_api(&core, &root, "resource-group/reindex", true, None).await.unwrap();
    assert_eq!(groups_of_resource(&core, &root, "", "web9").await, vec!["old-g"]);
    assert!(groups_of_resource(&core, &root, "tenant-a", "web9").await.is_empty());
}

/// An inherited group is read-only in the child: delete is refused, a write
/// creates the child's own group, and the parent's record never changes.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_child_cannot_modify_or_delete_inherited_asset_group() {
    let (_bvault, core, root) =
        new_unseal_test_bastion_vault("test_child_cannot_modify_or_delete_inherited_asset_group").await;
    make_namespaces(&core, &root, &["tenant-a", "tenant-a/child"]).await;
    put_group(&core, &root, "tenant-a", "ga", "web1").await;
    let path = "resource-group/groups/ga";

    let delete = ns_call(&core, &root, Operation::Delete, path, "tenant-a/child", None).await;
    assert!(delete.is_err(), "deleting an inherited group from the child must be refused");

    let body = json!({ "members": "web2" }).as_object().cloned();
    let write = ns_call(&core, &root, Operation::Write, path, "tenant-a/child", body).await.unwrap();
    assert!(!write.expect("shadowing write carries a warning").warnings.is_empty());

    let parent = read_in(&core, &root, "tenant-a", path).await.unwrap().unwrap().data.unwrap();
    assert_eq!(parent["members"], json!(["web1"]), "the inherited group is unchanged");
    let child = read_in(&core, &root, "tenant-a/child", path).await.unwrap().unwrap().data.unwrap();
    assert_eq!((child["members"].clone(), child["inherited"].as_bool()), (json!(["web2"]), Some(false)));

    // Deleting the child's own group re-exposes the inherited one.
    ns_call(&core, &root, Operation::Delete, path, "tenant-a/child", None).await.unwrap();
    let after = read_in(&core, &root, "tenant-a/child", path).await.unwrap().unwrap().data.unwrap();
    assert_eq!((after["members"].clone(), after["inherited"].as_bool()), (json!(["web1"]), Some(true)));
    assert_eq!(listed_groups(&core, &root, "tenant-a").await, vec!["ga"]);
}

/// An inherited group's members are the ancestor's objects. A tenant user who
/// reads the tenant's own `web1` must not see root's `web1` through root's
/// group, nor be shown that group in a listing.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_inherited_asset_group_members_are_probed_in_their_home_namespace() {
    use crate::test_utils::test_mount_auth_api;

    let (_bvault, core, root) =
        new_unseal_test_bastion_vault("test_inherited_asset_group_members_are_probed_in_their_home_namespace").await;
    make_namespaces(&core, &root, &["tenant-a"]).await;
    let body = json!({ "name": "web1", "type": "server", "hostname": "h.example" }).as_object().cloned();
    ns_call(&core, &root, Operation::Write, "resources/resources/web1", "tenant-a", body).await.unwrap();
    put_group(&core, &root, "", "rootg", "web1").await;

    ns_call(
        &core,
        &root,
        Operation::Write,
        "sys/policy/t-reader",
        "tenant-a",
        json!({ "policy": r#"
            path "tenant-a/resource-group/groups/*" { capabilities = ["read", "list"] }
            path "tenant-a/resources/resources/web1" { capabilities = ["read"] }
        "# })
        .as_object()
        .cloned(),
    )
    .await
    .unwrap();
    test_mount_auth_api(&core, &root, "userpass", "userpass").await;
    let user = json!({ "password": "pw-123456" }).as_object().cloned();
    test_write_api(&core, &root, "auth/userpass/users/tom", true, user).await.unwrap();
    let grp = json!({ "members": ["tom"], "policies": ["t-reader"] }).as_object().cloned();
    ns_call(&core, &root, Operation::Write, "identity/group/user/t", "tenant-a", grp).await.unwrap();
    let login_body = json!({ "password": "pw-123456" }).as_object().cloned();
    let login = ns_call(&core, "", Operation::Write, "auth/userpass/login/tom", "tenant-a", login_body).await;
    let tom = login.unwrap().unwrap().auth.unwrap().client_token;

    let data = read_in(&core, &tom, "tenant-a", "resource-group/groups/rootg").await.unwrap().unwrap().data.unwrap();
    assert_eq!(data["members"], json!([REDACTED_MEMBER]), "root's web1 is not tenant-a's web1");
    assert!(listed_groups(&core, &tom, "tenant-a").await.is_empty(), "tom reads no member of rootg");
}

// ── v2 batch read + change version ─────────────────────────────────────────

/// `GET resource-group/v2/groups/batch` in `ns`, the selectors on the query
/// string exactly as the GUI and the HTTP API send them (so this also covers
/// the logical query allowlist lifting `shape` and `since`).
#[maybe_async::maybe_async]
async fn batch_call(
    core: &dyn VaultCtx,
    token: &str,
    ns: &str,
    shape: &str,
    since: Option<&str>,
) -> Result<serde_json::Map<String, Value>, RvError> {
    let mut raw = format!("resource-group/v2/groups/batch?shape={shape}");
    if let Some(s) = since {
        raw.push_str(&format!("&since={s}"));
    }
    let (path, data) = crate::logical::split_path_query(&raw);
    let mut req = Request::new(&path);
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    req.data = data;
    if !ns.is_empty() {
        req.headers = Some(HashMap::from([("x-bastionvault-namespace".to_string(), ns.to_string())]));
    }
    Ok(core.handle_request(&mut req).await?.and_then(|r| r.data).unwrap_or_default())
}

/// What the N+1 the batch replaces returned: LIST, then GET each listed group,
/// keeping the reads that succeed.
#[maybe_async::maybe_async]
async fn reads_of_listed(core: &dyn VaultCtx, token: &str, ns: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for name in listed_groups(core, token, ns).await {
        if let Ok(Some(r)) = read_in(core, token, ns, &format!("resource-group/groups/{name}")).await {
            out.push(Value::Object(r.data.unwrap_or_default()));
        }
    }
    out
}

/// `by_resource` / `by_secret` built from individual reads the way the slim
/// shape must: this namespace's own groups, hidden members left out.
fn slim_from_reads(reads: &[Value], ns: &str) -> (Value, Value) {
    let mut by_resource: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    let mut by_secret: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for g in reads.iter().filter(|g| g["namespace"] == ns) {
        let name = g["name"].as_str().unwrap().to_string();
        for (index, key) in [(&mut by_resource, "members"), (&mut by_secret, "secrets")] {
            for m in g[key].as_array().unwrap().iter().filter_map(|m| m.as_str()).filter(|m| *m != REDACTED_MEMBER) {
                index.entry(m.to_string()).or_default().push(name.clone());
            }
        }
    }
    (json!(by_resource), json!(by_secret))
}

/// A root-namespace userpass user (on `mount`) holding a policy from `hcl`.
#[maybe_async::maybe_async]
async fn root_user(core: &dyn VaultCtx, root: &str, mount: &str, user: &str, hcl: &str) -> String {
    let policy = json!({ "policy": hcl }).as_object().cloned();
    test_write_api(core, root, &format!("sys/policies/acl/{user}-p"), true, policy).await.unwrap();
    let body = json!({ "password": "pw-123456XX!", "token_policies": format!("{user}-p"), "ttl": 0 });
    test_write_api(core, root, &format!("auth/{mount}/users/{user}"), true, body.as_object().cloned()).await.unwrap();
    let login = json!({ "password": "pw-123456XX!" }).as_object().cloned();
    let resp = ns_call(core, "", Operation::Write, &format!("auth/{mount}/login/{user}"), "", login).await;
    resp.unwrap().unwrap().auth.unwrap().client_token
}

/// The batch returns exactly what LIST-then-GET-each returns, redaction
/// included, for an admin and for non-admins; and a group the caller may list
/// but not read on its own is withheld, as its GET would be.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_asset_group_batch_equals_the_union_of_individual_reads() {
    let (_bvault, core, root) =
        new_unseal_test_bastion_vault("test_asset_group_batch_equals_the_union_of_individual_reads").await;
    test_write_api(&core, &root, "sys/auth/batchpass", true, json!({ "type": "userpass" }).as_object().cloned())
        .await
        .unwrap();
    let uma = root_user(
        &core,
        &root,
        "batchpass",
        "uma",
        r#"
            path "resource-group/groups/*"  { capabilities = ["create", "read", "update", "list"] }
            path "resources/resources/web1" { capabilities = ["read"] }
            path "secret/data/ok/*"          { capabilities = ["read"] }
        "#,
    )
    .await;
    // Lists through the member pass, but holds no read on `groups/+` beyond
    // `default`'s share-scoped one.
    let vic = root_user(
        &core,
        &root,
        "batchpass",
        "vic",
        r#"
            path "resource-group/groups"    { capabilities = ["list"] }
            path "resources/resources/web1" { capabilities = ["read"] }
        "#,
    )
    .await;

    let body = json!({ "description": "mixed", "members": "web1,web2", "secrets": "secret/ok/a,secret/no/b" });
    ns_call(&core, &root, Operation::Write, "resource-group/groups/mixed", "", body.as_object().cloned())
        .await
        .unwrap();
    put_group(&core, &root, "", "dark", "web3").await;
    put_group(&core, &uma, "", "mine", "web1,web2").await;

    // Root: everything, unredacted.
    let reads = reads_of_listed(&core, &root, "").await;
    assert_eq!(reads.len(), 3);
    let batch = batch_call(&core, &root, "", "full", None).await.unwrap();
    assert_eq!(batch["groups"], Value::Array(reads.clone()), "admin: batch = LIST + GET each");
    assert_eq!(batch["unchanged"], json!(false));
    assert!(batch["version"].is_string());
    let slim = batch_call(&core, &root, "", "slim", None).await.unwrap();
    let (by_resource, by_secret) = slim_from_reads(&reads, "");
    assert_eq!((slim["by_resource"].clone(), slim["by_secret"].clone()), (by_resource, by_secret));
    assert_eq!(slim["groups"], json!(["dark", "mine", "mixed"]));

    // Uma: `dark` is not listed (she reads no member of it), `mixed` is
    // redacted exactly as her GET redacts it.
    let reads = reads_of_listed(&core, &uma, "").await;
    let batch = batch_call(&core, &uma, "", "full", None).await.unwrap();
    assert_eq!(batch["groups"], Value::Array(reads.clone()), "non-admin: batch = LIST + GET each");
    let names: Vec<&str> = reads.iter().map(|g| g["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["mine", "mixed"]);
    let mixed = &reads[1];
    assert_eq!(mixed["members"], json!(["web1", REDACTED_MEMBER]));
    assert_eq!(mixed["secrets"], json!([REDACTED_MEMBER, "secret/ok/a"]));
    let slim = batch_call(&core, &uma, "", "slim", None).await.unwrap();
    let (by_resource, by_secret) = slim_from_reads(&reads, "");
    assert_eq!((slim["by_resource"].clone(), slim["by_secret"].clone()), (by_resource, by_secret));
    let leaked = serde_json::to_string(&slim).unwrap();
    assert!(!leaked.contains("secret/no/b") && !leaked.contains("web3"), "no hidden member in the maps: {leaked}");

    // Vic lists two groups but may read neither on its own: the batch must
    // not become a way around `groups/+`.
    assert_eq!(listed_groups(&core, &vic, "").await, vec!["mine", "mixed"]);
    assert!(reads_of_listed(&core, &vic, "").await.is_empty());
    let batch = batch_call(&core, &vic, "", "full", None).await.unwrap();
    assert_eq!(batch["groups"], json!([]));
    let slim = batch_call(&core, &vic, "", "slim", None).await.unwrap();
    assert_eq!((slim["groups"].clone(), slim["by_resource"].clone()), (json!([]), json!({})));
}

/// `since` equal to the current version answers "unchanged" with no group
/// data; a write (including a prune from another engine) moves the version,
/// a read never does; malformed selectors are refused.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_asset_group_batch_since_returns_unchanged_until_a_write() {
    let (_bvault, core, root) =
        new_unseal_test_bastion_vault("test_asset_group_batch_since_returns_unchanged_until_a_write").await;
    let body = json!({ "name": "web1", "type": "server", "hostname": "h.example" }).as_object().cloned();
    ns_call(&core, &root, Operation::Write, "resources/resources/web1", "", body).await.unwrap();
    put_group(&core, &root, "", "alpha", "web1").await;

    let first = batch_call(&core, &root, "", "slim", None).await.unwrap();
    let v1 = first["version"].as_str().unwrap().to_string();
    assert_eq!(first["by_resource"], json!({ "web1": ["alpha"] }));

    let same = batch_call(&core, &root, "", "slim", Some(&v1)).await.unwrap();
    assert_eq!(same["unchanged"], json!(true));
    assert_eq!(same["version"], json!(v1));
    for absent in ["groups", "by_resource", "by_secret", "by_file"] {
        assert!(same.get(absent).is_none(), "an unchanged answer carries no {absent}");
    }

    // Reads of every kind leave it alone.
    listed_groups(&core, &root, "").await;
    read_in(&core, &root, "", "resource-group/groups/alpha").await.unwrap();
    groups_of_resource(&core, &root, "", "web1").await;
    read_in(&core, &root, "", "resource-group/groups/alpha/history").await.unwrap();
    batch_call(&core, &root, "", "full", None).await.unwrap();
    assert_eq!(batch_call(&core, &root, "", "full", Some(&v1)).await.unwrap()["unchanged"], json!(true));

    // A write moves it, and the answer carries the new data.
    put_group(&core, &root, "", "beta", "web2").await;
    let after = batch_call(&core, &root, "", "slim", Some(&v1)).await.unwrap();
    assert_eq!(after["unchanged"], json!(false));
    let v2 = after["version"].as_str().unwrap().to_string();
    assert_ne!(v2, v1);
    assert_eq!(after["by_resource"], json!({ "web1": ["alpha"], "web2": ["beta"] }));

    // Deleting the resource prunes it from `alpha` through the resource
    // engine's lifecycle hook, which must move the version too.
    ns_call(&core, &root, Operation::Delete, "resources/resources/web1", "", None).await.unwrap();
    let pruned = batch_call(&core, &root, "", "slim", Some(&v2)).await.unwrap();
    assert_eq!(pruned["unchanged"], json!(false));
    assert_eq!(pruned["by_resource"], json!({ "web2": ["beta"] }));

    assert!(batch_call(&core, &root, "", "slim", Some("not%20a%20version")).await.is_err());
    assert!(batch_call(&core, &root, "", "everything", None).await.is_err());
}

/// Namespaces: own groups plus ancestors' (flagged `inherited`), never a
/// sibling's; the slim maps key only this namespace's own groups; a version
/// moves with the namespace and its ancestors only; and a tenant user sees in
/// the batch exactly what LIST + GET show them.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_asset_group_batch_follows_namespace_visibility() {
    use crate::test_utils::test_mount_auth_api;

    let (_bvault, core, root) =
        new_unseal_test_bastion_vault("test_asset_group_batch_follows_namespace_visibility").await;
    make_namespaces(&core, &root, &["tenant-a", "tenant-a/child", "tenant-b"]).await;
    let body = json!({ "name": "web1", "type": "server", "hostname": "h.example" }).as_object().cloned();
    ns_call(&core, &root, Operation::Write, "resources/resources/web1", "tenant-a", body).await.unwrap();
    put_group(&core, &root, "tenant-a", "ga", "web1").await;
    put_group(&core, &root, "", "rootg", "web1").await;
    put_group(&core, &root, "tenant-b", "gb", "web1").await;

    let names = |b: &serde_json::Map<String, Value>| -> Vec<(String, String, bool)> {
        b["groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| {
                let (n, ns) = (g["name"].as_str().unwrap(), g["namespace"].as_str().unwrap());
                (n.to_string(), ns.to_string(), g["inherited"].as_bool().unwrap())
            })
            .collect()
    };
    let child = batch_call(&core, &root, "tenant-a/child", "full", None).await.unwrap();
    assert_eq!(
        names(&child),
        vec![("ga".into(), "tenant-a".into(), true), ("rootg".into(), String::new(), true)],
        "own scope plus ancestors, never a sibling"
    );
    assert_eq!(child["groups"], Value::Array(reads_of_listed(&core, &root, "tenant-a/child").await));
    let sibling = batch_call(&core, &root, "tenant-b", "full", None).await.unwrap();
    assert_eq!(names(&sibling), vec![("gb".into(), "tenant-b".into(), false), ("rootg".into(), String::new(), true)]);

    // Root's `rootg` lists root's web1; it must not be keyed as tenant-a's.
    let slim = batch_call(&core, &root, "tenant-a", "slim", None).await.unwrap();
    assert_eq!(slim["groups"], json!(["ga", "rootg"]));
    assert_eq!(slim["by_resource"], json!({ "web1": ["ga"] }));

    let (v_child, v_sibling) =
        (child["version"].as_str().unwrap().to_string(), sibling["version"].as_str().unwrap().to_string());
    put_group(&core, &root, "tenant-a", "ga2", "web2").await;
    let unchanged = batch_call(&core, &root, "tenant-b", "full", Some(&v_sibling)).await.unwrap();
    assert_eq!(unchanged["unchanged"], json!(true), "a sibling's write does not move tenant-b's version");
    let moved = batch_call(&core, &root, "tenant-a/child", "full", Some(&v_child)).await.unwrap();
    assert_eq!(moved["unchanged"], json!(false), "an ancestor's write moves the child's version");
    put_group(&core, &root, "", "rootg2", "web2").await;
    let moved = batch_call(&core, &root, "tenant-b", "full", Some(&v_sibling)).await.unwrap();
    assert_eq!(moved["unchanged"], json!(false), "root is every namespace's ancestor");

    // A tenant user: reads tenant-a's web1, nothing of root's.
    ns_call(
        &core,
        &root,
        Operation::Write,
        "sys/policy/t-batch",
        "tenant-a",
        json!({ "policy": r#"
            path "tenant-a/resource-group/groups/*"         { capabilities = ["read", "list"] }
            path "tenant-a/resource-group/v2/groups/batch" { capabilities = ["read"] }
            path "tenant-a/resources/resources/web1"        { capabilities = ["read"] }
        "# })
        .as_object()
        .cloned(),
    )
    .await
    .unwrap();
    test_mount_auth_api(&core, &root, "userpass", "userpass").await;
    let user = json!({ "password": "pw-123456" }).as_object().cloned();
    test_write_api(&core, &root, "auth/userpass/users/tess", true, user).await.unwrap();
    let grp = json!({ "members": ["tess"], "policies": ["t-batch"] }).as_object().cloned();
    ns_call(&core, &root, Operation::Write, "identity/group/user/t", "tenant-a", grp).await.unwrap();
    let login_body = json!({ "password": "pw-123456" }).as_object().cloned();
    let login = ns_call(&core, "", Operation::Write, "auth/userpass/login/tess", "tenant-a", login_body).await;
    let tess = login.unwrap().unwrap().auth.unwrap().client_token;

    let mine = batch_call(&core, &tess, "tenant-a", "full", None).await.unwrap();
    assert_eq!(mine["groups"], Value::Array(reads_of_listed(&core, &tess, "tenant-a").await));
    let seen: Vec<String> = names(&mine).into_iter().map(|(n, _, _)| n).collect();
    assert_eq!(seen, vec!["ga"], "root's rootg (root's web1) and tenant-b's gb stay hidden");
    assert_eq!(mine["groups"][0]["members"], json!(["web1"]));
    if let Ok(other) = batch_call(&core, &tess, "tenant-b", "full", None).await {
        let leaked = serde_json::to_string(&other).unwrap();
        assert!(!leaked.contains("\"gb\""), "a sibling's group must not leak: {leaked}");
    }
}

/// One batch call is one audit entry: the per-group work happens inside the
/// handler, not as requests of its own.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_asset_group_batch_is_one_audit_entry() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_asset_group_batch_is_one_audit_entry").await;
    for (name, members) in [("a1", "web1"), ("a2", "web2"), ("a3", "web1,web3")] {
        put_group(&core, &root, "", name, members).await;
    }
    let dir = std::env::temp_dir().join(format!(
        "bv-asset-group-batch-audit-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("audit.log");
    let device = json!({ "type": "file", "options": { "file_path": log.display().to_string() } });
    test_write_api(&core, &root, "sys/audit/batch", true, device.as_object().cloned()).await.unwrap();

    let batch = batch_call(&core, &root, "", "full", None).await.unwrap();
    assert_eq!(batch["groups"].as_array().unwrap().len(), 3);

    // The broker writes one entry per request (`response` today; a
    // pre-dispatch `request` entry is planned). Either way: one per type, all
    // for the batch path, none for a per-group read.
    let entries: Vec<Value> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e["request"]["path"].as_str().is_some_and(|p| p.contains("resource-group/")))
        .collect();
    assert!(!entries.is_empty(), "the batch must be audited");
    for kind in ["request", "response"] {
        let n = entries.iter().filter(|e| e["type"] == kind).count();
        assert!(n <= 1, "{n} {kind} entries for one batch call: {entries:?}");
    }
    assert!(entries.iter().all(|e| e["request"]["path"] == "resource-group/v2/groups/batch"), "{entries:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
