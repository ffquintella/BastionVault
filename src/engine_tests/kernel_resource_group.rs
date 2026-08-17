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
use std::{collections::HashMap, sync::Arc};
#[allow(unused_imports)]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
#[allow(unused_imports)]
use serde_json::Value;
#[allow(unused_imports)]
use crate::{
    core::Core,
    errors::RvError,
    kernel_api::VaultCtx,
    logical::{Operation, Request},
    storage::StorageEntry,
};


use serde_json::json;

    use crate::modules::resource_group::*;
    use crate::test_utils::{
        new_unseal_test_bastion_vault, test_delete_api, test_list_api, test_read_api,
        test_write_api,
    };

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
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/auth/pass-r",
            true,
            j!({ "type": "userpass" }).as_object().cloned(),
        )
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
        let _ = test_read_api(&core, &carol_token, "secret/data/ok/a", true)
            .await
            .unwrap();

        // Carol reads the group: secret/ok/a stays, secret/forbidden/a
        // and the resource member (alpha) become `<hidden>`.
        let resp = test_read_api(&core, &carol_token, "resource-group/groups/mixed-visibility", true)
            .await
            .unwrap()
            .unwrap();
        let body = resp.data.unwrap();
        let members = body.get("members").and_then(|v| v.as_array()).unwrap().clone();
        let secrets = body.get("secrets").and_then(|v| v.as_array()).unwrap().clone();

        assert_eq!(
            members,
            vec![Value::String(REDACTED_MEMBER.to_string())],
            "resource members Carol can't read should be redacted",
        );
        let secrets_strs: Vec<String> = secrets
            .iter()
            .map(|v| v.as_str().unwrap_or("").to_string())
            .collect();
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
        let resp = test_read_api(&core, &root_token, "resource-group/groups/mixed-visibility", true)
            .await
            .unwrap()
            .unwrap();
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
            new_unseal_test_bastion_vault("test_asset_group_admin_owner_transfer_roundtrip")
                .await;

        // Root creates the group — owner_entity_id stays empty because
        // the root token has no entity_id metadata.
        let data = json!({ "description": "root-created" })
            .as_object()
            .cloned();
        let _ = test_write_api(&core, &root_token, "resource-group/groups/bundle-a", true, data)
            .await
            .unwrap();

        let resp = test_read_api(&core, &root_token, "resource-group/groups/bundle-a", true)
            .await
            .unwrap()
            .unwrap();
        let body = resp.data.unwrap();
        assert_eq!(
            body.get("owner_entity_id")
                .and_then(|v| v.as_str())
                .unwrap_or("missing"),
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
        let _ = test_write_api(&core, &root_token, "sys/asset-group-owner/transfer", true, xfer)
            .await
            .unwrap();

        let resp = test_read_api(&core, &root_token, "resource-group/groups/bundle-a", true)
            .await
            .unwrap()
            .unwrap();
        let body = resp.data.unwrap();
        assert_eq!(
            body.get("owner_entity_id")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
            "ent-owner-1",
        );

        // A subsequent `set_group` write must not change the owner.
        let update = json!({ "description": "updated description" })
            .as_object()
            .cloned();
        let _ = test_write_api(
            &core,
            &root_token,
            "resource-group/groups/bundle-a",
            true,
            update,
        )
        .await
        .unwrap();

        let resp = test_read_api(&core, &root_token, "resource-group/groups/bundle-a", true)
            .await
            .unwrap()
            .unwrap();
        let body = resp.data.unwrap();
        assert_eq!(
            body.get("owner_entity_id")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
            "ent-owner-1",
            "owner must survive regular writes",
        );
        assert_eq!(
            body.get("description").and_then(|v| v.as_str()).unwrap_or(""),
            "updated description",
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_resource_group_crud() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_resource_group_crud").await;

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
        let resp = test_read_api(&core, &root_token, "resource-group/groups/phoenix", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["name"], "phoenix");
        assert_eq!(data["description"], "project phoenix resources");
        // Members are canonicalized: lowercased, deduped, sorted.
        assert_eq!(data["members"], json!(["db-01", "web-01"]));
        // No secrets were supplied; the field is present and empty.
        assert_eq!(data["secrets"], json!([] as [String; 0]));

        // List.
        let resp = test_list_api(&core, &root_token, "resource-group/groups", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["keys"], json!(["phoenix"]));

        // Partial update: description only, members preserved.
        let patch = json!({ "description": "project phoenix (updated)" }).as_object().cloned();
        let _ = test_write_api(&core, &root_token, "resource-group/groups/phoenix", true, patch).await;
        let resp = test_read_api(&core, &root_token, "resource-group/groups/phoenix", true)
            .await
            .unwrap()
            .unwrap();
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
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_resource_group_reverse_index").await;

        // `web-01` lives in two groups.
        let a = json!({ "members": "web-01,db-01" }).as_object().cloned();
        let _ = test_write_api(&core, &root_token, "resource-group/groups/alpha", true, a).await;

        let b = json!({ "members": "web-01,api-01" }).as_object().cloned();
        let _ = test_write_api(&core, &root_token, "resource-group/groups/beta", true, b).await;

        // by-resource lookup returns both group names, sorted.
        let resp = test_read_api(&core, &root_token, "resource-group/by-resource/web-01", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["groups"], json!(["alpha", "beta"]));

        // `db-01` is only in alpha.
        let resp = test_read_api(&core, &root_token, "resource-group/by-resource/db-01", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["groups"], json!(["alpha"]));

        // Remove web-01 from alpha -> by-resource should only return beta.
        let patch = json!({ "members": "db-01" }).as_object().cloned();
        let _ = test_write_api(&core, &root_token, "resource-group/groups/alpha", true, patch).await;

        let resp = test_read_api(&core, &root_token, "resource-group/by-resource/web-01", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["groups"], json!(["beta"]));

        // Delete beta -> web-01 is in no groups; by-resource returns empty.
        let _ = test_delete_api(&core, &root_token, "resource-group/groups/beta", true, None).await;
        let resp = test_read_api(&core, &root_token, "resource-group/by-resource/web-01", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["groups"], json!([] as [String; 0]));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_resource_group_rename_resource() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_resource_group_rename_resource").await;

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

        let groups = store.rename_resource("old01", "new01").await.unwrap();
        assert_eq!(groups.len(), 2, "old01 belonged to two groups");

        // Reverse index moved: new01 in both groups, old01 in none.
        let resp = test_read_api(&core, &root_token, "resource-group/by-resource/new01", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["groups"], json!(["alpha", "beta"]));
        let resp = test_read_api(&core, &root_token, "resource-group/by-resource/old01", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["groups"], json!([] as [String; 0]));

        // The primary records list the new member; `keep01` is untouched.
        let resp = test_read_api(&core, &root_token, "resource-group/groups/alpha", true)
            .await
            .unwrap()
            .unwrap();
        let members = resp.data.unwrap()["members"].as_array().cloned().unwrap();
        assert!(members.contains(&json!("new01")));
        assert!(members.contains(&json!("keep01")));
        assert!(!members.contains(&json!("old01")));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_resource_group_acl_groups_qualifier() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_resource_group_acl_groups_qualifier").await;

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
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/auth/pass",
            true,
            json!({ "type": "userpass" }).as_object().cloned(),
        )
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
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_resource_delete_prunes_from_groups").await;

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
        let resp = test_read_api(&core, &root_token, "resource-group/groups/ops", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["members"], json!(["db-01", "web-01"]));

        // Delete the resource. Lifecycle hook must prune it from the group.
        let _ = test_delete_api(&core, &root_token, "resources/resources/web-01", true, None).await;

        let resp = test_read_api(&core, &root_token, "resource-group/groups/ops", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["members"], json!(["db-01"]));

        // And the reverse-lookup for the deleted resource is empty.
        let resp = test_read_api(&core, &root_token, "resource-group/by-resource/web-01", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["groups"], json!([] as [String; 0]));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_resource_group_secret_membership_and_canonicalization() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_resource_group_secret_membership_and_canonicalization").await;

        // Group with a mix of resources and secrets. Secrets are
        // supplied in three different forms; they must all canonicalize
        // to two distinct entries (`secret/foo/bar` and `secret/baz`).
        let data = json!({
            "members": "web-01",
            "secrets": "secret/foo/bar,secret/data/foo/bar,secret/metadata/baz,secret/baz",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &root_token, "resource-group/groups/mix", true, data).await;

        let resp = test_read_api(&core, &root_token, "resource-group/groups/mix", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["members"], json!(["web-01"]));
        // Canonicalized form: `/data/` and `/metadata/` stripped; deduped
        // and sorted lexicographically.
        assert_eq!(data["secrets"], json!(["secret/baz", "secret/foo/bar"]));

        // by-secret reverse lookup. The handler accepts base64url(no-pad).
        fn b64(s: &str) -> String {
            URL_SAFE_NO_PAD.encode(s.as_bytes())
        }

        // Canonical form matches.
        let path = format!("resource-group/by-secret/{}", b64("secret/foo/bar"));
        let resp = test_read_api(&core, &root_token, &path, true).await.unwrap().unwrap();
        assert_eq!(resp.data.unwrap()["groups"], json!(["mix"]));

        // KV-v2 data/ form matches the same entry.
        let path = format!("resource-group/by-secret/{}", b64("secret/data/foo/bar"));
        let resp = test_read_api(&core, &root_token, &path, true).await.unwrap().unwrap();
        assert_eq!(resp.data.unwrap()["groups"], json!(["mix"]));

        // KV-v2 metadata/ form matches the same entry.
        let path = format!("resource-group/by-secret/{}", b64("secret/metadata/foo/bar"));
        let resp = test_read_api(&core, &root_token, &path, true).await.unwrap().unwrap();
        assert_eq!(resp.data.unwrap()["groups"], json!(["mix"]));

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
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/mounts/kv/",
            true,
            json!({ "type": "kv" }).as_object().cloned(),
        )
        .await;
        let _ = test_write_api(
            &core,
            &root_token,
            "kv/alpha",
            true,
            json!({ "v": "1" }).as_object().cloned(),
        )
        .await;
        let _ = test_write_api(
            &core,
            &root_token,
            "kv/beta",
            true,
            json!({ "v": "2" }).as_object().cloned(),
        )
        .await;

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
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/auth/pass",
            true,
            json!({ "type": "userpass" }).as_object().cloned(),
        )
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
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_resource_group_history").await;

        let create = json!({
            "description": "initial",
            "members": "a,b",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &root_token, "resource-group/groups/team", true, create).await;

        let update = json!({ "members": "a,b,c" }).as_object().cloned();
        let _ = test_write_api(&core, &root_token, "resource-group/groups/team", true, update).await;

        let resp = test_read_api(&core, &root_token, "resource-group/groups/team/history", true)
            .await
            .unwrap()
            .unwrap();
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

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_list_filter_on_groups_gated_list_kv() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_list_filter_on_groups_gated_list_kv").await;

        // Policy grants read+list on kv/*, gated on membership in "crew".
        // The list op can't literally "belong to a group" — the
        // post-route filter narrows the returned keys to group members.
        let gated_hcl = r#"
            path "kv/*" {
                capabilities = ["read", "list"]
                groups = ["crew"]
            }
        "#;
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/policy/p-list-gated",
            true,
            json!({ "policy": gated_hcl }).as_object().cloned(),
        )
        .await;

        // KV-v1 mount with three secrets; two join the crew, one stays out.
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/mounts/kv/",
            true,
            json!({ "type": "kv" }).as_object().cloned(),
        )
        .await;
        for k in ["alpha", "beta", "gamma"] {
            let _ = test_write_api(
                &core,
                &root_token,
                &format!("kv/{k}"),
                true,
                json!({ "v": "x" }).as_object().cloned(),
            )
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

        // alice gets the gated policy.
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/auth/pass",
            true,
            json!({ "type": "userpass" }).as_object().cloned(),
        )
        .await;
        let _ = test_write_api(
            &core,
            &root_token,
            "auth/pass/users/alice",
            true,
            json!({
                "password": "hunter22XX!",
                "token_policies": "p-list-gated",
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

        // Listing kv/ as alice returns only group members — alpha, beta.
        // gamma lives in no group, so it is filtered out.
        let resp = test_list_api(&core, &token, "kv/", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        let keys = data["keys"].as_array().unwrap();
        let names: Vec<&str> = keys.iter().filter_map(|v| v.as_str()).collect();
        assert!(names.contains(&"alpha"), "expected alpha in {names:?}");
        assert!(names.contains(&"beta"), "expected beta in {names:?}");
        assert!(!names.contains(&"gamma"), "gamma should be filtered out of {names:?}");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_kv_delete_prunes_from_groups() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_kv_delete_prunes_from_groups").await;

        // KV-v1 mount, one secret, and a group containing it.
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/mounts/kv/",
            true,
            json!({ "type": "kv" }).as_object().cloned(),
        )
        .await;
        let _ = test_write_api(
            &core,
            &root_token,
            "kv/s1",
            true,
            json!({ "v": "x" }).as_object().cloned(),
        )
        .await;
        let _ = test_write_api(
            &core,
            &root_token,
            "resource-group/groups/club",
            true,
            json!({ "secrets": "kv/s1,kv/s2" }).as_object().cloned(),
        )
        .await;

        // Precondition: s1 and s2 are both listed as members.
        let resp = test_read_api(&core, &root_token, "resource-group/groups/club", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["secrets"], json!(["kv/s1", "kv/s2"]));

        // Delete kv/s1 — the post-route hook prunes it from the group.
        let _ = test_delete_api(&core, &root_token, "kv/s1", true, None).await;

        let resp = test_read_api(&core, &root_token, "resource-group/groups/club", true)
            .await
            .unwrap()
            .unwrap();
        // kv/s1 is gone; kv/s2 remains (never deleted).
        assert_eq!(resp.data.unwrap()["secrets"], json!(["kv/s2"]));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_policy_write_warns_on_unknown_groups() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_policy_write_warns_on_unknown_groups").await;

        // Create one real group so the check can distinguish "unknown"
        // from "no group subsystem present".
        let _ = test_write_api(
            &core,
            &root_token,
            "resource-group/groups/real",
            true,
            json!({}).as_object().cloned(),
        )
        .await;

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
