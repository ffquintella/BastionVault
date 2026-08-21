//! Lifted from `crates/bv-kernel/src/modules/identity/mod.rs`.
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

    use crate::modules::identity::*;
    use crate::test_utils::{
        new_unseal_test_bastion_vault, test_delete_api, test_list_api, test_read_api,
        test_write_api,
    };

    /// Regression: a userpass user that has never logged in must
    /// still appear in the alias list that drives the GUI user-picker.
    /// Before the pre-provision hook in `write_user`, the alias was
    /// only created on first login, so admins couldn't grant shares
    /// to a freshly-created user until after they authenticated once.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_userpass_create_preprovisions_entity_alias() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_userpass_create_preprovisions_entity_alias").await;

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
            "auth/pass/users/felipe",
            true,
            json!({
                "password": "hunter22XX!",
                "token_policies": "default",
            })
            .as_object()
            .cloned(),
        )
        .await
        .unwrap();

        // The aliases list — which the GUI reads — must now contain
        // felipe even though felipe has never logged in.
        let resp = test_read_api(&core, &root_token, "identity/entity/aliases", true)
            .await
            .unwrap()
            .unwrap();
        let body = resp.data.unwrap();
        let arr = body.get("aliases").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let has_felipe = arr.iter().any(|v| {
            let o = v.as_object();
            o.and_then(|o| o.get("name").and_then(|v| v.as_str())) == Some("felipe")
                && o.and_then(|o| o.get("mount").and_then(|v| v.as_str())) == Some("userpass/")
                && o.and_then(|o| o.get("entity_id").and_then(|v| v.as_str()))
                    .map(|s| !s.is_empty())
                    .unwrap_or(false)
        });
        assert!(
            has_felipe,
            "freshly-created userpass user should appear in the alias list: {arr:?}",
        );

        // Delete the user → alias disappears from the list (entity
        // record itself stays so audit trails are preserved, but the
        // (mount,name) lookup is gone).
        let _ = test_delete_api(&core, &root_token, "auth/pass/users/felipe", true, None).await;

        let resp = test_read_api(&core, &root_token, "identity/entity/aliases", true)
            .await
            .unwrap()
            .unwrap();
        let body = resp.data.unwrap();
        let arr = body.get("aliases").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let still_there = arr.iter().any(|v| {
            v.as_object()
                .and_then(|o| o.get("name").and_then(|v| v.as_str()))
                == Some("felipe")
        });
        assert!(!still_there, "delete-user should forget the alias: {arr:?}");
    }

    /// List `identity/entity/aliases` with an explicit namespace header.
    /// `test_list_api` builds a header-less request, and the header is the
    /// only thing that scopes this route.
    #[maybe_async::maybe_async]
    async fn list_aliases_in_ns(
        core: &dyn VaultCtx,
        token: &str,
        ns: &str,
    ) -> Vec<serde_json::Value> {
        let mut req = Request::new("identity/entity/aliases");
        req.operation = Operation::List;
        req.client_token = token.to_string();
        if !ns.is_empty() {
            let mut headers = HashMap::new();
            headers.insert("X-BastionVault-Namespace".to_string(), ns.to_string());
            req.headers = Some(headers);
        }
        let resp = core.handle_request(&mut req).await.unwrap().unwrap();
        resp.data
            .and_then(|d| d.get("aliases").and_then(|v| v.as_array()).cloned())
            .unwrap_or_default()
    }

    fn alias_named<'a>(
        arr: &'a [serde_json::Value],
        name: &str,
    ) -> Option<&'a serde_json::Map<String, serde_json::Value>> {
        arr.iter()
            .filter_map(|v| v.as_object())
            .find(|o| o.get("name").and_then(|v| v.as_str()) == Some(name))
    }

    /// Regression: the grantee picker was permanently empty in every
    /// non-root namespace. Aliases are written to root — `write_user`
    /// pre-provisions there unconditionally, and users on this deployment
    /// authenticate at root — while the list route scoped itself to the
    /// namespace header alone, so a namespaced caller saw zero grantees and
    /// could not share anything without pasting a raw UUID.
    ///
    /// A namespaced listing must therefore carry root's aliases too, each
    /// tagged with the namespace it came from, while a *sibling* namespace's
    /// aliases stay invisible.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_entity_aliases_list_includes_root_in_namespace() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_entity_aliases_list_includes_root_in_namespace")
                .await;

        for ns in ["pns", "sib"] {
            let _ = test_write_api(
                &core,
                &root_token,
                &format!("sys/namespaces/{ns}"),
                true,
                json!({}).as_object().cloned(),
            )
            .await
            .unwrap();
        }

        // A root user: created at root, alias pre-provisioned at root.
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
            "auth/pass/users/rootuser",
            true,
            json!({ "password": "hunter22XX!", "token_policies": "default" })
                .as_object()
                .cloned(),
        )
        .await
        .unwrap();

        // An alias that only exists in the sibling namespace's keyspace —
        // what a namespaced login would have created.
        let store = EntityStore::new(&core).await.unwrap();
        let sib_entity = store
            .get_or_create_entity_ns("userpass/", "sibuser", "sib")
            .await
            .unwrap();

        // Root's own listing is unchanged: root aliases, tagged root.
        let at_root = list_aliases_in_ns(&core, &root_token, "").await;
        let root_rec = alias_named(&at_root, "rootuser")
            .unwrap_or_else(|| panic!("root listing must contain rootuser: {at_root:?}"));
        assert_eq!(
            root_rec.get("namespace").and_then(|v| v.as_str()),
            Some(""),
            "root alias must be tagged with the root namespace: {root_rec:?}"
        );
        assert!(
            alias_named(&at_root, "sibuser").is_none(),
            "a namespace's alias must not leak into root's listing: {at_root:?}"
        );

        // The regression itself: listing from `pns` sees root's user.
        let in_pns = list_aliases_in_ns(&core, &root_token, "pns").await;
        let seen = alias_named(&in_pns, "rootuser").unwrap_or_else(|| {
            panic!("a namespaced listing must include root's aliases: {in_pns:?}")
        });
        assert_eq!(
            seen.get("namespace").and_then(|v| v.as_str()),
            Some(""),
            "a root alias surfaced in a namespace must still say it is root's: {seen:?}"
        );
        assert!(
            seen.get("entity_id").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false),
            "grantee picker needs a usable entity_id: {seen:?}"
        );

        // ...but not the sibling's, which stays isolated.
        assert!(
            alias_named(&in_pns, "sibuser").is_none(),
            "a sibling namespace's aliases must not be visible from `pns`: {in_pns:?}"
        );

        // The sibling's own listing has it, tagged with its namespace.
        let in_sib = list_aliases_in_ns(&core, &root_token, "sib").await;
        let sib_rec = alias_named(&in_sib, "sibuser")
            .unwrap_or_else(|| panic!("`sib` must see its own alias: {in_sib:?}"));
        assert_eq!(
            sib_rec.get("namespace").and_then(|v| v.as_str()),
            Some("sib"),
            "a namespace-local alias must be tagged with its namespace: {sib_rec:?}"
        );
        assert_eq!(
            sib_rec.get("entity_id").and_then(|v| v.as_str()),
            Some(sib_entity.id.as_str()),
            "the namespace-local entity_id is the one a namespaced login resolves to: {sib_rec:?}"
        );
        assert!(
            alias_named(&in_sib, "rootuser").is_some(),
            "`sib` must also see root's aliases: {in_sib:?}"
        );
    }

    /// Regression: a share granted inside a namespace to a login whose only
    /// entity lives in root must be redeemable by that login when it signs in
    /// to the namespace.
    ///
    /// The grantee picker lists the active namespace's aliases *plus* root's,
    /// and for a user who has never logged in to the namespace the root row is
    /// the only row on offer. Keying the share on it produced a grant nobody
    /// could redeem: `identity/sharing/for-me` indexes by the caller's own
    /// `entity_id`, which for a namespace login is a *different* UUID, so the
    /// share was invisible to the person it named and every
    /// `scopes = ["shared"]` rule resolved no capabilities.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_share_grant_in_namespace_keys_on_the_namespace_entity() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_share_grant_in_namespace_keys_on_the_namespace_entity")
                .await;

        let _ = test_write_api(
            &core,
            &root_token,
            "sys/namespaces/pns",
            true,
            json!({}).as_object().cloned(),
        )
        .await
        .unwrap();

        // The grantee exists only in root — the state of every user who has
        // not yet logged in to the namespace.
        let store = EntityStore::new(&core).await.unwrap();
        let root_entity = store
            .get_or_create_entity_ns("userpass/", "grantee", "")
            .await
            .unwrap();
        assert!(
            store.get_by_alias_ns("userpass/", "grantee", "pns").await.unwrap().is_none(),
            "precondition: the grantee must have no entity in `pns` yet"
        );

        // Grant inside `pns`, naming the only row the picker could offer.
        let target = URL_SAFE_NO_PAD.encode("db1".as_bytes());
        let mut req = Request::new(&format!(
            "identity/sharing/by-target/resource/{target}/{}",
            root_entity.id
        ));
        req.operation = Operation::Write;
        req.client_token = root_token.clone();
        let mut headers = HashMap::new();
        headers.insert("X-BastionVault-Namespace".to_string(), "pns".to_string());
        req.headers = Some(headers);
        req.body = json!({ "capabilities": ["read", "connect"] }).as_object().cloned();
        let resp = core.handle_request(&mut req).await.unwrap().unwrap();
        let stored = resp.data.unwrap();

        // The share is keyed on `pns`'s entity for that login, which the grant
        // pre-provisioned exactly as a first login would have.
        let pns_entity = store
            .get_by_alias_ns("userpass/", "grantee", "pns")
            .await
            .unwrap()
            .expect("granting in `pns` must resolve the login's entity there");
        assert_ne!(
            pns_entity.id, root_entity.id,
            "a namespace login resolves to its own entity, or there is nothing to fix"
        );
        assert_eq!(
            stored.get("grantee_entity_id").and_then(|v| v.as_str()),
            Some(pns_entity.id.as_str()),
            "the share must name the entity that authenticates in `pns`: {stored:?}"
        );

        // And it is reachable through the index that feeds "Shared with me".
        let share_store = ShareStore::new(&core).await.unwrap();
        let ptrs = share_store
            .list_shares_for_grantee(&pns_entity.id)
            .await
            .unwrap();
        assert!(
            ptrs.iter().any(|p| p.target_path.ends_with("db1")),
            "the grantee's own feed must list the share: {ptrs:?}"
        );
        assert!(
            share_store
                .list_shares_for_grantee(&root_entity.id)
                .await
                .unwrap()
                .is_empty(),
            "nothing may be left keyed on the entity that never authenticates in `pns`"
        );

        // The capability the scope gate demands resolves for the right entity
        // and for nobody else.
        assert_eq!(
            share_store
                .shared_capabilities(ShareTargetKind::Resource, "pns/db1", &pns_entity.id)
                .await
                .unwrap(),
            vec!["read".to_string(), "connect".to_string()],
        );
        assert!(
            share_store
                .shared_capabilities(ShareTargetKind::Resource, "pns/db1", &root_entity.id)
                .await
                .unwrap()
                .is_empty(),
        );
    }

    /// The mirror case, and the reason the re-point is conditional: a grant at
    /// root must stay on root's entity even when the grantee also has a
    /// namespace entity. Re-pointing unconditionally would send a root share
    /// to an identity that never authenticates at root — the same bug with the
    /// sign flipped.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_share_grant_at_root_keys_on_the_root_entity() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_share_grant_at_root_keys_on_the_root_entity").await;

        let _ = test_write_api(
            &core,
            &root_token,
            "sys/namespaces/pns",
            true,
            json!({}).as_object().cloned(),
        )
        .await
        .unwrap();

        let store = EntityStore::new(&core).await.unwrap();
        let root_entity = store.get_or_create_entity_ns("userpass/", "both", "").await.unwrap();
        let ns_entity = store.get_or_create_entity_ns("userpass/", "both", "pns").await.unwrap();
        assert_ne!(root_entity.id, ns_entity.id);

        // Grant at root, naming the *namespace* entity — the inverse mistake.
        let target = URL_SAFE_NO_PAD.encode("db2".as_bytes());
        let mut req = Request::new(&format!(
            "identity/sharing/by-target/resource/{target}/{}",
            ns_entity.id
        ));
        req.operation = Operation::Write;
        req.client_token = root_token.clone();
        req.body = json!({ "capabilities": ["read"] }).as_object().cloned();
        let resp = core.handle_request(&mut req).await.unwrap().unwrap();
        let stored = resp.data.unwrap();

        assert_eq!(
            stored.get("grantee_entity_id").and_then(|v| v.as_str()),
            Some(root_entity.id.as_str()),
            "a root grant belongs to the entity that authenticates at root: {stored:?}"
        );
    }

    /// A grantee id that resolves to no entity at all — a raw UUID pasted by
    /// an operator, or a share restored from a backup — has no login to
    /// re-resolve, so it must be stored verbatim rather than guessed at.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_share_grant_leaves_an_unknown_grantee_alone() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_share_grant_leaves_an_unknown_grantee_alone").await;

        let _ = test_write_api(
            &core,
            &root_token,
            "sys/namespaces/pns",
            true,
            json!({}).as_object().cloned(),
        )
        .await
        .unwrap();

        let orphan = "11111111-2222-3333-4444-555555555555";
        let target = URL_SAFE_NO_PAD.encode("db3".as_bytes());
        let mut req = Request::new(&format!(
            "identity/sharing/by-target/resource/{target}/{orphan}"
        ));
        req.operation = Operation::Write;
        req.client_token = root_token.clone();
        let mut headers = HashMap::new();
        headers.insert("X-BastionVault-Namespace".to_string(), "pns".to_string());
        req.headers = Some(headers);
        req.body = json!({ "capabilities": ["read"] }).as_object().cloned();
        let resp = core.handle_request(&mut req).await.unwrap().unwrap();
        let stored = resp.data.unwrap();

        assert_eq!(
            stored.get("grantee_entity_id").and_then(|v| v.as_str()),
            Some(orphan),
            "an unresolvable grantee must be stored verbatim: {stored:?}"
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_share_store_roundtrip_and_cascade() {
        let (_bvault, core, _root_token) =
            new_unseal_test_bastion_vault("test_share_store_roundtrip_and_cascade").await;

        let store = ShareStore::new(&core).await.unwrap();

        // Create a KV-secret share for grantee 'ent-bob' on 'secret/foo'.
        let share = SecretShare {
            target_kind: "kv-secret".into(),
            target_path: "secret/foo".into(),
            grantee_kind: String::new(),
            grantee_entity_id: "ent-bob".into(),
            granted_by_entity_id: "ent-alice".into(),
            capabilities: vec!["read".into(), "list".into()],
            granted_at: String::new(),
            expires_at: String::new(),
        };
        let stored = store.set_share(share).await.unwrap();
        assert_eq!(stored.capabilities, vec!["read".to_string(), "list".to_string()]);

        // Round-trip read.
        let got = store
            .get_share(ShareTargetKind::KvSecret, "secret/foo", "ent-bob")
            .await
            .unwrap();
        assert!(got.is_some(), "share should be readable by (kind, path, grantee)");

        // KV-v2 path form resolves to the same canonical key.
        let got_v2 = store
            .get_share(ShareTargetKind::KvSecret, "secret/data/foo", "ent-bob")
            .await
            .unwrap();
        assert!(got_v2.is_some(), "v2 `secret/data/foo` should canonicalize to `secret/foo`");

        // shared_capabilities returns the stored list.
        let caps = store
            .shared_capabilities(ShareTargetKind::KvSecret, "secret/foo", "ent-bob")
            .await
            .unwrap();
        assert_eq!(caps, vec!["read".to_string(), "list".to_string()]);

        // by-grantee lookup returns one pointer.
        let ptrs = store.list_shares_for_grantee("ent-bob").await.unwrap();
        assert_eq!(ptrs.len(), 1);
        assert_eq!(ptrs[0].target_kind, "kv-secret");
        assert_eq!(ptrs[0].target_path, "secret/foo");

        // by-target lookup returns one share.
        let shares = store
            .list_shares_for_target(ShareTargetKind::KvSecret, "secret/foo")
            .await
            .unwrap();
        assert_eq!(shares.len(), 1);

        // Cascade delete drops the share, reverse pointer, and capabilities.
        let removed = store
            .cascade_delete_target(ShareTargetKind::KvSecret, "secret/foo")
            .await
            .unwrap();
        assert_eq!(removed, 1);

        let got = store
            .get_share(ShareTargetKind::KvSecret, "secret/foo", "ent-bob")
            .await
            .unwrap();
        assert!(got.is_none());
        let ptrs = store.list_shares_for_grantee("ent-bob").await.unwrap();
        assert!(ptrs.is_empty());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_share_store_rename_target_repoints_resource_shares() {
        let (_bvault, core, _root_token) =
            new_unseal_test_bastion_vault("test_share_store_rename_target_repoints_resource_shares")
                .await;
        let store = ShareStore::new(&core).await.unwrap();

        // Two grantees share the resource `old01`.
        for grantee in ["ent-bob", "ent-carol"] {
            store
                .set_share(SecretShare {
                    target_kind: "resource".into(),
                    target_path: "old01".into(),
                    grantee_kind: String::new(),
                    grantee_entity_id: grantee.into(),
                    granted_by_entity_id: "ent-alice".into(),
                    capabilities: vec!["read".into()],
                    granted_at: String::new(),
                    expires_at: String::new(),
                })
                .await
                .unwrap();
        }

        let moved = store
            .rename_target(ShareTargetKind::Resource, "old01", "new01", "ent-admin")
            .await
            .unwrap();
        assert_eq!(moved, 2);

        // Both shares are now readable at the new name.
        for grantee in ["ent-bob", "ent-carol"] {
            let got = store
                .get_share(ShareTargetKind::Resource, "new01", grantee)
                .await
                .unwrap();
            assert!(got.is_some(), "share for {grantee} should move to new01");
            // ...and gone at the old name.
            let old = store
                .get_share(ShareTargetKind::Resource, "old01", grantee)
                .await
                .unwrap();
            assert!(old.is_none(), "share for {grantee} should not remain at old01");
        }

        // The by-target listing reflects the move.
        let at_new = store
            .list_shares_for_target(ShareTargetKind::Resource, "new01")
            .await
            .unwrap();
        assert_eq!(at_new.len(), 2);
        let at_old = store
            .list_shares_for_target(ShareTargetKind::Resource, "old01")
            .await
            .unwrap();
        assert!(at_old.is_empty());

        // A no-op rename (same canonical name) moves nothing.
        let moved = store
            .rename_target(ShareTargetKind::Resource, "new01", "NEW01", "ent-admin")
            .await
            .unwrap();
        assert_eq!(moved, 0);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_share_store_rejects_invalid_inputs() {
        let (_bvault, core, _root_token) =
            new_unseal_test_bastion_vault("test_share_store_rejects_invalid_inputs").await;
        let store = ShareStore::new(&core).await.unwrap();

        // Empty grantee → error.
        let err = store
            .set_share(SecretShare {
                target_kind: "kv-secret".into(),
                target_path: "secret/foo".into(),
                grantee_entity_id: "".into(),
                capabilities: vec!["read".into()],
                ..Default::default()
            })
            .await;
        assert!(err.is_err());

        // Empty capabilities → error.
        let err = store
            .set_share(SecretShare {
                target_kind: "kv-secret".into(),
                target_path: "secret/foo".into(),
                grantee_entity_id: "ent-x".into(),
                capabilities: vec![],
                ..Default::default()
            })
            .await;
        assert!(err.is_err());

        // Unknown capability is filtered out; if nothing remains → error.
        let err = store
            .set_share(SecretShare {
                target_kind: "kv-secret".into(),
                target_path: "secret/foo".into(),
                grantee_entity_id: "ent-x".into(),
                capabilities: vec!["sudo".into(), "deny".into()],
                ..Default::default()
            })
            .await;
        assert!(err.is_err());

        // Bad target_kind → error.
        let err = store
            .set_share(SecretShare {
                target_kind: "not-a-kind".into(),
                target_path: "secret/foo".into(),
                grantee_entity_id: "ent-x".into(),
                capabilities: vec!["read".into()],
                ..Default::default()
            })
            .await;
        assert!(err.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_identity_user_group_crud() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_identity_user_group_crud").await;

        // Create a user group with members and policies.
        let data = json!({
            "description": "platform engineers",
            "members": "alice,bob",
            "policies": "ops,readonly",
        })
        .as_object()
        .cloned();
        let ret = test_write_api(&core, &root_token, "identity/group/user/platform", true, data).await;
        assert!(ret.is_ok());

        // Read it back.
        let resp = test_read_api(&core, &root_token, "identity/group/user/platform", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["name"], "platform");
        assert_eq!(data["kind"], "user");
        assert_eq!(data["description"], "platform engineers");
        assert_eq!(data["members"], json!(["alice", "bob"]));
        assert_eq!(data["policies"], json!(["ops", "readonly"]));

        // List.
        let resp = test_list_api(&core, &root_token, "identity/group/user", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["keys"], json!(["platform"]));

        // Partial update (members only) preserves other fields.
        let patch = json!({ "members": "alice,bob,carol" }).as_object().cloned();
        let _ = test_write_api(&core, &root_token, "identity/group/user/platform", true, patch).await;
        let resp = test_read_api(&core, &root_token, "identity/group/user/platform", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["members"], json!(["alice", "bob", "carol"]));
        assert_eq!(data["policies"], json!(["ops", "readonly"]));

        // Delete.
        let _ = test_delete_api(&core, &root_token, "identity/group/user/platform", true, None).await;
        let resp = test_read_api(&core, &root_token, "identity/group/user/platform", false).await;
        assert!(resp.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_identity_app_group_isolated_from_user_group() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_identity_app_group_isolated_from_user_group").await;

        let app_data = json!({
            "members": "payments-api,billing-api",
            "policies": "app-readonly",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &root_token, "identity/group/app/services", true, app_data).await;

        // Listing user groups must not see the app group.
        let resp = test_list_api(&core, &root_token, "identity/group/user", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data.get("keys").cloned().unwrap_or(json!([])), json!([] as [String; 0]));

        // Listing app groups sees it.
        let resp = test_list_api(&core, &root_token, "identity/group/app", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["keys"], json!(["services"]));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_identity_group_policy_expansion_at_login() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_identity_group_policy_expansion_at_login").await;

        // Define two policies: one attached directly to the user, one via group.
        let direct_hcl = r#"
            path "path1/direct" {
                capabilities = ["read", "create", "update"]
            }
        "#;
        let group_hcl = r#"
            path "path1/group-only" {
                capabilities = ["read", "create", "update"]
            }
        "#;
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/policy/p-direct",
            true,
            json!({ "policy": direct_hcl }).as_object().cloned(),
        )
        .await;
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/policy/p-group",
            true,
            json!({ "policy": group_hcl }).as_object().cloned(),
        )
        .await;

        // Mount userpass and create user with only the direct policy.
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
                "token_policies": "p-direct",
                "ttl": 0,
            })
            .as_object()
            .cloned(),
        )
        .await;

        // Mount kv so the policies apply to a real path.
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/mounts/path1/",
            true,
            json!({ "type": "kv" }).as_object().cloned(),
        )
        .await;

        // Login and capture the token.
        let mut login_req = Request::new("auth/pass/login/alice");
        login_req.operation = Operation::Write;
        login_req.body = json!({ "password": "hunter22XX!" }).as_object().cloned();
        let resp = core.handle_request(&mut login_req).await.unwrap().unwrap();
        let token = resp.auth.unwrap().client_token;

        // Without group membership: direct path works, group path denied.
        let _ = test_write_api(
            &core,
            &token,
            "path1/direct",
            true,
            json!({ "v": "1" }).as_object().cloned(),
        )
        .await;
        let err = test_write_api(
            &core,
            &token,
            "path1/group-only",
            false,
            json!({ "v": "1" }).as_object().cloned(),
        )
        .await;
        assert!(err.is_err());

        // Add alice to a user-group that grants p-group.
        let _ = test_write_api(
            &core,
            &root_token,
            "identity/group/user/platform",
            true,
            json!({
                "members": "alice",
                "policies": "p-group",
            })
            .as_object()
            .cloned(),
        )
        .await;

        // Re-login to pick up new policies; group path must now work.
        let mut login_req = Request::new("auth/pass/login/alice");
        login_req.operation = Operation::Write;
        login_req.body = json!({ "password": "hunter22XX!" }).as_object().cloned();
        let resp = core.handle_request(&mut login_req).await.unwrap().unwrap();
        let token2 = resp.auth.unwrap().client_token;

        let _ = test_write_api(
            &core,
            &token2,
            "path1/group-only",
            true,
            json!({ "v": "2" }).as_object().cloned(),
        )
        .await;
        // Direct path still works too.
        let _ = test_write_api(
            &core,
            &token2,
            "path1/direct",
            true,
            json!({ "v": "3" }).as_object().cloned(),
        )
        .await;
    }

    // ── Per-user scoping tests ─────────────────────────────────────

    /// Alice writes a secret; Bob (secret-author policy) cannot read
    /// it because the `scopes = ["owner", "shared"]` filter denies
    /// access to non-owned entries without a share. Alice herself
    /// reads her own secret fine.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_per_user_scoping_owner_denies_non_owner() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_per_user_scoping_owner_denies_non_owner").await;

        // The default `secret/` mount is KV-v2; the seeded
        // `secret-author` policy grants CRUD on `secret/data/*` with
        // `scopes=["owner","shared"]`.
        //
        // Userpass with two users, both assigned `secret-author`.
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/auth/pass",
            true,
            json!({ "type": "userpass" }).as_object().cloned(),
        )
        .await;
        for name in ["alice", "bob"] {
            let _ = test_write_api(
                &core,
                &root_token,
                &format!("auth/pass/users/{name}"),
                true,
                json!({
                    "password": "hunter22XX!",
                    "token_policies": "secret-author",
                    "ttl": 0,
                })
                .as_object()
                .cloned(),
            )
            .await;
        }

        // Login as alice and write a KV-v2 secret under secret/data/.
        let alice_token = login_pass(&core, "alice").await;
        let _ = test_write_api(
            &core,
            &alice_token,
            "secret/data/alice-secret",
            true,
            json!({ "data": { "v": "hello" } }).as_object().cloned(),
        )
        .await;

        // Alice can read her own secret (owner match).
        let _ = test_read_api(&core, &alice_token, "secret/data/alice-secret", true).await;

        // Bob with secret-author cannot read alice's secret: the
        // scopes=["owner","shared"] filter denies him because he is
        // not the owner and no share exists.
        let bob_token = login_pass(&core, "bob").await;
        let err = test_read_api(&core, &bob_token, "secret/data/alice-secret", false).await;
        assert!(err.is_err(), "bob should be denied on alice's secret");
    }

    /// `secret-author` grants full CRUD on KV secrets the caller owns.
    /// A non-root user can write, read, update, and delete their own
    /// secret end-to-end.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_secret_author_full_crud_on_owned_secret() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_secret_author_full_crud_on_owned_secret").await;

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
            "auth/pass/users/carol",
            true,
            json!({
                "password": "hunter22XX!",
                "token_policies": "secret-author",
                "ttl": 0,
            })
            .as_object()
            .cloned(),
        )
        .await;

        let carol_token = login_pass(&core, "carol").await;

        // Write: carol becomes owner on the first write.
        let _ = test_write_api(
            &core,
            &carol_token,
            "secret/data/carol-db",
            true,
            json!({ "data": { "v": "pw1" } }).as_object().cloned(),
        )
        .await;
        // Read own.
        let _ = test_read_api(&core, &carol_token, "secret/data/carol-db", true).await;
        // Update own (same path, new value).
        let _ = test_write_api(
            &core,
            &carol_token,
            "secret/data/carol-db",
            true,
            json!({ "data": { "v": "pw2" } }).as_object().cloned(),
        )
        .await;
        // Delete own.
        let _ = test_delete_api(&core, &carol_token, "secret/data/carol-db", true, None).await;
    }

    /// `secret-author` listing a KV mount sees only their own
    /// entries. Alice writes two secrets, bob writes one; bob lists
    /// and only sees bob's own key.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_list_filter_by_ownership() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_list_filter_by_ownership").await;

        let _ = test_write_api(
            &core,
            &root_token,
            "sys/auth/pass",
            true,
            json!({ "type": "userpass" }).as_object().cloned(),
        )
        .await;
        for name in ["alice", "bob"] {
            let _ = test_write_api(
                &core,
                &root_token,
                &format!("auth/pass/users/{name}"),
                true,
                json!({
                    "password": "hunter22XX!",
                    "token_policies": "secret-author",
                    "ttl": 0,
                })
                .as_object()
                .cloned(),
            )
            .await;
        }

        // Alice writes two secrets on the default KV-v2 mount.
        let alice_token = login_pass(&core, "alice").await;
        for k in ["a1", "a2"] {
            let _ = test_write_api(
                &core,
                &alice_token,
                &format!("secret/data/{k}"),
                true,
                json!({ "data": { "v": "x" } }).as_object().cloned(),
            )
            .await;
        }

        // Bob writes one.
        let bob_token = login_pass(&core, "bob").await;
        let _ = test_write_api(
            &core,
            &bob_token,
            "secret/data/b1",
            true,
            json!({ "data": { "v": "x" } }).as_object().cloned(),
        )
        .await;

        // Bob listing the secret metadata index sees only "b1" —
        // a1/a2 are alice-owned and get filtered out by the
        // scopes=["owner","shared"] list gate.
        let resp = test_list_api(&core, &bob_token, "secret/metadata/", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        let keys: Vec<&str> = data["keys"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(keys.contains(&"b1"), "bob should see his own key in {keys:?}");
        assert!(!keys.contains(&"a1"), "bob should not see a1 in {keys:?}");
        assert!(!keys.contains(&"a2"), "bob should not see a2 in {keys:?}");
    }

    /// Regression for a bug where root-created resources showed as
    /// `Unowned` forever in the GUI. The owner-capture hook used to
    /// gate on `entity_id` only, which is empty for the root token, so
    /// every admin-created resource orphaned its owner record. The fix
    /// falls back to `display_name` (via `caller_audit_actor`), which
    /// is `"root"` for root tokens. Owner records must now exist after
    /// a root-token resource write.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_root_token_resource_write_captures_owner() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_root_token_resource_write_captures_owner").await;

        // Root creates a resource. Path is the GUI-facing
        // `resources/resources/<name>` form the post_route hook
        // pattern-matches on.
        let _ = test_write_api(
            &core,
            &root_token,
            "resources/resources/primary-gateway",
            true,
            json!({ "type": "server", "hostname": "gw-01.example" })
                .as_object()
                .cloned(),
        )
        .await;

        // Owner record must now be present and point at `"root"` (the
        // root token's display_name, surfaced via `caller_audit_actor`).
        let module = core
            .module_manager()
            .get_module::<IdentityModule>("identity")
            .expect("identity module");
        let store = module.owner_store().expect("owner store");
        let rec = store
            .get_resource_owner("primary-gateway")
            .await
            .unwrap()
            .expect("owner record must exist after root-token write");
        assert_eq!(
            rec.entity_id, "root",
            "root-created resources must stamp `root` as owner, not leave empty"
        );

        // Symmetrically: root KV writes capture the kv-owner record so
        // the Secrets page's Sharing tab has an owner to display.
        let _ = test_write_api(
            &core,
            &root_token,
            "secret/data/gateway-password",
            true,
            json!({ "data": { "v": "hunter22XX!" } }).as_object().cloned(),
        )
        .await;
        let kv_rec = store
            .get_kv_owner("secret/data/gateway-password")
            .await
            .unwrap()
            .expect("root-token KV write must capture owner record");
        assert_eq!(kv_rec.entity_id, "root");
    }

    /// A "ghost" owner record — an entry with an empty `entity_id` left
    /// over from older server versions — must not block the next
    /// authenticated write from capturing ownership. `get_kv_owner`
    /// surfaces such ghosts as `None` ("Unowned" in the GUI), and the
    /// user-facing promise is that the next write claims them.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_kv_ghost_record_overwritten_by_next_write() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_kv_ghost_record_overwritten").await;

        let module = core
            .module_manager()
            .get_module::<IdentityModule>("identity")
            .expect("identity module");
        let store = module.owner_store().expect("owner store");

        store
            .plant_kv_ghost_for_test("secret/data/ghost-secret")
            .await
            .unwrap();
        assert!(
            store.get_kv_owner("secret/data/ghost-secret").await.unwrap().is_none(),
            "ghost record must report as Unowned",
        );

        let _ = test_write_api(
            &core,
            &root_token,
            "secret/data/ghost-secret",
            true,
            json!({ "data": { "v": "x" } }).as_object().cloned(),
        )
        .await;

        let rec = store
            .get_kv_owner("secret/data/ghost-secret")
            .await
            .unwrap()
            .expect("write after ghost must stamp owner");
        assert_eq!(rec.entity_id, "root");
    }

    /// `sys/owner/backfill` — admin migration endpoint that stamps a
    /// given entity_id as owner of every currently-unowned target in
    /// `resources` + `kv_paths`. Exercises the sudo-gated handler end
    /// to end via `core.handle_request`, including the data-shape of
    /// the response and the never-overwrite invariant.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_owner_backfill_stamps_unowned_and_skips_owned() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_owner_backfill").await;

        let module = core
            .module_manager()
            .get_module::<IdentityModule>("identity")
            .expect("identity module");
        let store = module.owner_store().expect("owner store");

        // Seed three objects in three different states:
        //  - `orphan-resource`: exists in the owner store as unowned
        //    (we write an empty-entity_id record directly to simulate
        //    a pre-fix / legacy object)
        //  - `claimed-resource`: already owned by "alice-ent", must be
        //    left untouched by the backfill.
        //  - `legacy-kv`:  unowned KV path.
        //
        // `record_resource_owner_if_absent` won't write on empty
        // entity_id, so we simulate the legacy unowned state by simply
        // not creating a record at all — `get_resource_owner` returns
        // None, which the handler treats as the "stamp this" case.
        store
            .set_resource_owner("claimed-resource", "alice-ent")
            .await
            .unwrap();

        // Call the backfill endpoint as root (has all capabilities).
        let body = json!({
            "entity_id": "root",
            "resources": ["orphan-resource", "claimed-resource", "missing-slash/bad"],
            "kv_paths": ["secret/data/legacy-kv", "secret/..//escape"],
            "dry_run": false,
        })
        .as_object()
        .cloned();
        let resp = test_write_api(&core, &root_token, "sys/owner/backfill", true, body)
            .await
            .expect("backfill must succeed")
            .expect("response has data");
        let data = resp.data.expect("data envelope");

        let res_stamped = data
            .get("resources")
            .and_then(|v| v.get("stamped"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let res_already = data
            .get("resources")
            .and_then(|v| v.get("already_owned"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let res_invalid: Vec<String> = data
            .get("resources")
            .and_then(|v| v.get("invalid"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        assert_eq!(res_stamped, 1, "orphan-resource must be stamped once");
        assert_eq!(res_already, 1, "claimed-resource must be skipped as already-owned");
        assert_eq!(
            res_invalid,
            vec!["missing-slash/bad".to_string()],
            "names with '/' are invalid resource names"
        );

        let kv_stamped = data
            .get("kv")
            .and_then(|v| v.get("stamped"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let kv_invalid: Vec<String> = data
            .get("kv")
            .and_then(|v| v.get("invalid"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        assert_eq!(kv_stamped, 1, "legacy-kv must be stamped");
        assert_eq!(
            kv_invalid,
            vec!["secret/..//escape".to_string()],
            "malformed KV paths must be reported as invalid, not silently skipped"
        );

        // Verify the writes actually landed and the already-owned
        // record was not overwritten.
        let orphan_rec = store.get_resource_owner("orphan-resource").await.unwrap();
        assert_eq!(orphan_rec.map(|r| r.entity_id), Some("root".to_string()));
        let claimed_rec = store.get_resource_owner("claimed-resource").await.unwrap();
        assert_eq!(
            claimed_rec.map(|r| r.entity_id),
            Some("alice-ent".to_string()),
            "already-owned resource must not be overwritten"
        );
        let kv_rec = store
            .get_kv_owner("secret/data/legacy-kv")
            .await
            .unwrap();
        assert_eq!(kv_rec.map(|r| r.entity_id), Some("root".to_string()));
    }

    /// `dry_run = true` must report what would be stamped without
    /// writing any owner records.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_owner_backfill_dry_run_writes_nothing() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_owner_backfill_dry_run").await;
        let module = core
            .module_manager()
            .get_module::<IdentityModule>("identity")
            .expect("identity module");
        let store = module.owner_store().expect("owner store");

        let body = json!({
            "entity_id": "root",
            "resources": ["will-stay-unowned"],
            "dry_run": true,
        })
        .as_object()
        .cloned();
        let resp = test_write_api(&core, &root_token, "sys/owner/backfill", true, body)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        let stamped = data
            .get("resources")
            .and_then(|v| v.get("stamped"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        assert_eq!(stamped, 1, "dry run still reports what would be stamped");

        // But nothing was actually written.
        assert!(
            store
                .get_resource_owner("will-stay-unowned")
                .await
                .unwrap()
                .is_none(),
            "dry_run must not write owner records"
        );
    }

    /// Missing / empty `entity_id` must be rejected with 400.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_owner_backfill_rejects_empty_entity_id() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_owner_backfill_empty_entity").await;
        let body = json!({
            "entity_id": "",
            "resources": ["x"],
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &root_token, "sys/owner/backfill", false, body).await;
    }

    /// Helper: login via userpass with the shared password used
    /// across per-user-scoping tests.
    #[cfg(test)]
    async fn login_pass(core: &dyn VaultCtx, username: &str) -> String {
        let mut login_req = Request::new(format!("auth/pass/login/{username}"));
        login_req.operation = Operation::Write;
        login_req.body = json!({ "password": "hunter22XX!" }).as_object().cloned();
        let resp = core.handle_request(&mut login_req).await.unwrap().unwrap();
        resp.auth.unwrap().client_token
    }
