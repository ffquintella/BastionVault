//! Tests for the resource engine, which lives in `crates/bv-engine-resource`.
//!
//! Lifted out of the engine because they stand up a whole vault through
//! `crate::test_utils`; the engine's pure unit tests stayed with it.
//!
//! See roadmaps/workspace-decomposition.md § Phase 3.

mod brokered_enforcement_tests {
    use crate::test_utils::TestHttpServer;
    use serde_json::json;

    /// End-to-end proof of the brokered attach guard + the four-tier
    /// login-class lock:
    ///   - A resource whose type is pinned `brokered` rejects a static SSH
    ///     credential (private_key / password) with 409.
    ///   - A resource on the default (`shared-credential`) tier still
    ///     accepts a static credential.
    ///   - A per-resource attempt to weaken a locked global `brokered`
    ///     floor is refused with 403 `login_class_locked`.
    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn test_brokered_attach_guard_and_lock() {
        let mut server = TestHttpServer::new("test_brokered_attach_guard", true).await;
        let root = server.root_token.clone();
        server.token = root.clone();

        // Pin the `database` resource type to brokered.
        let (st, _) = server
            .write(
                "ssh-broker/policy/type/database",
                json!({ "login_class": "brokered", "lock": true }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();
        assert!(st == 200 || st == 204, "type policy write status: {st}");

        // Create a database-typed resource and a web-typed one.
        for (name, ty) in [("db01", "database"), ("web01", "web")] {
            let (st, _) = server
                .write(
                    &format!("resources/resources/{name}"),
                    json!({ "name": name, "type": ty }).as_object().cloned(),
                    Some(&root),
                )
                .unwrap();
            assert!(st == 200 || st == 204, "resource {name} write status: {st}");
        }

        // The effective class for db01 resolves to brokered via the type tier.
        let (st, resp) = server
            .write(
                "ssh-broker/policy/effective",
                json!({ "resource_id": "db01", "resource_type": "database" })
                    .as_object()
                    .cloned(),
                Some(&root),
            )
            .unwrap();
        assert_eq!(st, 200, "effective resolve status: {st} {resp:?}");
        assert_eq!(resp["data"]["login_class"], json!("brokered"), "{resp:?}");

        // Attaching a static SSH credential to the brokered resource → 409.
        let (st, resp) = server
            .write(
                "resources/secrets/db01/sshkey",
                json!({ "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n" })
                    .as_object()
                    .cloned(),
                Some(&root),
            )
            .unwrap();
        assert_eq!(st, 409, "brokered attach must be refused: {resp:?}");

        // The same secret on a shared-credential resource succeeds.
        let (st, _) = server
            .write(
                "resources/secrets/web01/sshkey",
                json!({ "password": "hunter2" }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();
        assert!(st == 200 || st == 204, "shared-credential attach status: {st}");

        // Lock the global tier at brokered, then try to relax it per-resource.
        let (st, _) = server
            .write(
                "ssh-broker/policy/global",
                json!({ "login_class_default": "brokered", "login_class_lock": true })
                    .as_object()
                    .cloned(),
                Some(&root),
            )
            .unwrap();
        assert!(st == 200 || st == 204, "global lock write status: {st}");
        let (st, resp) = server
            .write(
                "ssh-broker/policy/resource/db01",
                json!({ "login_class": "shared-credential" }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();
        assert_eq!(st, 403, "relaxing a locked tier must be refused: {resp:?}");
    }
}
mod rename_tests {
    use crate::test_utils::{
        new_unseal_test_bastion_vault, test_read_api, test_write_api,
    };
    use serde_json::json;

    /// End-to-end proof that a rename moves the resource's identity and all
    /// data reachable through the logical API: metadata, secret (+version),
    /// change history, asset-group membership, and attached files. Shares
    /// and ownership are covered by store-level tests in the identity module.
    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn test_resource_rename_migrates_everything() {
        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_resource_rename_migrates_everything").await;

        // Metadata.
        let _ = test_write_api(
            &core,
            &root,
            "resources/resources/old01",
            true,
            json!({ "name": "old01", "type": "server", "hostname": "h.example" })
                .as_object()
                .cloned(),
        )
        .await;

        // Secret (creates secret/, smeta/, sver/ entries).
        let _ = test_write_api(
            &core,
            &root,
            "resources/secrets/old01/login",
            true,
            json!({ "username": "u", "password": "p" }).as_object().cloned(),
        )
        .await;

        // Asset-group membership.
        let _ = test_write_api(
            &core,
            &root,
            "resource-group/groups/alpha",
            true,
            json!({ "members": "old01" }).as_object().cloned(),
        )
        .await;

        // A file attached to the resource ("hello" base64).
        let create = test_write_api(
            &core,
            &root,
            "files/files",
            true,
            json!({ "name": "key.pem", "resource": "old01", "content_base64": "aGVsbG8=" })
                .as_object()
                .cloned(),
        )
        .await
        .unwrap()
        .unwrap();
        let file_id = create.data.unwrap()["id"].as_str().unwrap().to_string();

        // ── Rename ──────────────────────────────────────────────────
        let _ = test_write_api(
            &core,
            &root,
            "resources/resources/old01/rename",
            true,
            json!({ "new_name": "new01" }).as_object().cloned(),
        )
        .await;
        // Files live in a separate mount — re-point them explicitly, as
        // the Tauri orchestrator does.
        let _ = test_write_api(
            &core,
            &root,
            "files/files/repoint-resource",
            true,
            json!({ "old_resource": "old01", "new_resource": "new01" })
                .as_object()
                .cloned(),
        )
        .await;

        // Old metadata is gone (a missing read returns `Ok(None)`).
        let gone = test_read_api(&core, &root, "resources/resources/old01", true)
            .await
            .unwrap();
        assert!(gone.is_none(), "old metadata should be gone: {gone:?}");

        // New metadata exists and carries the new name.
        let resp = test_read_api(&core, &root, "resources/resources/new01", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["name"], json!("new01"));

        // Secret moved to the new name.
        let resp = test_read_api(&core, &root, "resources/secrets/new01/login", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["password"], json!("p"));
        // ...and is gone under the old name (missing read → `Ok(None)`).
        let gone = test_read_api(&core, &root, "resources/secrets/old01/login", true)
            .await
            .unwrap();
        assert!(gone.is_none(), "old secret should be gone: {gone:?}");

        // History carried forward, ending with the rename entry.
        let resp = test_read_api(&core, &root, "resources/resources/new01/history", true)
            .await
            .unwrap()
            .unwrap();
        let entries = resp.data.unwrap()["entries"].as_array().cloned().unwrap();
        let rename_entry = entries
            .iter()
            .find(|e| e["op"] == json!("rename"))
            .unwrap_or_else(|| panic!("expected a rename history entry: {entries:?}"));
        // Audit record: who (user), when (ts), what (old -> new).
        assert!(
            rename_entry["user"].as_str().map(|u| !u.is_empty()).unwrap_or(false),
            "rename entry must record the actor: {rename_entry:?}"
        );
        assert!(
            rename_entry["ts"].as_str().map(|t| !t.is_empty()).unwrap_or(false),
            "rename entry must record a timestamp: {rename_entry:?}"
        );
        assert_eq!(
            rename_entry["changed_fields"],
            json!(["old01 -> new01"]),
            "rename entry must record the old -> new change: {rename_entry:?}"
        );

        // Asset-group membership re-pointed.
        let resp = test_read_api(&core, &root, "resource-group/by-resource/new01", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["groups"], json!(["alpha"]));
        let resp = test_read_api(&core, &root, "resource-group/by-resource/old01", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["groups"], json!([] as [String; 0]));

        // File re-pointed to the new resource name; blob untouched.
        let resp = test_read_api(&core, &root, &format!("files/files/{file_id}"), true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["resource"], json!("new01"));
    }

    /// Renaming onto an existing name must be refused so a rename can never
    /// silently clobber another resource.
    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn test_resource_rename_rejects_collision() {
        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_resource_rename_rejects_collision").await;

        for name in ["a01", "b01"] {
            let _ = test_write_api(
                &core,
                &root,
                &format!("resources/resources/{name}"),
                true,
                json!({ "name": name, "type": "server" }).as_object().cloned(),
            )
            .await;
        }

        // a01 -> b01 collides.
        let _ = test_write_api(
            &core,
            &root,
            "resources/resources/a01/rename",
            false,
            json!({ "new_name": "b01" }).as_object().cloned(),
        )
        .await;
        // a01 still exists.
        let _ = test_read_api(&core, &root, "resources/resources/a01", true).await;
    }

    /// An invalid or same-name target is refused.
    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn test_resource_rename_rejects_invalid_and_noop() {
        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_resource_rename_rejects_invalid_and_noop").await;

        let _ = test_write_api(
            &core,
            &root,
            "resources/resources/host01",
            true,
            json!({ "name": "host01", "type": "server" }).as_object().cloned(),
        )
        .await;

        // Path-escaping name.
        let _ = test_write_api(
            &core,
            &root,
            "resources/resources/host01/rename",
            false,
            json!({ "new_name": "bad/name" }).as_object().cloned(),
        )
        .await;
        // No-op (same canonical name).
        let _ = test_write_api(
            &core,
            &root,
            "resources/resources/host01/rename",
            false,
            json!({ "new_name": "HOST01" }).as_object().cloned(),
        )
        .await;
        // Empty.
        let _ = test_write_api(
            &core,
            &root,
            "resources/resources/host01/rename",
            false,
            json!({ "new_name": "  " }).as_object().cloned(),
        )
        .await;
    }
}
mod search_visibility_tests {
    use bv_kernel_api::VaultCtx;
    use crate::logical::{Operation, Request};
    use crate::test_utils::{new_unseal_test_bastion_vault, test_read_api, test_write_api};
    use serde_json::json;

    async fn login_pass(core: &dyn VaultCtx, user: &str) -> String {
        let mut req = Request::new(&format!("auth/pass/login/{user}"));
        req.operation = Operation::Write;
        req.body = json!({ "password": "hunter22XX!" }).as_object().cloned();
        let resp = core.handle_request(&mut req).await.unwrap().unwrap();
        resp.auth.unwrap().client_token
    }

    /// Create a userpass user carrying `policy_hcl` and return its token.
    async fn user_with_policy(
        core: &dyn VaultCtx,
        root: &str,
        user: &str,
        policy_hcl: &str,
    ) -> String {
        let policy_name = format!("p-{user}");
        let _ = test_write_api(
            core,
            root,
            &format!("sys/policy/{policy_name}"),
            true,
            json!({ "policy": policy_hcl }).as_object().cloned(),
        )
        .await;
        let _ = test_write_api(
            core,
            root,
            "sys/auth/pass",
            true,
            json!({ "type": "userpass" }).as_object().cloned(),
        )
        .await;
        let _ = test_write_api(
            core,
            root,
            &format!("auth/pass/users/{user}"),
            true,
            json!({
                "password": "hunter22XX!",
                "token_policies": policy_name,
                "ttl": 0,
            })
            .as_object()
            .cloned(),
        )
        .await;
        login_pass(core, user).await
    }

    async fn search_names(core: &dyn VaultCtx, token: &str) -> (Vec<String>, u64) {
        let resp = test_write_api(
            core,
            token,
            "resources/resources/search",
            true,
            json!({ "limit": 50 }).as_object().cloned(),
        )
        .await
        .unwrap()
        .unwrap();
        let data = resp.data.unwrap();
        let names = data["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v["name"].as_str().map(str::to_string))
            .collect();
        (names, data["total"].as_u64().unwrap())
    }

    async fn create_resources(core: &dyn VaultCtx, root: &str, names: &[&str]) {
        for n in names {
            let _ = test_write_api(
                core,
                root,
                &format!("resources/resources/{n}"),
                true,
                json!({ "type": "server", "hostname": format!("{n}.example") })
                    .as_object()
                    .cloned(),
            )
            .await;
        }
    }

    /// A caller granted search plus `read` on exactly one resource sees
    /// exactly that resource — not the names, hostnames, tags, or
    /// connection-profile shapes of the others. `total` and `has_more`
    /// describe the filtered set, so paging stays honest.
    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn test_search_returns_only_readable_resources() {
        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_search_returns_only_readable_resources").await;
        create_resources(&core, &root, &["r-alpha", "r-beta", "r-gamma"]).await;

        let alice = user_with_policy(
            &core,
            &root,
            "alice",
            r#"
                path "resources/resources/search" {
                    capabilities = ["create", "update"]
                }
                path "resources/resources/r-alpha" {
                    capabilities = ["read"]
                }
            "#,
        )
        .await;

        let (names, total) = search_names(&core, &alice).await;
        assert_eq!(names, vec!["r-alpha".to_string()], "alice must see only r-alpha");
        assert_eq!(total, 1, "total must count the filtered set, not the vault");

        // Root's view is unchanged — the filter short-circuits on root privs.
        let (names, total) = search_names(&core, &root).await;
        assert_eq!(total, 3, "root must still see every resource: {names:?}");
    }

    /// The filter must resolve access that comes from a *share*, not just from
    /// an ungated policy grant. This is the case that would silently break if
    /// the check were built on `ACL::explain_capability`, which probes with an
    /// identity-less request and so fails every `scopes`-gated rule closed.
    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn test_search_surfaces_a_shared_resource() {
        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_search_surfaces_a_shared_resource").await;
        create_resources(&core, &root, &["r-private", "r-shared"]).await;

        // Bob's only read grant on resources is gated on `shared`, so he sees
        // nothing until a share exists.
        let bob = user_with_policy(
            &core,
            &root,
            "bob",
            r#"
                path "resources/resources/search" {
                    capabilities = ["create", "update"]
                }
                path "resources/resources/*" {
                    capabilities = ["read"]
                    scopes = ["shared"]
                }
            "#,
        )
        .await;

        let (names, total) = search_names(&core, &bob).await;
        assert!(names.is_empty(), "bob must see nothing before the share: {names:?}");
        assert_eq!(total, 0);

        // Root shares r-shared with bob.
        let self_rec = test_read_api(&core, &bob, "identity/entity/self", true)
            .await
            .unwrap()
            .unwrap();
        let bob_id = self_rec.data.unwrap()["entity_id"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(!bob_id.is_empty(), "bob must have an entity_id to be a share grantee");
        // The URL segment is base64url(canonical path) even though
        // `target_path` in the body is authoritative — the route validates the
        // segment before reading the body.
        let target_b64 = {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
            URL_SAFE_NO_PAD.encode("r-shared")
        };
        let _ = test_write_api(
            &core,
            &root,
            &format!("identity/sharing/by-target/resource/{target_b64}/{bob_id}"),
            true,
            json!({
                "target_kind": "resource",
                "target_path": "r-shared",
                "capabilities": "read",
            })
            .as_object()
            .cloned(),
        )
        .await;

        let (names, total) = search_names(&core, &bob).await;
        assert_eq!(
            names,
            vec!["r-shared".to_string()],
            "the shared resource must appear once the share exists"
        );
        assert_eq!(total, 1, "r-private must stay hidden");
    }
}
mod ticket_store_tests {
    use crate::modules::resource::connect_mfa::*;
    // Mirrors the imports `connect_mfa.rs` had when this block lived inside
    // it as a `#[cfg(test)] mod` reaching them through `use super::*` — a glob
    // sees a module's private `use` statements only from inside the crate.
    use chrono::{Duration as ChronoDuration, Utc};

    use crate::storage::{barrier_view::BarrierView, Storage, StorageEntry};
    use bv_kernel_api::VaultCtx;

    fn binding() -> TicketBinding {
        TicketBinding {
            mount: "userpass/".into(),
            principal: "alice".into(),
            namespace: String::new(),
            resource: "web01".into(),
            profile_id: "p_abc".into(),
        }
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn ticket_mint_consume_is_single_use_and_bound() {
        let (_bvault, core, _root) =
            crate::test_utils::new_unseal_test_bastion_vault("test_connect_mfa_ticket").await;
        let store = ConnectMfaTicketStore::new(&core).unwrap();

        let (ticket, record) = store.mint(&binding(), "totp").await.unwrap();
        assert_eq!(record.method, "totp");
        assert_eq!(record.resource, "web01");

        // Redeems once…
        let got = store.consume(&ticket, &binding()).await.unwrap();
        assert_eq!(got.profile_id, "p_abc");

        // …and never again.
        assert!(matches!(
            store.consume(&ticket, &binding()).await,
            Err(TicketError::Unknown)
        ));

        // A ticket that was never minted is unknown, and an empty one too.
        assert!(matches!(store.consume("nope", &binding()).await, Err(TicketError::Unknown)));
        assert!(matches!(store.consume("", &binding()).await, Err(TicketError::Unknown)));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn ticket_binding_mismatches_are_refused() {
        let (_bvault, core, _root) =
            crate::test_utils::new_unseal_test_bastion_vault("test_connect_mfa_binding").await;
        let store = ConnectMfaTicketStore::new(&core).unwrap();

        // Wrong resource.
        let (t, _) = store.mint(&binding(), "fido2").await.unwrap();
        let mut other = binding();
        other.resource = "db01".into();
        assert!(matches!(
            store.consume(&t, &other).await,
            Err(TicketError::Mismatch("resource"))
        ));

        // Wrong profile.
        let (t, _) = store.mint(&binding(), "fido2").await.unwrap();
        let mut other = binding();
        other.profile_id = "p_other".into();
        assert!(matches!(
            store.consume(&t, &other).await,
            Err(TicketError::Mismatch("profile"))
        ));

        // Wrong principal.
        let (t, _) = store.mint(&binding(), "fido2").await.unwrap();
        let mut other = binding();
        other.principal = "mallory".into();
        assert!(matches!(
            store.consume(&t, &other).await,
            Err(TicketError::Mismatch("principal"))
        ));

        // Wrong namespace — a same-named resource in another tenant.
        let (t, _) = store.mint(&binding(), "fido2").await.unwrap();
        let mut other = binding();
        other.namespace = "tenant-b".into();
        assert!(matches!(
            store.consume(&t, &other).await,
            Err(TicketError::Mismatch("namespace"))
        ));

        // Every failed redemption still burnt its ticket.
        assert_eq!(store.tidy().await.unwrap(), 0);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn expired_tickets_are_refused_and_reaped() {
        let (_bvault, core, _root) =
            crate::test_utils::new_unseal_test_bastion_vault("test_connect_mfa_expiry").await;
        let store = ConnectMfaTicketStore::new(&core).unwrap();

        // Mint, then rewrite the record with an expiry in the past. Going
        // through storage directly keeps the test deterministic without a
        // clock abstraction.
        let (ticket, mut record) = store.mint(&binding(), "totp").await.unwrap();
        record.expires_at = (Utc::now() - ChronoDuration::seconds(1)).to_rfc3339();
        let view = BarrierView::new(core.barrier().clone(), "");
        view.put(&StorageEntry {
            key: ticket_key(&ticket),
            value: serde_json::to_vec(&record).unwrap(),
        })
        .await
        .unwrap();

        assert!(matches!(
            store.consume(&ticket, &binding()).await,
            Err(TicketError::Expired { .. })
        ));

        // tidy() removes stale records that were never presented.
        let (_unused, mut stale) = store.mint(&binding(), "totp").await.unwrap();
        stale.expires_at = (Utc::now() - ChronoDuration::seconds(1)).to_rfc3339();
        view.put(&StorageEntry {
            key: ticket_key(&_unused),
            value: serde_json::to_vec(&stale).unwrap(),
        })
        .await
        .unwrap();
        assert_eq!(store.tidy().await.unwrap(), 1);
    }
}

mod gate_tests {
    use crate::test_utils::TestHttpServer;

    /// End-to-end proof that the gate is decided and enforced server-side,
    /// on both the direct pre-flight and the brokered open.
    ///
    /// The profiles live on the resource record exactly as the GUI writes
    /// them, so this also pins the storage shape the server reads
    /// `require_mfa` out of.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn connect_gate_is_enforced_server_side() {
        let mut server = TestHttpServer::new("test_connect_mfa_gate", true).await;
        let root = server.root_token.clone();
        server.token = root.clone();

        server
            .write(
                "resources/secrets/db/ssh",
                serde_json::json!({ "password": "hunter2", "username": "deploy" }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();

        // One gated profile, one ungated, on the same resource.
        server
            .write(
                "resources/resources/db",
                serde_json::json!({
                    "name": "db",
                    "type": "server",
                    "os_type": "linux",
                    "hostname": "db.internal",
                    "connection_profiles": [
                        {
                            "id": "p_open",
                            "name": "Default",
                            "protocol": "ssh",
                            "username": "deploy",
                            "credential_source": { "kind": "secret", "secret_id": "ssh" }
                        },
                        {
                            "id": "p_gated",
                            "name": "Break-glass",
                            "protocol": "ssh",
                            "username": "root",
                            "require_mfa": true,
                            "credential_source": { "kind": "secret", "secret_id": "ssh" }
                        }
                    ]
                })
                .as_object()
                .cloned(),
                Some(&root),
            )
            .unwrap();

        let authorize = |token: &str, profile_id: &str, ticket: Option<&str>| -> u16 {
            let mut body = serde_json::Map::new();
            body.insert("resource".into(), serde_json::Value::String("db".into()));
            body.insert("profile_id".into(), serde_json::Value::String(profile_id.into()));
            if let Some(t) = ticket {
                body.insert("connect_ticket".into(), serde_json::Value::String(t.into()));
            }
            server.write("resources/v2/connect/authorize", Some(body), Some(token)).unwrap().0
        };

        // Ungated profile: authorized with no ticket, no behaviour change.
        assert!(
            (200..300).contains(&authorize(&root, "p_open", None)),
            "an ungated profile must authorize without a ticket"
        );

        // Gated profile with no ticket: refused. This is the whole feature.
        assert_eq!(
            authorize(&root, "p_gated", None),
            403,
            "a gated profile must be refused without a connect ticket"
        );

        // A fabricated ticket does not help — the server checks its own store,
        // not the caller's claim.
        assert_eq!(
            authorize(&root, "p_gated", Some("not-a-real-ticket")),
            403,
            "an unknown ticket must be refused"
        );

        // The brokered path refuses too, before it resolves any credential or
        // contacts a bastion. A 502/503 here would mean it had sailed past the
        // gate and failed later at dispatch.
        let brokered = |profile_id: &str| -> u16 {
            server
                .write(
                    "rustion/v2/session/open",
                    serde_json::json!({
                        "resource_name": "db",
                        "profile_id": profile_id,
                        "credential_source": { "kind": "secret", "secret_id": "ssh" },
                        "target_host": "10.0.0.5",
                        "target_port": 22,
                        "target_protocol": "ssh"
                    })
                    .as_object()
                    .cloned(),
                    Some(&root),
                )
                .unwrap()
                .0
        };
        assert_eq!(
            brokered("p_gated"),
            403,
            "the brokered open must refuse a gated profile before dispatch"
        );

        // An un-attributed brokered open (no profile_id) against a resource
        // that carries a gated profile is refused rather than routed around
        // the gate.
        let unattributed = server
            .write(
                "rustion/v2/session/open",
                serde_json::json!({
                    "resource_name": "db",
                    "credential_source": { "kind": "secret", "secret_id": "ssh" },
                    "target_host": "10.0.0.5",
                    "target_port": 22,
                    "target_protocol": "ssh"
                })
                .as_object()
                .cloned(),
                Some(&root),
            )
            .unwrap()
            .0;
        assert_eq!(
            unattributed, 400,
            "omitting profile_id on a resource with a gated profile must fail closed"
        );

        // The ungated profile still reaches dispatch on the brokered path —
        // proof the gate did not become a blanket refusal.
        let open = brokered("p_open");
        assert!(
            open == 502 || open == 503,
            "an ungated profile must pass the gate and fail only at dispatch (no bastion), got {open}"
        );
    }
}
