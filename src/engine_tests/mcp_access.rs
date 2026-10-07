//! Facade-level tests for MCP Access (`features/mcp-access.md`, Phase 2):
//! the `sys/mcp/*` app registry and the `mcp/token` exchange, both
//! implemented in `crates/bv-kernel/src/modules/system/mcp.rs`. Lives here
//! (not in `bv-kernel`'s own test suite) for the same "tests that could not
//! travel" reason as every other file in this directory: exercising the
//! exchange as a normally-routed request needs a whole vault stood up
//! through `test_utils`, which is a `#[cfg(test)]` module of this crate.

mod mod_test {
    use serde_json::{json, Value};

    use crate::{
        errors::RvError,
        test_utils::{
            new_unseal_test_bastion_vault, test_delete_api, test_list_api, test_mount_auth_api, test_read_api,
            test_write_api,
        },
    };

    /// Mounts AppRole, writes a `bypass_machine_binding` role (so login
    /// succeeds under this test env's `require_machine_identity` default
    /// without a real FerroGate machine token -- the MCP exchange's own
    /// spiffe/waiver check is independent and is what each test below
    /// actually exercises), and writes a policy granting `update` on
    /// `sys/mcp/token` (the exchange).
    async fn setup_app_role(core: &crate::core::Core, root_token: &str, role_name: &str) {
        test_mount_auth_api(core, root_token, "approle", "approle").await;
        let policy_hcl = r#"
            path "sys/mcp/token" { capabilities = ["update"] }
            path "secret/data/ai/*" { capabilities = ["read"] }
        "#;
        let _ = test_write_api(
            core,
            root_token,
            "sys/policy/mcp-reader",
            true,
            json!({ "policy": policy_hcl }).as_object().cloned(),
        )
        .await;

        let role_data = json!({
            "policies": "mcp-reader",
            "bypass_machine_binding": true,
        })
        .as_object()
        .cloned();
        let _ = test_write_api(core, root_token, &format!("auth/approle/role/{role_name}"), true, role_data).await;
    }

    /// A fresh login, minting a brand-new token -- separate from
    /// `setup_app_role` so a test can log in more than once (each of a
    /// role's AppRole logins normally has a bounded number of *token*
    /// uses; a shared token across several exchange attempts in one test
    /// would silently exhaust and fail on a later, unrelated assertion).
    async fn login_as(core: &crate::core::Core, root_token: &str, role_name: &str) -> String {
        let resp = test_read_api(core, root_token, &format!("auth/approle/role/{role_name}/role-id"), true).await;
        let role_id = resp.unwrap().unwrap().data.unwrap()["role_id"].as_str().unwrap().to_string();
        let resp =
            test_write_api(core, root_token, &format!("auth/approle/role/{role_name}/secret-id"), true, None).await;
        let secret_id = resp.unwrap().unwrap().data.unwrap()["secret_id"].as_str().unwrap().to_string();

        let mut req = crate::logical::Request::new("auth/approle/login");
        req.operation = crate::logical::Operation::Write;
        req.body = json!({ "role_id": role_id, "secret_id": secret_id }).as_object().cloned();
        let auth = core.handle_request(&mut req).await.unwrap().unwrap().auth.expect("approle login mints a token");
        assert_eq!(auth.metadata.get("role_name").map(String::as_str), Some(role_name));
        assert!(!auth.metadata.contains_key("spiffe_id"), "no machine identity on a bypassed login");
        auth.client_token
    }

    async fn register_mcp_app(core: &crate::core::Core, root_token: &str, app_name: &str, role_name: &str) {
        let app_data = json!({
            "approle_role": role_name,
            "tool_allowlist": "bv_kv_read_metadata",
            "path_scope": "secret/metadata/ai/*",
            "reveal_allowed": false,
        })
        .as_object()
        .cloned();
        let resp = test_write_api(core, root_token, &format!("sys/mcp/apps/{app_name}"), true, app_data).await;
        assert_eq!(resp.unwrap().unwrap().data.unwrap()["approle_role"], Value::String(role_name.to_string()));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_mcp_app_crud_and_config() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_mcp_app_crud").await;
        let core: &crate::core::Core = &core;

        register_mcp_app(core, &root_token, "ci-secrets-reader", "reader-role").await;

        let resp = test_list_api(core, &root_token, "sys/mcp/apps", true).await;
        let keys = resp.unwrap().unwrap().data.unwrap()["keys"].clone();
        assert_eq!(keys, json!(["ci-secrets-reader"]));

        let resp = test_read_api(core, &root_token, "sys/mcp/apps/ci-secrets-reader", true).await;
        let data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(data["reveal_allowed"], Value::Bool(false));
        assert_eq!(data["tool_allowlist"], json!(["bv_kv_read_metadata"]));

        // Config read/write.
        let resp = test_read_api(core, &root_token, "sys/mcp/config", true).await;
        assert_eq!(resp.unwrap().unwrap().data.unwrap()["waiver_max_days"], json!(90));
        let _ = test_write_api(
            core,
            &root_token,
            "sys/mcp/config",
            true,
            json!({ "waiver_max_days": 30 }).as_object().cloned(),
        )
        .await;
        let resp = test_read_api(core, &root_token, "sys/mcp/config", true).await;
        assert_eq!(resp.unwrap().unwrap().data.unwrap()["waiver_max_days"], json!(30));

        let _ = test_delete_api(core, &root_token, "sys/mcp/apps/ci-secrets-reader", true, None).await;
        let resp = test_read_api(core, &root_token, "sys/mcp/apps/ci-secrets-reader", false).await;
        assert!(resp.is_err());
    }

    /// The exchange refuses an unattested app until a sudo-granted waiver
    /// exists, succeeds once one does, and the minted token is genuinely
    /// MCP-bound (refused everywhere except the MCP dispatcher -- proven
    /// here via `check_token`'s own `is_mcp_dispatcher` gate).
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_mcp_token_exchange_requires_waiver_then_succeeds() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_mcp_exchange_waiver").await;
        let core: &crate::core::Core = &core;

        setup_app_role(core, &root_token, "reader-role").await;
        register_mcp_app(core, &root_token, "ci-secrets-reader", "reader-role").await;

        // No waiver yet, no spiffe_id on the login: refused.
        let exchange_body = || json!({ "app": "ci-secrets-reader" }).as_object().cloned();
        let first_login = login_as(core, &root_token, "reader-role").await;
        let resp = test_write_api(core, &first_login, "sys/mcp/token", false, exchange_body()).await;
        assert!(resp.is_err());

        // Grant the waiver (sudo -- root here) and retry.
        let waiver_data =
            json!({ "reason": "no FerroGate agent on this CI runner", "expires_in_days": 7 }).as_object().cloned();
        let resp =
            test_write_api(core, &root_token, "sys/mcp/apps/ci-secrets-reader/machine-waiver", true, waiver_data).await;
        assert!(resp.unwrap().unwrap().data.unwrap()["machine_waiver"]["reason"].is_string());

        // A non-sudo caller may not grant a waiver.
        let second_login = login_as(core, &root_token, "reader-role").await;
        let resp = test_write_api(
            core,
            &second_login,
            "sys/mcp/apps/ci-secrets-reader/machine-waiver",
            false,
            json!({ "reason": "x", "expires_in_days": 1 }).as_object().cloned(),
        )
        .await;
        assert!(matches!(resp, Err(RvError::ErrPermissionDenied)));

        let login_token = login_as(core, &root_token, "reader-role").await;
        let resp = test_write_api(core, &login_token, "sys/mcp/token", true, exchange_body()).await;
        let data = resp.unwrap().unwrap().data.expect("waived exchange mints a token");
        let mcp_token = data["auth"]["client_token"].as_str().unwrap().to_string();

        // check_token's symmetric gate: MCP-bound refused off the
        // dispatcher, accepted on it.
        let auth_module = core.module_manager().get_module::<crate::modules::auth::AuthModule>("auth").unwrap();
        let token_store = auth_module.token_store.load_full().unwrap();
        assert!(token_store.check_token("secret/data/ai/x", &mcp_token, "", false).await.is_err());
        assert!(token_store.check_token("secret/data/ai/x", &mcp_token, "", true).await.unwrap().is_some());

        // Deleting the app revokes the outstanding token.
        let _ = test_delete_api(core, &root_token, "sys/mcp/apps/ci-secrets-reader", true, None).await;
        assert!(token_store.check_token("secret/data/ai/x", &mcp_token, "", true).await.is_err());
    }

    /// A caller whose AppRole role name does not match the app's
    /// `approle_role` is refused, even with an active waiver.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_mcp_exchange_refuses_role_mismatch() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_mcp_exchange_role_mismatch").await;
        let core: &crate::core::Core = &core;

        setup_app_role(core, &root_token, "some-other-role").await;
        register_mcp_app(core, &root_token, "ci-secrets-reader", "reader-role").await;
        let login_token = login_as(core, &root_token, "some-other-role").await;
        let _ = test_write_api(
            core,
            &root_token,
            "sys/mcp/apps/ci-secrets-reader/machine-waiver",
            true,
            json!({ "reason": "test", "expires_in_days": 1 }).as_object().cloned(),
        )
        .await;

        let resp = test_write_api(
            core,
            &login_token,
            "sys/mcp/token",
            false,
            json!({ "app": "ci-secrets-reader" }).as_object().cloned(),
        )
        .await;
        assert!(matches!(resp, Err(RvError::ErrPermissionDenied)));
    }

    /// Mounts userpass and a policy letting a human operator run the pairing
    /// exchange and revoke a pairing, then returns a fresh login token.
    async fn operator_token(core: &crate::core::Core, root_token: &str, user: &str) -> String {
        test_mount_auth_api(core, root_token, "userpass", "userpass").await;
        let policy_hcl = r#"
            path "sys/mcp/token" { capabilities = ["update"] }
            path "sys/mcp/pairings/*" { capabilities = ["delete"] }
            path "secret/data/ai/*" { capabilities = ["read"] }
        "#;
        let _ = test_write_api(
            core,
            root_token,
            "sys/policy/mcp-pairer",
            true,
            json!({ "policy": policy_hcl }).as_object().cloned(),
        )
        .await;
        let _ = test_write_api(
            core,
            root_token,
            &format!("auth/userpass/users/{user}"),
            true,
            json!({ "password": "pw", "policies": "mcp-pairer" }).as_object().cloned(),
        )
        .await;
        let mut req = crate::logical::Request::new(format!("auth/userpass/login/{user}"));
        req.operation = crate::logical::Operation::Write;
        req.body = json!({ "password": "pw" }).as_object().cloned();
        core.handle_request(&mut req)
            .await
            .unwrap()
            .expect("userpass login response")
            .auth
            .expect("userpass login mints a token")
            .client_token
    }

    fn pairing_body(id: &str) -> Option<serde_json::Map<String, Value>> {
        json!({
            "pairing": {
                "id": id,
                "client_name": "claude-desktop",
                "client_version": "1.2.3",
                "tool_allowlist": ["bv_kv_read_metadata"],
                "path_scope": ["secret/metadata/ai/*"],
                "reveal_allowed": false,
                "destructive_allowed": false,
            },
            "catalogue_hash": "deadbeef",
        })
        .as_object()
        .cloned()
    }

    /// Pairing mode (Phase 4): an operator session exchanges for a
    /// pairing-bound token whose binding carries exactly the approved grant,
    /// is listed as a pairing token, and is revoked by pairing id.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_mcp_pairing_exchange_and_revoke_by_id() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_mcp_pairing_exchange").await;
        let core: &crate::core::Core = &core;
        let op = operator_token(core, &root_token, "felipe").await;

        let resp = test_write_api(core, &op, "sys/mcp/token", true, pairing_body("abc-123")).await;
        let data = resp.unwrap().unwrap().data.expect("pairing exchange mints a token");
        assert_eq!(data["auth"]["metadata"]["mcp_kind"], json!("pairing"));
        let mcp_token = data["auth"]["client_token"].as_str().unwrap().to_string();

        let auth_module = core.module_manager().get_module::<crate::modules::auth::AuthModule>("auth").unwrap();
        let token_store = auth_module.token_store.load_full().unwrap();
        assert!(token_store.check_token("secret/metadata/ai/x", &mcp_token, "", false).await.is_err());
        let auth = token_store
            .check_token("secret/metadata/ai/x", &mcp_token, "", true)
            .await
            .unwrap()
            .expect("a pairing token is accepted on the MCP dispatcher");
        let binding = auth.mcp_binding.expect("token carries its binding");
        assert_eq!(binding.kind, crate::logical::McpBindingKind::Pairing("abc-123".to_string()));
        assert_eq!(binding.client_name, "claude-desktop");
        assert_eq!(binding.tool_allowlist, vec!["bv_kv_read_metadata".to_string()]);
        assert_eq!(binding.path_scope, vec!["secret/metadata/ai/*".to_string()]);
        assert!(!binding.reveal_allowed && !binding.destructive_allowed);
        assert_eq!(binding.catalogue_hash, "deadbeef");

        let resp = test_list_api(core, &root_token, "sys/mcp/tokens", true).await;
        let rows = resp.unwrap().unwrap().data.unwrap()["tokens"].clone();
        assert_eq!(rows[0]["kind"], json!("pairing"));
        assert_eq!(rows[0]["app"], json!("pairing_abc-123"));

        // Revoke by pairing id as the operator (not root).
        let _ = test_delete_api(core, &op, "sys/mcp/pairings/abc-123", true, None).await;
        assert!(token_store.check_token("secret/metadata/ai/x", &mcp_token, "", true).await.is_err());
        let resp = test_list_api(core, &root_token, "sys/mcp/tokens", true).await;
        assert_eq!(resp.unwrap().unwrap().data.unwrap()["tokens"], json!([]));
    }

    /// Pairing is an operator-session feature: AppRole and root callers are
    /// refused, and so is an MCP-bound token or a malformed grant.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_mcp_pairing_refusals() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_mcp_pairing_refusals").await;
        let core: &crate::core::Core = &core;

        // Root.
        let resp = test_write_api(core, &root_token, "sys/mcp/token", false, pairing_body("r1")).await;
        assert!(resp.is_err());

        // AppRole login token: a machine-class principal, not an operator.
        setup_app_role(core, &root_token, "reader-role").await;
        let approle_login = login_as(core, &root_token, "reader-role").await;
        let resp = test_write_api(core, &approle_login, "sys/mcp/token", false, pairing_body("r2")).await;
        assert!(resp.is_err());

        // Operator, but a malformed grant.
        let op = operator_token(core, &root_token, "felipe").await;
        let bad_id = test_write_api(core, &op, "sys/mcp/token", false, pairing_body("Not Valid!")).await;
        assert!(bad_id.is_err());
        let mut bad_tool = pairing_body("ok-id").unwrap();
        bad_tool["pairing"]["tool_allowlist"] = json!(["../etc/passwd"]);
        assert!(test_write_api(core, &op, "sys/mcp/token", false, Some(bad_tool)).await.is_err());

        // `app` and `pairing` together, and neither.
        let mut both = pairing_body("both-ok").unwrap();
        both.insert("app".into(), json!("ci-secrets-reader"));
        assert!(test_write_api(core, &op, "sys/mcp/token", false, Some(both)).await.is_err());
        assert!(test_write_api(core, &op, "sys/mcp/token", false, json!({}).as_object().cloned()).await.is_err());

        // An MCP-bound token cannot itself exchange for another.
        let ok = test_write_api(core, &op, "sys/mcp/token", true, pairing_body("first")).await;
        let mcp_token = ok.unwrap().unwrap().data.unwrap()["auth"]["client_token"].as_str().unwrap().to_string();
        let auth_module = core.module_manager().get_module::<crate::modules::auth::AuthModule>("auth").unwrap();
        let token_store = auth_module.token_store.load_full().unwrap();
        assert!(token_store.check_token("sys/mcp/token", &mcp_token, "", false).await.is_err());
    }

    /// The short lifetime an MCP token advertises is enforced: it was never
    /// registered with the expiration manager, so nothing ended it, and
    /// `check_token` did not look at its TTL.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_mcp_token_ttl_is_enforced() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_mcp_token_ttl").await;
        let core: &crate::core::Core = &core;
        let auth_module = core.module_manager().get_module::<crate::modules::auth::AuthModule>("auth").unwrap();
        let token_store = auth_module.token_store.load_full().unwrap();
        let op = operator_token(core, &root_token, "felipe").await;

        // Through the real exchange, asking for one second.
        let resp = test_write_api(
            core,
            &op,
            "sys/mcp/token",
            true,
            json!({
                "pairing": { "id": "short-lived", "client_name": "c", "client_version": "1",
                             "tool_allowlist": [], "path_scope": [] },
                "ttl_secs": 1,
            })
            .as_object()
            .cloned(),
        )
        .await;
        let token = resp.unwrap().unwrap().data.unwrap()["auth"]["client_token"].as_str().unwrap().to_string();
        assert!(token_store.check_token("mcp/dispatch", &token, "", true).await.is_ok());

        std::thread::sleep(std::time::Duration::from_millis(2100));
        assert!(
            token_store.check_token("mcp/dispatch", &token, "", true).await.is_err(),
            "a token past its advertised lifetime must be refused at its next call"
        );
    }

    fn unix_now() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
    }

    /// A machine-identity waiver is enforced at every call, not only at
    /// exchange: a token minted under one is dead the moment the waiver
    /// expires, and dies immediately when the waiver is revoked.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_mcp_waiver_expiry_and_revocation_cut_off_live_tokens() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_mcp_waiver_enforcement").await;
        let core: &crate::core::Core = &core;
        let auth_module = core.module_manager().get_module::<crate::modules::auth::AuthModule>("auth").unwrap();
        let token_store = auth_module.token_store.load_full().unwrap();

        // Expiry. Minted directly so the test does not have to wait a day.
        let op = operator_token(core, &root_token, "felipe").await;
        let binding = |waived_until: Option<u64>| crate::logical::McpBinding {
            kind: crate::logical::McpBindingKind::App("x".into()),
            catalogue_hash: String::new(),
            tool_allowlist: vec![],
            path_scope: vec![],
            reveal_allowed: false,
            destructive_allowed: false,
            client_name: String::new(),
            client_version: String::new(),
            waived_until,
        };
        let expired =
            token_store.mint_mcp_token(&op, &[], 600, "t-expired".into(), binding(Some(unix_now() - 5))).await.unwrap();
        assert!(
            token_store.check_token("mcp/dispatch", &expired.client_token, "", true).await.is_err(),
            "a token whose waiver has expired must be refused at its next call"
        );
        let live =
            token_store.mint_mcp_token(&op, &[], 600, "t-live".into(), binding(Some(unix_now() + 600))).await.unwrap();
        assert!(token_store.check_token("mcp/dispatch", &live.client_token, "", true).await.unwrap().is_some());
        let unwaived = token_store.mint_mcp_token(&op, &[], 600, "t-plain".into(), binding(None)).await.unwrap();
        assert!(token_store.check_token("mcp/dispatch", &unwaived.client_token, "", true).await.unwrap().is_some());

        // Revocation: the waiver record goes, and so do the tokens minted under it.
        setup_app_role(core, &root_token, "reader-role").await;
        register_mcp_app(core, &root_token, "ci-secrets-reader", "reader-role").await;
        let _ = test_write_api(
            core,
            &root_token,
            "sys/mcp/apps/ci-secrets-reader/machine-waiver",
            true,
            json!({ "reason": "no agent", "expires_in_days": 7 }).as_object().cloned(),
        )
        .await;
        let login = login_as(core, &root_token, "reader-role").await;
        let resp = test_write_api(
            core,
            &login,
            "sys/mcp/token",
            true,
            json!({ "app": "ci-secrets-reader" }).as_object().cloned(),
        )
        .await;
        let minted = resp.unwrap().unwrap().data.unwrap()["auth"]["client_token"].as_str().unwrap().to_string();
        let auth = token_store.check_token("mcp/dispatch", &minted, "", true).await.unwrap().unwrap();
        assert!(auth.mcp_binding.unwrap().waived_until.is_some(), "a waived exchange stamps the expiry");

        let _ = test_delete_api(core, &root_token, "sys/mcp/apps/ci-secrets-reader/machine-waiver", true, None).await;
        assert!(
            token_store.check_token("mcp/dispatch", &minted, "", true).await.is_err(),
            "revoking the waiver must cut off the tokens minted under it"
        );
        let resp = test_list_api(core, &root_token, "sys/mcp/tokens", true).await;
        let rows = resp.unwrap().unwrap().data.unwrap()["tokens"].clone();
        assert!(
            rows.as_array().unwrap().iter().all(|r| r["app"] != json!("ci-secrets-reader")),
            "and their index entries are gone: {rows}"
        );
    }

    fn http_post(listen_addr: &str, path: &str, token: Option<&str>, body: Value) -> (u16, Value) {
        let agent = ureq::Agent::config_builder().http_status_as_error(false).build().new_agent();
        let mut builder = ::http::Request::builder()
            .method("POST")
            .uri(format!("http://{listen_addr}{path}"))
            .header("Content-Type", "application/json");
        if let Some(t) = token {
            builder = builder.header("Authorization", format!("Bearer {t}"));
        }
        let req = builder.body(serde_json::to_vec(&body).unwrap()).unwrap();
        let mut resp = agent.run(req).expect("request must complete");
        let status = resp.status().as_u16();
        let json: Value = resp.body_mut().read_json().unwrap_or(Value::Null);
        (status, json)
    }

    /// Revocation must take effect over real HTTP, not only in-process: a
    /// pairing token is dead at `/v2/mcp` the moment its pairing is revoked,
    /// and so is a token revoked by accessor.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_mcp_http_revocation_takes_effect() {
        use crate::test_utils::TestHttpServer;

        let mut server = TestHttpServer::new("test_mcp_http_revocation", false).await;
        let root = server.root_token.clone();
        let addr = server.listen_addr.clone();

        server.mount_auth("userpass", "userpass").unwrap();
        let policy = r#"
            path "sys/mcp/token" { capabilities = ["update"] }
            path "sys/mcp/pairings/*" { capabilities = ["delete"] }
            path "sys/mcp/tokens/*" { capabilities = ["delete"] }
        "#;
        server.write("sys/policy/mcp-pairer", json!({ "policy": policy }).as_object().cloned(), Some(&root)).unwrap();
        server
            .write(
                "auth/userpass/users/felipe",
                json!({ "password": "pw", "policies": "mcp-pairer" }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();
        let (_, login) =
            server.login("auth/userpass/login/felipe", json!({ "password": "pw" }).as_object().cloned(), None).unwrap();
        let op = login["auth"]["client_token"].as_str().unwrap().to_string();

        let list = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} });
        let mint = |id: &str| {
            let body = pairing_body(id).map(Value::Object).unwrap();
            let (status, resp) = http_post(&addr, "/v2/mcp/token", Some(&op), body);
            assert_eq!(status, 200, "{resp}");
            (
                resp["auth"]["client_token"].as_str().unwrap().to_string(),
                resp["auth"]["accessor"].as_str().unwrap().to_string(),
            )
        };

        // By pairing id. The route is v2-only: v1 is frozen and must not serve it.
        let (token, _) = mint("pair-one");
        assert_eq!(http_post(&addr, "/v2/mcp", Some(&token), list.clone()).0, 200);
        let v1_status = {
            let agent = ureq::Agent::config_builder().http_status_as_error(false).build().new_agent();
            let req = ::http::Request::builder()
                .method("DELETE")
                .uri(format!("http://{addr}/v1/sys/mcp/pairings/pair-one"))
                .header("X-BastionVault-Token", &op)
                .body(())
                .unwrap();
            agent.run(req).expect("request must complete").status().as_u16()
        };
        assert_eq!(v1_status, 404, "/v1/sys/mcp/pairings/{{id}} must not exist");
        assert_eq!(http_post(&addr, "/v2/mcp", Some(&token), list.clone()).0, 200, "the v1 attempt revoked nothing");
        server.url_prefix = server.url_prefix.replace("/v1", "/v2");
        let (status, _) = server.delete("sys/mcp/pairings/pair-one", None, Some(&op)).unwrap();
        assert!((200..300).contains(&status), "revoke answered {status}");
        assert_eq!(
            http_post(&addr, "/v2/mcp", Some(&token), list.clone()).0,
            403,
            "a revoked pairing's token must be dead"
        );

        // By accessor.
        let (token, accessor) = mint("pair-two");
        assert_eq!(http_post(&addr, "/v2/mcp", Some(&token), list.clone()).0, 200);
        let (status, _) = server.delete(&format!("sys/mcp/tokens/{accessor}"), None, Some(&root)).unwrap();
        assert!((200..300).contains(&status), "revoke answered {status}");
        assert_eq!(http_post(&addr, "/v2/mcp", Some(&token), list).0, 403, "a token revoked by accessor must be dead");
    }

    /// End-to-end over real HTTP (Phase 3, `crates/bv-server/src/mcp_routes.rs`):
    /// `POST /v2/mcp/token` mints an MCP-bound token, then `POST /v2/mcp`
    /// answers `tools/list` and dispatches a `tools/call` for
    /// `bv_kv_read_metadata` through the real logical pipeline. Uses raw
    /// `ureq` rather than `TestHttpServer`'s request helpers: those hard-code
    /// a `/v1` URL prefix, and MCP's routes are deliberately `/v2`-only, not
    /// nested under `/v1` or `/v2/sys`.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_mcp_http_end_to_end() {
        use crate::test_utils::TestHttpServer;

        fn raw_post(listen_addr: &str, path: &str, token: Option<&str>, body: Value) -> (u16, Value) {
            let agent = ureq::Agent::config_builder().http_status_as_error(false).build().new_agent();
            let mut builder = ::http::Request::builder()
                .method("POST")
                .uri(format!("http://{listen_addr}{path}"))
                .header("Content-Type", "application/json");
            if let Some(t) = token {
                builder = builder.header("Authorization", format!("Bearer {t}"));
            }
            let req = builder.body(serde_json::to_vec(&body).unwrap()).unwrap();
            let mut resp = agent.run(req).expect("request must complete");
            let status = resp.status().as_u16();
            let json: Value = resp.body_mut().read_json().unwrap_or(Value::Null);
            (status, json)
        }

        let mut server = TestHttpServer::new("test_mcp_http_flow", false).await;
        let root_token = server.root_token.clone();
        let listen_addr = server.listen_addr.clone();

        server.mount_auth("approle", "approle").unwrap();
        let policy_hcl = r#"
            path "sys/mcp/token" { capabilities = ["update"] }
            path "secret/metadata/ai/*" { capabilities = ["read"] }
        "#;
        server.write("sys/policy/mcp-reader", json!({ "policy": policy_hcl }).as_object().cloned(), None).unwrap();
        server
            .write(
                "auth/approle/role/reader-role",
                json!({ "policies": "mcp-reader", "bypass_machine_binding": true }).as_object().cloned(),
                None,
            )
            .unwrap();
        server
            .write(
                "sys/mcp/apps/ci-secrets-reader",
                json!({
                    "approle_role": "reader-role",
                    "tool_allowlist": "bv_kv_read_metadata",
                    "path_scope": "secret/metadata/ai/*",
                })
                .as_object()
                .cloned(),
                None,
            )
            .unwrap();
        server
            .write(
                "sys/mcp/apps/ci-secrets-reader/machine-waiver",
                json!({ "reason": "no FerroGate agent on this test runner", "expires_in_days": 1 })
                    .as_object()
                    .cloned(),
                None,
            )
            .unwrap();

        let (_, role_id_resp) = server.read("auth/approle/role/reader-role/role-id", None).unwrap();
        let role_id = role_id_resp["data"]["role_id"].as_str().unwrap().to_string();
        let (_, secret_id_resp) = server.write("auth/approle/role/reader-role/secret-id", None, None).unwrap();
        let secret_id = secret_id_resp["data"]["secret_id"].as_str().unwrap().to_string();
        let (_, login_resp) = server
            .write(
                "auth/approle/login",
                json!({ "role_id": role_id, "secret_id": secret_id }).as_object().cloned(),
                None,
            )
            .unwrap();
        let login_token = login_resp["auth"]["client_token"].as_str().unwrap().to_string();

        // Seed a KV secret to read metadata for.
        server.mount("secret", "kv-v2").unwrap();
        server
            .write("secret/data/ai/x", json!({ "data": { "k": "v" } }).as_object().cloned(), Some(&root_token))
            .unwrap();

        let (status, exchange_resp) =
            raw_post(&listen_addr, "/v2/mcp/token", Some(&login_token), json!({ "app": "ci-secrets-reader" }));
        assert_eq!(status, 200, "exchange failed: {exchange_resp:?}");
        let mcp_token = exchange_resp["auth"]["client_token"].as_str().unwrap().to_string();

        let (status, list_resp) = raw_post(
            &listen_addr,
            "/v2/mcp",
            Some(&mcp_token),
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }),
        );
        assert_eq!(status, 200);
        let tools = list_resp["result"]["tools"].as_array().unwrap();
        assert!(tools.iter().any(|t| t["name"] == "bv_kv_read_metadata"));

        let (status, call_resp) = raw_post(
            &listen_addr,
            "/v2/mcp",
            Some(&mcp_token),
            json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": { "name": "bv_kv_read_metadata", "arguments": { "mount": "secret", "path": "ai/x" } },
            }),
        );
        assert_eq!(status, 200, "tools/call failed: {call_resp:?}");
        assert!(call_resp.get("error").is_none(), "unexpected error: {call_resp:?}");
        assert_eq!(
            call_resp["result"]["structuredContent"]["current_version"],
            json!(1),
            "full response: {call_resp:?}"
        );

        // The login token (not exchanged) must be refused at /v2/mcp.
        let (status, _) = raw_post(
            &listen_addr,
            "/v2/mcp",
            Some(&login_token),
            json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {} }),
        );
        // 403, not 401: the login token is validly authenticated, just not
        // MCP-bound -- `check_token`'s MCP-origin gate refuses it as
        // `ErrPermissionDenied` before this handler's own "missing/invalid
        // token" 401 branch is ever reached.
        assert_eq!(status, 403);

        // The MCP-bound token must be refused off the MCP dispatcher.
        let (status, _) = server.read("secret/metadata/ai/x", Some(&mcp_token)).unwrap();
        assert_eq!(status, 403);
    }
}
