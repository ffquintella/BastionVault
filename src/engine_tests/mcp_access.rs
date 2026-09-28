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
        let waiver_data = json!({ "reason": "no FerroGate agent on this CI runner", "expires_in_days": 7 })
            .as_object()
            .cloned();
        let resp = test_write_api(
            core,
            &root_token,
            "sys/mcp/apps/ci-secrets-reader/machine-waiver",
            true,
            waiver_data,
        )
        .await;
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
        server
            .write("sys/policy/mcp-reader", json!({ "policy": policy_hcl }).as_object().cloned(), None)
            .unwrap();
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
        let (_, secret_id_resp) =
            server.write("auth/approle/role/reader-role/secret-id", None, None).unwrap();
        let secret_id = secret_id_resp["data"]["secret_id"].as_str().unwrap().to_string();
        let (_, login_resp) = server
            .write("auth/approle/login", json!({ "role_id": role_id, "secret_id": secret_id }).as_object().cloned(), None)
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
