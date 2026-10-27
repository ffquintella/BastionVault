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

    /// The in-process `/v2/mcp` handling (`crate::mcp_endpoint`) the desktop
    /// app answers an assistant with when its vault is embedded: a pairing
    /// token is served gate for gate as over HTTP, and anything that is not
    /// a live MCP-bound token is refused before a tool runs.
    #[tokio::test]
    async fn test_mcp_in_process_endpoint_serves_a_pairing_token_and_nothing_else() {
        use crate::mcp_endpoint::{handle_jsonrpc, McpEndpoint, McpEndpointOutcome};
        use bv_mcp::request_state::SingleUseGuard;

        let (_bvault, core_arc, root_token) = new_unseal_test_bastion_vault("test_mcp_in_process_endpoint").await;
        let core: &crate::core::Core = &core_arc;
        let op = operator_token(core, &root_token, "felipe").await;
        let resp = test_write_api(core, &op, "sys/mcp/token", true, pairing_body("in-proc")).await;
        let mcp_token = resp.unwrap().unwrap().data.unwrap()["auth"]["client_token"].as_str().unwrap().to_string();

        let guard = SingleUseGuard::new();
        let ep = McpEndpoint {
            core: &core_arc,
            client_ip: "",
            tool_timeout: std::time::Duration::from_secs(30),
            server_version: "9.9",
            request_state_key: b"in-process-test-key",
            single_use_guard: &guard,
        };
        let answer = |outcome: McpEndpointOutcome| match outcome {
            McpEndpointOutcome::Answer(r) => serde_json::to_value(r).unwrap(),
            other => panic!("expected a JSON-RPC answer, got {other:?}"),
        };
        let rpc = |id: u64, method: &str, params: Value| {
            serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })).unwrap()
        };

        let list = answer(handle_jsonrpc(&ep, &mcp_token, &rpc(1, "tools/list", json!({}))).await.unwrap());
        assert!(list["result"]["tools"].as_array().unwrap().iter().any(|t| t["name"] == "bv_kv_read_metadata"));
        let discover = answer(handle_jsonrpc(&ep, &mcp_token, &rpc(2, "server/discover", json!({}))).await.unwrap());
        assert_eq!(discover["result"]["serverInfo"]["version"], json!("9.9"));

        // The binding's gates apply: a tool outside the grant, a path outside
        // its scope.
        let not_granted =
            rpc(3, "tools/call", json!({ "name": "bv_kv_read", "arguments": { "mount": "secret", "path": "ai/x" } }));
        let refused = answer(handle_jsonrpc(&ep, &mcp_token, &not_granted).await.unwrap());
        assert_eq!(refused["error"]["data"]["code"], json!("mcp_tool_not_allowed"), "{refused}");
        let out_of_scope = rpc(
            4,
            "tools/call",
            json!({ "name": "bv_kv_read_metadata", "arguments": { "mount": "secret", "path": "other/y" } }),
        );
        let refused = answer(handle_jsonrpc(&ep, &mcp_token, &out_of_scope).await.unwrap());
        assert_eq!(refused["error"]["data"]["code"], json!("mcp_path_out_of_scope"), "{refused}");

        // A wrong protocol revision is a JSON-RPC error; a non-JSON-RPC body is
        // a bad request.
        let old = rpc(5, "tools/list", json!({ "_meta": { "io.modelcontextprotocol/protocolVersion": "1999-01-01" } }));
        assert!(answer(handle_jsonrpc(&ep, &mcp_token, &old).await.unwrap())["error"].is_object());
        assert!(matches!(
            handle_jsonrpc(&ep, &mcp_token, b"{not json").await.unwrap(),
            McpEndpointOutcome::BadRequest(_)
        ));

        // The operator's own login token is not MCP-bound: refused outright.
        assert!(handle_jsonrpc(&ep, &op, &rpc(6, "tools/list", json!({}))).await.is_err());

        // Revoking the pairing cuts the token off here too.
        let _ = test_delete_api(core, &op, "sys/mcp/pairings/in-proc", true, None).await;
        let after = handle_jsonrpc(&ep, &mcp_token, &rpc(7, "tools/list", json!({}))).await;
        assert!(!matches!(after, Ok(McpEndpointOutcome::Answer(_))), "a revoked token is not answered: {after:?}");
    }

    /// Regression for tools that never worked against a real vault:
    /// `bv_whoami` reported no policies, the resource tools routed to a
    /// `resource/` mount that does not exist, `bv_kv_list` hit the KV v2
    /// single-key route (no list operation) and could not list a mount's top
    /// level, and `bv_capabilities` sent a read that `sys/capabilities-self`
    /// does not accept.
    #[tokio::test]
    async fn test_mcp_in_process_whoami_kv_list_and_capabilities_against_a_real_vault() {
        use crate::mcp_endpoint::{handle_jsonrpc, McpEndpoint, McpEndpointOutcome};
        use bv_mcp::request_state::SingleUseGuard;

        let (_bvault, core_arc, root_token) = new_unseal_test_bastion_vault("test_mcp_in_process_tools").await;
        let core: &crate::core::Core = &core_arc;
        let op = operator_token(core, &root_token, "felipe").await;
        let mount = json!({ "type": "kv-v2" }).as_object().cloned();
        let _ = test_write_api(core, &root_token, "sys/mounts/mcpkv/", true, mount).await;
        let secret = json!({ "data": { "k": "v" } }).as_object().cloned();
        let _ = test_write_api(core, &root_token, "mcpkv/data/ai/x", true, secret).await;
        let resource = json!({ "type": "server", "hostname": "gw-01.example" }).as_object().cloned();
        let _ = test_write_api(core, &root_token, "resources/resources/gw", true, resource).await;
        let policy_hcl = r#"
            path "sys/mcp/token"         { capabilities = ["update"] }
            path "sys/capabilities-self" { capabilities = ["update"] }
            path "mcpkv/metadata/*"      { capabilities = ["read", "list"] }
            path "mcpkv/data/ai/*"       { capabilities = ["read"] }
            path "resources/resources/*" { capabilities = ["read", "list"] }
        "#;
        let policy = json!({ "policy": policy_hcl }).as_object().cloned();
        let _ = test_write_api(core, &root_token, "sys/policy/mcp-pairer", true, policy).await;

        let pairing = json!({
            "pairing": {
                "id": "tools",
                "client_name": "claude-code",
                "tool_allowlist": ["bv_whoami", "bv_kv_list", "bv_capabilities", "bv_resource_list", "bv_resource_describe"],
                "path_scope": ["mcpkv/*", "resources/*"],
            },
        })
        .as_object()
        .cloned();
        let resp = test_write_api(core, &op, "sys/mcp/token", true, pairing).await;
        let mcp_token = resp.unwrap().unwrap().data.unwrap()["auth"]["client_token"].as_str().unwrap().to_string();

        let guard = SingleUseGuard::new();
        let ep = McpEndpoint {
            core: &core_arc,
            client_ip: "",
            tool_timeout: std::time::Duration::from_secs(30),
            server_version: "9.9",
            request_state_key: b"in-process-test-key",
            single_use_guard: &guard,
        };
        let call = |id: u64, tool: &str, arguments: Value| {
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": { "name": tool, "arguments": arguments },
            }))
            .unwrap()
        };
        let result = |outcome: McpEndpointOutcome| match outcome {
            McpEndpointOutcome::Answer(r) => {
                let v = serde_json::to_value(r).unwrap();
                assert!(v["error"].is_null(), "tool call failed: {v}");
                v["result"]["structuredContent"].clone()
            }
            other => panic!("expected a JSON-RPC answer, got {other:?}"),
        };

        let whoami = result(handle_jsonrpc(&ep, &mcp_token, &call(1, "bv_whoami", json!({}))).await.unwrap());
        assert!(
            whoami["policies"].as_array().unwrap().contains(&json!("mcp-pairer")),
            "whoami reports the token's policies: {whoami}"
        );

        let listed = call(2, "bv_kv_list", json!({ "mount": "mcpkv", "path": "ai" }));
        let listed = result(handle_jsonrpc(&ep, &mcp_token, &listed).await.unwrap());
        assert_eq!(listed["keys"], json!(["x"]));
        let top =
            result(handle_jsonrpc(&ep, &mcp_token, &call(3, "bv_kv_list", json!({ "mount": "mcpkv" }))).await.unwrap());
        assert_eq!(top["keys"], json!(["ai/"]));

        let caps = call(4, "bv_capabilities", json!({ "path": "mcpkv/data/ai/x" }));
        let caps = result(handle_jsonrpc(&ep, &mcp_token, &caps).await.unwrap());
        assert!(
            caps["capabilities"]["mcpkv/data/ai/x"].as_array().unwrap().contains(&json!("read")),
            "capabilities on a granted path: {caps}"
        );

        let resources = result(handle_jsonrpc(&ep, &mcp_token, &call(5, "bv_resource_list", json!({}))).await.unwrap());
        assert!(resources["keys"].as_array().unwrap().contains(&json!("gw")), "resource list: {resources}");
        let gw = call(6, "bv_resource_describe", json!({ "name": "gw" }));
        let gw = result(handle_jsonrpc(&ep, &mcp_token, &gw).await.unwrap());
        assert_eq!(gw["hostname"], json!("gw-01.example"), "resource describe: {gw}");
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
            connect_allowed: false,
            confirm_connect: false,
            operator: None,
        };
        let expired = token_store
            .mint_mcp_token(&op, &[], 600, "t-expired".into(), binding(Some(unix_now() - 5)), None)
            .await
            .unwrap();
        assert!(
            token_store.check_token("mcp/dispatch", &expired.client_token, "", true).await.is_err(),
            "a token whose waiver has expired must be refused at its next call"
        );
        let live = token_store
            .mint_mcp_token(&op, &[], 600, "t-live".into(), binding(Some(unix_now() + 600)), None)
            .await
            .unwrap();
        assert!(token_store.check_token("mcp/dispatch", &live.client_token, "", true).await.unwrap().is_some());
        let unwaived = token_store.mint_mcp_token(&op, &[], 600, "t-plain".into(), binding(None), None).await.unwrap();
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

    // ── MCP brokered sessions, slice 1 (features/mcp-brokered-sessions.md) ──

    // `get`/`put` on the sys mount's own barrier view, to plant records as
    // an older server stored them.
    use crate::storage::Storage as _;

    /// The barrier view the `sys/` backend reads and writes (a logical mount
    /// view, not the core's system view).
    fn sys_mount_view(core: &crate::core::Core) -> std::sync::Arc<crate::storage::barrier_view::BarrierView> {
        core.router.matching_view("sys/mcp/config").unwrap().expect("the sys mount has a view")
    }

    fn pairing_body_with(id: &str, extra: Value) -> Option<serde_json::Map<String, Value>> {
        let mut body = pairing_body(id).unwrap();
        for (k, v) in extra.as_object().unwrap() {
            body["pairing"][k] = v.clone();
        }
        Some(body)
    }

    async fn exchanged_binding(core: &crate::core::Core, token: &str) -> crate::logical::McpBinding {
        let auth_module = core.module_manager().get_module::<crate::modules::auth::AuthModule>("auth").unwrap();
        let token_store = auth_module.token_store.load_full().unwrap();
        token_store
            .check_token("mcp/dispatch", token, "", true)
            .await
            .unwrap()
            .expect("an exchanged token is live on the MCP dispatcher")
            .mcp_binding
            .expect("and carries its binding")
    }

    /// The pairing exchange grants `connect_allowed` together with
    /// `reveal_allowed` (the owner's decision), forces `confirm_connect` on,
    /// and records the operator from the session's own metadata.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_mcp_pairing_exchange_grants_connect_with_the_operator_recorded() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_mcp_pairing_connect").await;
        let core: &crate::core::Core = &core;
        let op = operator_token(core, &root_token, "felipe").await;

        let body = pairing_body_with(
            "with-connect",
            json!({
                "tool_allowlist": ["bv_kv_read", "bv_resource_ssh_exec"],
                "reveal_allowed": true,
                "connect_allowed": true,
                "confirm_connect": true,
            }),
        );
        let resp = test_write_api(core, &op, "sys/mcp/token", true, body).await;
        let token = resp.unwrap().unwrap().data.unwrap()["auth"]["client_token"].as_str().unwrap().to_string();
        let binding = exchanged_binding(core, &token).await;
        assert!(binding.connect_allowed && binding.confirm_connect && binding.reveal_allowed);
        let operator = binding.operator.expect("a pairing binding names its operator");
        assert_eq!(operator.username, "felipe");
        assert_eq!(operator.mount_path, "userpass/");
        assert_eq!(operator.namespace, "", "root namespace");

        // Without a connect grant: no sessions, but confirmation is still
        // recorded as on — no pairing binding is ever minted without it.
        let resp = test_write_api(core, &op, "sys/mcp/token", true, pairing_body("no-connect")).await;
        let token = resp.unwrap().unwrap().data.unwrap()["auth"]["client_token"].as_str().unwrap().to_string();
        let binding = exchanged_binding(core, &token).await;
        assert!(!binding.connect_allowed);
        assert!(binding.confirm_connect);
        assert!(binding.operator.is_some());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_mcp_pairing_exchange_connect_refusals() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_mcp_pairing_connect_refusals").await;
        let core: &crate::core::Core = &core;
        let op = operator_token(core, &root_token, "felipe").await;

        for (id, extra, needle) in [
            // connect_allowed without confirm_connect.
            ("r-1", json!({ "connect_allowed": true }), "requires pairing.confirm_connect"),
            // confirm_connect can never be turned off, with or without connect.
            ("r-2", json!({ "connect_allowed": true, "confirm_connect": false }), "cannot be false"),
            ("r-3", json!({ "confirm_connect": false }), "cannot be false"),
            // A session tool in the allow-list needs connect_allowed.
            ("r-4", json!({ "tool_allowlist": ["bv_resource_ssh_exec"] }), "requires pairing.connect_allowed"),
            // Strictly typed.
            ("r-5", json!({ "connect_allowed": "yes", "confirm_connect": true }), "must be a boolean"),
            ("r-6", json!({ "connect_allowed": true, "confirm_connect": 1 }), "must be a boolean"),
        ] {
            let resp = test_write_api(core, &op, "sys/mcp/token", false, pairing_body_with(id, extra)).await;
            let err = resp.expect_err(id).to_string();
            assert!(err.contains(needle), "{id}: {err}");
        }
        // Nothing was minted for any of them.
        let resp = test_list_api(core, &root_token, "sys/mcp/tokens", true).await;
        assert_eq!(resp.unwrap().unwrap().data.unwrap()["tokens"], json!([]));
    }

    /// Network-mode apps never open sessions: `sys/mcp/apps` refuses a
    /// session tool in `tool_allowlist` (array or comma form), and an app
    /// record that already carries one — written before the rule — can
    /// neither be updated nor exchanged.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_mcp_apps_refuse_open_world_tools() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_mcp_apps_open_world").await;
        let core: &crate::core::Core = &core;

        for allowlist in [
            json!(["bv_kv_read_metadata", "bv_resource_ssh_exec"]),
            json!("bv_kv_read_metadata,bv_resource_web_fetch"),
            json!(["bv_resource_rdp_act"]),
        ] {
            let body = json!({ "approle_role": "reader-role", "tool_allowlist": allowlist }).as_object().cloned();
            let err = test_write_api(core, &root_token, "sys/mcp/apps/net-app", false, body).await.unwrap_err();
            assert!(err.to_string().contains("mcp_connect_requires_local_operator"), "{allowlist}: {err}");
        }
        let resp = test_read_api(core, &root_token, "sys/mcp/apps/net-app", false).await;
        assert!(resp.is_err(), "a refused write stores nothing");

        // A legacy record carrying a session tool, written straight to the
        // system view as an older server would have stored it.
        setup_app_role(core, &root_token, "reader-role").await;
        register_mcp_app(core, &root_token, "legacy-app", "reader-role").await;
        let view = sys_mount_view(core);
        let mut record: Value =
            serde_json::from_slice(&view.get("mcp/apps/legacy-app").await.unwrap().unwrap().value).unwrap();
        record["tool_allowlist"] = json!(["bv_kv_read_metadata", "bv_resource_ssh_exec"]);
        record["machine_waiver"] =
            json!({ "reason": "ci", "granted_by": "root", "granted_at": 0, "expires_at": u64::MAX / 2 });
        view.put(&crate::storage::StorageEntry::new("mcp/apps/legacy-app", &record).unwrap()).await.unwrap();

        let login = login_as(core, &root_token, "reader-role").await;
        let err =
            test_write_api(core, &login, "sys/mcp/token", false, json!({ "app": "legacy-app" }).as_object().cloned())
                .await
                .unwrap_err();
        assert!(err.to_string().contains("mcp_connect_requires_local_operator"), "{err}");

        let update = json!({ "description": "touch" }).as_object().cloned();
        let err = test_write_api(core, &root_token, "sys/mcp/apps/legacy-app", false, update).await.unwrap_err();
        assert!(err.to_string().contains("bv_resource_ssh_exec"), "{err}");
        let fixed = json!({ "tool_allowlist": ["bv_kv_read_metadata"] }).as_object().cloned();
        assert!(test_write_api(core, &root_token, "sys/mcp/apps/legacy-app", true, fixed).await.is_ok());
    }

    async fn read_mcp_config(core: &crate::core::Core, token: &str) -> serde_json::Map<String, Value> {
        test_read_api(core, token, "sys/mcp/config", true).await.unwrap().unwrap().data.unwrap()
    }

    async fn write_mcp_config(
        core: &crate::core::Core,
        token: &str,
        body: Value,
        ok: bool,
    ) -> Result<Option<crate::logical::Response>, RvError> {
        test_write_api(core, token, "sys/mcp/config", ok, body.as_object().cloned()).await
    }

    /// `sys/mcp/config`: the runtime switch and destination allow-list read
    /// as off / not set on an old record, validate every entry on write
    /// (leaving the record untouched on refusal), warn on an always-denied
    /// overlap, and reset with `null`.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_mcp_config_brokered_session_keys() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_mcp_config_brokered").await;
        let core: &crate::core::Core = &core;
        let token = root_token.as_str();

        // An old record (written before the keys existed) reads as off.
        let view = sys_mount_view(core);
        let old = json!({ "version": 1, "default_ttl_secs": 3600, "max_ttl_secs": 86400, "waiver_max_days": 90 });
        view.put(&crate::storage::StorageEntry::new("mcp/config", &old).unwrap()).await.unwrap();
        let data = read_mcp_config(core, token).await;
        assert_eq!(data["brokered_sessions_enabled"], json!(false));
        assert_eq!(data["brokered_sessions_allowed_target_cidrs"], Value::Null);

        let body =
            json!({ "brokered_sessions_enabled": true, "brokered_sessions_allowed_target_cidrs": ["10.20.0.0/16"] });
        let resp = write_mcp_config(core, token, body, true).await.unwrap().unwrap();
        assert!(resp.warnings.is_empty());
        let data = read_mcp_config(core, token).await;
        assert_eq!(data["brokered_sessions_enabled"], json!(true));
        assert_eq!(data["brokered_sessions_allowed_target_cidrs"], json!(["10.20.0.0/16"]));
        assert_eq!(data["waiver_max_days"], json!(90), "other keys are untouched");

        // An invalid entry refuses the write, naming it, and changes nothing.
        let body = json!({ "brokered_sessions_enabled": false, "brokered_sessions_allowed_target_cidrs": ["10.0.0.0/8", "10.0.0.1/33"] });
        let err = write_mcp_config(core, token, body, false).await.unwrap_err();
        assert!(err.to_string().contains("\"10.0.0.1/33\""), "{err}");
        let data = read_mcp_config(core, token).await;
        assert_eq!(data["brokered_sessions_enabled"], json!(true), "nothing was stored");
        assert_eq!(data["brokered_sessions_allowed_target_cidrs"], json!(["10.20.0.0/16"]));
        assert!(write_mcp_config(core, token, json!({ "brokered_sessions_enabled": "maybe" }), false).await.is_err());
        assert!(write_mcp_config(core, token, json!({ "brokered_sessions_allowed_target_cidrs": 7 }), false)
            .await
            .is_err());

        // An always-denied overlap is accepted with a warning (CLI comma form).
        let body = json!({ "brokered_sessions_allowed_target_cidrs": "10.0.0.0/8, 169.254.169.254/32" });
        let resp = write_mcp_config(core, token, body, true).await.unwrap().unwrap();
        assert_eq!(resp.warnings.len(), 1, "{:?}", resp.warnings);
        assert!(resp.warnings[0].contains("169.254.169.254/32"));
        let data = read_mcp_config(core, token).await;
        assert_eq!(data["brokered_sessions_allowed_target_cidrs"], json!(["10.0.0.0/8", "169.254.169.254/32"]));

        // An empty list is a list; `null` resets to the server config.
        write_mcp_config(core, token, json!({ "brokered_sessions_allowed_target_cidrs": [] }), true).await.unwrap();
        assert_eq!(read_mcp_config(core, token).await["brokered_sessions_allowed_target_cidrs"], json!([]));
        let body = json!({ "brokered_sessions_allowed_target_cidrs": null, "brokered_sessions_enabled": "false" });
        write_mcp_config(core, token, body, true).await.unwrap();
        let data = read_mcp_config(core, token).await;
        assert_eq!(data["brokered_sessions_allowed_target_cidrs"], Value::Null);
        assert_eq!(data["brokered_sessions_enabled"], json!(false));
    }

    // ── MCP brokered sessions, slice 2: the `mcp` audit block (T94 slice),
    // `connect.agent.refused`, and the effective destination list ──

    /// A file audit device in a fresh directory; returns the directory and the
    /// log path.
    async fn audit_file(core: &crate::core::Core, name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "bv-mcp-audit-{name}-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.log");
        let broker = core.audit_broker.load().as_ref().cloned().expect("broker installed at unseal");
        let mut options = std::collections::HashMap::new();
        options.insert("file_path".to_string(), log.display().to_string());
        broker
            .enable_device(crate::audit::AuditDeviceConfig {
                path: format!("mcp-{name}"),
                device_type: "file".into(),
                description: String::new(),
                options,
                namespace: String::new(),
                mirror: false,
            })
            .await
            .unwrap();
        (dir, log)
    }

    fn audit_lines(log: &std::path::Path) -> Vec<Value> {
        std::fs::read_to_string(log).unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
    }

    /// Every request a `tools/call` routes carries the `request.mcp` block:
    /// pairing, client, tool, catalogue and argument hashes, `allowed`, and
    /// the gatekeeper's asserted confirmation when it sent one. A session
    /// tool the dispatcher refuses yields `connect.agent.refused`, naming the
    /// operator and pairing; nothing in either holds the MCP token.
    #[tokio::test]
    async fn test_mcp_tools_call_audit_block_and_session_refusal_event() {
        use crate::mcp_endpoint::{handle_jsonrpc, McpEndpoint, McpEndpointOutcome};
        use bv_mcp::request_state::SingleUseGuard;

        let (_bvault, core_arc, root_token) = new_unseal_test_bastion_vault("test_mcp_audit_block").await;
        let core: &crate::core::Core = &core_arc;
        let (audit_dir, audit_log) = audit_file(core, "block").await;
        let op = operator_token(core, &root_token, "felipe").await;
        let mount = json!({ "type": "kv-v2" }).as_object().cloned();
        let _ = test_write_api(core, &root_token, "sys/mounts/mcpkv/", true, mount).await;
        let secret = json!({ "data": { "k": "v" } }).as_object().cloned();
        let _ = test_write_api(core, &root_token, "mcpkv/data/ai/x", true, secret).await;
        let policy_hcl = r#"
            path "sys/mcp/token"    { capabilities = ["update"] }
            path "mcpkv/metadata/*" { capabilities = ["read", "list"] }
        "#;
        let policy = json!({ "policy": policy_hcl }).as_object().cloned();
        let _ = test_write_api(core, &root_token, "sys/policy/mcp-pairer", true, policy).await;
        let pairing = json!({
            "pairing": {
                "id": "audited",
                "client_name": "claude-code",
                "client_version": "2.1",
                "tool_allowlist": ["bv_kv_list"],
                "path_scope": ["mcpkv/*"],
            },
        })
        .as_object()
        .cloned();
        let resp = test_write_api(core, &op, "sys/mcp/token", true, pairing).await;
        let mcp_token = resp.unwrap().unwrap().data.unwrap()["auth"]["client_token"].as_str().unwrap().to_string();

        let guard = SingleUseGuard::new();
        let ep = McpEndpoint {
            core: &core_arc,
            client_ip: "",
            tool_timeout: std::time::Duration::from_secs(30),
            server_version: "9.9",
            request_state_key: b"in-process-test-key",
            single_use_guard: &guard,
        };
        let call = |id: u64, tool: &str, arguments: Value, meta: Value| {
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": { "name": tool, "arguments": arguments, "_meta": meta },
            }))
            .unwrap()
        };
        let answer = |outcome: McpEndpointOutcome| match outcome {
            McpEndpointOutcome::Answer(r) => serde_json::to_value(r).unwrap(),
            other => panic!("expected a JSON-RPC answer, got {other:?}"),
        };

        // Confirmed by the operator (as the gatekeeper asserts it), then not.
        let confirmed_args = json!({ "mount": "mcpkv", "path": "ai" });
        let confirmed = json!({ "io.bastionvault/confirmation": { "by": "operator", "at": 1_760_000_000u64, "mfa": false } });
        let ok = answer(handle_jsonrpc(&ep, &mcp_token, &call(1, "bv_kv_list", confirmed_args.clone(), confirmed)).await.unwrap());
        assert!(ok["error"].is_null(), "{ok}");
        let plain_args = json!({ "mount": "mcpkv" });
        let ok = answer(handle_jsonrpc(&ep, &mcp_token, &call(2, "bv_kv_list", plain_args.clone(), json!({}))).await.unwrap());
        assert!(ok["error"].is_null(), "{ok}");

        // A session tool: refused by the dispatcher (no session tool ships yet).
        let session_args = json!({ "resource": "web-01", "profile": "p_agent", "command": "id" });
        let refused =
            answer(handle_jsonrpc(&ep, &mcp_token, &call(3, "bv_resource_ssh_exec", session_args, json!({}))).await.unwrap());
        let code = refused["error"]["data"]["code"].as_str().unwrap().to_string();

        let entries = audit_lines(&audit_log);
        let blocks: Vec<&Value> = entries.iter().filter(|e| e["request"]["mcp"].is_object()).collect();
        let first = blocks
            .iter()
            .find(|e| e["request"]["mcp"]["args_hash"] == json!(bv_mcp::dispatcher::args_hash(confirmed_args.as_object().unwrap())))
            .unwrap_or_else(|| panic!("the confirmed call's block is in the audit log: {blocks:#?}"));
        let mcp = &first["request"]["mcp"];
        assert_eq!(mcp["kind"], json!("pairing"));
        assert_eq!(mcp["name"], json!("audited"));
        assert_eq!(mcp["client_name"], json!("claude-code"));
        assert_eq!(mcp["client_version"], json!("2.1"));
        assert_eq!(mcp["tool"], json!("bv_kv_list"));
        assert_eq!(mcp["catalogue_hash"], json!(bv_mcp::catalogue::catalogue_hash()));
        assert_eq!(mcp["decision"], json!("allowed"));
        assert_eq!(mcp["transport"], json!("in-process"));
        assert_eq!(mcp["confirmed_by_operator"], json!(true));
        assert_eq!(mcp["operator_confirmation"], json!("asserted-by-local-host"));
        assert_eq!(first["request"]["path"], json!("mcpkv/metadata/ai/"));

        let second = blocks
            .iter()
            .find(|e| e["request"]["mcp"]["args_hash"] == json!(bv_mcp::dispatcher::args_hash(plain_args.as_object().unwrap())))
            .expect("the unconfirmed call's block");
        assert_eq!(second["request"]["mcp"]["confirmed_by_operator"], json!(false));
        assert!(second["request"]["mcp"].get("operator_confirmation").is_none());

        let refusal = entries
            .iter()
            .find(|e| e["type"] == "event" && e["request"]["path"] == "connect.agent.refused")
            .unwrap_or_else(|| panic!("connect.agent.refused is in the audit log: {entries:#?}"));
        let data = &refusal["request"]["data"];
        assert_eq!(data["reason"], json!(code));
        assert_eq!(data["tool"], json!("bv_resource_ssh_exec"));
        assert_eq!(data["protocol"], json!("ssh"));
        assert_eq!(data["resource"], json!("web-01"));
        assert_eq!(data["profile_id"], json!("p_agent"));
        assert_eq!(data["pairing_id"], json!("audited"));
        assert_eq!(data["operator"]["username"], json!("felipe"));
        assert!(data.get("command").is_none(), "no command text in audit");
        // No block was written for the refused call: nothing was routed.
        assert!(blocks.iter().all(|e| e["request"]["mcp"]["tool"] != "bv_resource_ssh_exec"));

        let raw = std::fs::read_to_string(&audit_log).unwrap();
        assert!(!raw.contains(&mcp_token), "the MCP token is never in the audit log");
        let _ = std::fs::remove_dir_all(audit_dir);
    }

    /// `sys/mcp/config` reports the destination list in force and where it
    /// comes from: the built-in default, the server config's
    /// `mcp.brokered_sessions` (`hcl`), or the runtime value — and the
    /// server's static switch, its protocols and the always-denied classes.
    #[tokio::test]
    async fn test_mcp_config_reports_the_effective_destination_list_and_its_source() {
        use crate::test_utils::{init_test_bastion_vault, new_test_backend, unseal_test_bastion_vault};

        // No server config: the default.
        let (_bvault, core, root) = new_unseal_test_bastion_vault("test_mcp_config_effective_default").await;
        let data = read_mcp_config(&core, &root).await;
        assert_eq!(data["brokered_sessions_target_cidrs_source"], json!("default"));
        assert_eq!(
            data["brokered_sessions_effective_target_cidrs"],
            json!(bv_utils::destination_policy::DEFAULT_ALLOWED_TARGET_CIDRS)
        );
        assert_eq!(data["brokered_sessions_server_enabled"], json!(false));
        assert_eq!(data["brokered_sessions_server_protocols"], json!([]));
        let denied = data["brokered_sessions_always_denied"].as_array().unwrap();
        assert!(denied.contains(&json!("loopback")) && denied.contains(&json!("vault-listener")), "{denied:?}");

        // A server config with its own list.
        let mut config = crate::config::Config::default();
        config.mcp.brokered_sessions.enabled = true;
        config.mcp.brokered_sessions.protocols = vec!["ssh".into()];
        config.mcp.brokered_sessions.allowed_target_cidrs = Some(vec!["10.9.0.0/16".into()]);
        let bvault = crate::BastionVault::new(new_test_backend("test_mcp_config_effective_hcl"), Some(&config)).unwrap();
        let seal = crate::core::SealConfig { secret_shares: 1, secret_threshold: 1 };
        let init = init_test_bastion_vault(&bvault, &seal).await;
        assert!(unseal_test_bastion_vault(&bvault, &[init.secret_shares[0].as_slice()]).await);
        let core = bvault.core.load().clone();
        let root = init.root_token.clone();
        let core: &crate::core::Core = &core;

        let data = read_mcp_config(core, &root).await;
        assert_eq!(data["brokered_sessions_target_cidrs_source"], json!("hcl"));
        assert_eq!(data["brokered_sessions_effective_target_cidrs"], json!(["10.9.0.0/16"]));
        assert_eq!(data["brokered_sessions_server_enabled"], json!(true));
        assert_eq!(data["brokered_sessions_server_protocols"], json!(["ssh"]));
        assert_eq!(data["brokered_sessions_allowed_target_cidrs"], Value::Null, "the runtime layer is unset");

        // The runtime layer replaces it, an empty list included; `null` hands
        // back to the server config. The write's own response says so too.
        let resp = write_mcp_config(core, &root, json!({ "brokered_sessions_allowed_target_cidrs": ["10.20.0.0/16"] }), true)
            .await
            .unwrap()
            .unwrap();
        let written = resp.data.unwrap();
        assert_eq!(written["brokered_sessions_target_cidrs_source"], json!("runtime"));
        assert_eq!(written["brokered_sessions_effective_target_cidrs"], json!(["10.20.0.0/16"]));
        write_mcp_config(core, &root, json!({ "brokered_sessions_allowed_target_cidrs": [] }), true).await.unwrap();
        let data = read_mcp_config(core, &root).await;
        assert_eq!(data["brokered_sessions_target_cidrs_source"], json!("runtime"));
        assert_eq!(data["brokered_sessions_effective_target_cidrs"], json!([]));
        write_mcp_config(core, &root, json!({ "brokered_sessions_allowed_target_cidrs": null }), true).await.unwrap();
        let data = read_mcp_config(core, &root).await;
        assert_eq!(data["brokered_sessions_target_cidrs_source"], json!("hcl"));
        assert_eq!(data["brokered_sessions_effective_target_cidrs"], json!(["10.9.0.0/16"]));

        // The derived keys are read-only: writing one changes nothing stored.
        write_mcp_config(core, &root, json!({ "brokered_sessions_target_cidrs_source": "runtime" }), true).await.unwrap();
        let view = sys_mount_view(core);
        let stored: Value = serde_json::from_slice(&view.get("mcp/config").await.unwrap().unwrap().value).unwrap();
        assert!(stored.get("brokered_sessions_target_cidrs_source").is_none(), "{stored}");
        assert!(stored.get("brokered_sessions_effective_target_cidrs").is_none(), "{stored}");
    }

    // ── MCP namespace selection, Phase 1 (features/mcp-namespace-selection.md) ──

    use crate::logical::{Operation, Response, CHILD_VISIBLE_META, NS_PATH_META};
    use crate::mcp_endpoint::{handle_jsonrpc, McpEndpoint, McpEndpointOutcome};
    use bv_mcp::request_state::SingleUseGuard;

    /// A call as `token`, addressed to namespace `ns` the way a client
    /// addresses one (the header); `""` is root.
    async fn ns_call(
        core: &crate::core::Core,
        token: &str,
        op: Operation,
        ns: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Option<Response>, RvError> {
        let mut req = crate::logical::Request::new(path);
        req.operation = op;
        req.client_token = token.to_string();
        req.body = body.and_then(|b| b.as_object().cloned());
        if !ns.is_empty() {
            req.headers = Some(std::collections::HashMap::from([("x-bastionvault-namespace".into(), ns.into())]));
        }
        core.handle_request(&mut req).await
    }

    /// `hcl` as policy `name` in namespace `ns`'s own store. Written through
    /// the store: `sys/policy` refuses a tenant policy that names a `sys/`
    /// path (`refuse_cross_namespace_paths`), and the exchange is one.
    async fn tenant_policy(core: &crate::core::Core, ns: &str, name: &str, hcl: &str) {
        use std::str::FromStr as _;
        let mut policy = crate::modules::policy::Policy::from_str(hcl).unwrap();
        policy.name = name.to_string();
        let module = core.module_manager().get_module::<crate::modules::policy::PolicyModule>("policy").unwrap();
        module.policy_store.load().set_policy_ns(policy, ns).await.unwrap();
    }

    fn tenant_operator_policy(ns: &str) -> String {
        format!(
            r#"
            path "sys/mcp/token"                {{ capabilities = ["update"] }}
            path "sys/mcp/pairings/*"           {{ capabilities = ["delete"] }}
            path "{ns}/resources/resources/*"   {{ capabilities = ["read", "list"] }}
        "#
        )
    }

    /// Namespaces `tenant-a` and `tenant-b`, a resource in each and one at
    /// root; `alice` (root userpass) holds `mcp-tenant` in both tenants, and
    /// `felipe` holds the root-namespace equivalent.
    async fn tenants(core: &crate::core::Core, root: &str) {
        for ns in ["tenant-a", "tenant-b"] {
            ns_call(core, root, Operation::Write, "", &format!("sys/namespaces/{ns}"), Some(json!({}))).await.unwrap();
            tenant_policy(core, ns, "mcp-tenant", &tenant_operator_policy(ns)).await;
        }
        for (ns, name) in [("tenant-a", "gw-a"), ("tenant-b", "gw-b"), ("", "gw-root")] {
            let record = json!({ "type": "server", "hostname": format!("{name}.example") });
            ns_call(core, root, Operation::Write, ns, &format!("resources/resources/{name}"), Some(record))
                .await
                .unwrap();
        }
        let root_policy = r#"
            path "sys/mcp/token"         { capabilities = ["update"] }
            path "resources/resources/*" { capabilities = ["read", "list"] }
        "#;
        let _ = test_write_api(
            core,
            root,
            "sys/policy/mcp-root",
            true,
            json!({ "policy": root_policy }).as_object().cloned(),
        )
        .await;
        test_mount_auth_api(core, root, "userpass", "userpass").await;
        for (user, policies) in [("alice", "mcp-tenant"), ("felipe", "mcp-root")] {
            let body = json!({ "password": "pw", "policies": policies }).as_object().cloned();
            let _ = test_write_api(core, root, &format!("auth/userpass/users/{user}"), true, body).await;
        }
    }

    /// `user`'s login, bound to namespace `ns` by the header at login.
    async fn login_in(core: &crate::core::Core, user: &str, ns: &str) -> String {
        let resp = ns_call(
            core,
            "",
            Operation::Write,
            ns,
            &format!("auth/userpass/login/{user}"),
            Some(json!({ "password": "pw" })),
        )
        .await
        .unwrap()
        .unwrap();
        resp.auth.expect("a login mints a token").client_token
    }

    fn tenant_pairing(id: &str) -> Option<serde_json::Map<String, Value>> {
        json!({
            "pairing": {
                "id": id,
                "client_name": "claude-code",
                "client_version": "2.1",
                "tool_allowlist": ["bv_whoami", "bv_resource_list", "bv_resource_describe"],
                "path_scope": ["resources/*"],
            },
        })
        .as_object()
        .cloned()
    }

    /// Exchanges `id` as `operator`; returns the token and the namespace the
    /// exchange answer reports.
    async fn pair_as(core: &crate::core::Core, operator: &str, id: &str) -> (String, Value) {
        let data = test_write_api(core, operator, "sys/mcp/token", true, tenant_pairing(id))
            .await
            .unwrap()
            .unwrap()
            .data
            .unwrap();
        (data["auth"]["client_token"].as_str().unwrap().to_string(), data["auth"]["metadata"]["namespace"].clone())
    }

    async fn tool_call(ep: &McpEndpoint<'_>, token: &str, tool: &str, arguments: Value) -> Value {
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": tool, "arguments": arguments },
        }))
        .unwrap();
        match handle_jsonrpc(ep, token, &body).await.unwrap() {
            McpEndpointOutcome::Answer(r) => serde_json::to_value(r).unwrap(),
            other => panic!("expected a JSON-RPC answer, got {other:?}"),
        }
    }

    fn ok(answer: Value) -> Value {
        assert!(answer["error"].is_null(), "the call failed: {answer}");
        answer["result"]["structuredContent"].clone()
    }

    fn refusal_code(answer: &Value) -> String {
        answer["error"]["data"]["code"]
            .as_str()
            .unwrap_or_else(|| panic!("expected a refusal, got {answer}"))
            .to_string()
    }

    /// A file audit device auditing namespace `ns` (`mirror` on a root one
    /// also receives every namespace's entries).
    async fn audit_device(
        core: &crate::core::Core,
        name: &str,
        ns: &str,
        mirror: bool,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "bv-mcp-ns-audit-{name}-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.log");
        let broker = core.audit_broker.load().as_ref().cloned().expect("broker installed at unseal");
        let options = std::collections::HashMap::from([("file_path".to_string(), log.display().to_string())]);
        broker
            .enable_device(crate::audit::AuditDeviceConfig {
                path: format!("ns-{name}"),
                device_type: "file".into(),
                description: String::new(),
                options,
                namespace: ns.to_string(),
                mirror,
            })
            .await
            .unwrap();
        (dir, log)
    }

    fn event_data(log: &std::path::Path, name: &str) -> Vec<Value> {
        audit_lines(log)
            .into_iter()
            .filter(|e| e["type"] == "event" && e["request"]["path"] == name)
            .map(|e| e["request"]["data"].clone())
            .collect()
    }

    /// An operator signed in to `tenant-a` pairs: the token is bound to
    /// `tenant-a` and never child-visible, `bv_resource_list` sees that
    /// tenant's resources and not root's or a sibling's, `bv_whoami` names
    /// the namespace, a `namespace` argument changes nothing, and the audit
    /// block carries it in the tenant's stream and the root mirror. A root
    /// operator is unchanged.
    #[tokio::test]
    async fn test_mcp_pairing_in_a_child_namespace_acts_there() {
        let (_bvault, core_arc, root) = new_unseal_test_bastion_vault("test_mcp_ns_child").await;
        let core: &crate::core::Core = &core_arc;
        let (root_dir, root_log) = audit_device(core, "root", "", true).await;
        let (tenant_dir, tenant_log) = audit_device(core, "tenant", "tenant-a", false).await;
        tenants(core, &root).await;

        let alice = login_in(core, "alice", "tenant-a").await;
        let (token, reported) = pair_as(core, &alice, "alice-a").await;
        assert_eq!(reported, json!("tenant-a"), "the exchange says where the token is bound");
        let auth_module = core.module_manager().get_module::<crate::modules::auth::AuthModule>("auth").unwrap();
        let store = auth_module.token_store.load_full().unwrap();
        let auth = store.check_token("mcp/dispatch", &token, "", true).await.unwrap().unwrap();
        assert_eq!(auth.metadata.get(NS_PATH_META).map(String::as_str), Some("tenant-a"));
        assert_eq!(auth.metadata.get(CHILD_VISIBLE_META).map(String::as_str), Some("false"));
        assert_eq!(auth.mcp_binding.unwrap().operator.unwrap().namespace, "tenant-a");

        let guard = SingleUseGuard::new();
        let ep = McpEndpoint {
            core: &core_arc,
            client_ip: "",
            tool_timeout: std::time::Duration::from_secs(30),
            server_version: "9.9",
            request_state_key: b"ns-test-key",
            single_use_guard: &guard,
        };
        assert_eq!(ok(tool_call(&ep, &token, "bv_whoami", json!({})).await)["namespace"], json!("tenant-a"));
        let listed = ok(tool_call(&ep, &token, "bv_resource_list", json!({})).await);
        assert_eq!(listed["keys"], json!(["gw-a"]), "the tenant's resources, not root's: {listed}");
        assert_eq!(listed["namespace"], json!("tenant-a"));
        let gw = ok(tool_call(&ep, &token, "bv_resource_describe", json!({ "name": "gw-a" })).await);
        assert_eq!(gw["hostname"], json!("gw-a.example"));
        for elsewhere in ["gw-root", "gw-b"] {
            let answer = tool_call(&ep, &token, "bv_resource_describe", json!({ "name": elsewhere })).await;
            assert!(
                answer["error"].is_object() || ok(answer.clone()).get("hostname").is_none(),
                "{elsewhere}: {answer}"
            );
        }
        // A `namespace` argument is not an input.
        for injected in [json!(""), json!("tenant-b"), json!("/")] {
            let listed = ok(tool_call(&ep, &token, "bv_resource_list", json!({ "namespace": injected })).await);
            assert_eq!((listed["keys"].clone(), listed["namespace"].clone()), (json!(["gw-a"]), json!("tenant-a")));
        }

        // A root operator is unchanged.
        let felipe = login_in(core, "felipe", "").await;
        let (root_token, reported) = pair_as(core, &felipe, "felipe-root").await;
        assert_eq!(reported, json!(""));
        let listed = ok(tool_call(&ep, &root_token, "bv_resource_list", json!({})).await);
        assert_eq!((listed["keys"].clone(), listed["namespace"].clone()), (json!(["gw-root"]), json!("")));
        assert_eq!(ok(tool_call(&ep, &root_token, "bv_whoami", json!({})).await)["namespace"], json!(""));

        // The audit block names the namespace, in the tenant's own stream and
        // in the root mirror.
        for log in [&tenant_log, &root_log] {
            let entries = audit_lines(log);
            let listed = entries
                .iter()
                .find(|e| e["request"]["mcp"]["tool"] == "bv_resource_list" && e["namespace"] == "tenant-a")
                .unwrap_or_else(|| panic!("the tenant call is audited in {log:?}: {entries:#?}"));
            assert_eq!(listed["request"]["mcp"]["namespace"], json!("tenant-a"));
            assert_eq!(listed["request"]["path"], json!("tenant-a/resources/resources/"));
        }
        assert!(
            audit_lines(&tenant_log).iter().all(|e| e["request"]["mcp"]["namespace"] != json!("")),
            "the root operator's calls are not in the tenant's stream"
        );
        let _ = std::fs::remove_dir_all(root_dir);
        let _ = std::fs::remove_dir_all(tenant_dir);
    }

    /// Follow the operator's session: re-exchanging the same pairing from a
    /// session in another namespace binds the new token there and records
    /// `mcp.pairing.namespace_changed`; a pairing whose earlier tokens predate
    /// namespace binding (root-bound) records the move from root; revoking
    /// the pairing removes its namespace record.
    #[tokio::test]
    async fn test_mcp_pairing_follows_the_operators_session_and_records_the_move() {
        use crate::storage::{Storage as _, StorageEntry};

        let (_bvault, core_arc, root) = new_unseal_test_bastion_vault("test_mcp_ns_follow").await;
        let core: &crate::core::Core = &core_arc;
        let (dir, log) = audit_device(core, "follow", "", true).await;
        tenants(core, &root).await;
        let guard = SingleUseGuard::new();
        let ep = McpEndpoint {
            core: &core_arc,
            client_ip: "",
            tool_timeout: std::time::Duration::from_secs(30),
            server_version: "9.9",
            request_state_key: b"ns-test-key",
            single_use_guard: &guard,
        };

        let in_a = login_in(core, "alice", "tenant-a").await;
        let (token_a, _) = pair_as(core, &in_a, "follow").await;
        let (again, _) = pair_as(core, &in_a, "follow").await;
        assert!(event_data(&log, "mcp.pairing.namespace_changed").is_empty(), "no move, no record");

        let in_b = login_in(core, "alice", "tenant-b").await;
        let (token_b, reported) = pair_as(core, &in_b, "follow").await;
        assert_eq!(reported, json!("tenant-b"));
        assert_eq!(ok(tool_call(&ep, &token_b, "bv_resource_list", json!({})).await)["keys"], json!(["gw-b"]));
        // The earlier tokens keep their own binding.
        assert_eq!(ok(tool_call(&ep, &token_a, "bv_resource_list", json!({})).await)["keys"], json!(["gw-a"]));
        assert_eq!(ok(tool_call(&ep, &again, "bv_whoami", json!({})).await)["namespace"], json!("tenant-a"));

        let moved = event_data(&log, "mcp.pairing.namespace_changed");
        assert_eq!(moved.len(), 1, "{moved:?}");
        assert_eq!(moved[0]["pairing_id"], json!("follow"));
        assert_eq!(moved[0]["previous_namespace"], json!("tenant-a"));
        assert_eq!(moved[0]["namespace"], json!("tenant-b"));
        assert_eq!(moved[0]["client_name"], json!("claude-code"));
        assert_eq!(moved[0]["operator"]["username"], json!("alice"));

        // A pairing whose tokens were minted before binding existed: an index
        // entry with no namespace, and no record. Those tokens were root-bound.
        let view = sys_mount_view(core);
        let old = br#"{"id":"gone","app_name":"pairing_legacy","client_name":"claude-code","client_version":"1","issued_at":1,"expires_at":2,"kind":"pairing"}"#;
        view.put(&StorageEntry { key: "mcp/app-tokens/pairing_legacy/old".into(), value: old.to_vec() }).await.unwrap();
        pair_as(core, &in_a, "legacy").await;
        let moved = event_data(&log, "mcp.pairing.namespace_changed");
        let legacy = moved.iter().find(|e| e["pairing_id"] == "legacy").expect("the move from root is recorded");
        assert_eq!((legacy["previous_namespace"].clone(), legacy["namespace"].clone()), (json!(""), json!("tenant-a")));

        // The token list says where each token is bound.
        let rows =
            test_list_api(core, &root, "sys/mcp/tokens", true).await.unwrap().unwrap().data.unwrap()["tokens"].clone();
        let namespaces: Vec<Value> = rows
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["app"] == "pairing_follow")
            .map(|r| r["namespace"].clone())
            .collect();
        assert!(namespaces.contains(&json!("tenant-a")) && namespaces.contains(&json!("tenant-b")), "{rows}");

        assert!(view.get("mcp/pairing-namespaces/follow").await.unwrap().is_some());
        ns_call(core, &in_b, Operation::Delete, "", "sys/mcp/pairings/follow", None).await.unwrap();
        assert!(view.get("mcp/pairing-namespaces/follow").await.unwrap().is_none(), "revoked with the pairing");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Fail closed: a namespace deleted after the token was minted, or a
    /// binding that does not normalize, refuses every call with
    /// `mcp_namespace_unavailable` -- never runs it at root -- and the
    /// exchange refuses to mint from a session in a deleted namespace.
    #[tokio::test]
    async fn test_mcp_namespace_unavailable_fails_closed() {
        use crate::modules::namespace::{NamespaceModule, NamespaceQuotas, NAMESPACE_MODULE_NAME};

        let (_bvault, core_arc, root) = new_unseal_test_bastion_vault("test_mcp_ns_gone").await;
        let core: &crate::core::Core = &core_arc;
        tenants(core, &root).await;
        let ns_store =
            core.module_manager().get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME).unwrap().store().unwrap();
        ns_store.create("tenant-gone", NamespaceQuotas::default(), false).await.unwrap();
        tenant_policy(core, "tenant-gone", "mcp-tenant", &tenant_operator_policy("tenant-gone")).await;
        let in_gone = login_in(core, "alice", "tenant-gone").await;
        let (token, reported) = pair_as(core, &in_gone, "gone").await;
        assert_eq!(reported, json!("tenant-gone"));
        ns_store.delete("tenant-gone", 0).await.unwrap();

        let guard = SingleUseGuard::new();
        let ep = McpEndpoint {
            core: &core_arc,
            client_ip: "",
            tool_timeout: std::time::Duration::from_secs(30),
            server_version: "9.9",
            request_state_key: b"ns-test-key",
            single_use_guard: &guard,
        };
        for tool in ["bv_whoami", "bv_resource_list"] {
            let answer = tool_call(&ep, &token, tool, json!({})).await;
            assert_eq!(refusal_code(&answer), "mcp_namespace_unavailable", "{tool}: {answer}");
            assert!(answer["error"]["message"].as_str().unwrap().contains("never run at root"), "{answer}");
        }
        let err = test_write_api(core, &in_gone, "sys/mcp/token", false, tenant_pairing("gone")).await.unwrap_err();
        assert!(err.to_string().contains("mcp_namespace_unavailable"), "{err}");

        // A stored binding that does not normalize is refused, not read as root.
        let in_a = login_in(core, "alice", "tenant-a").await;
        let (token, _) = pair_as(core, &in_a, "malformed").await;
        let auth_module = core.module_manager().get_module::<crate::modules::auth::AuthModule>("auth").unwrap();
        let store = auth_module.token_store.load_full().unwrap();
        let mut entry = store.lookup(&token).await.unwrap().unwrap();
        entry.meta.insert(NS_PATH_META.into(), "tenant-a/../tenant-b".into());
        store.create(&mut entry).await.unwrap();
        let answer = tool_call(&ep, &token, "bv_resource_list", json!({})).await;
        assert_eq!(refusal_code(&answer), "mcp_namespace_unavailable", "{answer}");
    }

    /// Injection regression: `X-BastionVault-Namespace` on `/v2/mcp` has no
    /// effect. A tenant-bound token stays in its tenant whatever the header
    /// says, and a root-bound token cannot be steered into a tenant.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_mcp_namespace_header_on_v2_mcp_changes_nothing() {
        use crate::test_utils::TestHttpServer;

        let server = TestHttpServer::new("test_mcp_ns_header", false).await;
        let core: &crate::core::Core = &server.core;
        let root = server.root_token.clone();
        tenants(core, &root).await;
        let (tenant_token, _) = pair_as(core, &login_in(core, "alice", "tenant-a").await, "hdr-a").await;
        let (root_token, _) = pair_as(core, &login_in(core, "felipe", "").await, "hdr-root").await;

        let post = |token: &str, header: Option<&str>| {
            let agent = ureq::Agent::config_builder().http_status_as_error(false).build().new_agent();
            let mut builder = ::http::Request::builder()
                .method("POST")
                .uri(format!("http://{}/v2/mcp", server.listen_addr))
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {token}"));
            if let Some(ns) = header {
                builder = builder.header("X-BastionVault-Namespace", ns);
            }
            let body = json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "bv_resource_list", "arguments": {} },
            });
            let mut resp = agent.run(builder.body(serde_json::to_vec(&body).unwrap()).unwrap()).unwrap();
            assert_eq!(resp.status().as_u16(), 200);
            ok(resp.body_mut().read_json::<Value>().unwrap())
        };
        for header in [None, Some(""), Some("tenant-b"), Some("tenant-a/../tenant-b")] {
            let listed = post(&tenant_token, header);
            assert_eq!(
                (listed["keys"].clone(), listed["namespace"].clone()),
                (json!(["gw-a"]), json!("tenant-a")),
                "{header:?}"
            );
        }
        for header in [Some("tenant-a"), Some("tenant-b")] {
            let listed = post(&root_token, header);
            assert_eq!(
                (listed["keys"].clone(), listed["namespace"].clone()),
                (json!(["gw-root"]), json!("")),
                "{header:?}"
            );
        }
    }

    // ── MCP namespace selection, Phase 2: narrowing at the exchange ──────

    /// `id`'s pairing body, asking to narrow to `namespace`.
    fn narrowed_pairing(id: &str, namespace: &str) -> Option<serde_json::Map<String, Value>> {
        let mut body = tenant_pairing(id).unwrap();
        body.insert("namespace".into(), json!(namespace));
        Some(body)
    }

    /// The exchange answer's data, or the refusal's text.
    async fn narrow_as(core: &crate::core::Core, operator: &str, id: &str, namespace: &str) -> Result<Value, String> {
        let body = narrowed_pairing(id, namespace).map(Value::Object);
        ns_call(core, operator, Operation::Write, "", "sys/mcp/token", body)
            .await
            .map(|r| Value::Object(r.and_then(|r| r.data).unwrap_or_default()))
            .map_err(|e| e.to_string())
    }

    /// `dti` (child-visible by default, so its logins are), with children
    /// `dti/esi` and `dti/ops`; `mcp-tenant` in `dti`, a resource in `dti/esi`.
    async fn dti_tree(core: &crate::core::Core, root: &str) {
        tenants(core, root).await;
        let dti = json!({ "child_visible_default": true });
        ns_call(core, root, Operation::Write, "", "sys/namespaces/dti", Some(dti)).await.unwrap();
        for child in ["dti/esi", "dti/ops", "tenant-a/sub"] {
            ns_call(core, root, Operation::Write, "", &format!("sys/namespaces/{child}"), Some(json!({})))
                .await
                .unwrap();
        }
        tenant_policy(core, "dti", "mcp-tenant", &tenant_operator_policy("dti")).await;
        let record = json!({ "type": "server", "hostname": "gw-esi.example" });
        ns_call(core, root, Operation::Write, "dti/esi", "resources/resources/gw-esi", Some(record)).await.unwrap();
    }

    /// T457 Phase 2: a child-visible operator narrows a pairing to a
    /// descendant. Policies must exist there first
    /// (`mcp_policy_not_in_namespace`, naming them); then the token is bound
    /// there, never child-visible, acts there, and the move from the
    /// session's namespace is recorded like any other. The operator's MFA
    /// reference follows the token, so a ticket binds where its calls run.
    #[tokio::test]
    async fn test_mcp_pairing_narrows_to_a_descendant() {
        let (_bvault, core_arc, root) = new_unseal_test_bastion_vault("test_mcp_ns_narrow").await;
        let core: &crate::core::Core = &core_arc;
        let (dir, log) = audit_device(core, "narrow", "", true).await;
        dti_tree(core, &root).await;
        let alice = login_in(core, "alice", "dti").await;

        let (_, reported) = pair_as(core, &alice, "narrow").await;
        assert_eq!(reported, json!("dti"), "no `namespace`: the session's own");

        let err = narrow_as(core, &alice, "narrow", "dti/esi").await.unwrap_err();
        assert!(err.contains("mcp_policy_not_in_namespace") && err.contains("mcp-tenant"), "{err}");
        assert!(err.contains("dti/esi"), "{err}");

        tenant_policy(core, "dti/esi", "mcp-tenant", &tenant_operator_policy("dti/esi")).await;
        let data = narrow_as(core, &alice, "narrow", "/dti/esi/").await.unwrap();
        assert_eq!(data["auth"]["metadata"]["namespace"], json!("dti/esi"), "the answer names the narrowed namespace");
        let token = data["auth"]["client_token"].as_str().unwrap().to_string();
        let auth_module = core.module_manager().get_module::<crate::modules::auth::AuthModule>("auth").unwrap();
        let store = auth_module.token_store.load_full().unwrap();
        let auth = store.check_token("mcp/dispatch", &token, "", true).await.unwrap().unwrap();
        assert_eq!(auth.metadata.get(NS_PATH_META).map(String::as_str), Some("dti/esi"));
        assert_eq!(auth.metadata.get(CHILD_VISIBLE_META).map(String::as_str), Some("false"));
        let operator = auth.mcp_binding.unwrap().operator.unwrap();
        assert_eq!((operator.username.as_str(), operator.namespace.as_str()), ("alice", "dti/esi"));

        let guard = SingleUseGuard::new();
        let ep = McpEndpoint {
            core: &core_arc,
            client_ip: "",
            tool_timeout: std::time::Duration::from_secs(30),
            server_version: "9.9",
            request_state_key: b"ns-test-key",
            single_use_guard: &guard,
        };
        let listed = ok(tool_call(&ep, &token, "bv_resource_list", json!({})).await);
        assert_eq!((listed["keys"].clone(), listed["namespace"].clone()), (json!(["gw-esi"]), json!("dti/esi")));

        let moved = event_data(&log, "mcp.pairing.namespace_changed");
        let moved: Vec<_> = moved.iter().filter(|e| e["pairing_id"] == "narrow").collect();
        assert_eq!(moved.len(), 1, "{moved:?}");
        assert_eq!(
            (moved[0]["previous_namespace"].clone(), moved[0]["namespace"].clone()),
            (json!("dti"), json!("dti/esi"))
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// T457 Phase 2 refusals, each with its stable code and never a token in
    /// another namespace: a sibling, the parent, a namespace that is not
    /// well formed, a descendant of a non-child-visible session, and an app
    /// exchange asking to narrow. A permitted descendant that does not exist
    /// is `mcp_namespace_unavailable`. The namespace header is not a
    /// narrowing request.
    #[tokio::test]
    async fn test_mcp_narrowing_is_refused_outside_the_sessions_reach() {
        let (_bvault, core_arc, root) = new_unseal_test_bastion_vault("test_mcp_ns_narrow_refused").await;
        let core: &crate::core::Core = &core_arc;
        dti_tree(core, &root).await;
        let in_dti = login_in(core, "alice", "dti").await;
        let in_a = login_in(core, "alice", "tenant-a").await;

        for (operator, target, code) in [
            (&in_dti, "tenant-a", "mcp_namespace_not_permitted"),
            (&in_dti, "", "mcp_namespace_not_permitted"),
            (&in_dti, "dti/../tenant-a", "mcp_namespace_not_permitted"),
            (&in_dti, "dti/missing", "mcp_namespace_unavailable"),
            (&in_a, "tenant-a/sub", "mcp_namespace_not_permitted"),
            (&in_a, "tenant-b", "mcp_namespace_not_permitted"),
            (&in_a, "", "mcp_namespace_not_permitted"),
        ] {
            let err = narrow_as(core, operator, "refused", target).await.unwrap_err();
            assert!(err.contains(code), "{target:?}: {err}");
        }
        let view = sys_mount_view(core);
        assert!(view.list("mcp/app-tokens/pairing_refused/").await.unwrap().is_empty(), "nothing was minted");

        // The session's own namespace is always within reach.
        let own = narrow_as(core, &in_a, "own", "tenant-a").await.unwrap();
        assert_eq!(own["auth"]["metadata"]["namespace"], json!("tenant-a"));

        let mut app = narrowed_pairing("x", "dti/esi").unwrap();
        app.remove("pairing");
        app.insert("app".into(), json!("some-app"));
        let err = ns_call(core, &in_dti, Operation::Write, "", "sys/mcp/token", Some(Value::Object(app)))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("applies to pairing exchanges only"), "{err}");

        // `X-BastionVault-Namespace` on the exchange asks for nothing: the
        // token follows the session, or the request is refused outright.
        let headed = ns_call(
            core,
            &in_dti,
            Operation::Write,
            "dti/esi",
            "sys/mcp/token",
            tenant_pairing("hdr").map(Value::Object),
        )
        .await;
        if let Ok(Some(resp)) = headed {
            assert_eq!(resp.data.unwrap()["auth"]["metadata"]["namespace"], json!("dti"));
        }
    }

    /// T457 Phase 2: a root-bound, non-child-visible session (an operator who
    /// works in a tenant through the namespace picker) may narrow a pairing to
    /// what an explicit assignment grants, as every other request may.
    /// No record keeps the strict verdict; a revoked one grants nothing.
    #[tokio::test]
    async fn test_mcp_narrowing_honors_a_namespace_assignment() {
        use crate::modules::namespace::{ns_assignment::NsAssignmentStore, NamespaceModule, NAMESPACE_MODULE_NAME};

        let (_bvault, core_arc, root) = new_unseal_test_bastion_vault("test_mcp_ns_narrow_assigned").await;
        let core: &crate::core::Core = &core_arc;
        dti_tree(core, &root).await;
        tenant_policy(core, "dti/esi", "mcp-root", &tenant_operator_policy("dti/esi")).await;
        // Signed in before the assignment exists: a record also limits login.
        let felipe = login_in(core, "felipe", "").await;

        let err = narrow_as(core, &felipe, "assigned", "dti/esi").await.unwrap_err();
        assert!(err.contains("mcp_namespace_not_permitted"), "no record, strict binding verdict: {err}");

        let ns_store =
            core.module_manager().get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME).and_then(|m| m.store()).unwrap();
        let assignments = NsAssignmentStore::new(core).unwrap();
        assignments.set(&ns_store, "userpass/", "felipe", vec!["dti/esi".into()]).await.unwrap().unwrap();

        let data = narrow_as(core, &felipe, "assigned", "dti/esi").await.unwrap();
        assert_eq!(data["auth"]["metadata"]["namespace"], json!("dti/esi"));
        let token = data["auth"]["client_token"].as_str().unwrap().to_string();
        let auth_module = core.module_manager().get_module::<crate::modules::auth::AuthModule>("auth").unwrap();
        let store = auth_module.token_store.load_full().unwrap();
        let auth = store.check_token("mcp/dispatch", &token, "", true).await.unwrap().unwrap();
        assert_eq!(auth.metadata.get(NS_PATH_META).map(String::as_str), Some("dti/esi"));
        assert_eq!(auth.metadata.get(CHILD_VISIBLE_META).map(String::as_str), Some("false"));

        for target in ["dti", "dti/ops", "tenant-a"] {
            let err = narrow_as(core, &felipe, "assigned-out", target).await.unwrap_err();
            assert!(err.contains("mcp_namespace_not_permitted"), "{target:?} is outside the assignment: {err}");
        }

        assignments.delete("userpass/", "felipe").await.unwrap();
        let err = narrow_as(core, &felipe, "assigned-revoked", "dti/esi").await.unwrap_err();
        assert!(err.contains("mcp_namespace_not_permitted"), "a revoked assignment grants nothing: {err}");
    }

    // ── MCP namespace selection: app tokens ───────────────────────────────

    /// A login as AppRole `tenant-app-role`, bound to namespace `ns` by the
    /// header at login (`""` is root), exchanged for app `tenant-app`'s MCP
    /// token holding only `policies`. Returns the answer's `auth` block.
    async fn app_exchange_in(core: &crate::core::Core, root: &str, ns: &str, policies: &str) -> Value {
        let resp = test_read_api(core, root, "auth/approle/role/tenant-app-role/role-id", true).await;
        let role_id = resp.unwrap().unwrap().data.unwrap()["role_id"].as_str().unwrap().to_string();
        let resp = test_write_api(core, root, "auth/approle/role/tenant-app-role/secret-id", true, None).await;
        let secret_id = resp.unwrap().unwrap().data.unwrap()["secret_id"].as_str().unwrap().to_string();
        let credentials = json!({ "role_id": role_id, "secret_id": secret_id });
        let login = ns_call(core, "", Operation::Write, ns, "auth/approle/login", Some(credentials))
            .await
            .unwrap()
            .unwrap()
            .auth
            .expect("an approle login mints a token")
            .client_token;
        let body = json!({ "app": "tenant-app", "policies": policies }).as_object().cloned();
        let data = test_write_api(core, &login, "sys/mcp/token", true, body).await.unwrap().unwrap().data.unwrap();
        data["auth"].clone()
    }

    /// T457 regression, app mode: a tenant AppRole's MCP token is bound to
    /// the tenant (never root, never child-visible) and its policy names
    /// resolve in the tenant's store. A name that exists only in root's
    /// store -- and does grant there -- grants nothing in the tenant. Before
    /// T457 the token was root-bound, so that root policy applied to it.
    #[tokio::test]
    async fn test_mcp_app_exchange_in_a_tenant_binds_there_and_resolves_policies_there() {
        let (_bvault, core_arc, root) = new_unseal_test_bastion_vault("test_mcp_ns_app").await;
        let core: &crate::core::Core = &core_arc;
        tenants(core, &root).await;
        // Root's store only. Grants the tenant's resources under either
        // spelling of the path, so it would act if it were resolved at root.
        let root_only = r#"
            path "sys/mcp/token"                  { capabilities = ["update"] }
            path "resources/resources/*"          { capabilities = ["read", "list"] }
            path "tenant-a/resources/resources/*" { capabilities = ["read", "list"] }
        "#;
        let body = json!({ "policy": root_only }).as_object().cloned();
        let _ = test_write_api(core, &root, "sys/policy/mcp-app-root-only", true, body).await;
        test_mount_auth_api(core, &root, "approle", "approle").await;
        let role = json!({ "policies": "mcp-tenant,mcp-app-root-only", "bypass_machine_binding": true });
        let _ = test_write_api(core, &root, "auth/approle/role/tenant-app-role", true, role.as_object().cloned()).await;
        let app = json!({
            "approle_role": "tenant-app-role",
            "tool_allowlist": "bv_resource_list,bv_resource_describe",
            "path_scope": "resources/*",
        });
        let _ = test_write_api(core, &root, "sys/mcp/apps/tenant-app", true, app.as_object().cloned()).await;
        let waiver = json!({ "reason": "no FerroGate agent in this test", "expires_in_days": 1 });
        let path = "sys/mcp/apps/tenant-app/machine-waiver";
        let _ = test_write_api(core, &root, path, true, waiver.as_object().cloned()).await;

        let auth_module = core.module_manager().get_module::<crate::modules::auth::AuthModule>("auth").unwrap();
        let store = auth_module.token_store.load_full().unwrap();
        let guard = SingleUseGuard::new();
        let ep = McpEndpoint {
            core: &core_arc,
            client_ip: "",
            tool_timeout: std::time::Duration::from_secs(30),
            server_version: "9.9",
            request_state_key: b"ns-test-key",
            single_use_guard: &guard,
        };

        // Bound to the tenant: the answer says so, and so does the token.
        let tenant = app_exchange_in(core, &root, "tenant-a", "mcp-tenant").await;
        assert_eq!(tenant["metadata"]["namespace"], json!("tenant-a"), "{tenant}");
        let token = tenant["client_token"].as_str().unwrap();
        let auth = store.check_token("mcp/dispatch", token, "", true).await.unwrap().unwrap();
        assert_eq!(auth.metadata.get(NS_PATH_META).map(String::as_str), Some("tenant-a"));
        assert_eq!(auth.metadata.get(CHILD_VISIBLE_META).map(String::as_str), Some("false"));
        // A tenant policy name resolves in the tenant's store and acts there.
        let listed = ok(tool_call(&ep, token, "bv_resource_list", json!({})).await);
        assert_eq!((listed["keys"].clone(), listed["namespace"].clone()), (json!(["gw-a"]), json!("tenant-a")));
        let gw = ok(tool_call(&ep, token, "bv_resource_describe", json!({ "name": "gw-a" })).await);
        assert_eq!(gw["hostname"], json!("gw-a.example"));

        // The root-only name is live at root: a root login's token acts with it.
        let at_root = app_exchange_in(core, &root, "", "mcp-app-root-only").await;
        assert_eq!(at_root["metadata"]["namespace"], json!(""), "{at_root}");
        let listed = ok(tool_call(&ep, at_root["client_token"].as_str().unwrap(), "bv_resource_list", json!({})).await);
        assert_eq!(listed["keys"], json!(["gw-root"]), "{listed}");

        // ...and dead in the tenant: held by the token, granting nothing.
        let root_named = app_exchange_in(core, &root, "tenant-a", "mcp-app-root-only").await;
        assert_eq!(root_named["metadata"]["namespace"], json!("tenant-a"), "{root_named}");
        let held = root_named["policies"].as_array().unwrap();
        assert!(held.contains(&json!("mcp-app-root-only")) && !held.contains(&json!("mcp-tenant")), "{root_named}");
        let token = root_named["client_token"].as_str().unwrap();
        let auth = store.check_token("mcp/dispatch", token, "", true).await.unwrap().unwrap();
        assert_eq!(auth.metadata.get(NS_PATH_META).map(String::as_str), Some("tenant-a"));
        // Resolved at root it would list and read `gw-a`; in the tenant's store
        // it does not exist, so the token sees and reads nothing there.
        let listed = ok(tool_call(&ep, token, "bv_resource_list", json!({})).await);
        assert_eq!((listed["keys"].clone(), listed["namespace"].clone()), (json!([]), json!("tenant-a")), "{listed}");
        let answer = tool_call(&ep, token, "bv_resource_describe", json!({ "name": "gw-a" })).await;
        assert_eq!(refusal_code(&answer), "mcp_backend_error", "the root policy must not apply: {answer}");
    }
}
