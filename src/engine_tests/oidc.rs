//! Tests for the oidc auth backend, which lives in `crates/bv-auth-oidc`.
//!
//! Lifted out of the backend because they stand up a whole vault through
//! `crate::test_utils`; its pure unit tests stayed with it.
//!
//! See roadmaps/workspace-decomposition.md § Phase 3.

mod integration_tests {
    use crate::kernel_api::VaultCtx;
    use serde_json::json;

    use crate::{
        logical::{Operation, Request},
        test_utils::{
            new_unseal_test_bastion_vault, test_delete_api, test_mount_auth_api, test_read_api,
            test_write_api,
        },
    };

    /// End-to-end CRUD through the actual vault core: mount the
    /// backend, write the provider config + a role, read them back,
    /// list roles, delete one. This proves path routing +
    /// storage + field parsing all wire up correctly without
    /// needing a live OIDC provider.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn oidc_config_and_role_crud() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_oidc_crud").await;

        test_mount_auth_api(&core, &root_token, "oidc", "oidc").await;

        // Write + read config.
        let cfg_body = json!({
            "oidc_discovery_url": "https://issuer.example.com",
            "oidc_client_id": "cid",
            "oidc_client_secret": "sekret",
            "default_role": "user",
            "allowed_redirect_uris": "http://127.0.0.1:8200/oidc/callback"
        })
        .as_object()
        .cloned();
        test_write_api(&core, &root_token, "auth/oidc/config", true, cfg_body)
            .await
            .unwrap();

        let cfg_resp = test_read_api(&core, &root_token, "auth/oidc/config", true)
            .await
            .unwrap()
            .unwrap();
        let data = cfg_resp.data.unwrap();
        assert_eq!(
            data.get("oidc_discovery_url").and_then(|v| v.as_str()),
            Some("https://issuer.example.com")
        );
        // Secret must be redacted.
        assert_eq!(
            data.get("oidc_client_secret_set").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert!(data.get("oidc_client_secret").is_none());
        // Default scopes get filled in.
        let scopes = data.get("oidc_scopes").and_then(|v| v.as_array()).unwrap();
        assert!(scopes.iter().any(|s| s.as_str() == Some("openid")));

        // Write + read + list + delete a role.
        let role_body = json!({
            "bound_audiences": "cid",
            "bound_claims": r#"{"hd":["example.com"]}"#,
            "claim_mappings": r#"{"email":"email","preferred_username":"username"}"#,
            "user_claim": "preferred_username",
            "groups_claim": "groups",
            "policies": "default,readonly",
            "token_ttl_secs": 3600
        })
        .as_object()
        .cloned();
        test_write_api(&core, &root_token, "auth/oidc/role/user", true, role_body)
            .await
            .unwrap();

        let role_resp = test_read_api(&core, &root_token, "auth/oidc/role/user", true)
            .await
            .unwrap()
            .unwrap();
        let role_data = role_resp.data.unwrap();
        assert_eq!(
            role_data
                .get("bound_audiences")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            Some(1)
        );
        assert_eq!(
            role_data
                .get("user_claim")
                .and_then(|v| v.as_str()),
            Some("preferred_username")
        );
        let policies = role_data
            .get("policies")
            .and_then(|v| v.as_array())
            .unwrap();
        assert!(policies.iter().any(|p| p.as_str() == Some("default")));
        assert!(policies.iter().any(|p| p.as_str() == Some("readonly")));

        // List roles.
        let mut list_req = Request::new("auth/oidc/role/");
        list_req.operation = Operation::List;
        list_req.client_token = root_token.clone();
        let list_resp = core.handle_request(&mut list_req).await.unwrap().unwrap();
        let keys = list_resp
            .data
            .as_ref()
            .and_then(|d| d.get("keys"))
            .and_then(|k| k.as_array())
            .unwrap();
        assert!(keys.iter().any(|k| k.as_str() == Some("user")));

        // Delete and confirm it's gone.
        test_delete_api(&core, &root_token, "auth/oidc/role/user", true, None)
            .await
            .unwrap();
        let deleted = test_read_api(&core, &root_token, "auth/oidc/role/user", true)
            .await
            .unwrap();
        assert!(deleted.is_none());
    }

    /// Auth-URL generation requires a reachable discovery endpoint,
    /// which we don't have in CI. Marked `#[ignore]`; run explicitly
    /// against a live IdP (Keycloak / Auth0 / etc.) with the
    /// appropriate env vars to validate the happy-path flow.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    #[ignore]
    async fn oidc_live_auth_url_roundtrip() {
        let discovery =
            std::env::var("BVAULT_TEST_OIDC_DISCOVERY").expect("BVAULT_TEST_OIDC_DISCOVERY");
        let client_id =
            std::env::var("BVAULT_TEST_OIDC_CLIENT_ID").expect("BVAULT_TEST_OIDC_CLIENT_ID");
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_oidc_live").await;
        test_mount_auth_api(&core, &root_token, "oidc", "oidc").await;

        let cfg = json!({
            "oidc_discovery_url": discovery,
            "oidc_client_id": client_id,
            "default_role": "user",
            "allowed_redirect_uris": "http://127.0.0.1:8200/oidc/callback"
        })
        .as_object()
        .cloned();
        test_write_api(&core, &root_token, "auth/oidc/config", true, cfg)
            .await
            .unwrap();
        let role = json!({
            "policies": "default",
            "user_claim": "preferred_username"
        })
        .as_object()
        .cloned();
        test_write_api(&core, &root_token, "auth/oidc/role/user", true, role)
            .await
            .unwrap();

        let body = json!({ "redirect_uri": "http://127.0.0.1:8200/oidc/callback" })
            .as_object()
            .cloned();
        let resp = test_write_api(&core, &root_token, "auth/oidc/auth_url", true, body)
            .await
            .unwrap()
            .unwrap();
        let url = resp
            .data
            .as_ref()
            .and_then(|d| d.get("auth_url"))
            .and_then(|v| v.as_str())
            .unwrap();
        assert!(url.starts_with("http"));
        assert!(url.contains("code_challenge="));
        assert!(url.contains("state="));
    }

    // Silence unused-import warnings for the `#[ignore]` test when
    // everything compiles but tokio::test isn't picked up in sync
    // builds.
    #[allow(dead_code)]
    fn _silence_unused_core(_c: &dyn VaultCtx) {}
}
