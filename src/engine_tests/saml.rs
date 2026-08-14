//! Tests for the saml auth backend, which lives in `crates/bv-auth-saml`.
//!
//! Lifted out of the backend because they stand up a whole vault through
//! `crate::test_utils`; its pure unit tests stayed with it.
//!
//! See roadmaps/workspace-decomposition.md § Phase 3.

mod integration_tests {
    use serde_json::json;

    use crate::{
        logical::{Operation, Request},
        test_utils::{
            new_unseal_test_bastion_vault, test_delete_api, test_mount_auth_api, test_read_api,
            test_write_api,
        },
    };

    /// End-to-end CRUD through the actual vault core: mount the
    /// backend, write IdP config + a role, read them back, list roles,
    /// delete one. Proves path routing + storage + field parsing
    /// wire up correctly. No live IdP required.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn saml_config_and_role_crud() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_saml_crud").await;

        test_mount_auth_api(&core, &root_token, "saml", "saml").await;

        // Write + read config.
        let cfg_body = json!({
            "idp_metadata_url": "https://idp.example.com/metadata",
            "entity_id": "https://bastionvault.example.com/saml",
            "acs_url": "https://bastionvault.example.com/v1/auth/saml/callback",
            "idp_sso_url": "https://idp.example.com/sso",
            "idp_cert": "-----BEGIN CERTIFICATE-----\nMIIC...redacted\n-----END CERTIFICATE-----",
            "default_role": "user",
            "allowed_redirect_uris": "http://127.0.0.1:8200/saml/callback"
        })
        .as_object()
        .cloned();
        test_write_api(&core, &root_token, "auth/saml/config", true, cfg_body)
            .await
            .unwrap();

        let cfg_resp = test_read_api(&core, &root_token, "auth/saml/config", true)
            .await
            .unwrap()
            .unwrap();
        let data = cfg_resp.data.unwrap();
        assert_eq!(
            data.get("idp_metadata_url").and_then(|v| v.as_str()),
            Some("https://idp.example.com/metadata")
        );
        assert_eq!(
            data.get("entity_id").and_then(|v| v.as_str()),
            Some("https://bastionvault.example.com/saml")
        );
        // Certificate must be redacted; a boolean hint indicates presence.
        assert_eq!(
            data.get("idp_cert_set").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert!(data.get("idp_cert").is_none());

        // Write + read + list + delete a role.
        let role_body = json!({
            "bound_attributes": r#"{"department":["engineering","sre"]}"#,
            "bound_subjects": "alice@example.com,bob@example.com",
            "bound_subjects_type": "emailAddress",
            "attribute_mappings": r#"{"email":"email","displayName":"name"}"#,
            "groups_attribute": "groups",
            "policies": "default,readonly",
            "token_ttl_secs": 3600
        })
        .as_object()
        .cloned();
        test_write_api(&core, &root_token, "auth/saml/role/user", true, role_body)
            .await
            .unwrap();

        let role_resp = test_read_api(&core, &root_token, "auth/saml/role/user", true)
            .await
            .unwrap()
            .unwrap();
        let role_data = role_resp.data.unwrap();
        assert_eq!(
            role_data
                .get("bound_subjects")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            Some(2)
        );
        assert_eq!(
            role_data
                .get("groups_attribute")
                .and_then(|v| v.as_str()),
            Some("groups")
        );
        let policies = role_data
            .get("policies")
            .and_then(|v| v.as_array())
            .unwrap();
        assert!(policies.iter().any(|p| p.as_str() == Some("default")));
        assert!(policies.iter().any(|p| p.as_str() == Some("readonly")));

        // List roles.
        let mut list_req = Request::new("auth/saml/role/");
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
        test_delete_api(&core, &root_token, "auth/saml/role/user", true, None)
            .await
            .unwrap();
        let deleted = test_read_api(&core, &root_token, "auth/saml/role/user", true)
            .await
            .unwrap();
        assert!(deleted.is_none());
    }
}
