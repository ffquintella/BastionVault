//! Tests for the approle auth backend, which lives in `crates/bv-auth-approle`.
//!
//! Lifted out of the backend because they stand up a whole vault through
//! `crate::test_utils`; its pure unit tests stayed with it.
//!
//! See roadmaps/workspace-decomposition.md § Phase 3.

/// Was `#[cfg(test)] mod test` in `lib.rs`.

mod mod_test {
    // `path_role`'s own test module was lifted here too, as `path_role_test`.
    use serde_json::{json, Value};

    // Was `use super::*` inside the backend, which also brought in the crate
    // root's private substrate aliases. Across a crate boundary those have to
    // be named.
    use bv_kernel_api::VaultCtx;

    use crate::{
        errors::RvError,
        logical::{field::FieldTrait, Operation, Request, Response},
        test_utils::{
            new_unseal_test_bastion_vault, test_delete_api, test_mount_auth_api, test_read_api, test_write_api,
        },
    };

    #[maybe_async::maybe_async]
    pub async fn test_read_role(
        core: &dyn VaultCtx,
        token: &str,
        path: &str,
        role_name: &str,
    ) -> Result<Option<Response>, RvError> {
        let resp = test_read_api(core, token, format!("auth/{}/role/{}", path, role_name).as_str(), true).await;
        assert!(resp.is_ok());
        resp
    }

    #[maybe_async::maybe_async]
    pub async fn test_write_role(
        core: &dyn VaultCtx,
        token: &str,
        path: &str,
        role_name: &str,
        role_id: &str,
        policies: &str,
        expect: bool,
    ) {
        let mut role_data = json!({
            "role_id": role_id,
            "policies": policies,
            "secret_id_num_uses": 10,
            "secret_id_ttl":      300,
            "token_ttl":          400,
            "token_max_ttl":      500,
        })
        .as_object()
        .unwrap()
        .clone();

        if role_id.is_empty() {
            role_data.remove("role_id");
        }

        let _ =
            test_write_api(core, token, format!("auth/{}/role/{}", path, role_name).as_str(), expect, Some(role_data))
                .await;
    }

    #[maybe_async::maybe_async]
    pub async fn test_delete_role(core: &dyn VaultCtx, token: &str, path: &str, role_name: &str) {
        let resp = test_delete_api(core, token, format!("auth/{}/role/{}", path, role_name).as_str(), true, None).await;
        assert!(resp.is_ok());
    }

    #[maybe_async::maybe_async]
    pub async fn generate_secret_id(core: &dyn VaultCtx, token: &str, path: &str, role_name: &str) -> (String, String) {
        let resp =
            test_write_api(core, token, format!("auth/{}/role/{}/secret-id", path, role_name).as_str(), true, None)
                .await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        let secret_id = resp_data["secret_id"].as_str().unwrap();
        let secret_id_accessor = resp_data["secret_id_accessor"].as_str().unwrap();

        (secret_id.to_string(), secret_id_accessor.to_string())
    }

    #[maybe_async::maybe_async]
    pub async fn test_login(
        core: &dyn VaultCtx,
        path: &str,
        role_id: &str,
        secret_id: &str,
        is_ok: bool,
    ) -> Result<Option<Response>, RvError> {
        // These legacy login tests predate mandatory machine binding. Disable
        // the server gate so they exercise the role_id + secret_id flow;
        // dedicated tests cover the machine-mandatory path.
        core.approle_require_machine().store(false, std::sync::atomic::Ordering::Relaxed);

        let data = json!({
            "role_id": role_id,
            "secret_id": secret_id,
        })
        .as_object()
        .cloned();

        let mut req = Request::new(format!("auth/{}/login", path).as_str());
        req.operation = Operation::Write;
        req.body = data;

        let resp = core.handle_request(&mut req).await;
        if is_ok {
            assert!(resp.is_ok());
            let resp = resp.as_ref().unwrap();
            assert!(resp.is_some());
            let resp = resp.as_ref().unwrap();
            assert!(resp.auth.is_some());
        } else {
            assert!(resp.is_err());
        }

        resp
    }

    #[maybe_async::maybe_async]
    async fn test_approle(core: &dyn VaultCtx, token: &str, path: &str, role_name: &str) {
        // Create a role
        let resp = test_write_api(core, token, format!("auth/{}/role/{}", path, role_name).as_str(), true, None).await;
        assert!(resp.is_ok());

        // Get the role-id
        let resp = test_read_api(core, token, format!("auth/{}/role/{}/role-id", path, role_name).as_str(), true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data;
        let role_id = resp_data.unwrap()["role_id"].clone();
        let role_id = role_id.as_str().unwrap();

        // Create a secret-id
        let (secret_id, secret_id_accessor) = generate_secret_id(core, token, path, role_name).await;

        // Ensure login works
        let _ = test_login(core, path, role_id, &secret_id, true).await;

        // Destroy secret ID accessor
        let data = json!({
            "secret_id_accessor": secret_id_accessor,
        })
        .as_object()
        .cloned();
        let resp = test_write_api(
            core,
            token,
            format!("auth/{}/role/{}/secret-id-accessor/destroy", path, role_name).as_str(),
            true,
            data,
        )
        .await;
        assert!(resp.is_ok());

        // Login again using the accessor's corresponding secret ID should fail
        let _ = test_login(core, path, role_id, &secret_id, false).await;

        // Generate another secret ID
        let (secret_id, _secret_id_accessor) = generate_secret_id(core, token, path, role_name).await;

        // Ensure login works
        let _ = test_login(core, path, role_id, &secret_id, true).await;

        // Destroy secret ID
        let data = json!({
            "secret_id": secret_id,
        })
        .as_object()
        .cloned();
        let resp = test_write_api(
            core,
            token,
            format!("auth/{}/role/{}/secret-id/destroy", path, role_name).as_str(),
            true,
            data,
        )
        .await;
        assert!(resp.is_ok());

        // Login again using the same secret ID should fail
        let _ = test_login(core, path, role_id, &secret_id, false).await;

        // Generate another secret ID
        let (secret_id, _secret_id_accessor) = generate_secret_id(core, token, path, role_name).await;

        // Ensure login works
        let _ = test_login(core, path, role_id, &secret_id, true).await;

        // Destroy the secret ID using lower cased role name
        let data = json!({
            "secret_id": secret_id,
        })
        .as_object()
        .cloned();
        let resp = test_write_api(
            core,
            token,
            format!("auth/{}/role/{}/secret-id/destroy", path, role_name.to_lowercase()).as_str(),
            true,
            data,
        )
        .await;
        assert!(resp.is_ok());

        // Login again using the same secret ID should fail
        let _ = test_login(core, path, role_id, &secret_id, false).await;

        // Generate another secret ID
        let (secret_id, _secret_id_accessor) = generate_secret_id(core, token, path, role_name).await;

        // Ensure login works
        let _ = test_login(core, path, role_id, &secret_id, true).await;

        // Destroy the secret ID using upper cased role name
        let data = json!({
            "secret_id": secret_id,
        })
        .as_object()
        .cloned();
        let resp = test_write_api(
            core,
            token,
            format!("auth/{}/role/{}/secret-id/destroy", path, role_name.to_uppercase()).as_str(),
            true,
            data,
        )
        .await;
        assert!(resp.is_ok());

        // Login again using the same secret ID should fail
        let _ = test_login(core, path, role_id, &secret_id, false).await;

        // Generate another secret ID
        let (secret_id, _secret_id_accessor) = generate_secret_id(core, token, path, role_name).await;

        // Ensure login works
        let _ = test_login(core, path, role_id, &secret_id, true).await;

        // Destroy the secret ID using mixed case name
        let data = json!({
            "secret_id": secret_id,
        })
        .as_object()
        .cloned();
        let mut mixed_case_name = role_name.to_string();
        if let Some(first_char) = mixed_case_name.get_mut(0..1) {
            let inverted_case_char = if first_char.chars().next().unwrap().is_uppercase() {
                first_char.to_lowercase()
            } else {
                first_char.to_uppercase()
            };
            mixed_case_name.replace_range(0..1, &inverted_case_char);
        }
        let resp = test_write_api(
            core,
            token,
            format!("auth/{}/role/{}/secret-id/destroy", path, mixed_case_name).as_str(),
            true,
            data,
        )
        .await;
        assert!(resp.is_ok());

        // Login again using the same secret ID should fail
        let _ = test_login(core, path, role_id, &secret_id, false).await;
    }

    #[maybe_async::maybe_async]
    async fn test_approle_role_service(core: &dyn VaultCtx, token: &str, path: &str, role_name: &str) {
        // Create a role
        let mut data = json!({
            "bind_secret_id":       true,
            "secret_id_num_uses":   0,
            "secret_id_ttl":        "10m",
            "token_policies":       "policy",
            "token_ttl":            "5m",
            "token_max_ttl":        "10m",
            "token_num_uses":       2,
            "token_type":           "default",
        })
        .as_object()
        .unwrap()
        .clone();
        let resp =
            test_write_api(core, token, format!("auth/{}/role/{}", path, role_name).as_str(), true, Some(data.clone()))
                .await;
        assert!(resp.is_ok());

        // Get the role field
        let resp = test_read_role(core, token, path, role_name).await;
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["bind_secret_id"].as_bool().unwrap(), data["bind_secret_id"].as_bool().unwrap());
        assert_eq!(resp_data["secret_id_num_uses"].as_i64().unwrap(), data["secret_id_num_uses"].as_i64().unwrap());
        assert_eq!(
            resp_data["secret_id_ttl"].as_u64().unwrap(),
            data["secret_id_ttl"].as_duration().unwrap().as_secs()
        );
        assert_eq!(
            resp_data["token_policies"].as_comma_string_slice().unwrap(),
            data["token_policies"].as_comma_string_slice().unwrap()
        );
        assert_eq!(resp_data["token_ttl"].as_u64().unwrap(), data["token_ttl"].as_duration().unwrap().as_secs());
        assert_eq!(
            resp_data["token_max_ttl"].as_u64().unwrap(),
            data["token_max_ttl"].as_duration().unwrap().as_secs()
        );
        assert_eq!(resp_data["token_num_uses"].as_i64().unwrap(), data["token_num_uses"].as_i64().unwrap());
        assert_eq!(resp_data["token_type"].as_str().unwrap(), data["token_type"].as_str().unwrap());

        // Update the role
        data["token_num_uses"] = Value::from(0);
        data["token_type"] = Value::from("batch");
        let resp =
            test_write_api(core, token, format!("auth/{}/role/{}", path, role_name).as_str(), true, Some(data.clone()))
                .await;
        assert!(resp.is_ok());

        // Get the role field
        let resp = test_read_role(core, token, path, role_name).await;
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["bind_secret_id"].as_bool().unwrap(), data["bind_secret_id"].as_bool().unwrap());
        assert_eq!(resp_data["secret_id_num_uses"].as_i64().unwrap(), data["secret_id_num_uses"].as_i64().unwrap());
        assert_eq!(
            resp_data["secret_id_ttl"].as_u64().unwrap(),
            data["secret_id_ttl"].as_duration().unwrap().as_secs()
        );
        assert_eq!(
            resp_data["token_policies"].as_comma_string_slice().unwrap(),
            data["token_policies"].as_comma_string_slice().unwrap()
        );
        assert_eq!(resp_data["token_ttl"].as_u64().unwrap(), data["token_ttl"].as_duration().unwrap().as_secs());
        assert_eq!(
            resp_data["token_max_ttl"].as_u64().unwrap(),
            data["token_max_ttl"].as_duration().unwrap().as_secs()
        );
        assert_eq!(resp_data["token_num_uses"].as_i64().unwrap(), data["token_num_uses"].as_i64().unwrap());
        assert_eq!(resp_data["token_type"].as_str().unwrap(), data["token_type"].as_str().unwrap());

        // Get the role-id
        let resp = test_read_api(core, token, format!("auth/{}/role/{}/role-id", path, role_name).as_str(), true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data;
        let role_id = resp_data.unwrap()["role_id"].clone();
        let role_id = role_id.as_str().unwrap();

        // Create a secret-id
        let (secret_id, _secret_id_accessor) = generate_secret_id(core, token, path, role_name).await;

        // Ensure login works
        let _ = test_login(core, path, role_id, &secret_id, true).await;

        // Get the role field
        let resp = test_read_role(core, token, path, role_name).await;
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        println!("resp_data: {:?}", resp_data);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_credential_approle_module() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_credential_approle_module").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle/").await;

        test_approle(&core, &root_token, "approle", "samplerolename").await;
        test_approle(&core, &root_token, "approle", "SAMPLEROLENAME").await;
        test_approle(&core, &root_token, "approle", "SampleRoleName").await;

        test_approle_role_service(&core, &root_token, "approle", "testrole").await;
    }
}
/// Was `#[cfg(test)] mod test` in `path_role.rs`.
mod path_role_test {
    use std::{default::Default, sync::Arc};

    use serde_json::{json, Value};

    // `super::super::` inside the backend: the sibling helpers live in the
    // block lifted from `lib.rs`, the two items in the crate root.
    use super::mod_test::{generate_secret_id, test_delete_role, test_login, test_write_role};
    use bv_kernel_api::VaultCtx;

    use crate::logical::field::FieldTrait;
    use crate::modules::credential::approle::path_role::*;
    use crate::modules::credential::approle::{AppRoleModule, SECRET_ID_PREFIX};
    use crate::{
        errors::RvError,
        logical::{Operation, Request},
        kernel_api::auth::MAX_LEASE_DURATION_SECS,
        storage::Storage,
        test_utils::{
            new_unseal_test_bastion_vault, test_delete_api, test_list_api, test_mount_auth_api, test_read_api,
            test_write_api,
        },
    };

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_read_local_secret_ids() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_approle_read_local_secret_ids").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        // Create a role
        let data = json!({
            "local_secret_ids": true,
            "bind_secret_id":   true,
        })
        .as_object()
        .unwrap()
        .clone();

        let resp = test_write_api(&core, &root_token, "auth/approle/role/testrole", true, Some(data.clone())).await;
        assert!(resp.is_ok());

        // Get the role field
        let resp = test_read_api(&core, &root_token, "auth/approle/role/testrole/local-secret-ids", true).await;
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["local_secret_ids"].as_bool().unwrap(), data["local_secret_ids"].as_bool().unwrap());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_local_non_secret_ids() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_approle_local_non_secret_ids").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        // Create a role with local_secret_ids set
        let data = json!({
            "policies": ["default", "role1policy"],
            "local_secret_ids": true,
            "bind_secret_id":   true,
        })
        .as_object()
        .cloned();
        let resp = test_write_api(&core, &root_token, "auth/approle/role/testrole1", true, data).await;
        assert!(resp.is_ok());

        // Create another role without setting local_secret_ids
        let data = json!({
            "policies": ["default", "role1policy"],
            "bind_secret_id":   true,
        })
        .as_object()
        .cloned();
        let resp = test_write_api(&core, &root_token, "auth/approle/role/testrole2", true, data).await;
        assert!(resp.is_ok());

        // Create secret IDs on testrole1
        let len = 10;
        for _i in 0..len {
            let ret = test_write_api(&core, &root_token, "auth/approle/role/testrole1/secret-id", true, None).await;
            assert!(ret.is_ok());
        }

        // Check the number of secret IDs generated
        let resp = test_list_api(&core, &root_token, "auth/approle/role/testrole1/secret-id", true).await;
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert!(resp_data["keys"].is_array());
        assert_eq!(resp_data["keys"].as_array().unwrap().len(), len);

        // Create secret IDs on testrole2
        for _i in 0..len {
            let ret = test_write_api(&core, &root_token, "auth/approle/role/testrole2/secret-id", true, None).await;
            assert!(ret.is_ok());
        }

        // Check the number of secret IDs generated
        let resp = test_list_api(&core, &root_token, "auth/approle/role/testrole2/secret-id", true).await;
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert!(resp_data["keys"].is_array());
        assert_eq!(resp_data["keys"].as_array().unwrap().len(), len);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_upgrade_secret_id_prefix() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_approle_upgrade_secret_id_prefix").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        let approle_module = core.module_manager().get_module::<AppRoleModule>("approle").unwrap();

        let mut req = Request::new("/auth/approle/testrole");
        req.operation = Operation::Write;
        req.storage = core.get_system_view().map(|arc| arc as Arc<dyn Storage>);

        let role_entry = RoleEntry {
            role_id: "testroleid".to_string(),
            hmac_key: "testhmackey".to_string(),
            bind_secret_id: true,
            bound_cidr_list_old: "127.0.0.1/18,192.178.1.2/24".to_string(),
            ..Default::default()
        };
        let resp = approle_module.set_role(&mut req, "testrole", &role_entry, "").await;
        assert!(resp.is_ok());

        // Reading the role entry should upgrade it to contain secret_id_prefix
        let resp = approle_module.get_role(&mut req, "testrole").await;
        assert!(resp.is_ok());
        let role_entry = resp.unwrap().unwrap();
        assert_ne!(role_entry.secret_id_prefix, "");

        // Ensure that the API response contains local_secret_ids
        req.operation = Operation::Read;
        req.path = "auth/approle/role/testrole".to_string();
        req.client_token = root_token.to_string();
        let _resp = core.handle_request(&mut req).await;
        req.storage = core.get_system_view().map(|arc| arc as Arc<dyn Storage>);

        let mock_backend = approle_module.new_backend();
        let resp = approle_module.read_role(&mock_backend, &mut req).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert!(!resp_data["local_secret_ids"].as_bool().unwrap());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_local_secret_id_immutablility() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_approle_local_secret_id_immutablility").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        // Create a role with local_secret_ids set
        let data = json!({
            "policies": ["default"],
            "bind_secret_id":   true,
            "local_secret_ids": true,
            "bound_cidr_list": ["127.0.0.1/18", "192.178.1.2/24"],
        })
        .as_object()
        .cloned();
        let resp = test_write_api(&core, &root_token, "auth/approle/role/testrole", true, data.clone()).await;
        assert!(resp.is_ok());

        // Attempt to modify local_secret_ids should fail
        let _ = test_write_api(&core, &root_token, "auth/approle/role/testrole", false, data.clone()).await;
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_upgrade_bound_cidr_list() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_approle_upgrade_bound_cidr_list").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        // Create a role with bound_cidr_list set
        let data = json!({
            "policies": ["default"],
            "bind_secret_id":   true,
            "bound_cidr_list": ["127.0.0.1/18", "192.178.1.2/24"],
        })
        .as_object()
        .unwrap()
        .clone();
        let resp = test_write_api(&core, &root_token, "auth/approle/role/testrole", true, Some(data.clone())).await;
        assert!(resp.is_ok());

        // Read the role and check that the bound_cidr_list is set properly
        let resp = test_read_api(&core, &root_token, "auth/approle/role/testrole", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        let expected: Vec<Value> =
            data["bound_cidr_list"].as_comma_string_slice().unwrap().iter().map(|s| Value::String(s.clone())).collect();
        assert_eq!(resp_data["secret_id_bound_cidrs"].as_array().unwrap().clone(), expected);

        let approle_module = core.module_manager().get_module::<AppRoleModule>("approle").unwrap();

        let mut req = Request::new("/auth/approle/testrole");
        req.operation = Operation::Write;
        req.storage = core.get_system_view().map(|arc| arc as Arc<dyn Storage>);

        // Modify the storage entry of the role to hold the old style string typed bound_cidr_list
        let role_entry = RoleEntry {
            role_id: "testroleid".to_string(),
            hmac_key: "testhmackey".to_string(),
            bind_secret_id: true,
            bound_cidr_list_old: "127.0.0.1/18,192.178.1.2/24".to_string(),
            secret_id_prefix: SECRET_ID_PREFIX.to_string(),
            ..Default::default()
        };
        let resp = approle_module.set_role(&mut req, "testrole", &role_entry, "").await;
        assert!(resp.is_ok());
        let expected: Vec<String> = role_entry.bound_cidr_list_old.split(',').map(|s| s.to_string()).collect();

        // Read the role. The upgrade code should have migrated the old type to the new type
        let resp = approle_module.get_role(&mut req, "testrole").await;
        assert!(resp.is_ok());
        let role_entry = resp.unwrap().unwrap();
        assert_eq!(role_entry.secret_id_bound_cidrs, expected);
        assert_eq!(role_entry.bound_cidr_list_old.len(), 0);
        assert_eq!(role_entry.bound_cidr_list.len(), 0);

        // Create a secret-id by supplying a subset of the role's CIDR blocks with the new type
        let data = json!({
            "cidr_list": ["127.0.0.1/24"],
        })
        .as_object()
        .cloned();
        let resp = test_write_api(&core, &root_token, "auth/approle/role/testrole/secret-id", true, data).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        let secret_id = resp_data["secret_id"].as_str().unwrap();
        assert_ne!(secret_id, "");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_role_name_lower_casing() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_approle_role_name_lower_casing").await;

        // This test predates mandatory machine binding and logs in with only
        // role_id + secret_id; disable the server gate for the legacy flow.
        core.approle_require_machine().store(false, std::sync::atomic::Ordering::Relaxed);

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        let approle_module = core.module_manager().get_module::<AppRoleModule>("approle").unwrap();

        let mut req = Request::new("/auth/approle/testrole");
        req.operation = Operation::Write;
        req.storage = core.get_system_view().map(|arc| arc as Arc<dyn Storage>);

        // Create a role with lower_case_role_name is false
        let role_entry = RoleEntry {
            role_id: "testroleid".to_string(),
            hmac_key: "testhmackey".to_string(),
            bind_secret_id: true,
            lower_case_role_name: false,
            secret_id_prefix: SECRET_ID_PREFIX.to_string(),
            ..Default::default()
        };
        let resp = approle_module.set_role(&mut req, "testRoleName", &role_entry, "").await;
        assert!(resp.is_ok());

        req.operation = Operation::Write;
        req.path = "auth/approle/role/testRoleName/secret-id".to_string();
        req.client_token = root_token.to_string();
        let _resp = core.handle_request(&mut req).await;
        req.storage = core.get_system_view().map(|arc| arc as Arc<dyn Storage>);

        let mock_backend = approle_module.new_backend();
        let resp = approle_module.write_role_secret_id(&mock_backend, &mut req).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        let secret_id = resp_data["secret_id"].as_str().unwrap();
        let role_id = "testroleid";

        // Regular login flow. This should succeed
        let data = json!({
            "role_id": role_id,
            "secret_id": secret_id,
        })
        .as_object()
        .cloned();
        req.path = "auth/approle/login".to_string();
        req.operation = Operation::Write;
        req.body = data;
        let _resp = core.handle_request(&mut req).await;
        req.storage = core.get_system_view().map(|arc| arc as Arc<dyn Storage>);
        let resp = approle_module.login(&mock_backend, &mut req).await;
        assert!(resp.is_ok());

        // Lower case the role name when generating the secret id
        req.path = "auth/approle/role/testrolename/secret-id".to_string();
        req.operation = Operation::Write;
        req.body = None;
        let _resp = core.handle_request(&mut req).await;
        req.storage = core.get_system_view().map(|arc| arc as Arc<dyn Storage>);
        let resp = approle_module.write_role_secret_id(&mock_backend, &mut req).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        let secret_id = resp_data["secret_id"].as_str().unwrap();

        // Login should fail
        let data = json!({
            "role_id": role_id,
            "secret_id": secret_id,
        })
        .as_object()
        .cloned();
        req.path = "auth/approle/login".to_string();
        req.operation = Operation::Write;
        req.body = data;
        let _resp = core.handle_request(&mut req).await;
        req.storage = core.get_system_view().map(|arc| arc as Arc<dyn Storage>);
        let resp = approle_module.login(&mock_backend, &mut req).await;
        assert!(resp.is_err());

        // Delete the role and create it again. This time don't directly persist
        // it, but route the request to the creation handler so that it sets the
        // lower_case_role_name to true.
        req.path = "auth/approle/role/testRoleName".to_string();
        req.operation = Operation::Delete;
        req.body = None;
        let _resp = core.handle_request(&mut req).await;
        req.storage = core.get_system_view().map(|arc| arc as Arc<dyn Storage>);
        let resp = approle_module.delete_role(&mock_backend, &mut req).await;
        assert!(resp.is_ok());

        let data = json!({
            "policies": ["default"],
            "bind_secret_id":   true,
        })
        .as_object()
        .cloned();
        let resp = test_write_api(&core, &root_token, "auth/approle/role/testRoleName", true, data).await;
        assert!(resp.is_ok());

        // Create secret id with lower cased role name
        let resp = test_write_api(&core, &root_token, "auth/approle/role/testrolename/secret-id", true, None).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        let secret_id = resp_data["secret_id"].as_str().unwrap();

        let resp = test_read_api(&core, &root_token, "auth/approle/role/testrolename/role-id", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        let role_id = resp_data["role_id"].as_str().unwrap();

        // Login should pass
        let _ = test_login(&core, "approle", role_id, secret_id, true).await;

        // Lookup of secret ID should work in case-insensitive manner
        let data = json!({
            "secret_id": secret_id,
        })
        .as_object()
        .cloned();
        let resp =
            test_write_api(&core, &root_token, "auth/approle/role/testrolename/secret-id/lookup", true, data).await;
        assert!(resp.is_ok());

        // Listing of secret IDs should work in case-insensitive manner
        let resp = test_list_api(&core, &root_token, "auth/approle/role/testrolename/secret-id", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        let keys = resp_data["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_role_read_set_index() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_approle_role_read_set_index").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        let approle_module = core.module_manager().get_module::<AppRoleModule>("approle").unwrap();
        let mock_backend = approle_module.new_backend();

        // Create a role
        let mut req = Request::new("/auth/approle/testrole");
        req.operation = Operation::Write;
        req.storage = core.get_system_view().map(|arc| arc as Arc<dyn Storage>);
        let role_entry = RoleEntry {
            role_id: "testroleid".to_string(),
            hmac_key: "testhmackey".to_string(),
            bind_secret_id: true,
            secret_id_prefix: SECRET_ID_PREFIX.to_string(),
            ..Default::default()
        };
        let resp = approle_module.set_role(&mut req, "testrole", &role_entry, "").await;
        assert!(resp.is_ok());

        // Get the role ID
        req.operation = Operation::Read;
        req.path = "auth/approle/role/testrole/role-id".to_string();
        req.client_token = root_token.to_string();
        let _resp = core.handle_request(&mut req).await;
        req.storage = core.get_system_view().map(|arc| arc as Arc<dyn Storage>);
        let resp = approle_module.read_role_role_id(&mock_backend, &mut req).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        let role_id = resp_data["role_id"].as_str().unwrap();

        // Delete the role ID index
        req.operation = Operation::Write;
        req.path = "auth/approle/role/testrole/role-id".to_string();
        req.client_token = root_token.to_string();
        let _resp = core.handle_request(&mut req).await;
        req.storage = core.get_system_view().map(|arc| arc as Arc<dyn Storage>);
        let resp = approle_module.delete_role_id(&mut req, role_id).await;
        assert!(resp.is_ok());

        // Read the role again. This should add the index and return a warning
        req.operation = Operation::Read;
        req.path = "auth/approle/role/testrole".to_string();
        req.client_token = root_token.to_string();
        let _resp = core.handle_request(&mut req).await;
        req.storage = core.get_system_view().map(|arc| arc as Arc<dyn Storage>);
        let resp = approle_module.read_role(&mock_backend, &mut req).await;
        assert!(resp.is_ok());
        let resp = resp.unwrap().unwrap();
        assert!(resp.warnings.contains(&"Role identifier was missing an index back to role name".to_string()));

        // Check if the index has been successfully created
        req.storage = core.get_system_view().map(|arc| arc as Arc<dyn Storage>);
        let role_id_entry = approle_module.get_role_id(&mut req, role_id).await;
        assert!(role_id_entry.is_ok());
        let role_id_entry = role_id_entry.unwrap().unwrap();
        assert_eq!(role_id_entry.name, "testrole");

        // Check if updating and reading of roles work and that there are no lock
        // contentions dangling due to previous operation
        let data = json!({
            "policies": ["default"],
            "bind_secret_id":   true,
        })
        .as_object()
        .cloned();
        let resp = test_write_api(&core, &root_token, "auth/approle/role/testrole", true, data).await;
        assert!(resp.is_ok());
        let resp = test_read_api(&core, &root_token, "auth/approle/role/testrole", true).await;
        assert!(resp.is_ok());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_cidr_subset() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_approle_cidr_subset").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        let mut role_data = json!({
            "role_id": "role-id-123",
            "policies": "a,b",
            "bound_cidr_list": "127.0.0.1/24",
        })
        .as_object()
        .unwrap()
        .clone();
        let resp =
            test_write_api(&core, &root_token, "auth/approle/role/testrole1", true, Some(role_data.clone())).await;
        assert!(resp.is_ok());

        let resp = test_read_api(&core, &root_token, "auth/approle/role/testrole", true).await;
        assert!(resp.is_ok());

        let mut secret_data = json!({
            "cidr_list": ["127.0.0.1/16"],
        })
        .as_object()
        .unwrap()
        .clone();
        let resp = test_write_api(
            &core,
            &root_token,
            "auth/approle/role/testrole1/secret-id",
            false,
            Some(secret_data.clone()),
        )
        .await;
        assert!(resp.is_err());

        role_data["bound_cidr_list"] = Value::from("192.168.27.29/16,172.245.30.40/24,10.20.30.40/30");
        let resp = test_write_api(&core, &root_token, "auth/approle/role/testrole1", true, Some(role_data)).await;
        assert!(resp.is_ok());

        secret_data["cidr_list"] = Value::from("192.168.27.29/20,172.245.30.40/25,10.20.30.40/32");
        let resp =
            test_write_api(&core, &root_token, "auth/approle/role/testrole1/secret-id", true, Some(secret_data)).await;
        assert!(resp.is_ok());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_token_bound_cidr_subset_32_mask() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_approle_token_bound_cidr_subset_32_mask").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        let role_data = json!({
            "role_id": "role-id-123",
            "policies": "a,b",
            "token_bound_cidrs": "127.0.0.1/32",
        })
        .as_object()
        .cloned();
        let resp = test_write_api(&core, &root_token, "auth/approle/role/testrole1", true, role_data).await;
        assert!(resp.is_ok());

        let resp = test_read_api(&core, &root_token, "auth/approle/role/testrole", true).await;
        assert!(resp.is_ok());

        let mut secret_data = json!({
            "token_bound_cidrs": ["127.0.0.1/32"],
        })
        .as_object()
        .unwrap()
        .clone();
        let resp = test_write_api(
            &core,
            &root_token,
            "auth/approle/role/testrole1/secret-id",
            true,
            Some(secret_data.clone()),
        )
        .await;
        assert!(resp.is_ok());

        secret_data["token_bound_cidrs"] = Value::from("127.0.0.1/24");
        let resp =
            test_write_api(&core, &root_token, "auth/approle/role/testrole1/secret-id", false, Some(secret_data)).await;
        assert!(resp.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_machine_binding_crud() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_approle_machine_binding_crud").await;

        test_mount_auth_api(&core, &root_token, "approle", "approle").await;
        test_write_role(&core, &root_token, "approle", "mrole", "mrole-id", "a,b", true).await;

        // Bind a machine by explicit machine_id with an environment scope.
        let bind = json!({ "machine_id": "abc123", "environments": "prod,prod-*" }).as_object().cloned();
        let resp = test_write_api(&core, &root_token, "auth/approle/role/mrole/machine/", true, bind).await;
        assert!(resp.is_ok());

        // List reflects the binding.
        let resp = test_list_api(&core, &root_token, "auth/approle/role/mrole/machine/", true).await;
        let data = resp.unwrap().unwrap().data.unwrap();
        let machines = data["machines"].as_array().unwrap();
        assert_eq!(machines.len(), 1);
        assert_eq!(machines[0]["machine_id"], "abc123");
        assert_eq!(machines[0]["environments"][0], "prod");

        // Read the single binding back.
        let resp = test_read_api(&core, &root_token, "auth/approle/role/mrole/machine/abc123", true).await;
        let data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(data["machine_id"], "abc123");

        // Re-binding the same machine updates (does not duplicate) it.
        let rebind = json!({ "machine_id": "abc123", "environments": "staging" }).as_object().cloned();
        let _ = test_write_api(&core, &root_token, "auth/approle/role/mrole/machine/", true, rebind).await;
        let resp = test_list_api(&core, &root_token, "auth/approle/role/mrole/machine/", true).await;
        let data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(data["machines"].as_array().unwrap().len(), 1);
        assert_eq!(data["machines"][0]["environments"][0], "staging");

        // The binding shows up on the role read.
        let resp = test_read_api(&core, &root_token, "auth/approle/role/mrole", true).await;
        let data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(data["bound_machines"].as_array().unwrap().len(), 1);

        // Delete the binding.
        let _ = test_delete_api(&core, &root_token, "auth/approle/role/mrole/machine/abc123", true, None).await;
        let resp = test_list_api(&core, &root_token, "auth/approle/role/mrole/machine/", true).await;
        let data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(data["machines"].as_array().unwrap().len(), 0);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_secret_id_environments_roundtrip() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_approle_secret_id_environments_roundtrip").await;

        test_mount_auth_api(&core, &root_token, "approle", "approle").await;
        test_write_role(&core, &root_token, "approle", "erole", "erole-id", "a,b", true).await;

        // Generate a secret-id scoped to environments.
        let gen = json!({ "environments": "prod,staging" }).as_object().cloned();
        let resp = test_write_api(&core, &root_token, "auth/approle/role/erole/secret-id", true, gen).await;
        let data = resp.unwrap().unwrap().data.unwrap();
        let accessor = data["secret_id_accessor"].as_str().unwrap().to_string();
        assert_eq!(data["environments"][0], "prod");

        // The scope is persisted and returned via accessor lookup.
        let lookup = json!({ "secret_id_accessor": accessor }).as_object().cloned();
        let resp =
            test_write_api(&core, &root_token, "auth/approle/role/erole/secret-id-accessor/lookup/", true, lookup)
                .await;
        let data = resp.unwrap().unwrap().data.unwrap();
        let envs = data["environments"].as_array().unwrap();
        assert_eq!(envs.len(), 2);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_login_requires_machine_when_gated() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_approle_login_requires_machine_when_gated").await;

        test_mount_auth_api(&core, &root_token, "approle", "approle").await;
        test_write_role(&core, &root_token, "approle", "grole", "grole-id", "a,b", true).await;

        let resp = test_write_api(&core, &root_token, "auth/approle/role/grole/secret-id", true, None).await;
        let secret_id = resp.unwrap().unwrap().data.unwrap()["secret_id"].as_str().unwrap().to_string();

        // Gate defaults to ON: login without a machine_token is rejected.
        let resp = test_read_api(&core, &root_token, "auth/approle/config", true).await;
        assert_eq!(resp.unwrap().unwrap().data.unwrap()["require_machine"], Value::Bool(true));

        let login = json!({ "role_id": "grole-id", "secret_id": secret_id }).as_object().cloned();
        let mut req = Request::new("auth/approle/login");
        req.operation = Operation::Write;
        req.body = login.clone();
        assert!(core.handle_request(&mut req).await.is_err());

        // Disable the gate: the same login now succeeds.
        let cfg = json!({ "require_machine": false }).as_object().cloned();
        let _ = test_write_api(&core, &root_token, "auth/approle/config", true, cfg).await;

        let mut req = Request::new("auth/approle/login");
        req.operation = Operation::Write;
        req.body = login;
        let resp = core.handle_request(&mut req).await;
        assert!(resp.is_ok());
        assert!(resp.unwrap().unwrap().auth.is_some());
    }

    /// Real end-to-end machine-bound AppRole login driven by the **local MIA
    /// agent**: mints a genuine DPoP-bound FerroGate child token from the
    /// running MIA, logs it into a `ferrogate` mount (root-bootstrap
    /// auto-approve, JWKS + trust domain fetched live via the MIA's CMIS),
    /// binds that machine to an AppRole, and confirms an AppRole login with the
    /// live machine token succeeds and is environment-scoped.
    ///
    /// Self-skipping: if no local MIA agent is reachable (socket absent, or CMIS
    /// unreachable — e.g. off-VPN), the test prints a skip line and returns. Run
    /// with `-- --nocapture` to see whether it ran or skipped. Unix + async only
    /// (the MIA helper client is Unix-domain-socket based).
    #[cfg(all(unix, not(feature = "sync_handler")))]
    #[tokio::test]
    async fn test_approle_login_with_live_mia_machine_token() {
        use std::os::unix::net::UnixStream;

        use crate::modules::credential::ferrogate::mia as ferrogate_mia;
        use ferrogate_mia::DpopKey;

        // ---- Availability gate: skip cleanly when there is no local MIA. ----
        let socket = ferrogate_mia::resolve_mia_socket_for(None);
        if UnixStream::connect(&socket).is_err() {
            eprintln!("skipping test_approle_login_with_live_mia_machine_token: no local MIA agent (socket not connectable at {socket})");
            return;
        }

        let audience = "https://approle-machine-e2e.test".to_string();

        // Derive trust_domain + a live JWKS from the MIA's CMIS. Skip if CMIS is
        // unreachable (off-VPN) or the local allowlist has no trust domain.
        let autoconf = match ferrogate_mia::build_autoconfig(audience.clone(), None).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skipping test_approle_login_with_live_mia_machine_token: MIA autoconfig failed (CMIS unreachable?): {e}");
                return;
            }
        };
        if autoconf.trust_domain.is_empty() || autoconf.fetched_jwks.is_empty() {
            eprintln!("skipping test_approle_login_with_live_mia_machine_token: autoconfig missing trust_domain/JWKS");
            return;
        }

        // Mint a real DPoP-bound child token from the MIA for our audience.
        let dpop = DpopKey::generate();
        let child = match ferrogate_mia::request_child_token(&socket, &audience, &dpop.jkt(), 300) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skipping test_approle_login_with_live_mia_machine_token: MIA token mint failed: {e}");
                return;
            }
        };
        let proof = dpop.proof("POST", &audience);

        // ---- Vault: mount + configure ferrogate with the live JWKS. ----
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_approle_login_with_live_mia_machine_token").await;
        test_mount_auth_api(&core, &root_token, "ferrogate", "ferrogate").await;

        let fcfg = json!({
            "trust_domain": autoconf.trust_domain,
            "expected_audience": audience,
            "jwks_source": "static_jwks",
            "static_jwks": autoconf.fetched_jwks,
            "accept_svid": false,
        })
        .as_object()
        .cloned();
        test_write_api(&core, &root_token, "auth/ferrogate/config", true, fcfg).await.unwrap();

        // FerroGate login: root bootstrap auto-approves the first machine and
        // mints a machine-bound vault token in one shot.
        let mut req = Request::new("auth/ferrogate/login");
        req.operation = Operation::Write;
        req.client_token = root_token.clone();
        req.body = json!({ "token": child.jws, "dpop": proof }).as_object().cloned();
        let resp = core
            .handle_request(&mut req)
            .await
            .expect("ferrogate login request")
            .expect("ferrogate login response");
        let mauth = resp.auth.expect("live MIA child token must mint a ferrogate token");
        let machine_token = mauth.client_token.clone();
        let spiffe_id = mauth.metadata.get("spiffe_id").cloned().unwrap_or_default();
        assert!(!machine_token.is_empty(), "ferrogate login returns a client token");
        assert!(spiffe_id.starts_with("spiffe://"), "machine token carries a spiffe_id: {spiffe_id}");

        // ---- AppRole bound to that machine, with an env-scoped secret id. ----
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;
        test_write_role(&core, &root_token, "approle", "miarole", "mia-role-id", "default", true).await;

        let bind = json!({ "spiffe_id": spiffe_id, "environments": "prod" }).as_object().cloned();
        test_write_api(&core, &root_token, "auth/approle/role/miarole/machine/", true, bind).await.unwrap();

        let gen = json!({ "environments": "prod" }).as_object().cloned();
        let r = test_write_api(&core, &root_token, "auth/approle/role/miarole/secret-id", true, gen)
            .await
            .unwrap()
            .unwrap();
        let secret_id = r.data.unwrap()["secret_id"].as_str().unwrap().to_string();

        // With the live-minted machine token the gated login succeeds and the
        // issued token is environment-scoped (secret-id ∩ machine scope).
        let mut req = Request::new("auth/approle/login");
        req.operation = Operation::Write;
        req.body = json!({
            "role_id": "mia-role-id",
            "secret_id": secret_id,
            "machine_token": machine_token,
        })
        .as_object()
        .cloned();
        let resp = core
            .handle_request(&mut req)
            .await
            .expect("approle login request")
            .expect("approle login response");
        let auth = resp.auth.expect("approle login with a bound machine token mints a token");
        assert_eq!(auth.metadata.get("approle_env_scoped").map(String::as_str), Some("true"));
        assert_eq!(auth.metadata.get("spiffe_id"), Some(&spiffe_id));
        assert!(auth.metadata.get("approle_env_machine").unwrap().contains("prod"));
        assert!(auth.metadata.get("approle_env_secret").unwrap().contains("prod"));

        // Without the machine token the gated login is refused.
        let mut req = Request::new("auth/approle/login");
        req.operation = Operation::Write;
        req.body = json!({ "role_id": "mia-role-id", "secret_id": secret_id }).as_object().cloned();
        assert!(core.handle_request(&mut req).await.is_err(), "gated approle login needs a machine token");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_role_constraints() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_approle_role_constraints").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        // Set bind_secret_id, which is enabled by default
        let mut role_data = json!({
            "role_id": "role-id-123",
            "policies": "a,b",
        })
        .as_object()
        .unwrap()
        .clone();
        let resp =
            test_write_api(&core, &root_token, "auth/approle/role/testrole1", true, Some(role_data.clone())).await;
        assert!(resp.is_ok());

        // Set bound_cidr_list alone by explicitly disabling bind_secret_id
        role_data.insert("bind_secret_id".to_string(), Value::from(false));
        role_data.insert("token_bound_cidrs".to_string(), Value::from("0.0.0.0/0"));
        let resp =
            test_write_api(&core, &root_token, "auth/approle/role/testrole1", true, Some(role_data.clone())).await;
        assert!(resp.is_ok());

        // Remove both constraints
        role_data["bind_secret_id"] = Value::from(false);
        role_data["token_bound_cidrs"] = Value::from("");
        let resp =
            test_write_api(&core, &root_token, "auth/approle/role/testrole1", false, Some(role_data.clone())).await;
        assert!(resp.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_update_role_id() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_approle_update_role_id").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        test_write_role(&core, &root_token, "approle", "testrole1", "role-id-123", "a,b", true).await;

        let role_id_data = json!({
            "role_id": "customroleid",
        })
        .as_object()
        .cloned();
        let resp = test_write_api(&core, &root_token, "auth/approle/role/testrole1/role-id", true, role_id_data).await;
        assert!(resp.is_ok());

        let resp = test_write_api(&core, &root_token, "auth/approle/role/testrole1/secret-id", true, None).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        let secret_id = resp_data["secret_id"].as_str().unwrap();

        // Login should fail
        let _ = test_login(&core, "approle", "role-id-123", secret_id, false).await;

        // Login should pass
        let _ = test_login(&core, "approle", "customroleid", secret_id, true).await;
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_role_id_uniqueness() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_approle_role_id_uniqueness").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        test_write_role(&core, &root_token, "approle", "testrole1", "role-id-123", "a,b", true).await;

        test_write_role(&core, &root_token, "approle", "testrole2", "role-id-123", "a,b", false).await;

        test_write_role(&core, &root_token, "approle", "testrole2", "role-id-456", "a,b", true).await;

        test_write_role(&core, &root_token, "approle", "testrole2", "role-id-123", "a,b", false).await;

        test_write_role(&core, &root_token, "approle", "testrole1", "role-id-456", "a,b", false).await;

        let mut role_id_data = json!({
            "role_id": "role-id-456",
        })
        .as_object()
        .unwrap()
        .clone();
        let resp = test_write_api(
            &core,
            &root_token,
            "auth/approle/role/testrole1/role-id",
            false,
            Some(role_id_data.clone()),
        )
        .await;
        assert!(resp.is_err());

        role_id_data["role_id"] = Value::from("role-id-123");
        let resp = test_write_api(
            &core,
            &root_token,
            "auth/approle/role/testrole2/role-id",
            false,
            Some(role_id_data.clone()),
        )
        .await;
        assert!(resp.is_err());

        role_id_data["role_id"] = Value::from("role-id-2000");
        let resp =
            test_write_api(&core, &root_token, "auth/approle/role/testrole2/role-id", true, Some(role_id_data.clone()))
                .await;
        assert!(resp.is_ok());

        role_id_data["role_id"] = Value::from("role-id-1000");
        let resp =
            test_write_api(&core, &root_token, "auth/approle/role/testrole1/role-id", true, Some(role_id_data.clone()))
                .await;
        assert!(resp.is_ok());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_role_delete_secret_id() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_approle_role_delete_secret_id").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        test_write_role(&core, &root_token, "approle", "role1", "", "a,b", true).await;

        let _ = generate_secret_id(&core, &root_token, "approle", "role1").await;
        let _ = generate_secret_id(&core, &root_token, "approle", "role1").await;
        let _ = generate_secret_id(&core, &root_token, "approle", "role1").await;

        let resp = test_list_api(&core, &root_token, "auth/approle/role/role1/secret-id", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        let keys = resp_data["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 3);

        test_delete_role(&core, &root_token, "approle", "role1").await;
        let _ = test_list_api(&core, &root_token, "auth/approle/role/role1/secret-id", false).await;
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_lookup_and_destroy_role_secret_id() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_approle_lookup_and_destroy_role_secret_id").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        test_write_role(&core, &root_token, "approle", "role1", "", "a,b", true).await;

        let (secret_id, _) = generate_secret_id(&core, &root_token, "approle", "role1").await;

        let secret_id_data = json!({
            "secret_id": secret_id,
        })
        .as_object()
        .cloned();
        let resp = test_write_api(
            &core,
            &root_token,
            "auth/approle/role/role1/secret-id/lookup",
            true,
            secret_id_data.clone(),
        )
        .await;
        assert!(resp.unwrap().unwrap().data.is_some());

        let _ = test_delete_api(
            &core,
            &root_token,
            "auth/approle/role/role1/secret-id/destroy",
            true,
            secret_id_data.clone(),
        )
        .await;
        let resp =
            test_write_api(&core, &root_token, "auth/approle/role/role1/secret-id/lookup", true, secret_id_data).await;
        assert!(resp.unwrap().is_none());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_lookup_and_destroy_role_secret_id_accessor() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_approle_lookup_and_destroy_role_secret_id_accessor").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        test_write_role(&core, &root_token, "approle", "role1", "", "a,b", true).await;

        let _ = generate_secret_id(&core, &root_token, "approle", "role1").await;

        let resp = test_list_api(&core, &root_token, "auth/approle/role/role1/secret-id", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        let keys = resp_data["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);

        let hmac_secret_id = keys[0].as_str().unwrap();
        let hmac_data = json!({
            "secret_id_accessor": hmac_secret_id,
        })
        .as_object()
        .cloned();
        let resp = test_write_api(
            &core,
            &root_token,
            "auth/approle/role/role1/secret-id-accessor/lookup",
            true,
            hmac_data.clone(),
        )
        .await;
        assert!(resp.unwrap().unwrap().data.is_some());

        let _ = test_delete_api(
            &core,
            &root_token,
            "auth/approle/role/role1/secret-id-accessor/destroy",
            true,
            hmac_data.clone(),
        )
        .await;
        let _ =
            test_write_api(&core, &root_token, "auth/approle/role/role1/secret-id-accessor/lookup", false, hmac_data)
                .await;
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_lookup_role_secret_id_accessor() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_approle_lookup_role_secret_id_accessor").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        test_write_role(&core, &root_token, "approle", "role1", "", "a,b", true).await;

        let hmac_data = json!({
            "secret_id_accessor": "invalid",
        })
        .as_object()
        .cloned();
        let _resp =
            test_write_api(&core, &root_token, "auth/approle/role/role1/secret-id-accessor/lookup", false, hmac_data)
                .await;
        // TODO: resp should ok
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_list_role_secret_id() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_approle_list_role_secret_id").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        test_write_role(&core, &root_token, "approle", "role1", "", "a,b", true).await;

        // Create 5 'secret_id's
        let _ = generate_secret_id(&core, &root_token, "approle", "role1").await;
        let _ = generate_secret_id(&core, &root_token, "approle", "role1").await;
        let _ = generate_secret_id(&core, &root_token, "approle", "role1").await;
        let _ = generate_secret_id(&core, &root_token, "approle", "role1").await;
        let _ = generate_secret_id(&core, &root_token, "approle", "role1").await;

        let resp = test_list_api(&core, &root_token, "auth/approle/role/role1/secret-id/", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        let keys = resp_data["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 5);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_list_role() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_approle_list_role").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        test_write_role(&core, &root_token, "approle", "role1", "", "a,b", true).await;
        test_write_role(&core, &root_token, "approle", "role2", "", "c,d", true).await;
        test_write_role(&core, &root_token, "approle", "role3", "", "e,f", true).await;
        test_write_role(&core, &root_token, "approle", "role4", "", "g,h", true).await;
        test_write_role(&core, &root_token, "approle", "role5", "", "i,j", true).await;

        let resp = test_list_api(&core, &root_token, "auth/approle/role", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        let mut keys = resp_data["keys"].as_array().unwrap().clone();
        keys.sort_by(|a, b| a.as_str().unwrap_or("").cmp(b.as_str().unwrap_or("")));
        assert_eq!(keys.len(), 5);
        let expect = json!(["role1", "role2", "role3", "role4", "role5"]);
        assert_eq!(expect.as_array().unwrap().clone(), keys);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_role_secret_id_without_fields() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_approle_role_secret_id_without_fields").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        let role_data = json!({
            "policies": "p,q,r,s",
            "secret_id_num_uses": 10,
            "secret_id_ttl":      300,
            "token_ttl":          400,
            "token_max_ttl":      500,
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(&core, &root_token, "auth/approle/role/role1", true, Some(role_data.clone())).await;

        let resp = test_write_api(&core, &root_token, "auth/approle/role/role1/secret-id", true, None).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        let secret_id = resp_data["secret_id"].as_str().unwrap();
        let secret_id_ttl = resp_data["secret_id_ttl"].as_int().unwrap();
        let secret_id_num_uses = resp_data["secret_id_num_uses"].as_int().unwrap();
        assert_ne!(secret_id, "");
        assert_eq!(secret_id_ttl, role_data["secret_id_ttl"].as_int().unwrap());
        assert_eq!(secret_id_num_uses, role_data["secret_id_num_uses"].as_int().unwrap());

        let secret_id_data = json!({
            "secret_id": "abcd123",
        })
        .as_object()
        .unwrap()
        .clone();
        let resp = test_write_api(
            &core,
            &root_token,
            "auth/approle/role/role1/custom-secret-id",
            true,
            Some(secret_id_data.clone()),
        )
        .await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        let secret_id = resp_data["secret_id"].as_str().unwrap();
        let secret_id_ttl = resp_data["secret_id_ttl"].as_int().unwrap();
        let secret_id_num_uses = resp_data["secret_id_num_uses"].as_int().unwrap();
        assert_eq!(secret_id, secret_id_data["secret_id"].as_str().unwrap());
        assert_eq!(secret_id_ttl, role_data["secret_id_ttl"].as_int().unwrap());
        assert_eq!(secret_id_num_uses, role_data["secret_id_num_uses"].as_int().unwrap());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_role_secret_id_with_valid_fields() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_approle_role_secret_id_with_valid_fields").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        let role_data = json!({
            "policies": "p,q,r,s",
            "secret_id_num_uses": 0,
            "secret_id_ttl":      0,
            "token_ttl":          400,
            "token_max_ttl":      500,
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &root_token, "auth/approle/role/role1", true, role_data).await;

        let cases = [json!({"name": "finite num_uses and ttl", "payload": {"secret_id": "finite", "ttl": 5, "num_uses": 5}}),
            json!({"name": "infinite num_uses and ttl", "payload": {"secret_id": "infinite", "ttl": 0, "num_uses": 0}}),
            json!({"name": "finite num_uses and infinite ttl", "payload": {"secret_id": "maxed1", "ttl": 0, "num_uses": 5}}),
            json!({"name": "infinite num_uses and finite ttl", "payload": {"secret_id": "maxed2", "ttl": 5, "num_uses": 0}})];

        for case in cases.iter() {
            let secret_id_data = case["payload"].as_object().unwrap().clone();
            let resp = test_write_api(
                &core,
                &root_token,
                "auth/approle/role/role1/secret-id",
                true,
                Some(secret_id_data.clone()),
            )
            .await;
            assert!(resp.is_ok());
            let resp_data = resp.unwrap().unwrap().data.unwrap();
            let secret_id = resp_data["secret_id"].as_str().unwrap();
            let secret_id_ttl = resp_data["secret_id_ttl"].as_int().unwrap();
            let secret_id_num_uses = resp_data["secret_id_num_uses"].as_int().unwrap();
            assert_ne!(secret_id, "");
            assert_eq!(secret_id_ttl, secret_id_data["ttl"].as_int().unwrap());
            assert_eq!(secret_id_num_uses, secret_id_data["num_uses"].as_int().unwrap());

            let resp = test_write_api(
                &core,
                &root_token,
                "auth/approle/role/role1/custom-secret-id",
                true,
                Some(secret_id_data.clone()),
            )
            .await;
            assert!(resp.is_ok());
            let resp_data = resp.unwrap().unwrap().data.unwrap();
            let secret_id = resp_data["secret_id"].as_str().unwrap();
            let secret_id_ttl = resp_data["secret_id_ttl"].as_int().unwrap();
            let secret_id_num_uses = resp_data["secret_id_num_uses"].as_int().unwrap();
            assert_eq!(secret_id, secret_id_data["secret_id"].as_str().unwrap());
            assert_eq!(secret_id_ttl, secret_id_data["ttl"].as_int().unwrap());
            assert_eq!(secret_id_num_uses, secret_id_data["num_uses"].as_int().unwrap());
        }
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_role_secret_id_with_invalid_fields() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_approle_role_secret_id_with_invalid_fields").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        let cases = [json!({
                "name": "infinite role secret id ttl",
                "options": {
                    "secret_id_num_uses": 1,
                    "secret_id_ttl": 0,
                },
                "cases": [{
                    "name": "higher num_uses",
                    "payload": {"secret_id": "abcd123", "ttl": 0, "num_uses": 2},
                    "expected": "num_uses cannot be higher than the role's secret_id_num_uses",
                }],
            }),
            json!({
                "name": "infinite role num_uses",
                "options": {
                    "secret_id_num_uses": 0,
                    "secret_id_ttl": 1,
                },
                "cases": [{
                    "name": "longer ttl",
                    "payload": {"secret_id": "abcd123", "ttl": 2, "num_uses": 0},
                    "expected": "ttl cannot be longer than the role's secret_id_ttl",
                }],
            }),
            json!({
                "name": "finite role ttl and num_uses",
                "options": {
                    "secret_id_num_uses": 2,
                    "secret_id_ttl": 2,
                },
                "cases": [{
                    "name": "infinite ttl",
                    "payload": {"secret_id": "abcd123", "ttl": 0, "num_uses": 1},
                    "expected": "ttl cannot be longer than the role's secret_id_ttl",
                },
                {
                    "name": "infinite num_uses",
                    "payload": {"secret_id": "abcd123", "ttl": 1, "num_uses": 0},
                    "expected": "num_uses cannot be higher than the role's secret_id_num_uses",
                }],
            }),
            json!({
                "name": "mixed role ttl and num_uses",
                "options": {
                    "secret_id_num_uses": 400,
                    "secret_id_ttl": 500,
                },
                "cases": [{
                    "name": "negative num_uses",
                    "payload": {"secret_id": "abcd123", "ttl": 0, "num_uses": -1},
                    "expected": "num_uses cannot be negative",
                }],
            })];

        for (i, case) in cases.iter().enumerate() {
            let mut role_data = json!({
                "policies": "p,q,r,s",
                "secret_id_num_uses": 0,
                "secret_id_ttl":      0,
                "token_ttl":          400,
                "token_max_ttl":      500,
            })
            .as_object()
            .unwrap()
            .clone();
            role_data["secret_id_num_uses"] = case["options"]["secret_id_num_uses"].clone();
            role_data["secret_id_ttl"] = case["options"]["secret_id_ttl"].clone();
            let _ = test_write_api(
                &core,
                &root_token,
                format!("auth/approle/role/role{}", i).as_str(),
                true,
                Some(role_data.clone()),
            )
            .await;

            for tc in case["cases"].as_array().unwrap().iter() {
                let secret_id_data = tc["payload"].as_object().unwrap().clone();
                let resp = test_write_api(
                    &core,
                    &root_token,
                    format!("auth/approle/role/role{}/secret-id", i).as_str(),
                    false,
                    Some(secret_id_data.clone()),
                )
                .await;
                if let Err(RvError::ErrResponse(err_text)) = resp {
                    assert_eq!(err_text, tc["expected"].as_str().unwrap());
                }
                let resp = test_write_api(
                    &core,
                    &root_token,
                    format!("auth/approle/role/role{}/custom-secret-id", i).as_str(),
                    false,
                    Some(secret_id_data.clone()),
                )
                .await;
                if let Err(RvError::ErrResponse(err_text)) = resp {
                    assert_eq!(err_text, tc["expected"].as_str().unwrap());
                }
            }
        }
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_role_crud() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_approle_role_crud").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        let req_data = json!({
            "policies": "p,q,r,s",
            "secret_id_num_uses": 10,
            "secret_id_ttl":      300,
            "token_ttl":          400,
            "token_max_ttl":      500,
            "token_num_uses":     600,
            "secret_id_bound_cidrs": "127.0.0.1/32,127.0.0.1/16",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &root_token, "auth/approle/role/role1", true, req_data).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1", true).await;
        let resp_data = resp.unwrap().unwrap().data.unwrap();

        let expected = json!({
            "bind_secret_id":        true,
            "local_secret_ids":      false,
            "policies":              ["p", "q", "r", "s"],
            "secret_id_num_uses":    10,
            "secret_id_ttl":         300,
            "token_ttl":             400,
            "token_max_ttl":         500,
            "token_num_uses":        600,
            "token_no_default_policy": false,
            "secret_id_bound_cidrs": ["127.0.0.1/32", "127.0.0.1/16"],
            "token_period":          0,
            "token_explicit_max_ttl":0,
            "token_bound_cidrs":     [],
            "token_policies":        ["p", "q", "r", "s"],
            "token_type":            "default",
        });
        assert_eq!(expected.as_object().unwrap().clone(), resp_data);

        let req_data = json!({
            "role_id": "test_role_id",
            "policies": "a,b,c,d",
            "secret_id_num_uses": 100,
            "secret_id_ttl":      3000,
            "token_ttl":          4000,
            "token_max_ttl":      5000,
            "period":      "5m",
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(&core, &root_token, "auth/approle/role/role1", true, Some(req_data.clone())).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1", true).await;
        let resp_data = resp.unwrap().unwrap().data.unwrap();

        let expected = json!({
            "bind_secret_id":        true,
            "local_secret_ids":      false,
            "policies":              ["a", "b", "c", "d"],
            "secret_id_num_uses":    100,
            "secret_id_ttl":         3000,
            "token_ttl":             4000,
            "token_max_ttl":         5000,
            "token_num_uses":        600,
            "token_no_default_policy": false,
            "secret_id_bound_cidrs": ["127.0.0.1/32", "127.0.0.1/16"],
            "period":                300,
            "token_period":          300,
            "token_explicit_max_ttl":0,
            "token_bound_cidrs":     [],
            "token_policies":        ["a", "b", "c", "d"],
            "token_type":            "default",
        });
        assert_eq!(expected.as_object().unwrap().clone(), resp_data);

        // RU for role_id field
        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/role-id", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        let role_id = resp_data["role_id"].as_str().unwrap();
        assert_eq!(role_id, req_data["role_id"].as_str().unwrap());

        let req_data = json!({
            "role_id": "custom_role_id",
        })
        .as_object()
        .unwrap()
        .clone();
        let _ =
            test_write_api(&core, &root_token, "auth/approle/role/role1/role-id", true, Some(req_data.clone())).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/role-id", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["role_id"].as_str().unwrap(), req_data["role_id"].as_str().unwrap());

        // RUD for bind_secret_id field
        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/bind-secret-id", true).await;
        assert!(resp.is_ok());

        let req_data = json!({
            "bind_secret_id": false,
        })
        .as_object()
        .unwrap()
        .clone();
        let _ =
            test_write_api(&core, &root_token, "auth/approle/role/role1/bind-secret-id", true, Some(req_data.clone()))
                .await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/bind-secret-id", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["bind_secret_id"].as_bool().unwrap(), req_data["bind_secret_id"].as_bool().unwrap());

        let _ = test_delete_api(&core, &root_token, "auth/approle/role/role1/bind-secret-id", true, None).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/bind-secret-id", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert!(resp_data["bind_secret_id"].as_bool().unwrap());

        // RUD for policies field
        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/policies", true).await;
        assert!(resp.is_ok());

        let req_data = json!({
            "policies": "a1,b1,c1,d1",
        })
        .as_object()
        .unwrap()
        .clone();
        let _ =
            test_write_api(&core, &root_token, "auth/approle/role/role1/policies", true, Some(req_data.clone())).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/policies", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(
            resp_data["policies"].as_comma_string_slice().unwrap(),
            req_data["policies"].as_comma_string_slice().unwrap()
        );
        assert_eq!(
            resp_data["token_policies"].as_comma_string_slice().unwrap(),
            req_data["policies"].as_comma_string_slice().unwrap()
        );

        let _ = test_delete_api(&core, &root_token, "auth/approle/role/role1/policies", true, None).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/policies", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["token_policies"].as_comma_string_slice().unwrap().len(), 0);

        // RUD for secret-id-num-uses field
        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/secret-id-num-uses", true).await;
        assert!(resp.is_ok());

        let req_data = json!({
            "secret_id_num_uses": 200,
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(
            &core,
            &root_token,
            "auth/approle/role/role1/secret-id-num-uses",
            true,
            Some(req_data.clone()),
        )
        .await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/secret-id-num-uses", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["secret_id_num_uses"].as_int().unwrap(), req_data["secret_id_num_uses"].as_int().unwrap());

        let _ = test_delete_api(&core, &root_token, "auth/approle/role/role1/secret-id-num-uses", true, None).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/secret-id-num-uses", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["secret_id_num_uses"].as_int().unwrap(), 0);

        // RUD for secret_id_ttl field
        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/secret-id-ttl", true).await;
        assert!(resp.is_ok());

        let req_data = json!({
            "secret_id_ttl": 3001,
        })
        .as_object()
        .unwrap()
        .clone();
        let _ =
            test_write_api(&core, &root_token, "auth/approle/role/role1/secret-id-ttl", true, Some(req_data.clone()))
                .await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/secret-id-ttl", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["secret_id_ttl"].as_int().unwrap(), req_data["secret_id_ttl"].as_int().unwrap());

        let _ = test_delete_api(&core, &root_token, "auth/approle/role/role1/secret-id-ttl", true, None).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/secret-id-ttl", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["secret_id_ttl"].as_int().unwrap(), 0);

        // RUD for token-num-uses field
        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/token-num-uses", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["token_num_uses"].as_int().unwrap(), 600);

        let req_data = json!({
            "token_num_uses": 60,
        })
        .as_object()
        .unwrap()
        .clone();
        let _ =
            test_write_api(&core, &root_token, "auth/approle/role/role1/token-num-uses", true, Some(req_data.clone()))
                .await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/token-num-uses", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["token_num_uses"].as_int().unwrap(), req_data["token_num_uses"].as_int().unwrap());

        let _ = test_delete_api(&core, &root_token, "auth/approle/role/role1/token-num-uses", true, None).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/token-num-uses", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["token_num_uses"].as_int().unwrap(), 0);

        // RUD for period field
        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/period", true).await;
        assert!(resp.is_ok());

        let req_data = json!({
            "period": 9001,
        })
        .as_object()
        .unwrap()
        .clone();
        let _ =
            test_write_api(&core, &root_token, "auth/approle/role/role1/period", true, Some(req_data.clone())).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/period", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["period"].as_int().unwrap(), req_data["period"].as_int().unwrap());

        let _ = test_delete_api(&core, &root_token, "auth/approle/role/role1/period", true, None).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/period", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["token_period"].as_int().unwrap(), 0);

        // RUD for token_ttl field
        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/token-ttl", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["token_ttl"].as_int().unwrap(), 4000);

        let req_data = json!({
            "token_ttl": 4001,
        })
        .as_object()
        .unwrap()
        .clone();
        let _ =
            test_write_api(&core, &root_token, "auth/approle/role/role1/token-ttl", true, Some(req_data.clone())).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/token-ttl", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["token_ttl"].as_int().unwrap(), req_data["token_ttl"].as_int().unwrap());

        let _ = test_delete_api(&core, &root_token, "auth/approle/role/role1/token-ttl", true, None).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/token-ttl", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["token_ttl"].as_int().unwrap(), 0);

        // RUD for token_max_ttl field
        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/token-max-ttl", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["token_max_ttl"].as_int().unwrap(), 5000);

        let req_data = json!({
            "token_max_ttl": 5001,
        })
        .as_object()
        .unwrap()
        .clone();
        let _ =
            test_write_api(&core, &root_token, "auth/approle/role/role1/token-max-ttl", true, Some(req_data.clone()))
                .await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/token-max-ttl", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["token_max_ttl"].as_int().unwrap(), req_data["token_max_ttl"].as_int().unwrap());

        let _ = test_delete_api(&core, &root_token, "auth/approle/role/role1/token-max-ttl", true, None).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/token-max-ttl", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["token_max_ttl"].as_int().unwrap(), 0);

        // Delete test for role
        test_delete_role(&core, &root_token, "approle", "role1").await;
        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1", true).await;
        assert!(resp.unwrap().is_none());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_role_token_bound_cidrs_crud() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_approle_role_token_bound_cidrs_crud").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        let req_data = json!({
            "policies": "p,q,r,s",
            "secret_id_num_uses": 10,
            "secret_id_ttl":      300,
            "token_ttl":          400,
            "token_max_ttl":      500,
            "token_num_uses":     600,
            "secret_id_bound_cidrs": "127.0.0.1/32,127.0.0.1/16",
            "token_bound_cidrs":     "127.0.0.1/32,127.0.0.1/16",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &root_token, "auth/approle/role/role1", true, req_data).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1", true).await;
        let resp_data = resp.unwrap().unwrap().data.unwrap();

        let expected = json!({
            "bind_secret_id":        true,
            "local_secret_ids":      false,
            "policies":              ["p", "q", "r", "s"],
            "secret_id_num_uses":    10,
            "secret_id_ttl":         300,
            "token_ttl":             400,
            "token_max_ttl":         500,
            "token_num_uses":        600,
            "token_no_default_policy": false,
            "secret_id_bound_cidrs": ["127.0.0.1/32", "127.0.0.1/16"],
            "token_bound_cidrs":     ["127.0.0.1", "127.0.0.1/16"],
            "token_period":          0,
            "token_explicit_max_ttl":0,
            "token_policies":        ["p", "q", "r", "s"],
            "token_type":            "default",
        });
        assert_eq!(expected.as_object().unwrap().clone(), resp_data);

        let req_data = json!({
            "role_id": "test_role_id",
            "policies": "a,b,c,d",
            "secret_id_num_uses": 100,
            "secret_id_ttl":      3000,
            "token_ttl":          4000,
            "token_max_ttl":      5000,
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &root_token, "auth/approle/role/role1", true, req_data).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1", true).await;
        let resp_data = resp.unwrap().unwrap().data.unwrap();

        let expected = json!({
            "bind_secret_id":        true,
            "local_secret_ids":      false,
            "policies":              ["a", "b", "c", "d"],
            "secret_id_num_uses":    100,
            "secret_id_ttl":         3000,
            "token_ttl":             4000,
            "token_max_ttl":         5000,
            "token_num_uses":        600,
            "token_no_default_policy": false,
            "secret_id_bound_cidrs": ["127.0.0.1/32", "127.0.0.1/16"],
            "token_period":          0,
            "token_explicit_max_ttl":0,
            "token_bound_cidrs":     ["127.0.0.1", "127.0.0.1/16"],
            "token_policies":        ["a", "b", "c", "d"],
            "token_type":            "default",
        });
        assert_eq!(expected.as_object().unwrap().clone(), resp_data);

        // RUD for secret-id-bound-cidrs field
        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/secret-id-bound-cidrs", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(
            resp_data["secret_id_bound_cidrs"].as_comma_string_slice().unwrap(),
            expected["secret_id_bound_cidrs"].as_comma_string_slice().unwrap()
        );

        let req_data = json!({
            "secret_id_bound_cidrs": ["127.0.0.1/20"],
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(
            &core,
            &root_token,
            "auth/approle/role/role1/secret-id-bound-cidrs",
            true,
            Some(req_data.clone()),
        )
        .await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/secret-id-bound-cidrs", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(
            resp_data["secret_id_bound_cidrs"].as_comma_string_slice().unwrap(),
            req_data["secret_id_bound_cidrs"].as_comma_string_slice().unwrap()
        );

        let _ = test_delete_api(&core, &root_token, "auth/approle/role/role1/secret-id-bound-cidrs", true, None).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/secret-id-bound-cidrs", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["secret_id_bound_cidrs"].as_comma_string_slice().unwrap().len(), 0);

        // RUD for token-bound-cidrs field
        let expected = json!({
            "token_bound_cidrs":     ["127.0.0.1", "127.0.0.1/16"],
        });
        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/token-bound-cidrs", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(
            resp_data["token_bound_cidrs"].as_comma_string_slice().unwrap(),
            expected["token_bound_cidrs"].as_comma_string_slice().unwrap()
        );

        let req_data = json!({
            "token_bound_cidrs": ["127.0.0.1/20"],
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(
            &core,
            &root_token,
            "auth/approle/role/role1/token-bound-cidrs",
            true,
            Some(req_data.clone()),
        )
        .await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/token-bound-cidrs", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(
            resp_data["token_bound_cidrs"].as_comma_string_slice().unwrap(),
            req_data["token_bound_cidrs"].as_comma_string_slice().unwrap()
        );

        let _ = test_delete_api(&core, &root_token, "auth/approle/role/role1/token-bound-cidrs", true, None).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1/token-bound-cidrs", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["token_bound_cidrs"].as_comma_string_slice().unwrap().len(), 0);

        // Delete test for role
        test_delete_role(&core, &root_token, "approle", "role1").await;
        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1", true).await;
        assert!(resp.unwrap().is_none());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_role_token_type_crud() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_approle_role_token_type_crud").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        let req_data = json!({
            "policies": "p,q,r,s",
            "secret_id_num_uses": 10,
            "secret_id_ttl":      300,
            "token_ttl":          400,
            "token_max_ttl":      500,
            "token_num_uses":     600,
            "token_type":         "default-service",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &root_token, "auth/approle/role/role1", true, req_data).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1", true).await;
        let resp_data = resp.unwrap().unwrap().data.unwrap();

        let expected = json!({
            "bind_secret_id":        true,
            "local_secret_ids":      false,
            "policies":              ["p", "q", "r", "s"],
            "secret_id_num_uses":    10,
            "secret_id_ttl":         300,
            "token_ttl":             400,
            "token_max_ttl":         500,
            "token_num_uses":        600,
            "token_no_default_policy": false,
            "secret_id_bound_cidrs": [],
            "token_bound_cidrs":     [],
            "token_period":          0,
            "token_explicit_max_ttl":0,
            "token_policies":        ["p", "q", "r", "s"],
            "token_type":            "service",
        });
        assert_eq!(expected.as_object().unwrap().clone(), resp_data);

        let req_data = json!({
            "role_id": "test_role_id",
            "policies": "a,b,c,d",
            "secret_id_num_uses": 100,
            "secret_id_ttl":      3000,
            "token_ttl":          4000,
            "token_max_ttl":      5000,
            "token_type":         "default-service",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &root_token, "auth/approle/role/role1", true, req_data).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1", true).await;
        let resp_data = resp.unwrap().unwrap().data.unwrap();

        let expected = json!({
            "bind_secret_id":        true,
            "local_secret_ids":      false,
            "policies":              ["a", "b", "c", "d"],
            "secret_id_num_uses":    100,
            "secret_id_ttl":         3000,
            "token_ttl":             4000,
            "token_max_ttl":         5000,
            "token_num_uses":        600,
            "token_no_default_policy": false,
            "secret_id_bound_cidrs": [],
            "token_period":          0,
            "token_explicit_max_ttl":0,
            "token_bound_cidrs":     [],
            "token_policies":        ["a", "b", "c", "d"],
            "token_type":            "service",
        });
        assert_eq!(expected.as_object().unwrap().clone(), resp_data);

        // Delete test for role
        test_delete_role(&core, &root_token, "approle", "role1").await;
        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1", true).await;
        assert!(resp.unwrap().is_none());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_role_token_util_upgrade() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_approle_role_token_util_upgrade").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        // token_type missing
        let req_data = json!({
            "policies": "p,q,r,s",
            "secret_id_num_uses": 10,
            "secret_id_ttl":      300,
            "token_ttl":          400,
            "token_max_ttl":      500,
            "token_num_uses":     600,
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &root_token, "auth/approle/role/role1", true, req_data).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1", true).await;
        let resp_data = resp.unwrap().unwrap().data.unwrap();

        let expected = json!({
            "bind_secret_id":        true,
            "local_secret_ids":      false,
            "policies":              ["p", "q", "r", "s"],
            "secret_id_num_uses":    10,
            "secret_id_ttl":         300,
            "token_ttl":             400,
            "token_max_ttl":         500,
            "token_num_uses":        600,
            "token_no_default_policy": false,
            "secret_id_bound_cidrs": [],
            "token_bound_cidrs":     [],
            "token_period":          0,
            "token_explicit_max_ttl":0,
            "token_policies":        ["p", "q", "r", "s"],
            "token_type":            "default",
        });
        assert_eq!(expected.as_object().unwrap().clone(), resp_data);

        // token_type empty
        let req_data = json!({
            "role_id": "test_role_id",
            "policies": "a,b,c,d",
            "secret_id_num_uses": 100,
            "secret_id_ttl":      3000,
            "token_ttl":          4000,
            "token_max_ttl":      5000,
            "token_type":         "",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &root_token, "auth/approle/role/role1", true, req_data).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1", true).await;
        let resp_data = resp.unwrap().unwrap().data.unwrap();

        let expected = json!({
            "bind_secret_id":        true,
            "local_secret_ids":      false,
            "policies":              ["a", "b", "c", "d"],
            "secret_id_num_uses":    100,
            "secret_id_ttl":         3000,
            "token_ttl":             4000,
            "token_max_ttl":         5000,
            "token_num_uses":        600,
            "token_no_default_policy": false,
            "secret_id_bound_cidrs": [],
            "token_period":          0,
            "token_explicit_max_ttl":0,
            "token_bound_cidrs":     [],
            "token_policies":        ["a", "b", "c", "d"],
            "token_type":            "default",
        });
        assert_eq!(expected.as_object().unwrap().clone(), resp_data);

        // token_type service
        let req_data = json!({
            "role_id": "test_role_id",
            "policies": "a,b,c,d",
            "secret_id_num_uses": 100,
            "secret_id_ttl":      3000,
            "token_ttl":          4000,
            "token_max_ttl":      5000,
            "token_type":         "service",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &root_token, "auth/approle/role/role1", true, req_data).await;

        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1", true).await;
        let resp_data = resp.unwrap().unwrap().data.unwrap();

        let expected = json!({
            "bind_secret_id":        true,
            "local_secret_ids":      false,
            "policies":              ["a", "b", "c", "d"],
            "secret_id_num_uses":    100,
            "secret_id_ttl":         3000,
            "token_ttl":             4000,
            "token_max_ttl":         5000,
            "token_num_uses":        600,
            "token_no_default_policy": false,
            "secret_id_bound_cidrs": [],
            "token_period":          0,
            "token_explicit_max_ttl":0,
            "token_bound_cidrs":     [],
            "token_policies":        ["a", "b", "c", "d"],
            "token_type":            "service",
        });
        assert_eq!(expected.as_object().unwrap().clone(), resp_data);

        // Delete test for role
        test_delete_role(&core, &root_token, "approle", "role1").await;
        let resp = test_read_api(&core, &root_token, "auth/approle/role/role1", true).await;
        assert!(resp.unwrap().is_none());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_role_secret_id_with_ttl() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_approle_role_secret_id_with_ttl").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        let mut role_data = json!({
            "policies": "default",
            "secret_id_ttl":      0,
        })
        .as_object()
        .unwrap()
        .clone();

        let cases = [json!({"name": "zero ttl", "role_name": "role-zero-ttl", "ttl": 0, "sys_ttl_cap": false}),
            json!({"name": "custom ttl", "role_name": "role-custom-ttl", "ttl": 60, "sys_ttl_cap": false}),
            json!({"name": "system ttl capped", "role_name": "role-sys-ttl-cap", "ttl": 700000000, "sys_ttl_cap": true})];

        for case in cases.iter() {
            let role_name = case["role_name"].as_str().unwrap();
            role_data["secret_id_ttl"] = case["ttl"].clone();
            let _ = test_write_api(
                &core,
                &root_token,
                format!("auth/approle/role/{}", role_name).as_str(),
                true,
                Some(role_data.clone()),
            )
            .await;

            let resp = test_write_api(
                &core,
                &root_token,
                format!("auth/approle/role/{}/secret-id", role_name).as_str(),
                true,
                None,
            )
            .await;
            assert!(resp.is_ok());
            let resp_data = resp.unwrap().unwrap().data.unwrap();
            let secret_id_ttl = resp_data["secret_id_ttl"].as_duration().unwrap();
            if case["sys_ttl_cap"].as_bool().unwrap() {
                assert_eq!(secret_id_ttl, MAX_LEASE_DURATION_SECS);
            } else {
                assert_eq!(secret_id_ttl, case["ttl"].as_duration().unwrap());
            }
        }
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_approle_role_secret_id_accessor_cross_delete() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_approle_role_secret_id_accessor_cross_delete").await;

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&core, &root_token, "approle", "approle").await;

        // Create First Role
        test_write_role(&core, &root_token, "approle", "role1", "", "a,b", true).await;
        let _ = generate_secret_id(&core, &root_token, "approle", "role1").await;

        // Create Second Role
        test_write_role(&core, &root_token, "approle", "role2", "", "a,b", true).await;
        let _ = generate_secret_id(&core, &root_token, "approle", "role2").await;

        // Get role2 secretID Accessor
        let resp = test_list_api(&core, &root_token, "auth/approle/role/role2/secret-id", true).await;
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        let keys = resp_data["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);

        // Attempt to destroy role2 secretID accessor using role1 path

        let hmac_secret_id = keys[0].as_str().unwrap();
        let hmac_data = json!({
            "secret_id_accessor": hmac_secret_id,
        })
        .as_object()
        .cloned();
        let _ =
            test_delete_api(&core, &root_token, "auth/approle/role/role1/secret-id-accessor/destroy", false, hmac_data)
                .await;
    }
}
/// Was `#[cfg(test)] mod test` in `path_tidy_secret_id.rs`.
mod path_tidy_secret_id_test {
    use crate::kernel_api::VaultCtx;
    use std::{
        default::Default,
        sync::{Arc, Mutex},
        thread,
        time::{Duration, Instant},
    };

    use std::sync::atomic::Ordering;

    use crate::logical::Backend;
    use crate::modules::credential::approle::validation::SecretIdAccessorStorageEntry;
    use crate::modules::credential::approle::{path_role::RoleEntry, AppRoleModule, SECRET_ID_PREFIX};
    use crate::{
        logical::{Operation, Request},
        storage::{Storage, StorageEntry},
        test_utils::{new_unseal_test_bastion_vault, test_mount_auth_api},
    };

    #[actix_rt::test]
    async fn test_approle_tidy_dangling_accessors_normal() {
        #[cfg(feature = "sync_handler")]
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_approle_tidy_dangling_accessors_normal");
        #[cfg(not(feature = "sync_handler"))]
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_approle_tidy_dangling_accessors_normal").await;

        // Mount approle auth to path: auth/approle
        #[cfg(feature = "sync_handler")]
        test_mount_auth_api(&core, &root_token, "approle", "approle/");
        #[cfg(not(feature = "sync_handler"))]
        test_mount_auth_api(&core, &root_token, "approle", "approle/").await;

        let approle_module = core.module_manager().get_module::<AppRoleModule>("approle").unwrap();

        // Create a role
        let mut req = Request::new("/auth/approle/role1");
        req.operation = Operation::Write;
        req.storage = core.get_system_view().map(|arc| arc as Arc<dyn Storage>);

        let role_entry = RoleEntry {
            role_id: "testroleid".to_string(),
            hmac_key: "testhmackey".to_string(),
            bind_secret_id: true,
            secret_id_ttl: Duration::from_secs(300),
            policies: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            ..Default::default()
        };
        #[cfg(not(feature = "sync_handler"))]
        let resp = approle_module.set_role(&mut req, "role1", &role_entry, "").await;
        #[cfg(feature = "sync_handler")]
        let resp = approle_module.set_role(&mut req, "role1", &role_entry, "");
        assert!(resp.is_ok());

        // Create a secret-id
        req.operation = Operation::Write;
        req.path = "auth/approle/role/role1/secret-id".to_string();
        req.client_token = root_token.to_string();

        #[cfg(feature = "sync_handler")]
        let _resp = core.handle_request(&mut req);
        #[cfg(not(feature = "sync_handler"))]
        let _resp = core.handle_request(&mut req).await;

        req.storage = core.get_system_view().map(|arc| arc as Arc<dyn Storage>);

        let mut mock_backend = approle_module.new_backend();
        assert!(mock_backend.init().is_ok());

        #[cfg(not(feature = "sync_handler"))]
        let resp = approle_module.write_role_secret_id(&mock_backend, &mut req).await;
        #[cfg(feature = "sync_handler")]
        let resp = approle_module.write_role_secret_id(&mock_backend, &mut req);
        assert!(resp.is_ok());

        #[cfg(not(feature = "sync_handler"))]
        let accessor = req.storage_list("accessor/").await;
        #[cfg(feature = "sync_handler")]
        let accessor = req.storage_list("accessor/");
        assert!(accessor.is_ok());

        let accessor = accessor.unwrap();
        assert_eq!(accessor.len(), 1);

        let entry = StorageEntry::new(
            "accessor/invalid1",
            &SecretIdAccessorStorageEntry { secret_id_hmac: "samplesecretidhmac".to_string() },
        )
        .unwrap();

        #[cfg(not(feature = "sync_handler"))]
        let result = req.storage_put(&entry).await;
        #[cfg(feature = "sync_handler")]
        let result = req.storage_put(&entry);
        assert!(result.is_ok());

        let entry = StorageEntry::new(
            "accessor/invalid2",
            &SecretIdAccessorStorageEntry { secret_id_hmac: "samplesecretidhmac2".to_string() },
        )
        .unwrap();

        #[cfg(not(feature = "sync_handler"))]
        let result = req.storage_put(&entry).await;
        #[cfg(feature = "sync_handler")]
        let result = req.storage_put(&entry);
        assert!(result.is_ok());

        #[cfg(not(feature = "sync_handler"))]
        let accessor = req.storage_list("accessor/").await;
        #[cfg(feature = "sync_handler")]
        let accessor = req.storage_list("accessor/");
        assert!(accessor.is_ok());
        let accessor = accessor.unwrap();
        assert_eq!(accessor.len(), 3);

        req.operation = Operation::Write;
        req.path = "tidy/secret-id".to_string();
        #[cfg(not(feature = "sync_handler"))]
        let _resp = mock_backend.handle_request(&mut req).await;
        #[cfg(feature = "sync_handler")]
        let _resp = mock_backend.handle_request(&mut req);

        assert!(req.ctx.wait_task_finish().await.is_ok());

        #[cfg(not(feature = "sync_handler"))]
        let accessor = req.storage_list("accessor/").await;
        #[cfg(feature = "sync_handler")]
        let accessor = req.storage_list("accessor/");
        assert!(accessor.is_ok());
        let accessor = accessor.unwrap();
        assert_eq!(accessor.len(), 1);
    }

    #[actix_rt::test]
    async fn test_approle_tidy_dangling_accessors_race() {
        #[cfg(not(feature = "sync_handler"))]
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_approle_tidy_dangling_accessors_race").await;
        #[cfg(feature = "sync_handler")]
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_approle_tidy_dangling_accessors_race");

        // Mount approle auth to path: auth/approle
        #[cfg(feature = "sync_handler")]
        test_mount_auth_api(&core, &root_token, "approle", "approle/");
        #[cfg(not(feature = "sync_handler"))]
        test_mount_auth_api(&core, &root_token, "approle", "approle/").await;

        let approle_module = core.module_manager().get_module::<AppRoleModule>("approle").unwrap();

        let mut mock_backend = approle_module.new_backend();
        assert!(mock_backend.init().is_ok());

        // Create a role
        let mut req = Request::new("/auth/approle/role1");
        req.operation = Operation::Write;
        req.storage = core.get_system_view().map(|arc| arc as Arc<dyn Storage>);

        let role_entry = RoleEntry {
            role_id: "testroleid".to_string(),
            hmac_key: "testhmackey".to_string(),
            bind_secret_id: true,
            secret_id_ttl: Duration::from_secs(300),
            policies: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            ..Default::default()
        };
        #[cfg(not(feature = "sync_handler"))]
        let resp = approle_module.set_role(&mut req, "role1", &role_entry, "").await;
        #[cfg(feature = "sync_handler")]
        let resp = approle_module.set_role(&mut req, "role1", &role_entry, "");
        assert!(resp.is_ok());

        // Create a secret-id
        req.operation = Operation::Write;
        req.path = "auth/approle/role/role1/secret-id".to_string();
        req.client_token = root_token.to_string();

        #[cfg(feature = "sync_handler")]
        let _resp = core.handle_request(&mut req);
        #[cfg(not(feature = "sync_handler"))]
        let _resp = core.handle_request(&mut req).await;

        req.storage = core.get_system_view().map(|arc| arc as Arc<dyn Storage>);
        #[cfg(not(feature = "sync_handler"))]
        let resp = approle_module.write_role_secret_id(&mock_backend, &mut req).await;
        #[cfg(feature = "sync_handler")]
        let resp = approle_module.write_role_secret_id(&mock_backend, &mut req);
        assert!(resp.is_ok());

        let count = Arc::new(Mutex::new(1));
        let start = Instant::now();
        let core_cloned = core.clone();

        while start.elapsed() < Duration::new(5, 0) {
            if start.elapsed() > Duration::from_millis(100)
                && approle_module.tidy_secret_id_cas_guard.load(Ordering::SeqCst) == 0
            {
                req.operation = Operation::Write;
                req.path = "tidy/secret-id".to_string();
                // The returned future is intentionally dropped (fire-and-forget) to
                // exercise the CAS guard race; not awaited on purpose.
                #[allow(clippy::let_underscore_future)]
                let _ = mock_backend.handle_request(&mut req);
            }

            let core_cloned2 = core_cloned.clone();
            let token = root_token.clone();
            let mb = mock_backend.clone();

            actix_rt::spawn(async move {
                let core = core_cloned2.clone();
                let approle_module = core.module_manager().get_module::<AppRoleModule>("approle").unwrap();
                let mut req = Request::new("auth/approle/role/role1/secret-id");
                req.operation = Operation::Write;
                req.client_token = token.clone();

                #[cfg(feature = "sync_handler")]
                let _resp = core.handle_request(&mut req);
                #[cfg(not(feature = "sync_handler"))]
                let _resp = core.handle_request(&mut req).await;

                req.storage = core.get_system_view().map(|arc| arc as Arc<dyn Storage>);
                #[cfg(not(feature = "sync_handler"))]
                let resp = approle_module.write_role_secret_id(&mb, &mut req).await;
                #[cfg(feature = "sync_handler")]
                let resp = approle_module.write_role_secret_id(&mb, &mut req);
                assert!(resp.is_ok());
            });

            let mut num = count.lock().unwrap();

            let entry = StorageEntry::new(
                format!("accessor/invalid{}", *num).as_str(),
                &SecretIdAccessorStorageEntry { secret_id_hmac: "samplesecretidhmac".to_string() },
            )
            .unwrap();

            #[cfg(not(feature = "sync_handler"))]
            assert!(req.storage_put(&entry).await.is_ok());
            #[cfg(feature = "sync_handler")]
            assert!(req.storage_put(&entry).is_ok());

            *num += 1;

            thread::sleep(Duration::from_micros(10));
        }

        assert!(req.ctx.wait_task_finish().await.is_ok());

        // Wait for tidy to finish
        while approle_module.tidy_secret_id_cas_guard.load(Ordering::SeqCst) != 0 {
            thread::sleep(Duration::from_micros(100));
        }

        // Run tidy again
        req.ctx.clear_task();

        req.operation = Operation::Write;
        req.path = "tidy/secret-id".to_string();
        #[cfg(not(feature = "sync_handler"))]
        let resp = mock_backend.handle_request(&mut req).await;
        #[cfg(feature = "sync_handler")]
        let resp = mock_backend.handle_request(&mut req);
        assert!(resp.is_ok());

        assert!(req.ctx.wait_task_finish().await.is_ok());

        let num = count.lock().unwrap();

        #[cfg(not(feature = "sync_handler"))]
        let accessor = req.storage_list("accessor/").await;
        #[cfg(feature = "sync_handler")]
        let accessor = req.storage_list("accessor/");
        assert!(accessor.is_ok());
        let accessor = accessor.unwrap();
        assert_eq!(accessor.len(), *num);

        #[cfg(not(feature = "sync_handler"))]
        let role_hmacs = req.storage_list(SECRET_ID_PREFIX).await;
        #[cfg(feature = "sync_handler")]
        let role_hmacs = req.storage_list(SECRET_ID_PREFIX);
        assert!(role_hmacs.is_ok());
        let role_hmacs = role_hmacs.unwrap();
        assert_eq!(role_hmacs.len(), 1);

        #[cfg(not(feature = "sync_handler"))]
        let secret_ids = req.storage_list(format!("{}{}", SECRET_ID_PREFIX, role_hmacs[0]).as_str()).await;
        #[cfg(feature = "sync_handler")]
        let secret_ids = req.storage_list(format!("{}{}", SECRET_ID_PREFIX, role_hmacs[0]).as_str());
        assert!(secret_ids.is_ok());
        let secret_ids = secret_ids.unwrap();
        assert_eq!(secret_ids.len(), *num);
    }
}
