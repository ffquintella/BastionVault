//! Tests for the userpass auth backend, which lives in `crates/bv-auth-userpass`.
//!
//! Lifted out of the backend because they stand up a whole vault through
//! `crate::test_utils`; its pure unit tests stayed with it.
//!
//! See roadmaps/workspace-decomposition.md § Phase 3.

mod test {
    use std::time::Duration;

    use serde_json::json;

    // Was `use super::*` inside the backend, which also brought in the
    // crate root's private substrate aliases. Across a crate boundary
    // those have to be named.
    use bv_kernel_api::VaultCtx;

    use crate::errors::RvError;
    use crate::{
        logical::{Operation, Request, Response},
        test_utils::{
            new_unseal_test_bastion_vault, test_delete_api, test_mount_api, test_mount_auth_api, test_read_api,
            test_write_api,
        },
    };

    #[maybe_async::maybe_async]
    async fn test_write_user(core: &dyn VaultCtx, token: &str, path: &str, username: &str, password: &str, ttl: i32) {
        let user_data = json!({
            "password": password,
            "ttl": ttl,
        })
        .as_object()
        .cloned();

        let resp =
            test_write_api(core, token, format!("auth/{}/users/{}", path, username).as_str(), true, user_data).await;
        assert!(resp.is_ok());
    }

    #[maybe_async::maybe_async]
    async fn test_read_user(core: &dyn VaultCtx, token: &str, username: &str) -> Result<Option<Response>, RvError> {
        let resp = test_read_api(core, token, format!("auth/pass/users/{}", username).as_str(), true).await;
        assert!(resp.is_ok());
        resp
    }

    #[maybe_async::maybe_async]
    async fn test_delete_user(core: &dyn VaultCtx, token: &str, username: &str) {
        let resp = test_delete_api(core, token, format!("auth/pass/users/{}", username).as_str(), true, None).await;
        assert!(resp.is_ok());
    }

    #[maybe_async::maybe_async]
    async fn test_login(
        core: &dyn VaultCtx,
        path: &str,
        username: &str,
        password: &str,
        is_ok: bool,
    ) -> Result<Option<Response>, RvError> {
        let login_data = json!({
            "password": password,
        })
        .as_object()
        .cloned();

        let mut req = Request::new(format!("auth/{}/login/{}", path, username).as_str());
        req.operation = Operation::Write;
        req.body = login_data;

        let resp = core.handle_request(&mut req).await;
        assert!(resp.is_ok());
        if is_ok {
            let resp = resp.as_ref().unwrap();
            assert!(resp.is_some());
        }
        resp
    }

    /// A user's `token_bound_cidrs` restricts where the issued token may be
    /// used. Also covers the legacy `bound_cidrs` alias, which `path_users`
    /// keeps in sync with the canonical field — both must reach the token.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_userpass_token_bound_cidrs_restrict_token_use() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_userpass_token_bound_cidrs_restrict_token_use").await;

        test_mount_auth_api(&core, &root_token, "userpass", "pass").await;

        // Canonical field.
        let user_data = json!({ "password": "pw", "token_bound_cidrs": ["10.0.0.0/24"] }).as_object().cloned();
        let resp = test_write_api(&core, &root_token, "auth/pass/users/bound", true, user_data).await;
        assert!(resp.is_ok());

        let resp = test_login(&core, "pass", "bound", "pw", true).await.unwrap().unwrap();
        let auth = resp.auth.unwrap();
        assert_eq!(
            auth.bound_cidrs,
            vec!["10.0.0.0/24".to_string()],
            "the user's token_bound_cidrs must reach the issued Auth"
        );

        let token = auth.client_token;
        assert!(use_token_from(&core, &token, "10.0.0.7:41222").await.is_ok(), "usable from inside the block");
        assert!(
            matches!(use_token_from(&core, &token, "203.0.113.9:41222").await, Err(RvError::ErrPermissionDenied)),
            "must be refused from outside the block"
        );
        assert!(
            matches!(use_token_from(&core, &token, "").await, Err(RvError::ErrPermissionDenied)),
            "must fail closed on an unknown source address"
        );

        // Legacy alias: `bound_cidrs` is mirrored onto `token_bound_cidrs`.
        let user_data = json!({ "password": "pw", "bound_cidrs": ["10.9.0.0/24"] }).as_object().cloned();
        let resp = test_write_api(&core, &root_token, "auth/pass/users/legacy", true, user_data).await;
        assert!(resp.is_ok());

        let resp = test_login(&core, "pass", "legacy", "pw", true).await.unwrap().unwrap();
        let token = resp.auth.unwrap().client_token;
        assert!(use_token_from(&core, &token, "10.9.0.7:41222").await.is_ok(), "legacy alias must bind the token");
        assert!(
            matches!(use_token_from(&core, &token, "10.0.0.7:41222").await, Err(RvError::ErrPermissionDenied)),
            "legacy alias must be enforced, not just stored"
        );

        // A user with no binding is unrestricted.
        test_write_user(&core, &root_token, "pass", "free", "pw", 0).await;
        let resp = test_login(&core, "pass", "free", "pw", true).await.unwrap().unwrap();
        let token = resp.auth.unwrap().client_token;
        for peer in ["10.0.0.7:41222", "203.0.113.9:41222", ""] {
            assert!(use_token_from(&core, &token, peer).await.is_ok(), "an unbound token must be usable from {peer:?}");
        }
    }

    /// Present `token` on an authenticated route from socket address
    /// `peer_addr` (pass `""` for a request with no connection information).
    #[maybe_async::maybe_async]
    async fn use_token_from(core: &dyn VaultCtx, token: &str, peer_addr: &str) -> Result<(), RvError> {
        let mut req = Request::new("auth/token/lookup-self");
        req.operation = Operation::Read;
        req.client_token = token.to_string();
        req.connection = Some(crate::logical::connection::Connection {
            peer_addr: peer_addr.to_string(),
            ..Default::default()
        });
        core.handle_request(&mut req).await.map(|_| ())
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_userpass_module() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_userpass_module").await;

        // mount userpass auth to path: auth/pass
        test_mount_auth_api(&core, &root_token, "userpass", "pass").await;

        test_write_user(&core, &root_token, "pass", "test", "123qwe!@#", 0).await;
        let resp = test_read_user(&core, &root_token, "test").await.unwrap();
        assert!(resp.is_some());

        test_delete_user(&core, &root_token, "test").await;
        let resp = test_read_user(&core, &root_token, "test").await.unwrap();
        assert!(resp.is_none());

        test_write_user(&core, &root_token, "pass", "test", "123qwe!@#", 0).await;
        let _ = test_login(&core, "pass", "test", "123qwe!@#", true).await;
        let _ = test_login(&core, "pass", "test", "xxxxxxx", false).await;
        let _ = test_login(&core, "pass", "xxxx", "123qwe!@#", false).await;
        let resp = test_login(&core, "pass", "test", "123qwe!@#", true).await;
        let login_auth = resp.unwrap().unwrap().auth.unwrap();
        let test_client_token = login_auth.client_token.clone();
        let resp = test_read_api(&core, &test_client_token, "auth/token/lookup-self", true).await;
        println!("read auth/token/lookup-self resp: {:?}", resp);
        assert!(resp.unwrap().is_some());

        test_delete_user(&core, &root_token, "test").await;
        let resp = test_login(&core, "pass", "test", "123qwe!@#", false).await;
        let login_resp = resp.unwrap().unwrap();
        assert!(login_resp.auth.is_none());

        test_write_user(&core, &root_token, "pass", "test2", "123qwe", 5).await;
        let resp = test_read_user(&core, &root_token, "test").await.unwrap();
        assert!(resp.is_none());
        let resp = test_login(&core, "pass", "test2", "123qwe", true).await;
        let login_auth = resp.unwrap().unwrap().auth.unwrap();
        println!("user login_auth: {:?}", login_auth);
        assert_eq!(login_auth.lease.ttl.as_secs(), 5);

        println!("wait 7s");
        std::thread::sleep(Duration::from_secs(7));
        let test_client_token = login_auth.client_token.clone();
        let resp = test_read_api(&core, &test_client_token, "auth/token/lookup-self", false).await;
        println!("read auth/token/lookup-self resp: {:?}", resp);
        assert_eq!(resp.unwrap_err(), RvError::ErrPermissionDenied);

        // mount userpass auth to path: auth/testpass
        test_mount_auth_api(&core, &root_token, "userpass", "testpass").await;
        test_write_user(&core, &root_token, "testpass", "testuser", "123qwe!@#", 0).await;
        let resp = test_login(&core, "testpass", "testuser", "123qwe!@#", true).await;
        let login_auth = resp.unwrap().unwrap().auth.unwrap();
        let test_client_token = login_auth.client_token.clone();
        println!("test_client_token: {}", test_client_token);
        let resp = test_read_api(&core, &test_client_token, "auth/token/lookup-self", true).await;
        println!("read auth/token/lookup-self resp: {:?}", resp);
        assert!(resp.unwrap().is_some());
    }

    #[maybe_async::maybe_async]
    async fn login_error(core: &dyn VaultCtx, path: &str, username: &str, password: &str) -> Option<String> {
        let mut req = Request::new(format!("auth/{path}/login/{username}").as_str());
        req.operation = Operation::Write;
        req.body = json!({ "password": password }).as_object().cloned();
        let resp = core.handle_request(&mut req).await.unwrap().unwrap();
        // A rejected login carries no auth block and surfaces the reason in data.error.
        assert!(resp.auth.is_none(), "expected rejection, got a token");
        resp.data.as_ref().and_then(|d| d.get("error")).and_then(|v| v.as_str()).map(String::from)
    }

    /// Feature: admin enable/disable switch and temporary account lockout.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_disable_and_lockout() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_disable_and_lockout").await;
        test_mount_auth_api(&core, &root_token, "userpass", "pass").await;
        test_write_user(&core, &root_token, "pass", "alice", "correct-horse", 0).await;

        // Tighten the lockout policy: lock after 3 failures.
        let cfg = json!({ "enabled": true, "max_failed_attempts": 3, "lockout_duration_secs": 600 })
            .as_object()
            .cloned();
        assert!(test_write_api(&core, &root_token, "auth/pass/config/lockout", true, cfg).await.is_ok());

        // Disabled account refuses even the correct password.
        let disable = json!({ "disabled": true }).as_object().cloned();
        assert!(test_write_api(&core, &root_token, "auth/pass/users/alice", true, disable).await.is_ok());
        assert_eq!(login_error(&core, "pass", "alice", "correct-horse").await.as_deref(), Some("account is disabled"));

        // Re-enable and confirm the correct password works again.
        let enable = json!({ "disabled": false }).as_object().cloned();
        assert!(test_write_api(&core, &root_token, "auth/pass/users/alice", true, enable).await.is_ok());
        let _ = test_login(&core, "pass", "alice", "correct-horse", true).await;

        // Three bad passwords trip the lock; the correct password is then
        // refused with the lockout message (proving lock precedes password check).
        for _ in 0..3 {
            assert_eq!(login_error(&core, "pass", "alice", "wrong").await.as_deref(), Some("invalid username or password"));
        }
        let locked = login_error(&core, "pass", "alice", "correct-horse").await.unwrap();
        assert!(locked.contains("temporarily locked"), "expected lockout message, got: {locked}");

        // Admin unlock clears it; the correct password works immediately.
        assert!(test_write_api(&core, &root_token, "auth/pass/users/alice/unlock", true, None).await.is_ok());
        let _ = test_login(&core, "pass", "alice", "correct-horse", true).await;

        // read_user exposes the computed `locked` flag as false post-unlock.
        let info = test_read_api(&core, &root_token, "auth/pass/users/alice", true).await.unwrap().unwrap();
        assert_eq!(info.data.unwrap().get("locked").and_then(|v| v.as_bool()), Some(false));
    }

    /// Feature: TOTP as a second factor, gated by the global MFA switch.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_totp_mfa_login() {
        use crate::modules::totp::{crypto, policy::Algorithm};

        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_totp_mfa_login").await;
        test_mount_auth_api(&core, &root_token, "userpass", "pass").await;
        test_mount_api(&core, &root_token, "totp", "totp").await;
        test_write_user(&core, &root_token, "pass", "bob", "pw-bob-123", 0).await;

        // Import a provider-mode TOTP key with a known seed so the test can
        // compute a valid code with the same primitives the login path uses.
        let seed: Vec<u8> = (0u8..20).collect();
        let b32 = crypto::otpauth::encode_secret(&seed);
        let key_body = json!({
            "generate": false, "key": b32, "digits": 6, "period": 30, "algorithm": "SHA1",
            "issuer": "BastionVault", "account_name": "bob"
        })
        .as_object()
        .cloned();
        assert!(test_write_api(&core, &root_token, "totp/keys/bobkey", true, key_body).await.is_ok());

        // Bind MFA to the user.
        let mfa_user = json!({ "totp_mfa_enabled": true, "totp_key": "bobkey" }).as_object().cloned();
        assert!(test_write_api(&core, &root_token, "auth/pass/users/bob", true, mfa_user).await.is_ok());

        // MFA is still globally OFF: password-only login must succeed.
        let _ = test_login(&core, "pass", "bob", "pw-bob-123", true).await;

        // Turn MFA on globally.
        let mfa_cfg = json!({ "enabled": true }).as_object().cloned();
        assert!(test_write_api(&core, &root_token, "auth/pass/config/mfa", true, mfa_cfg).await.is_ok());

        // Password-only now fails (code required).
        let need = login_error(&core, "pass", "bob", "pw-bob-123").await.unwrap();
        assert!(need.contains("TOTP code is required"), "got: {need}");

        // Wrong code fails.
        {
            let mut req = Request::new("auth/pass/login/bob");
            req.operation = Operation::Write;
            req.body = json!({ "password": "pw-bob-123", "totp_code": "000000" }).as_object().cloned();
            let resp = core.handle_request(&mut req).await.unwrap().unwrap();
            assert!(resp.auth.is_none());
        }

        // Correct current code succeeds.
        let now = crate::modules::credential::userpass::path_users::now_secs() as u64;
        let code = crypto::totp(&seed, now, Algorithm::Sha1, 6, 30);
        let mut req = Request::new("auth/pass/login/bob");
        req.operation = Operation::Write;
        req.body = json!({ "password": "pw-bob-123", "totp_code": code }).as_object().cloned();
        let resp = core.handle_request(&mut req).await.unwrap().unwrap();
        assert!(resp.auth.is_some(), "valid TOTP code should mint a token");
    }
}
