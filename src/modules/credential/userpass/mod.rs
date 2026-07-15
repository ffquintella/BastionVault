use std::{any::Any, sync::Arc};

use derive_more::Deref;

use crate::{
    core::Core,
    errors::RvError,
    logical::{Backend, LogicalBackend},
    modules::{auth::AuthModule, Module},
    new_logical_backend, new_logical_backend_internal,
};

pub mod cli;
pub mod path_config;
pub mod path_fido2_config;
pub mod path_fido2_credentials;
pub mod path_fido2_login;
pub mod path_fido2_register;
pub mod path_login;
pub mod path_users;

static USERPASS_BACKEND_HELP: &str = r#"
The "userpass" credential provider allows authentication using a combination of
a username and password, optionally reinforced with a TOTP second factor.

The username/password combination is configured using the "users/" endpoints by
a user with root access. Authentication is then done by supplying the username
and password (plus a "totp_code" when MFA is enabled) for "login".

Accounts can be enabled/disabled by an admin, temporarily locked out after
repeated failed password attempts (see "config/lockout"), and required to
present a TOTP code (see "config/mfa" and the per-user "totp_mfa_enabled" flag).
"#;

pub struct UserPassModule {
    pub name: String,
    pub backend: Arc<UserPassBackend>,
}

pub struct UserPassBackendInner {
    pub core: Arc<Core>,
}

#[derive(Deref)]
pub struct UserPassBackend {
    #[deref]
    pub inner: Arc<UserPassBackendInner>,
}

impl UserPassBackend {
    pub fn new(core: Arc<Core>) -> Self {
        Self { inner: Arc::new(UserPassBackendInner { core }) }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let userpass_backend_ref = self.inner.clone();

        let mut backend = new_logical_backend!({
            unauth_paths: ["login/*", "fido2/login/*", "fido2/config"],
            auth_renew_handler: userpass_backend_ref.login_renew,
            help: USERPASS_BACKEND_HELP,
        });

        backend.paths.push(Arc::new(self.users_path()));
        backend.paths.push(Arc::new(self.user_list_path()));
        backend.paths.push(Arc::new(self.user_password_path()));
        backend.paths.push(Arc::new(self.user_unlock_path()));
        backend.paths.push(Arc::new(self.lockout_config_path()));
        backend.paths.push(Arc::new(self.mfa_config_path()));
        backend.paths.push(Arc::new(self.login_path()));
        // FIDO2 paths
        backend.paths.push(Arc::new(self.fido2_config_path()));
        backend.paths.push(Arc::new(self.fido2_register_begin_path()));
        backend.paths.push(Arc::new(self.fido2_register_complete_path()));
        backend.paths.push(Arc::new(self.fido2_login_begin_path()));
        backend.paths.push(Arc::new(self.fido2_login_complete_path()));
        backend.paths.push(Arc::new(self.fido2_credentials_path()));

        backend
    }
}

impl UserPassModule {
    pub fn new(core: Arc<Core>) -> Self {
        Self { name: "userpass".to_string(), backend: Arc::new(UserPassBackend::new(core)) }
    }
}

impl Module for UserPassModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, core: &Core) -> Result<(), RvError> {
        let userpass = self.backend.clone();
        let userpass_backend_new_func = move |_c: Arc<Core>| -> Result<Arc<dyn Backend>, RvError> {
            let mut userpass_backend = userpass.new_backend();
            userpass_backend.init()?;
            Ok(Arc::new(userpass_backend))
        };

        if let Some(auth_module) = core.module_manager.get_module::<AuthModule>("auth") {
            return auth_module.add_auth_backend("userpass", Arc::new(userpass_backend_new_func));
        } else {
            log::error!("get auth module failed!");
        }

        Ok(())
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        if let Some(auth_module) = core.module_manager.get_module::<AuthModule>("auth") {
            return auth_module.delete_auth_backend("userpass");
        } else {
            log::error!("get auth module failed!");
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use serde_json::json;

    use super::*;
    use crate::{
        core::Core,
        logical::{Operation, Request, Response},
        test_utils::{
            new_unseal_test_bastion_vault, test_delete_api, test_mount_api, test_mount_auth_api, test_read_api,
            test_write_api,
        },
    };

    #[maybe_async::maybe_async]
    async fn test_write_user(core: &Core, token: &str, path: &str, username: &str, password: &str, ttl: i32) {
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
    async fn test_read_user(core: &Core, token: &str, username: &str) -> Result<Option<Response>, RvError> {
        let resp = test_read_api(core, token, format!("auth/pass/users/{}", username).as_str(), true).await;
        assert!(resp.is_ok());
        resp
    }

    #[maybe_async::maybe_async]
    async fn test_delete_user(core: &Core, token: &str, username: &str) {
        let resp = test_delete_api(core, token, format!("auth/pass/users/{}", username).as_str(), true, None).await;
        assert!(resp.is_ok());
    }

    #[maybe_async::maybe_async]
    async fn test_login(
        core: &Core,
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
    async fn login_error(core: &Core, path: &str, username: &str, password: &str) -> Option<String> {
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
        let now = super::path_users::now_secs() as u64;
        let code = crypto::totp(&seed, now, Algorithm::Sha1, 6, 30);
        let mut req = Request::new("auth/pass/login/bob");
        req.operation = Operation::Write;
        req.body = json!({ "password": "pw-bob-123", "totp_code": code }).as_object().cloned();
        let resp = core.handle_request(&mut req).await.unwrap().unwrap();
        assert!(resp.auth.is_some(), "valid TOTP code should mint a token");
    }
}
