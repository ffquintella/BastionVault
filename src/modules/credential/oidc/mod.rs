//! OpenID Connect authentication backend.
//!
//! Mirrors the Module/Backend pattern used by `userpass` and `approle`:
//!
//!   * `OidcModule` registers the backend with the auth module under
//!     the `"oidc"` kind.
//!   * `OidcBackend` + `OidcBackendInner` hold the shared core handle;
//!     per-path handlers live in `path_config.rs` / `path_roles.rs` /
//!     `path_auth_url.rs` / `path_callback.rs`.
//!
//! Endpoints registered on the backend (all mounted under `auth/<mount>/`):
//!
//!   `config`                      — GET / POST  (root)   provider config
//!   `role/<name>`                 — GET / POST / DELETE  per-role config
//!   `role/?`                      — LIST                 all role names
//!   `auth_url`                    — POST        (unauth) generate consent URL
//!   `callback`                    — POST        (unauth) finish consent flow
//!
//! The auth flow runs in two steps:
//!
//!   1. Client POSTs `auth_url` with a `role` + `redirect_uri`. We
//!      generate PKCE + CSRF state + nonce, stash them under
//!      `state/<state>` (short-lived), and return the authorization
//!      URL pointing at the IdP.
//!   2. Client POSTs `callback` with the `state` + `code` returned
//!      by the IdP. We load-and-delete the state record, exchange the
//!      code for tokens using `openidconnect`, verify the ID token
//!      against the IdP's JWKS, validate role-bound claims, and
//!      return an `Auth` carrying the role's policies. The token
//!      store then mints the vault token.
//!
//! Single-mount assumption: one config per mount. Multi-provider
//! setups use multiple mounts (`auth/okta/`, `auth/azuread/`, etc.).

use std::{any::Any, sync::Arc};

use derive_more::Deref;

use crate::{
    core::Core,
    errors::RvError,
    logical::{Backend, LogicalBackend},
    modules::{auth::AuthModule, Module},
    new_logical_backend, new_logical_backend_internal,
};

pub mod path_auth_url;
pub mod path_callback;
pub mod path_config;
pub mod path_roles;

static OIDC_BACKEND_HELP: &str = r#"
The "oidc" credential provider allows authentication against any
OpenID Connect compliant identity provider (Okta, Azure AD,
Keycloak, Google, Auth0, etc.) using the Authorization Code Flow
with PKCE.

Provider-level configuration (discovery URL, client id/secret,
allowed redirect URIs, default scopes) is written once at the
`config` endpoint. Role configuration (claim-to-policy mappings,
bound audiences / claims, token TTLs) is written at `role/<name>`.
Clients initiate login by POSTing `auth_url` with a role + redirect
URI, open the returned authorization URL in a browser, and finish
by POSTing the returned `code` + `state` back to `callback`.
"#;

pub struct OidcModule {
    pub name: String,
    pub backend: Arc<OidcBackend>,
}

pub struct OidcBackendInner {
    pub core: Arc<Core>,
}

#[derive(Deref)]
pub struct OidcBackend {
    #[deref]
    pub inner: Arc<OidcBackendInner>,
}

impl OidcBackend {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            inner: Arc::new(OidcBackendInner { core }),
        }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        // The renew-handler macro expects `ident.ident`, so bind a
        // named handle first.
        let oidc_backend_ref = self.inner.clone();

        let mut backend = new_logical_backend!({
            // `auth_url` and `callback` are the two endpoints the
            // browser-mediated flow needs to hit without a vault
            // token in hand; everything else is root-path admin.
            unauth_paths: ["auth_url", "callback"],
            auth_renew_handler: oidc_backend_ref.login_renew,
            help: OIDC_BACKEND_HELP,
        });

        backend.paths.push(Arc::new(self.config_path()));
        backend.paths.push(Arc::new(self.roles_path()));
        backend.paths.push(Arc::new(self.role_list_path()));
        backend.paths.push(Arc::new(self.auth_url_path()));
        backend.paths.push(Arc::new(self.callback_path()));

        backend
    }
}

impl OidcModule {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            name: "oidc".to_string(),
            backend: Arc::new(OidcBackend::new(core)),
        }
    }
}

impl Module for OidcModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, core: &Core) -> Result<(), RvError> {
        let oidc = self.backend.clone();
        let oidc_backend_new_func = move |_c: Arc<Core>| -> Result<Arc<dyn Backend>, RvError> {
            let mut b = oidc.new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };

        if let Some(auth_module) = core
            .module_manager
            .get_module::<AuthModule>("auth")
        {
            return auth_module.add_auth_backend("oidc", Arc::new(oidc_backend_new_func));
        }
        log::error!("oidc module: auth module missing on setup");
        Ok(())
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        if let Some(auth_module) = core
            .module_manager
            .get_module::<AuthModule>("auth")
        {
            return auth_module.delete_auth_backend("oidc");
        }
        Ok(())
    }
}

#[cfg(test)]
mod integration_tests {
    use serde_json::json;

    use crate::{
        core::Core,
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
    fn _silence_unused_core(_c: &Core) {}
}
