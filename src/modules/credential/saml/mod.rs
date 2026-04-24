//! SAML 2.0 authentication backend — Phase 1 + 2 scaffold.
//!
//! Mirrors the Module/Backend pattern used by `userpass`, `approle`,
//! and `oidc`:
//!
//!   * `SamlModule` registers the backend with the auth module under
//!     the `"saml"` kind.
//!   * `SamlBackend` + `SamlBackendInner` hold the shared core handle;
//!     per-path handlers live in `path_config.rs` / `path_roles.rs`.
//!
//! Endpoints registered on the backend (all mounted under `auth/<mount>/`):
//!
//!   `config`                      — GET / POST  (root)   IdP configuration
//!   `role/<name>`                 — GET / POST / DELETE  per-role config
//!   `role/?`                      — LIST                 all role names
//!
//! Phase 3 (login / callback / XML-signature verification) is not yet
//! wired — the crate decision for XML-DSig verification is deferred
//! until we pick between `samael` (C-dep-heavy, feature-complete) and
//! a pure-Rust XML-DSig path. Config + role state is persisted now so
//! operators can describe their IdP ahead of the flow shipping.
//!
//! Single-mount assumption: one IdP config per mount. Multi-IdP
//! setups use multiple mounts (`auth/okta/`, `auth/adfs/`, etc.).

use std::{any::Any, sync::Arc};

use derive_more::Deref;

use crate::{
    core::Core,
    errors::RvError,
    logical::{Backend, LogicalBackend},
    modules::{auth::AuthModule, Module},
    new_logical_backend, new_logical_backend_internal,
};

pub mod path_config;
pub mod path_roles;

static SAML_BACKEND_HELP: &str = r#"
The "saml" credential provider allows authentication against any
SAML 2.0 compliant identity provider (Okta, Azure AD, ADFS,
Keycloak, Shibboleth, etc.) using SP-initiated Single Sign-On.

IdP-level configuration (metadata URL or raw metadata, SP entity
id, ACS URL, signing certificate) is written once at the `config`
endpoint. Role configuration (attribute-to-policy mappings,
bound attributes / subjects, token TTLs) is written at
`role/<name>`. The login + callback endpoints will land in a
follow-up phase together with XML-signature verification.
"#;

pub struct SamlModule {
    pub name: String,
    pub backend: Arc<SamlBackend>,
}

pub struct SamlBackendInner {
    pub core: Arc<Core>,
}

#[derive(Deref)]
pub struct SamlBackend {
    #[deref]
    pub inner: Arc<SamlBackendInner>,
}

impl SamlBackend {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            inner: Arc::new(SamlBackendInner { core }),
        }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let mut backend = new_logical_backend!({
            // `login` and `callback` will be added in Phase 3 as
            // unauth paths; nothing is unauth yet.
            unauth_paths: [],
            help: SAML_BACKEND_HELP,
        });

        backend.paths.push(Arc::new(self.config_path()));
        backend.paths.push(Arc::new(self.roles_path()));
        backend.paths.push(Arc::new(self.role_list_path()));

        backend
    }
}

impl SamlModule {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            name: "saml".to_string(),
            backend: Arc::new(SamlBackend::new(core)),
        }
    }
}

impl Module for SamlModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, core: &Core) -> Result<(), RvError> {
        let saml = self.backend.clone();
        let saml_backend_new_func = move |_c: Arc<Core>| -> Result<Arc<dyn Backend>, RvError> {
            let mut b = saml.new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };

        if let Some(auth_module) = core
            .module_manager
            .get_module::<AuthModule>("auth")
        {
            return auth_module.add_auth_backend("saml", Arc::new(saml_backend_new_func));
        }
        log::error!("saml module: auth module missing on setup");
        Ok(())
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        if let Some(auth_module) = core
            .module_manager
            .get_module::<AuthModule>("auth")
        {
            return auth_module.delete_auth_backend("saml");
        }
        Ok(())
    }
}

#[cfg(test)]
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
