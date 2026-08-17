//! `auth_url` — generate an IdP authorization URL with PKCE.
//!
//! Flow:
//!   1. Client POSTs `auth_url` with `role` + `redirect_uri`.
//!   2. Validate `redirect_uri` against the role's + provider's
//!      whitelists.
//!   3. Generate PKCE verifier + challenge + CSRF state + nonce.
//!   4. Persist a short-lived `OidcAuthState` entry under
//!      `state/<state>` (5 min TTL, enforced on load in callback).
//!   5. Compose the authorization URL pointing at the IdP's
//!      authorize endpoint (fetched via discovery) and return it.
//!
//! The response carries only `auth_url` — everything else the
//! callback needs is keyed off the opaque `state` parameter that
//! rides with the redirect.

use std::{collections::HashMap, sync::Arc, time::Duration};

use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    reqwest, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    RedirectUrl, Scope,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{
    path_config::OidcConfig, path_roles::OidcRoleEntry, OidcBackend, OidcBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

pub(crate) const STATE_PREFIX: &str = "state/";
/// Maximum time between `auth_url` and `callback`. Matches the
/// window operators get to actually complete the consent in a
/// browser; longer than that and the user probably gave up.
pub(crate) const STATE_TTL_SECS: u64 = 300;

/// Per-request scratch state carried between `auth_url` (write)
/// and `callback` (read + delete). Storage key is the CSRF state
/// parameter, which is itself opaque random bytes.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct OidcAuthState {
    pub role_name: String,
    pub redirect_uri: String,
    pub nonce: String,
    pub code_verifier: String,
    pub created_at_unix: u64,
}

impl OidcAuthState {
    pub(crate) fn is_expired(&self, now_unix: u64) -> bool {
        now_unix.saturating_sub(self.created_at_unix) > STATE_TTL_SECS
    }
}

impl OidcBackend {
    pub fn auth_url_path(&self) -> Path {
        let this = self.inner.clone();
        new_path!({
            pattern: r"auth_url",
            fields: {
                "role": {
                    field_type: FieldType::Str,
                    description: "Role name; omit to use the provider config's default_role."
                },
                "redirect_uri": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Redirect URI the IdP will send the user back to after consent."
                }
            },
            operations: [
                {op: Operation::Write, handler: this.auth_url}
            ],
            help: "Generate an authorization URL for the configured OIDC provider."
        })
    }
}

#[maybe_async::maybe_async]
impl OidcBackendInner {
    pub async fn auth_url(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let cfg = OidcConfig::load(req).await?.ok_or_else(|| {
            RvError::ErrString(
                "oidc: provider config missing — POST to `config` first".into(),
            )
        })?;

        // Role selection: explicit > default > error.
        let role_name = req
            .get_data_as_str("role")
            .unwrap_or_default()
            .trim()
            .to_string();
        let role_name = if role_name.is_empty() {
            if cfg.default_role.is_empty() {
                return Err(RvError::ErrString(
                    "oidc: `role` is required (no `default_role` configured)".into(),
                ));
            }
            cfg.default_role.clone()
        } else {
            role_name
        };
        let role = OidcRoleEntry::load(req, &role_name).await?.ok_or_else(|| {
            RvError::ErrString(format!("oidc: role `{role_name}` not configured"))
        })?;

        // Redirect-URI validation. The per-role whitelist narrows
        // the provider-level whitelist; if either is empty that
        // tier accepts anything. At least one tier must be non-
        // empty to avoid turning the mount into an open-redirect
        // oracle.
        let redirect_uri = req
            .get_data_as_str("redirect_uri")
            .unwrap_or_default()
            .trim()
            .to_string();
        if redirect_uri.is_empty() {
            return Err(RvError::ErrString(
                "oidc: `redirect_uri` is required".into(),
            ));
        }
        if !role.allowed_redirect_uris.is_empty()
            && !role.allowed_redirect_uris.contains(&redirect_uri)
        {
            return Err(RvError::ErrString(format!(
                "oidc: redirect_uri `{redirect_uri}` not in role `{role_name}` whitelist"
            )));
        }
        if role.allowed_redirect_uris.is_empty()
            && !cfg.allowed_redirect_uris.is_empty()
            && !cfg.allowed_redirect_uris.contains(&redirect_uri)
        {
            return Err(RvError::ErrString(format!(
                "oidc: redirect_uri `{redirect_uri}` not in provider-level whitelist"
            )));
        }

        // Construct the OIDC client via discovery. Fetching the
        // discovery document + JWKS on every `auth_url` call is
        // wasteful but correct; a cache belongs behind the backend
        // state, not here. First-cut keeps the flow understandable.
        let http = reqwest_http_client()?;
        let issuer = IssuerUrl::new(cfg.oidc_discovery_url.clone())
            .map_err(|e| RvError::ErrString(format!("oidc: bad discovery URL: {e}")))?;
        let provider_metadata = CoreProviderMetadata::discover_async(issuer, &http)
            .await
            .map_err(|e| RvError::ErrString(format!("oidc: discovery: {e}")))?;

        let mut client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(cfg.oidc_client_id.clone()),
            if cfg.oidc_client_secret.is_empty() {
                None
            } else {
                Some(ClientSecret::new(cfg.oidc_client_secret.clone()))
            },
        );
        client = client.set_redirect_uri(
            RedirectUrl::new(redirect_uri.clone())
                .map_err(|e| RvError::ErrString(format!("oidc: bad redirect_uri: {e}")))?,
        );

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let mut builder = client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        // Union of provider-level + role-level scopes; de-duplicate
        // so the provider doesn't reject `scope=openid openid`.
        let mut scopes: Vec<String> = cfg.oidc_scopes.clone();
        for s in &role.oidc_scopes {
            if !scopes.contains(s) {
                scopes.push(s.clone());
            }
        }
        for s in scopes {
            builder = builder.add_scope(Scope::new(s));
        }
        let (auth_url, csrf_token, nonce) = builder.set_pkce_challenge(pkce_challenge).url();

        // Persist the scratch state so callback can look it up.
        let now = unix_now();
        let state_entry = OidcAuthState {
            role_name: role_name.clone(),
            redirect_uri: redirect_uri.clone(),
            nonce: nonce.secret().clone(),
            code_verifier: pkce_verifier.secret().clone(),
            created_at_unix: now,
        };
        req.storage_put(&StorageEntry {
            key: format!("{STATE_PREFIX}{}", csrf_token.secret()),
            value: serde_json::to_vec(&state_entry)?,
        })
        .await?;

        let mut data = Map::new();
        data.insert("auth_url".into(), Value::String(auth_url.to_string()));
        Ok(Some(Response::data_response(Some(data))))
    }
}

/// Shared reqwest client used for discovery / JWKS / token
/// exchange. Uses the standard `openidconnect` builder defaults
/// with a reasonable timeout so a slow IdP doesn't hang the vault.
pub(crate) fn reqwest_http_client() -> Result<reqwest::Client, RvError> {
    reqwest::ClientBuilder::new()
        // OIDC redirects on the IdP side are expected; disabling
        // redirects on our side follows the openidconnect crate's
        // explicit recommendation in the library docs to avoid
        // leaking bearer tokens through a misconfigured IdP.
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| RvError::ErrString(format!("oidc: http client: {e}")))
}

pub(crate) fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_ttl_boundary() {
        let s = OidcAuthState {
            role_name: "r".into(),
            redirect_uri: "http://x".into(),
            nonce: "n".into(),
            code_verifier: "v".into(),
            created_at_unix: 1_000,
        };
        // Exactly at the TTL is still fresh; one past it is stale.
        assert!(!s.is_expired(1_000 + STATE_TTL_SECS));
        assert!(s.is_expired(1_000 + STATE_TTL_SECS + 1));
    }
}
