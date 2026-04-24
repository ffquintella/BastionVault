//! `callback` — finish the OIDC consent flow.
//!
//! Flow:
//!   1. Client POSTs `callback` with `{state, code}` it received
//!      from the IdP's redirect.
//!   2. Load-and-delete the `state/<state>` entry (single-use).
//!   3. Reject if the state is stale (`STATE_TTL_SECS` exceeded).
//!   4. Re-create the `CoreClient` via discovery (fresh JWKS so
//!      key rotations on the IdP side propagate).
//!   5. Exchange the `code` + `code_verifier` for tokens.
//!   6. Verify the ID token (signature via JWKS, issuer, audience,
//!      nonce, expiry) — handled by `openidconnect`.
//!   7. Extract claims, validate role `bound_audiences` +
//!      `bound_claims`, project `claim_mappings` onto token
//!      metadata, and build the `Auth` reply for the token store.
//!
//! Failure in any step returns a specific `RvError::ErrString` so
//! operators can debug. The only error surface the client ever
//! sees is a failed login, not the IdP's internals.

#[allow(unused_imports)]
use std::{collections::HashMap, sync::Arc, time::Duration};

use openidconnect::{
    core::{CoreClient, CoreProviderMetadata},
    AuthorizationCode, ClientId, ClientSecret, IssuerUrl, Nonce, PkceCodeVerifier, RedirectUrl,
    TokenResponse,
};
use serde_json::{Map, Value};

use super::{
    path_auth_url::{reqwest_http_client, OidcAuthState, STATE_PREFIX},
    path_config::OidcConfig,
    path_roles::OidcRoleEntry,
    OidcBackend, OidcBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{
        Auth, Backend, Field, FieldType, Lease, Operation, Path, PathOperation, Request, Response,
    },
    new_fields, new_fields_internal, new_path, new_path_internal,
    utils::policy::equivalent_policies,
};

impl OidcBackend {
    pub fn callback_path(&self) -> Path {
        let this = self.inner.clone();
        new_path!({
            pattern: r"callback",
            fields: {
                "state": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Opaque state value returned by the IdP's redirect."
                },
                "code": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Authorization code returned by the IdP."
                }
            },
            operations: [
                {op: Operation::Write, handler: this.callback}
            ],
            help: "Exchange an IdP authorization code for a vault token."
        })
    }
}

#[maybe_async::maybe_async]
impl OidcBackendInner {
    pub async fn callback(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let state = req
            .get_data_as_str("state")
            .unwrap_or_default()
            .trim()
            .to_string();
        let code = req
            .get_data_as_str("code")
            .unwrap_or_default()
            .trim()
            .to_string();
        if state.is_empty() || code.is_empty() {
            return Err(RvError::ErrString(
                "oidc: `state` and `code` are required".into(),
            ));
        }

        // Load-and-delete the per-flow state. Deleting first defends
        // against replay: if two parallel `callback`s arrive for the
        // same state, exactly one wins the storage-delete and the
        // other falls into the "no such state" branch below.
        let state_key = format!("{STATE_PREFIX}{state}");
        let stored = req.storage_get(&state_key).await?.ok_or_else(|| {
            RvError::ErrString(
                "oidc: unknown or expired state — re-run `auth_url` to start over".into(),
            )
        })?;
        req.storage_delete(&state_key).await?;
        let auth_state: OidcAuthState = serde_json::from_slice(&stored.value)?;

        if auth_state.is_expired(super::path_auth_url::unix_now()) {
            return Err(RvError::ErrString(
                "oidc: state expired — re-run `auth_url`".into(),
            ));
        }

        let cfg = OidcConfig::load(req).await?.ok_or_else(|| {
            RvError::ErrString(
                "oidc: provider config missing during callback — mount may be misconfigured"
                    .into(),
            )
        })?;
        let role =
            OidcRoleEntry::load(req, &auth_state.role_name).await?.ok_or_else(|| {
                RvError::ErrString(format!(
                    "oidc: role `{}` no longer exists — rejecting login",
                    auth_state.role_name
                ))
            })?;

        // Re-construct the client the same way `auth_url` did. We
        // rediscover every callback so an IdP-side key rotation
        // between `auth_url` and `callback` is picked up without a
        // vault restart.
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
            RedirectUrl::new(auth_state.redirect_uri.clone())
                .map_err(|e| RvError::ErrString(format!("oidc: bad redirect_uri: {e}")))?,
        );

        let pkce_verifier = PkceCodeVerifier::new(auth_state.code_verifier.clone());
        let token_response = client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|e| RvError::ErrString(format!("oidc: code exchange setup: {e}")))?
            .set_pkce_verifier(pkce_verifier)
            .request_async(&http)
            .await
            .map_err(|e| RvError::ErrString(format!("oidc: code exchange: {e}")))?;

        let id_token = token_response
            .id_token()
            .ok_or_else(|| RvError::ErrString("oidc: no id_token in token response".into()))?;
        let nonce = Nonce::new(auth_state.nonce.clone());
        let claims = id_token
            .claims(&client.id_token_verifier(), &nonce)
            .map_err(|e| RvError::ErrString(format!("oidc: id_token verification: {e}")))?;

        // Project the strongly-typed Claims into a JSON map so
        // role.validate_claims + role.claim_mappings can work on
        // arbitrary fields without having to hand-enumerate every
        // well-known claim.
        let claims_json = serde_json::to_value(claims)
            .map_err(|e| RvError::ErrString(format!("oidc: serialize claims: {e}")))?;
        let claims_map: Map<String, Value> = match claims_json {
            Value::Object(m) => m,
            _ => Map::new(),
        };

        // Audience(s). openidconnect returns a Vec<Audience>; we
        // project to Vec<String> for `validate_claims`.
        let audiences: Vec<String> = claims
            .audiences()
            .iter()
            .map(|a| a.to_string())
            .collect();

        role.validate_claims(&audiences, &claims_map)?;

        // Build the Auth reply.
        let user_claim_name = if role.user_claim.is_empty() {
            "sub"
        } else {
            role.user_claim.as_str()
        };
        let display_name = claims_map
            .get(user_claim_name)
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| claims.subject().as_str())
            .to_string();

        let mut metadata: HashMap<String, String> = HashMap::new();
        metadata.insert("role".to_string(), auth_state.role_name.clone());
        metadata.insert("subject".to_string(), claims.subject().as_str().to_string());
        metadata.insert("username".to_string(), display_name.clone());
        metadata.insert("auth_method".to_string(), "oidc".to_string());

        for (claim_name, meta_key) in &role.claim_mappings {
            if let Some(v) = claims_map.get(claim_name) {
                metadata.insert(meta_key.clone(), claim_to_string(v));
            }
        }
        if !role.groups_claim.is_empty() {
            if let Some(v) = claims_map.get(&role.groups_claim) {
                metadata.insert(
                    "groups".to_string(),
                    claim_to_string(v),
                );
            }
        }

        let mut auth = Auth::default();
        auth.display_name = display_name;
        auth.policies = role.policies.clone();
        auth.metadata = metadata;
        auth.lease = Lease::default();
        if role.token_ttl_secs > 0 {
            auth.lease.ttl = Duration::from_secs(role.token_ttl_secs);
        }
        if role.token_max_ttl_secs > 0 {
            auth.lease.max_ttl = Duration::from_secs(role.token_max_ttl_secs);
        }

        Ok(Some(Response {
            auth: Some(auth),
            ..Default::default()
        }))
    }

    /// Renewal path — the token store calls this when a client
    /// tries to extend a token lifetime. We re-load the role to
    /// make sure it still exists and its policies haven't drifted;
    /// if they have, renewal fails and the client gets a fresh
    /// token by running the consent flow again.
    pub async fn login_renew(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let auth = req
            .auth
            .as_ref()
            .ok_or_else(|| RvError::ErrString("oidc renew: missing auth on request".into()))?;
        let role_name = auth
            .metadata
            .get("role")
            .cloned()
            .unwrap_or_default();
        if role_name.is_empty() {
            return Err(RvError::ErrString(
                "oidc renew: role metadata missing on token".into(),
            ));
        }
        let role = OidcRoleEntry::load(req, &role_name).await?.ok_or_else(|| {
            RvError::ErrString(format!("oidc renew: role `{role_name}` no longer exists"))
        })?;
        if !equivalent_policies(&auth.policies, &role.policies) {
            return Err(RvError::ErrString(
                "oidc renew: role policies drifted since token was minted".into(),
            ));
        }

        let mut renewed = Auth::default();
        renewed.display_name = auth.display_name.clone();
        renewed.policies = role.policies.clone();
        renewed.metadata = auth.metadata.clone();
        renewed.lease = Lease::default();
        if role.token_ttl_secs > 0 {
            renewed.lease.ttl = Duration::from_secs(role.token_ttl_secs);
        }
        if role.token_max_ttl_secs > 0 {
            renewed.lease.max_ttl = Duration::from_secs(role.token_max_ttl_secs);
        }
        Ok(Some(Response {
            auth: Some(renewed),
            ..Default::default()
        }))
    }
}

/// Flatten a claim value into a single string suitable for Vault
/// token metadata. Arrays become comma-separated lists; objects
/// serialize to JSON (unusual but not catastrophic — the caller
/// decides whether to mount such a claim at all).
fn claim_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        Value::Array(arr) => arr
            .iter()
            .map(claim_to_string)
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => serde_json::to_string(v).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_to_string_flattens_primitives() {
        assert_eq!(claim_to_string(&Value::String("a".into())), "a");
        assert_eq!(claim_to_string(&Value::Number(42.into())), "42");
        assert_eq!(claim_to_string(&Value::Bool(true)), "true");
        assert_eq!(claim_to_string(&Value::Null), "");
    }

    #[test]
    fn claim_to_string_joins_arrays() {
        let v = Value::Array(vec![
            Value::String("admins".into()),
            Value::String("devs".into()),
        ]);
        assert_eq!(claim_to_string(&v), "admins,devs");
    }

    #[test]
    fn claim_to_string_serializes_objects() {
        let v: Value = serde_json::from_str(r#"{"k":"v"}"#).unwrap();
        assert_eq!(claim_to_string(&v), r#"{"k":"v"}"#);
    }
}
