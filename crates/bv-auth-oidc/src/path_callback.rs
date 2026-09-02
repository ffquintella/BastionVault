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
    /// Public entry point: runs the consent-finishing exchange via
    /// `callback_inner` and records the outcome to the login-audit trail
    /// under the `oidc/` mount, so SSO sign-ins surface on the admin
    /// Audit page alongside password / FIDO2 / token logins. The
    /// principal is the resolved display name on success and `(unknown)`
    /// on a rejected attempt (the user is only known once the ID token
    /// verifies). The audit write is best-effort and never alters the
    /// login result.
    pub async fn callback(
        &self,
        backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let remote_addr = req.connection.as_ref().map(|c| c.peer_addr.clone()).unwrap_or_default();
        let result = self.callback_inner(backend, req).await;
        let (success, details) =
            bv_auth_audit::login_outcome(&result);
        let username = match &result {
            Ok(Some(resp)) => resp
                .auth
                .as_ref()
                .map(|a| a.display_name.clone())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "(unknown)".to_string()),
            _ => "(unknown)".to_string(),
        };
        bv_auth_audit::record_login(
            &self.core,
            "oidc/",
            &username,
            success,
            &remote_addr,
            &details,
        )
        .await;
        result
    }

    async fn callback_inner(
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

        // Multi-tenancy: bind the session to a namespace, exactly as `userpass/`
        // does. The IdP redirect carries no `X-BastionVault-Namespace` header, so
        // this resolves to the principal's *first assigned* namespace when one is
        // recorded and to root otherwise. Without a binding the issued token read
        // back as root-bound and non-child-visible, and — with no `mount_path`
        // below — could not be widened by a namespace assignment either, so an
        // SSO principal granted several namespaces could reach none of them.
        let (ns_path, ns_uuid) = crate::kernel_api::namespace::login_namespace_for_principal(
            &self.core,
            req,
            "oidc/",
            &display_name,
        )
        .await?;

        // Refuse the login if the principal's assignment excludes that namespace.
        // No record ⇒ unrestricted; fails closed otherwise.
        crate::kernel_api::namespace::enforce_login_assignment(
            &self.core,
            "oidc/",
            &display_name,
            &ns_path,
        )
        .await?;

        let mut metadata: HashMap<String, String> = HashMap::new();
        metadata.insert("role".to_string(), auth_state.role_name.clone());
        metadata.insert("subject".to_string(), claims.subject().as_str().to_string());
        metadata.insert("username".to_string(), display_name.clone());
        metadata.insert("auth_method".to_string(), "oidc".to_string());

        project_claim_mappings(
            &auth_state.role_name,
            &role.claim_mappings,
            &claims_map,
            &mut metadata,
        );
        if !role.groups_claim.is_empty() {
            if let Some(v) = claims_map.get(&role.groups_claim) {
                metadata.insert(
                    "groups".to_string(),
                    claim_to_string(v),
                );
            }
        }
        // The `(mount, name)` pair `NsAssignmentStore` is keyed by. Without it
        // `token_operable_resolved` cannot identify the principal, so no
        // assignment can widen the token and the holder is pinned to its login
        // namespace for the life of the session. Written *after* the role's
        // claim mappings so an IdP-supplied claim cannot rename the mount an
        // assignment is looked up under.
        metadata.insert("mount_path".to_string(), "oidc/".to_string());

        let mut auth = Auth::default();
        auth.display_name = display_name;
        auth.policies = role.policies.clone();
        auth.metadata = metadata;
        // Stamp the namespace binding. `child_visible` follows the namespace's
        // `child_visible_default` and fails safe to false.
        let child_visible =
            crate::kernel_api::namespace::login_child_visible(&self.core, &ns_path).await;
        crate::kernel_api::namespace::stamp_binding(
            &mut auth.metadata,
            &ns_path,
            &ns_uuid,
            child_visible,
        );
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

/// Project a role's `claim_mappings` onto the token's metadata, dropping any
/// mapping whose target is a reserved (backend-owned) key.
///
/// Read-old/write-new: `path_roles::write_role` refuses a reserved target, so
/// no role written after that check carries one — but a role persisted *before*
/// it can, and its stored JSON still deserializes. Dropping the mapping is the
/// fail-closed half: the IdP's value never reaches a backend-owned key, the
/// login still succeeds with the rest of the role intact, and the operator gets
/// a `security` record naming the role and the key so the role can be
/// rewritten. Refusing the login instead would lock out an SSO tenant on
/// upgrade for a role that is, in the common case, misconfigured by accident.
///
/// Only key names are logged. The claim's *value* is not: it is IdP-supplied
/// and these keys name principals.
fn project_claim_mappings(
    role_name: &str,
    mappings: &HashMap<String, String>,
    claims: &Map<String, Value>,
    metadata: &mut HashMap<String, String>,
) {
    for (claim_name, meta_key) in mappings {
        if crate::path_roles::reserved_mapping_target(meta_key) {
            log::warn!(
                target: "security",
                "oidc: role `{role_name}` maps claim `{claim_name}` onto reserved token metadata \
                 key `{meta_key}`; dropping the mapping. That key is set by the auth backend and \
                 read back as authorization input — rewrite the role's claim_mappings"
            );
            continue;
        }
        if let Some(v) = claims.get(claim_name) {
            metadata.insert(meta_key.clone(), claim_to_string(v));
        }
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

    fn mappings(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn claims(pairs: &[(&str, &str)]) -> Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), Value::String(v.to_string())))
            .collect()
    }

    #[test]
    fn unreserved_mappings_are_projected() {
        let mut metadata = HashMap::new();
        project_claim_mappings(
            "user",
            &mappings(&[("email", "email"), ("employee_id", "employee_id")]),
            &claims(&[("email", "a@example.com"), ("employee_id", "42")]),
            &mut metadata,
        );
        assert_eq!(metadata.get("email").map(String::as_str), Some("a@example.com"));
        assert_eq!(metadata.get("employee_id").map(String::as_str), Some("42"));
    }

    #[test]
    fn an_old_role_record_with_a_reserved_target_has_that_mapping_dropped() {
        // A role persisted before `write_role` learned to refuse a reserved
        // target: the stored JSON still deserializes, so the login path is
        // what has to fail closed.
        let role: crate::path_roles::OidcRoleEntry = serde_json::from_str(
            r#"{"claim_mappings":{"dept":"spiffe_id","email":"email"},
                "user_claim":"sub","policies":["default"]}"#,
        )
        .unwrap();
        assert_eq!(role.claim_mappings.len(), 2, "the old record still carries the reserved target");

        let mut metadata = HashMap::new();
        project_claim_mappings(
            "legacy",
            &role.claim_mappings,
            &claims(&[("dept", "engineering"), ("email", "a@example.com")]),
            &mut metadata,
        );

        // The whole point: an IdP claim must not be able to satisfy the
        // server-wide `require_machine_identity` gate.
        assert!(!metadata.contains_key("spiffe_id"), "{metadata:?}");
        // The rest of the role still works — dropping is per-mapping.
        assert_eq!(metadata.get("email").map(String::as_str), Some("a@example.com"));
    }

    #[test]
    fn a_reserved_target_cannot_overwrite_what_the_backend_wrote() {
        let mut metadata = HashMap::new();
        metadata.insert("username".to_string(), "alice".to_string());
        metadata.insert("mount_path".to_string(), "oidc/".to_string());
        project_claim_mappings(
            "legacy",
            &mappings(&[("dept", "username"), ("iss", "mount_path")]),
            &claims(&[("dept", "engineering"), ("iss", "ferrogate/")]),
            &mut metadata,
        );
        assert_eq!(metadata.get("username").map(String::as_str), Some("alice"));
        assert_eq!(metadata.get("mount_path").map(String::as_str), Some("oidc/"));
    }

    #[test]
    fn a_missing_claim_projects_nothing() {
        let mut metadata = HashMap::new();
        project_claim_mappings("user", &mappings(&[("email", "email")]), &claims(&[]), &mut metadata);
        assert!(metadata.is_empty());
    }
}
