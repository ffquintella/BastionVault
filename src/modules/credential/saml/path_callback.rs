//! `auth/<mount>/callback` — the Assertion Consumer Service (ACS)
//! endpoint the IdP POSTs a signed SAML Response to.
//!
//! Flow:
//!   1. Client POSTs `{saml_response, relay_state}`. The
//!      `saml_response` value is the base64-encoded Response as
//!      handed to the user-agent by the IdP's HTTP-POST binding.
//!   2. Load-and-delete the state record keyed by `relay_state`.
//!   3. base64-decode the Response.
//!   4. Parse into `ParsedResponse`.
//!   5. Run structural validation (timestamps, issuer, audience,
//!      InResponseTo, Destination) against the configured SP entity
//!      id and the stored request id.
//!   6. Verify the XML signature against the configured IdP cert.
//!   7. Project SAML attributes into the role's metadata mappings
//!      and produce an `Auth` with the role's policies attached.
//!
//! The TokenStore picks up the `Auth` and mints the vault token;
//! this handler does not touch token state directly.

use std::{collections::HashMap, sync::Arc};

use base64::{engine::general_purpose, Engine as _};
use serde_json::{Map, Value};

use super::path_config::SamlConfig;
use super::path_login::{load_and_delete_state, STATE_TTL_SECS};
use super::path_roles::SamlRoleEntry;
use super::response::parse_response;
use super::validate::{now_unix, validate, ValidationInput, DEFAULT_CLOCK_SKEW_SECS};
use super::verify::{parse_rsa_public_key_from_pem, verify_signed_assertion};
use super::{SamlBackend, SamlBackendInner};

use crate::{
    context::Context,
    errors::RvError,
    logical::{
        Auth, Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response,
    },
    new_fields, new_fields_internal, new_path, new_path_internal,
};

impl SamlBackend {
    pub fn callback_path(&self) -> Path {
        let this = self.inner.clone();
        new_path!({
            pattern: r"callback",
            fields: {
                "saml_response": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Base64-encoded SAML Response as POSTed by the IdP."
                },
                "relay_state": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "RelayState returned by the IdP, matching the value set by `login`."
                }
            },
            operations: [
                {op: Operation::Write, handler: this.handle_callback}
            ],
            help: "Process a SAML Response and issue a vault token."
        })
    }

    pub fn login_renew_handler(&self) -> super::SamlBackendInner {
        // Exists so `new_backend`'s renew-handler macro can bind a
        // named handle the way the OIDC backend does. Not a clone
        // of the trait object — callers use `self.inner.clone()`.
        SamlBackendInner {
            core: self.inner.core.clone(),
        }
    }
}

#[maybe_async::maybe_async]
impl SamlBackendInner {
    pub async fn handle_callback(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let cfg = SamlConfig::load(req)
            .await?
            .ok_or_else(|| RvError::ErrString("saml: mount is not configured".into()))?;

        let saml_response_b64 = req
            .get_data_as_str("saml_response")
            .unwrap_or_default();
        let relay_state = req.get_data_as_str("relay_state").unwrap_or_default();
        if saml_response_b64.trim().is_empty() || relay_state.trim().is_empty() {
            return Err(RvError::ErrString(
                "saml: both `saml_response` and `relay_state` are required".into(),
            ));
        }

        // Load-and-delete the state record (single-use).
        let state = load_and_delete_state(req, &relay_state)
            .await?
            .ok_or_else(|| {
                RvError::ErrString(
                    "saml: relay_state is unknown, expired, or already redeemed".into(),
                )
            })?;
        if now_unix().saturating_sub(state.created_at) > STATE_TTL_SECS {
            return Err(RvError::ErrString(
                "saml: relay_state expired — start a new login".into(),
            ));
        }

        // Decode the Response XML. Accept with and without whitespace
        // padding since operators sometimes paste the value manually.
        let xml = general_purpose::STANDARD
            .decode(saml_response_b64.replace(char::is_whitespace, ""))
            .map_err(|e| {
                RvError::ErrString(format!("saml: saml_response is not valid base64: {e}"))
            })?;

        let parsed = parse_response(&xml)?;

        // Structural validation against the stored request id +
        // configured SP entity id.
        let input = ValidationInput {
            expected_destination: &cfg.acs_url,
            expected_issuer: idp_entity_id(&cfg),
            expected_audience: &cfg.entity_id,
            expected_in_response_to: &state.request_id,
            now_unix: now_unix(),
            clock_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
        };
        validate(&parsed, &input)?;

        // Cryptographic verification.
        if cfg.idp_cert.trim().is_empty() {
            return Err(RvError::ErrString(
                "saml: no idp_cert configured — cannot verify the assertion signature".into(),
            ));
        }
        let pubkey = parse_rsa_public_key_from_pem(&cfg.idp_cert)?;
        verify_signed_assertion(&parsed, &pubkey)?;

        // Load the role so we know which policies to attach.
        let role = SamlRoleEntry::load(req, &state.role_name)
            .await?
            .ok_or_else(|| {
                RvError::ErrString(format!(
                    "saml: role `{}` was deleted between login and callback",
                    state.role_name
                ))
            })?;

        let assertion = parsed.assertion.as_ref().unwrap(); // validate() already ensured Some

        // Attribute-map projection: only surface the attributes the
        // role explicitly maps, plus the groups attribute when
        // configured. Everything else stays in the IdP's response
        // and is not exposed to vault policies.
        let mut metadata: HashMap<String, String> = HashMap::new();
        for (saml_attr, vault_key) in &role.attribute_mappings {
            if let Some(vals) = assertion.attributes.get(saml_attr) {
                if let Some(first) = vals.first() {
                    metadata.insert(vault_key.clone(), first.clone());
                }
            }
        }
        if !role.groups_attribute.is_empty() {
            if let Some(groups) = assertion.attributes.get(&role.groups_attribute) {
                metadata.insert("groups".into(), groups.join(","));
            }
        }
        metadata.insert("name_id".into(), assertion.name_id.clone());
        if !assertion.name_id_format.is_empty() {
            metadata.insert("name_id_format".into(), assertion.name_id_format.clone());
        }
        metadata.insert("role".into(), state.role_name.clone());

        // Role-level bound attributes + bound subjects were populated
        // by the admin; enforce them.
        let mut attributes_as_values: Map<String, Value> = Map::new();
        for (k, vs) in &assertion.attributes {
            attributes_as_values.insert(
                k.clone(),
                Value::Array(vs.iter().cloned().map(Value::String).collect()),
            );
        }
        role.validate_assertion(
            &assertion.name_id,
            &assertion.name_id_format,
            &attributes_as_values,
        )?;

        // Build the Auth response. TTL handling mirrors OIDC: 0
        // means "use the token store's default."
        let mut auth = Auth::default();
        auth.policies = role.policies.clone();
        auth.metadata = metadata;
        auth.display_name = assertion.name_id.clone();
        auth.ttl = std::time::Duration::from_secs(role.token_ttl_secs);
        auth.period = std::time::Duration::from_secs(role.token_max_ttl_secs);

        let mut resp = Response::default();
        resp.auth = Some(auth);
        Ok(Some(resp))
    }

    pub async fn login_renew(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        // Re-load the role that minted the original token and reject
        // renewal if it disappeared or its policies drifted — same
        // semantics as the OIDC `login_renew` handler.
        let role_name = req
            .auth
            .as_ref()
            .and_then(|a| a.metadata.get("role").cloned())
            .ok_or_else(|| {
                RvError::ErrString("saml: renew has no role on the auth metadata".into())
            })?;
        let role = SamlRoleEntry::load(req, &role_name)
            .await?
            .ok_or_else(|| {
                RvError::ErrString(format!(
                    "saml: role `{role_name}` no longer exists, rejecting renewal"
                ))
            })?;

        let want_policies: std::collections::BTreeSet<&str> =
            role.policies.iter().map(|s| s.as_str()).collect();
        let have_policies: std::collections::BTreeSet<&str> = req
            .auth
            .as_ref()
            .map(|a| a.policies.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default();
        if want_policies != have_policies {
            return Err(RvError::ErrString(
                "saml: role policies changed since token mint, refusing renewal".into(),
            ));
        }

        let mut resp = Response::default();
        if let Some(mut a) = req.auth.clone() {
            a.ttl = std::time::Duration::from_secs(role.token_ttl_secs);
            a.period = std::time::Duration::from_secs(role.token_max_ttl_secs);
            resp.auth = Some(a);
        }
        Ok(Some(resp))
    }
}

/// Expected IdP entity id for validation. IdPs vary:
///   * Some set `Issuer` to the same URL as `idp_sso_url`'s origin
///   * Some use a dedicated entity id configured separately
///
/// We trust `idp_sso_url` as the stable identifier today — extending
/// the config with an explicit `idp_entity_id` is a small follow-up
/// if operators hit mismatches.
fn idp_entity_id(cfg: &SamlConfig) -> &str {
    if !cfg.idp_sso_url.is_empty() {
        &cfg.idp_sso_url
    } else {
        &cfg.entity_id
    }
}
