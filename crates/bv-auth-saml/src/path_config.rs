//! IdP-level SAML configuration.
//!
//! Stored at `config` (single entry per mount). Holds the IdP
//! metadata source (URL or inline XML), the Service Provider entity
//! id + ACS URL, the IdP SSO endpoint, and the IdP signing
//! certificate that Phase 3's XML-signature verification will use to
//! validate assertions.
//!
//! `idp_cert` is stored as-written (the barrier handles
//! encryption-at-rest) and **redacted on read** so that a leaked
//! sudo-token in the audit log doesn't also surface the pinned
//! certificate bytes. Metadata XML is similarly redacted — operators
//! can re-fetch it from the IdP if they need to inspect it.

use std::{collections::HashMap, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{SamlBackend, SamlBackendInner};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

pub(crate) const CONFIG_KEY: &str = "config";

/// IdP-level configuration. Serialized as JSON to the mount's
/// barrier view.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SamlConfig {
    /// URL the SP should fetch to retrieve the IdP's metadata XML.
    /// Either this or `idp_metadata_xml` must be set — metadata-URL
    /// is preferred because it allows IdP cert rotation without a
    /// vault admin touching the config.
    #[serde(default)]
    pub idp_metadata_url: String,
    /// Inline IdP metadata XML, for air-gapped deployments or IdPs
    /// that do not publish a metadata endpoint. Redacted on read.
    #[serde(default)]
    pub idp_metadata_xml: String,
    /// SP entity id — the `Issuer` value we put on outgoing
    /// AuthnRequests and the `Audience` we expect in incoming
    /// assertions. Typically a URL identifying this vault.
    #[serde(default)]
    pub entity_id: String,
    /// Assertion Consumer Service URL — where the IdP POSTs the
    /// SAML Response after the user authenticates. Must match the
    /// `Destination` attribute on incoming responses.
    #[serde(default)]
    pub acs_url: String,
    /// IdP single-sign-on endpoint (HTTP-Redirect or HTTP-POST
    /// binding URL). May be left blank when `idp_metadata_url` is
    /// set — in that case Phase 3 will derive it from metadata.
    #[serde(default)]
    pub idp_sso_url: String,
    /// IdP single-logout endpoint, optional. Empty disables SLO.
    #[serde(default)]
    pub idp_slo_url: String,
    /// IdP signing certificate (PEM). Used to verify the XML
    /// signature on incoming SAML Responses. Redacted on read.
    #[serde(default)]
    pub idp_cert: String,
    /// Default role used when `login` is called without an explicit
    /// `role` parameter.
    #[serde(default)]
    pub default_role: String,
    /// Whitelist of post-login redirect URIs the client may request.
    /// Empty means "accept any URI we're handed", which is only
    /// appropriate for development. Roles can narrow this further.
    #[serde(default)]
    pub allowed_redirect_uris: Vec<String>,
}

impl SamlConfig {
    /// Read the config entry from storage. Returns `None` when the
    /// mount hasn't been configured yet, which is the only
    /// acceptable state before an admin does a `POST config`.
    pub async fn load(req: &Request) -> Result<Option<Self>, RvError> {
        match req.storage_get(CONFIG_KEY).await? {
            Some(entry) => Ok(Some(serde_json::from_slice(&entry.value)?)),
            None => Ok(None),
        }
    }

    /// Redacted form for API reads. Mirrors the OIDC `*_set` boolean
    /// pattern for the two sensitive fields so operators can confirm
    /// they are populated without the bytes surfacing in logs.
    fn to_public_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert(
            "idp_metadata_url".into(),
            Value::String(self.idp_metadata_url.clone()),
        );
        m.insert(
            "idp_metadata_xml_set".into(),
            Value::Bool(!self.idp_metadata_xml.is_empty()),
        );
        m.insert("entity_id".into(), Value::String(self.entity_id.clone()));
        m.insert("acs_url".into(), Value::String(self.acs_url.clone()));
        m.insert(
            "idp_sso_url".into(),
            Value::String(self.idp_sso_url.clone()),
        );
        m.insert(
            "idp_slo_url".into(),
            Value::String(self.idp_slo_url.clone()),
        );
        m.insert(
            "idp_cert_set".into(),
            Value::Bool(!self.idp_cert.is_empty()),
        );
        m.insert(
            "default_role".into(),
            Value::String(self.default_role.clone()),
        );
        m.insert(
            "allowed_redirect_uris".into(),
            Value::Array(
                self.allowed_redirect_uris
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        m
    }
}

impl SamlBackend {
    pub fn config_path(&self) -> Path {
        let this = self.inner.clone();
        let r = this.clone();
        let w = this.clone();
        new_path!({
            pattern: r"config",
            fields: {
                "idp_metadata_url": {
                    field_type: FieldType::Str,
                    description: "URL to fetch the IdP metadata XML (preferred over inline XML)."
                },
                "idp_metadata_xml": {
                    field_type: FieldType::SecretStr,
                    description: "Inline IdP metadata XML for air-gapped deployments. Redacted on read."
                },
                "entity_id": {
                    field_type: FieldType::Str,
                    description: "Service Provider entity id — the `Issuer` value on AuthnRequests."
                },
                "acs_url": {
                    field_type: FieldType::Str,
                    description: "Assertion Consumer Service URL — where the IdP POSTs the SAML Response."
                },
                "idp_sso_url": {
                    field_type: FieldType::Str,
                    description: "IdP single-sign-on endpoint URL. May be derived from metadata when blank."
                },
                "idp_slo_url": {
                    field_type: FieldType::Str,
                    description: "IdP single-logout endpoint URL. Optional."
                },
                "idp_cert": {
                    field_type: FieldType::SecretStr,
                    description: "IdP signing certificate (PEM) used to verify SAML Response signatures. Redacted on read."
                },
                "default_role": {
                    field_type: FieldType::Str,
                    description: "Role used when `login` is called without an explicit `role`."
                },
                "allowed_redirect_uris": {
                    field_type: FieldType::CommaStringSlice,
                    description: "Whitelist of redirect URIs that clients may request."
                }
            },
            operations: [
                {op: Operation::Read,  handler: r.read_config},
                {op: Operation::Write, handler: w.write_config}
            ],
            help: "Read or write the SAML IdP configuration for this mount."
        })
    }
}

#[maybe_async::maybe_async]
impl SamlBackendInner {
    pub async fn read_config(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let Some(cfg) = SamlConfig::load(req).await? else {
            return Ok(None);
        };
        Ok(Some(Response::data_response(Some(cfg.to_public_map()))))
    }

    pub async fn write_config(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        // Load existing (if any) so a partial write doesn't clear
        // fields the caller didn't provide. This lets an operator
        // rotate only the IdP cert without re-entering the ACS URL.
        let mut cfg = SamlConfig::load(req).await?.unwrap_or_default();

        if let Ok(Value::String(v)) = req.get_data("idp_metadata_url") {
            cfg.idp_metadata_url = v;
        }
        if let Ok(Value::String(v)) = req.get_data("idp_metadata_xml") {
            cfg.idp_metadata_xml = v;
        }
        if let Ok(Value::String(v)) = req.get_data("entity_id") {
            cfg.entity_id = v;
        }
        if let Ok(Value::String(v)) = req.get_data("acs_url") {
            cfg.acs_url = v;
        }
        if let Ok(Value::String(v)) = req.get_data("idp_sso_url") {
            cfg.idp_sso_url = v;
        }
        if let Ok(Value::String(v)) = req.get_data("idp_slo_url") {
            cfg.idp_slo_url = v;
        }
        if let Ok(Value::String(v)) = req.get_data("idp_cert") {
            cfg.idp_cert = v;
        }
        if let Ok(Value::String(v)) = req.get_data("default_role") {
            cfg.default_role = v;
        }
        if let Ok(v) = req.get_data("allowed_redirect_uris") {
            cfg.allowed_redirect_uris = parse_string_list(&v);
        }

        // Minimum-viable validation. We require `entity_id` + `acs_url`
        // because they identify *this* SP — neither can be derived
        // from IdP metadata. At least one IdP metadata source
        // (metadata URL, inline XML, or a raw SSO URL + cert pair)
        // must be present so Phase 3 has something to work with.
        if cfg.entity_id.trim().is_empty() {
            return Err(RvError::ErrString(
                "saml: `entity_id` is required".into(),
            ));
        }
        if cfg.acs_url.trim().is_empty() {
            return Err(RvError::ErrString("saml: `acs_url` is required".into()));
        }
        let has_metadata = !cfg.idp_metadata_url.trim().is_empty()
            || !cfg.idp_metadata_xml.trim().is_empty();
        let has_manual_idp =
            !cfg.idp_sso_url.trim().is_empty() && !cfg.idp_cert.trim().is_empty();
        if !has_metadata && !has_manual_idp {
            return Err(RvError::ErrString(
                "saml: must set either `idp_metadata_url`/`idp_metadata_xml` or both \
                 `idp_sso_url` and `idp_cert`"
                    .into(),
            ));
        }

        let bytes = serde_json::to_vec(&cfg)?;
        req.storage_put(&StorageEntry {
            key: CONFIG_KEY.to_string(),
            value: bytes,
        })
        .await?;
        Ok(None)
    }
}

/// Accept either a CommaStringSlice (`Value::Array(...)`) or a plain
/// comma-separated `Value::String` at the field layer. Mirrors the
/// identical helper in `oidc::path_config` — the logical-layer's
/// CommaStringSlice normaliser sometimes passes one form, sometimes
/// the other depending on the request shape.
fn parse_string_list(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .collect(),
        Value::String(s) => s
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_public_map_redacts_cert_and_metadata_xml() {
        let cfg = SamlConfig {
            idp_metadata_url: "https://idp.example.com/metadata".into(),
            idp_metadata_xml: "<EntityDescriptor>...private...</EntityDescriptor>".into(),
            entity_id: "https://sp.example.com".into(),
            acs_url: "https://sp.example.com/acs".into(),
            idp_sso_url: "https://idp.example.com/sso".into(),
            idp_slo_url: String::new(),
            idp_cert: "-----BEGIN CERTIFICATE-----\nSECRET\n-----END CERTIFICATE-----".into(),
            default_role: "user".into(),
            allowed_redirect_uris: vec!["http://localhost/cb".into()],
        };
        let m = cfg.to_public_map();
        assert_eq!(
            m.get("idp_cert_set").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            m.get("idp_metadata_xml_set").and_then(Value::as_bool),
            Some(true)
        );
        let rendered = serde_json::to_string(&m).unwrap();
        assert!(
            !rendered.contains("SECRET"),
            "IdP cert bytes leaked into serialized output"
        );
        assert!(
            !rendered.contains("...private..."),
            "Inline metadata XML leaked into serialized output"
        );
    }

    #[test]
    fn to_public_map_surfaces_absence() {
        let cfg = SamlConfig::default();
        let m = cfg.to_public_map();
        assert_eq!(
            m.get("idp_cert_set").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            m.get("idp_metadata_xml_set").and_then(Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn parse_string_list_accepts_array_and_comma_string() {
        assert_eq!(
            parse_string_list(&Value::Array(vec![
                Value::String("a".into()),
                Value::String("b".into())
            ])),
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(
            parse_string_list(&Value::String("a, b , ,c".into())),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
        assert!(parse_string_list(&Value::Null).is_empty());
    }
}
