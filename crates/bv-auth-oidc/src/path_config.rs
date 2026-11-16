//! Provider-level OIDC configuration.
//!
//! Stored at `config` (single entry per mount). Holds the discovery
//! URL, OAuth client identity, redirect-URI whitelist, and default
//! scopes that all roles on this mount share.
//!
//! `client_secret` is stored as-written (barrier handles encryption
//! at rest) and **redacted on read** so a leaked sudo-token on the
//! audit log doesn't also leak the secret.

use std::{collections::HashMap, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{OidcBackend, OidcBackendInner};
use crate::{
    context::Context,
    errors::RvError,
    http_client::normalize_discovery_ca_pem,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

pub(crate) const CONFIG_KEY: &str = "config";

/// Provider-level configuration. Serialized as JSON to the mount's
/// barrier view.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OidcConfig {
    /// Issuer URL pointing to the OIDC discovery document
    /// (`.well-known/openid-configuration`). The crate auto-appends
    /// the well-known path.
    #[serde(default)]
    pub oidc_discovery_url: String,
    #[serde(default)]
    pub oidc_client_id: String,
    /// Empty for public clients (PKCE-only). For confidential
    /// clients the secret is kept here and used during token
    /// exchange. Always redacted on read.
    #[serde(default)]
    pub oidc_client_secret: String,
    /// Default role used if the client doesn't specify one at
    /// `auth_url`.
    #[serde(default)]
    pub default_role: String,
    /// Whitelist of redirect URIs the client may request. Empty
    /// means "accept any URI we're handed", which is only
    /// appropriate for development — roles can narrow this
    /// further on a per-role basis.
    #[serde(default)]
    pub allowed_redirect_uris: Vec<String>,
    /// Scopes requested at auth-URL generation time. Defaults to
    /// `["openid","profile","email"]` when empty on write.
    #[serde(default)]
    pub oidc_scopes: Vec<String>,
    /// Extra trust anchors (one or more PEM CERTIFICATE blocks) for the
    /// HTTPS calls to the IdP: discovery, JWKS and the token exchange.
    /// Added to the built-in roots, never in place of them. Empty means
    /// none. Stored normalised (certificate blocks only); public, so
    /// returned on read. Absent in configs written before it existed.
    #[serde(default)]
    pub oidc_discovery_ca_pem: String,
}

impl OidcConfig {
    /// Read the config entry from storage. Returns `None` when the
    /// mount hasn't been configured yet, which is the only
    /// acceptable state before an admin does a `POST config`.
    pub async fn load(req: &Request) -> Result<Option<Self>, RvError> {
        match req.storage_get(CONFIG_KEY).await? {
            Some(entry) => Ok(Some(serde_json::from_slice(&entry.value)?)),
            None => Ok(None),
        }
    }

    /// Redacted form for API reads — removes the client secret but
    /// surfaces a boolean hint so operators know whether one is set.
    fn to_public_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("oidc_discovery_url".into(), Value::String(self.oidc_discovery_url.clone()));
        m.insert("oidc_client_id".into(), Value::String(self.oidc_client_id.clone()));
        m.insert("oidc_client_secret_set".into(), Value::Bool(!self.oidc_client_secret.is_empty()));
        m.insert("default_role".into(), Value::String(self.default_role.clone()));
        m.insert(
            "allowed_redirect_uris".into(),
            Value::Array(self.allowed_redirect_uris.iter().cloned().map(Value::String).collect()),
        );
        m.insert("oidc_scopes".into(), Value::Array(self.oidc_scopes.iter().cloned().map(Value::String).collect()));
        // Public CA certificates, not a secret: returned as stored.
        m.insert("oidc_discovery_ca_pem".into(), Value::String(self.oidc_discovery_ca_pem.clone()));
        m
    }
}

impl OidcBackend {
    pub fn config_path(&self) -> Path {
        let this = self.inner.clone();
        let r = this.clone();
        let w = this.clone();
        new_path!({
            pattern: r"config",
            fields: {
                "oidc_discovery_url": {
                    field_type: FieldType::Str,
                    description: "OIDC issuer / discovery URL (e.g. `https://accounts.google.com`)."
                },
                "oidc_client_id": {
                    field_type: FieldType::Str,
                    description: "OAuth 2.0 client id registered with the IdP."
                },
                "oidc_client_secret": {
                    field_type: FieldType::SecretStr,
                    description: "OAuth 2.0 client secret. Omit for public/PKCE-only clients. Redacted on read."
                },
                "default_role": {
                    field_type: FieldType::Str,
                    description: "Role used when `auth_url` is called without an explicit `role`."
                },
                "allowed_redirect_uris": {
                    field_type: FieldType::CommaStringSlice,
                    description: "Whitelist of redirect URIs that clients may request."
                },
                "oidc_scopes": {
                    field_type: FieldType::CommaStringSlice,
                    description: "Scopes requested at auth time; defaults to openid,profile,email when empty."
                },
                "oidc_discovery_ca_pem": {
                    field_type: FieldType::Str,
                    description: "Extra CA certificate(s), PEM, trusted in addition to the built-in roots for discovery, JWKS and token exchange (e.g. the intermediate an IdP does not send). At most 8 certificates and 64 KiB; no private keys. Empty clears; omit to keep."
                }
            },
            operations: [
                {op: Operation::Read,  handler: r.read_config},
                {op: Operation::Write, handler: w.write_config}
            ],
            help: "Read or write the OIDC provider configuration for this mount."
        })
    }
}

#[maybe_async::maybe_async]
impl OidcBackendInner {
    pub async fn read_config(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let Some(cfg) = OidcConfig::load(req).await? else {
            return Ok(None);
        };
        Ok(Some(Response::data_response(Some(cfg.to_public_map()))))
    }

    pub async fn write_config(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        // Load existing (if any) so a partial write doesn't clear
        // fields the caller didn't provide. This lets an operator
        // rotate only the client secret without re-entering the
        // discovery URL + redirect list.
        let mut cfg = OidcConfig::load(req).await?.unwrap_or_default();

        if let Ok(Value::String(v)) = req.get_data("oidc_discovery_url") {
            cfg.oidc_discovery_url = v;
        }
        if let Ok(Value::String(v)) = req.get_data("oidc_client_id") {
            cfg.oidc_client_id = v;
        }
        if let Ok(Value::String(v)) = req.get_data("oidc_client_secret") {
            cfg.oidc_client_secret = v;
        }
        if let Ok(Value::String(v)) = req.get_data("default_role") {
            cfg.default_role = v;
        }
        if let Ok(v) = req.get_data("allowed_redirect_uris") {
            cfg.allowed_redirect_uris = parse_string_list(&v);
        }
        if let Ok(v) = req.get_data("oidc_scopes") {
            let scopes = parse_string_list(&v);
            if !scopes.is_empty() {
                cfg.oidc_scopes = scopes;
            }
        }
        // Unlike the fields above, a value of the wrong type is an error
        // rather than ignored: silently keeping the old anchors would hide
        // a rejected trust change from the operator.
        let ca_pem_input = match req.get_data("oidc_discovery_ca_pem") {
            Ok(v) => Some(v),
            Err(RvError::ErrRequestFieldNotFound) | Err(RvError::ErrRequestNoData) => None,
            Err(RvError::ErrRequestFieldInvalid) => return Err(discovery_ca_pem_not_a_string()),
            Err(e) => return Err(e),
        };
        cfg.oidc_discovery_ca_pem = merge_discovery_ca_pem(&cfg.oidc_discovery_ca_pem, ca_pem_input.as_ref())?;

        // Minimum-viable validation: discovery URL and client id
        // are both required for the backend to function at all.
        if cfg.oidc_discovery_url.trim().is_empty() {
            return Err(RvError::ErrString("oidc: `oidc_discovery_url` is required".into()));
        }
        if cfg.oidc_client_id.trim().is_empty() {
            return Err(RvError::ErrString("oidc: `oidc_client_id` is required".into()));
        }

        // Default scopes — the RFC-standard minimum for an OIDC
        // flow is `openid`; `profile` + `email` are the near-universal
        // defaults that surface `preferred_username` and the email
        // claim, both commonly used in role bound_claims.
        if cfg.oidc_scopes.is_empty() {
            cfg.oidc_scopes = vec!["openid".into(), "profile".into(), "email".into()];
        }

        let bytes = serde_json::to_vec(&cfg)?;
        req.storage_put(&StorageEntry { key: CONFIG_KEY.to_string(), value: bytes }).await?;
        Ok(None)
    }
}

/// New value of `oidc_discovery_ca_pem` after a write: `None` (field
/// absent) keeps `current`, a blank string clears it, anything else must
/// pass `normalize_discovery_ca_pem` or the whole write is refused.
fn merge_discovery_ca_pem(current: &str, input: Option<&Value>) -> Result<String, RvError> {
    match input {
        None => Ok(current.to_string()),
        Some(Value::String(pem)) => normalize_discovery_ca_pem(pem),
        Some(_) => Err(discovery_ca_pem_not_a_string()),
    }
}

fn discovery_ca_pem_not_a_string() -> RvError {
    RvError::ErrString("oidc: `oidc_discovery_ca_pem` must be a string of PEM text".into())
}

/// Accept either a CommaStringSlice (`Value::Array(...)`) or a plain
/// comma-separated `Value::String` at the field layer — the logical-
/// layer's CommaStringSlice normaliser sometimes passes one form,
/// sometimes the other depending on the request shape.
fn parse_string_list(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => {
            a.iter().filter_map(|x| x.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect()
        }
        Value::String(s) => s.split(',').map(|p| p.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::test_pki;

    #[test]
    fn to_public_map_redacts_secret() {
        let cfg = OidcConfig {
            oidc_discovery_url: "https://example.com".into(),
            oidc_client_id: "cid".into(),
            oidc_client_secret: "highly-sensitive".into(),
            default_role: "user".into(),
            allowed_redirect_uris: vec!["http://localhost/cb".into()],
            oidc_scopes: vec!["openid".into()],
            oidc_discovery_ca_pem: String::new(),
        };
        let m = cfg.to_public_map();
        // The secret must never appear in the serialized output.
        assert_eq!(m.get("oidc_client_secret_set").and_then(Value::as_bool), Some(true));
        let rendered = serde_json::to_string(&m).unwrap();
        assert!(!rendered.contains("highly-sensitive"), "client secret leaked into serialized output");
    }

    #[test]
    fn to_public_map_returns_discovery_ca_pem_and_still_redacts_secret() {
        let pem = normalize_discovery_ca_pem(&test_pki::ca_pem()).unwrap();
        let cfg = OidcConfig {
            oidc_client_secret: "highly-sensitive".into(),
            oidc_discovery_ca_pem: pem.clone(),
            ..Default::default()
        };
        let m = cfg.to_public_map();
        assert_eq!(m.get("oidc_discovery_ca_pem").and_then(Value::as_str), Some(pem.as_str()));
        assert!(m.get("oidc_client_secret").is_none());
        assert!(!serde_json::to_string(&m).unwrap().contains("highly-sensitive"));

        let empty = OidcConfig::default().to_public_map();
        assert_eq!(empty.get("oidc_discovery_ca_pem").and_then(Value::as_str), Some(""));
    }

    /// A config persisted before `oidc_discovery_ca_pem` existed loads with
    /// it empty, and is written back with the field present.
    #[test]
    fn config_written_before_the_ca_field_loads_with_it_empty() {
        let old = br#"{"oidc_discovery_url":"https://idp.example.com","oidc_client_id":"cid",
            "oidc_client_secret":"s","default_role":"user","allowed_redirect_uris":["http://localhost/cb"],
            "oidc_scopes":["openid","profile","email"]}"#;
        let cfg: OidcConfig = serde_json::from_slice(old).unwrap();
        assert_eq!(cfg.oidc_discovery_url, "https://idp.example.com");
        assert_eq!(cfg.oidc_client_secret, "s");
        assert_eq!(cfg.oidc_discovery_ca_pem, "");

        let rewritten: Value = serde_json::from_slice(&serde_json::to_vec(&cfg).unwrap()).unwrap();
        assert_eq!(rewritten.get("oidc_discovery_ca_pem").and_then(Value::as_str), Some(""));
    }

    #[test]
    fn config_round_trips_the_ca_pem() {
        let pem = normalize_discovery_ca_pem(&test_pki::ca_pem()).unwrap();
        let cfg = OidcConfig { oidc_discovery_ca_pem: pem.clone(), ..Default::default() };
        let back: OidcConfig = serde_json::from_slice(&serde_json::to_vec(&cfg).unwrap()).unwrap();
        assert_eq!(back.oidc_discovery_ca_pem, pem);
    }

    #[test]
    fn absent_ca_pem_keeps_the_stored_value() {
        let stored = normalize_discovery_ca_pem(&test_pki::ca_pem()).unwrap();
        assert_eq!(merge_discovery_ca_pem(&stored, None).unwrap(), stored);
        assert_eq!(merge_discovery_ca_pem("", None).unwrap(), "");
    }

    #[test]
    fn empty_ca_pem_clears_the_stored_value() {
        let stored = normalize_discovery_ca_pem(&test_pki::ca_pem()).unwrap();
        assert_eq!(merge_discovery_ca_pem(&stored, Some(&Value::String(String::new()))).unwrap(), "");
        assert_eq!(merge_discovery_ca_pem(&stored, Some(&Value::String(" \n".into()))).unwrap(), "");
    }

    #[test]
    fn written_ca_pem_is_validated_and_normalised() {
        let input = format!("# issuer of the IdP's leaf\n{}", test_pki::ca_pem());
        let merged = merge_discovery_ca_pem("", Some(&Value::String(input.clone()))).unwrap();
        assert_eq!(merged, normalize_discovery_ca_pem(&input).unwrap());
        assert!(merged.starts_with("-----BEGIN CERTIFICATE-----"));

        let stored = merged;
        let chain = test_pki::chain(&["idp.test"]);
        for bad in ["garbage".to_string(), chain.leaf_key_pem.clone()] {
            assert!(merge_discovery_ca_pem(&stored, Some(&Value::String(bad))).is_err());
        }
        assert!(merge_discovery_ca_pem(&stored, Some(&Value::from(5))).is_err());
        assert!(merge_discovery_ca_pem(&stored, Some(&Value::Null)).is_err());
    }

    #[test]
    fn to_public_map_surfaces_secret_absence() {
        let cfg = OidcConfig::default();
        let m = cfg.to_public_map();
        assert_eq!(m.get("oidc_client_secret_set").and_then(Value::as_bool), Some(false));
    }

    #[test]
    fn parse_string_list_accepts_array_and_comma_string() {
        assert_eq!(
            parse_string_list(&Value::Array(vec![Value::String("a".into()), Value::String("b".into())])),
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(
            parse_string_list(&Value::String("a, b , ,c".into())),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
        assert!(parse_string_list(&Value::Null).is_empty());
    }
}
