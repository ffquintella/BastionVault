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
        m.insert(
            "oidc_discovery_url".into(),
            Value::String(self.oidc_discovery_url.clone()),
        );
        m.insert(
            "oidc_client_id".into(),
            Value::String(self.oidc_client_id.clone()),
        );
        m.insert(
            "oidc_client_secret_set".into(),
            Value::Bool(!self.oidc_client_secret.is_empty()),
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
        m.insert(
            "oidc_scopes".into(),
            Value::Array(self.oidc_scopes.iter().cloned().map(Value::String).collect()),
        );
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
    pub async fn read_config(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let Some(cfg) = OidcConfig::load(req).await? else {
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

        // Minimum-viable validation: discovery URL and client id
        // are both required for the backend to function at all.
        if cfg.oidc_discovery_url.trim().is_empty() {
            return Err(RvError::ErrString(
                "oidc: `oidc_discovery_url` is required".into(),
            ));
        }
        if cfg.oidc_client_id.trim().is_empty() {
            return Err(RvError::ErrString(
                "oidc: `oidc_client_id` is required".into(),
            ));
        }

        // Default scopes — the RFC-standard minimum for an OIDC
        // flow is `openid`; `profile` + `email` are the near-universal
        // defaults that surface `preferred_username` and the email
        // claim, both commonly used in role bound_claims.
        if cfg.oidc_scopes.is_empty() {
            cfg.oidc_scopes = vec![
                "openid".into(),
                "profile".into(),
                "email".into(),
            ];
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
/// comma-separated `Value::String` at the field layer — the logical-
/// layer's CommaStringSlice normaliser sometimes passes one form,
/// sometimes the other depending on the request shape.
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
    fn to_public_map_redacts_secret() {
        let cfg = OidcConfig {
            oidc_discovery_url: "https://example.com".into(),
            oidc_client_id: "cid".into(),
            oidc_client_secret: "highly-sensitive".into(),
            default_role: "user".into(),
            allowed_redirect_uris: vec!["http://localhost/cb".into()],
            oidc_scopes: vec!["openid".into()],
        };
        let m = cfg.to_public_map();
        // The secret must never appear in the serialized output.
        assert_eq!(
            m.get("oidc_client_secret_set").and_then(Value::as_bool),
            Some(true)
        );
        let rendered = serde_json::to_string(&m).unwrap();
        assert!(
            !rendered.contains("highly-sensitive"),
            "client secret leaked into serialized output"
        );
    }

    #[test]
    fn to_public_map_surfaces_secret_absence() {
        let cfg = OidcConfig::default();
        let m = cfg.to_public_map();
        assert_eq!(
            m.get("oidc_client_secret_set").and_then(Value::as_bool),
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
