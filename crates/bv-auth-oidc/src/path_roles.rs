//! OIDC roles — per-mount claim-to-policy mappings.
//!
//! Stored at `role/<name>`. A role:
//!   * Names the audiences (`aud`) we'll accept ID tokens for.
//!   * Pins arbitrary claim values the ID token must carry
//!     (`bound_claims`) — e.g. require `hd = example.com` so only
//!     people from a specific Google Workspace tenant can use it.
//!   * Maps OIDC claims onto Vault token metadata (`claim_mappings`).
//!   * Lists the vault policies to attach on successful login.
//!   * Carries per-role token TTL settings.
//!
//! `user_claim` is the claim used to name the principal in vault
//! audit logs (default: `sub`). `groups_claim` is the claim whose
//! value is a list of group names, surfaced on the token's metadata
//! so downstream identity-group bindings can match on it.

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

pub(crate) const ROLE_PREFIX: &str = "role/";

/// Stored role entry. Field names match the design doc so
/// operators hand-editing the preferences / writing Terraform
/// have a stable contract.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OidcRoleEntry {
    /// Values the ID token's `aud` claim must contain at least one
    /// of. Empty list accepts any audience, which is only safe for
    /// dev setups.
    #[serde(default)]
    pub bound_audiences: Vec<String>,
    /// Per-claim allow-list map: claim name → allowed values. A
    /// login must match at least one value for every listed claim.
    /// Missing claim ⇒ no match ⇒ login denied.
    #[serde(default)]
    pub bound_claims: HashMap<String, Vec<String>>,
    /// OIDC claim → Vault token metadata key. Lets operators
    /// project named claims (email, preferred_username,
    /// employee_id, ...) into `auth.metadata` without exposing
    /// every claim the IdP happens to ship.
    #[serde(default)]
    pub claim_mappings: HashMap<String, String>,
    /// Claim name used as the principal's display name. Default
    /// `sub` — unambiguous but opaque. `preferred_username` /
    /// `email` are more human-readable choices.
    #[serde(default)]
    pub user_claim: String,
    /// Claim whose value is a JSON array (or space-delimited string)
    /// of group names. Surfaced on `auth.metadata` so identity-group
    /// bindings that key on it pick up federated groups.
    #[serde(default)]
    pub groups_claim: String,
    /// Additional scopes to request on top of the provider-level
    /// `oidc_scopes` for this role. Useful when only some roles
    /// need access to privileged claims.
    #[serde(default)]
    pub oidc_scopes: Vec<String>,
    /// Narrower redirect-URI whitelist overriding the provider-
    /// level list. Empty falls through to provider config.
    #[serde(default)]
    pub allowed_redirect_uris: Vec<String>,
    /// Vault policies attached on successful login.
    #[serde(default)]
    pub policies: Vec<String>,
    /// Token TTL in seconds. 0 = default (token store's own TTL).
    #[serde(default)]
    pub token_ttl_secs: u64,
    /// Token max-TTL in seconds. 0 = unlimited renewal.
    #[serde(default)]
    pub token_max_ttl_secs: u64,
}

impl OidcRoleEntry {
    pub async fn load(req: &Request, name: &str) -> Result<Option<Self>, RvError> {
        let key = format!("{ROLE_PREFIX}{name}");
        match req.storage_get(&key).await? {
            Some(entry) => Ok(Some(serde_json::from_slice(&entry.value)?)),
            None => Ok(None),
        }
    }

    /// Apply `bound_audiences` and `bound_claims` against claim
    /// values extracted from the ID token. Returns `Ok(())` on
    /// success, a descriptive `RvError::ErrString` on rejection.
    pub fn validate_claims(
        &self,
        audiences: &[String],
        claims: &Map<String, Value>,
    ) -> Result<(), RvError> {
        if !self.bound_audiences.is_empty() {
            let matched = audiences.iter().any(|a| self.bound_audiences.contains(a));
            if !matched {
                return Err(RvError::ErrString(format!(
                    "oidc: token `aud` {audiences:?} does not match role `bound_audiences`"
                )));
            }
        }
        for (claim, allowed) in &self.bound_claims {
            let Some(value) = claims.get(claim) else {
                return Err(RvError::ErrString(format!(
                    "oidc: required bound_claim `{claim}` missing from ID token"
                )));
            };
            if !claim_matches_any(value, allowed) {
                return Err(RvError::ErrString(format!(
                    "oidc: bound_claim `{claim}` did not match allowed values"
                )));
            }
        }
        Ok(())
    }

    fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert(
            "bound_audiences".into(),
            Value::Array(
                self.bound_audiences
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        m.insert(
            "bound_claims".into(),
            Value::Object(
                self.bound_claims
                    .iter()
                    .map(|(k, vs)| {
                        (
                            k.clone(),
                            Value::Array(vs.iter().cloned().map(Value::String).collect()),
                        )
                    })
                    .collect(),
            ),
        );
        m.insert(
            "claim_mappings".into(),
            Value::Object(
                self.claim_mappings
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                    .collect(),
            ),
        );
        m.insert("user_claim".into(), Value::String(self.user_claim.clone()));
        m.insert(
            "groups_claim".into(),
            Value::String(self.groups_claim.clone()),
        );
        m.insert(
            "oidc_scopes".into(),
            Value::Array(
                self.oidc_scopes
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
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
            "policies".into(),
            Value::Array(self.policies.iter().cloned().map(Value::String).collect()),
        );
        m.insert(
            "token_ttl_secs".into(),
            Value::Number(self.token_ttl_secs.into()),
        );
        m.insert(
            "token_max_ttl_secs".into(),
            Value::Number(self.token_max_ttl_secs.into()),
        );
        m
    }
}

fn claim_matches_any(value: &Value, allowed: &[String]) -> bool {
    match value {
        Value::String(s) => allowed.iter().any(|a| a == s),
        Value::Number(n) => allowed.iter().any(|a| a == &n.to_string()),
        Value::Bool(b) => {
            let s = b.to_string();
            allowed.iter().any(|a| a == &s)
        }
        Value::Array(arr) => arr.iter().any(|v| claim_matches_any(v, allowed)),
        // Objects + nulls can't reasonably match a string allow-list.
        _ => false,
    }
}

impl OidcBackend {
    pub fn roles_path(&self) -> Path {
        let this = self.inner.clone();
        let r = this.clone();
        let w = this.clone();
        let d = this;
        new_path!({
            pattern: r"role/(?P<name>[\w-]+)",
            fields: {
                "name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Role name."
                },
                "bound_audiences": { field_type: FieldType::CommaStringSlice },
                "bound_claims":    { field_type: FieldType::Str },
                "claim_mappings":  { field_type: FieldType::Str },
                "user_claim":      { field_type: FieldType::Str },
                "groups_claim":    { field_type: FieldType::Str },
                "oidc_scopes":     { field_type: FieldType::CommaStringSlice },
                "allowed_redirect_uris": { field_type: FieldType::CommaStringSlice },
                "policies":        { field_type: FieldType::CommaStringSlice },
                "token_ttl_secs":  { field_type: FieldType::Int },
                "token_max_ttl_secs": { field_type: FieldType::Int }
            },
            operations: [
                {op: Operation::Read,   handler: r.read_role},
                {op: Operation::Write,  handler: w.write_role},
                {op: Operation::Delete, handler: d.delete_role}
            ],
            help: "Read, write, or delete the OIDC role named by `name`."
        })
    }

    pub fn role_list_path(&self) -> Path {
        let this = self.inner.clone();
        new_path!({
            pattern: r"role/?",
            operations: [
                {op: Operation::List, handler: this.list_roles}
            ],
            help: "List the names of all configured OIDC roles."
        })
    }
}

#[maybe_async::maybe_async]
impl OidcBackendInner {
    pub async fn read_role(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req.get_data_as_str("name").unwrap_or_default();
        let Some(role) = OidcRoleEntry::load(req, &name).await? else {
            return Ok(None);
        };
        Ok(Some(Response::data_response(Some(role.to_map()))))
    }

    pub async fn write_role(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req.get_data_as_str("name").unwrap_or_default();
        if name.trim().is_empty() {
            return Err(RvError::ErrString("oidc: role name is required".into()));
        }
        let mut role = OidcRoleEntry::load(req, &name).await?.unwrap_or_default();

        if let Ok(v) = req.get_data("bound_audiences") {
            role.bound_audiences = parse_string_list(&v);
        }
        if let Ok(v) = req.get_data("bound_claims") {
            // Accept either a JSON object (preferred) or the
            // comma-separated field-layer default. A plain-string
            // value that parses as JSON wins; anything else is an
            // error because silently dropping bound_claims would
            // be a security regression.
            if let Value::String(raw) = &v {
                if !raw.trim().is_empty() {
                    role.bound_claims = parse_claim_map(raw)?;
                }
            } else if let Value::Object(obj) = &v {
                role.bound_claims = obj
                    .iter()
                    .map(|(k, vs)| (k.clone(), vals_to_strings(vs)))
                    .collect();
            }
        }
        if let Ok(v) = req.get_data("claim_mappings") {
            if let Value::String(raw) = &v {
                if !raw.trim().is_empty() {
                    role.claim_mappings = parse_str_map(raw)?;
                }
            } else if let Value::Object(obj) = &v {
                role.claim_mappings = obj
                    .iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect();
            }
        }
        if let Ok(Value::String(v)) = req.get_data("user_claim") {
            role.user_claim = v;
        }
        if let Ok(Value::String(v)) = req.get_data("groups_claim") {
            role.groups_claim = v;
        }
        if let Ok(v) = req.get_data("oidc_scopes") {
            role.oidc_scopes = parse_string_list(&v);
        }
        if let Ok(v) = req.get_data("allowed_redirect_uris") {
            role.allowed_redirect_uris = parse_string_list(&v);
        }
        if let Ok(v) = req.get_data("policies") {
            role.policies = parse_string_list(&v);
        }
        if let Ok(v) = req.get_data("token_ttl_secs") {
            role.token_ttl_secs = v.as_u64().unwrap_or(0);
        }
        if let Ok(v) = req.get_data("token_max_ttl_secs") {
            role.token_max_ttl_secs = v.as_u64().unwrap_or(0);
        }

        if role.user_claim.is_empty() {
            role.user_claim = "sub".to_string();
        }

        let bytes = serde_json::to_vec(&role)?;
        req.storage_put(&StorageEntry {
            key: format!("{ROLE_PREFIX}{name}"),
            value: bytes,
        })
        .await?;
        Ok(None)
    }

    pub async fn delete_role(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req.get_data_as_str("name").unwrap_or_default();
        req.storage_delete(&format!("{ROLE_PREFIX}{name}")).await?;
        Ok(None)
    }

    pub async fn list_roles(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let names = req.storage_list(ROLE_PREFIX).await?;
        Ok(Some(Response::list_response(&names)))
    }
}

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

fn parse_claim_map(raw: &str) -> Result<HashMap<String, Vec<String>>, RvError> {
    let parsed: Value = serde_json::from_str(raw)
        .map_err(|e| RvError::ErrString(format!("bound_claims: invalid JSON: {e}")))?;
    match parsed {
        Value::Object(obj) => Ok(obj
            .into_iter()
            .map(|(k, v)| (k, vals_to_strings(&v)))
            .collect()),
        _ => Err(RvError::ErrString(
            "bound_claims: expected JSON object of claim → allowed-values".into(),
        )),
    }
}

fn parse_str_map(raw: &str) -> Result<HashMap<String, String>, RvError> {
    let parsed: Value = serde_json::from_str(raw)
        .map_err(|e| RvError::ErrString(format!("claim_mappings: invalid JSON: {e}")))?;
    match parsed {
        Value::Object(obj) => Ok(obj
            .into_iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
            .collect()),
        _ => Err(RvError::ErrString(
            "claim_mappings: expected JSON object of claim-name → metadata-key".into(),
        )),
    }
}

fn vals_to_strings(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect(),
        Value::String(s) => vec![s.clone()],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_claims_bound_audience_happy() {
        let role = OidcRoleEntry {
            bound_audiences: vec!["bastionvault".into()],
            ..Default::default()
        };
        role.validate_claims(
            &["bastionvault".to_string()],
            &Map::new(),
        )
        .unwrap();
    }

    #[test]
    fn validate_claims_bound_audience_rejects() {
        let role = OidcRoleEntry {
            bound_audiences: vec!["bastionvault".into()],
            ..Default::default()
        };
        let err = role
            .validate_claims(&["someone-else".to_string()], &Map::new())
            .unwrap_err();
        assert!(format!("{err}").contains("does not match"));
    }

    #[test]
    fn validate_claims_bound_claim_missing_rejects() {
        let role = OidcRoleEntry {
            bound_claims: [("hd".to_string(), vec!["example.com".to_string()])]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let err = role.validate_claims(&[], &Map::new()).unwrap_err();
        assert!(format!("{err}").contains("missing from ID token"));
    }

    #[test]
    fn validate_claims_bound_claim_mismatch_rejects() {
        let role = OidcRoleEntry {
            bound_claims: [("hd".to_string(), vec!["example.com".to_string()])]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let mut claims = Map::new();
        claims.insert("hd".into(), Value::String("other.com".into()));
        let err = role.validate_claims(&[], &claims).unwrap_err();
        assert!(format!("{err}").contains("did not match allowed"));
    }

    #[test]
    fn validate_claims_bound_claim_array_matches_any() {
        let role = OidcRoleEntry {
            bound_claims: [("groups".to_string(), vec!["admins".to_string()])]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let mut claims = Map::new();
        claims.insert(
            "groups".into(),
            Value::Array(vec![
                Value::String("engineering".into()),
                Value::String("admins".into()),
            ]),
        );
        role.validate_claims(&[], &claims).unwrap();
    }

    #[test]
    fn parse_claim_map_roundtrips() {
        let m = parse_claim_map(r#"{"hd":["a.com","b.com"],"grp":["admin"]}"#).unwrap();
        assert_eq!(m.get("hd").unwrap().len(), 2);
        assert_eq!(m.get("grp").unwrap(), &vec!["admin".to_string()]);
    }

    #[test]
    fn parse_claim_map_rejects_non_object() {
        let err = parse_claim_map(r#"["not","an","object"]"#).unwrap_err();
        assert!(format!("{err}").contains("expected JSON object"));
    }

    #[test]
    fn parse_str_map_extracts_strings_only() {
        let m = parse_str_map(r#"{"email":"mail","sub":"user_id","nope":123}"#).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m.get("email").unwrap(), "mail");
    }

    #[test]
    fn claim_matches_any_number() {
        assert!(claim_matches_any(
            &Value::Number(42.into()),
            &["42".to_string()]
        ));
    }

    #[test]
    fn claim_matches_any_boolean() {
        assert!(claim_matches_any(
            &Value::Bool(true),
            &["true".to_string()]
        ));
    }
}
