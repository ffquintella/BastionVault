//! Persisted environment and entitlement records, and their input checks.
//!
//! Both records carry `version` and are decoded with
//! [`decode_versioned`](crate::posix::model::decode_versioned): this build
//! reads and writes version 1 only and refuses any other version, a missing
//! version and any unknown field, so a stored record is never guessed at.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::posix::model::PosixError;

pub const MAX_ENVIRONMENT_NAME_LEN: usize = 64;
pub const MAX_ROLE_NAME_LEN: usize = 64;
pub const MAX_POLICY_NAME_LEN: usize = 128;
pub const MAX_ROLES_PER_ENVIRONMENT: usize = 64;
pub const MAX_POLICIES_PER_ROLE: usize = 32;
pub const MAX_ROLES_PER_ENTITLEMENT: usize = 32;
pub const MAX_DESCRIPTION_CHARS: usize = 256;

/// Policies a role may never map to. `root` is the synthetic superuser
/// policy; the other two are kernel-internal and never assignable. A role is
/// what a downstream credential is scoped by, so none of them belongs there.
pub const FORBIDDEN_POLICIES: &[&str] = &["root", "response-wrapping", "control-group"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvironmentState {
    Active,
    /// Terminal. The name stays reserved so a later environment can never
    /// inherit the entitlements granted against this one.
    Retired,
}

impl EnvironmentState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retired => "retired",
        }
    }
}

/// `idp/authz/environments/<name>`: an authorization boundary, bound for
/// life to one namespace, with the roles that may be granted in it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    pub version: u32,
    pub name: String,
    /// Canonical namespace path (`""` = root). Immutable.
    pub namespace: String,
    /// The namespace's uuid when the environment was created. A namespace
    /// deleted and recreated under the same path has another uuid, and the
    /// gate refuses it rather than carry the entitlements across.
    pub namespace_uuid: String,
    /// Role name -> the namespace's ACL policy names that role stands for.
    pub roles: BTreeMap<String, Vec<String>>,
    pub description: String,
    pub state: EnvironmentState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
}

impl Environment {
    pub fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("name".into(), Value::from(self.name.clone()));
        m.insert("namespace".into(), Value::from(self.namespace.clone()));
        m.insert("namespace_uuid".into(), Value::from(self.namespace_uuid.clone()));
        let roles: Map<String, Value> =
            self.roles.iter().map(|(role, policies)| (role.clone(), Value::from(policies.clone()))).collect();
        m.insert("roles".into(), Value::Object(roles));
        m.insert("description".into(), Value::from(self.description.clone()));
        m.insert("state".into(), Value::from(self.state.as_str()));
        m.insert("created_at".into(), Value::from(self.created_at.to_rfc3339()));
        m.insert("updated_at".into(), Value::from(self.updated_at.to_rfc3339()));
        m.insert("retired_at".into(), self.retired_at.map(|t| Value::from(t.to_rfc3339())).into());
        m
    }
}

/// Where a grant came from. Only `manual` and `external` can be written in
/// this build; `group` is reserved for entitlements derived from identity
/// groups, which are not implemented yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntitlementSource {
    Manual,
    Group,
    External,
}

impl EntitlementSource {
    pub fn parse_writable(s: &str) -> Result<Self, PosixError> {
        match s {
            "manual" => Ok(Self::Manual),
            "external" => Ok(Self::External),
            "group" => Err(PosixError::Invalid("group-derived entitlements are not implemented yet".into())),
            other => Err(PosixError::Invalid(format!("unknown source `{other}`: expected manual or external"))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Group => "group",
            Self::External => "external",
        }
    }
}

/// `idp/authz/entitlements/<entity_id>/<environment>`: this person may enter
/// this environment as these roles, until `not_after` if set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entitlement {
    pub version: u32,
    pub entity_id: String,
    pub environment: String,
    /// Sorted, deduplicated, never empty.
    pub roles: Vec<String>,
    pub not_after: Option<DateTime<Utc>>,
    pub source: EntitlementSource,
    /// Who granted it: the caller's entity id, or its display name for a
    /// token without one (`root`). Stamped by the server, never the client.
    pub granted_by: String,
    pub granted_at: DateTime<Utc>,
}

impl Entitlement {
    pub fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("entity_id".into(), Value::from(self.entity_id.clone()));
        m.insert("environment".into(), Value::from(self.environment.clone()));
        m.insert("roles".into(), Value::from(self.roles.clone()));
        m.insert("not_after".into(), self.not_after.map(|t| Value::from(t.to_rfc3339())).into());
        m.insert("source".into(), Value::from(self.source.as_str()));
        m.insert("granted_by".into(), Value::from(self.granted_by.clone()));
        m.insert("granted_at".into(), Value::from(self.granted_at.to_rfc3339()));
        m
    }
}

// ─── Input validation ───────────────────────────────────────────────

fn is_token(s: &str, max: usize, extra: &[u8]) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= max
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' || *c == b'_' || extra.contains(c))
}

/// Lower-case only, so `prod` and `Prod` can never be two environments.
pub fn validate_environment_name(name: &str) -> Result<(), PosixError> {
    if is_token(name, MAX_ENVIRONMENT_NAME_LEN, &[]) {
        Ok(())
    } else {
        Err(PosixError::Invalid(format!(
            "environment name must match ^[a-z0-9][a-z0-9_-]*$ and be at most {MAX_ENVIRONMENT_NAME_LEN} characters"
        )))
    }
}

pub fn validate_role_name(role: &str) -> Result<(), PosixError> {
    if is_token(role, MAX_ROLE_NAME_LEN, &[]) {
        Ok(())
    } else {
        Err(PosixError::Invalid(format!(
            "role name must match ^[a-z0-9][a-z0-9_-]*$ and be at most {MAX_ROLE_NAME_LEN} characters"
        )))
    }
}

/// Policy names as the policy store keeps them (it lower-cases on write).
/// Whether the policy exists is not checked: a role may name a policy the
/// namespace has not written yet, as a token role may.
pub fn validate_policy_name(policy: &str) -> Result<(), PosixError> {
    if !is_token(policy, MAX_POLICY_NAME_LEN, b".") {
        return Err(PosixError::Invalid(format!(
            "policy name `{policy}` must match ^[a-z0-9][a-z0-9_.-]*$ and be at most {MAX_POLICY_NAME_LEN} characters"
        )));
    }
    if FORBIDDEN_POLICIES.contains(&policy) {
        return Err(PosixError::Invalid(format!("policy `{policy}` cannot be bound to an environment role")));
    }
    Ok(())
}

pub fn validate_description(text: &str) -> Result<(), PosixError> {
    if text.chars().count() > MAX_DESCRIPTION_CHARS || text.chars().any(char::is_control) {
        return Err(PosixError::Invalid(format!(
            "description must be at most {MAX_DESCRIPTION_CHARS} characters without control characters"
        )));
    }
    Ok(())
}

/// Validate a role -> policies map and put every policy list in canonical
/// (sorted, deduplicated) order.
pub fn normalize_role_map(roles: BTreeMap<String, Vec<String>>) -> Result<BTreeMap<String, Vec<String>>, PosixError> {
    if roles.len() > MAX_ROLES_PER_ENVIRONMENT {
        return Err(PosixError::Invalid(format!("at most {MAX_ROLES_PER_ENVIRONMENT} roles per environment")));
    }
    let mut out = BTreeMap::new();
    for (role, mut policies) in roles {
        validate_role_name(&role)?;
        policies.sort();
        policies.dedup();
        if policies.len() > MAX_POLICIES_PER_ROLE {
            return Err(PosixError::Invalid(format!("role `{role}`: at most {MAX_POLICIES_PER_ROLE} policies")));
        }
        for p in &policies {
            validate_policy_name(p)?;
        }
        out.insert(role, policies);
    }
    Ok(out)
}

/// Validate a requested role list: non-empty, every name well-formed,
/// returned sorted and deduplicated.
pub fn normalize_role_list(roles: Vec<String>) -> Result<Vec<String>, PosixError> {
    let mut roles = roles;
    roles.sort();
    roles.dedup();
    if roles.is_empty() {
        return Err(PosixError::Invalid("at least one role is required".into()));
    }
    if roles.len() > MAX_ROLES_PER_ENTITLEMENT {
        return Err(PosixError::Invalid(format!("at most {MAX_ROLES_PER_ENTITLEMENT} roles per entitlement")));
    }
    for r in &roles {
        validate_role_name(r)?;
    }
    Ok(roles)
}

/// Parse a JSON object of role -> array of policy names.
pub fn parse_role_map(v: &Value) -> Result<BTreeMap<String, Vec<String>>, PosixError> {
    let Value::Object(obj) = v else {
        return Err(PosixError::Invalid("roles must be an object of role name -> array of policy names".into()));
    };
    let mut out = BTreeMap::new();
    for (role, policies) in obj {
        out.insert(role.clone(), parse_string_list(&format!("roles.{role}"), policies)?);
    }
    Ok(out)
}

/// Parse a JSON array of strings.
pub fn parse_string_list(field: &str, v: &Value) -> Result<Vec<String>, PosixError> {
    let Value::Array(items) = v else {
        return Err(PosixError::Invalid(format!("{field} must be an array of strings")));
    };
    items
        .iter()
        .map(|item| match item {
            Value::String(s) => Ok(s.clone()),
            _ => Err(PosixError::Invalid(format!("{field} must be an array of strings"))),
        })
        .collect()
}

/// Parse an RFC 3339 timestamp.
pub fn parse_timestamp(field: &str, s: &str) -> Result<DateTime<Utc>, PosixError> {
    DateTime::parse_from_rfc3339(s.trim())
        .map(|t| t.with_timezone(&Utc))
        .map_err(|_| PosixError::Invalid(format!("{field} must be an RFC 3339 timestamp")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::posix::model::decode_versioned;

    #[test]
    fn names_and_policies() {
        for ok in ["prod", "dev-1", "pci_eu", "0day"] {
            assert!(validate_environment_name(ok).is_ok(), "{ok}");
            assert!(validate_role_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", "Prod", "-prod", "pr od", "prod/eu", "prod.eu", &"a".repeat(65), "prøde"] {
            assert!(validate_environment_name(bad).is_err(), "{bad}");
            assert!(validate_role_name(bad).is_err(), "{bad}");
        }
        assert!(validate_policy_name("prod.admin-ro").is_ok());
        for bad in ["root", "response-wrapping", "control-group", "Admin", "a/b", ""] {
            assert!(validate_policy_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn role_maps_and_lists_are_canonical() {
        let map = parse_role_map(&serde_json::json!({"dba": ["b", "a", "a"], "ops": []})).unwrap();
        let map = normalize_role_map(map).unwrap();
        assert_eq!(map["dba"], vec!["a".to_string(), "b".to_string()]);
        assert!(map["ops"].is_empty());
        assert!(parse_role_map(&serde_json::json!({"dba": "a,b"})).is_err());
        assert!(parse_role_map(&serde_json::json!(["dba"])).is_err());
        assert!(normalize_role_map(parse_role_map(&serde_json::json!({"dba": ["root"]})).unwrap()).is_err());
        assert_eq!(normalize_role_list(vec!["b".into(), "a".into(), "b".into()]).unwrap(), vec!["a", "b"]);
        assert!(normalize_role_list(Vec::new()).is_err());
        assert!(EntitlementSource::parse_writable("group").is_err());
        assert!(parse_timestamp("not_after", "2026-12-31T00:00:00Z").is_ok());
        assert!(parse_timestamp("not_after", "tomorrow").is_err());
    }

    /// Version-1 records exactly as this build writes them. Kept verbatim so
    /// a future format change has to keep reading them.
    const V1_ENVIRONMENT: &str = r#"{"version":1,"name":"prod","namespace":"corp/prod",
        "namespace_uuid":"0f6c3e1a-1111-2222-3333-444455556666","roles":{"dba":["prod-dba"],"sysadmin":["prod-admin"]},
        "description":"Production","state":"active","created_at":"2026-11-16T10:00:00Z",
        "updated_at":"2026-11-16T10:00:00Z","retired_at":null}"#;
    const V1_ENTITLEMENT: &str = r#"{"version":1,"entity_id":"e-1","environment":"prod","roles":["sysadmin"],
        "not_after":"2026-12-31T00:00:00Z","source":"manual","granted_by":"root","granted_at":"2026-11-16T10:00:00Z"}"#;

    #[test]
    fn v1_records_decode() {
        let env: Environment = decode_versioned("environment", V1_ENVIRONMENT.as_bytes()).unwrap();
        assert_eq!((env.namespace.as_str(), env.state), ("corp/prod", EnvironmentState::Active));
        assert_eq!(env.roles["sysadmin"], vec!["prod-admin".to_string()]);
        let ent: Entitlement = decode_versioned("entitlement", V1_ENTITLEMENT.as_bytes()).unwrap();
        assert_eq!((ent.roles.clone(), ent.source), (vec!["sysadmin".to_string()], EntitlementSource::Manual));
        assert!(ent.not_after.is_some());
    }

    #[test]
    fn unknown_versions_and_fields_are_refused() {
        for (what, raw) in [("environment", V1_ENVIRONMENT), ("entitlement", V1_ENTITLEMENT)] {
            let v2 = raw.replacen("\"version\":1", "\"version\":2", 1);
            let extra = raw.replacen("\"version\":1", "\"version\":1,\"allow_all\":true", 1);
            let unversioned = raw.replacen("\"version\":1,", "", 1);
            for bad in [v2, extra, unversioned] {
                let res = if what == "environment" {
                    decode_versioned::<Environment>(what, bad.as_bytes()).map(|_| ())
                } else {
                    decode_versioned::<Entitlement>(what, bad.as_bytes()).map(|_| ())
                };
                assert!(matches!(res, Err(PosixError::Corrupt(_))), "{what}: {bad}");
            }
        }
        let bad_source = V1_ENTITLEMENT.replacen("\"manual\"", "\"everyone\"", 1);
        assert!(decode_versioned::<Entitlement>("entitlement", bad_source.as_bytes()).is_err());
    }
}
