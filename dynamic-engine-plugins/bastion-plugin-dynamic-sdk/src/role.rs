//! Roles: the recipe the host asks for (`dynamic.role`) before it generates
//! a credential. The plugin stores them at `roles/<name>`; the host checks
//! and expands their statement templates, never the plugin.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::DynamicError;

/// Current stored-role format.
pub const ROLE_RECORD_VERSION: u32 = 1;
/// Most statements of one kind (the host's `MAX_STATEMENTS`).
pub const MAX_STATEMENTS: usize = 32;
/// Longest single statement template.
pub const MAX_STATEMENT_LEN: usize = 16 * 1024;
/// Bounds of `username_max_len` (the host clamps generated names to them).
pub const MIN_USERNAME_MAX_LEN: usize = 32;
pub const DEFAULT_USERNAME_MAX_LEN: usize = 63;

/// The role as the host reads it: exactly the host's `RoleRecipe` fields
/// (it refuses unknown ones).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleRecipe {
    pub connection: String,
    #[serde(default)]
    pub creation_statements: Vec<String>,
    #[serde(default)]
    pub revocation_statements: Vec<String>,
    #[serde(default)]
    pub renew_statements: Vec<String>,
    #[serde(default)]
    pub default_ttl_secs: u64,
    #[serde(default)]
    pub max_ttl_secs: u64,
    #[serde(default = "default_true")]
    pub renewable: bool,
    #[serde(default = "default_username_max_len")]
    pub username_max_len: usize,
    /// The host's opt-in credential cache window (0: off). Omitted from the
    /// wire when off, so a host older than the cache still reads the role.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub cache_ttl_secs: u64,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

fn default_true() -> bool {
    true
}

fn default_username_max_len() -> usize {
    DEFAULT_USERNAME_MAX_LEN
}

pub(crate) fn record_version_one() -> u32 {
    1
}

/// What is persisted at `roles/<name>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredRole {
    #[serde(default = "record_version_one")]
    pub v: u32,
    #[serde(flatten)]
    pub recipe: RoleRecipe,
}

impl StoredRole {
    pub(crate) fn decode(bytes: &[u8]) -> Result<RoleRecipe, DynamicError> {
        let stored: StoredRole =
            serde_json::from_slice(bytes).map_err(|e| DynamicError::invalid(format!("stored role: {e}")))?;
        if stored.v > ROLE_RECORD_VERSION {
            return Err(DynamicError::invalid(format!(
                "stored role is format version {}, newer than this plugin understands ({ROLE_RECORD_VERSION})",
                stored.v
            )));
        }
        Ok(stored.recipe)
    }

    pub(crate) fn encode(recipe: &RoleRecipe) -> Result<Vec<u8>, DynamicError> {
        let stored = StoredRole { v: ROLE_RECORD_VERSION, recipe: recipe.clone() };
        serde_json::to_vec(&stored).map_err(|e| DynamicError::invalid(e.to_string()))
    }
}

/// Names that end up in storage and pool keys: `[A-Za-z0-9_.-]`, 1-64
/// characters, never `.` or `..` (the host's `check_name`).
pub fn check_name(field: &str, value: &str) -> Result<(), DynamicError> {
    let ok = !value.is_empty()
        && value.len() <= 64
        && value != "."
        && value != ".."
        && value.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if ok {
        Ok(())
    } else {
        Err(DynamicError::invalid(format!("{field} must be 1-64 characters of [A-Za-z0-9_.-]")))
    }
}

/// `90`, `90s`, `30m`, `1h30m`, `2d`: seconds.
pub fn parse_duration_secs(field: &str, value: &Value) -> Result<u64, DynamicError> {
    let bad = || DynamicError::invalid(format!("`{field}` must be seconds or a duration like 30m, 1h, 1h30m"));
    match value {
        Value::Null => Ok(0),
        Value::Number(n) => n.as_u64().ok_or_else(bad),
        Value::String(s) if s.trim().is_empty() => Ok(0),
        Value::String(s) => {
            let s = s.trim();
            if s.chars().all(|c| c.is_ascii_digit()) {
                return s.parse().map_err(|_| bad());
            }
            let (mut total, mut digits) = (0u64, String::new());
            for c in s.chars() {
                if c.is_ascii_digit() {
                    digits.push(c);
                    continue;
                }
                let unit = match c {
                    's' => 1,
                    'm' => 60,
                    'h' => 3600,
                    'd' => 86_400,
                    _ => return Err(bad()),
                };
                let n: u64 = digits.parse().map_err(|_| bad())?;
                total = n.checked_mul(unit).and_then(|v| total.checked_add(v)).ok_or_else(bad)?;
                digits.clear();
            }
            if !digits.is_empty() {
                return Err(bad());
            }
            Ok(total)
        }
        _ => Err(bad()),
    }
}

fn statements(field: &str, value: &Value) -> Result<Vec<String>, DynamicError> {
    let list = match value {
        Value::Null => Vec::new(),
        Value::String(s) if s.trim().is_empty() => Vec::new(),
        Value::String(s) => vec![s.clone()],
        Value::Array(items) => items
            .iter()
            .map(|v| v.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| DynamicError::invalid(format!("`{field}` must be a string or a list of strings")))?,
        _ => return Err(DynamicError::invalid(format!("`{field}` must be a string or a list of strings"))),
    };
    if list.len() > MAX_STATEMENTS {
        return Err(DynamicError::invalid(format!("`{field}`: at most {MAX_STATEMENTS} statements")));
    }
    for s in &list {
        if s.trim().is_empty() || s.len() > MAX_STATEMENT_LEN || s.contains('\0') {
            return Err(DynamicError::invalid(format!(
                "`{field}`: every statement must be non-empty, at most {MAX_STATEMENT_LEN} bytes, without NUL"
            )));
        }
    }
    Ok(list)
}

fn boolean(field: &str, value: &Value) -> Result<bool, DynamicError> {
    match value {
        Value::Bool(b) => Ok(*b),
        Value::String(s) if s == "true" => Ok(true),
        Value::String(s) if s == "false" => Ok(false),
        _ => Err(DynamicError::invalid(format!("`{field}` must be a boolean"))),
    }
}

impl RoleRecipe {
    /// Parse an operator's `roles/<name>` write. Unknown fields are refused
    /// so a typo is not silently dropped.
    pub fn from_input(input: &Map<String, Value>) -> Result<Self, DynamicError> {
        let mut r = RoleRecipe {
            connection: String::new(),
            creation_statements: Vec::new(),
            revocation_statements: Vec::new(),
            renew_statements: Vec::new(),
            default_ttl_secs: 0,
            max_ttl_secs: 0,
            renewable: true,
            username_max_len: DEFAULT_USERNAME_MAX_LEN,
            cache_ttl_secs: 0,
        };
        for (key, value) in input {
            match key.as_str() {
                "connection" | "db_name" => {
                    r.connection = value.as_str().unwrap_or_default().to_string();
                }
                "creation_statements" => r.creation_statements = statements(key, value)?,
                "revocation_statements" => r.revocation_statements = statements(key, value)?,
                "renew_statements" => r.renew_statements = statements(key, value)?,
                "default_ttl" | "default_ttl_secs" => r.default_ttl_secs = parse_duration_secs(key, value)?,
                "max_ttl" | "max_ttl_secs" => r.max_ttl_secs = parse_duration_secs(key, value)?,
                "renewable" => r.renewable = boolean(key, value)?,
                "cache_ttl" | "cache_ttl_secs" => r.cache_ttl_secs = parse_duration_secs(key, value)?,
                "username_max_len" => {
                    r.username_max_len = value
                        .as_u64()
                        .and_then(|n| usize::try_from(n).ok())
                        .ok_or_else(|| DynamicError::invalid("`username_max_len` must be a number"))?;
                }
                other => return Err(DynamicError::invalid(format!("unknown role field `{other}`"))),
            }
        }
        r.validate()?;
        Ok(r)
    }

    /// The SDK's shape checks. Statement templates are the host's to check.
    pub fn validate(&self) -> Result<(), DynamicError> {
        check_name("connection", &self.connection)?;
        if self.max_ttl_secs != 0 && self.default_ttl_secs > self.max_ttl_secs {
            return Err(DynamicError::invalid("default_ttl must not exceed max_ttl"));
        }
        if !(MIN_USERNAME_MAX_LEN..=DEFAULT_USERNAME_MAX_LEN).contains(&self.username_max_len) {
            return Err(DynamicError::invalid(format!(
                "username_max_len must be {MIN_USERNAME_MAX_LEN}..={DEFAULT_USERNAME_MAX_LEN}"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn input(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    #[test]
    fn an_operator_role_parses_into_the_host_recipe() {
        let r = RoleRecipe::from_input(&input(json!({
            "db_name": "prod",
            "creation_statements": "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}'",
            "revocation_statements": ["DROP ROLE IF EXISTS \"{{name}}\""],
            "default_ttl": "30m",
            "max_ttl": 7200,
            "renewable": "false"
        })))
        .unwrap();
        assert_eq!(r.connection, "prod");
        assert_eq!(r.creation_statements.len(), 1);
        assert_eq!((r.default_ttl_secs, r.max_ttl_secs, r.renewable), (1800, 7200, false));
        let wire = serde_json::to_value(&r).unwrap();
        let keys: Vec<&str> = wire.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "connection",
                "creation_statements",
                "default_ttl_secs",
                "max_ttl_secs",
                "renew_statements",
                "renewable",
                "revocation_statements",
                "username_max_len"
            ],
            "exactly the host's RoleRecipe fields"
        );
    }

    #[test]
    fn a_role_may_opt_into_the_host_credential_cache() {
        let r = RoleRecipe::from_input(&input(json!({ "connection": "prod", "cache_ttl": "45s" }))).unwrap();
        assert_eq!(r.cache_ttl_secs, 45);
        assert_eq!(serde_json::to_value(&r).unwrap()["cache_ttl_secs"], 45);
        // Off by default, and then not on the wire, so an older host still reads it.
        let off = RoleRecipe::from_input(&input(json!({ "connection": "prod" }))).unwrap();
        assert_eq!(off.cache_ttl_secs, 0);
        assert!(serde_json::to_value(&off).unwrap().get("cache_ttl_secs").is_none());
        assert!(RoleRecipe::from_input(&input(json!({ "connection": "prod", "cache_ttl": "x" }))).is_err());
    }

    #[test]
    fn bad_roles_are_refused() {
        for bad in [
            json!({ "connection": "../x" }),
            json!({ "connection": "prod", "sql": "x" }),
            json!({ "connection": "prod", "default_ttl": "1h", "max_ttl": "30m" }),
            json!({ "connection": "prod", "username_max_len": 8 }),
            json!({ "connection": "prod", "creation_statements": [""] }),
            json!({ "connection": "prod", "default_ttl": "1y" }),
            json!({ "connection": "prod", "renew_statements": [1] }),
        ] {
            assert!(RoleRecipe::from_input(&input(bad.clone())).is_err(), "{bad}");
        }
    }

    #[test]
    fn durations_parse() {
        let p = |v: Value| parse_duration_secs("t", &v).unwrap();
        assert_eq!(p(json!("90")), 90);
        assert_eq!(p(json!("1h30m")), 5400);
        assert_eq!(p(json!("2d")), 172_800);
        assert_eq!(p(json!(null)), 0);
        assert!(parse_duration_secs("t", &json!("5")).is_ok());
        assert!(parse_duration_secs("t", &json!("h")).is_err());
        assert!(parse_duration_secs("t", &json!("10x")).is_err());
    }

    #[test]
    fn stored_roles_are_versioned() {
        let r = RoleRecipe::from_input(&input(json!({ "connection": "prod" }))).unwrap();
        let bytes = StoredRole::encode(&r).unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains("\"v\":1"));
        assert_eq!(StoredRole::decode(&bytes).unwrap(), r);
        // A record without `v` reads as version 1; a newer one is refused.
        assert_eq!(StoredRole::decode(br#"{"connection":"prod"}"#).unwrap().connection, "prod");
        assert!(StoredRole::decode(br#"{"v":2,"connection":"prod"}"#).is_err(), "a newer format is refused by name");
    }
}
