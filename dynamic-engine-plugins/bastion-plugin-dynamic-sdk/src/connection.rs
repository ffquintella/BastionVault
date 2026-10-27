//! Connections: the coordinates and root credential of a target system,
//! stored by the plugin at `config/<name>`. The host keeps the TLS policy and
//! root credential version itself and strips them from the write it proxies.
//! Secret fields live in the host's barrier-encrypted plugin storage and are
//! never returned: a `config/<name>` read answers settings and roles only.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::{Zeroize, Zeroizing};

use crate::{role::check_name, secret::SecretString, DynamicError};

/// Current stored-connection format.
pub const CONNECTION_RECORD_VERSION: u32 = 1;
/// The `allowed_roles` entry that admits every role.
pub const ANY_ROLE: &str = "*";

/// Which `config/<name>` fields an engine accepts. Anything else is refused.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionSchema {
    /// Non-secret settings; a read returns them.
    pub settings: &'static [&'static str],
    /// Secret fields; stored, never returned.
    pub secrets: &'static [&'static str],
    /// Fields every connection must end up with.
    pub required: &'static [&'static str],
}

/// One stored connection, with its secrets.
#[derive(Clone)]
pub struct Connection {
    pub name: String,
    /// Roles allowed to use the connection; `*` admits all. Empty (the
    /// default) admits none, so a new connection mints nothing by accident.
    pub allowed_roles: Vec<String>,
    settings: BTreeMap<String, Value>,
    secrets: BTreeMap<String, SecretString>,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("name", &self.name)
            .field("allowed_roles", &self.allowed_roles)
            .field("settings", &self.settings)
            .field("secrets", &self.secrets.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
struct StoredConnection {
    #[serde(default = "crate::role::record_version_one")]
    v: u32,
    #[serde(default)]
    allowed_roles: Vec<String>,
    #[serde(default)]
    settings: BTreeMap<String, Value>,
    #[serde(default)]
    secrets: BTreeMap<String, String>,
}

impl Drop for StoredConnection {
    fn drop(&mut self) {
        self.secrets.values_mut().for_each(Zeroize::zeroize);
    }
}

fn role_list(value: &Value) -> Result<Vec<String>, DynamicError> {
    let bad = || DynamicError::invalid("`allowed_roles` must be a list of role names or a comma-separated string");
    let names: Vec<String> = match value {
        Value::Null => Vec::new(),
        Value::String(s) => s.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect(),
        Value::Array(items) => items
            .iter()
            .map(|v| v.as_str().map(|s| s.trim().to_string()))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(bad)?,
        _ => return Err(bad()),
    };
    for n in &names {
        if n != ANY_ROLE {
            check_name("allowed_roles entry", n)?;
        }
    }
    Ok(names)
}

impl Connection {
    pub fn new(name: &str) -> Self {
        Self { name: name.to_string(), allowed_roles: Vec::new(), settings: BTreeMap::new(), secrets: BTreeMap::new() }
    }

    pub fn setting(&self, key: &str) -> Option<&Value> {
        self.settings.get(key)
    }

    pub fn setting_str(&self, key: &str) -> Option<&str> {
        self.settings.get(key).and_then(Value::as_str)
    }

    pub fn secret(&self, key: &str) -> Option<&SecretString> {
        self.secrets.get(key)
    }

    /// Replace a secret (e.g. the root password after `rotate-root`).
    pub fn set_secret(&mut self, key: &str, value: SecretString) {
        self.secrets.insert(key.to_string(), value);
    }

    pub fn allows_role(&self, role: &str) -> bool {
        self.allowed_roles.iter().any(|r| r == ANY_ROLE || r == role)
    }

    pub(crate) fn secret_values(&self) -> impl Iterator<Item = &SecretString> {
        self.secrets.values()
    }

    /// What a `config/<name>` read answers: never a secret.
    pub(crate) fn metadata(&self) -> Map<String, Value> {
        let mut out: Map<String, Value> = self.settings.clone().into_iter().collect();
        out.insert("allowed_roles".into(), Value::from(self.allowed_roles.clone()));
        out
    }

    /// Merge an operator's write. A field left out keeps its stored value; a
    /// `null` clears it. Unknown fields are refused.
    pub fn apply_input(&mut self, schema: &ConnectionSchema, input: &Map<String, Value>) -> Result<(), DynamicError> {
        for (key, value) in input {
            if key == "allowed_roles" {
                self.allowed_roles = role_list(value)?;
            } else if schema.secrets.contains(&key.as_str()) {
                match value {
                    Value::Null => {
                        self.secrets.remove(key);
                    }
                    Value::String(s) if !s.is_empty() => {
                        self.secrets.insert(key.clone(), SecretString::new(s.clone()));
                    }
                    _ => return Err(DynamicError::invalid(format!("`{key}` must be a non-empty string"))),
                }
            } else if schema.settings.contains(&key.as_str()) {
                match value {
                    Value::Null => {
                        self.settings.remove(key);
                    }
                    Value::String(_) | Value::Number(_) | Value::Bool(_) => {
                        self.settings.insert(key.clone(), value.clone());
                    }
                    _ => return Err(DynamicError::invalid(format!("`{key}` must be a string, number or boolean"))),
                }
            } else {
                return Err(DynamicError::invalid(format!("unknown connection field `{key}`")));
            }
        }
        for field in schema.required {
            if !self.settings.contains_key(*field) && !self.secrets.contains_key(*field) {
                return Err(DynamicError::invalid(format!("connection field `{field}` is required")));
            }
        }
        Ok(())
    }

    pub(crate) fn decode(name: &str, bytes: &[u8]) -> Result<Self, DynamicError> {
        let mut stored: StoredConnection =
            serde_json::from_slice(bytes).map_err(|e| DynamicError::invalid(format!("stored connection: {e}")))?;
        if stored.v > CONNECTION_RECORD_VERSION {
            return Err(DynamicError::invalid(format!(
                "stored connection is format version {}, newer than this plugin understands ({CONNECTION_RECORD_VERSION})",
                stored.v
            )));
        }
        let secrets =
            stored.secrets.iter_mut().map(|(k, v)| (k.clone(), SecretString::new(std::mem::take(v)))).collect();
        Ok(Self {
            name: name.to_string(),
            allowed_roles: std::mem::take(&mut stored.allowed_roles),
            settings: std::mem::take(&mut stored.settings),
            secrets,
        })
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, DynamicError> {
        let stored = StoredConnection {
            v: CONNECTION_RECORD_VERSION,
            allowed_roles: self.allowed_roles.clone(),
            settings: self.settings.clone(),
            secrets: self.secrets.iter().map(|(k, v)| (k.clone(), v.expose().to_string())).collect(),
        };
        serde_json::to_vec(&stored).map(Zeroizing::new).map_err(|e| DynamicError::invalid(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const SCHEMA: ConnectionSchema = ConnectionSchema {
        settings: &["connection_url", "username"],
        secrets: &["password"],
        required: &["connection_url"],
    };

    fn write(conn: &mut Connection, v: Value) -> Result<(), DynamicError> {
        conn.apply_input(&SCHEMA, v.as_object().unwrap())
    }

    #[test]
    fn metadata_never_carries_a_secret() {
        let mut c = Connection::new("prod");
        write(
            &mut c,
            json!({ "connection_url": "postgres://db/app", "password": "root-secret-123", "allowed_roles": "ro, rw" }),
        )
        .unwrap();
        let meta = Value::Object(c.metadata()).to_string();
        assert!(!meta.contains("root-secret-123"), "{meta}");
        assert!(meta.contains("postgres://db/app"));
        assert_eq!(c.allowed_roles, ["ro", "rw"]);
        assert!(!format!("{c:?}").contains("root-secret-123"));
    }

    #[test]
    fn writes_merge_and_refuse_unknown_fields() {
        let mut c = Connection::new("prod");
        write(&mut c, json!({ "connection_url": "postgres://db/app", "password": "root-secret-123" })).unwrap();
        write(&mut c, json!({ "allowed_roles": ["*"] })).unwrap();
        assert_eq!(c.secret("password").unwrap().expose(), "root-secret-123", "kept when not resent");
        assert!(c.allows_role("anything"));
        assert!(write(&mut c, json!({ "pasword": "x" })).is_err());
        assert!(write(&mut c, json!({ "allowed_roles": ["../x"] })).is_err());
        assert!(write(&mut c, json!({ "password": "" })).is_err());
        assert!(write(&mut Connection::new("x"), json!({ "username": "u" })).is_err(), "connection_url is required");
        assert!(!Connection::new("x").allows_role("ro"), "no role by default");
    }

    #[test]
    fn records_round_trip_and_are_versioned() {
        let mut c = Connection::new("prod");
        write(
            &mut c,
            json!({ "connection_url": "postgres://db/app", "password": "root-secret-123", "allowed_roles": ["ro"] }),
        )
        .unwrap();
        let bytes = c.encode().unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains("\"v\":1"));
        let back = Connection::decode("prod", &bytes).unwrap();
        assert_eq!(back.secret("password").unwrap().expose(), "root-secret-123");
        assert_eq!(back.allowed_roles, ["ro"]);
        assert!(Connection::decode("prod", br#"{"v":9}"#).is_err());
        assert!(Connection::decode("prod", br#"{"settings":{"connection_url":"x"}}"#).is_ok(), "no v reads as 1");
    }
}
