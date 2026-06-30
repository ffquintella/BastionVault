use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VersionData {
    /// Shared "base" key/value set, applied to every environment.
    pub data: Map<String, Value>,
    /// Per-environment override sets, keyed by environment name. Each value is
    /// a JSON object whose keys override (or add to) the base `data` when the
    /// secret is read with `?env=<name>`. Empty for legacy/plain secrets.
    ///
    /// `#[serde(default)]` keeps pre-existing on-disk versions deserializable;
    /// `skip_serializing_if` keeps base-only versions byte-stable (no
    /// migration, no churn on the encrypted blob).
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub envs: Map<String, Value>,
    pub version: u64,
    pub created_time: String,
    pub deletion_time: String,
    pub destroyed: bool,
    /// Username (or display name) of the token that created this version.
    #[serde(default)]
    pub username: String,
    /// "create" | "update" | "restore".
    #[serde(default)]
    pub operation: String,
}

/// Resolve the effective value for a given environment: the shared base
/// merged with the environment's override set. Override keys win; values are
/// replaced wholesale (shallow merge — nested objects are not deep-merged).
///
/// `overrides` is the JSON object stored under `envs[<name>]`. A non-object
/// (which should never happen for a well-formed write) contributes nothing.
pub fn merge_env(base: &Map<String, Value>, overrides: &Value) -> Map<String, Value> {
    let mut merged = base.clone();
    if let Some(obj) = overrides.as_object() {
        for (k, v) in obj {
            merged.insert(k.clone(), v.clone());
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn merge_overrides_win_over_base() {
        let base = json!({"host": "db", "port": 5432}).as_object().unwrap().clone();
        let overrides = json!({"host": "db.prod", "tls": true});
        let merged = merge_env(&base, &overrides);
        assert_eq!(merged.get("host").unwrap(), "db.prod");
        assert_eq!(merged.get("port").unwrap().as_u64(), Some(5432));
        assert_eq!(merged.get("tls").unwrap(), &Value::Bool(true));
    }

    #[test]
    fn merge_with_non_object_override_returns_base() {
        let base = json!({"host": "db"}).as_object().unwrap().clone();
        assert_eq!(merge_env(&base, &Value::Null), base);
    }

    #[test]
    fn legacy_versiondata_without_envs_deserializes() {
        // On-disk JSON written before the `envs` field existed.
        let raw = r#"{"data":{"k":"v"},"version":1,"created_time":"t","deletion_time":"","destroyed":false}"#;
        let vd: VersionData = serde_json::from_str(raw).unwrap();
        assert!(vd.envs.is_empty());
        assert_eq!(vd.data.get("k").unwrap(), "v");
    }

    #[test]
    fn base_only_versiondata_omits_envs_when_serialized() {
        let vd = VersionData {
            data: json!({"k": "v"}).as_object().unwrap().clone(),
            ..Default::default()
        };
        // `skip_serializing_if` keeps legacy base-only blobs byte-stable.
        assert!(!serde_json::to_string(&vd).unwrap().contains("envs"));
    }
}
