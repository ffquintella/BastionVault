//! The records the host exchanges with a dynamic plugin or persists for it.
//!
//! Persisted ones carry a format version `v`; a reader accepts every version
//! up to its own and refuses a newer one by name rather than misreading it.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    credential::{DEFAULT_USERNAME_MAX_LEN, MIN_USERNAME_MAX_LEN},
    template, DynamicError,
};

/// Key of [`DynamicLeaseInternal`] inside a lease's `internal_data`.
pub const LEASE_INTERNAL_KEY: &str = "bv_dynamic";
/// Current [`DynamicLeaseInternal`] format.
pub const LEASE_INTERNAL_VERSION: u32 = 1;
/// Current [`ConnectionRecord`] format.
pub const CONNECTION_RECORD_VERSION: u32 = 1;
/// Largest plugin `internal` blob a lease may carry, serialised.
pub const MAX_PLUGIN_INTERNAL_BYTES: usize = 16 * 1024;
/// Most statements of one kind a role may carry.
pub const MAX_STATEMENTS: usize = 32;

fn version_one() -> u32 {
    1
}

fn default_true() -> bool {
    true
}

fn default_username_max_len() -> usize {
    DEFAULT_USERNAME_MAX_LEN
}

/// What the host keeps on a dynamic lease so it can renew and revoke it
/// without asking the plugin to remember anything. Never holds the password.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DynamicLeaseInternal {
    #[serde(default = "version_one")]
    pub v: u32,
    pub plugin: String,
    pub plugin_version: String,
    pub engine_type: String,
    pub role: String,
    pub connection: String,
    /// The generated target identity.
    pub username: String,
    /// Expanded at generation (they need only the name and role).
    #[serde(default)]
    pub revocation_statements: Vec<String>,
    /// Kept as validated templates: `{{expiration}}` changes on every renew.
    #[serde(default)]
    pub renew_statements: Vec<String>,
    /// The lease's ceiling from issue, in seconds; 0 when none. Bounds the
    /// `{{expiration}}` a renewal renders.
    #[serde(default)]
    pub max_ttl_secs: u64,
    /// Opaque to the host; handed back to the plugin on renew and revoke.
    #[serde(default)]
    pub plugin_internal: Value,
    /// The credential was put in the credential cache, so a cluster-wide
    /// cache marker exists for it until its lease is renewed or revoked.
    /// Added without a format bump: absent (every older lease) reads `false`,
    /// which is right, since no older node wrote a marker.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cached: bool,
}

impl DynamicLeaseInternal {
    /// Read the record out of a lease's `internal_data`.
    pub fn from_internal_data(data: &Map<String, Value>) -> Result<Self, DynamicError> {
        let raw = data
            .get(LEASE_INTERNAL_KEY)
            .ok_or_else(|| DynamicError::invalid("lease", "not issued by the dynamic-secrets host"))?;
        let rec: Self = serde_json::from_value(raw.clone())
            .map_err(|e| DynamicError::invalid("lease internal data", e.to_string()))?;
        if rec.v > LEASE_INTERNAL_VERSION {
            return Err(DynamicError::UnsupportedVersion { record: "dynamic lease", version: rec.v });
        }
        Ok(rec)
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

/// Host-owned settings of one connection, written when the operator writes
/// `config/<name>` and never by the plugin: the TLS policy the pool enforces
/// and the root credential version its connections are keyed by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionRecord {
    #[serde(default = "version_one")]
    pub v: u32,
    #[serde(default = "version_one_u64")]
    pub root_credential_version: u64,
    #[serde(default)]
    pub insecure_skip_tls_verify: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca_pem: Option<String>,
    /// A fresh random value on every `config/<name>` write (never an
    /// increment, so two nodes writing at once cannot repeat one), so every
    /// node's pool drains connections opened under the previous settings.
    /// Additive: a record without it reads 0; an older node ignores it.
    #[serde(default)]
    pub config_generation: u64,
    /// The non-secret target of the last accepted `config/<name>` write
    /// (`connection_url`, `username`), pinned by the host: a host execution
    /// dials only this endpoint. Absent on older records, and then the host
    /// offers no host execution for the connection (the plugin dials).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

fn version_one_u64() -> u64 {
    1
}

impl Default for ConnectionRecord {
    fn default() -> Self {
        Self {
            v: CONNECTION_RECORD_VERSION,
            root_credential_version: 1,
            insecure_skip_tls_verify: false,
            tls_ca_pem: None,
            config_generation: 0,
            connection_url: None,
            username: None,
        }
    }
}

impl ConnectionRecord {
    pub fn decode(bytes: &[u8]) -> Result<Self, DynamicError> {
        let rec: Self =
            serde_json::from_slice(bytes).map_err(|e| DynamicError::invalid("connection record", e.to_string()))?;
        if rec.v > CONNECTION_RECORD_VERSION {
            return Err(DynamicError::UnsupportedVersion { record: "connection", version: rec.v });
        }
        Ok(rec)
    }

    pub fn tls_policy(&self) -> crate::pool::TlsPolicy {
        match (&self.tls_ca_pem, self.insecure_skip_tls_verify) {
            (_, true) => crate::pool::TlsPolicy::insecure_skip_verify(),
            (Some(pem), false) => crate::pool::TlsPolicy::verify_with_ca(pem.clone()),
            (None, false) => crate::pool::TlsPolicy::default(),
        }
    }

    /// The pinned `(connection_url, username)`, when both were configured.
    pub fn pinned_endpoint(&self) -> Option<(&str, &str)> {
        Some((self.connection_url.as_deref()?, self.username.as_deref()?))
    }

    /// What the pool keys and drains this connection's target by.
    pub fn target_settings(&self) -> crate::pool::TargetSettings {
        crate::pool::TargetSettings {
            root_credential_version: self.root_credential_version,
            config_generation: self.config_generation,
            tls: self.tls_policy(),
        }
    }
}

/// A role as its plugin describes it to the host (`dynamic.role`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Opt-in credential cache window in seconds; 0 (the default) is off.
    /// The host clamps it (see `cache::effective_ttl`).
    #[serde(default)]
    pub cache_ttl_secs: u64,
}

impl RoleRecipe {
    /// Every template is checked against the allowlist; `{{password}}` may
    /// appear in creation statements only.
    pub fn validate(&self) -> Result<(), DynamicError> {
        check_name("connection", &self.connection)?;
        for (list, allow_password) in
            [(&self.creation_statements, true), (&self.revocation_statements, false), (&self.renew_statements, false)]
        {
            if list.len() > MAX_STATEMENTS {
                return Err(DynamicError::invalid("statements", format!("at most {MAX_STATEMENTS} per kind")));
            }
            for s in list {
                template::validate(s, allow_password)?;
            }
        }
        if !(MIN_USERNAME_MAX_LEN..=DEFAULT_USERNAME_MAX_LEN).contains(&self.username_max_len) {
            return Err(DynamicError::invalid(
                "username_max_len",
                format!("must be {MIN_USERNAME_MAX_LEN}..={DEFAULT_USERNAME_MAX_LEN}"),
            ));
        }
        Ok(())
    }

    /// The TTL a new credential gets: the role's default (one hour when it
    /// sets none), never past its max_ttl or `ceiling`.
    pub fn initial_ttl(&self, ceiling: Duration) -> Duration {
        let ttl = match self.default_ttl_secs {
            0 => Duration::from_secs(3600),
            s => Duration::from_secs(s),
        };
        let ttl = match self.max_ttl_secs {
            0 => ttl,
            m => ttl.min(Duration::from_secs(m)),
        };
        ttl.min(ceiling).max(Duration::from_secs(1))
    }
}

/// What a plugin asks the host to lease (`dynamic_lease_register`). It names
/// lifetimes and an opaque blob; the credential itself never passes here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRequest {
    #[serde(default)]
    pub internal: Value,
    #[serde(default)]
    pub ttl_secs: u64,
    #[serde(default)]
    pub max_ttl_secs: u64,
    #[serde(default = "default_true")]
    pub renewable: bool,
}

impl LeaseRequest {
    pub fn parse(params: &Value) -> Result<Self, DynamicError> {
        let req: Self = serde_json::from_value(params.clone())
            .map_err(|e| DynamicError::invalid("dynamic_lease_register request", e.to_string()))?;
        let size = serde_json::to_vec(&req.internal).map(|v| v.len()).unwrap_or(usize::MAX);
        if size > MAX_PLUGIN_INTERNAL_BYTES {
            return Err(DynamicError::invalid("internal", format!("exceeds {MAX_PLUGIN_INTERNAL_BYTES} bytes")));
        }
        Ok(req)
    }
}

/// Names that end up in storage keys and pool keys: `[A-Za-z0-9_.-]`, 1-64
/// characters, never `.` or `..`.
pub fn check_name(field: &'static str, value: &str) -> Result<(), DynamicError> {
    let ok = !value.is_empty()
        && value.len() <= 64
        && value != "."
        && value != ".."
        && value.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if ok {
        Ok(())
    } else {
        Err(DynamicError::invalid(field, "must be 1-64 characters of [A-Za-z0-9_.-]"))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn internal() -> DynamicLeaseInternal {
        DynamicLeaseInternal {
            v: LEASE_INTERNAL_VERSION,
            plugin: "pg".into(),
            plugin_version: "0.1.0".into(),
            engine_type: "database".into(),
            role: "readonly".into(),
            connection: "prod".into(),
            username: "v-a-r-1-00000000".into(),
            revocation_statements: vec!["DROP ROLE \"v-a-r-1-00000000\"".into()],
            renew_statements: vec!["ALTER ROLE \"{{name}}\" VALID UNTIL '{{expiration}}'".into()],
            max_ttl_secs: 3600,
            plugin_internal: json!({"oid": 42}),
            cached: false,
        }
    }

    /// Read-old/write-new for the two fields added with host connectors and
    /// cluster-wide cache invalidation: rows written before them read with
    /// the safe default, and a row that does not need one does not write it.
    #[test]
    fn records_written_before_cached_and_config_generation_still_read() {
        let old_lease = json!({"v":1,"plugin":"pg","plugin_version":"0.2.0","engine_type":"database",
            "role":"r","connection":"c","username":"u","revocation_statements":[],"renew_statements":[],
            "max_ttl_secs":0,"plugin_internal":null});
        let mut data = Map::new();
        data.insert(LEASE_INTERNAL_KEY.into(), old_lease);
        assert!(!DynamicLeaseInternal::from_internal_data(&data).unwrap().cached, "no marker was ever written");
        assert!(internal().to_value().get("cached").is_none(), "an uncached lease row is unchanged");
        let cached = DynamicLeaseInternal { cached: true, ..internal() };
        data.insert(LEASE_INTERNAL_KEY.into(), cached.to_value());
        assert!(DynamicLeaseInternal::from_internal_data(&data).unwrap().cached);

        let old_conn = br#"{"v":1,"root_credential_version":3,"insecure_skip_tls_verify":false}"#;
        let rec = ConnectionRecord::decode(old_conn).unwrap();
        assert_eq!(rec.config_generation, 0);
        assert_eq!(rec.pinned_endpoint(), None, "an older record pins nothing: no host execution");
        let pinned = ConnectionRecord { connection_url: Some("host=db".into()), ..rec.clone() };
        assert_eq!(pinned.pinned_endpoint(), None, "both halves are needed");
        let pinned = ConnectionRecord { username: Some("vault".into()), ..pinned };
        assert_eq!(pinned.pinned_endpoint(), Some(("host=db", "vault")));
        let numeric = br#"{"v":1,"config_generation":7}"#;
        assert_eq!(ConnectionRecord::decode(numeric).unwrap().config_generation, 7, "older counters still read");
        assert_eq!(rec.target_settings().root_credential_version, 3);
        let bumped = ConnectionRecord { config_generation: 4, ..rec };
        let back = ConnectionRecord::decode(&serde_json::to_vec(&bumped).unwrap()).unwrap();
        assert_eq!(back.v, CONNECTION_RECORD_VERSION, "additive: still format 1, readable by older nodes");
        assert_eq!(back.target_settings().config_generation, 4);
    }

    #[test]
    fn lease_internal_round_trips_through_internal_data() {
        let mut data = Map::new();
        data.insert(LEASE_INTERNAL_KEY.into(), internal().to_value());
        assert_eq!(DynamicLeaseInternal::from_internal_data(&data).unwrap(), internal());
    }

    #[test]
    fn lease_internal_never_names_a_password() {
        let v = internal().to_value();
        assert!(v.get("password").is_none());
    }

    #[test]
    fn lease_internal_tolerates_missing_optional_fields_and_refuses_newer_versions() {
        let mut data = Map::new();
        data.insert(
            LEASE_INTERNAL_KEY.into(),
            json!({"plugin":"pg","plugin_version":"1","engine_type":"database","role":"r","connection":"c","username":"u"}),
        );
        let rec = DynamicLeaseInternal::from_internal_data(&data).unwrap();
        assert_eq!(rec.v, 1);
        assert!(rec.revocation_statements.is_empty());
        assert_eq!(rec.plugin_internal, Value::Null);

        let mut future = internal().to_value();
        future["v"] = json!(LEASE_INTERNAL_VERSION + 1);
        data.insert(LEASE_INTERNAL_KEY.into(), future);
        assert!(matches!(
            DynamicLeaseInternal::from_internal_data(&data),
            Err(DynamicError::UnsupportedVersion { version: 2, .. })
        ));
        assert!(DynamicLeaseInternal::from_internal_data(&Map::new()).is_err(), "not a dynamic lease");
    }

    #[test]
    fn connection_record_defaults_to_verifying_tls() {
        let rec = ConnectionRecord::decode(br#"{}"#).unwrap();
        assert_eq!(rec, ConnectionRecord::default());
        assert!(rec.tls_policy().verifies());
        let insecure = ConnectionRecord { insecure_skip_tls_verify: true, ..Default::default() };
        assert!(!insecure.tls_policy().verifies());
        let ca = ConnectionRecord { tls_ca_pem: Some("PEM".into()), ..Default::default() };
        assert_eq!(ca.tls_policy().ca_pem(), Some("PEM"));
        assert!(matches!(
            ConnectionRecord::decode(br#"{"v":9}"#),
            Err(DynamicError::UnsupportedVersion { version: 9, .. })
        ));
    }

    fn recipe() -> RoleRecipe {
        serde_json::from_value(json!({
            "connection": "prod",
            "creation_statements": ["CREATE ROLE \"{{name}}\" PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'"],
            "revocation_statements": ["DROP ROLE \"{{name}}\""],
            "default_ttl_secs": 1800,
            "max_ttl_secs": 3600
        }))
        .unwrap()
    }

    #[test]
    fn recipes_are_validated() {
        recipe().validate().unwrap();
        let mut r = recipe();
        r.revocation_statements = vec!["DROP ROLE \"{{name}}\" -- {{password}}".into()];
        assert!(r.validate().is_err(), "the password never reaches a revocation statement");
        let mut r = recipe();
        r.creation_statements = vec!["CREATE ROLE {{user}}".into()];
        assert!(r.validate().is_err());
        let mut r = recipe();
        r.connection = "../other".into();
        assert!(r.validate().is_err());
        let mut r = recipe();
        r.username_max_len = 8;
        assert!(r.validate().is_err());
        assert!(serde_json::from_value::<RoleRecipe>(json!({"connection":"c","sql":"x"})).is_err());
    }

    #[test]
    fn the_cache_window_is_opt_in_and_old_recipes_still_parse() {
        assert_eq!(recipe().cache_ttl_secs, 0, "a recipe without the field never caches");
        let r: RoleRecipe = serde_json::from_value(json!({"connection": "prod", "cache_ttl_secs": 30})).unwrap();
        assert_eq!(r.cache_ttl_secs, 30);
        r.validate().unwrap();
    }

    #[test]
    fn initial_ttl_respects_max_ttl_and_ceiling() {
        let r = recipe();
        assert_eq!(r.initial_ttl(Duration::from_secs(86_400)), Duration::from_secs(1800));
        assert_eq!(r.initial_ttl(Duration::from_secs(60)), Duration::from_secs(60));
        let mut r = recipe();
        r.default_ttl_secs = 0;
        r.max_ttl_secs = 600;
        assert_eq!(r.initial_ttl(Duration::from_secs(86_400)), Duration::from_secs(600));
    }

    #[test]
    fn lease_requests_are_bounded() {
        let req = LeaseRequest::parse(&json!({"internal": {"oid": 1}, "ttl_secs": 60})).unwrap();
        assert!(req.renewable);
        assert!(LeaseRequest::parse(&json!({"internal": "x".repeat(MAX_PLUGIN_INTERNAL_BYTES)})).is_err());
        assert!(LeaseRequest::parse(&json!({"password": "nope"})).is_err(), "unknown fields are refused");
    }
}
