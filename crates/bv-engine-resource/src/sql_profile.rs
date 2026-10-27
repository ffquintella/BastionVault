//! The `sql` Connect protocol on `database` resources, the pure half
//! (features/sql-browser.md §5, §9.5; T124 Phase 1, subsystem 5). Parsing
//! and resolution only; the storage reads are in [`crate::sql_resource`].
//! An `sql` profile parses strictly (the T101 precedent): an unknown key, a
//! wrongly typed field or a value outside its vocabulary fails it closed.
//! Profiles of other protocols are never read here, so a record a pre-T102
//! GUI saved, keeping profiles it does not understand, is untouched.

use serde::Deserialize;
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use crate::kernel_api::policy::SqlCapability;
use crate::{bv_error_response_status, errors::RvError};

/// The protocol name on a connection profile.
pub const SQL_PROTOCOL: &str = "sql";
/// The built-in resource type the `sql` protocol is offered on.
pub const DATABASE_TYPE: &str = "database";
/// The reserved key on a resource secret naming the endpoints it may be sent
/// to (§5.4 rule 5).
pub const SQL_ENDPOINT_KEY: &str = "sql_endpoint";

/// Longest profile id, label, catalog or instance accepted.
const MAX_ID_LEN: usize = 128;
const MAX_LABEL_LEN: usize = 256;
const MAX_NAME_LEN: usize = crate::kernel_api::policy::SQL_MAX_NAME_LEN;
/// Longest `tls.ca_pem` accepted (a CA bundle, not a certificate store).
const MAX_CA_PEM_LEN: usize = 64 * 1024;
/// Longest DNS name.
const MAX_HOST_LEN: usize = 253;

// ── refusals ────────────────────────────────────────────────────────────

/// Why a database resource, an `sql` profile or its credential cannot be
/// used. `code` is stable and is the error's prefix; `message` never carries
/// a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlRefusal {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

/// The stable codes, as error prefixes.
pub mod reason {
    pub const INVALID_PROFILE: &str = "invalid_profile";
    pub const INVALID_RESOURCE_SETTINGS: &str = "invalid_resource_settings";
    pub const INVALID_TYPE_CONFIG: &str = "invalid_type_config";
    pub const NOT_A_DATABASE: &str = "not_a_database";
    pub const ENGINE_UNSUPPORTED: &str = "engine_unsupported";
    pub const SQL_DISABLED_FOR_TYPE: &str = "sql_disabled_for_type";
    pub const RESOURCE_NOT_FOUND: &str = "resource_not_found";
    pub const PROFILE_NOT_FOUND: &str = "profile_not_found";
    pub const PROFILE_NOT_SQL: &str = "profile_not_sql";
    pub const ENDPOINT_UNRESOLVABLE: &str = "endpoint_unresolvable";
    pub const CREDENTIAL_MISSING: &str = "credential_missing";
    pub const CREDENTIAL_INVALID: &str = "credential_invalid";
    pub const DYNAMIC_NOT_AVAILABLE: &str = "dynamic_not_available";
    pub const RESOURCE_MOUNT_UNAVAILABLE: &str = "resource_mount_unavailable";
}

impl SqlRefusal {
    pub fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into() }
    }

    fn invalid_profile(message: impl Into<String>) -> Self {
        Self::new(422, reason::INVALID_PROFILE, message)
    }

    pub fn into_rv(self) -> RvError {
        bv_error_response_status!(self.status, format!("{}: {}", self.code, self.message))
    }
}

impl std::fmt::Display for SqlRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl From<SqlRefusal> for RvError {
    fn from(r: SqlRefusal) -> Self {
        r.into_rv()
    }
}

// ── engines ─────────────────────────────────────────────────────────────

/// The engines the `database` type offers the `sql` protocol for, spelled
/// as the type's `engine` select stores them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlEngine {
    Postgresql,
    Mysql,
    Mariadb,
    Mssql,
    Oracle,
}

impl SqlEngine {
    pub const ALL: [SqlEngine; 5] =
        [SqlEngine::Postgresql, SqlEngine::Mysql, SqlEngine::Mariadb, SqlEngine::Mssql, SqlEngine::Oracle];

    pub const fn as_str(self) -> &'static str {
        match self {
            SqlEngine::Postgresql => "postgresql",
            SqlEngine::Mysql => "mysql",
            SqlEngine::Mariadb => "mariadb",
            SqlEngine::Mssql => "mssql",
            SqlEngine::Oracle => "oracle",
        }
    }

    /// The `database` type's default port for this engine.
    pub const fn default_port(self) -> u16 {
        match self {
            SqlEngine::Postgresql => 5432,
            SqlEngine::Mysql | SqlEngine::Mariadb => 3306,
            SqlEngine::Mssql => 1433,
            SqlEngine::Oracle => 1521,
        }
    }

    /// Exactly one of the five spellings; anything else (another engine the
    /// type lists, `""`, a different case) is `None`.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.as_str() == s)
    }
}

/// Is `sql` offered for the `database` type under its saved definition?
/// `None` (nothing saved) is the built-in block, which offers it.
/// `connect.enabled = false` turns everything off; a `connect.protocols`
/// array offers what it lists, any other value nothing (the GUI's
/// `connectProtocols`). `Err` for a block this server cannot read.
pub fn sql_offered_by_type(type_def: Option<&Value>) -> Result<bool, String> {
    let Some(def) = type_def else {
        return Ok(true);
    };
    let connect = match def.get("connect") {
        None | Some(Value::Null) => return Ok(true),
        Some(Value::Object(c)) => c,
        Some(_) => return Err("the `database` type's `connect` must be an object".into()),
    };
    match connect.get("enabled") {
        None | Some(Value::Null) | Some(Value::Bool(true)) => {}
        Some(Value::Bool(false)) => return Ok(false),
        Some(_) => return Err("the `database` type's `connect.enabled` must be a boolean".into()),
    }
    match connect.get("protocols") {
        None | Some(Value::Null) => Ok(true),
        Some(Value::Array(list)) => Ok(list.iter().any(|p| p.as_str() == Some(SQL_PROTOCOL))),
        Some(_) => Ok(false),
    }
}

// ── the resource-level `sql` block ──────────────────────────────────────

/// Where statements are enforced (§5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlEnforcement {
    /// The default: a read-only grant needs a read-only login; the database
    /// enforces the ceiling.
    DatabaseFirst,
    /// Opt-in: any profile whose ceiling covers the grant may serve, and the
    /// classifier alone holds the line (`db_enforced: false` in audit).
    ClassifierOnly,
}

impl SqlEnforcement {
    pub const fn as_str(self) -> &'static str {
        match self {
            SqlEnforcement::DatabaseFirst => "database-first",
            SqlEnforcement::ClassifierOnly => "classifier-only",
        }
    }
}

/// The resource record's own `sql` block: `{ "enforcement": … }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqlResourceSettings {
    pub enforcement: SqlEnforcement,
}

/// Read the resource record's `sql` block strictly. Absent is the default
/// (`database-first`); an unknown key or value refuses.
pub fn parse_resource_settings(meta: &Map<String, Value>) -> Result<SqlResourceSettings, SqlRefusal> {
    let bad = |m: &str| SqlRefusal::new(422, reason::INVALID_RESOURCE_SETTINGS, m);
    let block = match meta.get("sql") {
        None | Some(Value::Null) => return Ok(SqlResourceSettings { enforcement: SqlEnforcement::DatabaseFirst }),
        Some(Value::Object(o)) => o,
        Some(_) => return Err(bad("the resource's `sql` must be an object")),
    };
    if let Some(k) = block.keys().find(|k| k.as_str() != "enforcement") {
        return Err(bad(&format!("the resource's `sql` has an unknown key `{}`", truncate(k))));
    }
    let enforcement = match block.get("enforcement") {
        None | Some(Value::Null) => SqlEnforcement::DatabaseFirst,
        Some(Value::String(s)) if s == "database-first" => SqlEnforcement::DatabaseFirst,
        Some(Value::String(s)) if s == "classifier-only" => SqlEnforcement::ClassifierOnly,
        Some(_) => return Err(bad("`sql.enforcement` must be \"database-first\" or \"classifier-only\"")),
    };
    Ok(SqlResourceSettings { enforcement })
}

// ── endpoints ───────────────────────────────────────────────────────────

/// A database endpoint, `host:port` (IPv6 hosts bracketed). The one parser
/// both the profile side and the secret's binding go through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlEndpoint {
    pub host: String,
    pub port: u16,
}

impl SqlEndpoint {
    /// Parse `host:port` or `[v6]:port`. A missing or zero port, an empty
    /// host or whitespace is `None`. The host is lower-cased.
    pub fn parse(s: &str) -> Option<Self> {
        if s.is_empty() || s.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return None;
        }
        let (host, port) = if let Some(rest) = s.strip_prefix('[') {
            let (h, p) = rest.split_once("]:")?;
            (h, p)
        } else {
            let (h, p) = s.rsplit_once(':')?;
            if h.contains(':') {
                return None;
            }
            (h, p)
        };
        let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
        if host.is_empty() || host.contains(['[', ']', '/']) {
            return None;
        }
        Some(Self { host: host.to_ascii_lowercase(), port })
    }

    /// The same endpoint (host compared without ASCII case).
    pub fn matches(&self, other: &SqlEndpoint) -> bool {
        self.port == other.port && self.host.eq_ignore_ascii_case(&other.host)
    }
}

impl std::fmt::Display for SqlEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// Why a secret's `sql_endpoint` binds nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingError {
    /// Absent, `null` or an empty list: the credential is not bound.
    Unbound,
    /// A value or an entry that is not `host:port`.
    Invalid,
}

/// The endpoints a secret's `sql_endpoint` names: `"host:port"` or a list
/// of them. Any malformed entry invalidates the whole binding.
pub fn bound_endpoints(value: Option<&Value>) -> Result<Vec<SqlEndpoint>, BindingError> {
    let entries: Vec<&Value> = match value {
        None | Some(Value::Null) => return Err(BindingError::Unbound),
        Some(v @ Value::String(_)) => vec![v],
        Some(Value::Array(a)) => a.iter().collect(),
        Some(_) => return Err(BindingError::Invalid),
    };
    if entries.is_empty() {
        return Err(BindingError::Unbound);
    }
    entries.into_iter().map(|v| v.as_str().and_then(SqlEndpoint::parse).ok_or(BindingError::Invalid)).collect()
}

/// A secret write carrying the reserved `sql_endpoint` key must bind
/// something well formed, or unbind (`null` / `[]`), so a typo is refused
/// at write time rather than at every release.
pub fn validate_sql_endpoint_on_write(body: &Map<String, Value>) -> Result<(), String> {
    match bound_endpoints(body.get(SQL_ENDPOINT_KEY)) {
        Ok(_) | Err(BindingError::Unbound) => Ok(()),
        Err(BindingError::Invalid) => Err(format!(
            "`{SQL_ENDPOINT_KEY}` is reserved for the SQL browser's endpoint binding: it must be \"host:port\" \
             (\"[v6]:port\" for IPv6) or a list of them"
        )),
    }
}

/// A host as the plugin will dial it: ASCII (punycode for IDNs), lower-cased,
/// no whitespace, path, userinfo, wildcard or percent-encoding, no leading,
/// trailing or doubled dot; or a bare IPv6 address.
fn dial_host(raw: &str, what: &str) -> Result<String, String> {
    let bad = || format!("{what} must be a host name or an IP address");
    if raw.is_empty() || raw.len() > MAX_HOST_LEN || !raw.is_ascii() {
        return Err(bad());
    }
    if raw.contains(':') {
        return raw.parse::<std::net::Ipv6Addr>().map(|_| raw.to_ascii_lowercase()).map_err(|_| bad());
    }
    let ok_chars = raw.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_');
    if !ok_chars || raw.starts_with('.') || raw.ends_with('.') || raw.contains("..") {
        return Err(bad());
    }
    Ok(raw.to_ascii_lowercase())
}

// ── profiles ────────────────────────────────────────────────────────────

/// `tls.mode` (§5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlTlsMode {
    VerifyFull,
    VerifyCa,
    Require,
    Disable,
}

impl SqlTlsMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            SqlTlsMode::VerifyFull => "verify-full",
            SqlTlsMode::VerifyCa => "verify-ca",
            SqlTlsMode::Require => "require",
            SqlTlsMode::Disable => "disable",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        [SqlTlsMode::VerifyFull, SqlTlsMode::VerifyCa, SqlTlsMode::Require, SqlTlsMode::Disable]
            .into_iter()
            .find(|m| m.as_str() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlTls {
    pub mode: SqlTlsMode,
    pub server_name: Option<String>,
    pub ca_pem: Option<String>,
}

/// Where a profile's credential comes from (§5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqlCredentialSource {
    /// A resource secret, released only with the endpoint binding.
    Secret { secret_id: String },
    /// Reserved for Phase 9 (T130, blocked by T62): parsed, never released.
    Dynamic { mount: String, role: String },
}

/// A strictly parsed `sql` connection profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlProfile {
    pub id: String,
    /// The profile's `label`, else its `name`.
    pub label: Option<String>,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    pub catalog: Option<String>,
    pub instance: Option<String>,
    pub tls: SqlTls,
    /// What the login can do at the database, as the operator states it.
    pub ceiling: Vec<SqlCapability>,
    pub require_mfa: bool,
    /// Capabilities whose use needs a fresh ticket (Phase 5, T126).
    pub step_up: Vec<SqlCapability>,
    pub credential_source: SqlCredentialSource,
}

const PROFILE_KEYS: [&str; 8] = ["id", "name", "label", "is_default", "protocol", "target", "sql", "credential_source"];
const SQL_BLOCK_KEYS: [&str; 6] = ["catalog", "instance", "tls", "ceiling", "require_mfa", "step_up"];

fn truncate(s: &str) -> String {
    s.chars().take(64).collect()
}

fn only_keys(o: &Map<String, Value>, allowed: &[&str], what: &str) -> Result<(), SqlRefusal> {
    match o.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => Err(SqlRefusal::invalid_profile(format!("{what} has an unknown key `{}`", truncate(k)))),
        None => Ok(()),
    }
}

/// An optional text field: absent, `null` or `""` is `None`; a non-string,
/// control characters or more than `max` bytes refuse.
fn opt_text(o: &Map<String, Value>, key: &str, max: usize, what: &str) -> Result<Option<String>, SqlRefusal> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) if s.len() <= max && !s.chars().any(char::is_control) => Ok(Some(s.clone())),
        Some(_) => Err(SqlRefusal::invalid_profile(format!("{what} `{key}` must be a string of at most {max} bytes"))),
    }
}

fn opt_bool(o: &Map<String, Value>, key: &str, what: &str) -> Result<Option<bool>, SqlRefusal> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(SqlRefusal::invalid_profile(format!("{what} `{key}` must be a boolean"))),
    }
}

fn opt_port(o: &Map<String, Value>, key: &str, what: &str) -> Result<Option<u16>, SqlRefusal> {
    let bad = || SqlRefusal::invalid_profile(format!("{what} `{key}` must be an integer in 1..=65535"));
    match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => {
            n.as_u64().and_then(|n| u16::try_from(n).ok()).filter(|p| *p != 0).map(Some).ok_or_else(bad)
        }
        Some(_) => Err(bad()),
    }
}

/// A list of SQL capability names: every entry known, none repeated.
fn capability_list(v: &Value, what: &str) -> Result<Vec<SqlCapability>, SqlRefusal> {
    let list = v.as_array().ok_or_else(|| SqlRefusal::invalid_profile(format!("{what} must be a list")))?;
    let mut out: Vec<SqlCapability> = Vec::with_capacity(list.len());
    for entry in list {
        let cap = entry.as_str().and_then(SqlCapability::parse).ok_or_else(|| {
            SqlRefusal::invalid_profile(format!("{what} may name only the eleven sql_* capabilities"))
        })?;
        if out.contains(&cap) {
            return Err(SqlRefusal::invalid_profile(format!("{what} names `{cap}` twice")));
        }
        out.push(cap);
    }
    Ok(out)
}

fn parse_tls(v: Option<&Value>) -> Result<SqlTls, SqlRefusal> {
    let o = match v {
        None | Some(Value::Null) => {
            return Ok(SqlTls { mode: SqlTlsMode::VerifyFull, server_name: None, ca_pem: None })
        }
        Some(Value::Object(o)) => o,
        Some(_) => return Err(SqlRefusal::invalid_profile("`sql.tls` must be an object")),
    };
    only_keys(o, &["mode", "server_name", "ca_pem"], "`sql.tls`")?;
    let mode = match o.get("mode") {
        None | Some(Value::Null) => SqlTlsMode::VerifyFull,
        Some(Value::String(s)) => SqlTlsMode::parse(s).ok_or_else(|| {
            SqlRefusal::invalid_profile("`sql.tls.mode` must be verify-full, verify-ca, require or disable")
        })?,
        Some(_) => return Err(SqlRefusal::invalid_profile("`sql.tls.mode` must be a string")),
    };
    let server_name = match opt_text(o, "server_name", MAX_HOST_LEN, "`sql.tls`")? {
        Some(s) => Some(dial_host(&s, "`sql.tls.server_name`").map_err(SqlRefusal::invalid_profile)?),
        None => None,
    };
    let ca_pem = ca_pem_text(o)?;
    if ca_pem.is_some() && mode == SqlTlsMode::Disable {
        return Err(SqlRefusal::invalid_profile("`sql.tls.ca_pem` has no effect with `mode = disable`"));
    }
    Ok(SqlTls { mode, server_name, ca_pem })
}

/// `ca_pem` is PEM text: line breaks are expected, other control characters
/// are not.
fn ca_pem_text(o: &Map<String, Value>) -> Result<Option<String>, SqlRefusal> {
    let well_formed = |s: &str| {
        s.len() <= MAX_CA_PEM_LEN
            && s.contains("-----BEGIN CERTIFICATE-----")
            && !s.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    };
    match o.get("ca_pem") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) if well_formed(s) => Ok(Some(s.clone())),
        Some(_) => Err(SqlRefusal::invalid_profile(format!(
            "`sql.tls.ca_pem` must be PEM certificate text of at most {MAX_CA_PEM_LEN} bytes"
        ))),
    }
}

fn parse_credential_source(v: Option<&Value>) -> Result<SqlCredentialSource, SqlRefusal> {
    let o = v
        .and_then(Value::as_object)
        .ok_or_else(|| SqlRefusal::invalid_profile("`credential_source` is required and must be an object"))?;
    let segment = |key: &str| -> Result<String, SqlRefusal> {
        match opt_text(o, key, MAX_ID_LEN, "`credential_source`")? {
            Some(s) if !s.contains('/') && s.trim() == s && s != "." && s != ".." => Ok(s),
            _ => Err(SqlRefusal::invalid_profile(format!(
                "`credential_source.{key}` is required: a name without `/` or surrounding whitespace"
            ))),
        }
    };
    match o.get("kind").and_then(Value::as_str) {
        Some("secret") => {
            only_keys(o, &["kind", "secret_id"], "`credential_source`")?;
            Ok(SqlCredentialSource::Secret { secret_id: segment("secret_id")? })
        }
        Some("dynamic") => {
            only_keys(o, &["kind", "mount", "role"], "`credential_source`")?;
            let mount = match opt_text(o, "mount", MAX_ID_LEN, "`credential_source`")? {
                Some(m) if !m.chars().any(char::is_whitespace) => m,
                _ => return Err(SqlRefusal::invalid_profile("`credential_source.mount` is required")),
            };
            Ok(SqlCredentialSource::Dynamic { mount, role: segment("role")? })
        }
        _ => Err(SqlRefusal::invalid_profile(
            "an sql profile's `credential_source.kind` must be `secret` (or `dynamic`, reserved for dynamic \
             database credentials)",
        )),
    }
}

/// Parse an `sql` connection profile strictly for a resource of `engine`.
/// A profile whose `protocol` is not `sql` is refused as `profile_not_sql`.
pub fn parse_sql_profile(profile: &Value, engine: SqlEngine) -> Result<SqlProfile, SqlRefusal> {
    let o = profile.as_object().ok_or_else(|| SqlRefusal::invalid_profile("a connection profile must be an object"))?;
    if o.get("protocol").and_then(Value::as_str) != Some(SQL_PROTOCOL) {
        return Err(SqlRefusal::new(403, reason::PROFILE_NOT_SQL, "the connection profile is not a `sql` profile"));
    }
    only_keys(o, &PROFILE_KEYS, "the profile")?;
    let id = match opt_text(o, "id", MAX_ID_LEN, "the profile")? {
        Some(id) => id,
        None => return Err(SqlRefusal::invalid_profile("the profile needs an `id`")),
    };
    let label = match opt_text(o, "label", MAX_LABEL_LEN, "the profile")? {
        Some(l) => Some(l),
        None => opt_text(o, "name", MAX_LABEL_LEN, "the profile")?,
    };
    opt_bool(o, "is_default", "the profile")?;

    let (target_host, target_port) = match o.get("target") {
        None | Some(Value::Null) => (None, None),
        Some(Value::Object(t)) => {
            only_keys(t, &["host", "port"], "`target`")?;
            let host = match opt_text(t, "host", MAX_HOST_LEN, "`target`")? {
                Some(h) => Some(dial_host(&h, "`target.host`").map_err(SqlRefusal::invalid_profile)?),
                None => None,
            };
            (host, opt_port(t, "port", "`target`")?)
        }
        Some(_) => return Err(SqlRefusal::invalid_profile("`target` must be an object")),
    };

    let sql = o
        .get("sql")
        .and_then(Value::as_object)
        .ok_or_else(|| SqlRefusal::invalid_profile("an sql profile needs its `sql` block"))?;
    only_keys(sql, &SQL_BLOCK_KEYS, "`sql`")?;
    let catalog = opt_text(sql, "catalog", MAX_NAME_LEN, "`sql`")?;
    let instance = opt_text(sql, "instance", MAX_ID_LEN, "`sql`")?;
    if instance.is_some() && engine != SqlEngine::Mssql {
        return Err(SqlRefusal::invalid_profile(format!(
            "`sql.instance` names a SQL Server named instance; this resource's engine is {}",
            engine.as_str()
        )));
    }
    let tls = parse_tls(sql.get("tls"))?;
    let ceiling = match sql.get("ceiling") {
        Some(v @ Value::Array(_)) => capability_list(v, "`sql.ceiling`")?,
        _ => {
            return Err(SqlRefusal::invalid_profile(
                "`sql.ceiling` is required: the sql_* capabilities this profile's login can use at the database",
            ))
        }
    };
    if ceiling.is_empty() {
        return Err(SqlRefusal::invalid_profile("`sql.ceiling` must name at least one capability"));
    }
    let require_mfa = opt_bool(sql, "require_mfa", "`sql`")?.unwrap_or(false);
    let step_up = match sql.get("step_up") {
        None | Some(Value::Null) => Vec::new(),
        Some(v) => capability_list(v, "`sql.step_up`")?,
    };
    let credential_source = parse_credential_source(o.get("credential_source"))?;
    Ok(SqlProfile {
        id,
        label,
        target_host,
        target_port,
        catalog,
        instance,
        tls,
        ceiling,
        require_mfa,
        step_up,
        credential_source,
    })
}

/// Does a stored profile ask for connect-time MFA as an `sql` profile? Read
/// without the strict parse, so a profile that does not parse can never
/// skip the gate: anything but absence or an explicit `false` under
/// `sql.require_mfa` gates it. Not `sql` → `false`.
pub fn sql_gate_flag(profile: &Value) -> bool {
    if profile.get("protocol").and_then(Value::as_str) != Some(SQL_PROTOCOL) {
        return false;
    }
    match profile.get("sql") {
        None | Some(Value::Null) => false,
        Some(Value::Object(sql)) => {
            !matches!(sql.get("require_mfa"), None | Some(Value::Null) | Some(Value::Bool(false)))
        }
        Some(_) => true,
    }
}

/// The resource record's `port`: a number, or the numeric string a form
/// saves; absent, `null`, `""` and `0` are unset; anything else refuses.
fn resource_port(meta: &Map<String, Value>) -> Result<Option<u16>, SqlRefusal> {
    let bad = || SqlRefusal::new(422, reason::ENDPOINT_UNRESOLVABLE, "the resource's `port` must be 1..=65535");
    match meta.get("port") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => match n.as_u64() {
            Some(0) => Ok(None),
            Some(p) => u16::try_from(p).map(Some).map_err(|_| bad()),
            None => Err(bad()),
        },
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => match s.trim().parse::<u16>() {
            Ok(0) => Ok(None),
            Ok(p) => Ok(Some(p)),
            Err(_) => Err(bad()),
        },
        Some(_) => Err(bad()),
    }
}

/// The endpoint `profile` dials, from the stored profile and record only:
/// `target.host`, else the resource's `hostname`, else its `ip_address`;
/// `target.port`, else the resource's `port`, else the engine's default.
pub fn resolve_endpoint(
    profile: &SqlProfile,
    meta: &Map<String, Value>,
    engine: SqlEngine,
) -> Result<SqlEndpoint, SqlRefusal> {
    let unresolvable = |m: String| SqlRefusal::new(422, reason::ENDPOINT_UNRESOLVABLE, m);
    let record_host = |key: &str| -> Result<Option<String>, SqlRefusal> {
        match meta.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
            Some(Value::String(s)) => {
                dial_host(s.trim(), &format!("the resource's `{key}`")).map(Some).map_err(unresolvable)
            }
            Some(_) => Err(unresolvable(format!("the resource's `{key}` must be a string"))),
        }
    };
    let host = match &profile.target_host {
        Some(h) => h.clone(),
        None => match record_host("hostname")? {
            Some(h) => h,
            None => record_host("ip_address")?.ok_or_else(|| {
                unresolvable("the resource has no hostname or ip_address and the profile no `target.host`".into())
            })?,
        },
    };
    let port = match profile.target_port {
        Some(p) => p,
        None => resource_port(meta)?.unwrap_or(engine.default_port()),
    };
    Ok(SqlEndpoint { host, port })
}

/// What a strictly parsed profile looks like to the plugin: no credential,
/// only the secret's id.
pub fn profile_view(profile: &SqlProfile, endpoint: &SqlEndpoint) -> Value {
    let caps = |list: &[SqlCapability]| list.iter().map(|c| c.as_str()).collect::<Vec<_>>();
    let credential_source = match &profile.credential_source {
        SqlCredentialSource::Secret { secret_id } => json!({ "kind": "secret", "secret_id": secret_id }),
        SqlCredentialSource::Dynamic { mount, role } => json!({ "kind": "dynamic", "mount": mount, "role": role }),
    };
    json!({
        "id": profile.id,
        "label": profile.label,
        "endpoint": endpoint.to_string(),
        "host": endpoint.host,
        "port": endpoint.port,
        "catalog": profile.catalog,
        "instance": profile.instance,
        "tls": {
            "mode": profile.tls.mode.as_str(),
            "server_name": profile.tls.server_name,
            "ca_pem": profile.tls.ca_pem,
        },
        "ceiling": caps(&profile.ceiling),
        "require_mfa": profile.require_mfa,
        "step_up": caps(&profile.step_up),
        "credential_source": credential_source,
    })
}

// ── the credential ──────────────────────────────────────────────────────

/// The login a `secret` source releases. The password is zeroized on drop.
pub struct SqlSecretLogin {
    pub username: String,
    pub password: Zeroizing<String>,
    /// The secret's reserved `sql_endpoint`, as stored: the host decides
    /// bound, unbound or malformed (§5.4 rule 5).
    pub sql_endpoint: Option<Value>,
}

#[derive(Deserialize)]
struct SecretBody {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    sql_endpoint: Option<Value>,
}

/// Read the login out of a stored resource secret's bytes. A refusal never
/// quotes the stored value (serde's own error text can, so it is dropped).
pub fn parse_secret_login(raw: &[u8]) -> Result<SqlSecretLogin, SqlRefusal> {
    let invalid = || {
        SqlRefusal::new(
            422,
            reason::CREDENTIAL_INVALID,
            "the profile's secret must carry a non-empty `username` and `password` (strings)",
        )
    };
    let body: SecretBody = serde_json::from_slice(raw).map_err(|_| invalid())?;
    let password = Zeroizing::new(body.password.unwrap_or_default());
    let username = body.username.unwrap_or_default();
    if username.is_empty() || password.is_empty() || username.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(SqlSecretLogin { username, password, sql_endpoint: body.sql_endpoint })
}

// ── `?objects=` of the privileges read ──────────────────────────────────

/// Most objects one privileges read may name: with the eleven capabilities
/// on `sql/server` and resource-wide, the batch stays under
/// [`crate::kernel_api::policy::SQL_MAX_CHECKS`].
pub const MAX_PRIVILEGE_OBJECTS: usize = 64;
const MAX_OBJECTS_PARAM_LEN: usize = 16 * 1024;

/// Strict `%XX` decoding of one segment; `+` is literal here (the query
/// layer already turned `+` into a space once).
fn percent_decode_segment(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `objects`: comma-separated `catalog/schema/object` triples. A segment may
/// percent-encode `/`, `,` or `%` (`%2F`, `%2C`, `%25`) so any name can be
/// asked about. Empty is no objects.
pub fn parse_objects_param(raw: &str) -> Result<Vec<(String, String, String)>, String> {
    if raw.len() > MAX_OBJECTS_PARAM_LEN {
        return Err(format!("`objects` is longer than {MAX_OBJECTS_PARAM_LEN} bytes"));
    }
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let decode =
        |p: &str| percent_decode_segment(p).ok_or_else(|| "`objects` has a malformed percent-encoding".to_string());
    let mut out = Vec::new();
    for triple in raw.split(',') {
        let parts: Vec<&str> = triple.split('/').collect();
        let [c, s, o] = parts.as_slice() else {
            return Err("`objects` is a comma-separated list of catalog/schema/object".into());
        };
        out.push((decode(c)?, decode(s)?, decode(o)?));
        if out.len() > MAX_PRIVILEGE_OBJECTS {
            return Err(format!("`objects` may name at most {MAX_PRIVILEGE_OBJECTS} objects"));
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "sql_profile_tests.rs"]
mod tests;
