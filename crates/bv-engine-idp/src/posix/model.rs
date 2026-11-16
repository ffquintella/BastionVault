//! Persisted records, input validation and the identity state machine.
//!
//! Every record carries `version`. This build reads and writes version 1 and
//! refuses any other version explicitly, so a future format change must add a
//! read-old/write-new migration here rather than be misread.

use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::errors::RvError;

/// Version of every record this build writes.
pub const RECORD_VERSION: u32 = 1;

/// Lowest id a workforce identity may hold: below are system accounts.
pub const MIN_ID: u32 = 1000;
/// Highest id: tools that treat `uid_t` as signed break above `i32::MAX`.
pub const MAX_ID: u32 = i32::MAX as u32;
/// `nobody`/`nogroup` and `(uint16_t)-1`: never assigned to a person.
pub const RESERVED_IDS: [u32; 2] = [65534, 65535];
pub const DEFAULT_RANGE_MIN: u32 = 80_000;
pub const DEFAULT_RANGE_MAX: u32 = 999_999;
pub const MAX_SUPPLEMENTARY_GIDS: usize = 64;
pub const MAX_DISPLAY_NAME_CHARS: usize = 256;
pub const MAX_REASON_CHARS: usize = 256;
pub const MAX_LOGIN_LEN: usize = 32;
pub const MAX_ENTITY_ID_LEN: usize = 128;

/// Shared and system account names a person must never be projected as.
pub const RESERVED_LOGINS: &[&str] = &[
    "root",
    "toor",
    "admin",
    "administrator",
    "daemon",
    "bin",
    "sys",
    "sync",
    "nobody",
    "nogroup",
    "sshd",
    "operator",
];

/// A refusal with the HTTP status an operator should see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PosixError {
    Invalid(String),
    NotFound(String),
    Conflict(String),
    /// A stored record failed to decode or violated an invariant.
    Corrupt(String),
}

impl std::fmt::Display for PosixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(m) | Self::NotFound(m) | Self::Conflict(m) | Self::Corrupt(m) => f.write_str(m),
        }
    }
}

impl From<PosixError> for RvError {
    fn from(e: PosixError) -> Self {
        let status = match &e {
            PosixError::Invalid(_) => 400,
            PosixError::NotFound(_) => 404,
            PosixError::Conflict(_) => 409,
            PosixError::Corrupt(_) => 500,
        };
        RvError::ErrResponseStatus(status, e.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdKind {
    Uid,
    Gid,
}

impl IdKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Uid => "uid",
            Self::Gid => "gid",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdRange {
    pub min: u32,
    pub max: u32,
}

impl IdRange {
    pub const DEFAULT: IdRange = IdRange { min: DEFAULT_RANGE_MIN, max: DEFAULT_RANGE_MAX };

    pub fn validate(&self, kind: IdKind) -> Result<(), PosixError> {
        let k = kind.as_str();
        if self.min < MIN_ID || self.max > MAX_ID {
            return Err(PosixError::Invalid(format!("{k} range must lie within [{MIN_ID}, {MAX_ID}]")));
        }
        if self.min > self.max {
            return Err(PosixError::Invalid(format!("{k}_min ({}) is greater than {k}_max ({})", self.min, self.max)));
        }
        Ok(())
    }

    pub fn contains(&self, id: u32) -> bool {
        (self.min..=self.max).contains(&id)
    }
}

/// `idp/config`: the allocation ranges.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PosixConfig {
    pub version: u32,
    pub uid_range: IdRange,
    pub gid_range: IdRange,
    pub updated_at: Option<DateTime<Utc>>,
}

impl Default for PosixConfig {
    fn default() -> Self {
        Self { version: RECORD_VERSION, uid_range: IdRange::DEFAULT, gid_range: IdRange::DEFAULT, updated_at: None }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityState {
    Active,
    Disabled,
    Removed,
}

/// What a state change does, once it has been found legal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    NoOp,
    Disable,
    Reinstate,
    Remove,
}

impl IdentityState {
    pub fn parse(s: &str) -> Result<Self, PosixError> {
        match s {
            "active" => Ok(Self::Active),
            "disabled" => Ok(Self::Disabled),
            "removed" => Ok(Self::Removed),
            other => Err(PosixError::Invalid(format!("unknown state `{other}`: expected active, disabled or removed"))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Removed => "removed",
        }
    }

    /// `active -> disabled -> removed`, `disabled -> active` (reinstate).
    /// `removed` is terminal; an active identity is disabled before removal.
    pub fn transition(self, to: Self) -> Result<Transition, PosixError> {
        use IdentityState::*;
        match (self, to) {
            (Active, Active) | (Disabled, Disabled) | (Removed, Removed) => Ok(Transition::NoOp),
            (Active, Disabled) => Ok(Transition::Disable),
            (Disabled, Active) => Ok(Transition::Reinstate),
            (Disabled, Removed) => Ok(Transition::Remove),
            (Active, Removed) => {
                Err(PosixError::Conflict("an active identity must be disabled before it is removed".into()))
            }
            (Removed, _) => Err(PosixError::Conflict("identity is removed; removal is terminal".into())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UidSource {
    /// Allocated by this vault from the configured range.
    Vault,
    /// Seeded verbatim from an external authoritative numbering.
    Imported,
}

impl UidSource {
    pub fn parse(s: &str) -> Result<Self, PosixError> {
        match s {
            "vault" => Ok(Self::Vault),
            "imported" => Ok(Self::Imported),
            other => Err(PosixError::Invalid(format!("unknown uid_source `{other}`: expected vault or imported"))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vault => "vault",
            Self::Imported => "imported",
        }
    }
}

/// `idp/posix/identities/<entity_id>`: one workforce identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkforceIdentity {
    pub version: u32,
    pub entity_id: String,
    /// Immutable once allocated.
    pub login: String,
    /// Immutable once allocated; never reused.
    pub uid: u32,
    /// Immutable once allocated; never reused.
    pub primary_gid: u32,
    /// Supplementary groups, sorted and deduplicated.
    pub gids: Vec<u32>,
    pub display_name: String,
    pub state: IdentityState,
    pub uid_source: UidSource,
    pub allocated_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub state_changed_at: Option<DateTime<Utc>>,
    pub state_reason: Option<String>,
}

impl WorkforceIdentity {
    pub fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("entity_id".into(), Value::from(self.entity_id.clone()));
        m.insert("login".into(), Value::from(self.login.clone()));
        m.insert("uid".into(), Value::from(self.uid));
        m.insert("primary_gid".into(), Value::from(self.primary_gid));
        m.insert("gids".into(), Value::from(self.gids.clone()));
        m.insert("display_name".into(), Value::from(self.display_name.clone()));
        m.insert("state".into(), Value::from(self.state.as_str()));
        m.insert("uid_source".into(), Value::from(self.uid_source.as_str()));
        m.insert("allocated_at".into(), Value::from(self.allocated_at.to_rfc3339()));
        m.insert("updated_at".into(), Value::from(self.updated_at.to_rfc3339()));
        m.insert("state_changed_at".into(), self.state_changed_at.map(|t| Value::from(t.to_rfc3339())).into());
        m.insert("state_reason".into(), self.state_reason.clone().map(Value::from).into());
        m
    }
}

/// `index/{login,uid,gid}/<key>`: which identity holds a login or id. Never
/// deleted, so it doubles as the tombstone for a removed identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexEntry {
    pub version: u32,
    pub entity_id: String,
}

/// Decode a versioned record, refusing any version this build cannot read.
pub fn decode_versioned<T: DeserializeOwned>(what: &str, bytes: &[u8]) -> Result<T, PosixError> {
    #[derive(Deserialize)]
    struct Probe {
        version: Option<u32>,
    }
    let probe: Probe = serde_json::from_slice(bytes)
        .map_err(|e| PosixError::Corrupt(format!("stored {what} record is not valid JSON: {e}")))?;
    match probe.version {
        Some(RECORD_VERSION) => {}
        Some(v) => {
            return Err(PosixError::Corrupt(format!(
                "stored {what} record has version {v}; this build reads version {RECORD_VERSION} only"
            )))
        }
        None => return Err(PosixError::Corrupt(format!("stored {what} record has no version"))),
    }
    serde_json::from_slice(bytes).map_err(|e| PosixError::Corrupt(format!("stored {what} record is malformed: {e}")))
}

// ─── Input validation ───────────────────────────────────────────────

pub fn validate_entity_id(id: &str) -> Result<(), PosixError> {
    let ok = !id.is_empty()
        && id.len() <= MAX_ENTITY_ID_LEN
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(PosixError::Invalid(format!(
            "entity_id must be 1-{MAX_ENTITY_ID_LEN} characters of [A-Za-z0-9_-], starting with a letter or digit"
        )))
    }
}

/// POSIX portable login: `^[a-z_][a-z0-9_-]{0,31}$`, not a shared/system name.
pub fn validate_login(login: &str) -> Result<(), PosixError> {
    let bytes = login.as_bytes();
    let ok = !bytes.is_empty()
        && bytes.len() <= MAX_LOGIN_LEN
        && (bytes[0].is_ascii_lowercase() || bytes[0] == b'_')
        && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-');
    if !ok {
        return Err(PosixError::Invalid(format!(
            "login must match ^[a-z_][a-z0-9_-]*$ and be at most {MAX_LOGIN_LEN} characters"
        )));
    }
    if RESERVED_LOGINS.contains(&login) {
        return Err(PosixError::Invalid(format!("login `{login}` is a reserved shared or system account name")));
    }
    Ok(())
}

/// The GECOS field: no `:` (the passwd separator) and no control characters.
pub fn validate_display_name(name: &str) -> Result<(), PosixError> {
    if name.chars().count() > MAX_DISPLAY_NAME_CHARS {
        return Err(PosixError::Invalid(format!("display_name exceeds {MAX_DISPLAY_NAME_CHARS} characters")));
    }
    if name.chars().any(|c| c == ':' || c.is_control()) {
        return Err(PosixError::Invalid("display_name must not contain ':' or control characters".into()));
    }
    Ok(())
}

pub fn validate_reason(reason: &str) -> Result<(), PosixError> {
    if reason.chars().count() > MAX_REASON_CHARS || reason.chars().any(char::is_control) {
        return Err(PosixError::Invalid(format!(
            "reason must be at most {MAX_REASON_CHARS} characters without control characters"
        )));
    }
    Ok(())
}

/// An id seeded in import mode: human range, not reserved.
pub fn validate_import_id(kind: IdKind, id: u32) -> Result<(), PosixError> {
    if !(MIN_ID..=MAX_ID).contains(&id) || RESERVED_IDS.contains(&id) {
        return Err(PosixError::Invalid(format!(
            "imported {} {id} is outside [{MIN_ID}, {MAX_ID}] or reserved",
            kind.as_str()
        )));
    }
    Ok(())
}

/// A supplementary group reference (may be a low shared group like `wheel`).
pub fn validate_supplementary_gid(gid: u32) -> Result<(), PosixError> {
    if gid == 0 || gid > MAX_ID || RESERVED_IDS.contains(&gid) {
        return Err(PosixError::Invalid(format!(
            "supplementary gid {gid} is not allowed (0, reserved and ids above {MAX_ID} are refused)"
        )));
    }
    Ok(())
}

/// Parse a JSON number or numeric string into an id.
pub fn parse_id(field: &str, v: &Value) -> Result<u32, PosixError> {
    let n = match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    };
    n.and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| PosixError::Invalid(format!("{field} must be a non-negative 32-bit integer")))
}

pub fn parse_id_list(field: &str, v: &Value) -> Result<Vec<u32>, PosixError> {
    let Value::Array(items) = v else {
        return Err(PosixError::Invalid(format!("{field} must be an array of integers")));
    };
    items.iter().map(|item| parse_id(field, item)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_machine_follows_the_spec_diagram() {
        use IdentityState::*;
        assert_eq!(Active.transition(Disabled), Ok(Transition::Disable));
        assert_eq!(Disabled.transition(Active), Ok(Transition::Reinstate));
        assert_eq!(Disabled.transition(Removed), Ok(Transition::Remove));
        for s in [Active, Disabled, Removed] {
            assert_eq!(s.transition(s), Ok(Transition::NoOp));
        }
        assert!(matches!(Active.transition(Removed), Err(PosixError::Conflict(_))));
        assert!(matches!(Removed.transition(Active), Err(PosixError::Conflict(_))));
        assert!(matches!(Removed.transition(Disabled), Err(PosixError::Conflict(_))));
        assert!(IdentityState::parse("enabled").is_err());
    }

    #[test]
    fn login_validation() {
        for ok in ["alice", "_svc", "a1-b_2", "x"] {
            assert!(validate_login(ok).is_ok(), "{ok}");
        }
        for bad in ["", "Alice", "1alice", "al ice", "alice$", "al:ice", "root", "admin", &"a".repeat(33), "álice"] {
            assert!(validate_login(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn entity_id_and_display_name_validation() {
        assert!(validate_entity_id("6f1c2b9e-0d7a-4c55-9f37-1f2a3b4c5d6e").is_ok());
        for bad in ["", "-lead", "a/b", "a.b", "..", &"a".repeat(129)] {
            assert!(validate_entity_id(bad).is_err(), "{bad}");
        }
        assert!(validate_display_name("Alice Souza, Ops").is_ok());
        assert!(validate_display_name("Alice:0:0").is_err());
        assert!(validate_display_name("Alice\nroot").is_err());
        assert!(validate_display_name(&"x".repeat(257)).is_err());
    }

    #[test]
    fn id_validation_and_parsing() {
        assert!(validate_import_id(IdKind::Uid, 999).is_err());
        assert!(validate_import_id(IdKind::Uid, 1000).is_ok());
        assert!(validate_import_id(IdKind::Uid, 65534).is_err());
        assert!(validate_import_id(IdKind::Uid, MAX_ID + 1).is_err());
        assert!(validate_supplementary_gid(0).is_err());
        assert!(validate_supplementary_gid(4).is_ok());
        assert_eq!(parse_id("uid", &serde_json::json!(80017)), Ok(80017));
        assert_eq!(parse_id("uid", &serde_json::json!("80017")), Ok(80017));
        for bad in
            [serde_json::json!(-1), serde_json::json!(1.5), serde_json::json!("x"), serde_json::json!(5_000_000_000u64)]
        {
            assert!(parse_id("uid", &bad).is_err(), "{bad}");
        }
        assert!(parse_id_list("gids", &serde_json::json!("4,10")).is_err());
        assert_eq!(parse_id_list("gids", &serde_json::json!([4, "10"])), Ok(vec![4, 10]));
    }

    #[test]
    fn range_validation() {
        assert!(IdRange::DEFAULT.validate(IdKind::Uid).is_ok());
        assert!(IdRange { min: 999, max: 2000 }.validate(IdKind::Uid).is_err());
        assert!(IdRange { min: 5000, max: 4000 }.validate(IdKind::Gid).is_err());
        assert!(IdRange { min: 5000, max: MAX_ID + 1 }.validate(IdKind::Gid).is_err());
    }

    /// A version-1 identity record exactly as this build writes it. Kept
    /// verbatim so a future format change has to keep reading it.
    const V1_IDENTITY: &str = r#"{"version":1,"entity_id":"e-1","login":"alice","uid":80017,"primary_gid":80017,
        "gids":[4,80500],"display_name":"Alice Souza","state":"disabled","uid_source":"vault",
        "allocated_at":"2026-11-16T10:00:00Z","updated_at":"2026-11-16T11:00:00Z",
        "state_changed_at":"2026-11-16T11:00:00Z","state_reason":"left the team"}"#;

    #[test]
    fn v1_records_decode() {
        let rec: WorkforceIdentity = decode_versioned("identity", V1_IDENTITY.as_bytes()).unwrap();
        assert_eq!((rec.uid, rec.primary_gid, rec.state), (80017, 80017, IdentityState::Disabled));
        assert_eq!(rec.gids, vec![4, 80500]);
        let cfg: PosixConfig = decode_versioned(
            "config",
            br#"{"version":1,"uid_range":{"min":80000,"max":999999},"gid_range":{"min":80000,"max":999999},"updated_at":null}"#,
        )
        .unwrap();
        assert_eq!(cfg, PosixConfig::default());
        let idx: IndexEntry = decode_versioned("index", br#"{"version":1,"entity_id":"e-1"}"#).unwrap();
        assert_eq!(idx.entity_id, "e-1");
    }

    #[test]
    fn unknown_versions_and_malformed_records_fail_closed() {
        let v2 = V1_IDENTITY.replacen("\"version\":1", "\"version\":2", 1);
        assert!(matches!(
            decode_versioned::<WorkforceIdentity>("identity", v2.as_bytes()),
            Err(PosixError::Corrupt(_))
        ));
        let unversioned = br#"{"entity_id":"e-1"}"#;
        assert!(matches!(decode_versioned::<IndexEntry>("index", unversioned), Err(PosixError::Corrupt(_))));
        let extra = br#"{"version":1,"entity_id":"e-1","uid":5}"#;
        assert!(matches!(decode_versioned::<IndexEntry>("index", extra), Err(PosixError::Corrupt(_))));
        assert!(matches!(decode_versioned::<IndexEntry>("index", b"not json"), Err(PosixError::Corrupt(_))));
        let negative_uid = V1_IDENTITY.replacen("80017", "-1", 1);
        assert!(decode_versioned::<WorkforceIdentity>("identity", negative_uid.as_bytes()).is_err());
    }
}
