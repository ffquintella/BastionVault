//! The `dynamic_secret` audit event: who got which target identity, when it
//! expires, and which plugin build touched the target.
//!
//! The struct has no field for credential material. Text a plugin supplies
//! (an identity type, detail labels, an error) is bounded, restricted to a
//! label character set, and refused or redacted when it contains a secret the
//! host knows about, so a plugin cannot smuggle the password into the log.

use std::collections::BTreeMap;

use bv_kernel_api::mcp_events::McpAuditEvent;
use serde::{Deserialize, Serialize};

use crate::DynamicError;

/// Audit name of every event this module builds.
pub const DYNAMIC_SECRET_EVENT: &str = "dynamic_secret";
/// Longest label (identity type, detail key or value) a plugin may supply.
pub const MAX_LABEL_LEN: usize = 64;
/// Most detail entries one plugin event may carry.
pub const MAX_DETAIL_ENTRIES: usize = 8;
/// Longest error text kept on a `revoke_failed` event.
pub const MAX_ERROR_LEN: usize = 256;
/// A known secret shorter than this is not searched for (it would match noise).
const MIN_SECRET_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DynamicEventKind {
    Generate,
    Renew,
    Revoke,
    RevokeFailed,
    RotateRoot,
    /// The host served a cached credential (never plugin-emitted).
    CacheHit,
}

/// Whether the host observed the step itself or a plugin reported it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventOrigin {
    Host,
    Plugin,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Actor {
    pub entity_id: String,
    pub display_name: String,
}

/// One `dynamic_secret` event, as written to the audit broker.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DynamicSecretEvent {
    #[serde(rename = "type")]
    pub event_type: &'static str,
    pub event: DynamicEventKind,
    pub origin: EventOrigin,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    pub engine: String,
    /// `<plugin name>@<version>`: the exact build that touched the target.
    pub plugin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_identity_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<Actor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub detail: BTreeMap<String, String>,
}

impl McpAuditEvent for DynamicSecretEvent {
    const NAME: &'static str = DYNAMIC_SECRET_EVENT;
}

impl DynamicSecretEvent {
    pub fn new(event: DynamicEventKind, origin: EventOrigin, engine: &str, plugin: &str, version: &str) -> Self {
        Self {
            event_type: DYNAMIC_SECRET_EVENT,
            event,
            origin,
            lease_id: None,
            engine: engine.to_string(),
            plugin: format!("{plugin}@{version}"),
            role: None,
            connection: None,
            target_identity: None,
            target_identity_type: None,
            expires_at: None,
            ttl_secs: None,
            actor: None,
            request_id: None,
            error: None,
            detail: BTreeMap::new(),
        }
    }

    /// Attach a plugin-supplied identity type, refused unless it is a plain
    /// label free of every secret in `secrets`.
    pub fn with_identity_type(mut self, value: &str, secrets: &[&str]) -> Result<Self, DynamicError> {
        self.target_identity_type = Some(checked_label("target_identity_type", value, secrets)?);
        Ok(self)
    }

    /// Attach plugin-supplied detail, with the same rules per key and value.
    pub fn with_detail(mut self, detail: &BTreeMap<String, String>, secrets: &[&str]) -> Result<Self, DynamicError> {
        if detail.len() > MAX_DETAIL_ENTRIES {
            return Err(DynamicError::invalid("detail", format!("at most {MAX_DETAIL_ENTRIES} entries")));
        }
        for (k, v) in detail {
            self.detail.insert(checked_label("detail key", k, secrets)?, checked_label("detail value", v, secrets)?);
        }
        Ok(self)
    }

    /// Attach an error message: cut to [`MAX_ERROR_LEN`] characters with every
    /// known secret replaced, since errors are text the plugin controls.
    pub fn with_error(mut self, message: &str, secrets: &[&str]) -> Self {
        self.error = Some(redact(message, secrets));
        self
    }
}

fn holds_secret(value: &str, secrets: &[&str]) -> bool {
    secrets.iter().any(|s| s.len() >= MIN_SECRET_LEN && value.contains(s))
}

/// A plugin-supplied label: 1..=[`MAX_LABEL_LEN`] characters of `[a-z0-9_.:-]`
/// containing none of `secrets`.
pub fn checked_label(field: &'static str, value: &str, secrets: &[&str]) -> Result<String, DynamicError> {
    let ok_chars =
        value.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | ':' | '-'));
    if value.is_empty() || value.len() > MAX_LABEL_LEN || !ok_chars {
        return Err(DynamicError::invalid(field, format!("must be 1-{MAX_LABEL_LEN} characters of [a-z0-9_.:-]")));
    }
    if holds_secret(value, secrets) {
        return Err(DynamicError::invalid(field, "must not carry credential material"));
    }
    Ok(value.to_string())
}

/// `message` cut to [`MAX_ERROR_LEN`] characters, every secret replaced.
pub fn redact(message: &str, secrets: &[&str]) -> String {
    let mut out = message.to_string();
    for s in secrets.iter().filter(|s| s.len() >= MIN_SECRET_LEN) {
        out = out.replace(s, "<redacted>");
    }
    if out.chars().count() > MAX_ERROR_LEN {
        out = out.chars().take(MAX_ERROR_LEN).collect::<String>() + "…";
    }
    out
}

#[cfg(test)]
mod tests {
    use bv_kernel_api::mcp_events::event_fields;

    use super::*;
    use crate::credential::{generate_password, generate_username};

    fn event_with_everything(password: &str, username: &str) -> DynamicSecretEvent {
        let mut e =
            DynamicSecretEvent::new(DynamicEventKind::Generate, EventOrigin::Host, "database", "pg-plugin", "0.3.1");
        e.lease_id = Some("database/creds/readonly/abc".into());
        e.role = Some("readonly".into());
        e.connection = Some("postgres-prod".into());
        e.target_identity = Some(username.into());
        e.expires_at = Some("2026-10-26T18:32:11Z".into());
        e.ttl_secs = Some(1800);
        e.actor = Some(Actor { entity_id: "e-1".into(), display_name: "userpass-alice".into() });
        e.request_id = Some("req-1".into());
        e.with_identity_type("postgres_user", &[password]).unwrap()
    }

    #[test]
    fn the_event_never_contains_the_credential() {
        let password = generate_password().unwrap();
        let username = generate_username("userpass-alice", "readonly", 1_793_000_000, 63).unwrap();
        let event = event_with_everything(password.expose(), &username)
            .with_error(&format!("revoke failed for {username} using {}", password.expose()), &[password.expose()]);
        let fields = serde_json::Value::Object(event_fields(&event)).to_string();
        assert!(!fields.contains(password.expose()), "{fields}");
        assert!(fields.contains(&username), "the target identity is what a SOC joins on");
        assert!(fields.contains("\"type\":\"dynamic_secret\""));
        assert!(fields.contains("\"plugin\":\"pg-plugin@0.3.1\""));
        assert!(fields.contains("<redacted>"));
        assert_eq!(<DynamicSecretEvent as McpAuditEvent>::NAME, "dynamic_secret");
    }

    #[test]
    fn plugin_labels_cannot_carry_the_secret() {
        let secret = "s3cr3t-pa55word-value";
        let e = DynamicSecretEvent::new(DynamicEventKind::Generate, EventOrigin::Plugin, "database", "p", "1");
        assert!(e.clone().with_identity_type(secret, &[secret]).is_err());
        assert!(e.clone().with_identity_type(&format!("user_{secret}"), &[secret]).is_err());
        let mut detail = BTreeMap::new();
        detail.insert("note".to_string(), secret.to_string());
        assert!(e.clone().with_detail(&detail, &[secret]).is_err());
        // Free text and upper case are not labels.
        assert!(e.clone().with_identity_type("Postgres User", &[]).is_err());
        assert!(e.clone().with_identity_type(&"a".repeat(MAX_LABEL_LEN + 1), &[]).is_err());
        let many: BTreeMap<String, String> = (0..=MAX_DETAIL_ENTRIES).map(|i| (format!("k{i}"), "v".into())).collect();
        assert!(e.clone().with_detail(&many, &[]).is_err());
        let mut ok = BTreeMap::new();
        ok.insert("grants".to_string(), "select".to_string());
        assert_eq!(e.with_detail(&ok, &[secret]).unwrap().detail.get("grants").unwrap(), "select");
    }

    #[test]
    fn errors_are_bounded_and_redacted() {
        let long = "x".repeat(MAX_ERROR_LEN * 2);
        assert_eq!(redact(&long, &[]).chars().count(), MAX_ERROR_LEN + 1);
        assert_eq!(redact("pw=abcdefghij", &["abcdefghij"]), "pw=<redacted>");
        // Short "secrets" are not searched for.
        assert_eq!(redact("a b c", &["a"]), "a b c");
    }

    #[test]
    fn absent_fields_are_omitted() {
        let e = DynamicSecretEvent::new(DynamicEventKind::Revoke, EventOrigin::Host, "database", "p", "1");
        let v = serde_json::to_value(&e).unwrap();
        assert!(v.get("error").is_none());
        assert!(v.get("detail").is_none());
        assert_eq!(v["event"], "revoke");
        assert_eq!(v["origin"], "host");
    }
}
