//! Structured `dynamic_secret` events (`dynamic_audit_emit`).
//!
//! A plugin names only the event kind, an identity type and a few labels;
//! the host stamps the lease, role, connection, target identity, actor and
//! plugin build itself. Labels are `[a-z0-9_.:-]`, 1-64 characters, at most
//! eight detail entries, and never credential material (the host checks the
//! same rules; the SDK checks first so a plugin bug fails before the call).

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::{secret::contains_secret, DynamicError};

pub const MAX_LABEL_LEN: usize = 64;
pub const MAX_DETAIL_ENTRIES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Generate,
    Renew,
    Revoke,
    RevokeFailed,
    RotateRoot,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Generate => "generate",
            Self::Renew => "renew",
            Self::Revoke => "revoke",
            Self::RevokeFailed => "revoke_failed",
            Self::RotateRoot => "rotate_root",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    kind: EventKind,
    identity_type: Option<String>,
    detail: BTreeMap<String, String>,
}

fn check_label(field: &str, value: &str) -> Result<(), DynamicError> {
    let ok = !value.is_empty()
        && value.len() <= MAX_LABEL_LEN
        && value.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | ':' | '-'));
    if ok {
        Ok(())
    } else {
        Err(DynamicError::invalid(format!("audit {field} must be 1-{MAX_LABEL_LEN} characters of [a-z0-9_.:-]")))
    }
}

impl AuditEvent {
    pub fn new(kind: EventKind) -> Self {
        Self { kind, identity_type: None, detail: BTreeMap::new() }
    }

    /// e.g. `postgres_role`: what kind of identity the target holds.
    pub fn identity_type(mut self, value: &str) -> Result<Self, DynamicError> {
        check_label("target_identity_type", value)?;
        self.identity_type = Some(value.to_string());
        Ok(self)
    }

    pub fn detail(mut self, key: &str, value: &str) -> Result<Self, DynamicError> {
        check_label("detail key", key)?;
        check_label("detail value", value)?;
        if !self.detail.contains_key(key) && self.detail.len() >= MAX_DETAIL_ENTRIES {
            return Err(DynamicError::invalid(format!("at most {MAX_DETAIL_ENTRIES} audit detail entries")));
        }
        self.detail.insert(key.to_string(), value.to_string());
        Ok(self)
    }

    pub fn kind(&self) -> EventKind {
        self.kind
    }

    /// The `dynamic_audit_emit` request, refused if a label holds a secret.
    pub(crate) fn to_params(&self, secrets: &[&str]) -> Result<Value, DynamicError> {
        let labels = self.identity_type.iter().chain(self.detail.keys()).chain(self.detail.values());
        if labels.into_iter().any(|l| contains_secret(l, secrets)) {
            return Err(DynamicError::invalid("audit labels must not carry credential material"));
        }
        let mut params = json!({ "event": self.kind.as_str() });
        if let Some(t) = &self.identity_type {
            params["target_identity_type"] = Value::String(t.clone());
        }
        if !self.detail.is_empty() {
            params["detail"] = json!(self.detail);
        }
        Ok(params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_serialise_to_the_host_shape() {
        let e = AuditEvent::new(EventKind::Generate)
            .identity_type("postgres_role")
            .unwrap()
            .detail("statements", "2")
            .unwrap();
        assert_eq!(
            e.to_params(&[]).unwrap(),
            json!({"event": "generate", "target_identity_type": "postgres_role", "detail": {"statements": "2"}})
        );
        assert_eq!(AuditEvent::new(EventKind::RevokeFailed).to_params(&[]).unwrap(), json!({"event": "revoke_failed"}));
    }

    #[test]
    fn labels_are_bounded_and_secret_free() {
        assert!(AuditEvent::new(EventKind::Revoke).identity_type("Postgres Role").is_err());
        assert!(AuditEvent::new(EventKind::Revoke).detail("k", &"a".repeat(65)).is_err());
        let mut e = AuditEvent::new(EventKind::Revoke);
        for i in 0..MAX_DETAIL_ENTRIES {
            e = e.detail(&format!("k{i}"), "v").unwrap();
        }
        assert!(e.clone().detail("k-extra", "v").is_err());
        let leaky = AuditEvent::new(EventKind::Generate).detail("note", "zx9-long-password").unwrap();
        assert!(leaky.to_params(&["zx9-long-password"]).is_err());
    }
}
