//! Credential material a dynamic plugin receives from the host.
//!
//! The host generates every credential (`features/dynamic-secrets.md`); a
//! plugin only carries it to the target. [`SecretString`] keeps it out of
//! logs and replies by construction: no `Display`, no `Serialize`, and a
//! `Debug` that prints a placeholder. The bytes are wiped on drop.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

/// A known secret shorter than this is not searched for in error text: it
/// would match noise. Same floor as the host's `bv_dynamic::audit::redact`.
pub const MIN_REDACT_LEN: usize = 8;
/// Longest error text a plugin sends back to the host.
pub const MAX_ERROR_LEN: usize = 512;

/// A password, rendered statement or root credential.
#[derive(Clone, Default)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// The secret itself, for handing to the target system. Never log it.
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

/// `message` with every secret in `secrets` replaced by `<redacted>`, cut to
/// [`MAX_ERROR_LEN`] characters.
pub fn redact(message: &str, secrets: &[&str]) -> String {
    let mut out = message.to_string();
    for s in secrets.iter().filter(|s| s.len() >= MIN_REDACT_LEN) {
        out = out.replace(s, "<redacted>");
    }
    if out.chars().count() > MAX_ERROR_LEN {
        out = out.chars().take(MAX_ERROR_LEN).collect::<String>() + "…";
    }
    out
}

/// True when `text` contains any secret of [`MIN_REDACT_LEN`] or more.
pub fn contains_secret(text: &str, secrets: &[&str]) -> bool {
    secrets.iter().any(|s| s.len() >= MIN_REDACT_LEN && text.contains(s))
}

/// Zero every string inside a decoded envelope (the generate envelope holds
/// the password in its credential and its rendered statements).
pub fn wipe_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => s.zeroize(),
        serde_json::Value::Array(items) => items.iter_mut().for_each(wipe_value),
        serde_json::Value::Object(map) => map.values_mut().for_each(wipe_value),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_the_secret() {
        let s = SecretString::new("correct-horse-battery".into());
        assert_eq!(format!("{s:?}"), "SecretString(<redacted>)");
        assert_eq!(s.expose(), "correct-horse-battery");
    }

    #[test]
    fn redact_replaces_long_secrets_and_bounds_length() {
        let msg = "syntax error at or near \"Zx9-long-password\"";
        assert_eq!(redact(msg, &["Zx9-long-password", "short"]), "syntax error at or near \"<redacted>\"");
        assert!(contains_secret(msg, &["Zx9-long-password"]));
        assert!(!contains_secret("abc", &["abc"]), "too short to search for");
        assert_eq!(redact(&"x".repeat(2000), &[]).chars().count(), MAX_ERROR_LEN + 1);
    }

    #[test]
    fn wipe_value_zeroes_nested_strings() {
        let mut v = serde_json::json!({ "credential": { "password": "p" }, "statements": ["s"] });
        wipe_value(&mut v);
        assert_eq!(v["credential"]["password"], "");
        assert_eq!(v["statements"][0], "");
    }
}
