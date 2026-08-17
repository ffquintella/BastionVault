//! Connection config persisted at `core/ldap/config`.
//!
//! One config per mount. `bindpass` is barrier-encrypted at rest like
//! every other field; reads redact it. Operators rotate it via
//! `rotate-root`, which writes a freshly-generated password to the
//! directory under the bind DN itself and persists the new value.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::utils::{deserialize_duration, serialize_duration};

pub const CONFIG_KEY: &str = "core/ldap/config";

/// Chosen directory dialect; drives the password attribute + encoding
/// at modify-time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryType {
    #[default]
    OpenLdap,
    ActiveDirectory,
}

impl DirectoryType {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "" | "openldap" | "open_ldap" => Ok(Self::OpenLdap),
            "active_directory" | "ad" | "activedirectory" => Ok(Self::ActiveDirectory),
            other => Err(format!(
                "directory_type must be `openldap` or `active_directory`, got `{other}`"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TlsMinVersion {
    #[default]
    Tls12,
    Tls13,
}

impl TlsMinVersion {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "" | "tls12" | "1.2" | "tls1.2" => Ok(Self::Tls12),
            "tls13" | "1.3" | "tls1.3" => Ok(Self::Tls13),
            other => Err(format!(
                "tls_min_version must be `tls12` or `tls13`, got `{other}`"
            )),
        }
    }
}

/// Hard ceiling on `request_timeout` so an operator typo can't lock
/// up the engine for an hour. Matches the spec.
pub const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    pub url: String,
    pub binddn: String,
    pub bindpass: String,
    #[serde(default)]
    pub userdn: String,
    #[serde(default)]
    pub directory_type: DirectoryType,
    /// Reference to a generator (`sys/policies/password/<name>`).
    /// Empty = use the engine's built-in default (24-char alnum +
    /// symbol). Vault parity but the generator policies subsystem
    /// is not yet shipped in BastionVault — for now the field is
    /// persisted and the built-in is always used. See
    /// `features/ldap-secret-engine.md` § Password Generation.
    #[serde(default)]
    pub password_policy: String,
    #[serde(
        default = "default_request_timeout",
        serialize_with = "serialize_duration",
        deserialize_with = "deserialize_duration"
    )]
    pub request_timeout: Duration,
    #[serde(default)]
    pub client_tls_cert: String,
    #[serde(default)]
    pub client_tls_key: String,
    #[serde(default)]
    pub tls_min_version: TlsMinVersion,
    /// **Refused at write time** unless the operator also supplies
    /// `acknowledge_insecure_tls = true`. The two-flag opt-in is
    /// deliberate: a one-flag opt-in gets fat-fingered into prod.
    #[serde(default)]
    pub insecure_tls: bool,
    /// Used when callers reference accounts by short name — the
    /// engine searches `userdn` for `(<userattr>=<short>)` to resolve
    /// the full DN.
    #[serde(default = "default_userattr")]
    pub userattr: String,
    /// Set by the engine on first connect. Used to detect
    /// rotation-atomicity divergence: if the directory's password is
    /// not what we last persisted, refuse to serve the cached value
    /// and surface a "manual reconciliation required" error.
    #[serde(default)]
    pub starttls: bool,
}

fn default_request_timeout() -> Duration {
    DEFAULT_REQUEST_TIMEOUT
}

fn default_userattr() -> String {
    "cn".to_string()
}

impl LdapConfig {
    /// Validate static invariants; does not touch the network. The
    /// path handler runs this after parsing the request body and
    /// before persisting.
    pub fn validate(&self, acknowledge_insecure: bool) -> Result<(), String> {
        if self.url.trim().is_empty() {
            return Err("url is required".into());
        }
        if self.binddn.trim().is_empty() {
            return Err("binddn is required".into());
        }
        if self.bindpass.is_empty() {
            return Err("bindpass is required".into());
        }
        let url_lc = self.url.trim().to_ascii_lowercase();
        let is_ldaps = url_lc.starts_with("ldaps://");
        let is_ldap = url_lc.starts_with("ldap://");
        if !is_ldaps && !is_ldap {
            return Err(format!(
                "url must start with `ldap://` or `ldaps://`, got `{}`",
                self.url
            ));
        }
        // TLS-only by default. Plain `ldap://` without `starttls`
        // requires the two-flag opt-in.
        if is_ldap && !self.starttls && !self.insecure_tls {
            return Err(
                "plain `ldap://` requires either `starttls = true` or both \
                 `insecure_tls = true` + `acknowledge_insecure_tls = true`"
                    .into(),
            );
        }
        if self.insecure_tls && !acknowledge_insecure {
            return Err(
                "`insecure_tls = true` requires also setting \
                 `acknowledge_insecure_tls = true` to confirm the operator \
                 understood the implications"
                    .into(),
            );
        }
        if self.request_timeout > MAX_REQUEST_TIMEOUT {
            return Err(format!(
                "request_timeout {:?} exceeds the {MAX_REQUEST_TIMEOUT:?} ceiling",
                self.request_timeout
            ));
        }
        if !self.client_tls_cert.is_empty() && self.client_tls_key.is_empty() {
            return Err("client_tls_cert without client_tls_key".into());
        }
        if !self.client_tls_key.is_empty() && self.client_tls_cert.is_empty() {
            return Err("client_tls_key without client_tls_cert".into());
        }
        Ok(())
    }

    /// Strip the bind password before returning the config to a
    /// caller via the GET endpoint.
    pub fn redacted(&self) -> Self {
        let mut c = self.clone();
        c.bindpass = String::new();
        c.client_tls_key = String::new();
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> LdapConfig {
        LdapConfig {
            url: "ldaps://dc.example.com:636".into(),
            binddn: "CN=admin,DC=example,DC=com".into(),
            bindpass: "p".into(),
            userdn: "OU=svc,DC=example,DC=com".into(),
            directory_type: DirectoryType::OpenLdap,
            password_policy: String::new(),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            client_tls_cert: String::new(),
            client_tls_key: String::new(),
            tls_min_version: TlsMinVersion::Tls12,
            insecure_tls: false,
            userattr: "cn".into(),
            starttls: false,
        }
    }

    #[test]
    fn validates_well_formed() {
        assert!(fixture().validate(false).is_ok());
    }

    #[test]
    fn refuses_plain_ldap_without_opt_in() {
        let mut c = fixture();
        c.url = "ldap://dc.example.com".into();
        assert!(c.validate(false).is_err());
    }

    #[test]
    fn allows_plain_ldap_with_starttls() {
        let mut c = fixture();
        c.url = "ldap://dc.example.com".into();
        c.starttls = true;
        assert!(c.validate(false).is_ok());
    }

    #[test]
    fn insecure_tls_requires_two_flags() {
        let mut c = fixture();
        c.url = "ldap://dc.example.com".into();
        c.insecure_tls = true;
        // single-flag opt-in: refused.
        assert!(c.validate(false).is_err());
        // two-flag opt-in: allowed.
        assert!(c.validate(true).is_ok());
    }

    #[test]
    fn redacted_drops_secrets() {
        let mut c = fixture();
        c.bindpass = "real".into();
        c.client_tls_key = "BEGIN PRIVATE".into();
        let r = c.redacted();
        assert!(r.bindpass.is_empty());
        assert!(r.client_tls_key.is_empty());
    }

    #[test]
    fn directory_type_parse() {
        assert_eq!(
            DirectoryType::parse("openldap").unwrap(),
            DirectoryType::OpenLdap
        );
        assert_eq!(
            DirectoryType::parse("active_directory").unwrap(),
            DirectoryType::ActiveDirectory
        );
        assert_eq!(DirectoryType::parse("AD").unwrap(), DirectoryType::ActiveDirectory);
        assert!(DirectoryType::parse("kerberos").is_err());
    }
}
