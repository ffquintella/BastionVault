//! The host's connection-pool grant (`dynamic_pool_checkout`).
//!
//! A grant admits one connection to the target, counted against the
//! operator's pool size and keyed by the root credential version. It carries
//! the operator's TLS policy and the host's connector kinds (`host_execute`):
//! when the plugin's kind is listed, it asks the host to run the call's
//! rendered statements ([`crate::DynamicCtx::host_execute`]); else it dials.

use std::fmt;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::secret::SecretString;

/// How to verify the target's TLS certificate. Verification is the default:
/// a reply without a `tls` block, or one with `verify` missing, verifies.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TlsPolicy {
    #[serde(default = "default_true")]
    pub verify: bool,
    /// PEM bundle to trust instead of the system roots.
    #[serde(default)]
    pub ca_pem: Option<String>,
}

impl Default for TlsPolicy {
    fn default() -> Self {
        Self { verify: true, ca_pem: None }
    }
}

fn default_true() -> bool {
    true
}

/// One admitted connection slot, held until the host-to-plugin call ends.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PoolGrant {
    pub connection: String,
    pub root_credential_version: u64,
    #[serde(default)]
    pub tls: TlsPolicy,
    pub slot: u64,
    #[serde(default)]
    pub max_connections: u64,
    /// Connector kinds the host dials itself. Absent from older hosts.
    #[serde(default)]
    pub host_execute: Vec<String>,
}

impl PoolGrant {
    /// Whether the host runs this call's statements for a target of `kind`.
    /// When it does, a plugin must use it: dialling itself instead would
    /// bypass the host's TLS enforcement.
    pub fn executes(&self, kind: &str) -> bool {
        self.host_execute.iter().any(|k| k == kind)
    }
}

/// The stored connection a plugin presents for a host execution: where to
/// dial and as whom. No TLS field: the policy is the operator's, host-side.
pub struct HostConnector {
    pub kind: &'static str,
    pub url: String,
    pub username: String,
    pub password: SecretString,
    pub connect_timeout_secs: Option<u64>,
}

impl fmt::Debug for HostConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostConnector")
            .field("kind", &self.kind)
            .field("url", &self.url)
            .field("username", &self.username)
            .field("password", &self.password)
            .finish()
    }
}

impl HostConnector {
    /// The request's `connector` object. Holds the root secret: wipe it.
    pub(crate) fn to_params(&self) -> Value {
        let mut v = json!({
            "kind": self.kind, "url": self.url, "username": self.username, "password": self.password.expose(),
        });
        if let Some(t) = self.connect_timeout_secs {
            v["connect_timeout_secs"] = json!(t);
        }
        v
    }
}

/// What a host execution did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct HostExecution {
    pub executed: u64,
    /// A revoke found the identity already gone and ran nothing.
    #[serde(default)]
    pub identity_absent: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_grant_parses_the_host_reply_and_defaults_to_verifying() {
        let g: PoolGrant = serde_json::from_value(serde_json::json!({
            "connection": "prod", "root_credential_version": 2, "tls": { "verify": true },
            "slot": 7, "max_connections": 8
        }))
        .unwrap();
        assert!(g.tls.verify && g.tls.ca_pem.is_none());
        let g: PoolGrant =
            serde_json::from_value(serde_json::json!({ "connection": "c", "root_credential_version": 1, "slot": 1 }))
                .unwrap();
        assert!(g.tls.verify, "no tls block means verify");
        let g: PoolGrant = serde_json::from_value(serde_json::json!({
            "connection": "c", "root_credential_version": 1, "slot": 1, "tls": { "ca_pem": "PEM" }
        }))
        .unwrap();
        assert!(g.tls.verify && g.tls.ca_pem.as_deref() == Some("PEM"));
        assert!(!g.executes("postgres"), "an older host executes nothing");
        let g: PoolGrant = serde_json::from_value(serde_json::json!({
            "connection": "c", "root_credential_version": 1, "slot": 1, "host_execute": ["postgres"]
        }))
        .unwrap();
        assert!(g.executes("postgres") && !g.executes("mysql"));
    }

    #[test]
    fn a_host_connector_never_debugs_its_secret() {
        let c = HostConnector {
            kind: "postgres",
            url: "postgres://db/app".into(),
            username: "vault".into(),
            password: SecretString::new("root-secret-123".into()),
            connect_timeout_secs: Some(5),
        };
        assert!(!format!("{c:?}").contains("root-secret-123"));
        assert_eq!(c.to_params()["connect_timeout_secs"], 5);
    }
}
