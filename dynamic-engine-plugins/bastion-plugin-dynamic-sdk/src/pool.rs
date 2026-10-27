//! The host's connection-pool grant (`dynamic_pool_checkout`).
//!
//! The host pool hands out *slots*, not sockets: a grant admits one
//! connection to the target, counted against the operator's pool size and
//! keyed by the root credential version `rotate-root` bumps. It also carries
//! the TLS policy the operator set on `config/<name>`; a plugin dials with
//! exactly that policy and never weakens it on its own.

use serde::Deserialize;

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
    }
}
