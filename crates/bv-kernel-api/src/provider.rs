//! Credential providers: plugins a connection profile can name as its
//! credential source.
//!
//! Spec: [features/self-accounts.md](../../../features/self-accounts.md) §4.
//! Nothing here mentions any particular provider. The Connect paths in the
//! resource and Rustion engines ask [`PluginHost`](super::engines::PluginHost)
//! for the candidate list and for the credential of the one picked; the plugin
//! runtime turns those into the `provider.candidates` / `provider.release`
//! envelope ops, which only this bridge can produce.
//!
//! The types are narrowed the way [`PluginChannel`](super::engines::PluginChannel)
//! is: an engine sees what it needs to render and route, not the manifest.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Longest value the host accepts from a provider for any single text field
/// other than a secret (`username`, `domain`, labels).
pub const MAX_TEXT_LEN: usize = 256;
/// Longest password the host accepts from a provider.
pub const MAX_PASSWORD_LEN: usize = 1024;
/// Longest private key the host accepts from a provider.
pub const MAX_PRIVATE_KEY_LEN: usize = 16 * 1024;

/// The request's caller, attested by the host from the token. Never carries
/// the token, its accessor or its policies.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerIdentity {
    pub entity_id: String,
    pub display_name: String,
    /// Auth mount the principal logged in through, e.g. `userpass/`.
    pub principal_mount: String,
    pub principal_name: String,
    pub namespace: String,
}

/// A granted, active credential provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialProviderDecl {
    pub plugin: String,
    pub display_name: String,
    pub protocols: Vec<String>,
    pub secret_kinds: Vec<String>,
}

/// What kind of resource the connection is for. The resource *name* is
/// deliberately absent (data minimisation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderResource {
    #[serde(rename = "type")]
    pub resource_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_type: Option<String>,
}

/// The target being dialled, computed by the host from stored metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProviderTarget {
    /// SSH / RDP.
    Host { host: String, port: u16 },
    /// Web `form`: every origin the recipe may fill (start URL plus
    /// `allowed_origins`).
    Origins { origins: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderQuery {
    /// `ssh`, `rdp` or `web`.
    pub protocol: String,
    pub resource: ProviderResource,
    pub target: ProviderTarget,
}

/// One account the operator may pick. Metadata only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCandidate {
    pub id: String,
    pub label: String,
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    pub secret_kind: String,
    #[serde(default)]
    pub has_totp: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
}

/// What the connect recipe will fill. A provider returns only what is asked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderNeeds {
    pub password: bool,
    pub totp: bool,
}

/// Facts about this launch the host attests to the provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderConnectContext {
    /// A connect-time MFA ticket was redeemed for this launch.
    pub mfa_verified: bool,
    /// `direct`, `rustion` or `web`.
    pub transport: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderReleaseRequest {
    pub account_id: String,
    pub protocol: String,
    pub resource: ProviderResource,
    pub target: ProviderTarget,
    pub needs: ProviderNeeds,
    pub connect: ProviderConnectContext,
}

/// The secret half of a released credential. Held in `Zeroizing` buffers and
/// without a `Debug` that prints them.
pub enum ReleasedSecret {
    Password {
        password: Zeroizing<String>,
        totp_seed: Option<Zeroizing<String>>,
    },
    SshKey {
        private_key: Zeroizing<String>,
    },
}

impl ReleasedSecret {
    /// `password` or `ssh-key`, the manifest's `secret_kinds` vocabulary.
    pub fn kind(&self) -> &'static str {
        match self {
            ReleasedSecret::Password { .. } => "password",
            ReleasedSecret::SshKey { .. } => "ssh-key",
        }
    }
}

impl std::fmt::Debug for ReleasedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReleasedSecret::{}(<redacted>)", self.kind())
    }
}

/// A credential released by a provider, already validated by the host.
#[derive(Debug)]
pub struct ReleasedCredential {
    pub username: String,
    pub domain: Option<String>,
    pub secret: ReleasedSecret,
}

/// Why the host refused what a provider returned. The text is operator-facing
/// and never contains secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderOutputError(pub String);

impl std::fmt::Display for ProviderOutputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl ReleasedCredential {
    /// The shape check the host runs on whatever a provider returned
    /// (spec §4.4): the secret kind is one the provider declared and is
    /// compatible with the protocol, the username is non-empty, and every
    /// field is within the size limits. Fails closed.
    pub fn validate(
        &self,
        protocol: &str,
        declared_kinds: &[String],
    ) -> Result<(), ProviderOutputError> {
        let bad = |m: &str| Err(ProviderOutputError(m.to_string()));
        let kind = self.secret.kind();
        if !declared_kinds.iter().any(|k| k == kind) {
            return bad("provider returned a secret kind it did not declare");
        }
        // password: ssh | rdp | web.  ssh-key: ssh only.
        let compatible = match (kind, protocol) {
            ("password", "ssh" | "rdp" | "web") => true,
            ("ssh-key", "ssh") => true,
            _ => false,
        };
        if !compatible {
            return bad("provider returned a secret kind that is incompatible with the protocol");
        }
        if self.username.trim().is_empty() {
            return bad("provider returned an empty username");
        }
        if self.username.len() > MAX_TEXT_LEN
            || self.domain.as_ref().is_some_and(|d| d.len() > MAX_TEXT_LEN)
        {
            return bad("provider returned an oversize username or domain");
        }
        match &self.secret {
            ReleasedSecret::Password { password, totp_seed } => {
                if password.is_empty() {
                    return bad("provider returned an empty password");
                }
                if password.len() > MAX_PASSWORD_LEN
                    || totp_seed.as_ref().is_some_and(|t| t.len() > MAX_PASSWORD_LEN)
                {
                    return bad("provider returned an oversize secret");
                }
            }
            ReleasedSecret::SshKey { private_key } => {
                if private_key.is_empty() {
                    return bad("provider returned an empty private key");
                }
                if private_key.len() > MAX_PRIVATE_KEY_LEN {
                    return bad("provider returned an oversize secret");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw(user: &str, password: &str) -> ReleasedCredential {
        ReleasedCredential {
            username: user.into(),
            domain: None,
            secret: ReleasedSecret::Password {
                password: Zeroizing::new(password.into()),
                totp_seed: None,
            },
        }
    }

    fn kinds() -> Vec<String> {
        vec!["password".into(), "ssh-key".into()]
    }

    #[test]
    fn accepts_a_well_formed_password() {
        assert!(pw("felipe", "hunter2").validate("rdp", &kinds()).is_ok());
    }

    #[test]
    fn refuses_undeclared_kind() {
        let only_key = vec!["ssh-key".to_string()];
        assert!(pw("felipe", "x").validate("ssh", &only_key).is_err());
    }

    #[test]
    fn refuses_key_over_rdp_and_web() {
        let c = ReleasedCredential {
            username: "u".into(),
            domain: None,
            secret: ReleasedSecret::SshKey { private_key: Zeroizing::new("k".into()) },
        };
        assert!(c.validate("ssh", &kinds()).is_ok());
        assert!(c.validate("rdp", &kinds()).is_err());
        assert!(c.validate("web", &kinds()).is_err());
    }

    #[test]
    fn refuses_empty_and_oversize_fields() {
        assert!(pw("", "x").validate("ssh", &kinds()).is_err());
        assert!(pw("  ", "x").validate("ssh", &kinds()).is_err());
        assert!(pw("u", "").validate("ssh", &kinds()).is_err());
        assert!(pw(&"u".repeat(MAX_TEXT_LEN + 1), "x").validate("ssh", &kinds()).is_err());
        assert!(pw("u", &"p".repeat(MAX_PASSWORD_LEN + 1)).validate("ssh", &kinds()).is_err());
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let c = pw("felipe", "s3cret-value");
        assert!(!format!("{c:?}").contains("s3cret-value"));
    }
}
