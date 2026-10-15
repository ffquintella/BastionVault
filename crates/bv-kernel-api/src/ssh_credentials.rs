//! SSH credentials the vault resolves or mints under its own authority, for
//! a session it brokers: the Rustion path (`rustion/v2/session/open`) and MCP
//! agent sessions (`resources/v2/connect/agent/ssh/exec`).
//!
//! Both callers authorize first — the `connect` gate on the resource — and
//! then read or sign **router-direct**, skipping the per-caller ACL: a
//! connect-only caller never needs `read` on the secret or `update` on the
//! SSH engine. That is why this module takes no request and checks nothing:
//! calling it *is* the consequence of a check the caller already made.
//!
//! Here, in the kernel contract, because two engines need the same code and
//! an engine may not depend on another (`features/mcp-brokered-sessions.md`
//! §5.2: "moved into a shared place, not copied"). Each caller then picks
//! what it can use from what was resolved: Rustion seals a password for the
//! bastion and refuses a key, an agent session uses a key or a password.

use std::collections::BTreeMap;

use bv_errors::{bv_error_response_status, bv_error_string, RvError};
use bv_logical::{Operation, Request};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::ctx::VaultCtx;

/// What a `secret` credential source resolved to. Every secret field is in
/// zeroizing memory and none is printed by `Debug`.
pub struct ResolvedSecretCredential {
    /// The secret's `username`, when it carries one.
    pub username: Option<String>,
    pub password: Option<Zeroizing<String>>,
    /// An OpenSSH or PEM private key.
    pub private_key: Option<Zeroizing<String>>,
    /// The private key's passphrase.
    pub passphrase: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for ResolvedSecretCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedSecretCredential")
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("private_key", &self.private_key.as_ref().map(|_| "<redacted>"))
            .field("passphrase", &self.passphrase.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Who a resolution is attributed to in the `security` log line, which is
/// the only record of the router-direct read (it has no caller of its own).
pub struct SecretResolution<'a> {
    /// The log line's leading label, e.g. `rustion-connect-resolve`.
    pub audit_label: &'a str,
    /// The connecting principal, as the caller names it.
    pub actor: &'a str,
}

/// One path segment: no `/`, no `..`, not empty. A resource name or secret
/// id that is not one could address a different route of the resource
/// engine (`…/history`, `…/version/<n>`).
fn is_single_segment(s: &str) -> bool {
    !s.is_empty() && !s.contains('/') && s != "." && s != ".."
}

fn take_secret(data: &mut Map<String, Value>, key: &str) -> Option<Zeroizing<String>> {
    match data.remove(key) {
        Some(Value::String(s)) if !s.is_empty() => Some(Zeroizing::new(s)),
        Some(Value::String(s)) => {
            drop(Zeroizing::new(s));
            None
        }
        _ => None,
    }
}

/// Read the resource secret `secret_id` of `resource` under the server's
/// authority and return its login material. `ns_prefix` is the caller's
/// namespace request prefix (`""` or `"tenant-a/"`).
///
/// Refuses a secret with neither a `password` nor a `private_key` (422): it
/// cannot authenticate anything.
#[maybe_async::maybe_async]
pub async fn resolve_secret_credential(
    ctx: &dyn VaultCtx,
    ns_prefix: &str,
    resource: &str,
    secret_id: &str,
    who: &SecretResolution<'_>,
) -> Result<ResolvedSecretCredential, RvError> {
    if !is_single_segment(resource) || !is_single_segment(secret_id) {
        return Err(bv_error_response_status!(
            400,
            &format!("resource `{resource}` and secret id `{secret_id}` must each be one path segment")
        ));
    }
    let path = format!("{ns_prefix}resources/secrets/{resource}/{secret_id}");
    let mut sub = Request::new(&path);
    sub.operation = Operation::Read;
    let resp = ctx.router().handle_request(&mut sub).await?.ok_or_else(|| {
        bv_error_response_status!(404, &format!("resource secret `{secret_id}` not found for `{resource}`"))
    })?;
    let mut data = resp.data.unwrap_or_default();
    let password = take_secret(&mut data, "password");
    let private_key = take_secret(&mut data, "private_key");
    let passphrase = take_secret(&mut data, "passphrase");
    let username = data.get("username").and_then(Value::as_str).filter(|s| !s.is_empty()).map(String::from);
    if password.is_none() && private_key.is_none() {
        return Err(bv_error_response_status!(
            422,
            &format!("secret `{secret_id}` carries neither a `password` nor a `private_key` field")
        ));
    }

    log::info!(
        target: "security",
        "{}: user={} resource={} key={}",
        who.audit_label,
        who.actor,
        resource,
        secret_id
    );

    Ok(ResolvedSecretCredential { username, password, private_key, passphrase })
}

/// What to ask the SSH engine for, beyond the public key.
#[derive(Debug, Clone, Default)]
pub struct BrokeredCertRequest<'a> {
    /// The login the certificate is for (`valid_principals`). `None` falls
    /// back to the role's `default_user`.
    pub principal: Option<&'a str>,
    /// Critical options to request. The engine keeps only those the role's
    /// `allowed_critical_options` lists, silently: a caller that needs one
    /// must check the signed certificate ([`inspect_ssh_certificate`]).
    pub critical_options: BTreeMap<String, String>,
    /// Requested validity, seconds. The role's `max_ttl` still caps it.
    pub ttl_secs: Option<u64>,
}

/// An ephemeral key and the certificate the SSH engine signed for it.
pub struct MintedSshCert {
    /// The ephemeral Ed25519 private key, OpenSSH format. In memory only.
    pub private_key_openssh: Zeroizing<String>,
    /// The signed certificate, OpenSSH one-line format.
    pub certificate: String,
    /// The certificate serial as the engine reports it (16 hex digits).
    pub serial: String,
}

impl std::fmt::Debug for MintedSshCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedSshCert").field("serial", &self.serial).finish_non_exhaustive()
    }
}

/// Mint a brokered SSH certificate: an ephemeral Ed25519 keypair generated
/// in this process, its public half signed by `<ns_prefix><ssh_mount>/sign/<ssh_role>`
/// router-direct. The private key never leaves this process unsealed and is
/// returned in zeroizing memory.
///
/// `ns_prefix` is the caller's namespace prefix: the SSH engine that signs
/// is the one mounted in the caller's namespace, because a namespace's CA is
/// what its targets trust.
#[maybe_async::maybe_async]
pub async fn mint_brokered_ssh_cert(
    ctx: &dyn VaultCtx,
    ns_prefix: &str,
    ssh_mount: &str,
    ssh_role: &str,
    request: &BrokeredCertRequest<'_>,
) -> Result<MintedSshCert, RvError> {
    use ssh_key::{rand_core::OsRng, Algorithm, LineEnding, PrivateKey};

    // Ephemeral client keypair — in-memory only, never persisted.
    let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .map_err(|e| bv_error_string!(&format!("generate ephemeral ssh keypair: {e}")))?;
    let public_openssh = private_key
        .public_key()
        .to_openssh()
        .map_err(|e| bv_error_string!(&format!("serialize ephemeral pubkey: {e}")))?;
    let private_key_openssh: Zeroizing<String> = Zeroizing::new(
        private_key
            .to_openssh(LineEnding::LF)
            .map_err(|e| bv_error_string!(&format!("serialize ephemeral private key: {e}")))?
            .to_string(),
    );
    drop(private_key);

    let mut body = Map::new();
    body.insert("public_key".into(), Value::String(public_openssh));
    if let Some(p) = request.principal.filter(|s| !s.is_empty()) {
        body.insert("valid_principals".into(), Value::String(p.to_string()));
    }
    if !request.critical_options.is_empty() {
        let options: Map<String, Value> =
            request.critical_options.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect();
        body.insert("critical_options".into(), Value::Object(options));
    }
    if let Some(ttl) = request.ttl_secs {
        body.insert("ttl".into(), Value::String(format!("{ttl}s")));
    }
    let path = format!("{ns_prefix}{ssh_mount}/sign/{ssh_role}");
    let mut sub = Request::new_write_request(&path, Some(body));
    sub.operation = Operation::Write;
    let resp = ctx.router().handle_request(&mut sub).await?.ok_or_else(|| {
        bv_error_response_status!(502, &format!("ssh engine `{path}` returned no response while minting brokered cert"))
    })?;
    let data = resp.data.unwrap_or_default();
    let certificate = data
        .get("signed_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            bv_error_response_status!(502, &format!("ssh engine `{path}` sign response missing `signed_key`"))
        })?
        .to_string();
    let serial = data.get("serial_number").and_then(|v| v.as_str()).unwrap_or_default().to_string();

    Ok(MintedSshCert { private_key_openssh, certificate, serial })
}

/// What a signed certificate actually says, read back from its own bytes
/// rather than from what was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshCertificateFacts {
    pub serial: u64,
    pub key_id: String,
    pub valid_principals: Vec<String>,
    /// Unix seconds.
    pub valid_after: u64,
    /// Unix seconds.
    pub valid_before: u64,
    pub critical_options: BTreeMap<String, String>,
    pub extensions: BTreeMap<String, String>,
}

/// Parse an OpenSSH certificate (one-line format). The signature is not
/// verified: the caller has just received it from its own SSH engine and
/// reads it only to confirm which options and extensions it carries.
pub fn inspect_ssh_certificate(openssh: &str) -> Result<SshCertificateFacts, RvError> {
    let cert = ssh_key::Certificate::from_openssh(openssh.trim())
        .map_err(|e| bv_error_string!(&format!("the signed SSH certificate does not parse: {e}")))?;
    Ok(SshCertificateFacts {
        serial: cert.serial(),
        key_id: cert.key_id().to_string(),
        valid_principals: cert.valid_principals().to_vec(),
        valid_after: cert.valid_after(),
        valid_before: cert.valid_before(),
        critical_options: cert.critical_options().0.clone(),
        extensions: cert.extensions().0.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_segments_only() {
        for ok in ["web-01", "root-pw", "a.b"] {
            assert!(is_single_segment(ok), "{ok}");
        }
        for bad in ["", "a/b", "..", ".", "x/history"] {
            assert!(!is_single_segment(bad), "{bad:?}");
        }
    }

    #[test]
    fn debug_never_prints_secret_material() {
        let resolved = ResolvedSecretCredential {
            username: Some("ops".into()),
            password: Some(Zeroizing::new("hunter2".into())),
            private_key: Some(Zeroizing::new("-----BEGIN OPENSSH PRIVATE KEY-----".into())),
            passphrase: Some(Zeroizing::new("sesame".into())),
        };
        let printed = format!("{resolved:?}");
        assert!(printed.contains("ops"));
        for secret in ["hunter2", "OPENSSH", "sesame"] {
            assert!(!printed.contains(secret), "{printed}");
        }
        let minted = MintedSshCert {
            private_key_openssh: Zeroizing::new("-----BEGIN OPENSSH PRIVATE KEY-----".into()),
            certificate: "ssh-ed25519-cert-v01@openssh.com AAAA".into(),
            serial: "00000000000000ff".into(),
        };
        assert!(!format!("{minted:?}").contains("PRIVATE"));
    }

    #[test]
    fn a_malformed_certificate_is_refused() {
        assert!(inspect_ssh_certificate("not a certificate").is_err());
    }

    /// The facts are read from the certificate's own bytes: what the CA
    /// signed, including a default extension nobody asked for.
    #[test]
    fn inspection_reads_options_extensions_and_validity_back() {
        use ssh_key::{certificate::Builder, rand_core::OsRng, Algorithm, PrivateKey};
        let ca = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let user = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut builder =
            Builder::new_with_random_nonce(&mut OsRng, user.public_key().key_data().clone(), 1_000, 1_060).unwrap();
        builder.serial(0xff).unwrap();
        builder.key_id("agent-role").unwrap();
        builder.valid_principal("ops").unwrap();
        builder.critical_option("force-command", "uptime").unwrap();
        builder.extension("permit-pty", "").unwrap();
        let cert = builder.sign(&ca).unwrap().to_openssh().unwrap();

        let facts = inspect_ssh_certificate(&cert).unwrap();
        assert_eq!((facts.serial, facts.key_id.as_str()), (0xff, "agent-role"));
        assert_eq!(facts.valid_principals, vec!["ops".to_string()]);
        assert_eq!((facts.valid_after, facts.valid_before), (1_000, 1_060));
        assert_eq!(facts.critical_options.get("force-command").map(String::as_str), Some("uptime"));
        assert!(facts.extensions.contains_key("permit-pty"));
    }
}
