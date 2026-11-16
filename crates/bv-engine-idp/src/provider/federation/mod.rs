//! Shared by the SAML IdP and the OIDC OP (Phase 5): the RSA signing key
//! ring, the providers' own audit events, the self-service caller, random
//! identifiers and the URL rules for registered SP and client endpoints.

pub mod keys;

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use bv_errors::bv_error_response_status;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    errors::RvError,
    kernel_api::VaultCtx,
    logical::{Request, ENTITY_ID_META},
    posix::model::PosixError,
    provider::radius::tls::hex,
};

/// Longest registered URL (ACS, redirect, SSO, issuer).
pub const MAX_URL_LEN: usize = 2048;

/// Where `idp.oidc.*` and `idp.saml.*` go. An error turns an issue into a
/// refusal: a token or assertion nobody can attribute is not returned.
// Same macro-generated `double_must_use` as the gate's traits.
#[allow(clippy::double_must_use)]
#[maybe_async::maybe_async]
pub(crate) trait FederationAudit: Send + Sync {
    async fn record(
        &self,
        name: &'static str,
        fields: Map<String, Value>,
        req: Option<&Request>,
    ) -> Result<(), RvError>;
}

/// The gate's audit path: a `security` log line plus a broker event when a
/// device is enabled. Fields never carry a token, an assertion or a secret.
pub struct BrokerFederationAudit {
    pub ctx: Arc<dyn VaultCtx>,
}

#[maybe_async::maybe_async]
impl FederationAudit for BrokerFederationAudit {
    async fn record(
        &self,
        name: &'static str,
        fields: Map<String, Value>,
        req: Option<&Request>,
    ) -> Result<(), RvError> {
        log::info!(target: "security", "{name} {}", Value::Object(fields.clone()));
        let Some(broker) = self.ctx.audit_broker() else {
            return Ok(());
        };
        if !broker.has_devices() {
            return Ok(());
        }
        let mut entry = bv_audit::AuditEntry::event(name, fields, req, broker.hmac_key());
        broker.log(&mut entry).await
    }
}

/// The calling token's entity (a reserved metadata key only auth backends
/// set). The root token has none and is refused: these flows are
/// self-service, never on behalf of someone else.
pub(crate) fn caller_entity(req: &Request, what: &str) -> Result<String, RvError> {
    req.auth.as_ref().and_then(|a| a.metadata.get(ENTITY_ID_META)).filter(|id| !id.is_empty()).cloned().ok_or_else(
        || {
            bv_error_response_status!(
                403,
                &format!("{what} is self-service and the calling token is not bound to an entity")
            )
        },
    )
}

/// `n` bytes from the OS CSPRNG, base64url without padding.
pub(crate) fn random_b64url(n: usize) -> Zeroizing<String> {
    use rand::RngExt;

    let mut bytes = Zeroizing::new(vec![0u8; n]);
    rand::rng().fill(&mut bytes[..]);
    Zeroizing::new(B64URL.encode(&bytes[..]))
}

/// An XML `ID` / JWT `jti`: `_` and 40 hex digits (160 random bits).
pub(crate) fn random_id() -> String {
    use rand::RngExt;

    let mut bytes = [0u8; 20];
    rand::rng().fill(&mut bytes[..]);
    format!("_{}", hex(&bytes))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Constant-time equality (aws-lc), for secrets and their digests.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a, b).is_ok()
}

/// An absolute `https` URL with a host, no user info and no fragment. It is
/// stored verbatim and later matched byte for byte, never normalised.
pub fn validate_https_url(field: &str, s: &str) -> Result<(), PosixError> {
    let invalid = |why: &str| PosixError::Invalid(format!("{field}: {why}"));
    // Printable ASCII only and no backslash: WHATWG parsing rewrites `\`
    // and extra slashes, and an exact-match rule must mean what it shows.
    if s.is_empty() || s.len() > MAX_URL_LEN || !s.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b'\\') {
        return Err(invalid(&format!("must be 1-{MAX_URL_LEN} printable ASCII characters, no spaces or backslashes")));
    }
    if !s.starts_with("https://") || s[8..].starts_with('/') {
        return Err(invalid("must be an https URL naming a host"));
    }
    let url = url::Url::parse(s).map_err(|_| invalid("is not an absolute URL"))?;
    if url.scheme() != "https" {
        return Err(invalid("must be an https URL"));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(invalid("must name a host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("must not carry user information"));
    }
    if url.fragment().is_some() || s.contains('#') {
        return Err(invalid("must not carry a fragment"));
    }
    Ok(())
}

/// Opaque protocol values echoed back to the caller (`state`, `RelayState`,
/// `nonce`): printable ASCII, bounded.
pub(crate) fn validate_echo(field: &str, value: &str, max: usize) -> Result<(), PosixError> {
    if value.is_empty() || value.len() > max || !value.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(PosixError::Invalid(format!("{field} must be 1-{max} printable ASCII characters")));
    }
    Ok(())
}

/// Registered URLs: 1-`max`, each valid and none repeated.
pub(crate) fn validate_url_list(field: &str, urls: &[String], max: usize) -> Result<(), PosixError> {
    if urls.is_empty() || urls.len() > max {
        return Err(PosixError::Invalid(format!("{field} must list 1-{max} URLs")));
    }
    for (i, u) in urls.iter().enumerate() {
        validate_https_url(field, u)?;
        if urls[..i].contains(u) {
            return Err(PosixError::Invalid(format!("{field} lists `{u}` twice")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_urls_only_without_fragment_or_userinfo() {
        validate_https_url("u", "https://sp.example.com/acs").unwrap();
        validate_https_url("u", "https://sp.example.com:8443/a?b=c").unwrap();
        for bad in [
            "http://sp.example.com/acs",
            "https://sp.example.com/acs#frag",
            "https://user:pw@sp.example.com/acs",
            "javascript:alert(1)",
            "https:///nohost",
            "https://evil.example.com\\@sp.example.com/acs",
            "https://sp.example.com/a b",
            "HTTPS://sp.example.com/acs",
            " https://sp.example.com/acs",
            "/relative",
            "",
        ] {
            assert!(validate_https_url("u", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn echoed_values_are_bounded_printable_ascii() {
        validate_echo("state", "abc-123_~.", 16).unwrap();
        assert!(validate_echo("state", "", 16).is_err());
        assert!(validate_echo("state", "a\nb", 16).is_err());
        assert!(validate_echo("state", "é", 16).is_err());
        assert!(validate_echo("state", &"a".repeat(17), 16).is_err());
    }

    #[test]
    fn random_values_differ() {
        assert_ne!(random_id(), random_id());
        assert_ne!(random_b64url(32).as_str(), random_b64url(32).as_str());
        assert_eq!(random_id().len(), 41);
        assert!(ct_eq(b"abc", b"abc") && !ct_eq(b"abc", b"abd") && !ct_eq(b"abc", b"ab"));
    }
}
