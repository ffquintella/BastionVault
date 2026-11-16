//! Outbound SAML XML: the signed `Response`/`Assertion` and the IdP
//! metadata. The assertion is emitted already in exclusive-C14N form (sorted
//! attributes, namespaces declared where used, no empty-element tags,
//! c14n escaping), so any conformant canonicaliser yields the bytes signed.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::{
    errors::RvError,
    provider::federation::keys::{KeyRing, SigningKey},
};

pub const NS_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const NS_ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
pub const NS_METADATA: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
pub const NS_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub const ENVELOPED_SIGNATURE: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
pub const SHA256_DIGEST: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub const BINDING_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
pub const BINDING_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
pub const NAMEID_UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
pub const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const CM_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const ATTRNAME_BASIC: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
const AUTHN_CONTEXT_UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";

fn refuse_controls(s: &str) -> Result<(), RvError> {
    if s.chars().any(char::is_control) {
        return Err(bv_errors::bv_error_response_status!(500, "saml: a value carries a control character"));
    }
    Ok(())
}

/// Text content, escaped as exclusive C14N writes it.
pub fn text(s: &str) -> Result<String, RvError> {
    refuse_controls(s)?;
    Ok(s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;"))
}

/// A double-quoted attribute value, escaped as exclusive C14N writes it.
pub fn attr(s: &str) -> Result<String, RvError> {
    refuse_controls(s)?;
    Ok(s.replace('&', "&amp;").replace('<', "&lt;").replace('"', "&quot;"))
}

/// `xs:dateTime` in UTC, whole seconds.
pub fn instant(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// What one response asserts.
pub struct AssertionInput<'a> {
    pub idp_entity_id: &'a str,
    pub sp_entity_id: &'a str,
    pub acs_url: &'a str,
    /// The AuthnRequest ID; `None` for an IdP-initiated response.
    pub in_response_to: Option<&'a str>,
    pub name_id: &'a str,
    /// Attribute name and values, in order.
    pub attributes: Vec<(&'a str, Vec<String>)>,
    pub response_id: &'a str,
    pub assertion_id: &'a str,
    pub issue_instant: DateTime<Utc>,
    pub not_on_or_after: DateTime<Utc>,
}

/// The assertion without its signature, split where `<ds:Signature>` goes
/// (right after `<saml:Issuer>`, as the schema orders it).
fn assertion_parts(a: &AssertionInput<'_>) -> Result<(String, String), RvError> {
    let now = instant(a.issue_instant);
    let until = instant(a.not_on_or_after);
    let head = format!(
        r#"<saml:Assertion xmlns:saml="{NS_ASSERTION}" ID="{id}" IssueInstant="{now}" Version="2.0"><saml:Issuer>{issuer}</saml:Issuer>"#,
        id = attr(a.assertion_id)?,
        issuer = text(a.idp_entity_id)?,
    );
    let in_response_to = match a.in_response_to {
        Some(r) => format!(r#" InResponseTo="{}""#, attr(r)?),
        None => String::new(),
    };
    let mut tail = format!(
        concat!(
            r#"<saml:Subject><saml:NameID Format="{fmt}">{name}</saml:NameID>"#,
            r#"<saml:SubjectConfirmation Method="{bearer}"><saml:SubjectConfirmationData{irt} NotOnOrAfter="{until}" Recipient="{acs}"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject>"#,
            r#"<saml:Conditions NotBefore="{now}" NotOnOrAfter="{until}"><saml:AudienceRestriction><saml:Audience>{aud}</saml:Audience></saml:AudienceRestriction></saml:Conditions>"#,
            r#"<saml:AuthnStatement AuthnInstant="{now}" SessionIndex="{sid}"><saml:AuthnContext><saml:AuthnContextClassRef>{ctx}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"#,
            r#"<saml:AttributeStatement>"#
        ),
        fmt = NAMEID_UNSPECIFIED,
        name = text(a.name_id)?,
        bearer = CM_BEARER,
        irt = in_response_to,
        until = until,
        acs = attr(a.acs_url)?,
        now = now,
        aud = text(a.sp_entity_id)?,
        sid = attr(a.assertion_id)?,
        ctx = AUTHN_CONTEXT_UNSPECIFIED,
    );
    for (name, values) in &a.attributes {
        tail.push_str(&format!(r#"<saml:Attribute Name="{}" NameFormat="{ATTRNAME_BASIC}">"#, attr(name)?));
        for v in values {
            tail.push_str(&format!("<saml:AttributeValue>{}</saml:AttributeValue>", text(v)?));
        }
        tail.push_str("</saml:Attribute>");
    }
    tail.push_str("</saml:AttributeStatement></saml:Assertion>");
    Ok((head, tail))
}

/// The enveloped XML-DSig signature over the assertion: exclusive C14N
/// (the SAML auth backend's canonicaliser), SHA-256 digest, RSA-SHA256.
fn signature(unsigned_assertion: &str, assertion_id: &str, key: &SigningKey) -> Result<String, RvError> {
    let c14n = bv_auth_saml::verify::canonicalise_exclusive;
    let digest = B64.encode(Sha256::digest(c14n(unsigned_assertion.as_bytes())?));
    // `xmlns:ds` on SignedInfo too, so it canonicalises the same alone or
    // in context.
    let signed_info = format!(
        concat!(
            r#"<ds:SignedInfo xmlns:ds="{ds}"><ds:CanonicalizationMethod Algorithm="{c14n}"></ds:CanonicalizationMethod>"#,
            r##"<ds:SignatureMethod Algorithm="{rsa}"></ds:SignatureMethod><ds:Reference URI="#{id}"><ds:Transforms>"##,
            r#"<ds:Transform Algorithm="{env}"></ds:Transform><ds:Transform Algorithm="{c14n}"></ds:Transform></ds:Transforms>"#,
            r#"<ds:DigestMethod Algorithm="{sha}"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"#
        ),
        ds = NS_DSIG,
        c14n = EXC_C14N,
        rsa = RSA_SHA256,
        id = attr(assertion_id)?,
        env = ENVELOPED_SIGNATURE,
        sha = SHA256_DIGEST,
        digest = digest,
    );
    let value = B64.encode(key.sign(&c14n(signed_info.as_bytes())?)?);
    Ok(format!(
        concat!(
            r#"<ds:Signature xmlns:ds="{ds}">{si}<ds:SignatureValue>{value}</ds:SignatureValue>"#,
            r#"<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"#
        ),
        ds = NS_DSIG,
        si = signed_info,
        value = value,
        cert = key.cert_base64(),
    ))
}

/// The unsigned assertion (head + tail), exposed for the C14N fixed-point test.
#[cfg(test)]
pub(crate) fn unsigned_assertion(a: &AssertionInput<'_>) -> Result<String, RvError> {
    let (head, tail) = assertion_parts(a)?;
    Ok(format!("{head}{tail}"))
}

/// A `samlp:Response` (status Success) carrying one signed assertion.
pub fn signed_response(a: &AssertionInput<'_>, key: &SigningKey) -> Result<String, RvError> {
    let (head, tail) = assertion_parts(a)?;
    let sig = signature(&format!("{head}{tail}"), a.assertion_id, key)?;
    let in_response_to = match a.in_response_to {
        Some(r) => format!(r#" InResponseTo="{}""#, attr(r)?),
        None => String::new(),
    };
    Ok(format!(
        concat!(
            r#"<samlp:Response xmlns:samlp="{p}" xmlns:saml="{s}" Destination="{acs}" ID="{rid}"{irt} IssueInstant="{now}" Version="2.0">"#,
            r#"<saml:Issuer>{issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{ok}"></samlp:StatusCode></samlp:Status>"#,
            "{head}{sig}{tail}</samlp:Response>"
        ),
        p = NS_PROTOCOL,
        s = NS_ASSERTION,
        acs = attr(a.acs_url)?,
        rid = attr(a.response_id)?,
        irt = in_response_to,
        now = instant(a.issue_instant),
        issuer = text(a.idp_entity_id)?,
        ok = STATUS_SUCCESS,
        head = head,
        sig = sig,
        tail = tail,
    ))
}

/// IdP metadata: every published signing certificate (current first, then
/// retired keys in their overlap), unsigned requests accepted, POST and
/// Redirect bindings on the configured SSO URL.
pub fn metadata(entity_id: &str, sso_url: &str, ring: &KeyRing, now: DateTime<Utc>) -> Result<String, RvError> {
    let mut keys = String::new();
    for k in ring.published(now) {
        keys.push_str(&format!(
            concat!(
                r#"<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="{ds}"><ds:X509Data>"#,
                r#"<ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#
            ),
            ds = NS_DSIG,
            cert = k.cert_base64(),
        ));
    }
    Ok(format!(
        concat!(
            r#"<md:EntityDescriptor xmlns:md="{md}" entityID="{eid}"><md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="{p}">"#,
            r#"{keys}<md:NameIDFormat>{fmt}</md:NameIDFormat>"#,
            r#"<md:SingleSignOnService Binding="{redirect}" Location="{sso}"></md:SingleSignOnService>"#,
            r#"<md:SingleSignOnService Binding="{post}" Location="{sso}"></md:SingleSignOnService>"#,
            r#"</md:IDPSSODescriptor></md:EntityDescriptor>"#
        ),
        md = NS_METADATA,
        eid = attr(entity_id)?,
        p = NS_PROTOCOL,
        keys = keys,
        fmt = NAMEID_UNSPECIFIED,
        redirect = BINDING_REDIRECT,
        post = BINDING_POST,
        sso = attr(sso_url)?,
    ))
}
