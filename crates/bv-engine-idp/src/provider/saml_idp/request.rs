//! Inbound `<samlp:AuthnRequest>`: binding decode (bounded inflate for
//! HTTP-Redirect, plain base64 for HTTP-POST) and a namespace-aware parse
//! that refuses DTDs, custom entities, a second root and a repeated Issuer.
//! A request signature, if any, is not verified: nothing it says is
//! trusted beyond naming a registered SP and one of its registered ACS URLs.

use std::io::Read;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use quick_xml::{
    events::{BytesRef, Event},
    name::ResolveResult,
    NsReader, XmlVersion,
};

use super::xml::{NS_ASSERTION, NS_PROTOCOL};

/// Largest decoded (inflated) request accepted.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Largest encoded request accepted.
pub const MAX_ENCODED_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect`: DEFLATE + base64.
    Redirect,
    /// `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST`: base64.
    Post,
}

impl Binding {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "redirect" => Some(Self::Redirect),
            "post" => Some(Self::Post),
            _ => None,
        }
    }
}

/// The fields of an AuthnRequest this IdP reads. Everything else is ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthnRequest {
    pub id: String,
    pub version: String,
    pub issue_instant: String,
    pub destination: Option<String>,
    pub acs_url: Option<String>,
    pub acs_index: Option<String>,
    pub protocol_binding: Option<String>,
    pub force_authn: bool,
    pub issuer: String,
}

/// The binding-encoded request as bytes of XML, or why not.
pub fn decode(encoded: &str, binding: Binding) -> Result<Vec<u8>, &'static str> {
    if encoded.len() > MAX_ENCODED_BYTES {
        return Err("request_too_large");
    }
    let compact: String = encoded.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let raw = B64.decode(compact.as_bytes()).map_err(|_| "request_not_base64")?;
    match binding {
        Binding::Post => {
            if raw.len() > MAX_REQUEST_BYTES {
                return Err("request_too_large");
            }
            Ok(raw)
        }
        Binding::Redirect => {
            let mut out = Vec::new();
            let mut inflater = flate2::read::DeflateDecoder::new(raw.as_slice()).take(MAX_REQUEST_BYTES as u64 + 1);
            inflater.read_to_end(&mut out).map_err(|_| "request_not_deflate")?;
            if out.len() > MAX_REQUEST_BYTES {
                return Err("request_too_large");
            }
            Ok(out)
        }
    }
}

fn resolve_ref(r: &BytesRef<'_>) -> Result<String, &'static str> {
    if let Some(ch) = r.resolve_char_ref().map_err(|_| "malformed_xml")? {
        return Ok(ch.to_string());
    }
    let name = r.decode().map_err(|_| "malformed_xml")?;
    quick_xml::escape::resolve_predefined_entity(&name).map(str::to_string).ok_or("custom_entity")
}

fn owned_ns(r: &ResolveResult<'_>) -> Option<Vec<u8>> {
    match r {
        ResolveResult::Bound(ns) => Some(ns.as_ref().to_vec()),
        _ => None,
    }
}

fn read_root(
    e: &quick_xml::events::BytesStart<'_>,
    ns: Option<&[u8]>,
    roots: usize,
    out: &mut AuthnRequest,
) -> Result<(), &'static str> {
    if roots > 1 {
        return Err("multiple_roots");
    }
    if ns != Some(NS_PROTOCOL.as_bytes()) || e.local_name().as_ref() != b"AuthnRequest" {
        return Err("not_an_authn_request");
    }
    for attr in e.attributes() {
        let attr = attr.map_err(|_| "malformed_xml")?;
        if attr.key.prefix().is_some() {
            continue;
        }
        let value = attr.normalized_value(XmlVersion::Implicit1_0).map_err(|_| "malformed_xml")?.into_owned();
        match attr.key.local_name().as_ref() {
            b"ID" => out.id = value,
            b"Version" => out.version = value,
            b"IssueInstant" => out.issue_instant = value,
            b"Destination" => out.destination = Some(value),
            b"AssertionConsumerServiceURL" => out.acs_url = Some(value),
            b"AssertionConsumerServiceIndex" => out.acs_index = Some(value),
            b"ProtocolBinding" => out.protocol_binding = Some(value),
            b"ForceAuthn" => out.force_authn = value == "true" || value == "1",
            _ => {}
        }
    }
    Ok(())
}

/// Parse a decoded AuthnRequest.
pub fn parse(xml: &[u8]) -> Result<AuthnRequest, &'static str> {
    let mut reader = NsReader::from_reader(xml);
    reader.config_mut().trim_text(false);
    let mut out = AuthnRequest::default();
    let mut depth = 0usize;
    let mut roots = 0usize;
    let mut issuers = 0usize;
    let mut in_issuer = false;
    let mut text = String::new();

    loop {
        let (ns, event) = match reader.read_resolved_event() {
            Ok((ns, ev)) => (owned_ns(&ns), ev),
            Err(_) => return Err("malformed_xml"),
        };
        match event {
            Event::Eof => break,
            Event::DocType(_) => return Err("doctype_not_allowed"),
            Event::Decl(_) | Event::Comment(_) | Event::PI(_) => {}
            Event::Start(e) if depth == 0 => {
                roots += 1;
                read_root(&e, ns.as_deref(), roots, &mut out)?;
                depth = 1;
            }
            // An empty root is legal XML but carries no Issuer.
            Event::Empty(e) if depth == 0 => {
                roots += 1;
                read_root(&e, ns.as_deref(), roots, &mut out)?;
            }
            Event::Start(e) => {
                if in_issuer {
                    return Err("malformed_issuer");
                }
                if depth == 1 && ns.as_deref() == Some(NS_ASSERTION.as_bytes()) && e.local_name().as_ref() == b"Issuer"
                {
                    issuers += 1;
                    if issuers > 1 {
                        return Err("multiple_issuers");
                    }
                    in_issuer = true;
                    text.clear();
                }
                depth += 1;
            }
            Event::Empty(e) => {
                if depth == 1 && ns.as_deref() == Some(NS_ASSERTION.as_bytes()) && e.local_name().as_ref() == b"Issuer"
                {
                    return Err("empty_issuer");
                }
            }
            Event::End(_) => {
                depth = depth.saturating_sub(1);
                if in_issuer && depth == 1 {
                    in_issuer = false;
                    out.issuer = text.trim().to_string();
                }
            }
            Event::Text(t) => {
                if in_issuer {
                    text.push_str(&t.xml10_content().map_err(|_| "malformed_xml")?);
                }
            }
            Event::GeneralRef(r) => {
                let s = resolve_ref(&r)?;
                if in_issuer {
                    text.push_str(&s);
                }
            }
            Event::CData(c) => {
                if in_issuer {
                    text.push_str(std::str::from_utf8(c.as_ref()).map_err(|_| "malformed_xml")?);
                }
            }
        }
    }
    if roots == 0 {
        return Err("not_an_authn_request");
    }
    if out.issuer.is_empty() {
        return Err("missing_issuer");
    }
    Ok(out)
}
