//! SAML 2.0 Response parsing.
//!
//! Walks a decoded `<samlp:Response>` XML document and extracts the
//! fields we need for the login flow:
//!
//!   * Response-level: `Issuer`, `Destination`, `InResponseTo`,
//!     `Status/StatusCode`.
//!   * Assertion-level: `Issuer`, `Subject/NameID` (+ `Format`),
//!     `Conditions/NotBefore`, `Conditions/NotOnOrAfter`,
//!     `Conditions/AudienceRestriction/Audience`, `AttributeStatement`
//!     attributes.
//!   * Whatever `<Signature>` elements exist (response-level and/or
//!     assertion-level) with enough surrounding context that the
//!     signature-verification module can recover the referenced
//!     element's canonical bytes.
//!
//! We deliberately keep the parser tolerant of unexpected elements
//! and attributes — IdPs emit a LOT of vendor-specific extras
//! (`Advice`, `AuthnStatement`, session indexes, etc.) that we
//! don't care about for the login flow. We only reject the document
//! outright if a field we're structurally going to consume is
//! missing or malformed.

use std::collections::HashMap;

use quick_xml::events::Event;
use quick_xml::name::QName;
use quick_xml::Reader;

use crate::errors::RvError;

/// Parsed projection of a SAML 2.0 Response.
#[derive(Debug, Default, Clone)]
pub struct ParsedResponse {
    pub response_id: String,
    pub issuer: String,
    pub destination: String,
    pub in_response_to: String,
    pub status_code: String,
    pub status_message: String,
    pub assertion: Option<ParsedAssertion>,
    /// Raw XML bytes of the inbound response, held for later
    /// signature verification (we need to point the verifier at
    /// the exact `<Assertion>` element's byte range).
    pub raw_xml: Vec<u8>,
}

#[derive(Debug, Default, Clone)]
pub struct ParsedAssertion {
    pub id: String,
    pub issuer: String,
    pub name_id: String,
    pub name_id_format: String,
    pub not_before: String,
    pub not_on_or_after: String,
    pub audience_restrictions: Vec<String>,
    pub attributes: HashMap<String, Vec<String>>,
    /// Byte range of the `<Assertion>` element in `raw_xml`, inclusive
    /// of its start tag and closing tag. The signature verifier
    /// uses this to locate the signed region.
    pub xml_span: Option<(usize, usize)>,
}

/// Parse a decoded Response XML document. Returns a structured
/// projection plus the raw bytes so later verification steps can
/// walk back into the tree.
pub fn parse_response(xml: &[u8]) -> Result<ParsedResponse, RvError> {
    let mut out = ParsedResponse {
        raw_xml: xml.to_vec(),
        ..Default::default()
    };

    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);

    let mut stack: Vec<String> = Vec::new();
    // When we see the opening `<Assertion>` tag, record the byte
    // position where its first `<` lives so we can slice out the
    // subtree at the matching close.
    let mut assertion_start: Option<usize> = None;
    let mut in_assertion_depth: Option<usize> = None;
    let mut current_attribute: Option<(String, Vec<String>)> = None;
    let mut capture_text_into: Option<TextTarget> = None;
    let mut assertion = ParsedAssertion::default();

    loop {
        // quick_xml advances its byte position as events are parsed.
        // We snapshot the position *before* the next `read_event()`
        // so we know where that event started — whitespace between
        // tags can shift the actual `<` forward, which we account
        // for by scanning `find_next_lt`.
        let before_read_pos = reader.buffer_position() as usize;
        match reader.read_event() {
            Err(e) => {
                return Err(RvError::ErrString(format!(
                    "saml: response XML parse error at offset {before_read_pos}: {e}"
                )));
            }
            Ok(Event::Eof) => break,

            Ok(Event::Empty(e)) => {
                // Self-closing tag (`<Foo ... />`). We translate it
                // into Start + End for attribute handling, so
                // `<StatusCode Value="..." />` populates the status
                // code the same way `<StatusCode>...</StatusCode>`
                // would. Empty elements can't contain text so the
                // text-capture path stays untouched.
                let local = local_name(e.name());
                if local == "StatusCode" {
                    for attr in e.attributes().flatten() {
                        let key = local_name(attr.key);
                        if key == "Value" {
                            out.status_code = attr_value(&attr, &reader);
                        }
                    }
                }
                // Other self-closing elements are structural glue we
                // don't capture (Transforms, CanonicalizationMethod,
                // Conditions-with-no-children, etc.).
            }

            Ok(Event::Start(e)) => {
                let local = local_name(e.name());
                stack.push(local.clone());

                // Top-level `<Response>` attributes carry the
                // response id / destination / in-response-to, all
                // of which we need for the validator.
                if local == "Response" && stack.len() == 1 {
                    for attr in e.attributes().flatten() {
                        let key = local_name(attr.key);
                        let val = attr_value(&attr, &reader);
                        match key.as_str() {
                            "ID" => out.response_id = val,
                            "Destination" => out.destination = val,
                            "InResponseTo" => out.in_response_to = val,
                            _ => {}
                        }
                    }
                } else if local == "Assertion" {
                    // Record the byte position where `<Assertion`
                    // begins. Scanning forward from the pre-event
                    // buffer position skips over any whitespace
                    // between the previous close-tag and this open.
                    let start = find_next_lt(xml, before_read_pos);
                    assertion_start = Some(start);
                    in_assertion_depth = Some(stack.len());
                    for attr in e.attributes().flatten() {
                        let key = local_name(attr.key);
                        let val = attr_value(&attr, &reader);
                        if key == "ID" {
                            assertion.id = val;
                        }
                    }
                } else if local == "Conditions"
                    && in_assertion_depth.is_some()
                {
                    for attr in e.attributes().flatten() {
                        let key = local_name(attr.key);
                        let val = attr_value(&attr, &reader);
                        match key.as_str() {
                            "NotBefore" => assertion.not_before = val,
                            "NotOnOrAfter" => assertion.not_on_or_after = val,
                            _ => {}
                        }
                    }
                } else if local == "StatusCode" {
                    for attr in e.attributes().flatten() {
                        let key = local_name(attr.key);
                        if key == "Value" {
                            out.status_code = attr_value(&attr, &reader);
                        }
                    }
                } else if local == "NameID" && in_assertion_depth.is_some() {
                    for attr in e.attributes().flatten() {
                        let key = local_name(attr.key);
                        if key == "Format" {
                            assertion.name_id_format = attr_value(&attr, &reader);
                        }
                    }
                    capture_text_into = Some(TextTarget::NameId);
                } else if local == "Issuer" {
                    if in_assertion_depth.is_some() {
                        capture_text_into = Some(TextTarget::AssertionIssuer);
                    } else {
                        capture_text_into = Some(TextTarget::ResponseIssuer);
                    }
                } else if local == "Audience" {
                    capture_text_into = Some(TextTarget::Audience);
                } else if local == "StatusMessage" {
                    capture_text_into = Some(TextTarget::StatusMessage);
                } else if local == "Attribute" && in_assertion_depth.is_some() {
                    let mut name = String::new();
                    for attr in e.attributes().flatten() {
                        if local_name(attr.key) == "Name" {
                            name = attr_value(&attr, &reader);
                        }
                    }
                    current_attribute = Some((name, Vec::new()));
                } else if local == "AttributeValue" && current_attribute.is_some() {
                    capture_text_into = Some(TextTarget::AttributeValue);
                }
            }

            Ok(Event::Text(t)) => {
                if let Some(target) = capture_text_into.as_ref() {
                    let s = t.unescape().map_err(|e| {
                        RvError::ErrString(format!("saml: invalid text node: {e}"))
                    })?;
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        match target {
                            TextTarget::NameId => assertion.name_id = trimmed.to_string(),
                            TextTarget::AssertionIssuer => {
                                assertion.issuer = trimmed.to_string();
                            }
                            TextTarget::ResponseIssuer => {
                                out.issuer = trimmed.to_string();
                            }
                            TextTarget::Audience => {
                                assertion
                                    .audience_restrictions
                                    .push(trimmed.to_string());
                            }
                            TextTarget::StatusMessage => {
                                out.status_message = trimmed.to_string();
                            }
                            TextTarget::AttributeValue => {
                                if let Some((_, values)) = current_attribute.as_mut() {
                                    values.push(trimmed.to_string());
                                }
                            }
                        }
                    }
                }
            }

            Ok(Event::End(e)) => {
                let local = local_name(e.name());
                if local == "Attribute" {
                    if let Some((name, values)) = current_attribute.take() {
                        if !name.is_empty() {
                            assertion
                                .attributes
                                .entry(name)
                                .or_default()
                                .extend(values);
                        }
                    }
                }
                if local == "Assertion" {
                    if let Some(start) = assertion_start.take() {
                        // `buffer_position()` points just past the
                        // `</Assertion>` close; that's the end
                        // (exclusive) of the element span.
                        let end = reader.buffer_position() as usize;
                        assertion.xml_span = Some((start, end));
                    }
                    in_assertion_depth = None;
                }
                if matches!(
                    local.as_str(),
                    "NameID"
                        | "Issuer"
                        | "Audience"
                        | "StatusMessage"
                        | "AttributeValue"
                ) {
                    capture_text_into = None;
                }
                stack.pop();
            }

            _ => {}
        }
    }

    if out.response_id.is_empty() {
        return Err(RvError::ErrString(
            "saml: Response has no ID attribute".into(),
        ));
    }
    if !assertion.id.is_empty() {
        out.assertion = Some(assertion);
    }
    Ok(out)
}

/// Which text-target the next `Event::Text` should be captured into.
/// A small enum dedicated enough that a state-machine is clearer
/// than N booleans.
enum TextTarget {
    NameId,
    AssertionIssuer,
    ResponseIssuer,
    Audience,
    StatusMessage,
    AttributeValue,
}

/// Extract the local (unqualified) name from a possibly-namespaced
/// `QName`. SAML elements arrive as `saml:Issuer` / `samlp:Response`
/// / etc.; we match on local name only because namespace prefixes
/// vary by IdP while the local names are spec-fixed.
fn local_name(q: QName<'_>) -> String {
    let raw = q.as_ref();
    match raw.iter().position(|&b| b == b':') {
        Some(i) => String::from_utf8_lossy(&raw[i + 1..]).into_owned(),
        None => String::from_utf8_lossy(raw).into_owned(),
    }
}

/// Resolve an attribute's unescaped string value.
fn attr_value(
    attr: &quick_xml::events::attributes::Attribute<'_>,
    reader: &Reader<&[u8]>,
) -> String {
    attr.decode_and_unescape_value(reader.decoder())
        .map(|c| c.into_owned())
        .unwrap_or_default()
}

/// Given the byte offset just before a parsed start-tag (the
/// position the reader sat at before reading the event), scan
/// forward to the next `<`. The whitespace that typically sits
/// between a previous end-tag and the next start-tag means the
/// `<` is at or just after `from`.
fn find_next_lt(xml: &[u8], from: usize) -> usize {
    let end = xml.len();
    let mut i = from.min(end);
    while i < end {
        if xml[i] == b'<' {
            return i;
        }
        i += 1;
    }
    from
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_RESPONSE: &str = r#"<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="resp-1"
    Destination="https://sp.example.com/acs"
    InResponseTo="id-abc">
  <saml:Issuer>https://idp.example.com/saml</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
  </samlp:Status>
  <saml:Assertion ID="assert-1">
    <saml:Issuer>https://idp.example.com/saml</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-04-24T12:00:00Z" NotOnOrAfter="2026-04-24T13:00:00Z">
      <saml:AudienceRestriction>
        <saml:Audience>https://sp.example.com/saml</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>alice@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="groups">
        <saml:AttributeValue>engineering</saml:AttributeValue>
        <saml:AttributeValue>admins</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"#;

    #[test]
    fn parses_response_and_assertion() {
        let parsed = parse_response(SAMPLE_RESPONSE.as_bytes()).unwrap();
        assert_eq!(parsed.response_id, "resp-1");
        assert_eq!(parsed.destination, "https://sp.example.com/acs");
        assert_eq!(parsed.in_response_to, "id-abc");
        assert_eq!(parsed.issuer, "https://idp.example.com/saml");
        assert_eq!(
            parsed.status_code,
            "urn:oasis:names:tc:SAML:2.0:status:Success"
        );

        let a = parsed.assertion.unwrap();
        assert_eq!(a.id, "assert-1");
        assert_eq!(a.issuer, "https://idp.example.com/saml");
        assert_eq!(a.name_id, "alice@example.com");
        assert!(a.name_id_format.ends_with("emailAddress"));
        assert_eq!(a.not_before, "2026-04-24T12:00:00Z");
        assert_eq!(a.not_on_or_after, "2026-04-24T13:00:00Z");
        assert_eq!(
            a.audience_restrictions,
            vec!["https://sp.example.com/saml".to_string()]
        );
        assert_eq!(
            a.attributes.get("email"),
            Some(&vec!["alice@example.com".to_string()])
        );
        assert_eq!(
            a.attributes.get("groups"),
            Some(&vec!["engineering".to_string(), "admins".to_string()])
        );
    }

    #[test]
    fn parse_rejects_malformed_xml() {
        let err = parse_response(b"<not-xml").unwrap_err();
        assert!(format!("{err}").contains("parse error"));
    }

    #[test]
    fn parse_rejects_response_without_id() {
        let bad = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"></samlp:Response>"#;
        let err = parse_response(bad.as_bytes()).unwrap_err();
        assert!(format!("{err}").contains("no ID"));
    }

    #[test]
    fn captures_assertion_xml_span() {
        let parsed = parse_response(SAMPLE_RESPONSE.as_bytes()).unwrap();
        let a = parsed.assertion.unwrap();
        let (start, end) = a.xml_span.expect("assertion span must be captured");
        let slice = &SAMPLE_RESPONSE.as_bytes()[start..end];
        let s = std::str::from_utf8(slice).unwrap();
        assert!(s.trim_start().starts_with("<saml:Assertion"));
        assert!(s.trim_end().ends_with("</saml:Assertion>"));
    }
}
