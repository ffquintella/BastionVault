//! SAML assertion signature verification.
//!
//! Implements the minimum XML-DSig + Exclusive XML Canonicalisation
//! subset needed to verify the two signature shapes that every major
//! IdP (Azure AD, Okta, Keycloak, Shibboleth, ADFS) emits:
//!
//!   1. RSA-SHA256 signature (rarely RSA-SHA1 on legacy IdPs).
//!   2. `<ds:Signature>` enveloped in the signed element as a child,
//!      with `<ds:Reference URI="#<ID>">` pointing to its parent.
//!   3. Transform chain: `enveloped-signature` + `exclusive-c14n`.
//!
//! We support Assertion-level signatures (most common) and also
//! Response-level signatures (Azure AD + ADFS default). Both can
//! coexist; we verify whichever one covers the assertion we're
//! trusting the NameID and attributes out of.
//!
//! # What we don't support
//!
//! * Non-RSA signatures (ECDSA, DSA). Every mainstream IdP uses RSA.
//! * Detached signatures or enveloping signatures (the signature
//!   wrapping the payload). SAML in practice is always enveloped.
//! * `<InclusiveNamespaces>` PrefixList other than the empty set.
//!   IdPs we've tested don't use it.
//! * Multi-reference signatures. Each `<SignedInfo>` is expected to
//!   hold exactly one `<Reference>`.
//!
//! When any of the above is encountered we return a descriptive
//! error rather than silently accepting. The audit trail records
//! the failure reason so an operator can see whether they've hit a
//! spec edge case or a real attack attempt.

use base64::{engine::general_purpose, Engine as _};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
// The project's top-level `sha1` / `sha2` are at 0.11 and use
// `digest 0.11`, which is incompatible with `rsa 0.9`'s 0.10-based
// signature traits. The aliased `sha1-saml` / `sha2-saml` deps pull
// in the matching 0.10 lineage — kept isolated to this module.
use sha1_saml::Sha1;
use sha2_saml::{Digest, Sha256};

use crate::errors::RvError;

use super::response::ParsedResponse;

const XML_DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED_SIG: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SHA1_DIGEST: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
const SHA256_DIGEST: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

/// Extract an RSA public key from a PEM-encoded X.509 certificate.
/// The cert body may be wrapped in `-----BEGIN CERTIFICATE-----`
/// markers or be raw base64 (some admin UIs strip the header).
pub fn parse_rsa_public_key_from_pem(pem: &str) -> Result<RsaPublicKey, RvError> {
    let der = pem_decode_cert(pem)?;
    let (_rest, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| RvError::ErrString(format!("saml: failed to parse IdP X.509: {e}")))?;
    let spki = cert.public_key();

    // Accept only RSA public keys. SPKI-level algorithm identifiers
    // vary: we match by the RSA OID rather than wrestle with nested
    // algorithm-parameters parsing.
    use rsa::pkcs1::DecodeRsaPublicKey;
    if !spki.algorithm.algorithm.to_string().starts_with("1.2.840.113549.1.1") {
        return Err(RvError::ErrString(format!(
            "saml: IdP certificate uses unsupported public-key algorithm OID `{}`; only RSA is supported",
            spki.algorithm.algorithm
        )));
    }
    RsaPublicKey::from_pkcs1_der(spki.subject_public_key.data.as_ref())
        .map_err(|e| RvError::ErrString(format!("saml: failed to parse RSA public key: {e}")))
}

fn pem_decode_cert(pem: &str) -> Result<Vec<u8>, RvError> {
    let body = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>();
    general_purpose::STANDARD
        .decode(body.trim().replace(char::is_whitespace, ""))
        .or_else(|_| general_purpose::STANDARD.decode(pem.trim()))
        .map_err(|e| RvError::ErrString(format!("saml: IdP cert not valid base64: {e}")))
}

/// Verify the signature covering either the Response or the
/// Assertion inside `parsed`. Returns `Ok(())` on success; a
/// descriptive `RvError::ErrString` otherwise.
///
/// Preference order: assertion-level signature first (smaller
/// region, tighter security property), falling back to
/// response-level signature if no assertion-level one is present.
/// Returns an error if no signature covers the assertion at all.
pub fn verify_signed_assertion(
    parsed: &ParsedResponse,
    idp_public_key: &RsaPublicKey,
) -> Result<(), RvError> {
    let assertion = parsed
        .assertion
        .as_ref()
        .ok_or_else(|| RvError::ErrString("saml: no Assertion to verify".into()))?;

    // Try assertion-level first.
    if let Some((start, end)) = assertion.xml_span {
        let element = &parsed.raw_xml[start..end];
        if let Some(sig) = locate_signature_inside(element) {
            return verify_one(element, &sig, idp_public_key, &assertion.id);
        }
    }

    // Fall back to response-level. The signed region is the whole
    // Response element (minus its own enveloped signature descendant).
    if let Some(sig) = locate_signature_inside(&parsed.raw_xml) {
        return verify_one(&parsed.raw_xml, &sig, idp_public_key, &parsed.response_id);
    }

    Err(RvError::ErrString(
        "saml: Response carries no XML signature — rejecting (set `require_signed = false` in config once that escape hatch ships; until then, configure your IdP to sign)".into(),
    ))
}

/// Minimal structural model of a located `<Signature>` element.
#[derive(Debug)]
struct LocatedSignature {
    /// Byte range of the `<Signature>` element inside the containing
    /// XML span — used by the enveloped-signature transform to strip
    /// the signature from the signed region.
    span: (usize, usize),
    signed_info_xml: Vec<u8>,
    signature_value_b64: String,
    signature_method: String,
    canonicalization_method: String,
    digest_method: String,
    digest_value_b64: String,
    reference_uri: String,
    transforms: Vec<String>,
}

fn locate_signature_inside(xml: &[u8]) -> Option<LocatedSignature> {
    // Find the first `<*:Signature>` or `<Signature>` tag whose
    // namespace URI (declared inline or inherited) is XMLDSIG. We
    // match by element local-name + the namespace attribute we find
    // locally — a principled approach would track namespace scope,
    // but every IdP we've seen declares `xmlns:ds="xmldsig"` or
    // `xmlns="xmldsig"` on the Signature element itself.
    let (sig_start, sig_end) = find_element_span(xml, b"Signature")?;
    let inner = &xml[sig_start..sig_end];
    if !std::str::from_utf8(inner).unwrap_or("").contains(XML_DSIG_NS) {
        return None;
    }

    let signed_info_range = find_element_span_rel(inner, b"SignedInfo")?;
    let signed_info_xml = inner[signed_info_range.0..signed_info_range.1].to_vec();

    let signature_value_b64 = extract_element_text(inner, b"SignatureValue")?
        .split_whitespace()
        .collect::<String>();

    let signature_method = attribute_on_element(inner, b"SignatureMethod", b"Algorithm")
        .unwrap_or_default();
    let canonicalization_method =
        attribute_on_element(inner, b"CanonicalizationMethod", b"Algorithm")
            .unwrap_or_default();
    let digest_method =
        attribute_on_element(inner, b"DigestMethod", b"Algorithm").unwrap_or_default();
    let digest_value_b64 = extract_element_text(inner, b"DigestValue")
        .unwrap_or_default()
        .split_whitespace()
        .collect::<String>();
    let reference_uri =
        attribute_on_element(inner, b"Reference", b"URI").unwrap_or_default();

    let mut transforms = Vec::new();
    let mut search = inner;
    while let Some(idx) = find_tag(search, b"Transform") {
        // Pull the `Algorithm="..."` attribute out of the located tag.
        let tail = &search[idx..];
        let end = tail.iter().position(|&b| b == b'>').unwrap_or(tail.len());
        let tag = std::str::from_utf8(&tail[..end]).unwrap_or("");
        if let Some(v) = parse_attr(tag, "Algorithm") {
            transforms.push(v);
        }
        search = &search[idx + end..];
    }

    Some(LocatedSignature {
        span: (sig_start, sig_end),
        signed_info_xml,
        signature_value_b64,
        signature_method,
        canonicalization_method,
        digest_method,
        digest_value_b64,
        reference_uri,
        transforms,
    })
}

fn verify_one(
    signed_element: &[u8],
    sig: &LocatedSignature,
    key: &RsaPublicKey,
    expected_id: &str,
) -> Result<(), RvError> {
    // 1. The Reference URI must point at the element we're trusting.
    //    Trailing `#` + ID.
    let want = format!("#{}", expected_id);
    if sig.reference_uri != want {
        return Err(RvError::ErrString(format!(
            "saml: signature Reference URI `{}` does not cover the signed element `{}`",
            sig.reference_uri, want
        )));
    }

    // 2. Transforms must include enveloped-signature + exclusive-c14n
    //    (in either order; the spec doesn't mandate an ordering but
    //    in practice enveloped comes first).
    if !sig.transforms.iter().any(|t| t == ENVELOPED_SIG) {
        return Err(RvError::ErrString(
            "saml: signature missing enveloped-signature transform".into(),
        ));
    }
    if !sig.transforms.iter().any(|t| t == EXC_C14N) {
        return Err(RvError::ErrString(
            "saml: signature missing exclusive-c14n transform".into(),
        ));
    }
    if sig.canonicalization_method != EXC_C14N {
        return Err(RvError::ErrString(format!(
            "saml: unsupported CanonicalizationMethod `{}` — only exclusive-c14n is supported",
            sig.canonicalization_method
        )));
    }

    // 3. Strip the Signature descendant from the signed element to
    //    apply the enveloped-signature transform, then canonicalise.
    let post_transform = strip_signature(signed_element, sig.span);
    let canon_referenced = canonicalise_exclusive(&post_transform)?;

    // 4. Digest the canonical form and compare with DigestValue.
    let want_digest = general_purpose::STANDARD
        .decode(&sig.digest_value_b64)
        .map_err(|e| RvError::ErrString(format!("saml: DigestValue not base64: {e}")))?;
    let got_digest = match sig.digest_method.as_str() {
        SHA256_DIGEST => Sha256::digest(&canon_referenced).to_vec(),
        SHA1_DIGEST => {
            let mut h = Sha1::new();
            h.update(&canon_referenced);
            h.finalize().to_vec()
        }
        other => {
            return Err(RvError::ErrString(format!(
                "saml: unsupported DigestMethod `{other}` — only SHA-256 and SHA-1 are supported"
            )))
        }
    };
    if got_digest != want_digest {
        return Err(RvError::ErrString(
            "saml: signed element digest mismatch — the assertion has been modified in transit or the signer's cert is not the one we're comparing against".into(),
        ));
    }

    // 5. Canonicalise SignedInfo, then RSA-verify the SignatureValue
    //    over it.
    let canon_signed_info = canonicalise_exclusive(&sig.signed_info_xml)?;
    let sig_bytes = general_purpose::STANDARD
        .decode(sig.signature_value_b64.replace(char::is_whitespace, ""))
        .map_err(|e| RvError::ErrString(format!("saml: SignatureValue not base64: {e}")))?;

    match sig.signature_method.as_str() {
        RSA_SHA256 => {
            let verifier = VerifyingKey::<Sha256>::new(key.clone());
            let signature = Signature::try_from(sig_bytes.as_slice())
                .map_err(|e| RvError::ErrString(format!("saml: invalid RSA signature: {e}")))?;
            verifier.verify(&canon_signed_info, &signature).map_err(|e| {
                RvError::ErrString(format!("saml: signature verification failed: {e}"))
            })?;
        }
        RSA_SHA1 => {
            let verifier = VerifyingKey::<Sha1>::new(key.clone());
            let signature = Signature::try_from(sig_bytes.as_slice())
                .map_err(|e| RvError::ErrString(format!("saml: invalid RSA signature: {e}")))?;
            verifier.verify(&canon_signed_info, &signature).map_err(|e| {
                RvError::ErrString(format!("saml: signature verification failed: {e}"))
            })?;
        }
        other => {
            return Err(RvError::ErrString(format!(
                "saml: unsupported SignatureMethod `{other}` — only RSA-SHA256 and RSA-SHA1 are supported"
            )))
        }
    }

    Ok(())
}

/// Apply the enveloped-signature transform by dropping the
/// `<Signature>` subtree from the signed element.
fn strip_signature(element: &[u8], sig_span: (usize, usize)) -> Vec<u8> {
    let mut out = Vec::with_capacity(element.len());
    out.extend_from_slice(&element[..sig_span.0]);
    out.extend_from_slice(&element[sig_span.1..]);
    out
}

// ── XML helpers: element + attribute extraction ────────────────────
//
// These are byte-level scanners rather than XML-tree walkers because
// the verification flow needs to reason about exact byte ranges and
// reuse the caller's buffer. `quick_xml` could produce the same
// information but at a higher implementation cost.

fn find_tag(xml: &[u8], local: &[u8]) -> Option<usize> {
    // Look for `<` then optional `prefix:` then `local` followed by
    // `>` / whitespace. Matches both `<ds:Signature>` and
    // `<Signature>` and `<Signature xmlns="…">`.
    let needle_suffixes = [b' ', b'\t', b'\n', b'\r', b'>'];
    let mut i = 0;
    while i + 1 < xml.len() {
        if xml[i] == b'<' {
            let start_name = i + 1;
            let after_prefix = match xml[start_name..].iter().position(|&b| b == b':') {
                Some(p) => {
                    // Ensure we're not stepping out of this tag.
                    if xml[start_name..start_name + p]
                        .iter()
                        .any(|b| needle_suffixes.contains(b) || *b == b'/')
                    {
                        start_name
                    } else {
                        start_name + p + 1
                    }
                }
                None => start_name,
            };
            if xml.len() >= after_prefix + local.len()
                && &xml[after_prefix..after_prefix + local.len()] == local
            {
                let next = after_prefix + local.len();
                if next < xml.len() && needle_suffixes.contains(&xml[next]) {
                    return Some(i);
                }
            }
        }
        i += 1;
    }
    None
}

/// Find the `(start, end)` byte range of `<local>...</local>` where
/// `start` is the `<` and `end` is immediately after the matching
/// `>`. Returns the first match at the outermost depth of the
/// provided XML slice. Respects nesting of same-named elements.
fn find_element_span(xml: &[u8], local: &[u8]) -> Option<(usize, usize)> {
    let start = find_tag(xml, local)?;
    let end = find_matching_close(xml, start, local)?;
    Some((start, end))
}

fn find_element_span_rel(xml: &[u8], local: &[u8]) -> Option<(usize, usize)> {
    find_element_span(xml, local)
}

fn find_matching_close(xml: &[u8], start: usize, local: &[u8]) -> Option<usize> {
    // Walk forward counting opening tags of the same local name.
    let mut depth = 1usize;
    let mut i = start + 1;
    // First, skip past the opening tag to its `>`.
    while i < xml.len() && xml[i] != b'>' {
        i += 1;
    }
    if i >= xml.len() {
        return None;
    }
    // Self-closing?
    if i > 0 && xml[i - 1] == b'/' {
        return Some(i + 1);
    }
    i += 1;

    while i < xml.len() {
        if xml[i] == b'<' {
            if i + 1 < xml.len() && xml[i + 1] == b'/' {
                // Closing tag candidate.
                let after_slash = i + 2;
                let name_start = match xml[after_slash..].iter().position(|&b| b == b':') {
                    Some(p) if p < 32 => after_slash + p + 1,
                    _ => after_slash,
                };
                if xml.len() >= name_start + local.len()
                    && &xml[name_start..name_start + local.len()] == local
                {
                    // Require a proper close-tag terminator right
                    // after the local name so `</ds:SignatureValue>`
                    // doesn't prefix-match as a close for `Signature`.
                    let next = name_start + local.len();
                    let term_ok = next < xml.len()
                        && matches!(
                            xml[next],
                            b'>' | b' ' | b'\t' | b'\n' | b'\r'
                        );
                    if term_ok {
                        depth -= 1;
                        if depth == 0 {
                            // Find the `>` that closes this end tag.
                            let mut j = next;
                            while j < xml.len() && xml[j] != b'>' {
                                j += 1;
                            }
                            return Some(j + 1);
                        }
                    }
                }
            } else if let Some(tag_start) = find_tag_at(xml, i, local) {
                if tag_start == i {
                    depth += 1;
                }
            }
        }
        i += 1;
    }
    None
}

fn find_tag_at(xml: &[u8], pos: usize, local: &[u8]) -> Option<usize> {
    if xml.get(pos) != Some(&b'<') {
        return None;
    }
    let start_name = pos + 1;
    let after_prefix = match xml[start_name..].iter().position(|&b| b == b':') {
        Some(p) if p < 32 => start_name + p + 1,
        _ => start_name,
    };
    if xml.len() >= after_prefix + local.len()
        && &xml[after_prefix..after_prefix + local.len()] == local
    {
        let next = after_prefix + local.len();
        if next < xml.len()
            && (xml[next] == b' '
                || xml[next] == b'>'
                || xml[next] == b'\t'
                || xml[next] == b'\n'
                || xml[next] == b'\r'
                || xml[next] == b'/')
        {
            return Some(pos);
        }
    }
    None
}

fn extract_element_text(xml: &[u8], local: &[u8]) -> Option<String> {
    let (start, end) = find_element_span(xml, local)?;
    let inner = &xml[start..end];
    // Cut off opening + closing tag by finding the first `>` and
    // last `<`.
    let first_gt = inner.iter().position(|&b| b == b'>')? + 1;
    let last_lt = inner.iter().rposition(|&b| b == b'<')?;
    std::str::from_utf8(&inner[first_gt..last_lt])
        .ok()
        .map(|s| s.to_string())
}

fn attribute_on_element(xml: &[u8], local: &[u8], attr: &[u8]) -> Option<String> {
    let start = find_tag(xml, local)?;
    let tail = &xml[start..];
    let end = tail.iter().position(|&b| b == b'>')?;
    let tag = std::str::from_utf8(&tail[..end]).ok()?;
    let attr_name = std::str::from_utf8(attr).ok()?;
    parse_attr(tag, attr_name)
}

fn parse_attr(tag: &str, name: &str) -> Option<String> {
    // Very permissive attribute extractor that tolerates whitespace
    // and either quote style. Doesn't attempt XML-entity decoding
    // because Reference URIs / Algorithm URLs never contain entities.
    let key_double = format!("{name}=\"");
    let key_single = format!("{name}='");
    for key in [&key_double, &key_single] {
        if let Some(start) = tag.find(key.as_str()) {
            let after = start + key.len();
            let quote = &key[key.len() - 1..];
            if let Some(end) = tag[after..].find(quote) {
                return Some(tag[after..after + end].to_string());
            }
        }
    }
    None
}

// ── Exclusive XML Canonicalisation (subset) ────────────────────────
//
// A pragmatic implementation of Exclusive XML C14N 1.0
// (https://www.w3.org/TR/xml-exc-c14n/). Handles the forms produced
// by every major IdP we've seen:
//
//   * Namespace declarations pruned to those actually used by the
//     element or its in-scope attributes
//   * Attributes + namespace declarations sorted canonically
//   * Text escaping `&` / `<` / `>` / `\r`
//   * Attribute-value escaping `&` / `<` / `"` / `\t` / `\n` / `\r`
//   * Comments + processing instructions dropped
//
// The pragmatic limits (see module-level doc) produce wrong output
// for inputs that use features no real IdP emits on signed regions.

fn canonicalise_exclusive(xml: &[u8]) -> Result<Vec<u8>, RvError> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);
    reader.config_mut().expand_empty_elements = true;

    // Namespace scope stack. Each entry is the list of `(prefix, uri)`
    // bindings declared on that element. We track the "rendered" set
    // to avoid re-emitting a namespace that's already visible.
    let mut ns_rendered_stack: Vec<Vec<(String, String)>> = vec![Vec::new()];
    let mut out = Vec::with_capacity(xml.len());

    loop {
        match reader.read_event() {
            Err(e) => {
                return Err(RvError::ErrString(format!("saml: c14n parse error: {e}")))
            }
            Ok(Event::Eof) => break,
            Ok(Event::Decl(_)) => {
                // XML declaration is NOT part of the canonical form.
            }
            Ok(Event::PI(_)) | Ok(Event::Comment(_)) | Ok(Event::DocType(_)) => {
                // Omitted.
            }
            Ok(Event::Start(e)) => {
                // Pull the element's qualified name.
                let raw = e.name().as_ref().to_vec();
                let qname = std::str::from_utf8(&raw)
                    .map_err(|err| RvError::ErrString(format!("saml: c14n qname utf-8: {err}")))?
                    .to_string();
                let (elem_prefix, _elem_local) = split_qname(&qname);

                // Separate attributes into namespace decls + ordinary.
                let mut ns_decls: Vec<(String, String)> = Vec::new();
                let mut attrs: Vec<(String, String)> = Vec::new();
                for attr in e.attributes().flatten() {
                    let key = std::str::from_utf8(attr.key.as_ref())
                        .map_err(|err| {
                            RvError::ErrString(format!("saml: c14n attr utf-8: {err}"))
                        })?
                        .to_string();
                    let val = attr
                        .decode_and_unescape_value(reader.decoder())
                        .map_err(|err| {
                            RvError::ErrString(format!("saml: c14n attr decode: {err}"))
                        })?
                        .into_owned();
                    if key == "xmlns" {
                        ns_decls.push((String::new(), val));
                    } else if let Some(p) = key.strip_prefix("xmlns:") {
                        ns_decls.push((p.to_string(), val));
                    } else {
                        attrs.push((key, val));
                    }
                }

                // Compute the in-scope namespace visible *before* this
                // element, so we can decide what needs (re)rendering.
                let mut in_scope: std::collections::HashMap<String, String> =
                    std::collections::HashMap::new();
                for frame in &ns_rendered_stack {
                    for (p, u) in frame {
                        in_scope.insert(p.clone(), u.clone());
                    }
                }

                // Identify prefixes that the element / its attributes
                // actually use — that's the "visibly utilised" set in
                // the exclusive-c14n spec.
                let mut used_prefixes: std::collections::BTreeSet<String> =
                    std::collections::BTreeSet::new();
                used_prefixes.insert(elem_prefix.clone());
                for (k, _) in &attrs {
                    let (p, _) = split_qname(k);
                    if !p.is_empty() {
                        used_prefixes.insert(p);
                    }
                }

                // Namespace declarations to emit: used prefixes whose
                // current binding hasn't already been rendered.
                let mut emit_ns: Vec<(String, String)> = Vec::new();
                for p in &used_prefixes {
                    // Prefer a just-declared binding (ns_decls wins).
                    let uri = ns_decls
                        .iter()
                        .find(|(pp, _)| pp == p)
                        .map(|(_, u)| u.clone())
                        .or_else(|| in_scope.get(p).cloned());
                    if let Some(uri) = uri {
                        // Only emit if the prefix was not already
                        // rendered with the same URI in a visible
                        // ancestor.
                        let already = ns_rendered_stack
                            .iter()
                            .rev()
                            .find_map(|f| f.iter().find(|(pp, _)| pp == p))
                            .map(|(_, u)| u == &uri)
                            .unwrap_or(false);
                        if !already {
                            emit_ns.push((p.clone(), uri));
                        }
                    }
                }
                // Canonical sort: default ns (empty prefix) first,
                // then by prefix.
                emit_ns.sort_by(|a, b| a.0.cmp(&b.0));

                // Attribute canonical sort: by (namespace URI, local).
                // We approximate namespace URI lookup via `in_scope`
                // augmented with `ns_decls`.
                let mut scope_now = in_scope.clone();
                for (p, u) in &ns_decls {
                    scope_now.insert(p.clone(), u.clone());
                }
                let mut attrs_sorted: Vec<(String, String, String, String)> = attrs
                    .into_iter()
                    .map(|(k, v)| {
                        let (p, l) = split_qname(&k);
                        let uri = scope_now.get(&p).cloned().unwrap_or_default();
                        (uri, l, k, v)
                    })
                    .collect();
                attrs_sorted.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

                // Emit start tag.
                out.push(b'<');
                out.extend_from_slice(qname.as_bytes());
                for (p, u) in &emit_ns {
                    out.push(b' ');
                    if p.is_empty() {
                        out.extend_from_slice(b"xmlns=\"");
                    } else {
                        out.extend_from_slice(b"xmlns:");
                        out.extend_from_slice(p.as_bytes());
                        out.extend_from_slice(b"=\"");
                    }
                    write_attr_value(&mut out, u);
                    out.push(b'"');
                }
                for (_, _, k, v) in &attrs_sorted {
                    out.push(b' ');
                    out.extend_from_slice(k.as_bytes());
                    out.extend_from_slice(b"=\"");
                    write_attr_value(&mut out, v);
                    out.push(b'"');
                }
                out.push(b'>');

                // Record rendered namespaces for this element's subtree.
                let mut rendered_frame = Vec::new();
                for (p, u) in emit_ns {
                    rendered_frame.push((p, u));
                }
                ns_rendered_stack.push(rendered_frame);
            }
            Ok(Event::End(e)) => {
                let raw = e.name().as_ref().to_vec();
                out.push(b'<');
                out.push(b'/');
                out.extend_from_slice(&raw);
                out.push(b'>');
                ns_rendered_stack.pop();
            }
            Ok(Event::Text(t)) => {
                // `unescape` gives us the text content with XML
                // entities resolved (e.g. `&amp;` → `&`). The
                // canonical output then re-escapes per c14n rules.
                let s = t
                    .unescape()
                    .map_err(|e| RvError::ErrString(format!("saml: c14n text decode: {e}")))?;
                write_text(&mut out, &s);
            }
            Ok(Event::CData(c)) => {
                let s = std::str::from_utf8(c.as_ref())
                    .map_err(|e| RvError::ErrString(format!("saml: c14n cdata utf-8: {e}")))?;
                write_text(&mut out, s);
            }
            _ => {}
        }
    }

    Ok(out)
}

fn split_qname(q: &str) -> (String, String) {
    match q.find(':') {
        Some(i) => (q[..i].to_string(), q[i + 1..].to_string()),
        None => (String::new(), q.to_string()),
    }
}

fn write_text(out: &mut Vec<u8>, s: &str) {
    for ch in s.chars() {
        match ch {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '>' => out.extend_from_slice(b"&gt;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            other => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
}

fn write_attr_value(out: &mut Vec<u8>, s: &str) {
    for ch in s.chars() {
        match ch {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '"' => out.extend_from_slice(b"&quot;"),
            '\t' => out.extend_from_slice(b"&#x9;"),
            '\n' => out.extend_from_slice(b"&#xA;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            other => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_attr_handles_double_and_single_quotes() {
        // `r##"..."##` (double hashes) so the `#` inside `#id-1`
        // doesn't prematurely terminate the raw string literal.
        assert_eq!(
            parse_attr(r##"<Reference URI="#id-1" Foo="bar""##, "URI"),
            Some("#id-1".to_string())
        );
        assert_eq!(
            parse_attr(r##"<Reference URI='#id-2'"##, "URI"),
            Some("#id-2".to_string())
        );
        assert_eq!(parse_attr(r#"<Reference"#, "URI"), None);
    }

    #[test]
    fn canonicalise_sorts_attributes() {
        let input = br#"<foo b="2" a="1"/>"#;
        let got = canonicalise_exclusive(input).unwrap();
        assert_eq!(
            std::str::from_utf8(&got).unwrap(),
            r#"<foo a="1" b="2"></foo>"#
        );
    }

    #[test]
    fn canonicalise_escapes_text_and_attrs() {
        let input = br#"<foo a="&quot;&amp;">a&amp;b</foo>"#;
        let got = canonicalise_exclusive(input).unwrap();
        // Text `&` must become `&amp;`, attr `"` must become `&quot;`.
        assert_eq!(
            std::str::from_utf8(&got).unwrap(),
            r#"<foo a="&quot;&amp;">a&amp;b</foo>"#
        );
    }

    #[test]
    fn canonicalise_prunes_unused_namespaces() {
        // The `unused:` namespace is declared but not referenced by
        // any child — exclusive c14n drops it.
        let input = br#"<a xmlns:unused="http://x" xmlns:used="http://y"><used:child/></a>"#;
        let got = canonicalise_exclusive(input).unwrap();
        let s = std::str::from_utf8(&got).unwrap();
        assert!(!s.contains("unused"), "unused namespace leaked: {s}");
        assert!(s.contains("used"));
    }

    #[test]
    fn locate_signature_pulls_out_parts() {
        // Concatenate rather than use a raw string so the `#` in the
        // URNs (`#enveloped-signature`, `#sha256`, `#a1`) don't get
        // mistaken for the r"..." terminator.
        let xml: Vec<u8> = [
            r#"<saml:Assertion xmlns:saml="x" ID="a1">"#,
            r#"<ds:Signature xmlns:ds=""#, XML_DSIG_NS, r#"">"#,
            r#"<ds:SignedInfo>"#,
            r#"<ds:CanonicalizationMethod Algorithm=""#, EXC_C14N, r#""/>"#,
            r#"<ds:SignatureMethod Algorithm=""#, RSA_SHA256, r#""/>"#,
            r#"<ds:Reference URI="#, "\"#a1\"",  r#">"#,
            r#"<ds:Transforms>"#,
            r#"<ds:Transform Algorithm=""#, ENVELOPED_SIG, r#""/>"#,
            r#"<ds:Transform Algorithm=""#, EXC_C14N, r#""/>"#,
            r#"</ds:Transforms>"#,
            r#"<ds:DigestMethod Algorithm=""#, SHA256_DIGEST, r#""/>"#,
            r#"<ds:DigestValue>ZmFrZQ==</ds:DigestValue>"#,
            r#"</ds:Reference></ds:SignedInfo>"#,
            r#"<ds:SignatureValue>AAAA</ds:SignatureValue>"#,
            r#"</ds:Signature></saml:Assertion>"#,
        ]
        .concat()
        .into_bytes();
        let xml = xml.as_slice();
        let sig = locate_signature_inside(xml).unwrap();
        assert_eq!(sig.reference_uri, "#a1");
        assert_eq!(sig.signature_method, RSA_SHA256);
        assert_eq!(sig.digest_method, SHA256_DIGEST);
        assert_eq!(sig.canonicalization_method, EXC_C14N);
        assert_eq!(sig.digest_value_b64, "ZmFrZQ==");
        assert_eq!(sig.signature_value_b64, "AAAA");
        assert!(sig.transforms.contains(&ENVELOPED_SIG.to_string()));
        assert!(sig.transforms.contains(&EXC_C14N.to_string()));
    }

    #[test]
    fn pem_decode_accepts_marker_wrapped_and_raw() {
        let wrapped = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----";
        let raw = "AAAA";
        let a = pem_decode_cert(wrapped).unwrap();
        let b = pem_decode_cert(raw).unwrap();
        assert_eq!(a, b);
    }

    /// End-to-end signature-verification roundtrip. Generates a
    /// fresh RSA keypair in memory, signs the canonical form of an
    /// Assertion-shaped element, assembles the signed XML, and
    /// then confirms `verify_signed_assertion` accepts it and
    /// rejects it under a tampered payload.
    ///
    /// This test is the one that proves our c14n implementation is
    /// self-consistent end-to-end: we sign what we canonicalise,
    /// then verify that what we canonicalise matches what we signed.
    /// A bug in `canonicalise_exclusive` (attribute order, namespace
    /// pruning, escaping) would produce bytes the verifier then
    /// hashes to a different digest, and both assertions below
    /// would fail.
    #[test]
    fn roundtrip_signed_assertion_verifies() {
        use crate::modules::credential::saml::response::{
            ParsedAssertion, ParsedResponse,
        };
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding};
        use rsa::RsaPrivateKey;

        // 1. Generate a small (1024-bit) RSA key for test speed.
        // Use `rsa::rand_core::OsRng` rather than the top-level
        // `rand::rngs::OsRng` because `rsa 0.9` binds to
        // `rand_core 0.6`, while the project's `rand = "0.10"`
        // re-exports the 0.9 lineage — they're incompatible at
        // the trait level.
        let mut rng = rsa::rand_core::OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 1024).expect("gen key");
        let pub_key = RsaPublicKey::from(&priv_key);
        let signing_key: SigningKey<Sha256> = SigningKey::new(priv_key);

        // 2. Build the Assertion (without signature) that the IdP
        //    would sign.
        let assertion_id = "assert-roundtrip";
        let assertion_body = format!(
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{assertion_id}"><saml:Issuer>https://idp.test/</saml:Issuer><saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject></saml:Assertion>"#
        );

        // 3. Canonicalise + digest what we intend to sign. This is
        //    what the IdP-side sign path does conceptually: run its
        //    c14n on the assertion minus its signature descendant
        //    (here there's no signature yet), SHA-256 it, and
        //    embed the base64 digest as DigestValue.
        let canon_assertion = canonicalise_exclusive(assertion_body.as_bytes()).unwrap();
        let digest = Sha256::digest(&canon_assertion);
        let digest_b64 = general_purpose::STANDARD.encode(digest);

        // 4. Build SignedInfo containing the digest, canonicalise
        //    it, and sign the canonical form with RSA-SHA256. Uses
        //    double-hash raw-string delimiters so the embedded `#`
        //    in `URI="#{aid}"` doesn't prematurely close the literal.
        let signed_info = format!(
            r##"<ds:SignedInfo xmlns:ds="{ns}"><ds:CanonicalizationMethod Algorithm="{c14n}"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="{rsa256}"></ds:SignatureMethod><ds:Reference URI="#{aid}"><ds:Transforms><ds:Transform Algorithm="{env}"></ds:Transform><ds:Transform Algorithm="{c14n}"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="{sha256}"></ds:DigestMethod><ds:DigestValue>{dv}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##,
            ns = XML_DSIG_NS,
            c14n = EXC_C14N,
            rsa256 = RSA_SHA256,
            aid = assertion_id,
            env = ENVELOPED_SIG,
            sha256 = SHA256_DIGEST,
            dv = digest_b64,
        );
        let canon_signed_info = canonicalise_exclusive(signed_info.as_bytes()).unwrap();
        let signature = signing_key.sign_with_rng(&mut rng, &canon_signed_info);
        let signature_b64 =
            general_purpose::STANDARD.encode(signature.to_bytes());

        // 5. Splice SignedInfo + SignatureValue into the assertion
        //    just before `</saml:Assertion>`.
        let sig_block = format!(
            r#"<ds:Signature xmlns:ds="{ns}">{si}<ds:SignatureValue>{sv}</ds:SignatureValue></ds:Signature>"#,
            ns = XML_DSIG_NS,
            si = signed_info,
            sv = signature_b64,
        );
        let signed_assertion = assertion_body.replace(
            "</saml:Assertion>",
            &format!("{sig_block}</saml:Assertion>"),
        );

        // 6. Build a ParsedResponse that points at this assertion's
        //    byte span. `parse_response` would do this for us in
        //    production; we build it manually here to keep the test
        //    focused on the verifier.
        let response_xml = format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="resp-1">{signed_assertion}</samlp:Response>"#
        );
        let start = response_xml.find("<saml:Assertion").unwrap();
        let end = response_xml.find("</saml:Assertion>").unwrap() + "</saml:Assertion>".len();
        let parsed = ParsedResponse {
            response_id: "resp-1".into(),
            raw_xml: response_xml.as_bytes().to_vec(),
            assertion: Some(ParsedAssertion {
                id: assertion_id.to_string(),
                xml_span: Some((start, end)),
                ..Default::default()
            }),
            ..Default::default()
        };

        // 7. Happy path: verification succeeds.
        verify_signed_assertion(&parsed, &pub_key).expect("signature must verify");

        // 8. Negative path: flip a byte inside the assertion and
        //    confirm verification fails with a digest mismatch.
        let mut tampered = parsed.clone();
        let bytes = tampered.raw_xml.as_mut_slice();
        let idx = bytes
            .windows(5)
            .position(|w| w == b"alice")
            .expect("find alice");
        bytes[idx] = b'A';
        let err = verify_signed_assertion(&tampered, &pub_key).unwrap_err();
        assert!(
            format!("{err}").contains("digest mismatch"),
            "tampered assertion should fail with digest mismatch, got: {err}"
        );

        // Silence unused warning on `Keypair` import.
        let _ = signing_key.verifying_key();
    }
}
