//! PKCS#10 CSR parsing for `pki/sign/:role`, `pki/sign-verbatim`, and
//! `pki/root/sign-intermediate` (Phase 5).
//!
//! `rcgen` 0.14 does not expose CSR parsing publicly, so this module sits
//! between `x509-parser` (for the structural parse + signature verification)
//! and `rcgen::SubjectPublicKeyInfo::from_der` (which `params.signed_by`
//! consumes). The result is that the existing classical / PQC / composite
//! cert builders see a uniform `(spki_der, subject_dn, requested_sans)`
//! tuple regardless of who generated the keypair.
//!
//! Phase 5 supports CSRs whose subject public key is one of the classical
//! algorithms `rcgen::SubjectPublicKeyInfo::from_der` recognises (RSA,
//! ECDSA-P256/P384, Ed25519). PQC and composite CSRs are deferred — there
//! is no widely-deployed PKCS#10 wrapper for ML-DSA pubkeys yet, and the
//! engine generates fresh PQC keypairs server-side via `pki/issue` today.

use std::net::IpAddr;

use base64::{engine::general_purpose::STANDARD, Engine};
use x509_parser::{
    extensions::{GeneralName, ParsedExtension},
    prelude::FromDer,
};

use crate::errors::RvError;

/// What a parsed CSR yields to the cert-building path. `spki_der` is the
/// full SubjectPublicKeyInfo DER (algorithm + key); we hand it straight to
/// `rcgen::SubjectPublicKeyInfo::from_der`.
#[derive(Debug, Clone)]
pub struct ParsedCsr {
    pub subject_dn: String,
    pub common_name: Option<String>,
    pub spki_der: Vec<u8>,
    pub requested_dns_sans: Vec<String>,
    pub requested_ip_sans: Vec<IpAddr>,
}

/// Parse a CSR, verify its self-signature, and extract the bits the cert
/// builders need. Failure modes are deliberately distinct so the caller can
/// give the operator a useful error:
///
/// - `ErrPkiPemBundleInvalid` — couldn't decode PEM / DER.
/// - `ErrPkiCertChainIncorrect` — CSR signature did not verify against its
///   own public key. This is the primary defence against accepting a CSR
///   forged by someone who does not actually hold the private key.
/// - `ErrPkiKeyTypeInvalid` — public key algorithm is one we cannot
///   reconstruct via `rcgen::SubjectPublicKeyInfo::from_der`.
pub fn parse_and_verify(pem_or_der: &str) -> Result<ParsedCsr, RvError> {
    let der = decode_pem_or_der(pem_or_der)?;
    let (rest, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(&der)
        .map_err(|_| RvError::ErrPkiPemBundleInvalid)?;
    if !rest.is_empty() {
        return Err(RvError::ErrPkiPemBundleInvalid);
    }

    // Self-signature check: the CSR is signed by the private key whose
    // public counterpart is in `subject_pki`. A failure here means we'd be
    // issuing a cert for a key the requester may not actually hold.
    csr.verify_signature().map_err(|e| {
        log::warn!("pki/csr: CSR self-signature failed verification: {e:?}");
        RvError::ErrPkiCertChainIncorrect
    })?;

    let info = &csr.certification_request_info;

    let subject_dn = info.subject.to_string();
    let common_name = extract_common_name(&info.subject);

    let spki_der = info.subject_pki.raw.to_vec();

    let (dns, ips) = extract_san_request(&csr);

    Ok(ParsedCsr { subject_dn, common_name, spki_der, requested_dns_sans: dns, requested_ip_sans: ips })
}

fn extract_common_name(subject: &x509_parser::x509::X509Name<'_>) -> Option<String> {
    subject
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string())
}

/// Walk the CSR's `extensionRequest` attribute looking for SubjectAltName.
/// CSRs frequently put their requested SANs there (per RFC 2986 §4.1).
fn extract_san_request(
    csr: &x509_parser::certification_request::X509CertificationRequest<'_>,
) -> (Vec<String>, Vec<IpAddr>) {
    let mut dns = Vec::new();
    let mut ips = Vec::new();
    if let Some(exts) = csr.requested_extensions() {
        for ext in exts {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                for gn in &san.general_names {
                    match gn {
                        GeneralName::DNSName(d) => dns.push(d.to_string()),
                        GeneralName::IPAddress(bytes) => {
                            if let Some(ip) = ip_from_bytes(bytes) {
                                ips.push(ip);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    (dns, ips)
}

fn ip_from_bytes(b: &[u8]) -> Option<IpAddr> {
    match b.len() {
        4 => {
            let mut a = [0u8; 4];
            a.copy_from_slice(b);
            Some(IpAddr::from(a))
        }
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            Some(IpAddr::from(a))
        }
        _ => None,
    }
}

/// Accepts either a PEM "CERTIFICATE REQUEST" / "NEW CERTIFICATE REQUEST"
/// block or a raw DER blob (base64-decoded). Returns DER bytes.
pub fn decode_pem_or_der(input: &str) -> Result<Vec<u8>, RvError> {
    let trimmed = input.trim();
    if trimmed.starts_with("-----BEGIN") {
        let mut in_block = false;
        let mut b64 = String::new();
        for line in trimmed.lines() {
            if line.starts_with("-----BEGIN") {
                in_block = true;
                continue;
            }
            if line.starts_with("-----END") {
                break;
            }
            if in_block {
                b64.push_str(line.trim());
            }
        }
        STANDARD.decode(b64.as_bytes()).map_err(|_| RvError::ErrPkiPemBundleInvalid)
    } else {
        // Try treating as base64 first (Vault clients sometimes send the
        // base64 body without armour); fall back to raw DER bytes.
        if let Ok(bytes) = STANDARD.decode(trimmed.as_bytes()) {
            Ok(bytes)
        } else {
            Ok(input.as_bytes().to_vec())
        }
    }
}
