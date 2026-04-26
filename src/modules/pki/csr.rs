//! PKCS#10 CSR parsing for `pki/sign/:role`, `pki/sign-verbatim`, and
//! `pki/root/sign-intermediate` (Phase 5 + 5.1).
//!
//! `rcgen` 0.14 does not expose CSR parsing publicly, so this module sits
//! between `x509-parser` (for the structural parse) and either
//! `rcgen::SubjectPublicKeyInfo::from_der` (classical, fed to
//! `params.signed_by`) or `fips204` (PQC, fed to the manual
//! [`super::x509_pqc`] builder). The result is that downstream cert
//! handlers see a uniform [`ParsedCsr`] regardless of who generated the
//! keypair or which algorithm class it belongs to.
//!
//! **Phase 5.1 closes the gap that PQC roles could `issue` but not
//! `sign`.** ML-DSA-44 / 65 / 87 CSRs are now recognised: the CSR's
//! self-signature is verified directly via `fips204` (since x509-parser's
//! `verify_signature()` only knows ring/aws_lc_rs algorithms and would
//! reject an ML-DSA CSR even with the `verify` feature on), and the
//! parsed result carries the algorithm class + raw public key bytes the
//! PQC builder needs.

use std::net::IpAddr;

use base64::{engine::general_purpose::STANDARD, Engine};
use bv_crypto::{ML_DSA_44_PUBLIC_KEY_LEN, ML_DSA_44_SIGNATURE_LEN, ML_DSA_65_PUBLIC_KEY_LEN,
                ML_DSA_65_SIGNATURE_LEN, ML_DSA_87_PUBLIC_KEY_LEN, ML_DSA_87_SIGNATURE_LEN};
use fips204::{ml_dsa_44, ml_dsa_65, ml_dsa_87, traits::{SerDes, Verifier}};
use x509_parser::{
    der_parser::asn1_rs::oid,
    extensions::{GeneralName, ParsedExtension},
    prelude::FromDer,
};

use super::pqc::MlDsaLevel;
use crate::errors::RvError;

/// Algorithm class recognised in the CSR's SubjectPublicKeyInfo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsrAlgClass {
    Classical,
    MlDsa(MlDsaLevel),
}

/// What a parsed CSR yields to the cert-building path.
///
/// - `spki_der` — full SubjectPublicKeyInfo DER (algorithm + key); used by
///   the classical path through `rcgen::SubjectPublicKeyInfo::from_der`.
/// - `raw_public_key` — bare public-key bytes (the BIT STRING contents of
///   the SPKI). The PQC builder embeds these directly into a new
///   `SubjectPublicKeyInfo` it constructs via `x509-cert`.
/// - `algorithm_class` — drives dispatch in `path_issue::sign_csr_*`
///   between the rcgen and `x509_pqc` builders.
#[derive(Debug, Clone)]
pub struct ParsedCsr {
    pub subject_dn: String,
    pub common_name: Option<String>,
    pub spki_der: Vec<u8>,
    pub raw_public_key: Vec<u8>,
    pub algorithm_class: CsrAlgClass,
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

    let info = &csr.certification_request_info;
    let alg_class = classify_alg(&info.subject_pki.algorithm.algorithm);

    // Self-signature check. Failure modes:
    //   - Classical → x509-parser's verify_signature (ring under the hood)
    //   - PQC      → fips204 directly; x509-parser doesn't know ML-DSA
    //                without aws_lc_rs_unstable (which we forbid).
    // Either way: a failure means we'd be issuing a cert for a key the
    // requester may not actually hold, so reject hard.
    match alg_class {
        CsrAlgClass::Classical => {
            csr.verify_signature().map_err(|e| {
                log::warn!("pki/csr: classical CSR self-signature failed verification: {e:?}");
                RvError::ErrPkiCertChainIncorrect
            })?;
        }
        CsrAlgClass::MlDsa(level) => verify_pqc_csr(&csr, level)?,
    }

    let subject_dn = info.subject.to_string();
    let common_name = extract_common_name(&info.subject);
    let spki_der = info.subject_pki.raw.to_vec();
    let raw_public_key = info.subject_pki.subject_public_key.data.to_vec();
    let (dns, ips) = extract_san_request(&csr);

    Ok(ParsedCsr {
        subject_dn,
        common_name,
        spki_der,
        raw_public_key,
        algorithm_class: alg_class,
        requested_dns_sans: dns,
        requested_ip_sans: ips,
    })
}

/// Match the SPKI algorithm OID against the three ML-DSA security levels
/// (IETF lamps draft `2.16.840.1.101.3.4.3.{17,18,19}`); anything else is
/// assumed classical and routed through x509-parser's verifier.
fn classify_alg(alg_oid: &x509_parser::der_parser::asn1_rs::Oid) -> CsrAlgClass {
    let ml_dsa_44_oid = oid!(2.16.840 .1 .101 .3 .4 .3 .17);
    let ml_dsa_65_oid = oid!(2.16.840 .1 .101 .3 .4 .3 .18);
    let ml_dsa_87_oid = oid!(2.16.840 .1 .101 .3 .4 .3 .19);
    if *alg_oid == ml_dsa_44_oid {
        CsrAlgClass::MlDsa(MlDsaLevel::L44)
    } else if *alg_oid == ml_dsa_65_oid {
        CsrAlgClass::MlDsa(MlDsaLevel::L65)
    } else if *alg_oid == ml_dsa_87_oid {
        CsrAlgClass::MlDsa(MlDsaLevel::L87)
    } else {
        CsrAlgClass::Classical
    }
}

/// Verify an ML-DSA CSR's self-signature with `fips204`. The bytes that
/// were signed are `certification_request_info.raw` — the DER-encoded
/// `CertificationRequestInfo` SEQUENCE the requester computed before
/// signing.
fn verify_pqc_csr(
    csr: &x509_parser::certification_request::X509CertificationRequest<'_>,
    level: MlDsaLevel,
) -> Result<(), RvError> {
    // x509-parser's BIT STRING `data` is a `Cow<[u8]>`; deref to a slice.
    let pk_bytes: &[u8] = &csr.certification_request_info.subject_pki.subject_public_key.data;
    let sig_bytes: &[u8] = &csr.signature_value.data;
    let cri_bytes: &[u8] = csr.certification_request_info.raw;

    let ok = match level {
        MlDsaLevel::L44 => verify_with::<{ ML_DSA_44_PUBLIC_KEY_LEN }, { ML_DSA_44_SIGNATURE_LEN }, _, _>(
            pk_bytes,
            sig_bytes,
            cri_bytes,
            ml_dsa_44::PublicKey::try_from_bytes,
            |pk, msg, sig| pk.verify(msg, sig, &[]),
        ),
        MlDsaLevel::L65 => verify_with::<{ ML_DSA_65_PUBLIC_KEY_LEN }, { ML_DSA_65_SIGNATURE_LEN }, _, _>(
            pk_bytes,
            sig_bytes,
            cri_bytes,
            ml_dsa_65::PublicKey::try_from_bytes,
            |pk, msg, sig| pk.verify(msg, sig, &[]),
        ),
        MlDsaLevel::L87 => verify_with::<{ ML_DSA_87_PUBLIC_KEY_LEN }, { ML_DSA_87_SIGNATURE_LEN }, _, _>(
            pk_bytes,
            sig_bytes,
            cri_bytes,
            ml_dsa_87::PublicKey::try_from_bytes,
            |pk, msg, sig| pk.verify(msg, sig, &[]),
        ),
    };
    if ok {
        Ok(())
    } else {
        log::warn!("pki/csr: ML-DSA CSR self-signature failed verification");
        Err(RvError::ErrPkiCertChainIncorrect)
    }
}

/// Generic helper to keep the three ML-DSA branches readable. It does the
/// length checks, builds the typed PublicKey, and runs `verify`.
fn verify_with<const PK: usize, const SIG: usize, P, V>(
    pk_bytes: &[u8],
    sig_bytes: &[u8],
    msg: &[u8],
    from_bytes: impl FnOnce([u8; PK]) -> Result<P, &'static str>,
    verify: V,
) -> bool
where
    V: FnOnce(&P, &[u8], &[u8; SIG]) -> bool,
{
    let pk_arr: [u8; PK] = match pk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_arr: [u8; SIG] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let pk = match from_bytes(pk_arr) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    verify(&pk, msg, &sig_arr)
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
