//! X.509 builders for composite (hybrid) signatures — Phase 3 preview.
//!
//! Mirrors [`super::x509_pqc`] in shape (manual TBSCertificate / TBSCertList
//! DER assembly via `x509-cert` + `der`), but the SPKI's `subjectPublicKey`
//! BIT STRING wraps the composite SPKI bytes (see
//! [`CompositeSigner::composite_public_key_der`]) and the outer cert
//! `signatureValue` BIT STRING wraps the composite signature bytes.
//!
//! Most of the helper plumbing (DN builder, validity, SAN/EKU extensions,
//! cert parsing) is pulled in from `x509_pqc.rs` via `pub(super)`-elevated
//! helpers — we don't duplicate the logic, only the algorithm-identifier and
//! signing seam differ.

use std::time::Duration;

use const_oid::AssociatedOid;
use x509_cert::{
    certificate::{CertificateInner, TbsCertificateInner, Version},
    crl::{CertificateList, RevokedCert, TbsCertList},
    der::{
        asn1::{BitString, OctetString},
        Encode,
    },
    ext::{
        pkix::{BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier},
        Extension,
    },
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    Certificate,
};

use super::{
    composite::{CompositeSigner, OID_COMPOSITE_MLDSA65_ECDSAP256},
    path_roles::RoleEntry,
    x509::{RevokedEntry, SubjectInput},
    x509_pqc,
};
use crate::errors::RvError;

const CRL_NUMBER_OID: const_oid::ObjectIdentifier = const_oid::ObjectIdentifier::new_unwrap("2.5.29.20");

fn composite_alg_id() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned { oid: OID_COMPOSITE_MLDSA65_ECDSAP256, parameters: None }
}

fn composite_spki(signer: &CompositeSigner) -> Result<SubjectPublicKeyInfoOwned, RvError> {
    let pk_der = signer.composite_public_key_der()?;
    Ok(SubjectPublicKeyInfoOwned {
        algorithm: composite_alg_id(),
        subject_public_key: BitString::from_bytes(&pk_der).map_err(x509_pqc::der_err)?,
    })
}

fn sign_tbs<T: Encode>(tbs: &T, signer: &CompositeSigner) -> Result<BitString, RvError> {
    let tbs_der = tbs.to_der().map_err(x509_pqc::der_err)?;
    let composite_sig = signer.sign(&tbs_der)?;
    BitString::from_bytes(&composite_sig).map_err(x509_pqc::der_err)
}

/// Build a self-signed composite root CA. Returns `(PEM, serial bytes)`.
pub fn build_root_ca(
    common_name: &str,
    organization: &str,
    ttl: Duration,
    signer: &CompositeSigner,
) -> Result<(String, Vec<u8>), RvError> {
    let alg_id = composite_alg_id();
    let spki = composite_spki(signer)?;

    let dn = x509_pqc::build_dn_cn_o(common_name, organization)?;
    let validity = x509_pqc::build_validity(Duration::from_secs(30), ttl)?;
    let serial_bytes = super::x509::random_serial_bytes();
    let serial =
        SerialNumber::<x509_cert::certificate::Rfc5280>::new(&serial_bytes).map_err(x509_pqc::der_err)?;

    // Identify the SKI off the *composite* public key bytes so leaves
    // chained against this root carry a matching AKI.
    let ski_input = signer.composite_public_key_der()?;
    let ski = x509_pqc::subject_key_identifier(&ski_input)?;
    let extensions = vec![
        x509_pqc::encode_ext(true, &BasicConstraints { ca: true, path_len_constraint: None })?,
        x509_pqc::encode_ext(
            true,
            &KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign | KeyUsages::DigitalSignature),
        )?,
        x509_pqc::encode_ext_octets(SubjectKeyIdentifier::OID, false, ski)?,
    ];

    let tbs = TbsCertificateInner {
        version: Version::V3,
        serial_number: serial,
        signature: alg_id.clone(),
        issuer: dn.clone(),
        validity,
        subject: dn,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };
    let signature = sign_tbs(&tbs, signer)?;
    let cert = CertificateInner { tbs_certificate: tbs, signature_algorithm: alg_id, signature };
    Ok((pem_encode("CERTIFICATE", &cert.to_der().map_err(x509_pqc::der_err)?), serial_bytes))
}

/// Build a leaf cert under a composite CA. Returns `(PEM, serial bytes)`.
pub fn build_leaf(
    role: &RoleEntry,
    subject: &SubjectInput,
    ttl: Duration,
    leaf_signer: &CompositeSigner,
    ca_signer: &CompositeSigner,
    ca_cert_pem: &str,
) -> Result<(String, Vec<u8>), RvError> {
    let alg_id = composite_alg_id();
    let leaf_spki = composite_spki(leaf_signer)?;

    let ca_cert = parse_cert_pem(ca_cert_pem)?;
    let issuer = ca_cert.tbs_certificate.subject.clone();
    let ca_ski = x509_pqc::extract_ski(&ca_cert)?;

    let subject_dn = x509_pqc::build_leaf_dn(role, &subject.common_name)?;
    let validity = x509_pqc::build_validity(role.not_before_duration, ttl)?;
    let serial_bytes = super::x509::random_serial_bytes();
    let serial =
        SerialNumber::<x509_cert::certificate::Rfc5280>::new(&serial_bytes).map_err(x509_pqc::der_err)?;

    let leaf_pk_bytes = leaf_signer.composite_public_key_der()?;
    let mut extensions = vec![
        x509_pqc::encode_ext(true, &BasicConstraints { ca: false, path_len_constraint: None })?,
        x509_pqc::encode_ext(
            true,
            &KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment | KeyUsages::KeyAgreement),
        )?,
        x509_pqc::encode_ext_octets(
            SubjectKeyIdentifier::OID,
            false,
            x509_pqc::subject_key_identifier(&leaf_pk_bytes)?,
        )?,
        x509_pqc::encode_aki(&ca_ski)?,
    ];
    if let Some(eku) = x509_pqc::build_extended_key_usage(role)? {
        extensions.push(eku);
    }
    if let Some(san) = x509_pqc::build_subject_alt_name(subject)? {
        extensions.push(san);
    }

    let tbs = TbsCertificateInner {
        version: Version::V3,
        serial_number: serial,
        signature: alg_id.clone(),
        issuer,
        validity,
        subject: subject_dn,
        subject_public_key_info: leaf_spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };
    let signature = sign_tbs(&tbs, ca_signer)?;
    let cert = CertificateInner { tbs_certificate: tbs, signature_algorithm: alg_id, signature };
    Ok((pem_encode("CERTIFICATE", &cert.to_der().map_err(x509_pqc::der_err)?), serial_bytes))
}

/// Build a CRL signed by a composite CA.
pub fn build_crl(
    crl_number: u64,
    next_update_secs: u64,
    revoked: &[RevokedEntry],
    ca_signer: &CompositeSigner,
    ca_cert_pem: &str,
) -> Result<String, RvError> {
    let alg_id = composite_alg_id();
    let ca_cert = parse_cert_pem(ca_cert_pem)?;
    let issuer = ca_cert.tbs_certificate.subject.clone();

    let now = std::time::SystemTime::now();
    let next = now + Duration::from_secs(next_update_secs.max(60));

    let revoked_certs: Result<Vec<RevokedCert>, RvError> = revoked
        .iter()
        .map(|r| {
            let serial = SerialNumber::new(&r.serial).map_err(x509_pqc::der_err)?;
            let revoked_at = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(r.revoked_at_unix);
            Ok(RevokedCert {
                serial_number: serial,
                revocation_date: x509_pqc::time_from_system(revoked_at)?,
                crl_entry_extensions: None,
            })
        })
        .collect();
    let revoked_certs = revoked_certs?;

    let crl_number_ext = Extension {
        extn_id: CRL_NUMBER_OID,
        critical: false,
        extn_value: OctetString::new(
            SerialNumber::<x509_cert::certificate::Rfc5280>::from(crl_number)
                .to_der()
                .map_err(x509_pqc::der_err)?,
        )
        .map_err(x509_pqc::der_err)?,
    };

    let tbs = TbsCertList {
        version: Version::V2,
        signature: alg_id.clone(),
        issuer,
        this_update: x509_pqc::time_from_system(now)?,
        next_update: Some(x509_pqc::time_from_system(next)?),
        revoked_certificates: if revoked_certs.is_empty() { None } else { Some(revoked_certs) },
        crl_extensions: Some(vec![crl_number_ext]),
    };
    let signature = sign_tbs(&tbs, ca_signer)?;
    let crl = CertificateList { tbs_cert_list: tbs, signature_algorithm: alg_id, signature };
    Ok(pem_encode("X509 CRL", &crl.to_der().map_err(x509_pqc::der_err)?))
}

// ── tiny duplicates of two PEM helpers (we don't import them from
// x509_pqc to keep the call surface clean — they're 5 lines each) ────────

fn parse_cert_pem(pem: &str) -> Result<Certificate, RvError> {
    use x509_cert::der::Decode;
    let der = x509_pqc::pem_decode_first(pem)?;
    Certificate::from_der(&der).map_err(x509_pqc::der_err)
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    x509_pqc::pem_encode(label, der)
}
