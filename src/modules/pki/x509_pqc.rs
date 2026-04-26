//! Pure-Rust DER assembly for ML-DSA certificates and CRLs.
//!
//! Phase 2 sidesteps `rcgen` for PQC because rcgen 0.14 only ships ML-DSA
//! support behind `aws_lc_rs_unstable` (a forbidden C-linked dep). Here we
//! build [`x509_cert::Certificate`] / [`x509_cert::crl::CertificateList`]
//! directly with `x509-cert` + `der`, sign the DER-encoded TBS bytes with
//! [`MlDsaSigner`], and stuff the signature into the BIT STRING.
//!
//! The extension set mirrors what the classical (rcgen-driven) Phase 1 path
//! already emits, so a chain switching between PQC and classical issuers
//! still presents the same ext profile to verifiers (BasicConstraints, KU,
//! EKU, SAN, SubjectKeyIdentifier, AuthorityKeyIdentifier). What's deferred
//! to Phase 2.1: AIA / CRL DP / Name Constraints.

use std::{
    net::IpAddr,
    str::FromStr,
    time::{Duration, SystemTime},
};

use const_oid::{AssociatedOid, ObjectIdentifier};
use sha2::{Digest, Sha256};
use x509_cert::{
    certificate::{CertificateInner, TbsCertificateInner, Version},
    crl::{CertificateList, RevokedCert, TbsCertList},
    der::{
        asn1::{BitString, GeneralizedTime, Ia5String, OctetString, UtcTime},
        Decode, Encode,
    },
    ext::{
        pkix::{
            name::{GeneralName, GeneralNames},
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
            SubjectAltName, SubjectKeyIdentifier,
        },
        Extension,
    },
    name::Name,
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    time::{Time, Validity},
    Certificate,
};

use super::{
    path_roles::RoleEntry,
    pqc::MlDsaSigner,
    x509::{RevokedEntry, SubjectInput},
};
use crate::errors::RvError;

/// Build a self-signed ML-DSA root CA cert and return `(PEM, serial bytes)`.
pub fn build_root_ca(
    common_name: &str,
    organization: &str,
    ttl: Duration,
    signer: &MlDsaSigner,
) -> Result<(String, Vec<u8>), RvError> {
    let alg_id = AlgorithmIdentifierOwned { oid: signer.level().oid(), parameters: None };
    let spki = SubjectPublicKeyInfoOwned {
        algorithm: alg_id.clone(),
        subject_public_key: BitString::from_bytes(signer.public_key()).map_err(der_err)?,
    };

    let dn = build_dn_cn_o(common_name, organization)?;
    let validity = build_validity(Duration::from_secs(30), ttl)?;
    let serial_bytes = super::x509::random_serial_bytes();
    let serial = SerialNumber::new(&serial_bytes).map_err(der_err)?;

    let ski = subject_key_identifier(signer.public_key())?;
    let extensions = vec![
        encode_ext(true, &BasicConstraints { ca: true, path_len_constraint: None })?,
        encode_ext(true, &KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign | KeyUsages::DigitalSignature))?,
        encode_ext_octets(SubjectKeyIdentifier::OID, false, ski.clone())?,
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

    let cert = sign_certificate(tbs, signer, alg_id)?;
    Ok((pem_encode("CERTIFICATE", &cert.to_der().map_err(der_err)?), serial_bytes))
}

/// Build a leaf cert signed by an ML-DSA CA.
pub fn build_leaf(
    role: &RoleEntry,
    subject: &SubjectInput,
    ttl: Duration,
    leaf_signer: &MlDsaSigner,
    ca_signer: &MlDsaSigner,
    ca_cert_pem: &str,
) -> Result<(String, Vec<u8>), RvError> {
    let leaf_alg = AlgorithmIdentifierOwned { oid: leaf_signer.level().oid(), parameters: None };
    let ca_alg = AlgorithmIdentifierOwned { oid: ca_signer.level().oid(), parameters: None };

    let spki = SubjectPublicKeyInfoOwned {
        algorithm: leaf_alg.clone(),
        subject_public_key: BitString::from_bytes(leaf_signer.public_key()).map_err(der_err)?,
    };

    // Reload the CA cert so we can pull issuer DN + AKI from it.
    let ca_cert = parse_cert_pem(ca_cert_pem)?;
    let issuer = ca_cert.tbs_certificate.subject.clone();
    let ca_ski = extract_ski(&ca_cert)?;

    let subject_dn = build_leaf_dn(role, &subject.common_name)?;
    let validity = build_validity(role.not_before_duration, ttl)?;
    let serial_bytes = super::x509::random_serial_bytes();
    let serial = SerialNumber::new(&serial_bytes).map_err(der_err)?;

    let mut extensions = vec![
        encode_ext(true, &BasicConstraints { ca: false, path_len_constraint: None })?,
        encode_ext(
            true,
            &KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment | KeyUsages::KeyAgreement),
        )?,
        encode_ext_octets(SubjectKeyIdentifier::OID, false, subject_key_identifier(leaf_signer.public_key())?)?,
        encode_aki(&ca_ski)?,
    ];
    if let Some(eku) = build_extended_key_usage(role)? {
        extensions.push(eku);
    }
    if let Some(san) = build_subject_alt_name(subject)? {
        extensions.push(san);
    }

    let tbs = TbsCertificateInner {
        version: Version::V3,
        serial_number: serial,
        signature: ca_alg.clone(),
        issuer,
        validity,
        subject: subject_dn,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };

    let cert = sign_certificate(tbs, ca_signer, ca_alg)?;
    Ok((pem_encode("CERTIFICATE", &cert.to_der().map_err(der_err)?), serial_bytes))
}

/// Build a CRL signed by an ML-DSA CA.
pub fn build_crl(
    crl_number: u64,
    next_update_secs: u64,
    revoked: &[RevokedEntry],
    ca_signer: &MlDsaSigner,
    ca_cert_pem: &str,
) -> Result<String, RvError> {
    let alg_id = AlgorithmIdentifierOwned { oid: ca_signer.level().oid(), parameters: None };
    let ca_cert = parse_cert_pem(ca_cert_pem)?;
    let issuer = ca_cert.tbs_certificate.subject.clone();

    let now = SystemTime::now();
    let next = now + Duration::from_secs(next_update_secs.max(60));
    let revoked_certs: Result<Vec<RevokedCert>, RvError> = revoked
        .iter()
        .map(|r| {
            let serial = SerialNumber::new(&r.serial).map_err(der_err)?;
            let revoked_at = SystemTime::UNIX_EPOCH + Duration::from_secs(r.revoked_at_unix);
            Ok(RevokedCert {
                serial_number: serial,
                revocation_date: time_from_system(revoked_at)?,
                crl_entry_extensions: None,
            })
        })
        .collect();
    let revoked_certs = revoked_certs?;

    // crlNumber extension (OID 2.5.29.20) — monotonic counter required by
    // verifiers to detect rollback.
    let crl_number_oid: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.20");
    let crl_number_ext = Extension {
        extn_id: crl_number_oid,
        critical: false,
        extn_value: OctetString::new(SerialNumber::<x509_cert::certificate::Rfc5280>::from(crl_number).to_der().map_err(der_err)?)
            .map_err(der_err)?,
    };

    let tbs = TbsCertList {
        version: Version::V2,
        signature: alg_id.clone(),
        issuer,
        this_update: time_from_system(now)?,
        next_update: Some(time_from_system(next)?),
        revoked_certificates: if revoked_certs.is_empty() { None } else { Some(revoked_certs) },
        crl_extensions: Some(vec![crl_number_ext]),
    };

    let tbs_der = tbs.to_der().map_err(der_err)?;
    let signature = ca_signer.sign(&tbs_der)?;
    let crl = CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: alg_id,
        signature: BitString::from_bytes(&signature).map_err(der_err)?,
    };
    Ok(pem_encode("X509 CRL", &crl.to_der().map_err(der_err)?))
}

// ── helpers ────────────────────────────────────────────────────────────

fn sign_certificate(
    tbs: TbsCertificateInner,
    signer: &MlDsaSigner,
    alg_id: AlgorithmIdentifierOwned,
) -> Result<Certificate, RvError> {
    let tbs_der = tbs.to_der().map_err(der_err)?;
    let signature = signer.sign(&tbs_der)?;
    Ok(CertificateInner {
        tbs_certificate: tbs,
        signature_algorithm: alg_id,
        signature: BitString::from_bytes(&signature).map_err(der_err)?,
    })
}

fn build_dn_cn_o(common_name: &str, organization: &str) -> Result<Name, RvError> {
    let s = if organization.is_empty() {
        format!("CN={}", common_name)
    } else {
        format!("CN={},O={}", common_name, organization)
    };
    Name::from_str(&s).map_err(der_err)
}

fn build_leaf_dn(role: &RoleEntry, cn: &str) -> Result<Name, RvError> {
    let mut parts: Vec<String> = Vec::new();
    if !cn.is_empty() {
        parts.push(format!("CN={cn}"));
    }
    if !role.organization.is_empty() {
        parts.push(format!("O={}", role.organization));
    }
    if !role.ou.is_empty() {
        parts.push(format!("OU={}", role.ou));
    }
    if !role.country.is_empty() {
        parts.push(format!("C={}", role.country));
    }
    if !role.locality.is_empty() {
        parts.push(format!("L={}", role.locality));
    }
    if !role.province.is_empty() {
        parts.push(format!("ST={}", role.province));
    }
    Name::from_str(&parts.join(",")).map_err(der_err)
}

fn build_validity(backdate: Duration, lifetime: Duration) -> Result<Validity, RvError> {
    let now = SystemTime::now();
    let start = now - backdate;
    let end = now + lifetime;
    Ok(Validity { not_before: time_from_system(start)?, not_after: time_from_system(end)? })
}

/// RFC 5280 §4.1.2.5: dates ≤ 2049 use UTCTime, dates ≥ 2050 use
/// GeneralizedTime. `Time::try_from(SystemTime)` only emits UTCTime, which
/// silently truncates 4-digit years; we steer the choice manually.
fn time_from_system(t: SystemTime) -> Result<Time, RvError> {
    let dur = t.duration_since(SystemTime::UNIX_EPOCH).map_err(|_| RvError::ErrPkiInternal)?;
    let utc = UtcTime::from_unix_duration(dur);
    match utc {
        Ok(u) => Ok(Time::UtcTime(u)),
        Err(_) => {
            let g = GeneralizedTime::from_unix_duration(dur).map_err(der_err)?;
            Ok(Time::GeneralTime(g))
        }
    }
}

fn subject_key_identifier(public_key: &[u8]) -> Result<OctetString, RvError> {
    let mut h = Sha256::new();
    h.update(public_key);
    let digest = h.finalize();
    // RFC 7093 method 1: 160-bit truncated SHA-256.
    OctetString::new(digest[..20].to_vec()).map_err(der_err)
}

fn encode_aki(ca_ski: &OctetString) -> Result<Extension, RvError> {
    let aki = AuthorityKeyIdentifier {
        key_identifier: Some(ca_ski.clone()),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };
    encode_ext(false, &aki)
}

fn encode_ext<E: Encode + const_oid::AssociatedOid>(critical: bool, value: &E) -> Result<Extension, RvError> {
    Ok(Extension {
        extn_id: E::OID,
        critical,
        extn_value: OctetString::new(value.to_der().map_err(der_err)?).map_err(der_err)?,
    })
}

fn encode_ext_octets(oid: ObjectIdentifier, critical: bool, value: OctetString) -> Result<Extension, RvError> {
    let der = value.to_der().map_err(der_err)?;
    Ok(Extension { extn_id: oid, critical, extn_value: OctetString::new(der).map_err(der_err)? })
}

fn build_extended_key_usage(role: &RoleEntry) -> Result<Option<Extension>, RvError> {
    let server_auth: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
    let client_auth: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");

    let mut oids: Vec<ObjectIdentifier> = Vec::new();
    if role.server_flag {
        oids.push(server_auth);
    }
    if role.client_flag {
        oids.push(client_auth);
    }
    if oids.is_empty() {
        return Ok(None);
    }
    Ok(Some(encode_ext(false, &ExtendedKeyUsage(oids))?))
}

fn build_subject_alt_name(subject: &SubjectInput) -> Result<Option<Extension>, RvError> {
    if subject.alt_names.is_empty() && subject.ip_sans.is_empty() {
        return Ok(None);
    }
    let mut names: GeneralNames = Vec::new();
    for d in &subject.alt_names {
        let ia5 = Ia5String::new(d.as_str()).map_err(der_err)?;
        names.push(GeneralName::DnsName(ia5));
    }
    for ip in &subject.ip_sans {
        let bytes = match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        names.push(GeneralName::IpAddress(OctetString::new(bytes).map_err(der_err)?));
    }
    Ok(Some(encode_ext(false, &SubjectAltName(names))?))
}

fn parse_cert_pem(pem: &str) -> Result<Certificate, RvError> {
    let der = pem_decode_first(pem)?;
    Certificate::from_der(&der).map_err(der_err)
}

fn extract_ski(cert: &Certificate) -> Result<OctetString, RvError> {
    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts {
            if ext.extn_id == SubjectKeyIdentifier::OID {
                let ski = SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes()).map_err(der_err)?;
                return Ok(ski.0);
            }
        }
    }
    // Fall back to a SHA-256 of the SPKI bit string. Matches what we emit for
    // self-signed roots that pre-date this code, so we never fail to build an
    // AKI for a chained leaf.
    let pk_der = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    subject_key_identifier(pk_der)
}

fn pem_decode_first(pem: &str) -> Result<Vec<u8>, RvError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mut in_block = false;
    let mut b64 = String::new();
    for line in pem.lines() {
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
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let body = STANDARD.encode(der);
    let mut out = String::with_capacity(body.len() + 64);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

fn der_err(e: impl std::fmt::Debug) -> RvError {
    log::error!("pki/x509-pqc: DER error: {e:?}");
    RvError::ErrPkiInternal
}
