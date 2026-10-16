//! Pure-Rust DER assembly for ML-DSA certificates and CRLs.
//!
//! Phase 2 sidesteps `rcgen` for PQC because rcgen 0.14 only ships ML-DSA
//! support behind `aws_lc_rs_unstable` (a forbidden C-linked dep). Here we
//! build [`x509_cert::Certificate`] / [`x509_cert::crl::CertificateList`]
//! directly with `x509-cert` + `der`, sign the DER-encoded TBS bytes with
//! [`MlDsaSigner`], and stuff the signature into the BIT STRING.
//!
//! The extension set mirrors what the classical Phase 1 path
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
    attr::AttributeTypeAndValue,
    certificate::{CertificateInner, TbsCertificateInner, Version},
    crl::{CertificateList, RevokedCert, TbsCertList},
    der::{
        asn1::{Any, BitString, GeneralizedTime, Ia5String, OctetString, PrintableStringRef, SetOfVec, UtcTime},
        Decode, Encode, Tag,
    },
    ext::{
        pkix::{
            crl::dp::DistributionPoint,
            name::{DistributionPointName, GeneralName, GeneralNames},
            AuthorityKeyIdentifier, BasicConstraints, CrlDistributionPoints, ExtendedKeyUsage,
            KeyUsage, KeyUsages, SubjectAltName, SubjectKeyIdentifier,
        },
        Extension,
    },
    name::{Name, RdnSequence, RelativeDistinguishedName},
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    time::{Time, Validity},
    Certificate,
};

use super::{
    path_roles::RoleEntry,
    pqc::{MlDsaLevel, MlDsaSigner},
    x509::{IssuingCa, RevokedEntry, SubjectInput},
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
    urls: &super::x509::IssuanceUrls,
) -> Result<(String, Vec<u8>), RvError> {
    let leaf_alg = AlgorithmIdentifierOwned { oid: leaf_signer.level().oid(), parameters: None };
    let ca_alg = AlgorithmIdentifierOwned { oid: ca_signer.level().oid(), parameters: None };

    let spki = SubjectPublicKeyInfoOwned {
        algorithm: leaf_alg.clone(),
        subject_public_key: BitString::from_bytes(leaf_signer.public_key()).map_err(der_err)?,
    };

    let ca = load_ml_dsa_issuing_ca(ca_cert_pem, ca_signer)?;

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
    ];
    extensions.extend(ca.authority_key_identifier()?);
    if let Some(eku) = build_extended_key_usage(role)? {
        extensions.push(eku);
    }
    if let Some(san) = build_subject_alt_name(subject)? {
        extensions.push(san);
    }
    if let Some(sid) = build_ad_sid_extension(subject)? {
        extensions.push(sid);
    }
    if let Some(cdp) = build_crl_distribution_points(urls)? {
        extensions.push(cdp);
    }

    let tbs = TbsCertificateInner {
        version: Version::V3,
        serial_number: serial,
        signature: ca_alg.clone(),
        issuer: ca.name,
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

/// Build a leaf cert from a CSR-supplied ML-DSA public key, signed by an
/// ML-DSA CA. Mirrors [`super::x509::build_leaf_from_spki`] for the PQC
/// path: the leaf's public key comes from the CSR (the requester holds the
/// private key), and the CA signs the TBS.
pub fn build_leaf_from_pqc_spki(
    role: &RoleEntry,
    subject: &SubjectInput,
    ttl: Duration,
    leaf_pk_bytes: &[u8],
    leaf_level: MlDsaLevel,
    ca_signer: &MlDsaSigner,
    ca_cert_pem: &str,
    urls: &super::x509::IssuanceUrls,
) -> Result<(String, Vec<u8>), RvError> {
    let leaf_alg = AlgorithmIdentifierOwned { oid: leaf_level.oid(), parameters: None };
    let ca_alg = AlgorithmIdentifierOwned { oid: ca_signer.level().oid(), parameters: None };

    let spki = SubjectPublicKeyInfoOwned {
        algorithm: leaf_alg.clone(),
        subject_public_key: BitString::from_bytes(leaf_pk_bytes).map_err(der_err)?,
    };

    let ca = load_ml_dsa_issuing_ca(ca_cert_pem, ca_signer)?;

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
        encode_ext_octets(SubjectKeyIdentifier::OID, false, subject_key_identifier(leaf_pk_bytes)?)?,
    ];
    extensions.extend(ca.authority_key_identifier()?);
    if let Some(eku) = build_extended_key_usage(role)? {
        extensions.push(eku);
    }
    if let Some(san) = build_subject_alt_name(subject)? {
        extensions.push(san);
    }
    if let Some(sid) = build_ad_sid_extension(subject)? {
        extensions.push(sid);
    }
    if let Some(cdp) = build_crl_distribution_points(urls)? {
        extensions.push(cdp);
    }

    let tbs = TbsCertificateInner {
        version: Version::V3,
        serial_number: serial,
        signature: ca_alg.clone(),
        issuer: ca.name,
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

/// Build a CRL signed by an ML-DSA CA. Thin wrapper over
/// [`build_crl_with_alg`] that supplies the ML-DSA `AlgorithmIdentifier`
/// and routes signing through `MlDsaSigner::sign`.
pub fn build_crl(
    crl_number: u64,
    next_update_secs: u64,
    revoked: &[RevokedEntry],
    ca_signer: &MlDsaSigner,
    ca_cert_pem: &str,
) -> Result<String, RvError> {
    let alg_id = AlgorithmIdentifierOwned { oid: ca_signer.level().oid(), parameters: None };
    build_crl_with_alg(crl_number, next_update_secs, revoked, ca_cert_pem, alg_id, |tbs_der| {
        ca_signer.sign(tbs_der)
    })
}

/// Generic CRL assembly. Phase 5.4: the classical / PQC / composite paths
/// all share this helper instead of each maintaining its own near-copy
/// of the TBS-build + sign + wrap dance.
///
/// `alg_id` is the `AlgorithmIdentifier` the verifier expects on the
/// outer `signatureAlgorithm`; `sign(tbs_der)` produces the signature
/// bytes that go into the outer BIT STRING. Both paths previously
/// duplicated this body, including the `crlNumber` extension boilerplate
/// and the `parse_cert_pem` → issuer-DN extraction. Unifying them means
/// any future CRL-extension addition (CRL-DP, AKI, IDP) lands once.
pub(super) fn build_crl_with_alg<F>(
    crl_number: u64,
    next_update_secs: u64,
    revoked: &[RevokedEntry],
    ca_cert_pem: &str,
    alg_id: AlgorithmIdentifierOwned,
    sign: F,
) -> Result<String, RvError>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, RvError>,
{
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
        extn_value: OctetString::new(
            SerialNumber::<x509_cert::certificate::Rfc5280>::from(crl_number).to_der().map_err(der_err)?,
        )
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
    let signature = sign(&tbs_der)?;
    let crl = CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: alg_id,
        signature: BitString::from_bytes(&signature).map_err(der_err)?,
    };
    Ok(pem_encode("X509 CRL", &crl.to_der().map_err(der_err)?))
}

// ── helpers ────────────────────────────────────────────────────────────

/// Issuer name and AKI for a certificate `ca_signer` signs, through the
/// loader every issuing path shares, after checking the CA certificate
/// certifies the public key the CA's seed derives.
fn load_ml_dsa_issuing_ca(ca_cert_pem: &str, ca_signer: &MlDsaSigner) -> Result<IssuingCa, RvError> {
    ca_signer.ensure_public_key_matches_seed()?;
    let signing_key = SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned { oid: ca_signer.level().oid(), parameters: None },
        subject_public_key: BitString::from_bytes(ca_signer.public_key()).map_err(der_err)?,
    };
    super::x509::load_issuing_ca(ca_cert_pem, &signing_key)
}

pub(super) fn sign_certificate(
    tbs: TbsCertificateInner,
    signer: &MlDsaSigner,
    alg_id: AlgorithmIdentifierOwned,
) -> Result<Certificate, RvError> {
    assemble_certificate(tbs, alg_id, |tbs_der| signer.sign(tbs_der))
}

/// Sign `tbs` and wrap it into a certificate; the certificate counterpart
/// of [`build_crl_with_alg`], shared with classical issuance in
/// [`super::x509`]. `sign` gets exactly the DER embedded as
/// `tbsCertificate`; `alg_id` must equal `tbs.signature` (RFC 5280
/// §4.1.1.2), and a mismatch is a builder bug that fails closed.
pub(super) fn assemble_certificate<F>(
    tbs: TbsCertificateInner,
    alg_id: AlgorithmIdentifierOwned,
    sign: F,
) -> Result<Certificate, RvError>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, RvError>,
{
    if tbs.signature != alg_id {
        log::error!("pki/x509: TBS signature algorithm does not match the outer signatureAlgorithm");
        return Err(RvError::ErrPkiInternal);
    }
    let tbs_der = tbs.to_der().map_err(der_err)?;
    let signature = sign(&tbs_der)?;
    Ok(CertificateInner {
        tbs_certificate: tbs,
        signature_algorithm: alg_id,
        signature: BitString::from_bytes(&signature).map_err(der_err)?,
    })
}

pub(super) fn build_dn_cn_o(common_name: &str, organization: &str) -> Result<Name, RvError> {
    let s = if organization.is_empty() {
        format!("CN={}", common_name)
    } else {
        format!("CN={},O={}", common_name, organization)
    };
    Name::from_str(&s).map_err(der_err)
}

/// Leaf subject for ML-DSA and composite certificates: one single-valued RDN
/// per non-empty field, encoded ST, L, C, OU, O, CN (the order the RFC 4514
/// parse used here before produced, so issued subjects keep their bytes);
/// C is a PrintableString, the rest UTF8String. Values are taken literally:
/// that parse read `,` `+` `\` and a leading `#` as DN syntax, so a
/// requested CN such as `a.example.com,CN=b` added attributes.
pub(super) fn build_leaf_dn(role: &RoleEntry, cn: &str) -> Result<Name, RvError> {
    use super::x509::{
        ATTR_COMMON_NAME, ATTR_COUNTRY, ATTR_LOCALITY, ATTR_ORGANIZATION, ATTR_ORGANIZATIONAL_UNIT, ATTR_PROVINCE,
    };
    let fields = [
        (ATTR_PROVINCE, role.province.as_str()),
        (ATTR_LOCALITY, role.locality.as_str()),
        (ATTR_COUNTRY, role.country.as_str()),
        (ATTR_ORGANIZATIONAL_UNIT, role.ou.as_str()),
        (ATTR_ORGANIZATION, role.organization.as_str()),
        (ATTR_COMMON_NAME, cn),
    ];
    let mut rdns = Vec::with_capacity(fields.len());
    for (oid, value) in fields.into_iter().filter(|(_, value)| !value.is_empty()) {
        let tag = if oid == ATTR_COUNTRY {
            PrintableStringRef::new(value).map_err(|e| {
                RvError::ErrString(format!("pki: role country `{value}` is not a valid PrintableString ({e})"))
            })?;
            Tag::PrintableString
        } else {
            Tag::Utf8String
        };
        let atv = AttributeTypeAndValue { oid, value: Any::new(tag, value.as_bytes()).map_err(der_err)? };
        rdns.push(RelativeDistinguishedName(SetOfVec::try_from(vec![atv]).map_err(der_err)?));
    }
    if rdns.is_empty() {
        return Err(RvError::ErrString(
            "pki: the certificate subject would be empty; set a common_name or the role's subject fields".into(),
        ));
    }
    Ok(RdnSequence(rdns))
}

pub(super) fn build_validity(backdate: Duration, lifetime: Duration) -> Result<Validity, RvError> {
    let now = SystemTime::now();
    let start = now - backdate;
    let end = now + lifetime;
    Ok(Validity { not_before: time_from_system(start)?, not_after: time_from_system(end)? })
}

/// RFC 5280 §4.1.2.5: dates ≤ 2049 use UTCTime, dates ≥ 2050 use
/// GeneralizedTime. `Time::try_from(SystemTime)` only emits UTCTime, which
/// silently truncates 4-digit years; we steer the choice manually.
pub(super) fn time_from_system(t: SystemTime) -> Result<Time, RvError> {
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

pub(super) fn subject_key_identifier(public_key: &[u8]) -> Result<OctetString, RvError> {
    let mut h = Sha256::new();
    h.update(public_key);
    let digest = h.finalize();
    // RFC 7093 method 1: 160-bit truncated SHA-256.
    OctetString::new(digest[..20].to_vec()).map_err(der_err)
}

pub(super) fn encode_aki(ca_ski: &OctetString) -> Result<Extension, RvError> {
    let aki = AuthorityKeyIdentifier {
        key_identifier: Some(ca_ski.clone()),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };
    encode_ext(false, &aki)
}

pub(super) fn encode_ext<E: Encode + const_oid::AssociatedOid>(critical: bool, value: &E) -> Result<Extension, RvError> {
    Ok(Extension {
        extn_id: E::OID,
        critical,
        extn_value: OctetString::new(value.to_der().map_err(der_err)?).map_err(der_err)?,
    })
}

pub(super) fn encode_ext_octets(oid: ObjectIdentifier, critical: bool, value: OctetString) -> Result<Extension, RvError> {
    let der = value.to_der().map_err(der_err)?;
    Ok(Extension { extn_id: oid, critical, extn_value: OctetString::new(der).map_err(der_err)? })
}

pub(super) fn build_extended_key_usage(role: &RoleEntry) -> Result<Option<Extension>, RvError> {
    let server_auth: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
    let client_auth: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");

    let mut oids: Vec<ObjectIdentifier> = Vec::new();
    if role.server_flag {
        oids.push(server_auth);
    }
    if role.client_flag {
        oids.push(client_auth);
    }
    // Named + dotted entries from `ext_key_usage`, then the OID-only
    // `ext_key_usage_oids` channel. Mirrors the classical path's
    // `parse_ext_key_usages` so a role behaves identically whether it
    // runs on a classical or a PQC issuer.
    for extra in role.ext_key_usage.iter().chain(role.ext_key_usage_oids.iter()) {
        if let Some(oid) = resolve_ext_key_usage_oid(extra)? {
            if !oids.contains(&oid) {
                oids.push(oid);
            }
        }
    }
    if oids.is_empty() {
        return Ok(None);
    }
    Ok(Some(encode_ext(false, &ExtendedKeyUsage(oids))?))
}

/// Resolve one `ext_key_usage` / `ext_key_usage_oids` entry to an OID for
/// the hand-rolled DER paths. Same name table and same leniency rule as
/// [`super::x509::resolve_ext_key_usage`]: unknown names are skipped,
/// malformed OIDs are an error.
fn resolve_ext_key_usage_oid(value: &str) -> Result<Option<ObjectIdentifier>, RvError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return Ok(Some(super::ad_ext::parse_oid(trimmed)?));
    }
    let dotted = match trimmed.to_ascii_lowercase().as_str() {
        "serverauth" => "1.3.6.1.5.5.7.3.1",
        "clientauth" => "1.3.6.1.5.5.7.3.2",
        "codesigning" => "1.3.6.1.5.5.7.3.3",
        "emailprotection" => "1.3.6.1.5.5.7.3.4",
        "timestamping" => "1.3.6.1.5.5.7.3.8",
        "ocspsigning" => "1.3.6.1.5.5.7.3.9",
        "any" | "anyextendedkeyusage" => "2.5.29.37.0",
        "smartcardlogon" => super::ad_ext::SMARTCARD_LOGON_EKU_OID,
        "kdcauthentication" => super::ad_ext::KDC_AUTH_EKU_OID,
        _ => return Ok(None),
    };
    Ok(Some(super::ad_ext::parse_oid(dotted)?))
}

pub(super) fn build_subject_alt_name(subject: &SubjectInput) -> Result<Option<Extension>, RvError> {
    if subject.alt_names.is_empty()
        && subject.ip_sans.is_empty()
        && subject.upn_sans.is_empty()
        && subject.email_sans.is_empty()
    {
        return Ok(None);
    }
    let mut names: GeneralNames = Vec::new();
    for d in &subject.alt_names {
        names.push(dns_general_name(d)?);
    }
    for ip in &subject.ip_sans {
        names.push(ip_general_name(ip)?);
    }
    // S/MIME rfc822Names and AD smart-card UPN otherNames share this one
    // SAN extension with the DNS / IP names — a second subjectAltName
    // extension would make the certificate invalid.
    for addr in &subject.email_sans {
        names.push(super::email_san::rfc822_general_name(addr)?);
    }
    for upn in &subject.upn_sans {
        names.push(super::ad_ext::upn_general_name(upn)?);
    }
    Ok(Some(encode_ext(false, &SubjectAltName(names))?))
}

/// A `dNSName` SAN entry. Non-ASCII names cannot be an IA5String and are
/// refused with the offending name, rather than as an opaque DER error.
pub(super) fn dns_general_name(name: &str) -> Result<GeneralName, RvError> {
    let ia5 = Ia5String::new(name)
        .map_err(|e| RvError::ErrString(format!("alt_names: cannot encode `{name}` as an IA5String dNSName ({e})")))?;
    Ok(GeneralName::DnsName(ia5))
}

/// An `iPAddress` SAN entry: 4 octets for IPv4, 16 for IPv6.
pub(super) fn ip_general_name(ip: &IpAddr) -> Result<GeneralName, RvError> {
    let bytes = match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    Ok(GeneralName::IpAddress(OctetString::new(bytes).map_err(der_err)?))
}

/// The AD SID extension for a subject, when one was requested. Returns
/// `None` for every subject that did not ask for it, so the PQC / composite
/// certificate profile is unchanged unless the role opted in.
pub(super) fn build_ad_sid_extension(subject: &SubjectInput) -> Result<Option<Extension>, RvError> {
    match &subject.ad_sid {
        Some(sid) => Ok(Some(super::ad_ext::sid_extension(sid)?)),
        None => Ok(None),
    }
}

/// CRL distribution points from `pki/config/urls`, as a single
/// `DistributionPoint` holding every configured URI. Shared with the
/// classical path (byte-identical to rcgen's encoding), so a chain that
/// mixes issuer classes presents the same CDP shape to verifiers.
pub(super) fn build_crl_distribution_points(
    urls: &super::x509::IssuanceUrls,
) -> Result<Option<Extension>, RvError> {
    if urls.crl_distribution_points.is_empty() {
        return Ok(None);
    }
    let mut names: GeneralNames = Vec::new();
    for uri in &urls.crl_distribution_points {
        let ia5 = Ia5String::new(uri.as_str()).map_err(der_err)?;
        names.push(GeneralName::UniformResourceIdentifier(ia5));
    }
    let dp = DistributionPoint {
        distribution_point: Some(DistributionPointName::FullName(names)),
        reasons: None,
        crl_issuer: None,
    };
    Ok(Some(encode_ext(false, &CrlDistributionPoints(vec![dp]))?))
}

pub(super) fn parse_cert_pem(pem: &str) -> Result<Certificate, RvError> {
    let der = pem_decode_first(pem)?;
    Certificate::from_der(&der).map_err(der_err)
}

pub(super) fn pem_decode_first(pem: &str) -> Result<Vec<u8>, RvError> {
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

pub(super) fn pem_encode(label: &str, der: &[u8]) -> String {
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

pub(super) fn der_err(e: impl std::fmt::Debug) -> RvError {
    log::error!("pki/x509-pqc: DER error: {e:?}");
    RvError::ErrPkiInternal
}

#[cfg(test)]
mod tests {
    //! ML-DSA issuance must chain to its CA the way classical issuance does
    //! (T147): issuer copied verbatim, AKI = the CA's SKI or absent, and the
    //! CA certificate must certify the key that signs. Fixtures are shared
    //! with `x509::tests`.

    use bv_crypto::{ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN};
    use fips204::{
        ml_dsa_65,
        traits::{SerDes, Verifier},
    };

    use super::*;
    use crate::x509::{
        tests::{
            ad_cs_subject, assert_issuer_and_aki, assert_key_mismatch_refused, der_of, leaf_role, leaf_subject,
            multi_valued_subject, self_signed_ca_pem, unsort_multi_valued_rdn, FIELD_SKI,
        },
        IssuanceUrls,
    };

    const LEVEL: MlDsaLevel = MlDsaLevel::L65;

    struct PqcCa {
        signer: MlDsaSigner,
        pem: String,
    }

    fn ml_dsa_spki(public_key: &[u8]) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned { oid: LEVEL.oid(), parameters: None },
            subject_public_key: BitString::from_bytes(public_key).unwrap(),
        }
    }

    /// Self-signed ML-DSA CA certifying `certified_key`, signed by `signer`.
    fn pqc_ca_for(
        signer: MlDsaSigner,
        certified_key: &[u8],
        subject: Name,
        ski: Option<&[u8]>,
        patch: impl Fn(Vec<u8>) -> Vec<u8>,
    ) -> PqcCa {
        let alg = AlgorithmIdentifierOwned { oid: LEVEL.oid(), parameters: None };
        let pem =
            self_signed_ca_pem(ml_dsa_spki(certified_key), alg, subject, ski, patch, |tbs| signer.sign(tbs).unwrap());
        PqcCa { signer, pem }
    }

    fn pqc_ca(subject: Name, ski: Option<&[u8]>) -> PqcCa {
        let signer = MlDsaSigner::generate(LEVEL).unwrap();
        let public_key = signer.public_key().to_vec();
        pqc_ca_for(signer, &public_key, subject, ski, |der| der)
    }

    /// Both ML-DSA entry points: `pki/issue` and `pki/sign` / ACME.
    fn issue_both(ca_signer: &MlDsaSigner, ca_pem: &str) -> [Result<(String, Vec<u8>), RvError>; 2] {
        let leaf = MlDsaSigner::generate(LEVEL).unwrap();
        let (role, subject, ttl, urls) =
            (leaf_role(), leaf_subject("pqc.fgv.br"), Duration::from_secs(3600), IssuanceUrls::default());
        [
            build_leaf(&role, &subject, ttl, &leaf, ca_signer, ca_pem, &urls),
            build_leaf_from_pqc_spki(&role, &subject, ttl, leaf.public_key(), LEVEL, ca_signer, ca_pem, &urls),
        ]
    }

    fn assert_ml_dsa_signed_by(cert_pem: &str, ca: &MlDsaSigner) {
        let cert = Certificate::from_der(&der_of(cert_pem)).unwrap();
        let pk: [u8; ML_DSA_65_PUBLIC_KEY_LEN] = ca.public_key().try_into().unwrap();
        let sig: [u8; ML_DSA_65_SIGNATURE_LEN] = cert.signature.raw_bytes().try_into().unwrap();
        let tbs = cert.tbs_certificate.to_der().unwrap();
        assert!(ml_dsa_65::PublicKey::try_from_bytes(pk).unwrap().verify(&tbs, &sig, &[]), "signature verifies");
    }

    #[test]
    fn pqc_leaf_issuer_is_ca_subject_verbatim_and_aki_is_ca_ski() {
        let ca = pqc_ca(ad_cs_subject(), Some(&FIELD_SKI));
        for issued in issue_both(&ca.signer, &ca.pem) {
            let (pem, _) = issued.expect("issue under an AD CS-named ML-DSA CA");
            assert_issuer_and_aki(&pem, &ca.pem, Some(&FIELD_SKI));
            assert_ml_dsa_signed_by(&pem, &ca.signer);
        }
    }

    #[test]
    fn pqc_ca_without_ski_issues_without_aki() {
        // This used to derive a key id from the CA key, matching nothing
        // the CA advertises.
        let ca = pqc_ca(ad_cs_subject(), None);
        for issued in issue_both(&ca.signer, &ca.pem) {
            let (pem, _) = issued.expect("issue under an ML-DSA CA without SKI");
            assert_issuer_and_aki(&pem, &ca.pem, None);
        }
    }

    #[test]
    fn pqc_non_canonical_ca_subject_is_refused() {
        let signer = MlDsaSigner::generate(LEVEL).unwrap();
        let public_key = signer.public_key().to_vec();
        let ca = pqc_ca_for(signer, &public_key, multi_valued_subject(), Some(&FIELD_SKI), unsort_multi_valued_rdn);
        for issued in issue_both(&ca.signer, &ca.pem) {
            let err = issued.expect_err("a CA subject that cannot be copied verbatim must be refused");
            assert!(format!("{err:?}").contains("byte-for-byte"), "operator-facing reason: {err:?}");
        }
    }

    #[test]
    fn pqc_empty_ca_ski_is_refused() {
        let ca = pqc_ca(ad_cs_subject(), Some(&[]));
        for issued in issue_both(&ca.signer, &ca.pem) {
            let err = issued.expect_err("an empty CA SubjectKeyIdentifier must be refused");
            assert!(format!("{err:?}").contains("malformed SubjectKeyIdentifier"), "operator-facing reason: {err:?}");
        }
    }

    #[test]
    fn pqc_ca_certificate_for_another_key_is_refused() {
        let ca = pqc_ca(ad_cs_subject(), Some(&FIELD_SKI));
        let wrong = MlDsaSigner::generate(LEVEL).unwrap();
        for issued in issue_both(&wrong, &ca.pem) {
            assert_key_mismatch_refused(issued, "is not the public key of the stored private key");
        }
        let other_level = MlDsaSigner::generate(MlDsaLevel::L44).unwrap();
        for issued in issue_both(&other_level, &ca.pem) {
            assert_key_mismatch_refused(issued, "the certificate holds a 2.16.840.1.101.3.4.3.18 key");
        }
    }

    #[test]
    fn pqc_signer_whose_stored_public_key_is_not_its_seed_is_refused() {
        // The CA certificate matches the cached public key, but the seed
        // that signs belongs to another key: a check on the cached copy
        // alone would pass and issue certificates that do not verify.
        let certified = MlDsaSigner::generate(LEVEL).unwrap();
        let seed_owner = MlDsaSigner::generate(LEVEL).unwrap();
        let tampered = seed_owner.with_cached_public_key(certified.public_key().to_vec());
        let ca = pqc_ca_for(certified, &tampered.public_key().to_vec(), ad_cs_subject(), Some(&FIELD_SKI), |der| der);
        for issued in issue_both(&tampered, &ca.pem) {
            let err = issued.expect_err("a signer inconsistent with its seed must be refused");
            assert!(format!("{err:?}").contains("not the one its private seed derives"), "reason: {err:?}");
        }
    }

    // ── build_leaf_dn ──────────────────────────────────────────────────

    fn dn_role() -> RoleEntry {
        RoleEntry {
            organization: "FGV".into(),
            ou: "TI".into(),
            country: "BR".into(),
            locality: "Rio de Janeiro".into(),
            province: "RJ".into(),
            ..Default::default()
        }
    }

    #[test]
    fn leaf_dn_bytes_are_unchanged_for_plain_values() {
        // The RFC 4514 parse this replaced, for values with no DN syntax in
        // them: issued subjects must keep their bytes (ST … CN order, C as
        // PrintableString).
        let before = Name::from_str("CN=app.fgv.br,O=FGV,OU=TI,C=BR,L=Rio de Janeiro,ST=RJ").unwrap();
        let after = build_leaf_dn(&dn_role(), "app.fgv.br").unwrap();
        assert_eq!(after.to_der().unwrap(), before.to_der().unwrap());
        assert_eq!(after.0.first().unwrap().0.get(0).unwrap().oid, crate::x509::ATTR_PROVINCE, "ST encoded first");
        assert_eq!(after.0.last().unwrap().0.get(0).unwrap().oid, crate::x509::ATTR_COMMON_NAME, "CN encoded last");

        let cn_only = build_leaf_dn(&RoleEntry::default(), "only.example").unwrap();
        assert_eq!(cn_only.to_der().unwrap(), Name::from_str("CN=only.example").unwrap().to_der().unwrap());
    }

    #[test]
    fn leaf_dn_takes_dn_syntax_in_values_literally() {
        // A requested CN the old string parse split into extra CN and O
        // attributes; separators, escapes and a leading `#` in role values.
        let cn = "a.example.com,CN=evil.example.net+O=Evil";
        let role = RoleEntry {
            organization: "Acme, Inc.".into(),
            ou: r"R\2CD".into(),
            locality: "#0c0141".into(),
            ..Default::default()
        };
        let dn = build_leaf_dn(&role, cn).unwrap();
        let attrs: Vec<(String, Vec<u8>)> =
            dn.0.iter()
                .map(|rdn| {
                    assert_eq!(rdn.0.len(), 1, "every RDN is single-valued");
                    let atv = rdn.0.get(0).unwrap();
                    (atv.oid.to_string(), atv.value.value().to_vec())
                })
                .collect();
        let expected: Vec<(String, Vec<u8>)> =
            [("2.5.4.7", "#0c0141"), ("2.5.4.11", r"R\2CD"), ("2.5.4.10", "Acme, Inc."), ("2.5.4.3", cn)]
                .iter()
                .map(|(oid, value)| (oid.to_string(), value.as_bytes().to_vec()))
                .collect();
        assert_eq!(attrs, expected);
    }

    #[test]
    fn leaf_dn_refuses_unencodable_country_and_empty_subject() {
        let role = RoleEntry { country: "B&R".into(), ..Default::default() };
        let err = build_leaf_dn(&role, "x.example").expect_err("`&` is not a PrintableString character");
        assert!(format!("{err:?}").contains("PrintableString"), "reason: {err:?}");
        let err = build_leaf_dn(&RoleEntry::default(), "").expect_err("an empty subject must be refused");
        assert!(format!("{err:?}").contains("subject would be empty"), "reason: {err:?}");
    }
}
