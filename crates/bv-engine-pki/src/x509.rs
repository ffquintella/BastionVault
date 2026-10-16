//! X.509 / CRL builders for the PKI engine: role-config knobs in, DER out.
//!
//! Certificates a classical CA issues are built with `x509-cert` and signed
//! with the CA's `rcgen::KeyPair`, as CRLs are; see [`sign_issued_certificate`]
//! for why rcgen's `signed_by` is no longer used for them. rcgen still builds
//! the self-signed root and CSRs and owns classical key handling.

use std::{net::IpAddr, str::FromStr, time::Duration};

use const_oid::{AssociatedOid, ObjectIdentifier};
use rand::Rng;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyUsagePurpose, OtherNameValue, PublicKeyData as _, SanType, SerialNumber, SigningKey as _,
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use x509_cert::{
    attr::AttributeTypeAndValue,
    certificate::{TbsCertificateInner, Version},
    der::{
        asn1::{Any, OctetString, SetOfVec},
        flagset::FlagSet,
        Decode, Encode, Tag,
    },
    ext::{
        pkix::{
            name::GeneralNames, BasicConstraints as PkixBasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
            SubjectAltName, SubjectKeyIdentifier,
        },
        Extension,
    },
    name::{Name, RdnSequence, RelativeDistinguishedName},
    serial_number::SerialNumber as PkixSerialNumber,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    time::Validity,
};

use super::{
    crypto::{rcgen_err, CertSigner},
    path_roles::RoleEntry,
    x509_pqc,
};
use crate::errors::RvError;

/// Subject knobs supplied at issue time (typically derived from request body
/// `common_name`, `alt_names`, `ip_sans`, plus the role's locked-in DN fields).
#[derive(Debug, Default, Clone)]
pub struct SubjectInput {
    pub common_name: String,
    pub alt_names: Vec<String>,
    pub ip_sans: Vec<IpAddr>,
    /// AD smart-card logon: UPNs to emit as `subjectAltName` `otherName`
    /// entries (OID 1.3.6.1.4.1.311.20.2.3). Gated by the role's
    /// `allow_upn_sans` and validated by
    /// [`super::ad_ext::validate_upn`] before it lands here.
    pub upn_sans: Vec<String>,
    /// S/MIME: addresses to emit as `subjectAltName` `rfc822Name`
    /// entries. Gated by the role's `allow_email_sans` /
    /// `allowed_email_domains` and validated by
    /// [`super::email_san::validate_email`] before it lands here.
    pub email_sans: Vec<String>,
    /// AD smart-card logon: the account SID to emit in the
    /// `szOID_NTDS_CA_SECURITY_EXT` extension for KB5014754 strong
    /// mapping. Gated by the role's `allow_ad_sid`; already normalised
    /// and validated by [`super::ad_ext::validate_ad_sid`].
    pub ad_sid: Option<String>,
}

/// Mount-level URLs from `pki/config/urls` that get embedded in issued
/// leaves.
///
/// Only the CRL distribution points are wired today. They matter for AD
/// smart-card logon in particular: a domain controller that cannot reach a
/// CRL for the logon certificate has no revocation source, and Microsoft's
/// third-party-CA guidance calls for a populated, reachable CDP.
///
/// Empty is the default and emits nothing, so a mount that never
/// configured `config/urls` produces byte-identical certificates to before
/// this was wired up.
#[derive(Debug, Default, Clone)]
pub struct IssuanceUrls {
    pub crl_distribution_points: Vec<String>,
}

impl IssuanceUrls {
    pub fn is_empty(&self) -> bool {
        self.crl_distribution_points.is_empty()
    }
}

/// rcgen parameters for a role-driven leaf. Since issuance moved to
/// [`issue_leaf`], this only feeds [`build_leaf_csr`]; the
/// `leaf_extensions_match_rcgen_profile` test pins the two to the same
/// subject DN and extension profile, so a change to one must be mirrored in
/// the other.
fn params_for_subject(
    role: &RoleEntry,
    subject: &SubjectInput,
    ttl: Duration,
    serial_bytes: &[u8],
    urls: &IssuanceUrls,
) -> Result<CertificateParams, RvError> {
    let mut sans: Vec<String> = Vec::new();
    if !subject.common_name.is_empty() {
        sans.push(subject.common_name.clone());
    }
    sans.extend(subject.alt_names.iter().cloned());

    let mut params = CertificateParams::new(sans).map_err(rcgen_err)?;

    for ip in &subject.ip_sans {
        params.subject_alt_names.push(SanType::IpAddress(*ip));
    }

    // S/MIME: the mailbox rides in the same SAN extension as the DNS / IP
    // names. `CertificateParams::new` only ever produces DnsName /
    // IpAddress, so an address handed to `alt_names` would have become a
    // dNSName with an `@` in it — hence the separate channel.
    for addr in &subject.email_sans {
        params.subject_alt_names.push(super::email_san::rcgen_rfc822_san(addr)?);
    }

    // AD smart-card logon: the UPN rides in the *same* SAN extension as
    // the DNS / IP names (a second subjectAltName extension would make
    // the certificate invalid), so it has to go through rcgen's SAN list
    // rather than a custom extension.
    if !subject.upn_sans.is_empty() {
        let upn_arcs = super::ad_ext::upn_san_arcs();
        for upn in &subject.upn_sans {
            params.subject_alt_names.push(SanType::OtherName((
                upn_arcs.clone(),
                OtherNameValue::Utf8String(upn.clone()),
            )));
        }
    }

    // The SID extension has no rcgen representation, so it goes in as a
    // custom extension. `from_oid_content` wraps the content we hand it
    // in the extension's OCTET STRING, so we pass the bare GeneralNames
    // DER — matching what the hand-rolled DER paths put in `extn_value`.
    if let Some(sid) = &subject.ad_sid {
        let content = super::ad_ext::sid_extension_der(sid)?;
        let oid = super::ad_ext::parse_oid_arcs(super::ad_ext::SID_EXT_OID)?;
        params.custom_extensions.push(rcgen::CustomExtension::from_oid_content(&oid, content));
    }

    if !urls.crl_distribution_points.is_empty() {
        params.crl_distribution_points = vec![rcgen::CrlDistributionPoint {
            uris: urls.crl_distribution_points.clone(),
        }];
    }

    let mut dn = DistinguishedName::new();
    if !subject.common_name.is_empty() {
        dn.push(DnType::CommonName, subject.common_name.clone());
    }
    if !role.organization.is_empty() {
        dn.push(DnType::OrganizationName, role.organization.clone());
    }
    if !role.ou.is_empty() {
        dn.push(DnType::OrganizationalUnitName, role.ou.clone());
    }
    if !role.country.is_empty() {
        dn.push(DnType::CountryName, role.country.clone());
    }
    if !role.locality.is_empty() {
        dn.push(DnType::LocalityName, role.locality.clone());
    }
    if !role.province.is_empty() {
        dn.push(DnType::StateOrProvinceName, role.province.clone());
    }
    params.distinguished_name = dn;

    let now = OffsetDateTime::now_utc();
    let backdate = time::Duration::seconds(role.not_before_duration.as_secs() as i64);
    let lifetime = time::Duration::seconds(ttl.as_secs() as i64);
    params.not_before = now - backdate;
    params.not_after = now + lifetime;

    params.key_usages = parse_key_usages(&role.key_usage);
    params.extended_key_usages = parse_ext_key_usages(role, &role.ext_key_usage)?;
    params.serial_number = Some(SerialNumber::from_slice(serial_bytes));

    Ok(params)
}

/// Generate an 8-byte positive random serial. Returned as raw bytes so callers
/// can stash them in storage; convert via `SerialNumber::from_slice` when
/// embedding in a cert.
pub fn random_serial_bytes() -> Vec<u8> {
    let mut buf = [0u8; 8];
    rand::rng().fill_bytes(&mut buf);
    buf[0] &= 0x7f;
    if buf[0] == 0 {
        buf[0] = 0x01;
    }
    buf.to_vec()
}

fn parse_key_usages(values: &[String]) -> Vec<KeyUsagePurpose> {
    values
        .iter()
        .filter_map(|v| match v.to_ascii_lowercase().as_str() {
            "digitalsignature" => Some(KeyUsagePurpose::DigitalSignature),
            "contentcommitment" | "nonrepudiation" => Some(KeyUsagePurpose::ContentCommitment),
            "keyencipherment" => Some(KeyUsagePurpose::KeyEncipherment),
            "dataencipherment" => Some(KeyUsagePurpose::DataEncipherment),
            "keyagreement" => Some(KeyUsagePurpose::KeyAgreement),
            "keycertsign" => Some(KeyUsagePurpose::KeyCertSign),
            "crlsign" => Some(KeyUsagePurpose::CrlSign),
            "encipheronly" => Some(KeyUsagePurpose::EncipherOnly),
            "decipheronly" => Some(KeyUsagePurpose::DecipherOnly),
            _ => None,
        })
        .collect()
}

/// Resolve one `ext_key_usage` entry.
///
/// Named purposes keep their historical spelling. Two Microsoft EKUs get
/// friendly names because they have no RFC 5280 equivalent and typing the
/// OID by hand is error-prone: `smartcardlogon` and `kdcauthentication`.
/// Anything shaped like a dotted-decimal OID is parsed as one, so an
/// operator can drop a raw OID into `ext_key_usage` without reaching for
/// the separate `ext_key_usage_oids` field.
///
/// Unknown *names* return `Ok(None)` and are skipped, preserving the
/// pre-existing lenient behaviour for roles already in storage. A
/// malformed *OID* is an error — it can only be a typo, and silently
/// dropping it would emit a certificate missing the usage the operator
/// asked for.
fn resolve_ext_key_usage(value: &str) -> Result<Option<ExtendedKeyUsagePurpose>, RvError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    // Dotted-decimal shape → treat as an OID.
    if trimmed.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        let arcs = super::ad_ext::parse_oid_arcs(trimmed)
            .map_err(|e| RvError::ErrString(format!("ext_key_usage: {e}")))?;
        return Ok(Some(ExtendedKeyUsagePurpose::Other(arcs)));
    }
    let named = match trimmed.to_ascii_lowercase().as_str() {
        "serverauth" => Some(ExtendedKeyUsagePurpose::ServerAuth),
        "clientauth" => Some(ExtendedKeyUsagePurpose::ClientAuth),
        "codesigning" => Some(ExtendedKeyUsagePurpose::CodeSigning),
        "emailprotection" => Some(ExtendedKeyUsagePurpose::EmailProtection),
        "timestamping" => Some(ExtendedKeyUsagePurpose::TimeStamping),
        "ocspsigning" => Some(ExtendedKeyUsagePurpose::OcspSigning),
        "any" | "anyextendedkeyusage" => Some(ExtendedKeyUsagePurpose::Any),
        "smartcardlogon" => Some(ExtendedKeyUsagePurpose::Other(
            super::ad_ext::parse_oid_arcs(super::ad_ext::SMARTCARD_LOGON_EKU_OID)?,
        )),
        "kdcauthentication" => Some(ExtendedKeyUsagePurpose::Other(
            super::ad_ext::parse_oid_arcs(super::ad_ext::KDC_AUTH_EKU_OID)?,
        )),
        _ => None,
    };
    Ok(named)
}

fn parse_ext_key_usages(
    role: &RoleEntry,
    values: &[String],
) -> Result<Vec<ExtendedKeyUsagePurpose>, RvError> {
    let mut out: Vec<ExtendedKeyUsagePurpose> = Vec::new();
    for v in values {
        if let Some(purpose) = resolve_ext_key_usage(v)? {
            if !out.contains(&purpose) {
                out.push(purpose);
            }
        }
    }
    // `ext_key_usage_oids` is the OID-only channel — every entry must
    // parse (it was already validated at role-write time, so a failure
    // here means the role predates validation or storage was edited
    // out-of-band).
    for oid in &role.ext_key_usage_oids {
        let arcs = super::ad_ext::parse_oid_arcs(oid)
            .map_err(|e| RvError::ErrString(format!("ext_key_usage_oids: {e}")))?;
        let purpose = ExtendedKeyUsagePurpose::Other(arcs);
        if !out.contains(&purpose) {
            out.push(purpose);
        }
    }
    if role.server_flag && !out.contains(&ExtendedKeyUsagePurpose::ServerAuth) {
        out.push(ExtendedKeyUsagePurpose::ServerAuth);
    }
    if role.client_flag && !out.contains(&ExtendedKeyUsagePurpose::ClientAuth) {
        out.push(ExtendedKeyUsagePurpose::ClientAuth);
    }
    Ok(out)
}

/// Build a self-signed CA certificate. Returns the cert plus the serial bytes
/// embedded in it so the caller can persist the serial alongside the cert.
pub fn build_root_ca(
    common_name: &str,
    organization: &str,
    ttl: Duration,
    signer: &CertSigner,
) -> Result<(Certificate, Vec<u8>), RvError> {
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(rcgen_err)?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name.to_string());
    if !organization.is_empty() {
        dn.push(DnType::OrganizationName, organization.to_string());
    }
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages =
        vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];

    let now = OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::seconds(30);
    params.not_after = now + time::Duration::seconds(ttl.as_secs() as i64);
    let serial = random_serial_bytes();
    params.serial_number = Some(SerialNumber::from_slice(&serial));

    let cert = params.self_signed(signer.key_pair()).map_err(rcgen_err)?;
    Ok((cert, serial))
}

/// Build a leaf cert signed by the provided CA. Returns the cert PEM plus
/// the serial bytes embedded in it (for storage indexing and CRL inclusion).
pub fn build_leaf(
    role: &RoleEntry,
    subject: &SubjectInput,
    ttl: Duration,
    leaf_signer: &CertSigner,
    ca_signer: &CertSigner,
    ca_cert_pem: &str,
    urls: &IssuanceUrls,
) -> Result<(String, Vec<u8>), RvError> {
    let spki_der = leaf_signer.key_pair().subject_public_key_info();
    issue_leaf(role, subject, ttl, &spki_der, ca_signer, ca_cert_pem, urls)
}

/// Build a leaf cert from a CSR-supplied public key, signed by the
/// provided CA. Used by `pki/sign/:role` and `pki/sign-verbatim` — the
/// caller picks `subject` based on the role's policy on which fields to
/// honour from the CSR (`use_csr_common_name`, `use_csr_sans`).
pub fn build_leaf_from_spki(
    role: &RoleEntry,
    subject: &SubjectInput,
    ttl: Duration,
    spki_der: &[u8],
    ca_signer: &CertSigner,
    ca_cert_pem: &str,
    urls: &IssuanceUrls,
) -> Result<(String, Vec<u8>), RvError> {
    let spki_der = accepted_spki_der(spki_der)?;
    issue_leaf(role, subject, ttl, &spki_der, ca_signer, ca_cert_pem, urls)
}

/// Build an intermediate-CA cert signed by this mount's root. The result is
/// a cert with `BasicConstraints(ca=true)` plus key-cert-sign / crl-sign
/// usage, suitable for an operator to install on another mount via
/// `pki/intermediate/set-signed`.
pub fn build_intermediate_ca(
    common_name: &str,
    organization: &str,
    ttl: Duration,
    spki_der: &[u8],
    ca_signer: &CertSigner,
    ca_cert_pem: &str,
    path_len: Option<u8>,
) -> Result<(String, Vec<u8>), RvError> {
    let spki_der = accepted_spki_der(spki_der)?;
    let serial = random_serial_bytes();

    // CN is always written, O only when set — the DN rcgen used to build.
    let mut attrs = vec![(ATTR_COMMON_NAME, common_name)];
    if !organization.is_empty() {
        attrs.push((ATTR_ORGANIZATION, organization));
    }
    let key_usage = KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign | KeyUsages::DigitalSignature);
    // Order and criticality as rcgen emitted them for a CA: KU, SKI, BC.
    let extensions = vec![
        x509_pqc::encode_ext(true, &key_usage)?,
        x509_pqc::encode_ext_octets(SubjectKeyIdentifier::OID, false, spki_key_identifier(&spki_der)?)?,
        x509_pqc::encode_ext(true, &PkixBasicConstraints { ca: true, path_len_constraint: path_len })?,
    ];

    let pem = sign_issued_certificate(
        IssuedTbs {
            serial: &serial,
            subject: utf8_name(&attrs)?,
            spki: decode_spki(&spki_der)?,
            validity: x509_pqc::build_validity(Duration::from_secs(30), ttl)?,
            extensions,
        },
        ca_signer,
        ca_cert_pem,
    )?;
    Ok((pem, serial))
}

/// Build a CSR for an intermediate keypair. The intermediate mount uses
/// this in `pki/intermediate/generate` to hand the operator a CSR they can
/// sign on a root mount (or out-of-band on an offline root).
///
/// The CSR is *just* the subject + public key + (no extensions). CA-ness,
/// path length, and key usages are decided by the signing root via
/// `pki/root/sign-intermediate`, not by the CSR — putting `is_ca = true`
/// in a CSR is a polite hint only and rcgen 0.14 errors on
/// `serialize_request` if it's set.
pub fn build_intermediate_csr(
    common_name: &str,
    organization: &str,
    signer: &CertSigner,
) -> Result<rcgen::CertificateSigningRequest, RvError> {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(rcgen_err)?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, common_name.to_string());
    if !organization.is_empty() {
        dn.push(rcgen::DnType::OrganizationName, organization.to_string());
    }
    params.distinguished_name = dn;
    params.serialize_request(signer.key_pair()).map_err(rcgen_err)
}

/// Build a CSR for a leaf-style request (CN + SANs + role-driven DN /
/// key usages). Used by `pki/csr/generate` to produce a CSR that gets
/// signed by an *external* CA. The CSR's public key matches `signer`'s
/// keypair; when the operator brings the upstream-signed cert back via
/// `pki/csr/<id>/set-signed`, we verify the SPKI matches before
/// indexing.
///
/// We intentionally route through [`params_for_subject`] so the CSR
/// requests the *same* key usages and EKUs the role would otherwise
/// produce on `pki/issue/:role`. Whether the upstream CA honours those
/// requested attributes is its policy decision — a CSR is a polite ask,
/// not an instruction.
pub fn build_leaf_csr(
    role: &RoleEntry,
    subject: &SubjectInput,
    signer: &CertSigner,
) -> Result<rcgen::CertificateSigningRequest, RvError> {
    // CSRs don't carry serial / validity bytes — the issuing CA assigns
    // both. Pass a throw-away serial through `params_for_subject` so we
    // can reuse it for SAN/DN/EKU population, then clear it again: rcgen
    // 0.14 does not merely ignore a serial in `serialize_request`, it
    // refuses the whole call with `UnsupportedInCsr`. Leaving it set made
    // every `pki/csr/generate` fail with "Certificate parameter
    // unsupported in CSR" — the validity dates are ignored, but the
    // serial is not.
    let serial_throwaway = random_serial_bytes();
    // No CDP in a generated CSR: rcgen refuses CRL-DP in a CSR, and the
    // upstream CA sets its own distribution points anyway.
    let mut params =
        params_for_subject(role, subject, role.ttl, &serial_throwaway, &IssuanceUrls::default())?;
    params.serial_number = None;
    params.serialize_request(signer.key_pair()).map_err(rcgen_err)
}

// ── classical issuance ─────────────────────────────────────────────────

const ATTR_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const ATTR_ORGANIZATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
const ATTR_ORGANIZATIONAL_UNIT: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");
const ATTR_COUNTRY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.6");
const ATTR_LOCALITY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.7");
const ATTR_PROVINCE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.8");

/// Everything about an issued certificate except who issues it.
struct IssuedTbs<'a> {
    serial: &'a [u8],
    subject: Name,
    spki: SubjectPublicKeyInfoOwned,
    validity: Validity,
    /// In emission order; the AuthorityKeyIdentifier is prepended later.
    extensions: Vec<Extension>,
}

/// The issuing CA, read from its certificate.
struct IssuingCa {
    /// The CA's subject, proven to re-encode to its exact bytes.
    name: Name,
    /// The CA's SubjectKeyIdentifier, when its certificate has one.
    key_id: Option<OctetString>,
}

/// Leaf profile, in the order rcgen emitted it: SAN, KU, EKU, CRL DP, then
/// the AD SID custom extension. Leaves carry no SKI or BasicConstraints,
/// as before.
fn issue_leaf(
    role: &RoleEntry,
    subject: &SubjectInput,
    ttl: Duration,
    spki_der: &[u8],
    ca_signer: &CertSigner,
    ca_cert_pem: &str,
    urls: &IssuanceUrls,
) -> Result<(String, Vec<u8>), RvError> {
    let serial = random_serial_bytes();
    let subject_dn = leaf_subject_name(role, subject)?;

    let mut extensions = Vec::new();
    extensions.extend(leaf_subject_alt_name(subject, subject_dn.0.is_empty())?);
    extensions.extend(key_usage_extension(&parse_key_usages(&role.key_usage))?);
    extensions.extend(ext_key_usage_extension(&parse_ext_key_usages(role, &role.ext_key_usage)?)?);
    extensions.extend(x509_pqc::build_crl_distribution_points(urls)?);
    extensions.extend(x509_pqc::build_ad_sid_extension(subject)?);

    let pem = sign_issued_certificate(
        IssuedTbs {
            serial: &serial,
            subject: subject_dn,
            spki: decode_spki(spki_der)?,
            validity: x509_pqc::build_validity(role.not_before_duration, ttl)?,
            extensions,
        },
        ca_signer,
        ca_cert_pem,
    )?;
    Ok((pem, serial))
}

/// Sign `parts` with a classical CA and return the certificate PEM.
///
/// rcgen's `Issuer` rebuilt the CA subject as a map keyed by attribute type,
/// so `DC=br, DC=fgv` came out as `DC=fgv` and multi-valued RDNs were
/// refused; it also wrote no AuthorityKeyIdentifier. Leaves under AD CS CAs
/// then did not chain. Here the issuer is the CA subject verbatim and the
/// AKI (first, non-critical, keyIdentifier only) is the CA's SKI.
fn sign_issued_certificate(parts: IssuedTbs<'_>, ca_signer: &CertSigner, ca_cert_pem: &str) -> Result<String, RvError> {
    let ca = load_issuing_ca(ca_cert_pem)?;
    let alg_id = certificate_signature_alg_id(ca_signer)?;

    let mut extensions = Vec::with_capacity(parts.extensions.len() + 1);
    match &ca.key_id {
        Some(key_id) => extensions.push(x509_pqc::encode_aki(key_id)?),
        // No SKI to point at. A derived key id would match nothing the CA
        // advertises, and path builders that look issuers up by key id
        // would then miss the CA; without an AKI they match on the issuer
        // name, which is now exact. Logged so the CA can be fixed.
        None => log::warn!(
            "pki: issuing CA `{}` has no SubjectKeyIdentifier; issuing without an AuthorityKeyIdentifier",
            ca.name
        ),
    }
    extensions.extend(parts.extensions);

    let tbs = TbsCertificateInner {
        version: Version::V3,
        serial_number: PkixSerialNumber::new(parts.serial).map_err(encode_err("the serial number"))?,
        signature: alg_id.clone(),
        issuer: ca.name,
        validity: parts.validity,
        subject: parts.subject,
        subject_public_key_info: parts.spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        // RFC 5280: Extensions is SIZE (1..MAX); rcgen omitted it when empty.
        extensions: if extensions.is_empty() { None } else { Some(extensions) },
    };
    let cert =
        x509_pqc::assemble_certificate(tbs, alg_id, |tbs_der| ca_signer.key_pair().sign(tbs_der).map_err(rcgen_err))?;
    let der = cert.to_der().map_err(encode_err("the certificate"))?;
    Ok(x509_pqc::pem_encode("CERTIFICATE", &der))
}

/// Read the issuer Name and SKI from the CA certificate. Parsed with
/// x509-parser (as rcgen did); only the subject is decoded with x509-cert,
/// which re-sorts SET OF members. A subject that does not re-encode to its
/// own bytes, or an SKI that does not parse, is refused: emitting an issuer
/// or AKI that does not match the CA would recreate the chaining failure.
fn load_issuing_ca(ca_cert_pem: &str) -> Result<IssuingCa, RvError> {
    use x509_parser::{extensions::ParsedExtension, oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER};

    let ca_der = x509_pqc::pem_decode_first(ca_cert_pem)?;
    let (_, ca) = x509_parser::parse_x509_certificate(&ca_der)
        .map_err(|e| RvError::ErrString(format!("pki: cannot parse the issuing CA certificate ({e})")))?;
    let ca_subject = &ca.tbs_certificate.subject;

    let raw_subject = ca_subject.as_raw();
    let name = Name::from_der(raw_subject)
        .map_err(|e| RvError::ErrString(format!("pki: cannot decode the issuing CA's subject `{ca_subject}` ({e})")))?;
    if name.to_der().map_err(encode_err("the issuing CA's subject"))? != raw_subject {
        return Err(RvError::ErrString(format!(
            "pki: the issuing CA's subject `{ca_subject}` is not DER-canonical (for example an unsorted \
             multi-valued RDN) and cannot be copied byte-for-byte into the issuer field; re-issue the CA \
             certificate with a DER-encoded subject"
        )));
    }

    let malformed_ski = || {
        RvError::ErrString(format!(
            "pki: the issuing CA certificate `{ca_subject}` has a malformed SubjectKeyIdentifier extension"
        ))
    };
    let key_id = match ca.get_extension_unique(&OID_X509_EXT_SUBJECT_KEY_IDENTIFIER) {
        Ok(None) => None,
        Ok(Some(ext)) => match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(kid) if !kid.0.is_empty() => {
                Some(OctetString::new(kid.0.to_vec()).map_err(|_| malformed_ski())?)
            }
            _ => return Err(malformed_ski()),
        },
        Err(e) => {
            return Err(RvError::ErrString(format!(
                "pki: the issuing CA certificate `{ca_subject}` has more than one SubjectKeyIdentifier ({e})"
            )))
        }
    };
    Ok(IssuingCa { name, key_id })
}

/// The `AlgorithmIdentifier` for certificates `signer` signs. The identifier
/// follows the key type (RSA hash by modulus size, as `CertSigner` pins it)
/// while `KeyPair::sign` uses the algorithm the key pair was loaded with;
/// if those ever disagreed the certificate would not verify, so fail closed.
fn certificate_signature_alg_id(signer: &CertSigner) -> Result<AlgorithmIdentifierOwned, RvError> {
    use super::crypto::KeyAlgorithm;

    let expected: &'static rcgen::SignatureAlgorithm = match signer.algorithm() {
        KeyAlgorithm::Rsa2048 => &rcgen::PKCS_RSA_SHA256,
        KeyAlgorithm::Rsa3072 => &rcgen::PKCS_RSA_SHA384,
        KeyAlgorithm::Rsa4096 => &rcgen::PKCS_RSA_SHA512,
        KeyAlgorithm::EcdsaP256 => &rcgen::PKCS_ECDSA_P256_SHA256,
        KeyAlgorithm::EcdsaP384 => &rcgen::PKCS_ECDSA_P384_SHA384,
        KeyAlgorithm::Ed25519 => &rcgen::PKCS_ED25519,
        // ML-DSA and composite CAs have their own builders.
        _ => return Err(RvError::ErrPkiKeyTypeInvalid),
    };
    if signer.key_pair().algorithm() != expected {
        return Err(RvError::ErrString(format!(
            "pki: the {} CA key is loaded with a signature algorithm that does not match its key type; \
             refusing to sign",
            signer.algorithm().as_str()
        )));
    }
    classical_signature_alg_id(signer.algorithm())
}

/// Check a CSR-supplied SubjectPublicKeyInfo against the key types rcgen
/// can represent (RSA, P-256, P-384, Ed25519) — the set accepted before —
/// and return the DER rcgen would have embedded for it.
fn accepted_spki_der(spki_der: &[u8]) -> Result<Vec<u8>, RvError> {
    let public_key = rcgen::SubjectPublicKeyInfo::from_der(spki_der).map_err(rcgen_err)?;
    Ok(public_key.subject_public_key_info())
}

fn decode_spki(spki_der: &[u8]) -> Result<SubjectPublicKeyInfoOwned, RvError> {
    SubjectPublicKeyInfoOwned::from_der(spki_der)
        .map_err(|e| RvError::ErrString(format!("pki: cannot decode the subject public key ({e})")))
}

/// SKI for an issued CA certificate: SHA-256 over the DER SPKI, truncated
/// to 160 bits. That is rcgen's `KeyIdMethod::Sha256`, so an intermediate
/// re-signed after the move keeps the key identifier it had before.
fn spki_key_identifier(spki_der: &[u8]) -> Result<OctetString, RvError> {
    let digest = Sha256::digest(spki_der);
    OctetString::new(digest[..20].to_vec()).map_err(encode_err("the SubjectKeyIdentifier"))
}

/// A Name of single-valued RDNs, in the given order, with UTF8String values.
fn utf8_name(attrs: &[(ObjectIdentifier, &str)]) -> Result<Name, RvError> {
    let mut rdns = Vec::with_capacity(attrs.len());
    for (oid, value) in attrs {
        let value = Any::new(Tag::Utf8String, value.as_bytes()).map_err(encode_err("a subject attribute"))?;
        let atv = AttributeTypeAndValue { oid: *oid, value };
        let set = SetOfVec::try_from(vec![atv]).map_err(encode_err("a subject RDN"))?;
        rdns.push(RelativeDistinguishedName(set));
    }
    Ok(RdnSequence(rdns))
}

/// Leaf subject as rcgen encoded it: CN, O, OU, C, L, ST, each its own RDN,
/// UTF8String, skipped when empty. Built field by field, so a role value
/// containing `,` or `+` stays one attribute.
fn leaf_subject_name(role: &RoleEntry, subject: &SubjectInput) -> Result<Name, RvError> {
    let attrs: Vec<(ObjectIdentifier, &str)> = [
        (ATTR_COMMON_NAME, subject.common_name.as_str()),
        (ATTR_ORGANIZATION, role.organization.as_str()),
        (ATTR_ORGANIZATIONAL_UNIT, role.ou.as_str()),
        (ATTR_COUNTRY, role.country.as_str()),
        (ATTR_LOCALITY, role.locality.as_str()),
        (ATTR_PROVINCE, role.province.as_str()),
    ]
    .into_iter()
    .filter(|(_, value)| !value.is_empty())
    .collect();
    utf8_name(&attrs)
}

/// SAN as [`params_for_subject`] builds it: CN and `alt_names` (IP-shaped
/// entries become iPAddress), then `ip_sans`, rfc822Names and UPNs.
/// Critical iff the subject DN is empty (RFC 5280 §4.2.1.6).
fn leaf_subject_alt_name(subject: &SubjectInput, subject_dn_is_empty: bool) -> Result<Option<Extension>, RvError> {
    let mut names: GeneralNames = Vec::new();
    let cn = Some(&subject.common_name).filter(|cn| !cn.is_empty());
    for name in cn.into_iter().chain(subject.alt_names.iter()) {
        names.push(match IpAddr::from_str(name) {
            Ok(ip) => x509_pqc::ip_general_name(&ip)?,
            Err(_) => x509_pqc::dns_general_name(name)?,
        });
    }
    for ip in &subject.ip_sans {
        names.push(x509_pqc::ip_general_name(ip)?);
    }
    for addr in &subject.email_sans {
        names.push(super::email_san::rfc822_general_name(addr)?);
    }
    for upn in &subject.upn_sans {
        names.push(super::ad_ext::upn_general_name(upn)?);
    }
    if names.is_empty() {
        return Ok(None);
    }
    Ok(Some(x509_pqc::encode_ext(subject_dn_is_empty, &SubjectAltName(names))?))
}

/// KeyUsage from the role's names (via [`parse_key_usages`]); critical, and
/// omitted when no name resolved.
fn key_usage_extension(purposes: &[KeyUsagePurpose]) -> Result<Option<Extension>, RvError> {
    if purposes.is_empty() {
        return Ok(None);
    }
    let flags = purposes.iter().fold(FlagSet::<KeyUsages>::default(), |acc, purpose| {
        acc | match purpose {
            KeyUsagePurpose::DigitalSignature => KeyUsages::DigitalSignature,
            KeyUsagePurpose::ContentCommitment => KeyUsages::NonRepudiation,
            KeyUsagePurpose::KeyEncipherment => KeyUsages::KeyEncipherment,
            KeyUsagePurpose::DataEncipherment => KeyUsages::DataEncipherment,
            KeyUsagePurpose::KeyAgreement => KeyUsages::KeyAgreement,
            KeyUsagePurpose::KeyCertSign => KeyUsages::KeyCertSign,
            KeyUsagePurpose::CrlSign => KeyUsages::CRLSign,
            KeyUsagePurpose::EncipherOnly => KeyUsages::EncipherOnly,
            KeyUsagePurpose::DecipherOnly => KeyUsages::DecipherOnly,
        }
    });
    Ok(Some(x509_pqc::encode_ext(true, &KeyUsage(flags))?))
}

/// ExtendedKeyUsage from [`parse_ext_key_usages`], in its order; non-critical.
fn ext_key_usage_extension(purposes: &[ExtendedKeyUsagePurpose]) -> Result<Option<Extension>, RvError> {
    if purposes.is_empty() {
        return Ok(None);
    }
    let oids = purposes.iter().map(ext_key_usage_oid).collect::<Result<Vec<_>, _>>()?;
    Ok(Some(x509_pqc::encode_ext(false, &ExtendedKeyUsage(oids))?))
}

fn ext_key_usage_oid(purpose: &ExtendedKeyUsagePurpose) -> Result<ObjectIdentifier, RvError> {
    let dotted = match purpose {
        ExtendedKeyUsagePurpose::Any => "2.5.29.37.0",
        ExtendedKeyUsagePurpose::ServerAuth => "1.3.6.1.5.5.7.3.1",
        ExtendedKeyUsagePurpose::ClientAuth => "1.3.6.1.5.5.7.3.2",
        ExtendedKeyUsagePurpose::CodeSigning => "1.3.6.1.5.5.7.3.3",
        ExtendedKeyUsagePurpose::EmailProtection => "1.3.6.1.5.5.7.3.4",
        ExtendedKeyUsagePurpose::TimeStamping => "1.3.6.1.5.5.7.3.8",
        ExtendedKeyUsagePurpose::OcspSigning => "1.3.6.1.5.5.7.3.9",
        ExtendedKeyUsagePurpose::Other(arcs) => {
            let dotted = arcs.iter().map(u64::to_string).collect::<Vec<_>>().join(".");
            return super::ad_ext::parse_oid(&dotted);
        }
    };
    super::ad_ext::parse_oid(dotted)
}

fn encode_err(what: &'static str) -> impl Fn(x509_cert::der::Error) -> RvError {
    move |e| RvError::ErrString(format!("pki: failed to encode {what} ({e})"))
}

/// Build a CRL signed by a *classical* CA (RSA / ECDSA / Ed25519).
///
/// Phase 5.4: this used to drive `rcgen::CertificateRevocationListParams`
/// for classical and a separate manual `x509-cert::crl` path for PQC and
/// composite. Phase 5.4 unifies the three onto
/// [`super::x509_pqc::build_crl_with_alg`] so future CRL-extension work
/// (CRL-DP, AKI, IDP) only needs to land in one place. The classical
/// path now signs the TBS DER bytes directly via `rcgen::SigningKey`
/// (which routes through ring) — same crypto, just one CRL emitter.
pub fn build_crl(
    crl_number: u64,
    next_update_secs: u64,
    revoked: &[RevokedEntry],
    ca_signer: &CertSigner,
    ca_cert_pem: &str,
) -> Result<String, RvError> {
    use rcgen::SigningKey;
    let alg_id = classical_signature_alg_id(ca_signer.algorithm())?;
    super::x509_pqc::build_crl_with_alg(
        crl_number,
        next_update_secs,
        revoked,
        ca_cert_pem,
        alg_id,
        |tbs_der| ca_signer.key_pair().sign(tbs_der).map_err(rcgen_err),
    )
}

/// Map a classical signing algorithm to the `AlgorithmIdentifier` that
/// goes on the outer `signatureAlgorithm` of an X.509 CRL.
///
/// Per RFC 4055: RSA-PKCS#1-v1.5 algorithms (`sha{256,384,512}WithRSAEncryption`)
/// MUST carry an explicit NULL parameter. ECDSA and Ed25519 algorithms
/// MUST omit the parameter (per RFC 5758 / RFC 8410). We honour both
/// rules here so verifiers that strict-check the AlgorithmIdentifier
/// (Java's `CertPath` validators are notably picky) accept the CRL.
fn classical_signature_alg_id(
    alg: super::crypto::KeyAlgorithm,
) -> Result<x509_cert::spki::AlgorithmIdentifierOwned, RvError> {
    use super::crypto::KeyAlgorithm;
    use x509_cert::der::asn1::AnyRef;

    let null_params: Option<x509_cert::der::Any> = {
        // ASN.1 NULL is `0x05 0x00`. Build it via AnyRef::null() and own.
        let any_ref = AnyRef::from(x509_cert::der::asn1::Null);
        Some(any_ref.into())
    };

    let (oid, parameters): (const_oid::ObjectIdentifier, Option<x509_cert::der::Any>) = match alg {
        // sha256WithRSAEncryption
        KeyAlgorithm::Rsa2048 => (
            const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
            null_params.clone(),
        ),
        // sha384WithRSAEncryption
        KeyAlgorithm::Rsa3072 => (
            const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12"),
            null_params.clone(),
        ),
        // sha512WithRSAEncryption
        KeyAlgorithm::Rsa4096 => (
            const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13"),
            null_params,
        ),
        // ecdsa-with-SHA256
        KeyAlgorithm::EcdsaP256 => (
            const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
            None,
        ),
        // ecdsa-with-SHA384
        KeyAlgorithm::EcdsaP384 => (
            const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"),
            None,
        ),
        // id-Ed25519 (RFC 8410)
        KeyAlgorithm::Ed25519 => (
            const_oid::ObjectIdentifier::new_unwrap("1.3.101.112"),
            None,
        ),
        // PQC + composite are handled by their own builders, not this one.
        KeyAlgorithm::MlDsa44 | KeyAlgorithm::MlDsa65 | KeyAlgorithm::MlDsa87 => {
            return Err(RvError::ErrPkiKeyTypeInvalid);
        }
        #[cfg(feature = "pki_pqc_composite")]
        KeyAlgorithm::CompositeEcdsaP256MlDsa44
        | KeyAlgorithm::CompositeEcdsaP256MlDsa65
        | KeyAlgorithm::CompositeEcdsaP384MlDsa87 => return Err(RvError::ErrPkiKeyTypeInvalid),
    };
    Ok(x509_cert::spki::AlgorithmIdentifierOwned { oid, parameters })
}

/// One revoked-cert record persisted in storage and folded into each new CRL.
#[derive(Debug, Clone)]
pub struct RevokedEntry {
    pub serial: Vec<u8>,
    pub revoked_at_unix: u64,
}

/// Validate a DNS-style name (CN or DNS SAN) against the role's
/// emission-control matrix.
///
/// Phase L4 closes the deferred domain-policy gap from Phase 1. The
/// matrix mirrors Vault's role rules:
///
/// - `allow_any_name = true` (Vault default + BastionVault default for
///   freshly-written roles): everything passes.
/// - Otherwise the name is accepted only if it is one of:
///   - `"localhost"` / `"localdomain"` when `allow_localhost = true`,
///   - present in `allowed_domains` when `allow_bare_domains = true`,
///   - a strict subdomain of an entry in `allowed_domains` when
///     `allow_subdomains = true`,
///   - a glob match against an entry in `allowed_domains` when
///     `allow_glob_domains = true`.
///
/// `allowed_domains` is the conjunctive root of the rules — empty
/// `allowed_domains` with `allow_any_name = false` means "no DNS names
/// accepted" (combine with `allow_ip_sans` for IP-only mTLS).
pub fn validate_common_name(role: &RoleEntry, cn: &str) -> Result<(), RvError> {
    if cn.is_empty() {
        return Err(RvError::ErrPkiDataInvalid);
    }
    validate_dns_name(role, cn)
}

/// Apply the role's domain-policy matrix to a single DNS-style name.
/// Used by [`validate_common_name`] and by the issue/sign handlers when
/// they walk DNS SANs.
pub fn validate_dns_name(role: &RoleEntry, name: &str) -> Result<(), RvError> {
    if name.is_empty() {
        return Err(RvError::ErrPkiDataInvalid);
    }
    if role.allow_any_name {
        return Ok(());
    }
    if role.allow_localhost && (name == "localhost" || name == "localdomain") {
        return Ok(());
    }

    let candidate = name.to_ascii_lowercase();
    for raw in &role.allowed_domains {
        let allowed = raw.trim().to_ascii_lowercase();
        if allowed.is_empty() {
            continue;
        }
        if role.allow_bare_domains && candidate == allowed {
            return Ok(());
        }
        if role.allow_subdomains && is_strict_subdomain(&candidate, &allowed) {
            return Ok(());
        }
        if role.allow_glob_domains && glob_match(&allowed, &candidate) {
            return Ok(());
        }
    }
    Err(RvError::ErrString(format!(
        "name `{name}` is not permitted by the role's emission policy"
    )))
}

/// `child` is a strict subdomain of `parent` when it ends with
/// `.<parent>` and the prefix carries at least one label. Equality
/// alone does not count — that's `allow_bare_domains`'s job.
fn is_strict_subdomain(child: &str, parent: &str) -> bool {
    if child.len() <= parent.len() + 1 {
        return false;
    }
    let suffix_start = child.len() - parent.len();
    if &child[suffix_start..] != parent {
        return false;
    }
    // The character right before `parent` must be `.`, and the prefix
    // must be a non-empty label sequence.
    child.as_bytes()[suffix_start - 1] == b'.' && !child[..suffix_start - 1].is_empty()
}

/// Single-label glob match: `*` in `pattern` matches one or more
/// characters within the same label. `*` does NOT span dots — wildcard
/// subdomains require a separate `allow_subdomains` rule.
fn glob_match(pattern: &str, name: &str) -> bool {
    // Patterns and names are split into label vectors; each label is
    // matched independently with the `*` rule above. This keeps the
    // semantics close to Vault's documentation:
    // `*-prod.example.com` matches `web-prod.example.com` but NOT
    // `web.prod.example.com`.
    let p_labels: Vec<&str> = pattern.split('.').collect();
    let n_labels: Vec<&str> = name.split('.').collect();
    if p_labels.len() != n_labels.len() {
        return false;
    }
    p_labels.iter().zip(n_labels.iter()).all(|(p, n)| label_glob(p, n))
}

fn label_glob(pattern: &str, label: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == label;
    }
    // Split pattern on `*`; each part must occur in order in `label`.
    // Anchored at start (first part) and end (last part) so leading
    // and trailing literal text is enforced.
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut cursor = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            if !label[cursor..].starts_with(part) {
                return false;
            }
            cursor += part.len();
        } else if i == parts.len() - 1 {
            if !label[cursor..].ends_with(part) {
                return false;
            }
            // Make sure the suffix doesn't overlap material we already
            // consumed (e.g. pattern `**` against an empty middle).
            if label.len() < cursor + part.len() {
                return false;
            }
        } else {
            match label[cursor..].find(part) {
                Some(idx) => cursor += idx + part.len(),
                None => return false,
            }
        }
    }
    // `*` requires at least one character of replacement — empty `*`
    // matches are not allowed (Vault parity).
    !label.is_empty()
}

/// Parse a comma-separated alt_names string into DNS labels + IP SANs.
pub fn split_alt_names(input: &str) -> (Vec<String>, Vec<IpAddr>) {
    let mut dns = Vec::new();
    let mut ips = Vec::new();
    for raw in input.split(',') {
        let v = raw.trim();
        if v.is_empty() {
            continue;
        }
        if let Ok(ip) = IpAddr::from_str(v) {
            ips.push(ip);
        } else {
            dns.push(v.to_string());
        }
    }
    (dns, ips)
}

#[cfg(test)]
mod tests {
    //! Classical issuance must chain to its CA. Field report: under an AD CS
    //! CA `DC=br, DC=fgv, CN=FGV-SSL-CA-V1` (SKI `86:79:B4:…`) leaves carried
    //! issuer `DC=fgv, CN=FGV-SSL-CA-V1` and no AKI. Test CAs are built with
    //! `x509-cert` (rcgen cannot express them) from keys generated per test.

    use super::*;
    use crate::crypto::KeyAlgorithm;
    use rcgen::{Issuer, KeyPair};
    use x509_cert::{
        attr::AttributeTypeAndValue,
        certificate::{CertificateInner, TbsCertificateInner, Version},
        der::{
            asn1::{Any, BitString, OctetString, SetOfVec},
            Decode, Encode, Tag, Tagged,
        },
        ext::{
            pkix::{BasicConstraints as PkixBasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier},
            Extension,
        },
        name::{Name, RdnSequence, RelativeDistinguishedName},
        serial_number::SerialNumber as PkixSerialNumber,
        spki::SubjectPublicKeyInfoOwned,
    };
    use x509_parser::{
        extensions::ParsedExtension,
        oid_registry::{OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER, OID_X509_EXT_BASIC_CONSTRAINTS},
    };

    use crate::x509_pqc;

    const OID_DC: &str = "0.9.2342.19200300.100.1.25";
    const OID_CN: &str = "2.5.4.3";
    const OID_O: &str = "2.5.4.10";
    const OID_C: &str = "2.5.4.6";
    const OID_AKI: &str = "2.5.29.35";

    /// The CA SKI from the field report, padded to 160 bits. Deliberately
    /// *not* derived from the CA key: the AKI must copy the CA's SKI, not
    /// recompute one.
    const FIELD_SKI: [u8; 20] = [
        0x86, 0x79, 0xB4, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE,
        0x0F, 0x1E,
    ];

    // ── test CA construction ───────────────────────────────────────────

    fn atv(oid: &str, tag: Tag, value: &str) -> AttributeTypeAndValue {
        AttributeTypeAndValue {
            oid: ObjectIdentifier::new_unwrap(oid),
            value: Any::new(tag, value.as_bytes()).unwrap(),
        }
    }

    fn rdn(atvs: Vec<AttributeTypeAndValue>) -> RelativeDistinguishedName {
        RelativeDistinguishedName(SetOfVec::try_from(atvs).unwrap())
    }

    /// `DC=br, DC=fgv, CN=FGV-SSL-CA-V1` in encoding order, as AD CS
    /// writes it: domainComponent as IA5String, CN as PrintableString.
    fn ad_cs_subject() -> Name {
        RdnSequence(vec![
            rdn(vec![atv(OID_DC, Tag::Ia5String, "br")]),
            rdn(vec![atv(OID_DC, Tag::Ia5String, "fgv")]),
            rdn(vec![atv(OID_CN, Tag::PrintableString, "FGV-SSL-CA-V1")]),
        ])
    }

    /// `C=BR` followed by the multi-valued RDN `CN=x+O=y`.
    fn multi_valued_subject() -> Name {
        RdnSequence(vec![
            rdn(vec![atv(OID_C, Tag::PrintableString, "BR")]),
            rdn(vec![atv(OID_CN, Tag::Utf8String, "x"), atv(OID_O, Tag::Utf8String, "y")]),
        ])
    }

    struct TestCa {
        signer: CertSigner,
        pem: String,
    }

    /// Self-signed CA over `subject`, carrying `ski` as its
    /// SubjectKeyIdentifier when given. `patch` rewrites the TBS DER
    /// before it is signed, for building deliberately non-canonical CAs.
    fn make_ca_with(
        alg: KeyAlgorithm,
        subject: Name,
        ski: Option<&[u8]>,
        patch: impl Fn(Vec<u8>) -> Vec<u8>,
    ) -> TestCa {
        let signer = CertSigner::generate(alg).expect("CA keygen");
        let spki = SubjectPublicKeyInfoOwned::from_der(&signer.key_pair().subject_public_key_info()).unwrap();
        let alg_id = classical_signature_alg_id(alg).unwrap();
        let mut exts: Vec<Extension> = vec![
            x509_pqc::encode_ext(true, &PkixBasicConstraints { ca: true, path_len_constraint: None }).unwrap(),
            x509_pqc::encode_ext(true, &KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)).unwrap(),
        ];
        if let Some(ski) = ski {
            exts.push(
                x509_pqc::encode_ext_octets(SubjectKeyIdentifier::OID, false, OctetString::new(ski.to_vec()).unwrap())
                    .unwrap(),
            );
        }
        let tbs: TbsCertificateInner = TbsCertificateInner {
            version: Version::V3,
            serial_number: PkixSerialNumber::new(&random_serial_bytes()).unwrap(),
            signature: alg_id.clone(),
            issuer: subject.clone(),
            validity: x509_pqc::build_validity(Duration::from_secs(60), Duration::from_secs(86_400)).unwrap(),
            subject,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(exts),
        };
        let tbs_der = patch(tbs.to_der().unwrap());
        let sig = signer.key_pair().sign(&tbs_der).unwrap();
        // Assemble the outer SEQUENCE by hand so a patched TBS is
        // embedded exactly as signed.
        let mut body = tbs_der;
        body.extend(alg_id.to_der().unwrap());
        body.extend(BitString::from_bytes(&sig).unwrap().to_der().unwrap());
        let mut der = Vec::new();
        x509_cert::der::Header::new(Tag::Sequence, x509_cert::der::Length::try_from(body.len()).unwrap())
            .unwrap()
            .encode_to_vec(&mut der)
            .unwrap();
        der.extend(body);
        TestCa { signer, pem: x509_pqc::pem_encode("CERTIFICATE", &der) }
    }

    fn make_ca(alg: KeyAlgorithm, subject: Name, ski: Option<&[u8]>) -> TestCa {
        make_ca_with(alg, subject, ski, |der| der)
    }

    fn der_of(pem: &str) -> Vec<u8> {
        x509_pqc::pem_decode_first(pem).unwrap()
    }

    fn leaf_role() -> RoleEntry {
        RoleEntry {
            key_usage: vec!["DigitalSignature".into(), "KeyEncipherment".into()],
            organization: "FGV".into(),
            ..Default::default()
        }
    }

    fn leaf_subject(cn: &str) -> SubjectInput {
        SubjectInput { common_name: cn.into(), alt_names: vec![cn.into()], ..Default::default() }
    }

    /// The checks a strict path builder makes: the issuer Name is the CA
    /// subject byte-for-byte, the AKI keyIdentifier is the CA's SKI (or
    /// absent), and the signature verifies under the CA key with matching
    /// inner/outer algorithm identifiers.
    fn assert_chains(cert_pem: &str, ca_pem: &str, expected_aki: Option<&[u8]>) {
        let cert_der = der_of(cert_pem);
        let ca_der = der_of(ca_pem);
        let (_, cert) = x509_parser::parse_x509_certificate(&cert_der).expect("issued cert parses");
        let (_, ca) = x509_parser::parse_x509_certificate(&ca_der).expect("CA parses");

        assert_eq!(
            cert.tbs_certificate.issuer.as_raw(),
            ca.tbs_certificate.subject.as_raw(),
            "issuer must be the CA subject byte-for-byte (issuer `{}`, CA subject `{}`)",
            cert.tbs_certificate.issuer,
            ca.tbs_certificate.subject,
        );

        let aki = cert.get_extension_unique(&OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER).expect("at most one AKI");
        match expected_aki {
            Some(kid) => {
                let ext = aki.expect("AuthorityKeyIdentifier must be present");
                assert!(!ext.critical, "AKI must be non-critical (RFC 5280 §4.2.1.1)");
                match ext.parsed_extension() {
                    ParsedExtension::AuthorityKeyIdentifier(a) => {
                        assert_eq!(a.key_identifier.as_ref().map(|k| k.0), Some(kid), "AKI keyId == CA SKI");
                        assert!(a.authority_cert_issuer.is_none());
                        assert!(a.authority_cert_serial.is_none());
                    }
                    other => panic!("AKI did not parse: {other:?}"),
                }
            }
            None => assert!(aki.is_none(), "no AKI expected"),
        }

        assert_eq!(cert.signature_algorithm, cert.tbs_certificate.signature, "inner/outer signature alg");
        cert.verify_signature(Some(ca.public_key())).expect("signature verifies under the CA key");
    }

    // ── 1. build_leaf ──────────────────────────────────────────────────

    #[test]
    fn leaf_issuer_is_ca_subject_verbatim_and_aki_is_ca_ski() {
        let ca = make_ca(KeyAlgorithm::EcdsaP256, ad_cs_subject(), Some(&FIELD_SKI));
        let leaf_key = CertSigner::generate(KeyAlgorithm::EcdsaP256).unwrap();
        let (pem, _) = build_leaf(
            &leaf_role(),
            &leaf_subject("app.fgv.br"),
            Duration::from_secs(3600),
            &leaf_key,
            &ca.signer,
            &ca.pem,
            &IssuanceUrls::default(),
        )
        .expect("issue leaf");
        assert_chains(&pem, &ca.pem, Some(&FIELD_SKI));
    }

    // ── 2. build_leaf_from_spki / build_intermediate_ca ────────────────

    #[test]
    fn sign_path_leaf_issuer_is_ca_subject_verbatim_and_aki_is_ca_ski() {
        let ca = make_ca(KeyAlgorithm::EcdsaP256, ad_cs_subject(), Some(&FIELD_SKI));
        let requester = CertSigner::generate(KeyAlgorithm::EcdsaP384).unwrap();
        let spki_der = requester.key_pair().subject_public_key_info();
        let (pem, _) = build_leaf_from_spki(
            &leaf_role(),
            &leaf_subject("csr.fgv.br"),
            Duration::from_secs(3600),
            &spki_der,
            &ca.signer,
            &ca.pem,
            &IssuanceUrls::default(),
        )
        .expect("sign CSR leaf");
        assert_chains(&pem, &ca.pem, Some(&FIELD_SKI));
        let cert = x509_cert::Certificate::from_der(&der_of(&pem)).unwrap();
        assert_eq!(cert.tbs_certificate.subject_public_key_info.to_der().unwrap(), spki_der, "CSR key embedded");
    }

    #[test]
    fn intermediate_issuer_is_ca_subject_verbatim_and_aki_is_ca_ski() {
        let ca = make_ca(KeyAlgorithm::EcdsaP256, ad_cs_subject(), Some(&FIELD_SKI));
        let child = CertSigner::generate(KeyAlgorithm::EcdsaP256).unwrap();
        let spki_der = child.key_pair().subject_public_key_info();
        let (pem, _) = build_intermediate_ca(
            "FGV Issuing CA 2",
            "FGV",
            Duration::from_secs(86_400),
            &spki_der,
            &ca.signer,
            &ca.pem,
            Some(0),
        )
        .expect("sign intermediate");
        assert_chains(&pem, &ca.pem, Some(&FIELD_SKI));

        let der = der_of(&pem);
        let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
        let bc = cert.get_extension_unique(&OID_X509_EXT_BASIC_CONSTRAINTS).unwrap().expect("BC present");
        assert!(bc.critical);
        match bc.parsed_extension() {
            ParsedExtension::BasicConstraints(b) => {
                assert!(b.ca);
                assert_eq!(b.path_len_constraint, Some(0));
            }
            other => panic!("BC did not parse: {other:?}"),
        }
    }

    // ── 3. multi-valued RDN in the CA subject ──────────────────────────

    #[test]
    fn multi_valued_rdn_ca_subject_is_copied_verbatim() {
        let ca = make_ca(KeyAlgorithm::EcdsaP256, multi_valued_subject(), Some(&FIELD_SKI));
        let leaf_key = CertSigner::generate(KeyAlgorithm::EcdsaP256).unwrap();
        let (leaf, _) = build_leaf(
            &leaf_role(),
            &leaf_subject("mv.example"),
            Duration::from_secs(3600),
            &leaf_key,
            &ca.signer,
            &ca.pem,
            &IssuanceUrls::default(),
        )
        .expect("a multi-valued RDN in the CA subject must not block issuance");
        assert_chains(&leaf, &ca.pem, Some(&FIELD_SKI));

        let (from_csr, _) = build_leaf_from_spki(
            &leaf_role(),
            &leaf_subject("mv-csr.example"),
            Duration::from_secs(3600),
            &leaf_key.key_pair().subject_public_key_info(),
            &ca.signer,
            &ca.pem,
            &IssuanceUrls::default(),
        )
        .expect("sign path");
        assert_chains(&from_csr, &ca.pem, Some(&FIELD_SKI));

        let (inter, _) = build_intermediate_ca(
            "MV Sub CA",
            "",
            Duration::from_secs(86_400),
            &leaf_key.key_pair().subject_public_key_info(),
            &ca.signer,
            &ca.pem,
            None,
        )
        .expect("sign-intermediate path");
        assert_chains(&inter, &ca.pem, Some(&FIELD_SKI));
    }

    // ── 4. CA without a SubjectKeyIdentifier ───────────────────────────

    #[test]
    fn ca_without_ski_issues_without_aki() {
        let ca = make_ca(KeyAlgorithm::EcdsaP256, ad_cs_subject(), None);
        let leaf_key = CertSigner::generate(KeyAlgorithm::EcdsaP256).unwrap();
        let (leaf, _) = build_leaf(
            &leaf_role(),
            &leaf_subject("noski.example"),
            Duration::from_secs(3600),
            &leaf_key,
            &ca.signer,
            &ca.pem,
            &IssuanceUrls::default(),
        )
        .expect("issue under a CA without SKI");
        assert_chains(&leaf, &ca.pem, None);

        let (inter, _) = build_intermediate_ca(
            "No SKI Sub CA",
            "",
            Duration::from_secs(86_400),
            &leaf_key.key_pair().subject_public_key_info(),
            &ca.signer,
            &ca.pem,
            None,
        )
        .expect("sign intermediate under a CA without SKI");
        assert_chains(&inter, &ca.pem, None);
    }

    // ── 5. signature per classical CA key type ─────────────────────────

    #[test]
    fn issued_signature_verifies_for_each_classical_ca_key_type() {
        // (CA key type, expected outer signatureAlgorithm OID)
        let cases = [
            (KeyAlgorithm::EcdsaP256, "1.2.840.10045.4.3.2"),
            (KeyAlgorithm::EcdsaP384, "1.2.840.10045.4.3.3"),
            (KeyAlgorithm::Ed25519, "1.3.101.112"),
            (KeyAlgorithm::Rsa2048, "1.2.840.113549.1.1.11"),
        ];
        for (alg, sig_oid) in cases {
            assert_ca_signs_leaf_with(alg, sig_oid);
        }
    }

    /// rcgen's reloaded issuer signed RSA-3072 leaves with SHA-256; they now
    /// follow the key's pinned hash, as CRLs already did. Separate test: the
    /// debug-build RSA-3072 keygen is slow and should run in parallel.
    #[test]
    fn rsa3072_ca_signs_with_sha384() {
        assert_ca_signs_leaf_with(KeyAlgorithm::Rsa3072, "1.2.840.113549.1.1.12");
    }

    fn assert_ca_signs_leaf_with(alg: KeyAlgorithm, sig_oid: &str) {
        let ca = make_ca(alg, ad_cs_subject(), Some(&FIELD_SKI));
        let leaf_key = CertSigner::generate(KeyAlgorithm::EcdsaP256).unwrap();
        let (leaf, _) = build_leaf(
            &leaf_role(),
            &leaf_subject("sig.example"),
            Duration::from_secs(3600),
            &leaf_key,
            &ca.signer,
            &ca.pem,
            &IssuanceUrls::default(),
        )
        .unwrap_or_else(|e| panic!("issue under {alg:?} CA: {e:?}"));
        assert_chains(&leaf, &ca.pem, Some(&FIELD_SKI));
        let cert = x509_cert::Certificate::from_der(&der_of(&leaf)).unwrap();
        assert_eq!(cert.signature_algorithm.oid.to_string(), sig_oid, "{alg:?} signature algorithm");
        if matches!(alg, KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa3072) {
            // RFC 4055: PKCS#1 v1.5 identifiers carry an explicit NULL.
            assert_eq!(cert.signature_algorithm.parameters.as_ref().map(|p| p.tag()), Some(Tag::Null));
        } else {
            assert!(cert.signature_algorithm.parameters.is_none(), "{alg:?} parameters must be absent");
        }
    }

    // ── 6. extension parity with the rcgen profile ─────────────────────

    /// The rcgen-built reference for `role` + `subject`, signed by a CA
    /// rcgen can parse. Only the subject, key and extensions are compared,
    /// so the reference issuer does not matter.
    fn rcgen_reference_leaf(
        role: &RoleEntry,
        subject: &SubjectInput,
        serial: &[u8],
        leaf_key: &CertSigner,
        urls: &IssuanceUrls,
    ) -> String {
        let ca = make_ca(
            KeyAlgorithm::EcdsaP256,
            RdnSequence(vec![rdn(vec![atv(OID_CN, Tag::Utf8String, "Reference CA")])]),
            Some(&FIELD_SKI),
        );
        let params = params_for_subject(role, subject, Duration::from_secs(3600), serial, urls).unwrap();
        let kp = KeyPair::from_pem(ca.signer.pem_pkcs8()).unwrap();
        let issuer = Issuer::from_ca_cert_pem(&ca.pem, kp).unwrap();
        params.signed_by(leaf_key.key_pair(), &issuer).unwrap().pem()
    }

    fn assert_leaf_profile_matches_rcgen(
        role: &RoleEntry,
        subject: &SubjectInput,
        urls: &IssuanceUrls,
    ) -> Vec<Extension> {
        let ca = make_ca(KeyAlgorithm::EcdsaP256, ad_cs_subject(), Some(&FIELD_SKI));
        let leaf_key = CertSigner::generate(KeyAlgorithm::EcdsaP256).unwrap();
        let (pem, serial) = build_leaf(role, subject, Duration::from_secs(3600), &leaf_key, &ca.signer, &ca.pem, urls)
            .expect("issue leaf");
        let reference = rcgen_reference_leaf(role, subject, &serial, &leaf_key, urls);

        let new = x509_cert::Certificate::from_der(&der_of(&pem)).unwrap().tbs_certificate;
        let old = x509_cert::Certificate::from_der(&der_of(&reference)).unwrap().tbs_certificate;
        assert_eq!(new.subject.to_der().unwrap(), old.subject.to_der().unwrap(), "subject DN encoding");
        assert_eq!(new.serial_number, old.serial_number, "serial");
        assert_eq!(new.subject_public_key_info, old.subject_public_key_info, "SPKI");
        assert_eq!(new.version, old.version);

        let aki = ObjectIdentifier::new_unwrap(OID_AKI);
        let new_exts: Vec<Extension> =
            new.extensions.clone().unwrap_or_default().into_iter().filter(|e| e.extn_id != aki).collect();
        let old_exts: Vec<Extension> = old.extensions.unwrap_or_default();
        assert_eq!(new_exts, old_exts, "every extension other than AKI matches the rcgen profile, in order");
        new.extensions.unwrap_or_default()
    }

    #[test]
    fn leaf_extensions_match_rcgen_profile() {
        let role = RoleEntry {
            key_usage: vec!["DigitalSignature".into(), "KeyEncipherment".into(), "bogus".into()],
            ext_key_usage: vec!["codesigning".into(), "smartcardlogon".into(), "1.3.6.1.5.5.7.3.4".into()],
            ext_key_usage_oids: vec!["1.2.3.4.5".into()],
            organization: "FGV".into(),
            ou: "TI".into(),
            country: "BR".into(),
            locality: "Rio de Janeiro".into(),
            province: "RJ".into(),
            ..Default::default()
        };
        let subject = SubjectInput {
            common_name: "app.fgv.br".into(),
            alt_names: vec!["www.fgv.br".into(), "192.0.2.10".into()],
            ip_sans: vec!["10.0.0.5".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            upn_sans: vec!["alice@fgv.br".into()],
            email_sans: vec!["alice@fgv.br".into()],
            ad_sid: Some("S-1-5-21-1004336348-1177238915-682003330-512".into()),
        };
        let urls = IssuanceUrls { crl_distribution_points: vec!["http://crl.fgv.br/ca.crl".into()] };
        let exts = assert_leaf_profile_matches_rcgen(&role, &subject, &urls);

        // The comparison above is only meaningful if the profile is rich.
        let oids: Vec<String> = exts.iter().map(|e| e.extn_id.to_string()).collect();
        for want in ["2.5.29.17", "2.5.29.15", "2.5.29.37", "2.5.29.31", crate::ad_ext::SID_EXT_OID] {
            assert!(oids.iter().any(|o| o == want), "extension {want} missing from {oids:?}");
        }
        let san = exts.iter().find(|e| e.extn_id.to_string() == "2.5.29.17").unwrap();
        assert!(!san.critical, "SAN is non-critical when the subject DN is non-empty");
    }

    #[test]
    fn leaf_with_empty_subject_dn_matches_rcgen_profile() {
        // No CN and no role DN fields: rcgen marks the SAN critical
        // (RFC 5280 §4.2.1.6). EKU comes from the role's server/client flags.
        let role = RoleEntry::default();
        let subject = SubjectInput { alt_names: vec!["only-san.example".into()], ..Default::default() };
        let exts = assert_leaf_profile_matches_rcgen(&role, &subject, &IssuanceUrls::default());
        let san = exts.iter().find(|e| e.extn_id.to_string() == "2.5.29.17").expect("SAN");
        assert!(san.critical, "SAN must be critical when the subject DN is empty");
    }

    #[test]
    fn intermediate_extensions_match_rcgen_profile() {
        // The rcgen parameters the old `build_intermediate_ca` used.
        let (cn, org, path_len) = ("FGV Issuing CA 2", "FGV", Some(1));
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn.to_string());
        dn.push(DnType::OrganizationName, org.to_string());
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        params.key_usages =
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];

        let ca = make_ca(KeyAlgorithm::EcdsaP384, ad_cs_subject(), Some(&FIELD_SKI));
        let child = CertSigner::generate(KeyAlgorithm::EcdsaP256).unwrap();
        let spki_der = child.key_pair().subject_public_key_info();
        let (pem, serial) =
            build_intermediate_ca(cn, org, Duration::from_secs(86_400), &spki_der, &ca.signer, &ca.pem, path_len)
                .expect("sign intermediate");
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        let reference = {
            let rcgen_ca = make_ca(
                KeyAlgorithm::EcdsaP256,
                RdnSequence(vec![rdn(vec![atv(OID_CN, Tag::Utf8String, "Reference CA")])]),
                Some(&FIELD_SKI),
            );
            let kp = KeyPair::from_pem(rcgen_ca.signer.pem_pkcs8()).unwrap();
            let issuer = Issuer::from_ca_cert_pem(&rcgen_ca.pem, kp).unwrap();
            let public_key = rcgen::SubjectPublicKeyInfo::from_der(&spki_der).unwrap();
            params.signed_by(&public_key, &issuer).unwrap().pem()
        };

        let new = x509_cert::Certificate::from_der(&der_of(&pem)).unwrap().tbs_certificate;
        let old = x509_cert::Certificate::from_der(&der_of(&reference)).unwrap().tbs_certificate;
        assert_eq!(new.subject.to_der().unwrap(), old.subject.to_der().unwrap(), "subject DN encoding");
        assert_eq!(new.serial_number, old.serial_number, "serial");
        assert_eq!(new.subject_public_key_info, old.subject_public_key_info, "SPKI");
        let aki = ObjectIdentifier::new_unwrap(OID_AKI);
        let new_exts: Vec<Extension> =
            new.extensions.unwrap_or_default().into_iter().filter(|e| e.extn_id != aki).collect();
        // KU, SKI (same key-id method), BC with pathLen — byte-identical.
        assert_eq!(new_exts, old.extensions.unwrap_or_default(), "intermediate profile matches rcgen");
    }

    // ── fail-closed cases ──────────────────────────────────────────────

    #[test]
    fn non_canonical_ca_subject_is_refused() {
        // Swap the two members of the multi-valued RDN after DER sorting,
        // so the CA subject is BER-ordered. Re-encoding it would silently
        // re-sort, producing an issuer that does not byte-match.
        let cn = atv(OID_CN, Tag::Utf8String, "x").to_der().unwrap();
        let o = atv(OID_O, Tag::Utf8String, "y").to_der().unwrap();
        let sorted: Vec<u8> = [cn.clone(), o.clone()].concat();
        let swapped: Vec<u8> = [o, cn].concat();
        let ca = make_ca_with(KeyAlgorithm::EcdsaP256, multi_valued_subject(), Some(&FIELD_SKI), |mut der| {
            let mut i = 0;
            let mut patched = 0;
            while i + sorted.len() <= der.len() {
                if der[i..i + sorted.len()] == sorted[..] {
                    der[i..i + sorted.len()].copy_from_slice(&swapped);
                    patched += 1;
                    i += sorted.len();
                } else {
                    i += 1;
                }
            }
            assert_eq!(patched, 2, "issuer and subject both patched");
            der
        });
        let leaf_key = CertSigner::generate(KeyAlgorithm::EcdsaP256).unwrap();
        let err = build_leaf(
            &leaf_role(),
            &leaf_subject("ber.example"),
            Duration::from_secs(3600),
            &leaf_key,
            &ca.signer,
            &ca.pem,
            &IssuanceUrls::default(),
        )
        .expect_err("a CA subject that cannot be copied verbatim must be refused");
        assert!(format!("{err:?}").contains("byte-for-byte"), "operator-facing reason: {err:?}");
    }

    #[test]
    fn malformed_ca_ski_is_refused() {
        // An SKI extension whose value is a NULL rather than an OCTET
        // STRING, in an otherwise well-formed CA.
        let base = make_ca(KeyAlgorithm::EcdsaP256, ad_cs_subject(), None);
        let cert = x509_cert::Certificate::from_der(&der_of(&base.pem)).unwrap();
        let mut tbs = cert.tbs_certificate.clone();
        tbs.extensions.as_mut().unwrap().push(Extension {
            extn_id: SubjectKeyIdentifier::OID,
            critical: false,
            extn_value: OctetString::new(vec![0x05, 0x00]).unwrap(),
        });
        let sig = base.signer.key_pair().sign(&tbs.to_der().unwrap()).unwrap();
        let rebuilt = CertificateInner {
            tbs_certificate: tbs,
            signature_algorithm: cert.signature_algorithm.clone(),
            signature: BitString::from_bytes(&sig).unwrap(),
        };
        let ca = TestCa { signer: base.signer, pem: x509_pqc::pem_encode("CERTIFICATE", &rebuilt.to_der().unwrap()) };
        let leaf_key = CertSigner::generate(KeyAlgorithm::EcdsaP256).unwrap();
        let err = build_leaf(
            &leaf_role(),
            &leaf_subject("badski.example"),
            Duration::from_secs(3600),
            &leaf_key,
            &ca.signer,
            &ca.pem,
            &IssuanceUrls::default(),
        )
        .expect_err("a malformed CA SubjectKeyIdentifier must be refused, not ignored");
        assert!(format!("{err:?}").contains("SubjectKeyIdentifier"), "operator-facing reason: {err:?}");
    }
}
