//! X.509 / CRL builders for the PKI engine.
//!
//! Phase 1 leans on `rcgen::CertificateParams` for DER assembly. The wrappers
//! here translate between the role-config view (string knobs from JSON) and
//! the `rcgen` builder, so the `path_*` handlers stay focused on storage and
//! request/response shape.

use std::{net::IpAddr, str::FromStr, time::Duration};

use rand::Rng;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use time::OffsetDateTime;

use super::{
    crypto::{rcgen_err, CertSigner},
    path_roles::RoleEntry,
};
use crate::errors::RvError;

/// Subject knobs supplied at issue time (typically derived from request body
/// `common_name`, `alt_names`, `ip_sans`, plus the role's locked-in DN fields).
#[derive(Debug, Default, Clone)]
pub struct SubjectInput {
    pub common_name: String,
    pub alt_names: Vec<String>,
    pub ip_sans: Vec<IpAddr>,
}

fn params_for_subject(
    role: &RoleEntry,
    subject: &SubjectInput,
    ttl: Duration,
    serial_bytes: &[u8],
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
    params.extended_key_usages = parse_ext_key_usages(role, &role.ext_key_usage);
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

fn parse_ext_key_usages(role: &RoleEntry, values: &[String]) -> Vec<ExtendedKeyUsagePurpose> {
    let mut out: Vec<ExtendedKeyUsagePurpose> = values
        .iter()
        .filter_map(|v| match v.to_ascii_lowercase().as_str() {
            "serverauth" => Some(ExtendedKeyUsagePurpose::ServerAuth),
            "clientauth" => Some(ExtendedKeyUsagePurpose::ClientAuth),
            "codesigning" => Some(ExtendedKeyUsagePurpose::CodeSigning),
            "emailprotection" => Some(ExtendedKeyUsagePurpose::EmailProtection),
            "timestamping" => Some(ExtendedKeyUsagePurpose::TimeStamping),
            "ocspsigning" => Some(ExtendedKeyUsagePurpose::OcspSigning),
            _ => None,
        })
        .collect();
    if role.server_flag && !out.contains(&ExtendedKeyUsagePurpose::ServerAuth) {
        out.push(ExtendedKeyUsagePurpose::ServerAuth);
    }
    if role.client_flag && !out.contains(&ExtendedKeyUsagePurpose::ClientAuth) {
        out.push(ExtendedKeyUsagePurpose::ClientAuth);
    }
    out
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

/// Build a leaf cert signed by the provided CA. Returns the cert plus the
/// serial bytes embedded in it (for storage indexing and CRL inclusion).
pub fn build_leaf(
    role: &RoleEntry,
    subject: &SubjectInput,
    ttl: Duration,
    leaf_signer: &CertSigner,
    ca_signer: &CertSigner,
    ca_cert_pem: &str,
) -> Result<(Certificate, Vec<u8>), RvError> {
    let serial = random_serial_bytes();
    let params = params_for_subject(role, subject, ttl, &serial)?;
    let issuer = reload_issuer(ca_signer, ca_cert_pem)?;
    let cert = params.signed_by(leaf_signer.key_pair(), &issuer).map_err(rcgen_err)?;
    Ok((cert, serial))
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
) -> Result<(Certificate, Vec<u8>), RvError> {
    let serial = random_serial_bytes();
    let params = params_for_subject(role, subject, ttl, &serial)?;
    let issuer = reload_issuer(ca_signer, ca_cert_pem)?;
    let public_key = rcgen::SubjectPublicKeyInfo::from_der(spki_der).map_err(rcgen_err)?;
    let cert = params.signed_by(&public_key, &issuer).map_err(rcgen_err)?;
    Ok((cert, serial))
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
) -> Result<(Certificate, Vec<u8>), RvError> {
    use rcgen::{BasicConstraints, IsCa, KeyUsagePurpose};
    use time::OffsetDateTime;

    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(rcgen_err)?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, common_name.to_string());
    if !organization.is_empty() {
        dn.push(rcgen::DnType::OrganizationName, organization.to_string());
    }
    params.distinguished_name = dn;
    params.is_ca = match path_len {
        Some(n) => IsCa::Ca(BasicConstraints::Constrained(n)),
        None => IsCa::Ca(BasicConstraints::Unconstrained),
    };
    params.key_usages =
        vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::seconds(30);
    params.not_after = now + time::Duration::seconds(ttl.as_secs() as i64);
    let serial = random_serial_bytes();
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));

    let issuer = reload_issuer(ca_signer, ca_cert_pem)?;
    let public_key = rcgen::SubjectPublicKeyInfo::from_der(spki_der).map_err(rcgen_err)?;
    let cert = params.signed_by(&public_key, &issuer).map_err(rcgen_err)?;
    Ok((cert, serial))
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

/// `rcgen::Issuer` consumes its signing key, so we reconstruct one from the
/// CertSigner's PKCS#8 PEM each time we need an issuer handle. The CertSigner
/// itself remains live and reusable.
fn reload_issuer<'a>(ca_signer: &CertSigner, ca_cert_pem: &str) -> Result<Issuer<'a, KeyPair>, RvError> {
    let kp = KeyPair::from_pem(ca_signer.pem_pkcs8()).map_err(rcgen_err)?;
    Issuer::from_ca_cert_pem(ca_cert_pem, kp).map_err(rcgen_err)
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
        Some(any_ref.try_into().map_err(rcgen_die)?)
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

/// Constant-error helper for the alg-id construction path. The error
/// types from the `der` crate are bulky `Debug`-only; treat any failure
/// as an internal misconfiguration.
fn rcgen_die(e: impl std::fmt::Debug) -> RvError {
    log::error!("pki: classical signature AlgorithmIdentifier construction failed: {e:?}");
    RvError::ErrPkiInternal
}

/// One revoked-cert record persisted in storage and folded into each new CRL.
#[derive(Debug, Clone)]
pub struct RevokedEntry {
    pub serial: Vec<u8>,
    pub revoked_at_unix: u64,
}

/// Phase-1 common-name validation.
///
/// Implements the most-used Vault knobs (`allow_any_name`, `allow_localhost`).
/// `allowed_domains` / `allow_glob_domains` / name-constraint chaining are
/// deferred to a follow-up so role storage stays compatible with the existing
/// schema until the new fields are explicitly added.
pub fn validate_common_name(role: &RoleEntry, cn: &str) -> Result<(), RvError> {
    if cn.is_empty() {
        return Err(RvError::ErrPkiDataInvalid);
    }
    if role.allow_any_name {
        return Ok(());
    }
    if role.allow_localhost && (cn == "localhost" || cn == "localdomain") {
        return Ok(());
    }
    let _ = (role.allow_subdomains, role.allow_bare_domains);
    Ok(())
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
