//! Yubico attestation chain verification for YubiHSM 2 keys (T454 phase 7,
//! `features/hsm-pool-ha.md` § Attestation verification). A device signs an
//! attested key's certificate with its attestation key, whose certificate
//! (opaque object 0) a Yubico intermediate signs under a Yubico root. Those
//! Yubico certificates are neither shipped nor fetched: the operator supplies
//! them (`attestation_roots_file`), and without them every attestation fails.

use std::{
    collections::BTreeMap,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};
use x509_parser::{
    asn1_rs::{Any, Class, FromDer, Tag},
    certificate::X509Certificate,
    parse_x509_certificate,
    pem::Pem,
    time::ASN1Time,
};

use crate::errors::RvError;

/// Where an operator gets the Yubico attestation root and intermediates.
pub const YUBICO_ATTESTATION_DOCS_URL: &str = "https://developers.yubico.com/YubiHSM2/Concepts/Attestation.html";
/// YubiHSM 2 object origin "generated on the device" (attestation ext `.3`).
pub const ORIGIN_GENERATED: u8 = 0x01;

/// OID arc of the YubiHSM 2 attestation extensions, `1.3.6.1.4.1.41482.4.<n>`.
const YUBIHSM_ARC: &str = "1.3.6.1.4.1.41482.4.";
const EXT_FIRMWARE: u32 = 1;
const EXT_SERIAL: u32 = 2;
const EXT_ORIGIN: u32 = 3;
const EXT_DOMAINS: u32 = 4;
const EXT_CAPABILITIES: u32 = 5;
const EXT_OBJECT_ID: u32 = 6;
const EXT_LABEL: u32 = 9;

/// Critical extensions a link may carry; any other critical one is refused
/// (RFC 5280 § 4.2: an unrecognized critical extension fails validation).
const KNOWN_CRITICAL: &[&str] = &["2.5.29.19", "2.5.29.15", "2.5.29.37"];
/// Signature algorithms accepted on any link: SHA-2 RSA PKCS#1, ECDSA, Ed25519.
/// SHA-1, MD5 and RSA-PSS are refused rather than verified.
const SIGNATURE_ALGORITHMS: &[(&str, &str)] = &[
    ("1.2.840.113549.1.1.11", "sha256WithRSAEncryption"),
    ("1.2.840.113549.1.1.12", "sha384WithRSAEncryption"),
    ("1.2.840.113549.1.1.13", "sha512WithRSAEncryption"),
    ("1.2.840.10045.4.3.2", "ecdsa-with-SHA256"),
    ("1.2.840.10045.4.3.3", "ecdsa-with-SHA384"),
    ("1.3.101.112", "Ed25519"),
];
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_ED25519: &str = "1.3.101.112";

/// Trust-file certificates above the device certificate, root included.
const MAX_ANCHOR_PATH: usize = 4;
const MAX_ANCHORS_FILE_BYTES: u64 = 1 << 20;

fn invalid(why: impl Into<String>) -> RvError {
    RvError::ErrHsmAttestationInvalid(why.into())
}

/// The refusal when no trust file is configured: says what to set and where
/// the certificates come from, since BastionVault cannot supply them.
pub fn anchors_not_configured() -> RvError {
    invalid(format!(
        "no Yubico attestation trust anchors are configured, so a YubiHSM 2 key cannot be attested: set \
         `attestation_roots_file` in the `hsm \"yubihsm2\"` block to a PEM file holding the Yubico YubiHSM \
         attestation root and intermediate certificates. Download them from Yubico ({YUBICO_ATTESTATION_DOCS_URL}) \
         and check their SHA-256 fingerprints against Yubico's published values; BastionVault neither ships nor \
         fetches them"
    ))
}

fn sha256_hex(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

/// A YubiHSM serial as BastionVault spells it (`yubihsm` 0.42: ten digits).
pub fn format_serial(serial: u32) -> String {
    format!("{serial:010}")
}

/// Parse a configured or reported serial (`36470559` or `0036470559`).
pub fn parse_serial(text: &str) -> Result<u32, RvError> {
    let text = text.trim();
    if text.is_empty() || text.len() > 10 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(format!("{text:?} is not a YubiHSM 2 serial (1-10 decimal digits)")));
    }
    text.parse::<u32>().map_err(|_| invalid(format!("{text:?} does not fit a YubiHSM 2 serial")))
}

/// The attested key's algorithm, from its certificate's public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestedKeyAlgorithm {
    EcP256,
    Ed25519,
    Other,
}

struct AnchorCert {
    der: Vec<u8>,
    sha256: String,
    self_signed: bool,
}

/// The operator's Yubico trust file: one or more self-signed roots plus the
/// intermediates between them and the device certificates.
pub struct YubicoTrustAnchors {
    certs: Vec<AnchorCert>,
    source: String,
}

impl std::fmt::Debug for YubicoTrustAnchors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YubicoTrustAnchors")
            .field("source", &self.source)
            .field("certificates", &self.certs.iter().map(|c| c.sha256.as_str()).collect::<Vec<_>>())
            .finish()
    }
}

impl YubicoTrustAnchors {
    /// Read the trust file. A missing, unreadable, oversized or rootless file
    /// is an error naming the path; nothing falls back to an empty set.
    pub fn load(path: &Path) -> Result<Self, RvError> {
        let source = path.display().to_string();
        let meta = std::fs::metadata(path)
            .map_err(|e| invalid(format!("cannot read the Yubico attestation trust file {source}: {e}")))?;
        if meta.len() > MAX_ANCHORS_FILE_BYTES {
            return Err(invalid(format!("the Yubico attestation trust file {source} is larger than 1 MiB")));
        }
        let pem = std::fs::read(path)
            .map_err(|e| invalid(format!("cannot read the Yubico attestation trust file {source}: {e}")))?;
        Self::from_pem(&pem, &source)
    }

    /// Parse PEM `CERTIFICATE` blocks. Anything else in a block is refused.
    pub fn from_pem(pem: &[u8], source: &str) -> Result<Self, RvError> {
        let mut certs: Vec<AnchorCert> = Vec::new();
        for block in Pem::iter_from_buffer(pem) {
            let block = block.map_err(|e| invalid(format!("{source}: malformed PEM: {e}")))?;
            if block.label != "CERTIFICATE" {
                return Err(invalid(format!("{source}: unexpected PEM block {:?}; only certificates", block.label)));
            }
            let (rest, cert) = parse_x509_certificate(&block.contents)
                .map_err(|e| invalid(format!("{source}: certificate {} does not parse: {e}", certs.len() + 1)))?;
            if !rest.is_empty() {
                return Err(invalid(format!("{source}: trailing bytes after certificate {}", certs.len() + 1)));
            }
            let self_signed = cert.subject().as_raw() == cert.issuer().as_raw() && cert.verify_signature(None).is_ok();
            let sha256 = sha256_hex(&block.contents);
            if certs.iter().any(|c| c.sha256 == sha256) {
                continue;
            }
            certs.push(AnchorCert { der: block.contents, sha256, self_signed });
        }
        if certs.is_empty() {
            return Err(invalid(format!("{source} holds no certificate")));
        }
        if !certs.iter().any(|c| c.self_signed) {
            return Err(invalid(format!(
                "{source} holds no self-signed root: add the Yubico attestation root ({YUBICO_ATTESTATION_DOCS_URL})"
            )));
        }
        Ok(Self { certs, source: source.to_string() })
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    /// SHA-256 of every self-signed root, for the operator to compare.
    pub fn root_fingerprints(&self) -> Vec<String> {
        self.certs.iter().filter(|c| c.self_signed).map(|c| c.sha256.clone()).collect()
    }

    /// Walk from `device` up through trust-file certificates to a
    /// self-signed root; returns that root's fingerprint.
    fn verify_device_certificate(&self, device: &X509Certificate<'_>, now: ASN1Time) -> Result<String, RvError> {
        let mut parsed = Vec::with_capacity(self.certs.len());
        for c in &self.certs {
            let (_, cert) = parse_x509_certificate(&c.der)
                .map_err(|e| invalid(format!("{}: certificate no longer parses: {e}", self.source)))?;
            parsed.push(cert);
        }
        let mut child: &X509Certificate<'_> = device;
        let mut what = "the device attestation certificate".to_string();
        for _ in 0..MAX_ANCHOR_PATH {
            let issuer = parsed
                .iter()
                .enumerate()
                .filter(|(_, a)| a.subject().as_raw() == child.issuer().as_raw())
                .find(|(_, a)| child.verify_signature(Some(a.public_key())).is_ok())
                .map(|(i, _)| i)
                .ok_or_else(|| {
                    invalid(format!(
                        "{what} (issuer {}) is not signed by any certificate in the Yubico trust file {}",
                        child.issuer(),
                        self.source
                    ))
                })?;
            let anchor = &parsed[issuer];
            let label = format!("trust-file certificate {} ({})", self.certs[issuer].sha256, anchor.subject());
            check_link(anchor, &label, now)?;
            require_ca(anchor, &label)?;
            if self.certs[issuer].self_signed {
                return Ok(self.certs[issuer].sha256.clone());
            }
            child = anchor;
            what = label;
        }
        Err(invalid(format!("no root within {MAX_ANCHOR_PATH} trust-file certificates of the device certificate")))
    }
}

/// What a verified attestation says about the key, from the YubiHSM
/// extensions of its certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YubiHsmAttestation {
    pub serial: u32,
    pub object_id: u16,
    pub label: String,
    pub origin: u8,
    pub capabilities: u64,
    pub domains: u16,
    /// `major.minor.build`, when the certificate carries it.
    pub firmware: Option<String>,
    pub algorithm: AttestedKeyAlgorithm,
    /// SEC1-uncompressed point (P-256) or the 32-byte key (Ed25519).
    pub public_key: Vec<u8>,
    pub device_certificate_sha256: String,
    pub root_sha256: String,
}

/// The object `provision` created: what its attestation must say exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedKey<'a> {
    pub serial: u32,
    pub object_id: u16,
    pub label: &'a str,
    pub capabilities: u64,
    pub domains: u16,
    pub algorithm: AttestedKeyAlgorithm,
}

impl YubiHsmAttestation {
    /// Refuse unless every attested property equals `expected`; the error
    /// lists each mismatch.
    pub fn require(&self, expected: &ExpectedKey<'_>) -> Result<(), RvError> {
        let mut wrong = Vec::new();
        if self.serial != expected.serial {
            wrong.push(format!("serial {} (expected {})", self.serial, expected.serial));
        }
        if self.object_id != expected.object_id {
            wrong.push(format!("object {:#06x} (expected {:#06x})", self.object_id, expected.object_id));
        }
        if self.label != expected.label {
            wrong.push(format!("label {:?} (expected {:?})", self.label, expected.label));
        }
        if self.capabilities != expected.capabilities {
            wrong.push(format!("capabilities {:#018x} (expected {:#018x})", self.capabilities, expected.capabilities));
        }
        if self.domains != expected.domains {
            wrong.push(format!("domains {:#06x} (expected {:#06x})", self.domains, expected.domains));
        }
        if self.algorithm != expected.algorithm {
            wrong.push(format!("algorithm {:?} (expected {:?})", self.algorithm, expected.algorithm));
        }
        if wrong.is_empty() {
            Ok(())
        } else {
            Err(invalid(format!("the attestation does not match what provision created: {}", wrong.join(", "))))
        }
    }
}

fn asn1_now(now: SystemTime) -> Result<ASN1Time, RvError> {
    let secs = now.duration_since(UNIX_EPOCH).map_err(|_| invalid("the host clock is before 1970"))?.as_secs();
    ASN1Time::from_timestamp(secs as i64).map_err(|e| invalid(format!("the host clock is out of range: {e}")))
}

/// The attestation is the attested key's certificate followed by the device
/// attestation certificate, both DER. Exactly two: the Yubico intermediates
/// and root come from the trust file, never from the device.
fn parse_chain(chain: &[u8]) -> Result<Vec<X509Certificate<'_>>, RvError> {
    if chain.is_empty() {
        return Err(invalid("the attestation is empty"));
    }
    let mut certs = Vec::new();
    let mut rest = chain;
    while !rest.is_empty() {
        if certs.len() == 2 {
            return Err(invalid(
                "the attestation carries more than the key and device certificates; Yubico intermediates come \
                 from the trust file",
            ));
        }
        let (next, cert) = parse_x509_certificate(rest).map_err(|e| {
            invalid(format!("attestation certificate {} is truncated or malformed: {e}", certs.len() + 1))
        })?;
        certs.push(cert);
        rest = next;
    }
    if certs.len() < 2 {
        return Err(invalid(
            "the attestation is truncated: it holds the key certificate but not the device attestation \
             certificate (object 0); re-run `operator hsm provision` with this build to produce a full bundle",
        ));
    }
    Ok(certs)
}

/// Checks every link gets: v3, an accepted signature algorithm that matches
/// the TBS one, validity at `now`, no unknown critical extension.
fn check_link(cert: &X509Certificate<'_>, what: &str, now: ASN1Time) -> Result<(), RvError> {
    if cert.version().0 != 2 {
        return Err(invalid(format!("{what} is not an X.509 v3 certificate")));
    }
    let alg = cert.signature_algorithm.algorithm.to_id_string();
    if !SIGNATURE_ALGORITHMS.iter().any(|(oid, _)| *oid == alg) {
        return Err(invalid(format!("{what} is signed with an algorithm that is not accepted ({alg})")));
    }
    if cert.tbs_certificate.signature != cert.signature_algorithm {
        return Err(invalid(format!("{what}: the signed and outer signature algorithms differ")));
    }
    if !cert.validity().is_valid_at(now) {
        return Err(invalid(format!(
            "{what} is not valid now (valid {} to {})",
            cert.validity().not_before,
            cert.validity().not_after
        )));
    }
    for ext in cert.extensions() {
        let oid = ext.oid.to_id_string();
        if ext.critical && !KNOWN_CRITICAL.contains(&oid.as_str()) {
            return Err(invalid(format!("{what} carries an unrecognized critical extension {oid}")));
        }
    }
    Ok(())
}

fn require_ca(cert: &X509Certificate<'_>, what: &str) -> Result<(), RvError> {
    let bc = cert.basic_constraints().map_err(|e| invalid(format!("{what}: basic constraints: {e}")))?;
    if !bc.map(|b| b.value.ca).unwrap_or(false) {
        return Err(invalid(format!("{what} is not a CA certificate (basicConstraints CA:TRUE)")));
    }
    let ku = cert.key_usage().map_err(|e| invalid(format!("{what}: key usage: {e}")))?;
    if let Some(ku) = ku {
        if !ku.value.key_cert_sign() {
            return Err(invalid(format!("{what} may not sign certificates (keyUsage lacks keyCertSign)")));
        }
    }
    Ok(())
}

fn yubihsm_extensions<'a>(cert: &'a X509Certificate<'a>) -> Result<BTreeMap<u32, &'a [u8]>, RvError> {
    let mut out = BTreeMap::new();
    for ext in cert.extensions() {
        let oid = ext.oid.to_id_string();
        let Some(suffix) = oid.strip_prefix(YUBIHSM_ARC) else { continue };
        let Ok(n) = suffix.parse::<u32>() else { continue };
        if out.insert(n, ext.value).is_some() {
            return Err(invalid(format!("the key certificate carries YubiHSM extension {oid} twice")));
        }
    }
    Ok(out)
}

fn ext<'a>(exts: &BTreeMap<u32, &'a [u8]>, n: u32) -> Result<&'a [u8], RvError> {
    exts.get(&n).copied().ok_or_else(|| invalid(format!("the key certificate lacks YubiHSM extension {YUBIHSM_ARC}{n}")))
}

/// One universal, primitive DER value filling `bytes`.
fn der_value(bytes: &[u8], n: u32) -> Result<Any<'_>, RvError> {
    let bad = || invalid(format!("YubiHSM extension {YUBIHSM_ARC}{n} is not one DER value"));
    let (rest, any) = Any::from_der(bytes).map_err(|_| bad())?;
    if !rest.is_empty() || any.header.class() != Class::Universal || any.header.is_constructed() {
        return Err(bad());
    }
    Ok(any)
}

fn der_uint(bytes: &[u8], n: u32, max_bytes: usize) -> Result<u64, RvError> {
    let any = der_value(bytes, n)?;
    let data = any.data;
    if any.header.tag() != Tag::Integer || data.is_empty() || data[0] & 0x80 != 0 {
        return Err(invalid(format!("YubiHSM extension {YUBIHSM_ARC}{n} is not a non-negative INTEGER")));
    }
    let digits = if data.len() > 1 && data[0] == 0 { &data[1..] } else { data };
    if digits.len() > max_bytes {
        return Err(invalid(format!("YubiHSM extension {YUBIHSM_ARC}{n} is out of range")));
    }
    Ok(digits.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
}

/// A BIT STRING carrying a `len`-byte big-endian field (origin 1, domains 2,
/// capabilities 8). Read in full, or without its trailing zero bits as DER
/// writes a bit list: both encodings are the same bits, left-aligned, so a
/// device using either is read alike. Longer than `len` bytes, or unused
/// bits that are not zero, is refused. A misread could only refuse, never
/// accept: the value is then compared exactly against the expected profile.
fn der_bits(bytes: &[u8], n: u32, len: usize) -> Result<u64, RvError> {
    debug_assert!((1..=8).contains(&len));
    let any = der_value(bytes, n)?;
    let data = any.data;
    let bad = || invalid(format!("YubiHSM extension {YUBIHSM_ARC}{n} is not a BIT STRING of at most {len} bytes"));
    if any.header.tag() != Tag::BitString || data.is_empty() || data.len() > len + 1 {
        return Err(bad());
    }
    let (unused, body) = (data[0], &data[1..]);
    let padding_is_zero = body.last().map_or(unused == 0, |last| last & ((1u8 << unused.min(7)) - 1) == 0);
    if unused > 7 || !padding_is_zero {
        return Err(bad());
    }
    let mut field = [0u8; 8];
    field[..body.len()].copy_from_slice(body);
    Ok(field[..len].iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
}

fn der_text(bytes: &[u8], n: u32) -> Result<String, RvError> {
    let any = der_value(bytes, n)?;
    let text_tags = [Tag::Utf8String, Tag::PrintableString, Tag::Ia5String, Tag::OctetString];
    if !text_tags.contains(&any.header.tag()) {
        return Err(invalid(format!("YubiHSM extension {YUBIHSM_ARC}{n} is not a string")));
    }
    let text = std::str::from_utf8(any.data)
        .map_err(|_| invalid(format!("YubiHSM extension {YUBIHSM_ARC}{n} is not UTF-8")))?;
    // Labels are a fixed 40-byte field on the device, NUL-padded.
    Ok(text.trim_end_matches('\0').to_string())
}

fn der_firmware(bytes: &[u8]) -> Result<String, RvError> {
    let any = der_value(bytes, EXT_FIRMWARE)?;
    if any.header.tag() != Tag::OctetString || any.data.len() != 3 {
        return Err(invalid(format!("YubiHSM extension {YUBIHSM_ARC}{EXT_FIRMWARE} is not a 3-byte version")));
    }
    Ok(format!("{}.{}.{}", any.data[0], any.data[1], any.data[2]))
}

fn attested_key(cert: &X509Certificate<'_>) -> Result<(AttestedKeyAlgorithm, Vec<u8>), RvError> {
    let spki = cert.public_key();
    let key: &[u8] = &spki.subject_public_key.data;
    let alg = spki.algorithm.algorithm.to_id_string();
    let curve = spki.algorithm.parameters.as_ref().and_then(|p| p.as_oid().ok()).map(|o| o.to_id_string());
    match (alg.as_str(), curve.as_deref()) {
        (OID_EC_PUBLIC_KEY, Some(OID_P256)) => {
            if key.len() != 65 || key[0] != 0x04 {
                return Err(invalid("the attested P-256 key is not an uncompressed point"));
            }
            Ok((AttestedKeyAlgorithm::EcP256, key.to_vec()))
        }
        (OID_ED25519, _) => {
            if key.len() != 32 {
                return Err(invalid("the attested Ed25519 key is not 32 bytes"));
            }
            Ok((AttestedKeyAlgorithm::Ed25519, key.to_vec()))
        }
        _ => Ok((AttestedKeyAlgorithm::Other, key.to_vec())),
    }
}

/// Verify a YubiHSM 2 attestation (`key certificate ‖ device certificate`,
/// DER) against the operator's Yubico trust file at time `now`. Refuses any
/// break in the chain, an unaccepted algorithm, an expired link, a key that
/// was not generated on the device, or missing / malformed YubiHSM extensions.
pub fn verify_chain(
    anchors: &YubicoTrustAnchors,
    chain: &[u8],
    now: SystemTime,
) -> Result<YubiHsmAttestation, RvError> {
    let now = asn1_now(now)?;
    let certs = parse_chain(chain)?;
    let (leaf, device) = (&certs[0], &certs[1]);
    check_link(leaf, "the attested key's certificate", now)?;
    check_link(device, "the device attestation certificate", now)?;
    if leaf.basic_constraints().ok().flatten().map(|b| b.value.ca).unwrap_or(false) {
        return Err(invalid("the attested key's certificate claims to be a CA"));
    }
    if leaf.issuer().as_raw() != device.subject().as_raw() || leaf.verify_signature(Some(device.public_key())).is_err()
    {
        return Err(invalid("the attested key's certificate is not signed by the device attestation certificate"));
    }
    // The device certificate's own position is fixed: it must be issued by a
    // trust-file certificate. A key certificate (issued by a device key, which
    // is never in the trust file) therefore cannot stand in for it.
    let root_sha256 = anchors.verify_device_certificate(device, now)?;

    let exts = yubihsm_extensions(leaf)?;
    let serial = u32::try_from(der_uint(ext(&exts, EXT_SERIAL)?, EXT_SERIAL, 4)?)
        .map_err(|_| invalid("the attested serial is out of range"))?;
    let origin = der_bits(ext(&exts, EXT_ORIGIN)?, EXT_ORIGIN, 1)? as u8;
    if origin != ORIGIN_GENERATED {
        return Err(invalid(format!(
            "the attested key's origin is {origin:#04x}, not generated on the device ({ORIGIN_GENERATED:#04x}): an \
             imported or re-imported key is never a pool key"
        )));
    }
    let domains = der_bits(ext(&exts, EXT_DOMAINS)?, EXT_DOMAINS, 2)? as u16;
    let capabilities = der_bits(ext(&exts, EXT_CAPABILITIES)?, EXT_CAPABILITIES, 8)?;
    let object_id = u16::try_from(der_uint(ext(&exts, EXT_OBJECT_ID)?, EXT_OBJECT_ID, 2)?)
        .map_err(|_| invalid("the attested object id is out of range"))?;
    let label = der_text(ext(&exts, EXT_LABEL)?, EXT_LABEL)?;
    // Reported, never decided on: an unexpected encoding reads as `None`
    // rather than refusing a chain over a display field.
    let firmware = exts.get(&EXT_FIRMWARE).and_then(|v| der_firmware(v).ok());
    let (algorithm, public_key) = attested_key(leaf)?;

    Ok(YubiHsmAttestation {
        serial,
        object_id,
        label,
        origin,
        capabilities,
        domains,
        firmware,
        algorithm,
        public_key,
        device_certificate_sha256: sha256_hex(device.as_raw()),
        root_sha256,
    })
}

/// Public facts about one DER certificate (the device attestation
/// certificate in a phase 7 snapshot). Never holds key material.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CertificateSummary {
    pub sha256: String,
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
}

pub fn certificate_summary(der: &[u8]) -> Result<CertificateSummary, RvError> {
    let (_, cert) = parse_x509_certificate(der).map_err(|e| invalid(format!("certificate does not parse: {e}")))?;
    Ok(CertificateSummary {
        sha256: sha256_hex(der),
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        not_before: cert.validity().not_before.to_string(),
        not_after: cert.validity().not_after.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rcgen::{
        date_time_ymd, BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, Issuer, KeyPair,
        KeyUsagePurpose, SignatureAlgorithm, PKCS_ECDSA_P256_SHA256, PKCS_ED25519,
    };

    use super::*;

    const SERIAL: u32 = 36_470_559;
    const SIGN_ECDSA: u64 = 0x80;
    const SIGN_EDDSA: u64 = 0x100;
    const EXPORTABLE_UNDER_WRAP: u64 = 0x1_0000;

    // ---- DER encoders for the YubiHSM extensions ----

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        assert!(body.len() < 128);
        let mut v = vec![tag, body.len() as u8];
        v.extend_from_slice(body);
        v
    }
    fn der_int(value: u64) -> Vec<u8> {
        let mut bytes: Vec<u8> = value.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        if bytes.is_empty() || bytes[0] & 0x80 != 0 {
            bytes.insert(0, 0);
        }
        tlv(0x02, &bytes)
    }
    fn der_bitstring(bytes: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8];
        body.extend_from_slice(bytes);
        tlv(0x03, &body)
    }
    fn yubi_ext(n: u64, content: Vec<u8>) -> CustomExtension {
        CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 41482, 4, n], content)
    }

    // ---- fake Yubico PKI ----

    struct Node {
        params: CertificateParams,
        key: KeyPair,
        der: Vec<u8>,
        pem: String,
    }

    impl Node {
        fn issuer(&self) -> Issuer<'_, &KeyPair> {
            Issuer::from_params(&self.params, &self.key)
        }
    }

    fn ca_params(name: &str) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = date_time_ymd(2020, 1, 1);
        params.not_after = date_time_ymd(2090, 1, 1);
        params
    }

    fn root(name: &str) -> Node {
        let params = ca_params(name);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key).unwrap();
        Node { der: cert.der().to_vec(), pem: cert.pem(), params, key }
    }

    fn signed(params: CertificateParams, alg: &'static SignatureAlgorithm, by: &Node) -> Node {
        let key = KeyPair::generate_for(alg).unwrap();
        let cert = params.signed_by(&key, &by.issuer()).unwrap();
        Node { der: cert.der().to_vec(), pem: cert.pem(), params, key }
    }

    /// The device certificate as Yubico issues it: not a CA by extension.
    fn device_params(serial: u32) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, format!("YubiHSM Attestation id:{serial}"));
        params.not_before = date_time_ymd(2024, 1, 1);
        params.not_after = date_time_ymd(2071, 1, 1);
        params
    }

    #[derive(Clone)]
    struct Leaf {
        serial: u32,
        origin: u8,
        capabilities: u64,
        domains: u16,
        object_id: u16,
        label: &'static str,
        not_after: (i32, u8, u8),
    }

    impl Leaf {
        fn identity() -> Self {
            Self {
                serial: SERIAL,
                origin: ORIGIN_GENERATED,
                capabilities: SIGN_ECDSA,
                domains: 0x0002,
                object_id: 4,
                label: "bv-identity",
                not_after: (2071, 1, 1),
            }
        }
        fn params(&self) -> CertificateParams {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.distinguished_name = rcgen::DistinguishedName::new();
            params.distinguished_name.push(DnType::CommonName, "YubiHSM Attestation");
            params.not_before = date_time_ymd(2024, 1, 1);
            params.not_after = date_time_ymd(self.not_after.0, self.not_after.1, self.not_after.2);
            params.custom_extensions = vec![
                yubi_ext(1, tlv(0x04, &[2, 4, 1])),
                yubi_ext(2, der_int(u64::from(self.serial))),
                yubi_ext(3, der_bitstring(&[self.origin])),
                yubi_ext(4, der_bitstring(&self.domains.to_be_bytes())),
                yubi_ext(5, der_bitstring(&self.capabilities.to_be_bytes())),
                yubi_ext(6, der_int(u64::from(self.object_id))),
                yubi_ext(9, tlv(0x0c, self.label.as_bytes())),
            ];
            params
        }
    }

    struct Pki {
        root: Node,
        intermediate: Node,
        device: Node,
    }

    impl Pki {
        fn new() -> Self {
            let root = root("Yubico Test Attestation Root");
            let intermediate = signed(ca_params("Yubico Test Attestation Intermediate"), &PKCS_ECDSA_P256_SHA256, &root);
            let device = signed(device_params(SERIAL), &PKCS_ECDSA_P256_SHA256, &intermediate);
            Self { root, intermediate, device }
        }

        fn anchors(&self) -> YubicoTrustAnchors {
            let pem = format!("{}{}", self.root.pem, self.intermediate.pem);
            YubicoTrustAnchors::from_pem(pem.as_bytes(), "test-anchors.pem").unwrap()
        }

        fn chain(&self, leaf: &Leaf, alg: &'static SignatureAlgorithm) -> (Vec<u8>, Node) {
            let leaf = signed(leaf.params(), alg, &self.device);
            let mut chain = leaf.der.clone();
            chain.extend_from_slice(&self.device.der);
            (chain, leaf)
        }
    }

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_793_000_000) // 2026-10
    }

    fn expected(object_id: u16, label: &str, caps: u64, domains: u16, alg: AttestedKeyAlgorithm) -> ExpectedKey<'_> {
        ExpectedKey { serial: SERIAL, object_id, label, capabilities: caps, domains, algorithm: alg }
    }

    fn refusal(r: Result<YubiHsmAttestation, RvError>) -> String {
        match r {
            Ok(a) => panic!("accepted: {a:?}"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn a_genuine_chain_is_accepted_and_read() {
        let pki = Pki::new();
        let (chain, leaf) = pki.chain(&Leaf::identity(), &PKCS_ECDSA_P256_SHA256);
        let a = verify_chain(&pki.anchors(), &chain, now()).unwrap();
        assert_eq!((a.serial, a.object_id, a.label.as_str()), (SERIAL, 4, "bv-identity"));
        assert_eq!((a.origin, a.capabilities, a.domains), (ORIGIN_GENERATED, SIGN_ECDSA, 0x0002));
        assert_eq!(a.firmware.as_deref(), Some("2.4.1"));
        assert_eq!(a.algorithm, AttestedKeyAlgorithm::EcP256);
        assert_eq!(a.public_key, leaf.key.public_key_raw(), "the attested key is the leaf's");
        assert_eq!(a.root_sha256, sha256_hex(&pki.root.der));
        assert_eq!(a.device_certificate_sha256, sha256_hex(&pki.device.der));
        a.require(&expected(4, "bv-identity", SIGN_ECDSA, 0x0002, AttestedKeyAlgorithm::EcP256)).unwrap();

        // Ed25519 (bv-authz) reads the same way.
        let authz = Leaf { capabilities: SIGN_EDDSA, domains: 1, object_id: 7, label: "bv-authz", ..Leaf::identity() };
        let (chain, leaf) = pki.chain(&authz, &PKCS_ED25519);
        let a = verify_chain(&pki.anchors(), &chain, now()).unwrap();
        assert_eq!(a.algorithm, AttestedKeyAlgorithm::Ed25519);
        assert_eq!(a.public_key, leaf.key.public_key_raw());
        a.require(&expected(7, "bv-authz", SIGN_EDDSA, 1, AttestedKeyAlgorithm::Ed25519)).unwrap();
    }

    #[test]
    fn a_chain_to_another_root_is_refused() {
        let pki = Pki::new();
        let (chain, _) = pki.chain(&Leaf::identity(), &PKCS_ECDSA_P256_SHA256);
        // Same names, different keys: a look-alike Yubico PKI.
        let other = Pki::new();
        let err = refusal(verify_chain(&other.anchors(), &chain, now()));
        assert!(err.contains("not signed by any certificate in the Yubico trust file"), "{err}");
        // A trust file with only the right root but not the intermediate.
        let root_only = YubicoTrustAnchors::from_pem(pki.root.pem.as_bytes(), "root-only.pem").unwrap();
        assert!(verify_chain(&root_only, &chain, now()).is_err());
    }

    #[test]
    fn a_wrong_serial_or_profile_is_refused() {
        let pki = Pki::new();
        let other_device = Leaf { serial: 36_470_560, ..Leaf::identity() };
        let (chain, _) = pki.chain(&other_device, &PKCS_ECDSA_P256_SHA256);
        let a = verify_chain(&pki.anchors(), &chain, now()).unwrap();
        let err = a
            .require(&expected(4, "bv-identity", SIGN_ECDSA, 2, AttestedKeyAlgorithm::EcP256))
            .unwrap_err()
            .to_string();
        assert!(err.contains("serial 36470560 (expected 36470559)"), "{err}");

        let exportable = Leaf { capabilities: SIGN_ECDSA | EXPORTABLE_UNDER_WRAP, ..Leaf::identity() };
        let (chain, _) = pki.chain(&exportable, &PKCS_ECDSA_P256_SHA256);
        let err = verify_chain(&pki.anchors(), &chain, now())
            .unwrap()
            .require(&expected(4, "bv-identity", SIGN_ECDSA, 2, AttestedKeyAlgorithm::EcP256))
            .unwrap_err()
            .to_string();
        assert!(err.contains("capabilities"), "{err}");

        let wrong_domain = Leaf { domains: 1, ..Leaf::identity() };
        let (chain, _) = pki.chain(&wrong_domain, &PKCS_ECDSA_P256_SHA256);
        let a = verify_chain(&pki.anchors(), &chain, now()).unwrap();
        assert!(a.require(&expected(4, "bv-identity", SIGN_ECDSA, 2, AttestedKeyAlgorithm::EcP256)).is_err());
        // The right profile with the wrong algorithm (an Ed25519 key in the identity slot).
        let (chain, _) = pki.chain(&Leaf::identity(), &PKCS_ED25519);
        let a = verify_chain(&pki.anchors(), &chain, now()).unwrap();
        assert!(a.require(&expected(4, "bv-identity", SIGN_ECDSA, 2, AttestedKeyAlgorithm::EcP256)).is_err());
    }

    #[test]
    fn an_expired_link_is_refused() {
        let pki = Pki::new();
        let expired = Leaf { not_after: (2025, 1, 1), ..Leaf::identity() };
        let (chain, _) = pki.chain(&expired, &PKCS_ECDSA_P256_SHA256);
        assert!(refusal(verify_chain(&pki.anchors(), &chain, now())).contains("not valid now"));
        // And every link is dated: the whole chain before its first day.
        let (chain, _) = pki.chain(&Leaf::identity(), &PKCS_ECDSA_P256_SHA256);
        let before = UNIX_EPOCH + Duration::from_secs(1_600_000_000); // 2020-09
        assert!(refusal(verify_chain(&pki.anchors(), &chain, before)).contains("not valid now"));
    }

    #[test]
    fn a_key_not_generated_on_the_device_is_refused() {
        let pki = Pki::new();
        for origin in [0x02u8, 0x11, 0x12, 0x00] {
            let leaf = Leaf { origin, ..Leaf::identity() };
            let (chain, _) = pki.chain(&leaf, &PKCS_ECDSA_P256_SHA256);
            let err = refusal(verify_chain(&pki.anchors(), &chain, now()));
            assert!(err.contains("not generated on the device"), "origin {origin:#x}: {err}");
        }
    }

    #[test]
    fn a_truncated_or_padded_attestation_is_refused() {
        let pki = Pki::new();
        let (chain, leaf) = pki.chain(&Leaf::identity(), &PKCS_ECDSA_P256_SHA256);
        assert!(refusal(verify_chain(&pki.anchors(), &[], now())).contains("empty"));
        assert!(refusal(verify_chain(&pki.anchors(), &leaf.der, now())).contains("truncated"), "leaf only");
        let cut = &chain[..chain.len() - 10];
        assert!(refusal(verify_chain(&pki.anchors(), cut, now())).contains("truncated or malformed"));
        let cut = &chain[..leaf.der.len() / 2];
        assert!(refusal(verify_chain(&pki.anchors(), cut, now())).contains("truncated or malformed"));
        let mut padded = chain.clone();
        padded.extend_from_slice(&pki.intermediate.der);
        assert!(refusal(verify_chain(&pki.anchors(), &padded, now())).contains("more than the key and device"));
    }

    #[test]
    fn a_tampered_or_misplaced_link_is_refused() {
        let pki = Pki::new();
        let (mut chain, leaf) = pki.chain(&Leaf::identity(), &PKCS_ECDSA_P256_SHA256);
        // Flip a bit inside the leaf's signature value (its last bytes).
        let at = leaf.der.len() - 3;
        chain[at] ^= 0x01;
        assert!(verify_chain(&pki.anchors(), &chain, now()).is_err());

        // A key certificate standing in for the device certificate: a genuine
        // attested key signs a forged "attestation" claiming another serial.
        let (_, attested) = pki.chain(&Leaf::identity(), &PKCS_ECDSA_P256_SHA256);
        let forged = signed(Leaf { serial: 1, ..Leaf::identity() }.params(), &PKCS_ECDSA_P256_SHA256, &attested);
        let mut chain = forged.der.clone();
        chain.extend_from_slice(&attested.der);
        assert!(refusal(verify_chain(&pki.anchors(), &chain, now())).contains("not signed by any certificate"));

        // An intermediate that is not a CA cannot carry the chain.
        let root = root("Yubico Test Attestation Root");
        let mut not_ca = device_params(0);
        not_ca.distinguished_name = rcgen::DistinguishedName::new();
        not_ca.distinguished_name.push(DnType::CommonName, "Not A CA");
        let not_ca = signed(not_ca, &PKCS_ECDSA_P256_SHA256, &root);
        let device = signed(device_params(SERIAL), &PKCS_ECDSA_P256_SHA256, &not_ca);
        let pki2 = Pki { root, intermediate: not_ca, device };
        let (chain, _) = pki2.chain(&Leaf::identity(), &PKCS_ECDSA_P256_SHA256);
        assert!(refusal(verify_chain(&pki2.anchors(), &chain, now())).contains("not a CA certificate"));
    }

    #[test]
    fn missing_or_malformed_extensions_are_refused() {
        let pki = Pki::new();
        let mut params = Leaf::identity().params();
        params.custom_extensions.retain(|e| e.oid_components().last() != Some(3));
        let leaf = signed(params, &PKCS_ECDSA_P256_SHA256, &pki.device);
        let chain = [leaf.der.clone(), pki.device.der.clone()].concat();
        assert!(refusal(verify_chain(&pki.anchors(), &chain, now())).contains("lacks YubiHSM extension"));

        // Capabilities longer than 8 bytes, or with non-zero unused bits.
        for bad in [vec![0u8; 10], vec![3, 0x80, 0x01]] {
            let mut params = Leaf::identity().params();
            params.custom_extensions[4] = yubi_ext(5, tlv(0x03, &bad));
            let leaf = signed(params, &PKCS_ECDSA_P256_SHA256, &pki.device);
            let chain = [leaf.der.clone(), pki.device.der.clone()].concat();
            let err = refusal(verify_chain(&pki.anchors(), &chain, now()));
            assert!(err.contains("BIT STRING of at most 8 bytes"), "{bad:?}: {err}");
        }

        // A malformed firmware field is reported as unknown, not refused.
        let mut params = Leaf::identity().params();
        params.custom_extensions[0] = yubi_ext(1, tlv(0x04, &[2, 4]));
        let leaf = signed(params, &PKCS_ECDSA_P256_SHA256, &pki.device);
        let chain = [leaf.der.clone(), pki.device.der.clone()].concat();
        assert_eq!(verify_chain(&pki.anchors(), &chain, now()).unwrap().firmware, None);

        let mut params = Leaf::identity().params();
        let mut critical = yubi_ext(77, tlv(0x05, &[]));
        critical.set_criticality(true);
        params.custom_extensions.push(critical);
        let leaf = signed(params, &PKCS_ECDSA_P256_SHA256, &pki.device);
        let chain = [leaf.der.clone(), pki.device.der.clone()].concat();
        assert!(refusal(verify_chain(&pki.anchors(), &chain, now())).contains("unrecognized critical extension"));
    }

    /// The device may write a field in full or DER-minimal (trailing zero
    /// bits dropped); both are the same bits and must read the same value.
    #[test]
    fn a_der_minimal_bit_string_reads_as_the_full_field() {
        let pki = Pki::new();
        let read = |domains: &[u8], capabilities: Option<&[u8]>| {
            let mut params = Leaf::identity().params();
            params.custom_extensions[3] = yubi_ext(4, tlv(0x03, domains));
            if let Some(caps) = capabilities {
                params.custom_extensions[4] = yubi_ext(5, tlv(0x03, caps));
            }
            let leaf = signed(params, &PKCS_ECDSA_P256_SHA256, &pki.device);
            let chain = [leaf.der.clone(), pki.device.der.clone()].concat();
            let a = verify_chain(&pki.anchors(), &chain, now()).unwrap();
            (a.domains, a.capabilities)
        };
        // Domain 2 (0x0002) with its one trailing zero bit dropped.
        assert_eq!(read(&[1, 0x00, 0x02], None), (0x0002, SIGN_ECDSA));
        // Domain 9 (0x0100) and bit 32 of the capabilities, trailing zero bytes dropped.
        assert_eq!(read(&[0, 0x01], Some(&[0, 0, 0, 0, 0x01])), (0x0100, 0x0000_0001_0000_0000));
        // The full-width encodings of the same values.
        assert_eq!(
            read(&[0, 0x01, 0x00], Some(&[0, 0, 0, 0, 0x01, 0, 0, 0, 0])),
            (0x0100, 0x0000_0001_0000_0000)
        );
    }

    #[test]
    fn the_trust_file_must_hold_a_root_and_only_certificates() {
        let pki = Pki::new();
        let err = YubicoTrustAnchors::from_pem(pki.intermediate.pem.as_bytes(), "x.pem").unwrap_err().to_string();
        assert!(err.contains("no self-signed root") && err.contains(YUBICO_ATTESTATION_DOCS_URL), "{err}");
        assert!(YubicoTrustAnchors::from_pem(b"", "x.pem").is_err());
        let key = format!("{}{}", pki.root.pem, pki.root.key.serialize_pem());
        assert!(YubicoTrustAnchors::from_pem(key.as_bytes(), "x.pem").unwrap_err().to_string().contains("PRIVATE KEY"));
        let missing = YubicoTrustAnchors::load(Path::new("/nonexistent/yubico-roots.pem")).unwrap_err().to_string();
        assert!(missing.contains("/nonexistent/yubico-roots.pem"), "{missing}");
        let anchors = pki.anchors();
        assert_eq!(anchors.root_fingerprints(), vec![sha256_hex(&pki.root.der)]);

        let unconfigured = anchors_not_configured().to_string();
        assert!(unconfigured.contains("attestation_roots_file") && unconfigured.contains(YUBICO_ATTESTATION_DOCS_URL));
    }

    #[test]
    fn serials_parse_in_both_spellings() {
        assert_eq!(parse_serial("36470559").unwrap(), SERIAL);
        assert_eq!(parse_serial("0036470559").unwrap(), SERIAL);
        assert_eq!(format_serial(SERIAL), "0036470559");
        for bad in ["", "abc", "00364705591", "-1", "99999999999"] {
            assert!(parse_serial(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_summary_names_the_certificate() {
        let pki = Pki::new();
        let s = certificate_summary(&pki.device.der).unwrap();
        assert_eq!(s.sha256, sha256_hex(&pki.device.der));
        assert!(s.subject.contains("YubiHSM Attestation id:36470559") && s.issuer.contains("Intermediate"), "{s:?}");
    }
}
