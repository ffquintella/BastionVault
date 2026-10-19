//! `issuer/<ref>/renew` — re-issue an issuer's CA certificate for the same
//! key and subject with a fresh validity (T455). Only the serial, validity
//! and signature change. Rules, storage order and trade-offs: see
//! `features/pki-key-management-and-lifecycle.md`, "Issuer renewal".

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use const_oid::AssociatedOid as _;
use rcgen::{PublicKeyData as _, SigningKey as _};
use x509_cert::{
    certificate::Version,
    der::{asn1::BitString, Decode, Encode},
    ext::{pkix::AuthorityKeyIdentifier, Extension},
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    time::Validity,
    Certificate,
};

use super::{
    crypto::{rcgen_err, Signer},
    issuers::{self, IssuerHandle},
    storage::{self, IssuerCertHistory, IssuerCertHistoryEntry, ISSUER_CERT_HISTORY_FORMAT_VERSION},
    x509, x509_pqc,
};
use crate::{errors::RvError, logical::Request};

/// `notBefore` backdate, as root and intermediate generation use.
const RENEW_BACKDATE: Duration = Duration::from_secs(30);

/// 9999-12-31T23:59:59Z, the last instant RFC 5280 §4.1.2.5 can encode.
const MAX_NOT_AFTER_UNIX: u64 = 253_402_300_799;

/// The validity the operator asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewLifetime {
    /// Keep the current certificate's `notAfter - notBefore`, starting now.
    SameSpan,
    /// End `ttl` from now.
    Ttl(Duration),
}

/// Who signed the renewed certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewedBy {
    /// The issuer's own key (a self-signed issuer).
    SelfSigned,
    /// A parent issuer on the same mount.
    Parent { id: String, name: String },
}

/// Result of [`renew_issuer`]. Public material only.
#[derive(Debug, Clone)]
pub struct RenewOutcome {
    pub issuer_id: String,
    pub issuer_name: String,
    pub certificate_pem: String,
    pub serial_hex: String,
    pub not_before_unix: i64,
    pub not_after_unix: i64,
    pub previous_serial_hex: String,
    pub previous_not_after_unix: i64,
    pub renewed_by: RenewedBy,
    /// `true` when the parent's own `notAfter` cut the requested lifetime.
    pub ttl_clamped: bool,
}

// ── signing seam ──────────────────────────────────────────────────────

/// The signature `AlgorithmIdentifier` a signer emits and the public key a
/// CA certificate must certify for it.
struct SigningIdentity {
    alg_id: AlgorithmIdentifierOwned,
    spki: SubjectPublicKeyInfoOwned,
}

fn signing_identity(signer: &Signer) -> Result<SigningIdentity, RvError> {
    match signer {
        Signer::Classical(cs) => Ok(SigningIdentity {
            alg_id: x509::certificate_signature_alg_id(cs)?,
            spki: x509::decode_spki(&cs.key_pair().subject_public_key_info())?,
        }),
        Signer::MlDsa(ml) => {
            ml.ensure_public_key_matches_seed()?;
            let alg_id = AlgorithmIdentifierOwned { oid: ml.level().oid(), parameters: None };
            let spki = SubjectPublicKeyInfoOwned {
                algorithm: alg_id.clone(),
                subject_public_key: BitString::from_bytes(ml.public_key()).map_err(x509_pqc::der_err)?,
            };
            Ok(SigningIdentity { alg_id, spki })
        }
        #[cfg(feature = "pki_pqc_composite")]
        Signer::Composite(c) => {
            c.pqc().ensure_public_key_matches_seed()?;
            Ok(SigningIdentity {
                alg_id: super::x509_composite::composite_alg_id(c),
                spki: super::x509_composite::composite_spki(c)?,
            })
        }
    }
}

fn sign_with(signer: &Signer, tbs_der: &[u8]) -> Result<Vec<u8>, RvError> {
    match signer {
        Signer::Classical(cs) => cs.key_pair().sign(tbs_der).map_err(rcgen_err),
        Signer::MlDsa(ml) => ml.sign(tbs_der),
        #[cfg(feature = "pki_pqc_composite")]
        Signer::Composite(c) => c.sign(tbs_der),
    }
}

// ── certificate facts ─────────────────────────────────────────────────

/// What renewal needs to know about a certificate, read once.
struct CertFacts {
    subject_raw: Vec<u8>,
    issuer_raw: Vec<u8>,
    issuer_dn: String,
    spki_raw: Vec<u8>,
    authority_key_id: Option<Vec<u8>>,
    subject_key_id: Option<Vec<u8>>,
    serial_hex: String,
    not_before_unix: i64,
    not_after_unix: i64,
}

impl CertFacts {
    fn parse(cert_der: &[u8]) -> Result<Self, RvError> {
        use x509_parser::{
            extensions::ParsedExtension,
            oid_registry::{OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER, OID_X509_EXT_SUBJECT_KEY_IDENTIFIER},
        };
        let (_, cert) = x509_parser::parse_x509_certificate(cert_der).map_err(|e| {
            RvError::ErrResponseStatus(400, format!("pki: cannot parse the issuer certificate for renewal ({e})"))
        })?;
        let tbs = &cert.tbs_certificate;
        let malformed = |what: &str| {
            RvError::ErrResponseStatus(
                400,
                format!("pki: the issuer certificate `{}` has a malformed or repeated {what}", tbs.subject),
            )
        };
        let authority_key_id = match cert.get_extension_unique(&OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER) {
            Ok(None) => None,
            Ok(Some(ext)) => match ext.parsed_extension() {
                ParsedExtension::AuthorityKeyIdentifier(aki) => aki.key_identifier.as_ref().map(|k| k.0.to_vec()),
                _ => return Err(malformed("AuthorityKeyIdentifier")),
            },
            Err(_) => return Err(malformed("AuthorityKeyIdentifier")),
        };
        let subject_key_id = match cert.get_extension_unique(&OID_X509_EXT_SUBJECT_KEY_IDENTIFIER) {
            Ok(None) => None,
            Ok(Some(ext)) => match ext.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(kid) => Some(kid.0.to_vec()),
                _ => return Err(malformed("SubjectKeyIdentifier")),
            },
            Err(_) => return Err(malformed("SubjectKeyIdentifier")),
        };
        Ok(Self {
            subject_raw: tbs.subject.as_raw().to_vec(),
            issuer_raw: tbs.issuer.as_raw().to_vec(),
            issuer_dn: tbs.issuer.to_string(),
            spki_raw: tbs.subject_pki.raw.to_vec(),
            authority_key_id,
            subject_key_id,
            serial_hex: storage::serial_to_hex(tbs.raw_serial()),
            not_before_unix: tbs.validity.not_before.timestamp(),
            not_after_unix: tbs.validity.not_after.timestamp(),
        })
    }

    /// Issuer and subject are the same bytes, and no AKI names a key other
    /// than the certificate's own SKI. A self-issued key-rollover cross
    /// certificate (AKI ≠ SKI) is therefore not self-signed.
    fn is_self_signed(&self) -> bool {
        if self.subject_raw != self.issuer_raw {
            return false;
        }
        match (&self.authority_key_id, &self.subject_key_id) {
            (Some(aki), Some(ski)) => aki == ski,
            _ => true,
        }
    }
}

// ── pure re-issuance ──────────────────────────────────────────────────

/// The parent CA that re-signs a non-self-signed issuer.
pub(crate) struct ParentCa<'a> {
    pub cert_pem: &'a str,
    pub signer: &'a Signer,
}

/// A re-issued CA certificate.
#[derive(Debug)]
pub(crate) struct RenewedCertificate {
    pub pem: String,
    pub serial: Vec<u8>,
}

/// Re-issue `current_pem` (which must certify `own`) with a fresh serial
/// and the given validity. `parent = None` re-signs with `own` and requires
/// a self-signed certificate; `Some` has the parent sign and points the AKI
/// at the parent's SKI. Everything else is copied, then re-checked.
pub(crate) fn reissue_ca_certificate(
    current_pem: &str,
    own: &Signer,
    parent: Option<ParentCa<'_>>,
    not_before: SystemTime,
    not_after: SystemTime,
) -> Result<RenewedCertificate, RvError> {
    // Refuses a certificate for another key and a non-canonical subject.
    let own_identity = signing_identity(own)?;
    x509::load_issuing_ca(current_pem, &own_identity.spki)?;

    let current_der = x509_pqc::pem_decode_first(current_pem)?;
    let facts = CertFacts::parse(&current_der)?;
    let current = Certificate::from_der(&current_der).map_err(|e| {
        RvError::ErrResponseStatus(400, format!("pki: cannot decode the issuer certificate for renewal ({e})"))
    })?;

    let mut tbs = current.tbs_certificate;
    let serial = fresh_serial(tbs.serial_number.as_bytes());
    tbs.serial_number = SerialNumber::new(&serial).map_err(x509_pqc::der_err)?;
    tbs.validity = Validity {
        not_before: x509_pqc::time_from_system(not_before)?,
        not_after: x509_pqc::time_from_system(not_after)?,
    };

    let (signer, alg_id, expected_issuer_raw) = match parent {
        None => {
            if !facts.is_self_signed() {
                return Err(not_self_signed_error(&facts.issuer_dn));
            }
            // Same bytes as the issuer field, and proven DER-canonical above.
            tbs.issuer = tbs.subject.clone();
            (own, own_identity.alg_id, facts.subject_raw.clone())
        }
        Some(parent) => {
            let parent_identity = signing_identity(parent.signer)?;
            let parent_ca = x509::load_issuing_ca(parent.cert_pem, &parent_identity.spki)?;
            let parent_subject_raw = parent_ca.name.to_der().map_err(x509_pqc::der_err)?;
            tbs.issuer = parent_ca.name.clone();
            tbs.extensions =
                replace_authority_key_identifier(tbs.extensions.take(), parent_ca.authority_key_identifier()?);
            (parent.signer, parent_identity.alg_id, parent_subject_raw)
        }
    };
    if tbs.extensions.is_some() {
        // RFC 5280 §4.1.2.1: extensions require v3. A v1 root keeps v1.
        tbs.version = Version::V3;
    }
    tbs.signature = alg_id.clone();

    let cert = x509_pqc::assemble_certificate(tbs, alg_id, |tbs_der| sign_with(signer, tbs_der))?;
    let der = cert.to_der().map_err(x509_pqc::der_err)?;

    // Fail closed if the copy changed anything renewal promised to keep.
    let renewed = CertFacts::parse(&der)?;
    if renewed.subject_raw != facts.subject_raw
        || renewed.spki_raw != facts.spki_raw
        || renewed.subject_key_id != facts.subject_key_id
        || renewed.issuer_raw != expected_issuer_raw
    {
        log::error!(
            "pki/issuers: renewed certificate issued by `{}` does not preserve subject, key or issuer",
            facts.issuer_dn
        );
        return Err(RvError::ErrPkiInternal);
    }

    Ok(RenewedCertificate { pem: x509_pqc::pem_encode("CERTIFICATE", &der), serial })
}

/// A random serial that differs from `previous`, so "new serial" is an
/// invariant rather than a probability.
fn fresh_serial(previous: &[u8]) -> Vec<u8> {
    loop {
        let candidate = x509::random_serial_bytes();
        if candidate != previous {
            return candidate;
        }
    }
}

/// Swap the AKI for `aki` at the position the old one held (first when
/// there was none). `None` drops it: a parent without SKI has nothing to
/// point at, and a stale key id would mislead path builders.
fn replace_authority_key_identifier(
    extensions: Option<Vec<Extension>>,
    aki: Option<Extension>,
) -> Option<Vec<Extension>> {
    let mut extensions = extensions.unwrap_or_default();
    let position = extensions.iter().position(|e| e.extn_id == AuthorityKeyIdentifier::OID);
    extensions.retain(|e| e.extn_id != AuthorityKeyIdentifier::OID);
    if let Some(aki) = aki {
        let at = position.unwrap_or(0).min(extensions.len());
        extensions.insert(at, aki);
    }
    if extensions.is_empty() {
        None
    } else {
        Some(extensions)
    }
}

// ── storage orchestration ─────────────────────────────────────────────

/// Renew the issuer `reference` (id or name). Every refusal is an explicit
/// error that names the issuer.
#[maybe_async::maybe_async]
pub async fn renew_issuer(req: &Request, reference: &str, lifetime: RenewLifetime) -> Result<RenewOutcome, RvError> {
    let issuer = issuers::load_issuer(req, reference).await?;
    let own = match (&issuer.signer, issuer.meta.keyless) {
        (Some(signer), false) => signer,
        _ => return Err(keyless_renew_error(&issuer.name)),
    };

    let current_der = x509_pqc::pem_decode_first(&issuer.cert_pem)?;
    let facts = CertFacts::parse(&current_der)?;
    let parent = if facts.is_self_signed() { None } else { Some(find_local_parent(req, &issuer, &facts).await?) };

    let now = SystemTime::now();
    let not_before = now.checked_sub(RENEW_BACKDATE).ok_or(RvError::ErrPkiInternal)?;
    let requested_not_after = match lifetime {
        RenewLifetime::Ttl(ttl) => {
            if ttl.is_zero() {
                return Err(RvError::ErrResponseStatus(400, "renew: `ttl` must be longer than zero".into()));
            }
            now.checked_add(ttl).ok_or_else(ttl_too_large_error)?
        }
        RenewLifetime::SameSpan => {
            let span = facts.not_after_unix.saturating_sub(facts.not_before_unix);
            if span <= RENEW_BACKDATE.as_secs() as i64 {
                return Err(RvError::ErrResponseStatus(
                    400,
                    format!(
                        "renew: cannot derive a validity period from issuer `{}` (its certificate spans {span}s); \
                         pass `ttl`",
                        issuer.name
                    ),
                ));
            }
            not_before.checked_add(Duration::from_secs(span as u64)).ok_or_else(ttl_too_large_error)?
        }
    };
    let requested_lifetime = requested_not_after.duration_since(now).map_err(|_| RvError::ErrPkiInternal)?;

    let (lifetime, ttl_clamped) = match &parent {
        Some(parent) => {
            check_parent_may_sign(parent, &issuer)?;
            issuers::clamp_ttl_to_issuer(parent, requested_lifetime)?
        }
        None => (requested_lifetime, false),
    };
    let not_after = now.checked_add(lifetime).ok_or_else(ttl_too_large_error)?;
    let not_after_unix = unix_secs(not_after)?;
    if not_after_unix > MAX_NOT_AFTER_UNIX {
        return Err(ttl_too_large_error());
    }

    let parent_ca = match &parent {
        Some(p) => Some(ParentCa { cert_pem: &p.cert_pem, signer: issuers::require_key(p)? }),
        None => None,
    };
    let renewed = reissue_ca_certificate(&issuer.cert_pem, own, parent_ca, not_before, not_after)?;
    let serial_hex = storage::serial_to_hex(&renewed.serial);

    // Retain, then replace, then record: a failed metadata write leaves the
    // earlier notAfter in force, so issuance clamps to it or is refused.
    append_history(
        req,
        &issuer.id,
        IssuerCertHistoryEntry {
            serial_hex: facts.serial_hex.clone(),
            certificate_pem: issuer.cert_pem.clone(),
            not_after_unix: facts.not_after_unix,
            replaced_at_unix: unix_secs(now)?,
            replaced_by_serial_hex: serial_hex.clone(),
        },
    )
    .await?;
    storage::put_string(req, &storage::issuer_cert_key(&issuer.id), &renewed.pem).await?;
    let mut meta = issuer.meta.clone();
    meta.serial_hex = serial_hex.clone();
    meta.not_after_unix = not_after_unix as i64;
    storage::put_json(req, &storage::issuer_meta_key(&issuer.id), &meta).await?;

    let renewed_by = match &parent {
        Some(p) => RenewedBy::Parent { id: p.id.clone(), name: p.name.clone() },
        None => RenewedBy::SelfSigned,
    };
    log::info!(
        "pki/issuers: renewed issuer {} ({}): serial {} -> {}, not_after {} -> {}, signed by {}",
        issuer.id,
        issuer.name,
        facts.serial_hex,
        serial_hex,
        facts.not_after_unix,
        not_after_unix,
        match &renewed_by {
            RenewedBy::SelfSigned => "itself",
            RenewedBy::Parent { name, .. } => name.as_str(),
        }
    );

    Ok(RenewOutcome {
        issuer_id: issuer.id.clone(),
        issuer_name: issuer.name.clone(),
        certificate_pem: renewed.pem,
        serial_hex,
        not_before_unix: unix_secs(not_before)? as i64,
        not_after_unix: not_after_unix as i64,
        previous_serial_hex: facts.serial_hex,
        previous_not_after_unix: facts.not_after_unix,
        renewed_by,
        ttl_clamped,
    })
}

/// The certificates `issuer_id` held before each renewal, oldest first.
/// Empty for an issuer that was never renewed.
#[maybe_async::maybe_async]
pub async fn load_history(req: &Request, issuer_id: &str) -> Result<IssuerCertHistory, RvError> {
    match req.storage_get(&storage::issuer_history_key(issuer_id)).await? {
        Some(entry) => IssuerCertHistory::decode(&entry.value),
        None => Ok(IssuerCertHistory { version: ISSUER_CERT_HISTORY_FORMAT_VERSION, entries: Vec::new() }),
    }
}

/// Retain a replaced certificate. Idempotent per serial, so a renewal
/// retried after a failed certificate write does not list it twice.
#[maybe_async::maybe_async]
async fn append_history(req: &Request, issuer_id: &str, entry: IssuerCertHistoryEntry) -> Result<(), RvError> {
    let mut history = load_history(req, issuer_id).await?;
    match history.entries.iter_mut().find(|e| e.serial_hex == entry.serial_hex) {
        Some(existing) => {
            existing.replaced_at_unix = entry.replaced_at_unix;
            existing.replaced_by_serial_hex = entry.replaced_by_serial_hex;
        }
        None => history.entries.push(entry),
    }
    history.version = ISSUER_CERT_HISTORY_FORMAT_VERSION;
    storage::put_json(req, &storage::issuer_history_key(issuer_id), &history).await
}

/// The key-holding issuer on this mount that signed `issuer`: its subject
/// is the issuer's `Issuer` name byte for byte and, when the issuer has an
/// AKI and the candidate an SKI, the key identifiers agree.
#[maybe_async::maybe_async]
async fn find_local_parent(req: &Request, issuer: &IssuerHandle, facts: &CertFacts) -> Result<IssuerHandle, RvError> {
    let index = issuers::list_issuers(req).await?;
    let mut key_holding: Vec<String> = Vec::new();
    let mut keyless: Vec<String> = Vec::new();
    for (id, name) in &index.by_id {
        if *id == issuer.id {
            continue;
        }
        let Some(pem) = storage::get_string(req, &storage::issuer_cert_key(id)).await? else {
            continue;
        };
        let Ok(der) = x509_pqc::pem_decode_first(&pem) else {
            continue;
        };
        let Ok(candidate) = CertFacts::parse(&der) else {
            continue;
        };
        if candidate.subject_raw != facts.issuer_raw {
            continue;
        }
        if let (Some(aki), Some(ski)) = (&facts.authority_key_id, &candidate.subject_key_id) {
            if aki != ski {
                continue;
            }
        }
        let meta: Option<storage::CaMetadata> = storage::get_json(req, &storage::issuer_meta_key(id)).await?;
        if meta.map(|m| m.keyless).unwrap_or(true) {
            keyless.push(name.clone());
        } else {
            key_holding.push(id.clone());
        }
    }

    match key_holding.as_slice() {
        [id] => issuers::load_issuer(req, id).await,
        [] if !keyless.is_empty() => Err(RvError::ErrResponseStatus(
            409,
            format!(
                "issuer `{}` was signed by `{}`, which this mount holds only as trust/chain-only issuer `{}` \
                 (no private key); renew it at the CA that holds that key and import the new certificate",
                issuer.name,
                facts.issuer_dn,
                keyless.join("`, `")
            ),
        )),
        [] => Err(RvError::ErrResponseStatus(
            409,
            format!(
                "issuer `{}` was signed by `{}`, which is not an issuer on this mount, so it cannot be re-signed \
                 here; renew it at that CA (`intermediate/generate/internal` with `key_ref={}` produces a CSR for \
                 the same key) and import the signed certificate",
                issuer.name,
                facts.issuer_dn,
                if issuer.meta.key_id.is_empty() { "<managed key>" } else { issuer.meta.key_id.as_str() }
            ),
        )),
        many => Err(RvError::ErrResponseStatus(
            409,
            format!(
                "issuer `{}` was signed by `{}`, and {} key-holding issuers on this mount match that name and key \
                 identifier; remove the duplicates before renewing",
                issuer.name,
                facts.issuer_dn,
                many.len()
            ),
        )),
    }
}

/// The checks `root/sign-intermediate` makes before a parent signs a CA
/// certificate, with messages that name both issuers.
fn check_parent_may_sign(parent: &IssuerHandle, child: &IssuerHandle) -> Result<(), RvError> {
    if !parent.usages.issuing_certificates {
        return Err(RvError::ErrResponseStatus(
            409,
            format!(
                "issuer `{}` is signed by `{}`, which does not have the `issuing-certificates` usage; \
                 enable it on `{}` to renew `{}`",
                child.name, parent.name, parent.name, child.name
            ),
        ));
    }
    if super::path_intermediate::issuer_path_len(&parent.cert_pem)? == Some(0) {
        return Err(RvError::ErrResponseStatus(
            409,
            format!(
                "issuer `{}` is signed by `{}`, whose pathLenConstraint is 0, so it cannot sign a CA certificate",
                child.name, parent.name
            ),
        ));
    }
    Ok(())
}

fn keyless_renew_error(issuer_name: &str) -> RvError {
    RvError::ErrResponseStatus(
        400,
        format!(
            "issuer `{issuer_name}` is trust/chain-only (imported without a private key) and cannot be renewed here; \
             renew it at the CA that holds its key and import the new certificate"
        ),
    )
}

fn not_self_signed_error(issuer_dn: &str) -> RvError {
    RvError::ErrResponseStatus(
        409,
        format!("pki: the certificate was issued by `{issuer_dn}`, not by its own key; it must be renewed by that CA"),
    )
}

fn ttl_too_large_error() -> RvError {
    RvError::ErrResponseStatus(400, "renew: `ttl` reaches past 9999-12-31, the last date X.509 can encode".into())
}

fn unix_secs(t: SystemTime) -> Result<u64, RvError> {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).map_err(|_| RvError::ErrPkiInternal)
}

#[cfg(test)]
mod tests {
    //! Pure re-issuance: what renewal keeps, what it changes, who signs.
    //! Storage and the HTTP surface: `src/engine_tests/pki_issuer_renew.rs`.

    use std::str::FromStr;

    use x509_cert::{
        certificate::{Rfc5280, TbsCertificateInner},
        der::asn1::{Ia5String, OctetString},
        ext::pkix::{
            constraints::name::{GeneralSubtree, GeneralSubtrees, NameConstraints},
            name::GeneralName,
            BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier,
        },
    };

    use super::*;
    use crate::{
        crypto::{CertSigner, KeyAlgorithm},
        pqc::{MlDsaLevel, MlDsaSigner},
        x509::tests::{
            ad_cs_subject, assert_issuer_and_aki, der_of, leaf_role, leaf_subject, self_signed_ca_pem, FIELD_SKI,
        },
    };

    fn hours(h: u64) -> Duration {
        Duration::from_secs(h * 3600)
    }

    fn window(lifetime: Duration) -> (SystemTime, SystemTime) {
        let now = SystemTime::now();
        (now - RENEW_BACKDATE, now + lifetime)
    }

    fn facts(pem: &str) -> CertFacts {
        CertFacts::parse(&der_of(pem)).unwrap()
    }

    /// TBS patch appending a permitted-subtree name constraint, which no
    /// engine builder emits: renewal must copy it untouched.
    fn with_name_constraint(der: Vec<u8>) -> Vec<u8> {
        let mut tbs = TbsCertificateInner::<Rfc5280>::from_der(&der).unwrap();
        let nc = NameConstraints {
            permitted_subtrees: Some(GeneralSubtrees::from(vec![GeneralSubtree {
                base: GeneralName::DnsName(Ia5String::new("fgv.br").unwrap()),
                minimum: 0,
                maximum: None,
            }])),
            excluded_subtrees: None,
        };
        tbs.extensions.as_mut().unwrap().push(x509_pqc::encode_ext(true, &nc).unwrap());
        tbs.to_der().unwrap()
    }

    /// A self-signed classical CA over the AD CS subject with an SKI, its
    /// TBS passed through `patch` before signing.
    fn classical_root_with(alg: KeyAlgorithm, patch: impl Fn(Vec<u8>) -> Vec<u8>) -> (Signer, String) {
        let cs = CertSigner::generate(alg).unwrap();
        let spki = SubjectPublicKeyInfoOwned::from_der(&cs.key_pair().subject_public_key_info()).unwrap();
        let alg_id = x509::certificate_signature_alg_id(&cs).unwrap();
        let pem = self_signed_ca_pem(spki, alg_id, ad_cs_subject(), Some(&FIELD_SKI), patch, |tbs| {
            cs.key_pair().sign(tbs).unwrap()
        });
        (Signer::Classical(cs), pem)
    }

    fn classical_root(alg: KeyAlgorithm) -> (Signer, String) {
        classical_root_with(alg, with_name_constraint)
    }

    fn extensions_of(pem: &str) -> Vec<Extension> {
        Certificate::from_der(&der_of(pem)).unwrap().tbs_certificate.extensions.unwrap_or_default()
    }

    fn without_aki(exts: Vec<Extension>) -> Vec<Extension> {
        exts.into_iter().filter(|e| e.extn_id != AuthorityKeyIdentifier::OID).collect()
    }

    fn verify_classical(cert_pem: &str, signer_cert_pem: &str) {
        let (cert_der, ca_der) = (der_of(cert_pem), der_of(signer_cert_pem));
        let (_, cert) = x509_parser::parse_x509_certificate(&cert_der).unwrap();
        let (_, ca) = x509_parser::parse_x509_certificate(&ca_der).unwrap();
        cert.verify_signature(Some(ca.public_key())).expect("signature verifies under the signing CA's key");
    }

    #[test]
    fn a_self_signed_root_keeps_subject_key_and_extensions_with_a_new_serial_and_validity() {
        for alg in [KeyAlgorithm::Rsa2048, KeyAlgorithm::EcdsaP256, KeyAlgorithm::Ed25519] {
            let (signer, old_pem) = classical_root(alg);
            let (nb, na) = window(hours(24 * 400));
            let renewed = reissue_ca_certificate(&old_pem, &signer, None, nb, na).expect("renew a self-signed root");

            let (old, new) = (facts(&old_pem), facts(&renewed.pem));
            assert_eq!(new.subject_raw, old.subject_raw, "{alg:?}: subject kept byte for byte");
            assert_eq!(new.issuer_raw, old.subject_raw, "{alg:?}: still self-issued");
            assert_eq!(new.spki_raw, old.spki_raw, "{alg:?}: same key");
            assert_ne!(new.serial_hex, old.serial_hex, "{alg:?}: new serial");
            assert_eq!(new.serial_hex, storage::serial_to_hex(&renewed.serial));
            assert!(new.not_after_unix > old.not_after_unix, "{alg:?}: later notAfter");
            assert_eq!(extensions_of(&renewed.pem), extensions_of(&old_pem), "{alg:?}: every extension copied");
            verify_classical(&renewed.pem, &renewed.pem);
        }
    }

    #[test]
    fn the_name_constraint_fixture_really_carries_one() {
        let (_, pem) = classical_root(KeyAlgorithm::EcdsaP256);
        let nc_oid = const_oid::ObjectIdentifier::from_str("2.5.29.30").unwrap();
        assert!(extensions_of(&pem).iter().any(|e| e.extn_id == nc_oid), "fixture must carry a name constraint");
    }

    #[test]
    fn a_leaf_issued_under_the_old_root_chains_to_the_renewed_root() {
        let (signer, old_pem) = classical_root(KeyAlgorithm::EcdsaP256);
        let Signer::Classical(cs) = &signer else { unreachable!() };
        let leaf_key = CertSigner::generate(KeyAlgorithm::EcdsaP256).unwrap();
        let (leaf_pem, _) = x509::build_leaf(
            &leaf_role(),
            &leaf_subject("app.fgv.br"),
            hours(1),
            &leaf_key,
            cs,
            &old_pem,
            &x509::IssuanceUrls::default(),
        )
        .unwrap();

        let (nb, na) = window(hours(48));
        let renewed = reissue_ca_certificate(&old_pem, &signer, None, nb, na).unwrap();
        assert_issuer_and_aki(&leaf_pem, &renewed.pem, Some(&FIELD_SKI));
        verify_classical(&leaf_pem, &renewed.pem);
    }

    #[test]
    fn a_certificate_for_another_key_is_refused() {
        let (_, old_pem) = classical_root(KeyAlgorithm::EcdsaP256);
        let other = Signer::Classical(CertSigner::generate(KeyAlgorithm::EcdsaP256).unwrap());
        let (nb, na) = window(hours(1));
        let err = reissue_ca_certificate(&old_pem, &other, None, nb, na).unwrap_err();
        assert!(format!("{err:?}").contains("does not belong to the issuer's signing key"), "{err:?}");
    }

    #[test]
    fn an_intermediate_is_re_signed_by_its_parent_and_never_by_itself() {
        let (root_signer, root_pem) = classical_root(KeyAlgorithm::EcdsaP384);
        let Signer::Classical(root_cs) = &root_signer else { unreachable!() };
        let int_cs = CertSigner::generate(KeyAlgorithm::EcdsaP256).unwrap();
        let (int_pem, _) = x509::build_intermediate_ca(
            "Issuing CA",
            "FGV",
            hours(24),
            &int_cs.key_pair().subject_public_key_info(),
            root_cs,
            &root_pem,
            Some(0),
        )
        .unwrap();
        let int_signer = Signer::Classical(int_cs);
        let (nb, na) = window(hours(48));

        // Without its parent it is refused, not silently turned into a root.
        let err = reissue_ca_certificate(&int_pem, &int_signer, None, nb, na).unwrap_err();
        assert!(format!("{err:?}").contains("must be renewed by that CA"), "{err:?}");

        let parent = ParentCa { cert_pem: &root_pem, signer: &root_signer };
        let renewed = reissue_ca_certificate(&int_pem, &int_signer, Some(parent), nb, na).unwrap();
        let (old, new) = (facts(&int_pem), facts(&renewed.pem));
        assert_eq!(new.subject_raw, old.subject_raw);
        assert_eq!(new.spki_raw, old.spki_raw);
        assert_ne!(new.serial_hex, old.serial_hex);
        assert_issuer_and_aki(&renewed.pem, &root_pem, Some(&FIELD_SKI));
        verify_classical(&renewed.pem, &root_pem);
        // BasicConstraints (with its path length), KeyUsage and SKI survive.
        assert_eq!(without_aki(extensions_of(&renewed.pem)), without_aki(extensions_of(&int_pem)));
    }

    #[test]
    fn a_self_issued_certificate_naming_another_key_is_not_self_signed() {
        let foreign_aki = |der: Vec<u8>| {
            let mut tbs = TbsCertificateInner::<Rfc5280>::from_der(&der).unwrap();
            let other = OctetString::new(vec![0xAB; 20]).unwrap();
            tbs.extensions.as_mut().unwrap().push(x509_pqc::encode_aki(&other).unwrap());
            tbs.to_der().unwrap()
        };
        let (signer, pem) = classical_root_with(KeyAlgorithm::EcdsaP256, foreign_aki);
        assert!(!facts(&pem).is_self_signed());
        let (nb, na) = window(hours(1));
        let err = reissue_ca_certificate(&pem, &signer, None, nb, na).unwrap_err();
        assert!(format!("{err:?}").contains("must be renewed by that CA"), "{err:?}");
    }

    #[test]
    fn an_ml_dsa_root_is_re_signed_with_its_own_key() {
        use bv_crypto::{ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN};
        use fips204::{
            ml_dsa_65,
            traits::{SerDes, Verifier},
        };

        let ml = MlDsaSigner::generate(MlDsaLevel::L65).unwrap();
        let (old_pem, _) = x509_pqc::build_root_ca("PQC Root", "FGV", hours(24), &ml).unwrap();
        let public_key: [u8; ML_DSA_65_PUBLIC_KEY_LEN] = ml.public_key().try_into().unwrap();
        let signer = Signer::MlDsa(ml);
        let (nb, na) = window(hours(24 * 30));
        let renewed = reissue_ca_certificate(&old_pem, &signer, None, nb, na).unwrap();

        let (old, new) = (facts(&old_pem), facts(&renewed.pem));
        assert_eq!(new.subject_raw, old.subject_raw);
        assert_eq!(new.spki_raw, old.spki_raw);
        assert_ne!(new.serial_hex, old.serial_hex);
        assert_eq!(extensions_of(&renewed.pem), extensions_of(&old_pem));

        let cert = Certificate::from_der(&der_of(&renewed.pem)).unwrap();
        let sig: [u8; ML_DSA_65_SIGNATURE_LEN] = cert.signature.raw_bytes().try_into().unwrap();
        let tbs = cert.tbs_certificate.to_der().unwrap();
        assert!(ml_dsa_65::PublicKey::try_from_bytes(public_key).unwrap().verify(&tbs, &sig, &[]));
    }

    #[test]
    fn the_authority_key_identifier_is_replaced_in_place() {
        let bc = x509_pqc::encode_ext(true, &BasicConstraints { ca: true, path_len_constraint: None }).unwrap();
        let ku = x509_pqc::encode_ext(true, &KeyUsage(KeyUsages::KeyCertSign.into())).unwrap();
        let ski = x509_pqc::encode_ext_octets(SubjectKeyIdentifier::OID, false, OctetString::new(vec![1; 20]).unwrap())
            .unwrap();
        let aki = |byte: u8| x509_pqc::encode_aki(&OctetString::new(vec![byte; 20]).unwrap()).unwrap();

        assert_eq!(
            replace_authority_key_identifier(Some(vec![bc.clone(), aki(2), ku.clone(), ski.clone()]), Some(aki(3))),
            Some(vec![bc.clone(), aki(3), ku.clone(), ski.clone()])
        );
        // No AKI before: the parent's goes first, as the builders emit it.
        assert_eq!(
            replace_authority_key_identifier(Some(vec![bc.clone(), ku.clone()]), Some(aki(3))),
            Some(vec![aki(3), bc.clone(), ku.clone()])
        );
        // A parent without SKI: the stale AKI is dropped, not kept.
        assert_eq!(replace_authority_key_identifier(Some(vec![aki(9), bc.clone()]), None), Some(vec![bc]));
        assert_eq!(replace_authority_key_identifier(None, None), None);
    }

    #[test]
    fn a_history_record_from_a_newer_format_is_refused() {
        let current = format!(r#"{{"version":{ISSUER_CERT_HISTORY_FORMAT_VERSION},"entries":[]}}"#);
        assert!(IssuerCertHistory::decode(current.as_bytes()).is_ok());
        // A record without a version field still reads.
        assert!(IssuerCertHistory::decode(br#"{"entries":[]}"#).is_ok());
        let newer = format!(r#"{{"version":{},"entries":[]}}"#, ISSUER_CERT_HISTORY_FORMAT_VERSION + 1);
        let err = IssuerCertHistory::decode(newer.as_bytes()).unwrap_err();
        assert!(format!("{err:?}").contains("newer than"), "{err:?}");
    }
}
