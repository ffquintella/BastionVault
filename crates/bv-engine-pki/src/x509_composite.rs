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
    composite::CompositeSigner,
    path_roles::RoleEntry,
    x509::{IssuingCa, RevokedEntry, SubjectInput},
    x509_pqc,
};
use crate::errors::RvError;

const CRL_NUMBER_OID: const_oid::ObjectIdentifier = const_oid::ObjectIdentifier::new_unwrap("2.5.29.20");

/// AlgorithmIdentifier for the cert / CRL signature. Reads the OID off
/// the signer so multi-variant deployments (P256+L44, P256+L65,
/// P384+L87) emit the right `signatureAlgorithm` for each pairing.
pub(super) fn composite_alg_id(signer: &CompositeSigner) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned { oid: signer.oid(), parameters: None }
}

pub(super) fn composite_spki(signer: &CompositeSigner) -> Result<SubjectPublicKeyInfoOwned, RvError> {
    let pk_der = signer.composite_public_key_der()?;
    Ok(SubjectPublicKeyInfoOwned {
        algorithm: composite_alg_id(signer),
        subject_public_key: BitString::from_bytes(&pk_der).map_err(x509_pqc::der_err)?,
    })
}

/// Issuer name and AKI for a certificate `ca_signer` signs, through the
/// loader every issuing path shares. The composite key is
/// `SEQUENCE { ML-DSA key, classical key }`, so comparing it with the CA
/// certificate compares both components; the classical half is derived by
/// `ring` from its private key, the ML-DSA half is checked against its seed.
fn load_composite_issuing_ca(ca_cert_pem: &str, ca_signer: &CompositeSigner) -> Result<IssuingCa, RvError> {
    ca_signer.pqc().ensure_public_key_matches_seed()?;
    super::x509::load_issuing_ca(ca_cert_pem, &composite_spki(ca_signer)?)
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
    let alg_id = composite_alg_id(signer);
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
    urls: &super::x509::IssuanceUrls,
) -> Result<(String, Vec<u8>), RvError> {
    // `signatureAlgorithm` reflects the *CA*'s algorithm — it's the OID
    // operators verify against. The leaf's SPKI carries its own (which
    // may legitimately differ when an operator mixes variants on
    // purpose, even though the path-issue gate today refuses that).
    let alg_id = composite_alg_id(ca_signer);
    let leaf_spki = composite_spki(leaf_signer)?;

    let ca = load_composite_issuing_ca(ca_cert_pem, ca_signer)?;

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
    ];
    extensions.extend(ca.authority_key_identifier()?);
    if let Some(eku) = x509_pqc::build_extended_key_usage(role)? {
        extensions.push(eku);
    }
    if let Some(san) = x509_pqc::build_subject_alt_name(subject)? {
        extensions.push(san);
    }
    if let Some(sid) = x509_pqc::build_ad_sid_extension(subject)? {
        extensions.push(sid);
    }
    if let Some(cdp) = x509_pqc::build_crl_distribution_points(urls)? {
        extensions.push(cdp);
    }

    let tbs = TbsCertificateInner {
        version: Version::V3,
        serial_number: serial,
        signature: alg_id.clone(),
        issuer: ca.name,
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
    let alg_id = composite_alg_id(ca_signer);
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

#[cfg(test)]
mod tests {
    //! Composite issuance must chain to its CA the way classical issuance
    //! does (T147), and the CA certificate must certify both halves of the
    //! composite key that signs. Fixtures are shared with `x509::tests`.

    use rcgen::PublicKeyData as _;
    use x509_cert::{
        der::{asn1::SequenceOf, Decode},
        name::Name,
    };

    use super::*;
    use crate::{
        crypto::KeyAlgorithm,
        x509::{
            tests::{
                ad_cs_subject, assert_issuer_and_aki, assert_key_mismatch_refused, leaf_role, leaf_subject,
                multi_valued_subject, self_signed_ca_pem, unsort_multi_valued_rdn, FIELD_SKI,
            },
            IssuanceUrls,
        },
    };

    const ALG: KeyAlgorithm = KeyAlgorithm::CompositeEcdsaP256MlDsa44;

    /// A composite SubjectPublicKeyInfo from explicit halves, in the
    /// `SEQUENCE { ML-DSA key, classical key }` shape the signer emits.
    fn spki_from_halves(signer: &CompositeSigner, pq: &[u8], classical: &[u8]) -> SubjectPublicKeyInfoOwned {
        let mut seq: SequenceOf<BitString, 2> = SequenceOf::new();
        seq.add(BitString::from_bytes(pq).unwrap()).unwrap();
        seq.add(BitString::from_bytes(classical).unwrap()).unwrap();
        SubjectPublicKeyInfoOwned {
            algorithm: composite_alg_id(signer),
            subject_public_key: BitString::from_bytes(&seq.to_der().unwrap()).unwrap(),
        }
    }

    /// Self-signed composite CA certifying `certified`, signed by `signer`.
    fn composite_ca_pem(
        signer: &CompositeSigner,
        certified: SubjectPublicKeyInfoOwned,
        subject: Name,
        ski: Option<&[u8]>,
        patch: impl Fn(Vec<u8>) -> Vec<u8>,
    ) -> String {
        self_signed_ca_pem(certified, composite_alg_id(signer), subject, ski, patch, |tbs| signer.sign(tbs).unwrap())
    }

    fn own_ca_pem(signer: &CompositeSigner, subject: Name, ski: Option<&[u8]>) -> String {
        composite_ca_pem(signer, composite_spki(signer).unwrap(), subject, ski, |der| der)
    }

    fn issue(ca_signer: &CompositeSigner, ca_pem: &str) -> Result<(String, Vec<u8>), RvError> {
        let leaf = CompositeSigner::generate(ALG).unwrap();
        build_leaf(
            &leaf_role(),
            &leaf_subject("hybrid.fgv.br"),
            Duration::from_secs(3600),
            &leaf,
            ca_signer,
            ca_pem,
            &IssuanceUrls::default(),
        )
    }

    #[test]
    fn composite_leaf_issuer_is_ca_subject_verbatim_and_aki_is_ca_ski() {
        let ca = CompositeSigner::generate(ALG).unwrap();
        let ca_pem = own_ca_pem(&ca, ad_cs_subject(), Some(&FIELD_SKI));
        let (pem, _) = issue(&ca, &ca_pem).expect("issue under an AD CS-named composite CA");
        assert_issuer_and_aki(&pem, &ca_pem, Some(&FIELD_SKI));
    }

    #[test]
    fn composite_ca_without_ski_issues_without_aki() {
        // This used to derive a key id from the CA key, matching nothing
        // the CA advertises.
        let ca = CompositeSigner::generate(ALG).unwrap();
        let ca_pem = own_ca_pem(&ca, ad_cs_subject(), None);
        let (pem, _) = issue(&ca, &ca_pem).expect("issue under a composite CA without SKI");
        assert_issuer_and_aki(&pem, &ca_pem, None);
    }

    #[test]
    fn composite_non_canonical_ca_subject_is_refused() {
        let ca = CompositeSigner::generate(ALG).unwrap();
        let spki = composite_spki(&ca).unwrap();
        let ca_pem = composite_ca_pem(&ca, spki, multi_valued_subject(), Some(&FIELD_SKI), unsort_multi_valued_rdn);
        let err = issue(&ca, &ca_pem).expect_err("a CA subject that cannot be copied verbatim must be refused");
        assert!(format!("{err:?}").contains("byte-for-byte"), "operator-facing reason: {err:?}");
    }

    #[test]
    fn composite_ca_certificate_must_certify_both_halves_of_the_signing_key() {
        let ca = CompositeSigner::generate(ALG).unwrap();
        let other = CompositeSigner::generate(ALG).unwrap();
        let (ca_pq, ca_classical) = (ca.pqc().public_key(), ca.classical().key_pair().der_bytes());
        let (other_pq, other_classical) = (other.pqc().public_key(), other.classical().key_pair().der_bytes());

        // Sanity: the halves are where the shared encoder puts them.
        let own = composite_spki(&ca).unwrap();
        assert_eq!(own, spki_from_halves(&ca, ca_pq, ca_classical));
        let halves = SequenceOf::<BitString, 2>::from_der(own.subject_public_key.raw_bytes()).unwrap();
        assert_eq!(halves.get(0).unwrap().raw_bytes(), ca_pq);

        let reason = "is not the public key of the stored private key";
        for (what, certified) in [
            ("another composite key", composite_spki(&other).unwrap()),
            ("the ML-DSA half differs", spki_from_halves(&ca, other_pq, ca_classical)),
            ("the classical half differs", spki_from_halves(&ca, ca_pq, other_classical)),
        ] {
            let ca_pem = composite_ca_pem(&ca, certified, ad_cs_subject(), Some(&FIELD_SKI), |der| der);
            let result = issue(&ca, &ca_pem);
            assert!(result.is_err(), "{what}: must be refused");
            assert_key_mismatch_refused(result, reason);
        }
        issue(&ca, &own_ca_pem(&ca, ad_cs_subject(), Some(&FIELD_SKI))).expect("the CA's own certificate issues");
    }

    #[test]
    fn composite_signer_whose_stored_ml_dsa_key_is_not_its_seed_is_refused() {
        // The CA certificate matches the cached ML-DSA public key, but the
        // seed that signs belongs to another key.
        let ca = CompositeSigner::generate(ALG).unwrap();
        let other = CompositeSigner::generate(ALG).unwrap();
        let tampered = ca.with_pqc_cached_public_key(other.pqc().public_key().to_vec()).unwrap();
        let ca_pem = own_ca_pem(&tampered, ad_cs_subject(), Some(&FIELD_SKI));
        let err = issue(&tampered, &ca_pem).expect_err("a signer inconsistent with its seed must be refused");
        assert!(format!("{err:?}").contains("not the one its private seed derives"), "reason: {err:?}");
    }
}
