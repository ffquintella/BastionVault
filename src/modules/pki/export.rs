//! Export-format helpers for `pki/cert/<serial>/export` and
//! `pki/issuer/<ref>/export`.
//!
//! Two output shapes today:
//!
//! 1. **PEM bundle** — concatenated `BEGIN CERTIFICATE` blocks (one
//!    per cert in the chain), optionally followed by the leaf's
//!    `BEGIN PRIVATE KEY` PEM. The natural shape every TLS toolchain
//!    accepts.
//! 2. **PKCS#7** — `cms 0.2`'s `ContentInfo::try_from(PkiPath)` builds
//!    a certs-only `SignedData` envelope with empty `signerInfos` and
//!    empty `digestAlgorithms`. This is the universally-importable
//!    `.p7b` shape (Windows MMC, macOS Keychain, Java keystore,
//!    OpenSSL `pkcs7 -inform DER -print_certs` all round-trip
//!    cleanly). PKCS#7 doesn't carry private keys — the
//!    `include_private_key` knob is intentionally rejected with
//!    `format=pkcs7`.
//!
//! PKCS#12 is intentionally NOT in this file — it's a follow-up PR
//! that wires `pkcs12 0.1.0` + `pkcs5 0.7`'s PBES2 encrypt + MAC.

use cms::{
    cert::CertificateChoices,
    content_info::{CmsVersion, ContentInfo},
    encrypted_data::EncryptedData,
    enveloped_data::EncryptedContentInfo,
    revocation::RevocationInfoChoices,
    signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignedData, SignerInfos,
    },
};
use const_oid::ObjectIdentifier;
use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
// PKCS#12 KDF (RFC 7292 Appendix B.2) is implemented in `pkcs12 0.1`
// against the `digest 0.10` trait family. The host crate's main `sha2`
// dep is on the 0.11 family (digest 0.11); routing through the
// `sha2-saml` alias — which is `sha2 0.10` (digest 0.10) — gives us a
// trait-compatible Sha256 to feed `pkcs12::kdf::derive_key_utf8::<D>`.
use sha2_saml::Sha256 as Sha256Pkcs12Kdf;
use sha2::Sha256;
use x509_cert::der::{
    self,
    asn1::{Any, AnyRef, OctetString, SetOfVec},
    Decode, Encode,
};
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;

use crate::errors::RvError;

/// Container of the host-side export response.
pub struct ExportBundle {
    /// `pem` | `pkcs7`. Drives both the encoded body shape and the
    /// MIME-style label the GUI surfaces in the toast.
    pub format: ExportFormat,
    /// The encoded payload. PEM bundles ship as UTF-8 text.
    /// PKCS#7 ships either as DER bytes (`format=pkcs7-der`) or
    /// PEM-armored (`format=pkcs7`, default — interoperates with
    /// macOS / Windows tooling).
    pub body: Vec<u8>,
    /// Suggested filename extension — used by the GUI's save-dialog.
    pub extension: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Pem,
    Pkcs7,
    Pkcs12,
}

impl ExportFormat {
    pub fn parse(s: &str) -> Result<Self, RvError> {
        match s.to_ascii_lowercase().as_str() {
            "" | "pem" => Ok(Self::Pem),
            "pkcs7" | "p7b" | "p7c" => Ok(Self::Pkcs7),
            "pkcs12" | "p12" | "pfx" => Ok(Self::Pkcs12),
            other => Err(RvError::ErrString(format!(
                "export: unknown format `{other}` (accepted: pem, pkcs7, pkcs12)"
            ))),
        }
    }

    pub fn is_binary(self) -> bool {
        matches!(self, Self::Pkcs12)
    }
}

/// Produce a PEM bundle of `cert_pem` followed by every PEM in
/// `chain_pems` (issuer chain in subject→root order — caller's
/// responsibility), with `private_key_pem` appended last when
/// supplied. All inputs are expected to already be valid PEM
/// (`-----BEGIN <label>-----` … `-----END <label>-----` with trailing
/// newline).
pub fn pem_bundle(
    cert_pem: &str,
    chain_pems: &[String],
    private_key_pem: Option<&str>,
) -> ExportBundle {
    let mut out = String::with_capacity(
        cert_pem.len()
            + chain_pems.iter().map(|p| p.len()).sum::<usize>()
            + private_key_pem.map(|s| s.len()).unwrap_or(0)
            + 16,
    );
    out.push_str(cert_pem.trim_end());
    out.push('\n');
    for p in chain_pems {
        out.push_str(p.trim_end());
        out.push('\n');
    }
    if let Some(k) = private_key_pem {
        out.push_str(k.trim_end());
        out.push('\n');
    }
    ExportBundle {
        format: ExportFormat::Pem,
        body: out.into_bytes(),
        extension: "pem",
    }
}

/// Wrap one or more cert PEMs in a certs-only PKCS#7 `SignedData`
/// `ContentInfo`. Output is PEM-armored under `-----BEGIN PKCS7-----`,
/// matching what every common importer expects from a `.p7b` file.
///
/// `cert_pem` is the leaf; `chain_pems` are the intermediates and
/// (optionally) root, in the same order the PEM bundle path uses.
/// PKCS#7 doesn't carry private keys, so any caller-supplied
/// `include_private_key=true` is rejected at the route handler before
/// reaching this function.
pub fn pkcs7_certs_only(
    cert_pem: &str,
    chain_pems: &[String],
) -> Result<ExportBundle, RvError> {
    let leaf = parse_cert_pem(cert_pem)?;
    let mut certs: Vec<Certificate> = Vec::with_capacity(chain_pems.len() + 1);
    certs.push(leaf);
    for p in chain_pems {
        certs.push(parse_cert_pem(p)?);
    }

    // Hand-build the SignedData here rather than going through
    // `cms`'s `TryFrom<PkiPath>`. Reason: `PkiPath` was added in a
    // newer x509-cert version and isn't always public on the
    // 0.2.x line we're pinned to. The component pieces ARE stable.
    let mut cert_set: CertificateSet = CertificateSet(SetOfVec::new());
    for cert in certs {
        cert_set
            .0
            .insert(CertificateChoices::Certificate(cert))
            .map_err(der_err)?;
    }

    let signed_data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: SetOfVec::new(),
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: const_oid::db::rfc5911::ID_DATA,
            econtent: None,
        },
        certificates: Some(cert_set),
        // Match OpenSSL's certs-only PKCS#7 shape — emit an empty
        // `crls` field rather than omitting it. Some Java verifiers
        // throw if it's missing.
        crls: Some(RevocationInfoChoices(Default::default())),
        signer_infos: SignerInfos(SetOfVec::new()),
    };
    let inner_der = signed_data.to_der().map_err(der_err)?;
    let inner_any =
        Any::from_der(&inner_der).map_err(der_err)?;
    let _ = AnyRef::try_from(inner_der.as_slice()); // sanity-only
    let content_info = ContentInfo {
        content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
        content: inner_any,
    };

    let der = content_info.to_der().map_err(der_err)?;
    // PEM-armor the DER — `.p7b` is always PEM in practice.
    let armored = pem::encode(&pem::Pem::new("PKCS7", der));

    Ok(ExportBundle {
        format: ExportFormat::Pkcs7,
        body: armored.into_bytes(),
        extension: "p7b",
    })
}

fn parse_cert_pem(pem_str: &str) -> Result<Certificate, RvError> {
    let parsed = pem::parse(pem_str.trim())
        .map_err(|e| RvError::ErrString(format!("export: bad PEM: {e}")))?;
    if parsed.tag() != "CERTIFICATE" {
        return Err(RvError::ErrString(format!(
            "export: expected CERTIFICATE PEM, got `{}`",
            parsed.tag()
        )));
    }
    Certificate::from_der(parsed.contents()).map_err(der_err)
}

/// PBKDF2 iteration count used for both the cert-bag PBES2 envelope
/// and the shrouded-key envelope. 100k matches what current OpenSSL
/// defaults at; doubling it would only slow down brute-force by a
/// constant, while making interactive imports noticeably laggy.
const PBKDF2_ITERATIONS: u32 = 100_000;

/// HMAC-SHA256 outer MAC iteration count, used by the pkcs12 KDF
/// (RFC 7292 Appendix B.2) to derive the MAC key from the password.
const MAC_ITERATIONS: i32 = 100_000;

/// `id-data` content-type OID — wraps an unencrypted SafeContents.
/// (1.2.840.113549.1.7.1)
const ID_DATA: ObjectIdentifier = const_oid::db::rfc5911::ID_DATA;
/// `id-encryptedData` content-type OID — wraps a PBES2-encrypted
/// SafeContents. (1.2.840.113549.1.7.6)
const ID_ENCRYPTED_DATA: ObjectIdentifier =
    const_oid::db::rfc5911::ID_ENCRYPTED_DATA;
/// `hmacWithSHA256` algorithm OID for the outer PFX MAC.
/// (1.2.840.113549.2.9)
const ID_HMAC_WITH_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.2.9");

/// Build a password-encrypted PKCS#12 (`.p12`) bundle.
///
/// Layout (interoperable with OpenSSL / Java / Windows / macOS):
///   * AuthenticatedSafe = SEQUENCE OF [
///       ContentInfo(id-encryptedData, EncryptedData(PBES2 over
///         SafeContents containing one or more CertBags — leaf + chain)),
///       (when private_key_pem is supplied)
///       ContentInfo(id-data, SafeContents containing one
///         pkcs8-shrouded-key bag with the leaf's PKCS#8 wrapped in
///         a PBES2 EncryptedPrivateKeyInfo).
///     ]
///   * Outer ContentInfo = id-data wrapping the AuthenticatedSafe DER.
///   * MacData = HMAC-SHA256 over the AuthenticatedSafe DER, key
///     derived via the PKCS#12 KDF (RFC 7292 Appendix B.2).
///
/// Both encrypted sections use the *same* `password` so importers
/// only prompt once. The salts and IVs are freshly random per
/// envelope (drawn from `rand::rng()`).
pub fn build_pkcs12(
    cert_pem: &str,
    chain_pems: &[String],
    private_key_pem: Option<&str>,
    password: &str,
) -> Result<ExportBundle, RvError> {
    use pkcs12::{
        authenticated_safe::AuthenticatedSafe, digest_info::DigestInfo,
        mac_data::MacData, pfx::Pfx, pfx::Version, safe_bag::SafeBag,
        PKCS_12_PKCS8_KEY_BAG_OID, PKCS_12_X509_CERT_OID,
    };
    use pkcs12::cert_type::CertBag;

    if password.is_empty() {
        return Err(RvError::ErrString(
            "export: PKCS#12 requires a non-empty password (it's the file's \
             encryption key)"
                .into(),
        ));
    }

    let mut rng = rand::rng();

    // ── 1. Encrypted CertBag bundle ──────────────────────────────────
    //
    // CertBag for the leaf + each chain cert, wrapped in a SEQUENCE OF
    // SafeBag → encrypted with PBES2.
    let leaf_cert = parse_cert_pem(cert_pem)?;
    let mut all_certs: Vec<Certificate> = Vec::with_capacity(chain_pems.len() + 1);
    all_certs.push(leaf_cert);
    for p in chain_pems {
        all_certs.push(parse_cert_pem(p)?);
    }

    let mut cert_bags: Vec<SafeBag> = Vec::with_capacity(all_certs.len());
    for cert in &all_certs {
        let cert_der = cert.to_der().map_err(der_err)?;
        let cert_bag = CertBag {
            cert_id: PKCS_12_X509_CERT_OID,
            cert_value: OctetString::new(cert_der).map_err(der_err)?,
        };
        let cert_bag_der = cert_bag.to_der().map_err(der_err)?;
        cert_bags.push(SafeBag {
            bag_id: pkcs12::PKCS_12_CERT_BAG_OID,
            bag_value: cert_bag_der,
            bag_attributes: None,
        });
    }
    let cert_safe_contents_der = encode_safe_contents(&cert_bags)?;

    // PBES2 envelope for the cert SafeContents.
    let mut cert_pbes_salt = [0u8; 16];
    let mut cert_pbes_iv = [0u8; 16];
    rng.fill_bytes(&mut cert_pbes_salt);
    rng.fill_bytes(&mut cert_pbes_iv);
    let cert_pbes_params = pkcs5::pbes2::Parameters::pbkdf2_sha256_aes256cbc(
        PBKDF2_ITERATIONS,
        &cert_pbes_salt,
        &cert_pbes_iv,
    )
    .map_err(pkcs5_err)?;
    let cert_ciphertext = cert_pbes_params
        .encrypt(password, &cert_safe_contents_der)
        .map_err(pkcs5_err)?;

    // Encode `pbes2 + AlgorithmIdentifier` as the contentEncryptionAlgorithm.
    // pkcs5::pbes2::Parameters implements `Sequence`, so we wrap it in
    // an AlgorithmIdentifier with `id-pbes2` OID.
    let pbes2_params_der = cert_pbes_params.to_der().map_err(der_err)?;
    let cert_enc_alg = AlgorithmIdentifierOwned {
        oid: pkcs5::pbes2::PBES2_OID,
        parameters: Some(
            x509_cert::der::Any::from_der(&pbes2_params_der).map_err(der_err)?,
        ),
    };
    let cert_enc_content_info = EncryptedContentInfo {
        content_type: ID_DATA,
        content_enc_alg: cert_enc_alg,
        encrypted_content: Some(OctetString::new(cert_ciphertext).map_err(der_err)?),
    };
    let cert_encrypted_data = EncryptedData {
        version: CmsVersion::V0,
        enc_content_info: cert_enc_content_info,
        unprotected_attrs: None,
    };
    let cert_encrypted_data_der = cert_encrypted_data.to_der().map_err(der_err)?;
    let cert_content_info = ContentInfo {
        content_type: ID_ENCRYPTED_DATA,
        content: Any::from_der(&cert_encrypted_data_der).map_err(der_err)?,
    };

    // ── 2. (optional) Shrouded private-key bag in id-data ────────────
    let mut auth_safe: Vec<ContentInfo> = vec![cert_content_info];

    if let Some(key_pem) = private_key_pem {
        let parsed = pem::parse(key_pem.trim()).map_err(|e| {
            RvError::ErrString(format!("export: bad private-key PEM: {e}"))
        })?;
        if parsed.tag() != "PRIVATE KEY" {
            return Err(RvError::ErrString(format!(
                "export: expected `PRIVATE KEY` PEM, got `{}`",
                parsed.tag()
            )));
        }
        let pkcs8_der = parsed.contents();

        // PBES2 envelope for the PKCS#8 key.
        let mut key_pbes_salt = [0u8; 16];
        let mut key_pbes_iv = [0u8; 16];
        rng.fill_bytes(&mut key_pbes_salt);
        rng.fill_bytes(&mut key_pbes_iv);
        let key_pbes_params = pkcs5::pbes2::Parameters::pbkdf2_sha256_aes256cbc(
            PBKDF2_ITERATIONS,
            &key_pbes_salt,
            &key_pbes_iv,
        )
        .map_err(pkcs5_err)?;
        let key_ciphertext = key_pbes_params
            .encrypt(password, pkcs8_der)
            .map_err(pkcs5_err)?;

        // Build EncryptedPrivateKeyInfo manually as
        //   SEQUENCE { AlgorithmIdentifier(pbes2 + params), OCTET STRING ct }
        let key_pbes_der = key_pbes_params.to_der().map_err(der_err)?;
        let alg_id_bytes =
            encode_algorithm_identifier(pkcs5::pbes2::PBES2_OID, &key_pbes_der)?;
        let ct_bytes = encode_octet_string(&key_ciphertext)?;
        let mut epki_inner = Vec::with_capacity(alg_id_bytes.len() + ct_bytes.len());
        epki_inner.extend_from_slice(&alg_id_bytes);
        epki_inner.extend_from_slice(&ct_bytes);
        let epki = wrap_in_tag(0x30, &epki_inner);

        // PKCS-8 shrouded-key SafeBag.
        let key_bag = SafeBag {
            bag_id: PKCS_12_PKCS8_KEY_BAG_OID,
            bag_value: epki,
            bag_attributes: None,
        };
        let key_safe_contents_der = encode_safe_contents(&[key_bag])?;
        let key_content_info = ContentInfo {
            content_type: ID_DATA,
            content: Any::from_der(&encode_octet_string(&key_safe_contents_der)?)
                .map_err(der_err)?,
        };
        auth_safe.push(key_content_info);
    }

    // ── 3. AuthenticatedSafe → outer id-data ContentInfo ────────────
    let auth_safe_der = encode_authenticated_safe(&auth_safe)?;
    let outer_content_info = ContentInfo {
        content_type: ID_DATA,
        content: Any::from_der(&encode_octet_string(&auth_safe_der)?)
            .map_err(der_err)?,
    };

    // ── 4. MAC over the AuthenticatedSafe DER ───────────────────────
    let mut mac_salt = [0u8; 16];
    rng.fill_bytes(&mut mac_salt);
    let mac_key = pkcs12::kdf::derive_key_utf8::<Sha256Pkcs12Kdf>(
        password,
        &mac_salt,
        pkcs12::kdf::Pkcs12KeyType::Mac,
        MAC_ITERATIONS,
        32,
    )
    .map_err(der_err)?;
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(&mac_key).map_err(|e| {
            RvError::ErrString(format!("export: hmac key length: {e}"))
        })?;
    mac.update(&auth_safe_der);
    let mac_digest = mac.finalize().into_bytes();

    let mac_data = MacData {
        mac: DigestInfo {
            algorithm: AlgorithmIdentifierOwned {
                oid: ID_HMAC_WITH_SHA256,
                parameters: None,
            },
            digest: OctetString::new(mac_digest.to_vec()).map_err(der_err)?,
        },
        mac_salt: OctetString::new(mac_salt.to_vec()).map_err(der_err)?,
        iterations: MAC_ITERATIONS,
    };

    // ── 5. PFX top-level ────────────────────────────────────────────
    let pfx = Pfx {
        version: Version::V3,
        auth_safe: outer_content_info,
        mac_data: Some(mac_data),
    };
    let der = pfx.to_der().map_err(der_err)?;

    Ok(ExportBundle {
        format: ExportFormat::Pkcs12,
        body: der,
        extension: "p12",
    })
}

// ── ASN.1 helpers ───────────────────────────────────────────────────

fn encode_safe_contents(
    bags: &[pkcs12::safe_bag::SafeBag],
) -> Result<Vec<u8>, RvError> {
    // SafeContents = SEQUENCE OF SafeBag.  Each bag encodes itself
    // through `der::Encode`; we wrap them in an outer SEQUENCE.
    let mut inner = Vec::new();
    for bag in bags {
        let mut bytes = Vec::new();
        bag.encode(&mut bytes).map_err(der_err)?;
        inner.extend_from_slice(&bytes);
    }
    Ok(wrap_in_tag(0x30, &inner))
}

fn encode_authenticated_safe(items: &[ContentInfo]) -> Result<Vec<u8>, RvError> {
    let mut inner = Vec::new();
    for ci in items {
        let mut bytes = Vec::new();
        ci.encode(&mut bytes).map_err(der_err)?;
        inner.extend_from_slice(&bytes);
    }
    Ok(wrap_in_tag(0x30, &inner))
}

fn encode_octet_string(content: &[u8]) -> Result<Vec<u8>, RvError> {
    Ok(wrap_in_tag(0x04, content))
}

fn encode_algorithm_identifier(
    oid: ObjectIdentifier,
    params_der: &[u8],
) -> Result<Vec<u8>, RvError> {
    let mut inner = Vec::new();
    let mut oid_bytes = Vec::new();
    oid.encode(&mut oid_bytes).map_err(der_err)?;
    inner.extend_from_slice(&oid_bytes);
    inner.extend_from_slice(params_der);
    Ok(wrap_in_tag(0x30, &inner))
}

/// Wrap `content` in a primitive DER TLV with the given tag byte,
/// computing the appropriate short / long-form length encoding.
fn wrap_in_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    push_der_length(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

fn push_der_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let mut buf = [0u8; 8];
    let mut n = len;
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = (n & 0xff) as u8;
        n >>= 8;
    }
    let bytes = &buf[i..];
    out.push(0x80 | bytes.len() as u8);
    out.extend_from_slice(bytes);
}

fn pkcs5_err(e: pkcs5::Error) -> RvError {
    RvError::ErrString(format!("export: PBES2 error: {e}"))
}

fn der_err(e: der::Error) -> RvError {
    RvError::ErrString(format!("export: DER error: {e}"))
}
