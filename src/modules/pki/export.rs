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
    revocation::RevocationInfoChoices,
    signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignedData, SignerInfos,
    },
};
use x509_cert::der::{
    self,
    asn1::{Any, AnyRef, SetOfVec},
    Decode, Encode,
};
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
}

impl ExportFormat {
    pub fn parse(s: &str) -> Result<Self, RvError> {
        match s.to_ascii_lowercase().as_str() {
            "" | "pem" => Ok(Self::Pem),
            "pkcs7" | "p7b" | "p7c" => Ok(Self::Pkcs7),
            other => Err(RvError::ErrString(format!(
                "export: unknown format `{other}` (accepted: pem, pkcs7)"
            ))),
        }
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

fn der_err(e: der::Error) -> RvError {
    RvError::ErrString(format!("export: DER error: {e}"))
}
