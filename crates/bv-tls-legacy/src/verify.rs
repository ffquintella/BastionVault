//! Server authentication: certificate chain, name and ServerKeyExchange
//! signature, all through `rustls-webpki`. There is no switch that turns any
//! of it off.

use rustls_pki_types::{
    pem::PemObject, CertificateDer, ServerName, SignatureVerificationAlgorithm, TrustAnchor, UnixTime,
};
use webpki::{ring as algs, EndEntityCert, KeyUsage};

use crate::error::TlsError;

/// Most certificates a server may present.
pub(crate) const MAX_CHAIN_LEN: usize = 10;
/// Most extra anchors a caller may add.
const MAX_EXTRA_ANCHORS: usize = 64;

/// Signature algorithms accepted on the certificate chain (the set rustls'
/// `ring` provider accepts; no SHA-1).
static CHAIN_ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    algs::ECDSA_P256_SHA256,
    algs::ECDSA_P256_SHA384,
    algs::ECDSA_P384_SHA256,
    algs::ECDSA_P384_SHA384,
    algs::ED25519,
    algs::RSA_PKCS1_2048_8192_SHA256,
    algs::RSA_PKCS1_2048_8192_SHA384,
    algs::RSA_PKCS1_2048_8192_SHA512,
    algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
];

/// `signature_algorithms` values offered in the ClientHello (RFC 5246
/// §7.4.1.4.1 / RFC 8446 code points). ECDSA is listed for the chain only.
pub(crate) const OFFERED_SIGNATURE_SCHEMES: [u16; 8] = [
    0x0804, // rsa_pss_rsae_sha256
    0x0805, // rsa_pss_rsae_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0401, // rsa_pkcs1_sha256
    0x0501, // rsa_pkcs1_sha384
    0x0601, // rsa_pkcs1_sha512
    0x0403, // ecdsa_secp256r1_sha256
    0x0503, // ecdsa_secp384r1_sha384
];

/// The webpki algorithm for a ServerKeyExchange signature scheme. Only the
/// RSA schemes we offered qualify under an ECDHE_RSA suite.
pub(crate) fn ske_algorithm(scheme: u16) -> Option<&'static dyn SignatureVerificationAlgorithm> {
    Some(match scheme {
        0x0401 => algs::RSA_PKCS1_2048_8192_SHA256,
        0x0501 => algs::RSA_PKCS1_2048_8192_SHA384,
        0x0601 => algs::RSA_PKCS1_2048_8192_SHA512,
        0x0804 => algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        0x0805 => algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        0x0806 => algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        _ => return None,
    })
}

/// The anchors a server chain must end at: the Mozilla set from
/// `webpki-roots`, plus any the caller adds. Added anchors never replace the
/// built-in ones.
#[derive(Clone)]
pub struct TrustAnchors {
    anchors: Vec<TrustAnchor<'static>>,
}

impl TrustAnchors {
    /// The built-in `webpki-roots` set.
    pub fn with_webpki_roots() -> Self {
        Self { anchors: webpki_roots::TLS_SERVER_ROOTS.to_vec() }
    }

    /// No anchors at all; tests only, so a test chain cannot accidentally
    /// verify through a public root.
    #[cfg(test)]
    pub(crate) fn empty() -> Self {
        Self { anchors: Vec::new() }
    }

    /// Add one DER certificate as an anchor (a root or an intermediate the
    /// server does not send).
    pub fn add_der(&mut self, der: &[u8]) -> Result<(), TlsError> {
        if self.anchors.len() >= webpki_roots::TLS_SERVER_ROOTS.len() + MAX_EXTRA_ANCHORS {
            return Err(TlsError::InvalidTrustAnchor(format!("more than {MAX_EXTRA_ANCHORS} extra anchors")));
        }
        let cert = CertificateDer::from(der);
        let anchor = webpki::anchor_from_trusted_cert(&cert)
            .map_err(|e| TlsError::InvalidTrustAnchor(format!("not an X.509 certificate: {e:?}")))?;
        self.anchors.push(anchor.to_owned());
        Ok(())
    }

    /// Add every CERTIFICATE block of `pem`; returns how many were added.
    /// Any other block, or none at all, is an error.
    pub fn add_pem(&mut self, pem: &str) -> Result<usize, TlsError> {
        let mut added = 0;
        for item in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            let cert = item.map_err(|e| TlsError::InvalidTrustAnchor(format!("bad PEM: {e:?}")))?;
            self.add_der(cert.as_ref())?;
            added += 1;
        }
        if added == 0 {
            return Err(TlsError::InvalidTrustAnchor("no CERTIFICATE block in the PEM".into()));
        }
        Ok(added)
    }

    /// Number of anchors (built-in + added).
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Whether there are no anchors at all.
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

/// Verify the server's chain (leaf first) for `server_name` at the current
/// time with the `serverAuth` EKU.
pub(crate) fn verify_server_chain(
    chain: &[CertificateDer<'static>],
    server_name: &ServerName<'_>,
    anchors: &TrustAnchors,
) -> Result<(), TlsError> {
    let (leaf, intermediates) =
        chain.split_first().ok_or_else(|| TlsError::CertificateRejected("server sent no certificate".into()))?;
    let reject = |e: webpki::Error| TlsError::CertificateRejected(format!("{e:?}"));
    let ee = EndEntityCert::try_from(leaf).map_err(reject)?;
    ee.verify_for_usage(
        CHAIN_ALGS,
        &anchors.anchors,
        intermediates,
        UnixTime::now(),
        KeyUsage::server_auth(),
        None,
        None,
    )
    .map_err(reject)?;
    ee.verify_is_valid_for_subject_name(server_name).map_err(reject)?;
    Ok(())
}

/// Verify the ServerKeyExchange signature over `signed` with the leaf key.
pub(crate) fn verify_ske_signature(
    leaf: &CertificateDer<'static>,
    scheme: u16,
    signed: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    let alg = ske_algorithm(scheme).ok_or(TlsError::PeerMisbehaved {
        alert: crate::error::alert::ILLEGAL_PARAMETER,
        what: "ServerKeyExchange signed with a scheme the client did not offer for an ECDHE_RSA suite",
    })?;
    let ee = EndEntityCert::try_from(leaf).map_err(|e| TlsError::CertificateRejected(format!("{e:?}")))?;
    ee.verify_signature(alg, signed, signature).map_err(|_| TlsError::BadServerKeyExchangeSignature)
}
