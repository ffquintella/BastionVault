//! RadSec (RFC 6614) TLS: the aws-lc-rs provider, TLS 1.2 and 1.3, a NAS
//! client certificate required and verified against the configured CA. The
//! NAS is then identified by the SHA-256 of its certificate, pinned on its
//! client record. Key material is never echoed in an error.

use std::sync::Arc;

use rustls::{
    crypto::CryptoProvider,
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    RootCertStore, ServerConfig,
};
use sha2::{Digest, Sha256};

use crate::posix::model::PosixError;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn invalid(msg: String) -> PosixError {
    PosixError::Invalid(msg)
}

pub fn certificates(pem: &str, what: &str) -> Result<Vec<CertificateDer<'static>>, PosixError> {
    let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid(format!("{what}: malformed PEM")))?;
    if certs.is_empty() {
        return Err(invalid(format!("{what}: no PEM certificate found")));
    }
    Ok(certs)
}

fn private_key(pem: &str) -> Result<PrivateKeyDer<'static>, PosixError> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes())
        .map_err(|_| invalid("tls_key_pem: no PEM private key found, or the PEM is malformed".into()))
}

/// Lower-case hex SHA-256 of a DER certificate: how a RadSec NAS is named.
pub fn cert_fingerprint(der: &[u8]) -> String {
    hex(&Sha256::digest(der))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 64 lower-case hex digits.
pub fn validate_fingerprint(fp: &str) -> Result<(), PosixError> {
    if fp.len() == 64 && fp.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        Ok(())
    } else {
        Err(invalid("cert_sha256 must be the 64 lower-case hex digits of the NAS certificate's SHA-256".into()))
    }
}

/// The listener's TLS configuration. Building it is also how a config write
/// is validated: a certificate and key that do not match are refused then.
pub fn server_config(cert_pem: &str, key_pem: &str, client_ca_pem: &str) -> Result<Arc<ServerConfig>, PosixError> {
    let provider = provider();
    let mut roots = RootCertStore::empty();
    for cert in certificates(client_ca_pem, "client_ca_pem")? {
        roots.add(cert).map_err(|e| invalid(format!("client_ca_pem: unusable CA certificate: {e}")))?;
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| invalid(format!("client_ca_pem: {e}")))?;
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| invalid(format!("TLS versions unavailable: {e}")))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates(cert_pem, "tls_cert_pem")?, private_key(key_pem)?)
        .map_err(|_| invalid("tls_cert_pem and tls_key_pem do not form a usable identity".into()))?;
    Ok(Arc::new(config))
}
