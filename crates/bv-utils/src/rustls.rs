use std::fmt;

use rustls::{
    crypto::{self, WebPkiSupportedAlgorithms},
    pki_types::{CertificateDer, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
    client::danger::HandshakeSignatureValid,
    DistinguishedName, DigitallySignedStruct, Error, SignatureScheme,
};

/// Requests a client certificate at the TLS layer but defers trust decisions to application code.
///
/// This matches the previous OpenSSL behavior used by the cert auth backend: the handshake still
/// proves possession of the client private key, while BastionVault decides whether the certificate
/// should be trusted for login.
pub struct OptionalClientAuthVerifier {
    supported_algs: WebPkiSupportedAlgorithms,
}

impl OptionalClientAuthVerifier {
    pub fn new() -> Self {
        Self {
            supported_algs: rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        }
    }
}

impl fmt::Debug for OptionalClientAuthVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OptionalClientAuthVerifier")
    }
}

impl ClientCertVerifier for OptionalClientAuthVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}
