use std::{fmt::Debug, sync::Arc, time::SystemTime};

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};

use crate::errors::RvError;

#[derive(Debug, Clone, Default)]
pub struct CertBundle {
    pub certificate_pem: Vec<u8>,
    pub ca_chain_pem: Vec<Vec<u8>>,
    pub private_key: Vec<u8>,
}

impl CertBundle {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Certificate {
    pub common_name: String,
    pub not_before: Option<SystemTime>,
    pub not_after: Option<SystemTime>,
    pub key_type: String,
    pub key_bits: u32,
}

impl Certificate {
    pub fn to_cert_bundle(
        &self,
        _ca_cert_pem: Option<&[u8]>,
        _ca_key_pem: Option<&[u8]>,
        _private_key_pem: Option<&[u8]>,
    ) -> Result<CertBundle, RvError> {
        Err(RvError::ErrLogicalOperationUnsupported)
    }
}

pub fn validate_certificate_key_type_and_bits(key_type: &str, key_bits: u64) -> Result<u32, RvError> {
    match (key_type, key_bits) {
        ("ml-kem-768", 768) => Ok(768),
        ("ml-dsa-65", 65) => Ok(65),
        _ => Err(RvError::ErrPkiKeyTypeInvalid),
    }
}

pub fn cert_bundle_from_pem_bundle(_pem_bundle: &str) -> Result<CertBundle, RvError> {
    Err(RvError::ErrLogicalOperationUnsupported)
}

pub fn ensure_not_after_within_ca(_ca_cert: &[u8], _requested_not_after: SystemTime) -> Result<(), RvError> {
    Err(RvError::ErrLogicalOperationUnsupported)
}

pub fn certificate_pem_string(cert_pem: &[u8]) -> Result<String, RvError> {
    String::from_utf8(cert_pem.to_vec()).map_err(|e| RvError::ErrString(e.to_string()))
}

pub fn certificate_pem_string_from_der(cert_der: &[u8]) -> Result<String, RvError> {
    String::from_utf8(cert_der.to_vec()).map_err(|e| RvError::ErrString(e.to_string()))
}

pub fn certificate_chain_pem_string(chain: &[Vec<u8>], reverse: bool) -> Result<String, RvError> {
    let iter: Box<dyn Iterator<Item = &Vec<u8>>> = if reverse {
        Box::new(chain.iter().rev())
    } else {
        Box::new(chain.iter())
    };

    let mut pem = String::new();
    for cert in iter {
        pem.push_str(&certificate_pem_string(cert)?);
    }

    Ok(pem)
}

#[derive(Debug)]
pub struct DisabledVerifier;

impl ServerCertVerifier for DisabledVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

pub type DisabledVerifierRef = Arc<DisabledVerifier>;
