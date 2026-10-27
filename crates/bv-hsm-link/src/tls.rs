//! TLS configuration for both halves: TLS 1.3 only, aws-lc-rs provider,
//! client certificates mandatory at the gateway, and the client identity
//! taken from an exact DNS SAN match.

use std::{fmt, sync::Arc};

use bv_errors::RvError;
use rustls::{
    crypto::CryptoProvider,
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    ClientConfig, RootCertStore, ServerConfig,
};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

use crate::config::LinkTls;

fn invalid(msg: impl Into<String>) -> RvError {
    RvError::ErrHsmConfigInvalid(msg.into())
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn certificates(pem: &[u8], what: &str) -> Result<Vec<CertificateDer<'static>>, RvError> {
    let certs = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| invalid(format!("{what}: malformed PEM: {e:?}")))?;
    if certs.is_empty() {
        return Err(invalid(format!("{what}: no PEM certificate found")));
    }
    Ok(certs)
}

/// The key's PEM error is not echoed: it could quote part of the file.
fn private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, RvError> {
    PrivateKeyDer::from_pem_slice(pem)
        .map_err(|_| invalid("link key: no PEM private key found, or the PEM is malformed"))
}

fn roots(pem: &[u8], what: &str) -> Result<Arc<RootCertStore>, RvError> {
    let mut store = RootCertStore::empty();
    for cert in certificates(pem, what)? {
        store.add(cert).map_err(|e| invalid(format!("{what}: unusable CA certificate: {e}")))?;
    }
    Ok(Arc::new(store))
}

/// Gateway side: present `tls`'s certificate, require a client certificate
/// chaining to `tls`'s CA. No CRL: revoking a node means removing it from
/// `allowed_clients` (and revoking its device auth keys).
pub(crate) fn server_config(tls: &LinkTls) -> Result<Arc<ServerConfig>, RvError> {
    let provider = provider();
    let verifier = WebPkiClientVerifier::builder_with_provider(roots(&tls.ca_pem, "client CA")?, provider.clone())
        .build()
        .map_err(|e| invalid(format!("client CA: {e}")))?;
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| invalid(format!("TLS 1.3 unavailable: {e}")))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates(&tls.cert_chain_pem, "gateway certificate")?, private_key(&tls.key_pem)?)
        .map_err(|e| invalid(format!("gateway certificate and key do not form a usable identity: {e}")))?;
    Ok(Arc::new(config))
}

/// Relay side: verify the gateway against `tls`'s CA and the URL's host,
/// and present the node's certificate.
pub(crate) fn client_config(tls: &LinkTls) -> Result<Arc<ClientConfig>, RvError> {
    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| invalid(format!("TLS 1.3 unavailable: {e}")))?
        .with_root_certificates(roots(&tls.ca_pem, "link CA")?)
        .with_client_auth_cert(certificates(&tls.cert_chain_pem, "node link certificate")?, private_key(&tls.key_pem)?)
        .map_err(|e| invalid(format!("node link certificate and key do not form a usable identity: {e}")))?;
    Ok(Arc::new(config))
}

/// Why an authenticated TLS peer is still refused.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IdentityError {
    NoCertificate,
    Unparseable,
    NotAllowed(Vec<String>),
    Ambiguous(Vec<String>),
}

/// At most 4 names of at most 64 characters, escaped: the SANs are
/// attacker-chosen text headed for the log.
fn shown(names: &[String]) -> String {
    let mut parts: Vec<String> = names.iter().take(4).map(|n| n.chars().take(64).collect::<String>()).collect();
    if names.len() > 4 {
        parts.push(format!("... {} more", names.len() - 4));
    }
    format!("{parts:?}")
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::NoCertificate => f.write_str("no client certificate"),
            IdentityError::Unparseable => f.write_str("client certificate SANs cannot be parsed"),
            IdentityError::NotAllowed(names) => {
                write!(f, "no DNS SAN of the client certificate is in allowed_clients (presented {})", shown(names))
            }
            IdentityError::Ambiguous(names) => {
                write!(f, "client certificate names more than one allowed client {}", shown(names))
            }
        }
    }
}

/// The client id of a verified peer: the one DNS SAN of its end-entity
/// certificate that equals an allowed client, byte for byte. Zero matches or
/// two different matches refuse the connection.
pub(crate) fn client_identity(
    certs: Option<&[CertificateDer<'_>]>,
    is_allowed: impl Fn(&str) -> bool,
) -> Result<String, IdentityError> {
    let end_entity = certs.and_then(<[_]>::first).ok_or(IdentityError::NoCertificate)?;
    let (rest, cert) = parse_x509_certificate(end_entity.as_ref()).map_err(|_| IdentityError::Unparseable)?;
    if !rest.is_empty() {
        return Err(IdentityError::Unparseable);
    }
    let san = cert.subject_alternative_name().map_err(|_| IdentityError::Unparseable)?;
    let names: Vec<String> = san
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    GeneralName::DNSName(name) => Some((*name).to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let mut matches: Vec<String> = names.iter().filter(|n| is_allowed(n)).cloned().collect();
    matches.sort();
    matches.dedup();
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(IdentityError::NotAllowed(names)),
        _ => Err(IdentityError::Ambiguous(matches)),
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair, SanType};

    use super::*;

    fn cert_with(sans: Vec<SanType>) -> CertificateDer<'static> {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = sans;
        params.self_signed(&key).unwrap().der().clone()
    }

    fn dns(name: &str) -> SanType {
        SanType::DnsName(name.try_into().unwrap())
    }

    fn identity(cert: &CertificateDer<'static>) -> Result<String, IdentityError> {
        let allowed = ["vault-1", "vault-2"];
        client_identity(Some(std::slice::from_ref(cert)), |n| allowed.contains(&n))
    }

    #[test]
    fn the_one_allowed_dns_san_is_the_identity() {
        assert_eq!(identity(&cert_with(vec![dns("vault-1")])), Ok("vault-1".to_string()));
        // Extra names that are not allowed do not matter; repeating one does not
        // make it ambiguous.
        let extra = cert_with(vec![dns("vault-2.internal"), dns("vault-2"), dns("vault-2")]);
        assert_eq!(identity(&extra), Ok("vault-2".to_string()));
    }

    #[test]
    fn matching_is_exact() {
        for name in ["VAULT-1", "vault-1.", "vault-1x", "*", "*.internal", "vault"] {
            assert!(matches!(identity(&cert_with(vec![dns(name)])), Err(IdentityError::NotAllowed(_))), "{name}");
        }
        // The node id only in a URI or IP SAN, or only in the CN, is not a match.
        let uri = cert_with(vec![SanType::URI("vault-1".try_into().unwrap())]);
        assert!(matches!(identity(&uri), Err(IdentityError::NotAllowed(_))));
        assert!(matches!(identity(&cert_with(vec![])), Err(IdentityError::NotAllowed(_))));
    }

    #[test]
    fn two_allowed_names_are_ambiguous_and_refused() {
        let both = cert_with(vec![dns("vault-1"), dns("vault-2")]);
        assert_eq!(identity(&both), Err(IdentityError::Ambiguous(vec!["vault-1".into(), "vault-2".into()])));
    }

    #[test]
    fn no_or_garbage_certificate_is_refused() {
        assert_eq!(client_identity(None, |_| true), Err(IdentityError::NoCertificate));
        assert_eq!(client_identity(Some(&[][..]), |_| true), Err(IdentityError::NoCertificate));
        let garbage = CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x00]);
        assert_eq!(client_identity(Some(&[garbage][..]), |_| true), Err(IdentityError::Unparseable));
    }

    #[test]
    fn refusal_text_escapes_and_bounds_presented_names() {
        let names: Vec<String> = (0..6).map(|i| format!("n{i}\u{1b}[31m{}", "x".repeat(100))).collect();
        let text = IdentityError::NotAllowed(names).to_string();
        assert!(!text.contains('\u{1b}'), "{text}");
        assert!(text.contains("2 more") && text.len() < 500, "{text}");
    }
}
