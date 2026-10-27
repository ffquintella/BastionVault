//! TLS for host connectors: rustls on the `ring` provider, chosen explicitly
//! per configuration (never the process-wide default provider). Verifies
//! against the connection's CA when the operator gave one, else the OS trust
//! store; skips verification only under the operator's insecure policy.

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{ring, verify_tls12_signature, verify_tls13_signature, CryptoProvider},
    pki_types::{pem::PemObject, CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{pool::TlsPolicy, DynamicError};

/// Where the OS trust store comes from (a function so tests can replace it).
pub type RootSource = fn() -> Result<Vec<CertificateDer<'static>>, String>;

/// The OS trust store. An empty store is an error up front rather than a
/// less useful verification failure later.
pub fn system_roots() -> Result<Vec<CertificateDer<'static>>, String> {
    let loaded = rustls_native_certs::load_native_certs();
    if loaded.certs.is_empty() {
        return Err(format!("no system root certificates could be loaded ({} errors)", loaded.errors.len()));
    }
    Ok(loaded.certs)
}

fn parse_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>, DynamicError> {
    let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| DynamicError::invalid("tls_ca_pem", "not a PEM certificate bundle"))?;
    if certs.is_empty() {
        return Err(DynamicError::invalid("tls_ca_pem", "holds no certificate"));
    }
    Ok(certs)
}

/// The rustls client configuration for `policy`.
pub fn client_config(policy: &TlsPolicy, system: RootSource) -> Result<Arc<ClientConfig>, DynamicError> {
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| DynamicError::invalid("tls", e.to_string()))?;
    let config = if policy.verifies() {
        let anchors = match policy.ca_pem() {
            Some(pem) => parse_pem(pem)?,
            None => system().map_err(|e| DynamicError::invalid("tls trust store", e))?,
        };
        let mut roots = RootCertStore::empty();
        let (added, _) = roots.add_parsable_certificates(anchors);
        if added == 0 {
            return Err(DynamicError::invalid("tls trust store", "no usable trust anchor"));
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate(provider)))
            .with_no_client_auth()
    };
    Ok(Arc::new(config))
}

/// `insecure_skip_tls_verify`: chain and name are not checked; the handshake
/// signatures still are, with the provider's algorithms.
#[derive(Debug)]
struct AcceptAnyCertificate(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCertificate {
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
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A pending client handshake.
pub type Handshake<S> = Pin<Box<dyn Future<Output = io::Result<TlsStream<S>>> + Send>>;

/// A rustls client handshake to `name` over `stream`.
pub fn connect_tls<S>(config: Arc<ClientConfig>, name: &str, stream: S) -> Result<Handshake<S>, io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let name = ServerName::try_from(name.to_string())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the host name is not a valid TLS server name"))?;
    Ok(Box::pin(async move {
        let tls = tokio_rustls::TlsConnector::from(config).connect(name, stream).await?;
        Ok(TlsStream(tls))
    }))
}

/// A client TLS stream.
pub struct TlsStream<S>(tokio_rustls::client::TlsStream<S>);

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::{
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig,
    };
    use tokio_rustls::TlsAcceptor;

    use super::*;

    fn unrelated_roots() -> Result<Vec<CertificateDer<'static>>, String> {
        let other = generate_simple_self_signed(vec!["unrelated.example".to_string()]).map_err(|e| e.to_string())?;
        Ok(vec![other.cert.der().clone()])
    }

    fn server_for(name: &str) -> (TlsAcceptor, String) {
        let CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec![name.to_string()]).unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)
            .unwrap();
        (TlsAcceptor::from(Arc::new(config)), cert.pem())
    }

    /// Handshake against a server whose certificate names `cert_name`,
    /// dialling `dial_name`; `trust_it` makes it the operator CA.
    async fn handshake(policy: TlsPolicy, cert_name: &str, dial_name: &str, trust_it: bool) -> io::Result<()> {
        let (acceptor, cert_pem) = server_for(cert_name);
        let policy = if trust_it { TlsPolicy::verify_with_ca(cert_pem) } else { policy };
        let config = client_config(&policy, unrelated_roots).map_err(|e| io::Error::other(e.to_string()))?;
        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        let connect = connect_tls(config, dial_name, client_io)?;
        let (client, _server) = tokio::join!(connect, acceptor.accept(server_io));
        client.map(|_| ())
    }

    #[tokio::test]
    async fn the_operator_ca_is_trusted_and_the_name_is_checked() {
        handshake(TlsPolicy::default(), "db.internal", "db.internal", true).await.unwrap();
        let wrong = handshake(TlsPolicy::default(), "db.internal", "other.internal", true).await;
        assert!(wrong.is_err(), "a certificate for another name is refused");
    }

    #[tokio::test]
    async fn verification_is_the_default_and_an_unknown_issuer_is_refused() {
        let refused = handshake(TlsPolicy::default(), "db.internal", "db.internal", false).await;
        let err = refused.expect_err("a self-signed server not in the trust store");
        assert!(err.to_string().to_lowercase().contains("certificate"), "{err}");
    }

    #[tokio::test]
    async fn only_the_insecure_policy_skips_verification() {
        handshake(TlsPolicy::insecure_skip_verify(), "db.internal", "anything.example", false).await.unwrap();
    }

    #[test]
    fn a_bad_ca_bundle_or_an_empty_store_is_refused_up_front() {
        assert!(client_config(&TlsPolicy::verify_with_ca("not a pem".into()), unrelated_roots).is_err());
        let none: RootSource = || Ok(Vec::new());
        assert!(client_config(&TlsPolicy::default(), none).is_err());
    }
}
