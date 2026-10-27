//! TLS to PostgreSQL with rustls (ring provider), following the host's pool
//! grant: verify against the operator's CA when the connection has one,
//! else the OS trust store; skip verification only when the host says the
//! operator set `insecure_skip_tls_verify`. Never on the plugin's own say.

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bastion_plugin_dynamic_sdk::{DynamicError, TlsPolicy};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{ring, verify_tls12_signature, verify_tls13_signature, CryptoProvider},
    pki_types::{pem::PemObject, CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::tls::{ChannelBinding, MakeTlsConnect, TlsConnect, TlsStream};

/// Where the OS trust store comes from (a function so tests can replace it).
pub type RootSource = fn() -> Result<Vec<CertificateDer<'static>>, String>;

/// The OS trust store. Refuses to answer an empty store rather than letting
/// every verification fail later with a less useful error.
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
        .map_err(|_| DynamicError::invalid("the connection's tls_ca_pem is not a PEM certificate bundle"))?;
    if certs.is_empty() {
        return Err(DynamicError::invalid("the connection's tls_ca_pem holds no certificate"));
    }
    Ok(certs)
}

/// The rustls client configuration for one grant's TLS policy.
pub fn client_config(policy: &TlsPolicy, system: RootSource) -> Result<Arc<ClientConfig>, DynamicError> {
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| DynamicError::invalid(format!("TLS setup: {e}")))?;
    let config = if policy.verify {
        let anchors = match &policy.ca_pem {
            Some(pem) => parse_pem(pem)?,
            None => system().map_err(DynamicError::Target)?,
        };
        let mut roots = RootCertStore::empty();
        let (added, _) = roots.add_parsable_certificates(anchors);
        if added == 0 {
            return Err(DynamicError::invalid("no usable trust anchor for the connection"));
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

/// `insecure_skip_tls_verify`: the chain and name are not checked; the
/// handshake signatures still are, with the provider's algorithms.
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

/// tokio-postgres' TLS hook over rustls. No channel binding is offered
/// (SCRAM-SHA-256 without `-PLUS`); the certificate check is rustls'.
#[derive(Clone)]
pub struct MakeRustls {
    config: Arc<ClientConfig>,
}

impl MakeRustls {
    pub fn new(config: Arc<ClientConfig>) -> Self {
        Self { config }
    }
}

impl<S> MakeTlsConnect<S> for MakeRustls
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = RustlsStream<S>;
    type TlsConnect = RustlsConnect;
    type Error = io::Error;

    fn make_tls_connect(&mut self, domain: &str) -> Result<RustlsConnect, io::Error> {
        let name = ServerName::try_from(domain.to_string())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the host name is not a valid TLS server name"))?;
        Ok(RustlsConnect { config: self.config.clone(), name })
    }
}

pub struct RustlsConnect {
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
}

impl<S> TlsConnect<S> for RustlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = RustlsStream<S>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<RustlsStream<S>>> + Send>>;

    fn connect(self, stream: S) -> Self::Future {
        Box::pin(async move {
            let tls = tokio_rustls::TlsConnector::from(self.config).connect(self.name, stream).await?;
            Ok(RustlsStream(tls))
        })
    }
}

pub struct RustlsStream<S>(tokio_rustls::client::TlsStream<S>);

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RustlsStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RustlsStream<S> {
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

impl<S: AsyncRead + AsyncWrite + Unpin> TlsStream for RustlsStream<S> {
    fn channel_binding(&self) -> ChannelBinding {
        ChannelBinding::none()
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

    /// Handshake our connector against a server whose certificate names
    /// `cert_name`, dialling `dial_name`; `trust_it` puts the server's
    /// certificate in the policy as the operator CA. Ok when the client
    /// accepted the server.
    async fn handshake(policy: TlsPolicy, cert_name: &str, dial_name: &str, trust_it: bool) -> io::Result<()> {
        let (acceptor, cert_pem) = server_for(cert_name);
        let policy = if trust_it { TlsPolicy { ca_pem: Some(cert_pem), ..policy } } else { policy };
        let config = client_config(&policy, unrelated_roots).map_err(|e| io::Error::other(e.to_string()))?;
        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        let mut make = MakeRustls::new(config);
        let connect = MakeTlsConnect::<tokio::io::DuplexStream>::make_tls_connect(&mut make, dial_name)?;
        let (client, _server) = tokio::join!(connect.connect(client_io), acceptor.accept(server_io));
        client.map(|_| ())
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    }

    #[test]
    fn the_operator_ca_is_trusted_and_the_name_is_checked() {
        rt().block_on(async {
            handshake(TlsPolicy::default(), "db.internal", "db.internal", true).await.unwrap();
            let wrong = handshake(TlsPolicy::default(), "db.internal", "other.internal", true).await;
            assert!(wrong.is_err(), "a certificate for another name is refused");
        });
    }

    #[test]
    fn verification_is_the_default_and_an_unknown_issuer_is_refused() {
        rt().block_on(async {
            let refused = handshake(TlsPolicy::default(), "db.internal", "db.internal", false).await;
            let err = refused.expect_err("a self-signed server not in the trust store");
            assert!(err.to_string().to_lowercase().contains("certificate"), "{err}");
        });
    }

    #[test]
    fn only_the_hosts_insecure_policy_skips_verification() {
        rt().block_on(async {
            let insecure = TlsPolicy { verify: false, ca_pem: None };
            handshake(insecure, "db.internal", "anything.example", false).await.unwrap();
        });
    }

    #[test]
    fn a_bad_ca_bundle_is_refused_up_front() {
        let policy = TlsPolicy { verify: true, ca_pem: Some("not a pem".into()) };
        assert!(client_config(&policy, unrelated_roots).is_err());
        let none: RootSource = || Ok(Vec::new());
        assert!(client_config(&TlsPolicy::default(), none).is_err(), "an empty trust store is an error");
    }
}
