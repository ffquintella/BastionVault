//! Web Application Connect, proxy mode — the upstream leg's trust decision
//! (features/web-application-connect.md §10; T106 step 3).
//!
//! In proxy mode the webview no longer validates the session's origins: it
//! validates the proxy. The proxy therefore has to make the decision the
//! engine used to, and make the *same* one the Phase 4 gate would:
//!
//! 1. `rustls-platform-verifier` — the OS trust store on macOS and Windows,
//!    the native roots on Linux (chain, host name, validity, `serverAuth`).
//!    A certificate it accepts is used, pin or not: a pin is an override,
//!    never a restriction.
//! 2. Rejected, and the profile pins keys: `tls_pin::decide`, the function
//!    [`super::web_tls_pin`] and the vault's agent fetch already share. A
//!    pinned leaf is accepted as is; a pinned *presented* issuer only if the
//!    leaf verifies under it alone for this host.
//! 3. Rejected, and the profile pins nothing: refused.
//!
//! There is no trust on first use here and no operator prompt. The Phase 4a
//! prompt asks a human about a certificate their own window is showing them;
//! a proxy connection has no window of its own, and a session that fell back
//! to "accept anything" on the leg that carries the credential would be
//! worse than one that fails. **The refusal is the whole point**: the
//! `CONNECT` fails, the webview shows an error, and the secret is never
//! offered to a server nobody vouched for.

// See the note in `web_proxy.rs`: nothing constructs a session proxy until
// the platform wiring of T106 step 4.
#![allow(dead_code)]

use std::fmt;
use std::sync::Arc;

use bastion_vault::utils::tls_pin::{decide, PinDecision, PinMatch, PinRefusal, PinSet};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

/// How an upstream handshake was admitted, for the lock state and the audit
/// line (T106 step 6). Never carries a name from the certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamTrust {
    /// The platform's trust store accepted it.
    Platform,
    /// The platform rejected it; one of the profile's pins admitted it.
    Pinned(PinMatch),
}

impl UpstreamTrust {
    pub fn label(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::Pinned(PinMatch::Leaf) => "pinned-leaf",
            Self::Pinned(PinMatch::Issuer { .. }) => "pinned-issuer",
        }
    }
}

/// Why an upstream handshake was refused. [`check`](Self::check) is the
/// fixed `[a-z0-9_]{1,32}` name that goes in a log or audit line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamRefusal {
    /// The platform rejected it and the profile pins nothing.
    Unpinned,
    /// The platform rejected it and no pin admits it.
    Pin(PinRefusal),
}

impl UpstreamRefusal {
    pub fn check(self) -> &'static str {
        match self {
            Self::Unpinned => "proxy_upstream_untrusted",
            Self::Pin(r) => r.check(),
        }
    }
}

/// The upstream verifier of one session: the platform's trust, plus the
/// profile's pins as the override. Shared by every upstream connection the
/// session makes, so it holds no per-handshake state — a refusal surfaces as
/// the handshake error, which the listener turns into a named `CONNECT`
/// failure.
pub struct UpstreamVerifier {
    platform: Arc<dyn ServerCertVerifier>,
    pins: PinSet,
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for UpstreamVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamVerifier").field("pins", &self.pins.len()).finish_non_exhaustive()
    }
}

impl UpstreamVerifier {
    pub fn new(pins: PinSet) -> Result<Arc<Self>, String> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let platform = rustls_platform_verifier::Verifier::new(Arc::clone(&provider))
            .map_err(|e| format!("web proxy: the platform trust store could not be opened: {e}"))?;
        Ok(Arc::new(Self { platform: Arc::new(platform), pins, provider }))
    }

    /// For the tests, and for a future host that wants to pass its own
    /// anchors: `platform` stands in for the OS trust store.
    #[cfg(test)]
    fn with_platform(platform: Arc<dyn ServerCertVerifier>, pins: PinSet) -> Arc<Self> {
        Arc::new(Self { platform, pins, provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()) })
    }

    /// A client configuration that trusts exactly what this verifier admits.
    /// HTTP/1.1 only: the terminated leg speaks 1.1 and the proxy does not
    /// translate versions.
    pub fn client_config(self: &Arc<Self>) -> Result<Arc<ClientConfig>, String> {
        let mut config = ClientConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("web proxy: TLS client configuration: {e}"))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::clone(self) as Arc<dyn ServerCertVerifier>)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    /// The decision on its own, without a handshake — so the rules are
    /// testable and so the listener can name a refusal.
    fn judge(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<UpstreamTrust, (UpstreamRefusal, rustls::Error)> {
        let platform_error = match self.platform.verify_server_cert(end_entity, intermediates, server_name, ocsp, now) {
            Ok(_) => return Ok(UpstreamTrust::Platform),
            Err(e) => e,
        };
        // The proxy only ever dials the session's own https origins — a
        // `CONNECT` outside the termination scope is tunnelled and never
        // reaches this verifier — so the host is in the pins' scope by
        // construction.
        let chain: Vec<Vec<u8>> =
            std::iter::once(end_entity).chain(intermediates.iter()).map(|c| c.as_ref().to_vec()).collect();
        let host = server_name.to_str();
        match decide(&self.pins, Some(host.as_ref()), &chain, now) {
            PinDecision::Accept(m) => Ok(UpstreamTrust::Pinned(m)),
            PinDecision::NotApplicable => Err((UpstreamRefusal::Unpinned, platform_error)),
            PinDecision::Refuse(r) => {
                Err((UpstreamRefusal::Pin(r), rustls::Error::General(format!("TLS pin refused: {}", r.check()))))
            }
        }
    }
}

impl ServerCertVerifier for UpstreamVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.judge(end_entity, intermediates, server_name, ocsp_response, now) {
            Ok(trust) => {
                // Origin and verdict only: never a path, a query, or a name
                // read out of the certificate.
                log::debug!("web proxy: upstream {} trusted ({})", server_name.to_str(), trust.label());
                Ok(ServerCertVerified::assertion())
            }
            Err((refusal, error)) => {
                log::warn!("web proxy: upstream {} refused ({})", server_name.to_str(), refusal.check());
                Err(error)
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use bastion_vault::utils::tls_pin::SpkiPin;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
    use rustls::client::WebPkiServerVerifier;
    use rustls::RootCertStore;

    use super::*;

    struct Ca {
        params: CertificateParams,
        key: KeyPair,
        der: Vec<u8>,
    }

    fn ca() -> Ca {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, "Upstream test CA");
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let der = params.self_signed(&key).unwrap().der().to_vec();
        Ca { params, key, der }
    }

    fn leaf(ca: &Ca, host: &str) -> Vec<u8> {
        let key = KeyPair::generate().unwrap();
        CertificateParams::new(vec![host.to_string()])
            .unwrap()
            .signed_by(&key, &Issuer::from_params(&ca.params, &ca.key))
            .unwrap()
            .der()
            .to_vec()
    }

    /// Stands in for the platform's trust store.
    fn platform(roots: &[&[u8]]) -> Arc<dyn ServerCertVerifier> {
        let mut store = RootCertStore::empty();
        for der in roots {
            store.add(CertificateDer::from(der.to_vec())).unwrap();
        }
        if store.is_empty() {
            // An empty root store is not a usable WebPkiServerVerifier, and
            // "trusts nothing" is exactly what the test wants.
            return Arc::new(TrustsNothing);
        }
        WebPkiServerVerifier::builder_with_provider(
            Arc::new(store),
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .build()
        .unwrap()
    }

    #[derive(Debug)]
    struct TrustsNothing;

    impl ServerCertVerifier for TrustsNothing {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer))
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            unreachable!()
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            unreachable!()
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            Vec::new()
        }
    }

    fn pins(list: &[&[u8]]) -> PinSet {
        let strs: Vec<String> = list.iter().map(|der| SpkiPin::of_certificate(der).unwrap().to_string()).collect();
        PinSet::from_strs(&strs).unwrap()
    }

    fn judge(v: &UpstreamVerifier, chain: &[Vec<u8>], host: &str) -> Result<UpstreamTrust, UpstreamRefusal> {
        let name = ServerName::try_from(host.to_string()).unwrap();
        let rest: Vec<CertificateDer<'_>> = chain[1..].iter().map(|c| CertificateDer::from(c.as_slice())).collect();
        v.judge(&CertificateDer::from(chain[0].as_slice()), &rest, &name, &[], UnixTime::now()).map_err(|(r, _)| r)
    }

    #[test]
    fn a_platform_trusted_certificate_is_used_pin_or_not() {
        let ca = ca();
        let cert = leaf(&ca, "app.internal");
        let other = self::ca();
        let v = UpstreamVerifier::with_platform(platform(&[&ca.der]), pins(&[&other.der]));
        assert_eq!(judge(&v, std::slice::from_ref(&cert), "app.internal"), Ok(UpstreamTrust::Platform));
    }

    #[test]
    fn an_untrusted_certificate_needs_a_pin_and_never_a_prompt() {
        let self_signed = ca();
        let cert = leaf(&self_signed, "app.internal");

        let pinned = UpstreamVerifier::with_platform(platform(&[]), pins(&[&cert]));
        assert_eq!(
            judge(&pinned, std::slice::from_ref(&cert), "app.internal"),
            Ok(UpstreamTrust::Pinned(PinMatch::Leaf))
        );

        let wrong = UpstreamVerifier::with_platform(platform(&[]), pins(&[&self::ca().der]));
        assert_eq!(
            judge(&wrong, std::slice::from_ref(&cert), "app.internal"),
            Err(UpstreamRefusal::Pin(PinRefusal::Mismatch))
        );

        let unpinned = UpstreamVerifier::with_platform(platform(&[]), PinSet::default());
        assert_eq!(judge(&unpinned, &[cert], "app.internal"), Err(UpstreamRefusal::Unpinned));
        assert_eq!(UpstreamRefusal::Unpinned.check(), "proxy_upstream_untrusted");
    }

    #[test]
    fn an_issuer_pin_admits_only_a_leaf_it_signed_for_this_host() {
        let ca = ca();
        let cert = leaf(&ca, "app.internal");
        let v = UpstreamVerifier::with_platform(platform(&[]), pins(&[&ca.der]));
        assert_eq!(
            judge(&v, &[cert.clone(), ca.der.clone()], "app.internal"),
            Ok(UpstreamTrust::Pinned(PinMatch::Issuer { depth: 1 }))
        );
        assert_eq!(
            judge(&v, &[cert, ca.der.clone()], "evil.internal"),
            Err(UpstreamRefusal::Pin(PinRefusal::IssuerUnverified))
        );
    }

    /// The real constructor has to work on the development host: it is the
    /// only thing between the credential and an unverified server.
    #[test]
    fn the_platform_verifier_can_be_built() {
        assert!(UpstreamVerifier::new(PinSet::default()).is_ok());
    }
}
