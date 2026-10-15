//! The certificate check of an agent fetch (`features/mcp-brokered-sessions.md`
//! §6.3 "TLS"): platform roots, plus the profile's `tls_pin_sha256` with the
//! Phase 4 pinning semantics — through `bv_utils::tls_pin`, the decision the
//! desktop app makes, not a copy of it.
//!
//! In order, for every certificate a fetch's server presents:
//!
//! 1. rustls' WebPKI verification against the platform roots (chain, host
//!    name, validity, `serverAuth`). A certificate it accepts is used, pin
//!    or not: a pin is an override, never a restriction.
//! 2. Rejected, and the profile pins keys: `tls_pin::decide` — a pinned leaf
//!    is accepted as is; a pinned presented issuer only if the leaf verifies
//!    under it alone for this host. Anything else is refused.
//! 3. Rejected, and the profile pins nothing: refused.
//!
//! There is no trust on first use and no "accept anyway": an agent has no
//! operator at the certificate, and the desktop's prompt is for humans
//! looking at their own window. The handshake signature is always verified
//! with the presented leaf's key, so a pin is a proof of possession, not a
//! name match.
//!
//! The verifier records what it decided for each handshake, so the executor
//! can name a refusal precisely (`mcp_web_tls_unpinned`,
//! `mcp_web_tls_pin_mismatch`) and the event can say how trust was
//! established.

use std::{
    fmt,
    sync::{Arc, Mutex, OnceLock},
};

use bv_utils::tls_pin::{decide, PinDecision, PinMatch, PinRefusal, PinSet};
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, RootCertStore, SignatureScheme,
};

/// How one handshake's certificate was judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVerdict {
    /// The platform roots trust it.
    Platform,
    /// The platform rejected it; a pin admitted it.
    Pinned(PinMatch),
    /// The platform rejected it, and the profile pins nothing.
    Unpinned,
    /// The platform rejected it, and no pin admits it.
    PinRefused(PinRefusal),
}

impl TlsVerdict {
    /// `platform`, `pinned-leaf`, `pinned-issuer`: for events and
    /// transcripts. `None` for a refusal.
    pub fn trust_label(self) -> Option<&'static str> {
        match self {
            Self::Platform => Some("platform"),
            Self::Pinned(PinMatch::Leaf) => Some("pinned-leaf"),
            Self::Pinned(PinMatch::Issuer { .. }) => Some("pinned-issuer"),
            Self::Unpinned | Self::PinRefused(_) => None,
        }
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// The platform's trust anchors, read once per process. An operator who
/// adds a CA to the system store restarts the vault for it to count here.
/// An unreadable store is logged and treated as empty: every certificate is
/// then "rejected by the platform", and only a pin admits one — closed, not
/// open.
pub fn platform_roots() -> Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    ROOTS
        .get_or_init(|| {
            let loaded = rustls_native_certs::load_native_certs();
            for e in &loaded.errors {
                log::warn!("mcp web fetch: a platform trust anchor could not be read: {e}");
            }
            let mut roots = RootCertStore::empty();
            let (added, ignored) = roots.add_parsable_certificates(loaded.certs);
            if ignored > 0 {
                log::warn!("mcp web fetch: {ignored} platform trust anchors were unusable; {added} loaded");
            }
            Arc::new(roots)
        })
        .clone()
}

/// The verifier for one fetch: the platform roots, the profile's pins, and
/// a record of the last verdict.
pub struct AgentCertVerifier {
    platform: Option<Arc<WebPkiServerVerifier>>,
    pins: PinSet,
    provider: Arc<CryptoProvider>,
    last: Mutex<Option<TlsVerdict>>,
}

impl fmt::Debug for AgentCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentCertVerifier").field("pins", &self.pins.len()).finish_non_exhaustive()
    }
}

impl AgentCertVerifier {
    /// `roots` are the platform's (see [`platform_roots`]); tests pass their
    /// own. An empty store trusts nothing.
    pub fn new(roots: Arc<RootCertStore>, pins: PinSet) -> Arc<Self> {
        let provider = provider();
        let platform = if roots.is_empty() {
            None
        } else {
            match WebPkiServerVerifier::builder_with_provider(roots, provider.clone()).build() {
                Ok(v) => Some(v),
                Err(e) => {
                    log::warn!("mcp web fetch: the platform roots could not be used ({e}); only pins are trusted");
                    None
                }
            }
        };
        Arc::new(Self { platform, pins, provider, last: Mutex::new(None) })
    }

    /// What the last handshake decided, taken.
    pub fn take_verdict(&self) -> Option<TlsVerdict> {
        self.last.lock().ok().and_then(|mut v| v.take())
    }

    fn record(&self, verdict: TlsVerdict) {
        if let Ok(mut v) = self.last.lock() {
            *v = Some(verdict);
        }
    }

    /// A client config that trusts exactly what this verifier admits: TLS
    /// 1.2 and 1.3, HTTP/1.1 only, no client certificate.
    pub fn client_config(self: &Arc<Self>) -> Result<rustls::ClientConfig, rustls::Error> {
        let mut config = rustls::ClientConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(self.clone())
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }
}

impl ServerCertVerifier for AgentCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let platform_error = match &self.platform {
            Some(v) => match v.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now) {
                Ok(ok) => {
                    self.record(TlsVerdict::Platform);
                    return Ok(ok);
                }
                Err(e) => e,
            },
            None => rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
        };
        // Rejected by the platform. Only a pin may admit it; the fetch
        // dials only the profile's own https origins, so the host is in
        // scope by construction.
        let chain: Vec<Vec<u8>> =
            std::iter::once(end_entity).chain(intermediates.iter()).map(|c| c.as_ref().to_vec()).collect();
        let host = server_name.to_str();
        match decide(&self.pins, Some(host.as_ref()), &chain, now) {
            PinDecision::Accept(m) => {
                self.record(TlsVerdict::Pinned(m));
                Ok(ServerCertVerified::assertion())
            }
            PinDecision::NotApplicable => {
                self.record(TlsVerdict::Unpinned);
                Err(platform_error)
            }
            PinDecision::Refuse(r) => {
                self.record(TlsVerdict::PinRefused(r));
                Err(rustls::Error::General(format!("TLS pin refused: {}", r.check())))
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
    use bv_utils::tls_pin::SpkiPin;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};

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
        params.distinguished_name.push(DnType::CommonName, "Test CA");
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

    fn roots(ca: &Ca) -> Arc<RootCertStore> {
        let mut r = RootCertStore::empty();
        r.add(CertificateDer::from(ca.der.clone())).unwrap();
        Arc::new(r)
    }

    fn verify(v: &AgentCertVerifier, chain: &[Vec<u8>], host: &str) -> Result<(), rustls::Error> {
        let name = ServerName::try_from(host.to_string()).unwrap();
        let rest: Vec<CertificateDer<'_>> = chain[1..].iter().map(|c| CertificateDer::from(c.as_slice())).collect();
        v.verify_server_cert(&CertificateDer::from(chain[0].as_slice()), &rest, &name, &[], UnixTime::now()).map(|_| ())
    }

    fn pins(list: &[&[u8]]) -> PinSet {
        let strs: Vec<String> = list.iter().map(|der| SpkiPin::of_certificate(der).unwrap().to_string()).collect();
        PinSet::from_strs(&strs).unwrap()
    }

    /// Trusted by the roots: accepted, whatever the pins say.
    #[test]
    fn a_platform_trusted_certificate_is_used_pin_or_not() {
        let ca = ca();
        let cert = leaf(&ca, "app.internal");
        let other = self::ca();
        let v = AgentCertVerifier::new(roots(&ca), pins(&[&other.der]));
        assert!(verify(&v, std::slice::from_ref(&cert), "app.internal").is_ok());
        assert_eq!(v.take_verdict(), Some(TlsVerdict::Platform));
        // The roots check the name: another host is rejected, and with no
        // matching pin, refused.
        assert!(verify(&v, &[cert], "other.internal").is_err());
        assert_eq!(v.take_verdict(), Some(TlsVerdict::PinRefused(PinRefusal::Mismatch)));
    }

    /// Untrusted by the roots: a leaf pin admits it, a mismatch and a
    /// missing pin refuse it. No prompt, no trust on first use.
    #[test]
    fn an_untrusted_certificate_needs_a_pin() {
        let self_signed = ca();
        let cert = leaf(&self_signed, "app.internal");
        let empty = Arc::new(RootCertStore::empty());

        let pinned = AgentCertVerifier::new(empty.clone(), pins(&[&cert]));
        assert!(verify(&pinned, std::slice::from_ref(&cert), "app.internal").is_ok());
        assert_eq!(pinned.take_verdict(), Some(TlsVerdict::Pinned(PinMatch::Leaf)));
        assert_eq!(TlsVerdict::Pinned(PinMatch::Leaf).trust_label(), Some("pinned-leaf"));

        let wrong = AgentCertVerifier::new(empty.clone(), pins(&[&self::ca().der]));
        assert!(verify(&wrong, std::slice::from_ref(&cert), "app.internal").is_err());
        assert_eq!(wrong.take_verdict(), Some(TlsVerdict::PinRefused(PinRefusal::Mismatch)));

        let unpinned = AgentCertVerifier::new(empty, PinSet::default());
        assert!(verify(&unpinned, &[cert], "app.internal").is_err());
        assert_eq!(unpinned.take_verdict(), Some(TlsVerdict::Unpinned));
    }

    /// An issuer pin: the presented CA vouches only for its own leaf, for
    /// this host.
    #[test]
    fn an_issuer_pin_admits_only_a_leaf_it_signed_for_this_host() {
        let ca = ca();
        let cert = leaf(&ca, "app.internal");
        let v = AgentCertVerifier::new(Arc::new(RootCertStore::empty()), pins(&[&ca.der]));
        assert!(verify(&v, &[cert.clone(), ca.der.clone()], "app.internal").is_ok());
        assert_eq!(v.take_verdict(), Some(TlsVerdict::Pinned(PinMatch::Issuer { depth: 1 })));
        assert!(verify(&v, &[cert, ca.der.clone()], "evil.internal").is_err());
        assert_eq!(v.take_verdict(), Some(TlsVerdict::PinRefused(PinRefusal::IssuerUnverified)));
    }
}
