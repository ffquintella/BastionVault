//! Web Application Connect, proxy mode — the per-session certificate
//! authority (features/web-application-connect.md §10; T106 step 2).
//!
//! The session webview is pointed at a loopback proxy that terminates TLS
//! for the session's own https origins, so it has to present a certificate
//! those origins' hosts. Nothing is installed in the OS trust store: the
//! webview is told to trust exactly two public keys, through the Phase 4
//! gate ([`super::web_tls_pin`]) — this CA's (issuer path) and the leaves'
//! (leaf path).
//!
//! What that costs is bounded on purpose:
//!
//! * **One key per session, one leaf per host.** Every leaf shares a single
//!   ECDSA P-256 key, so the leaf pin is one value for the whole session.
//! * **The CA is name-constrained** to the session's hosts, so even if its
//!   certificate were somehow reused it could not vouch for anything else.
//!   A verifier that enforces RFC 5280 name constraints (rustls' WebPKI,
//!   which the Phase 4 issuer path runs) rejects a leaf outside the set.
//! * **The CA's signing key is dropped as soon as the leaves are minted.**
//!   It is never stored on the returned value, so no later code path — and
//!   no later bug — can mint another certificate under this CA.
//! * **Short validity.** These certificates have no revocation path of any
//!   kind, so they expire on their own.
//!
//! Keys and certificates live only in memory and only for the session. No
//! Tauri, no sockets: unit-tested.

// See the note in `web_proxy.rs`: nothing constructs a session proxy until
// the platform wiring of T106 step 4.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use bastion_vault::utils::tls_pin::SpkiPin;
use rand::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose, NameConstraints, SerialNumber,
};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, ServerConfig};
use rustls::sign::CertifiedKey;
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

use super::web_proxy::bare_host;

/// How long a session's certificates are valid. There is no revocation path
/// for them, so the window is deliberately short; a web session that
/// outlives it has to be reopened.
const VALIDITY: Duration = Duration::days(7);

/// Clock-skew allowance on `notBefore`.
const BACKDATE: Duration = Duration::hours(1);

/// Most hosts one session may terminate. A profile names a handful; the
/// bound stops a malformed profile from asking for thousands of signatures
/// at launch.
pub const MAX_SESSION_HOSTS: usize = 64;

/// The certificates of one session: a name-constrained CA, and one leaf per
/// terminated host under a single key.
pub struct SessionCa {
    ca_der: Vec<u8>,
    ca_pin: SpkiPin,
    leaf_pin: SpkiPin,
    /// Keyed by the host as [`super::web_proxy::HttpsOrigin`] matches it:
    /// lower-cased, an IPv6 literal still bracketed.
    configs: BTreeMap<String, Arc<ServerConfig>>,
}

impl fmt::Debug for SessionCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hosts are not secret, but they are not interesting either; the
        // count is what a log line wants, and no key material is printable
        // from here at all.
        f.debug_struct("SessionCa").field("hosts", &self.configs.len()).finish_non_exhaustive()
    }
}

impl SessionCa {
    /// Mint the session's CA and its leaves. `hosts` are the distinct hosts
    /// of the session's termination scope
    /// ([`super::web_proxy::TerminationScope::hosts`]).
    pub fn mint(hosts: &[String]) -> Result<Self, String> {
        if hosts.is_empty() {
            return Err("web proxy: the session terminates no origin, so there is nothing to certify".to_string());
        }
        if hosts.len() > MAX_SESSION_HOSTS {
            return Err(format!(
                "web proxy: the session names {} hosts; at most {MAX_SESSION_HOSTS} are certified",
                hosts.len()
            ));
        }

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let now = OffsetDateTime::now_utc();
        let not_before = now - BACKDATE;
        let not_after = now + VALIDITY;

        let mut ca_params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| format!("web proxy: session CA parameters: {e}"))?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        ca_params.name_constraints = Some(name_constraints(hosts)?);
        ca_params.distinguished_name = distinguished_name("BastionVault web session CA");
        ca_params.not_before = not_before;
        ca_params.not_after = not_after;
        ca_params.serial_number = Some(random_serial());

        let leaf_key = KeyPair::generate().map_err(|e| format!("web proxy: session leaf key: {e}"))?;
        let leaf_key_der = Zeroizing::new(leaf_key.serialize_der());

        let mut configs = BTreeMap::new();
        let mut leaf_pin = None;
        let ca_der;
        {
            // Scoped so the CA's signing key is dropped with the issuer, the
            // moment the last leaf is signed. It is never moved onto `Self`.
            let ca_key = KeyPair::generate().map_err(|e| format!("web proxy: session CA key: {e}"))?;
            let ca_cert = ca_params.self_signed(&ca_key).map_err(|e| format!("web proxy: session CA: {e}"))?;
            ca_der = ca_cert.der().to_vec();
            let issuer = Issuer::from_params(&ca_params, &ca_key);

            for host in hosts {
                let leaf_der = mint_leaf(host, &leaf_key, &issuer, not_before, not_after)?;
                if leaf_pin.is_none() {
                    leaf_pin = Some(
                        SpkiPin::of_certificate(&leaf_der)
                            .map_err(|e| format!("web proxy: session leaf public key {e}"))?,
                    );
                }
                let chain = vec![CertificateDer::from(leaf_der), CertificateDer::from(ca_der.clone())];
                let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key_der.to_vec()));
                let certified = CertifiedKey::from_der(chain, key, &provider)
                    .map_err(|e| format!("web proxy: session leaf key could not be loaded: {e}"))?;
                let host = host.to_ascii_lowercase();
                configs.insert(host.clone(), server_config(&provider, host, Arc::new(certified))?);
            }
        }

        let ca_pin = SpkiPin::of_certificate(&ca_der).map_err(|e| format!("web proxy: session CA public key {e}"))?;
        let leaf_pin = leaf_pin.ok_or_else(|| "web proxy: no session leaf was minted".to_string())?;
        Ok(Self { ca_der, ca_pin, leaf_pin, configs })
    }

    /// The session CA's DER certificate — what the Linux shim registers per
    /// host and what the terminated connections present as the leaf's
    /// issuer. Public data.
    pub fn ca_der(&self) -> &[u8] {
        &self.ca_der
    }

    /// The pin the Phase 4 gate's **issuer** path matches (host-bound).
    pub fn ca_pin(&self) -> SpkiPin {
        self.ca_pin
    }

    /// The pin the Phase 4 gate's **leaf** path matches. One value for the
    /// session: every leaf shares the key.
    pub fn leaf_pin(&self) -> SpkiPin {
        self.leaf_pin
    }

    /// The TLS server configuration for one terminated host, or an error if
    /// the host is not one of the session's. Built once, at mint time.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        self.configs
            .get(&host.to_ascii_lowercase())
            .cloned()
            .ok_or_else(|| format!("web proxy: no session certificate for `{host}`"))
    }
}

fn mint_leaf(
    host: &str,
    leaf_key: &KeyPair,
    issuer: &Issuer<'_, impl rcgen::SigningKey>,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> Result<Vec<u8>, String> {
    // `CertificateParams::new` reads an IP literal as an iPAddress SAN and
    // anything else as a dNSName; the brackets of an IPv6 literal have to go
    // for that to happen.
    let mut params = CertificateParams::new(vec![bare_host(host).to_string()])
        .map_err(|e| format!("web proxy: `{host}` cannot be a certificate name: {e}"))?;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    // The identity is the SAN. The common name is a fixed label so a long
    // host cannot overflow the 64-character attribute limit, and WebPKI
    // ignores it.
    params.distinguished_name = distinguished_name("BastionVault web session");
    params.use_authority_key_identifier_extension = true;
    params.not_before = not_before;
    params.not_after = not_after;
    // Every leaf shares one key, so rcgen's default serial (a digest of the
    // public key) would be the same for all of them.
    params.serial_number = Some(random_serial());
    Ok(params
        .signed_by(leaf_key, issuer)
        .map_err(|e| format!("web proxy: session certificate for `{host}`: {e}"))?
        .der()
        .to_vec())
}

fn server_config(
    provider: &Arc<CryptoProvider>,
    host: String,
    key: Arc<CertifiedKey>,
) -> Result<Arc<ServerConfig>, String> {
    let mut config = ServerConfig::builder_with_provider(Arc::clone(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("web proxy: TLS server configuration: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(HostBoundCert { host, key }));
    // The proxy speaks HTTP/1.1 on both legs. Advertising nothing else keeps
    // the webview off h2, whose framing this listener does not handle.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Serves one host's leaf, and only for that host. The connection was
/// already bound to a host by its `CONNECT` authority, so an SNI naming a
/// different one is a mismatch, not a second virtual host: refuse it rather
/// than answer with this host's certificate.
#[derive(Debug)]
struct HostBoundCert {
    host: String,
    key: Arc<CertifiedKey>,
}

impl ResolvesServerCert for HostBoundCert {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        match hello.server_name() {
            // No SNI: an IP-literal origin, which sends none.
            None => Some(Arc::clone(&self.key)),
            Some(sni) if sni.eq_ignore_ascii_case(bare_host(&self.host)) => Some(Arc::clone(&self.key)),
            Some(_) => None,
        }
    }
}

fn distinguished_name(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn
}

fn random_serial() -> SerialNumber {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    // RFC 5280: serial numbers are positive integers.
    bytes[0] &= 0x7f;
    bytes[0] |= 0x01;
    SerialNumber::from(bytes.to_vec())
}

/// `permittedSubtrees` covering exactly the session's hosts. A name form is
/// only constrained when a subtree of that form is present, so an IP-literal
/// host contributes a single-address subnet rather than relying on the DNS
/// entries to cover it.
fn name_constraints(hosts: &[String]) -> Result<NameConstraints, String> {
    let mut permitted = Vec::with_capacity(hosts.len());
    for host in hosts {
        let bare = bare_host(host);
        match bare.parse::<IpAddr>() {
            Ok(IpAddr::V4(a)) => permitted.push(GeneralSubtree::IpAddress(CidrSubnet::from_v4_prefix(a.octets(), 32))),
            Ok(IpAddr::V6(a)) => permitted.push(GeneralSubtree::IpAddress(CidrSubnet::from_v6_prefix(a.octets(), 128))),
            Err(_) => {
                if bare.is_empty() {
                    return Err("web proxy: a session origin has an empty host".to_string());
                }
                permitted.push(GeneralSubtree::DnsName(bare.to_ascii_lowercase()));
            }
        }
    }
    Ok(NameConstraints { permitted_subtrees: permitted, excluded_subtrees: Vec::new() })
}

#[cfg(test)]
mod tests {
    use rustls::client::danger::ServerCertVerifier as _;
    use rustls::client::WebPkiServerVerifier;
    use rustls::pki_types::{ServerName, UnixTime};
    use rustls::RootCertStore;

    use super::*;

    /// Exactly the check the Phase 4 gate's issuer path runs: WebPKI with
    /// `anchor` as the only trust anchor, for `host`.
    fn verifies_under(anchor: &[u8], chain: &[CertificateDer<'static>], host: &str) -> bool {
        let mut roots = RootCertStore::empty();
        if roots.add(CertificateDer::from(anchor.to_vec())).is_err() {
            return false;
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let Ok(verifier) = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider).build() else {
            return false;
        };
        let Ok(name) = ServerName::try_from(host.to_string()) else { return false };
        verifier.verify_server_cert(&chain[0], &chain[1..], &name, &[], UnixTime::now()).is_ok()
    }

    fn mint(hosts: &[&str]) -> SessionCa {
        SessionCa::mint(&hosts.iter().map(|h| h.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn a_session_certifies_only_its_own_hosts() {
        let ca = mint(&["app.example.test", "sso.example.test"]);
        assert!(ca.server_config("APP.example.test").is_ok());
        assert!(ca.server_config("cdn.example.test").is_err());
    }

    #[test]
    fn the_ca_and_leaf_pins_are_stable_and_distinct() {
        let ca = mint(&["app.example.test", "sso.example.test"]);
        assert_ne!(ca.ca_pin(), ca.leaf_pin());
        // A second session shares nothing with the first.
        let other = mint(&["app.example.test"]);
        assert_ne!(ca.ca_pin(), other.ca_pin());
        assert_ne!(ca.leaf_pin(), other.leaf_pin());
    }

    #[test]
    fn mint_rejects_an_empty_or_oversized_host_set() {
        assert!(SessionCa::mint(&[]).is_err());
        let many: Vec<String> = (0..MAX_SESSION_HOSTS + 1).map(|i| format!("h{i}.example.test")).collect();
        assert!(SessionCa::mint(&many).is_err());
    }

    /// The name constraint is what stops this CA from being useful for
    /// anything but the session: a leaf it signed for an outside host does
    /// not verify under it.
    #[test]
    fn the_name_constraint_refuses_a_host_outside_the_session() {
        let in_scope = "app.example.test";
        let out_of_scope = "evil.example.test";
        let key = KeyPair::generate().unwrap();
        let now = OffsetDateTime::now_utc();
        let (not_before, not_after) = (now - BACKDATE, now + VALIDITY);

        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        ca_params.name_constraints = Some(name_constraints(&[in_scope.to_string()]).unwrap());
        ca_params.distinguished_name = distinguished_name("BastionVault web session CA");
        ca_params.not_before = not_before;
        ca_params.not_after = not_after;
        let ca_key = KeyPair::generate().unwrap();
        let ca_der = ca_params.self_signed(&ca_key).unwrap().der().to_vec();
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let good = mint_leaf(in_scope, &key, &issuer, not_before, not_after).unwrap();
        let bad = mint_leaf(out_of_scope, &key, &issuer, not_before, not_after).unwrap();

        assert!(verifies_under(&ca_der, &[CertificateDer::from(good)], in_scope));
        assert!(!verifies_under(&ca_der, &[CertificateDer::from(bad)], out_of_scope));
    }

    /// Another session's CA vouches for nothing of this one's.
    #[test]
    fn a_leaf_does_not_verify_under_another_sessions_ca() {
        let host = "app.example.test";
        let now = OffsetDateTime::now_utc();
        let (not_before, not_after) = (now - BACKDATE, now + VALIDITY);
        let constraints = name_constraints(&[host.to_string()]).unwrap();

        let make = || {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
            params.name_constraints = Some(constraints.clone());
            params.distinguished_name = distinguished_name("BastionVault web session CA");
            params.not_before = not_before;
            params.not_after = not_after;
            let key = KeyPair::generate().unwrap();
            let der = params.self_signed(&key).unwrap().der().to_vec();
            (params, key, der)
        };
        let (a_params, a_key, a_der) = make();
        let (_b_params, _b_key, b_der) = make();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf = mint_leaf(host, &leaf_key, &Issuer::from_params(&a_params, &a_key), not_before, not_after).unwrap();

        assert!(verifies_under(&a_der, &[CertificateDer::from(leaf.clone())], host));
        assert!(!verifies_under(&b_der, &[CertificateDer::from(leaf)], host));
    }

    #[test]
    fn an_ip_literal_host_gets_an_address_constraint() {
        let constraints = name_constraints(&["[::1]".to_string(), "127.0.0.1".to_string()]).unwrap();
        assert_eq!(constraints.permitted_subtrees.len(), 2);
        assert!(constraints.permitted_subtrees.iter().all(|s| matches!(s, GeneralSubtree::IpAddress(_))));
        // And the leaf for a bracketed IPv6 host is minted with the address,
        // not the brackets, as its SAN.
        assert!(SessionCa::mint(&["[::1]".to_string()]).is_ok());
    }
}
