//! TLS SPKI pinning, the decision (`features/web-application-connect.md` §8,
//! T96 Phase 4): one implementation for the desktop app's session windows
//! and the vault's own agent web fetch (`features/mcp-brokered-sessions.md`
//! §6.3, T137).
//!
//! Moved here from the desktop crate (`gui/src-tauri/src/session/web_tls_pin.rs`)
//! without changing what it decides, so the two can never disagree about
//! what a pin admits. The desktop keeps its platform shims, its per-window
//! gate and its operator prompt; the vault wraps this in a rustls verifier
//! with no prompt at all.
//!
//! Appliances commonly serve self-signed or private-CA certificates. A `web`
//! profile may carry `tls_pin_sha256`: SHA-256 digests of a certificate's DER
//! `SubjectPublicKeyInfo`. The rules:
//!
//! * **A pin is an override, never a restriction.** It is consulted only for
//!   a certificate the platform has already rejected. A certificate the
//!   platform trusts is used as before, pin or not.
//! * **Only for a session's own https origins.** The caller decides scope:
//!   [`decide`] is given the host only when the origin is one of the
//!   session's https origins, and otherwise answers
//!   [`PinDecision::NotApplicable`] — the platform's rejection stands.
//! * **Leaf pin:** the leaf's SPKI is in the set. The TLS handshake proves
//!   the server holds that key, so nothing else is checked — not the host
//!   name, not the validity period. Appliance certificates commonly name the
//!   vendor rather than the host and carry long-expired dates; the pin names
//!   the exact key the operator confirmed.
//! * **Issuer pin:** the SPKI of a CA / intermediate certificate the server
//!   presented is in the set. A presented issuer certificate proves nothing by
//!   itself — it is public, and anyone can append it to their own chain — so
//!   the leaf must then pass rustls' WebPKI verification with that certificate
//!   as the **only** trust anchor: chain signatures, validity periods,
//!   `serverAuth` usage, and the host name. The issuer must be among the
//!   certificates the server presents (an SPKI digest alone is not a trust
//!   anchor).
//! * **Anything else is refused.** There is no "accept any certificate" path
//!   here; whether a caller may ask a human instead is the caller's policy
//!   (the desktop may, for a profile without pins; an agent session never).
//!
//! Pins are public-key digests, not secrets; they are compared with `==`.

use std::{fmt, sync::Arc};

use base64::Engine as _;
use rustls::{
    client::{danger::ServerCertVerifier as _, WebPkiServerVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    RootCertStore,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Most pins one profile may carry. A profile needs one or two (the current
/// key and the next); the bound keeps a pasted list from growing unnoticed.
pub const MAX_PINS: usize = 16;

/// Longest chain read off a platform or a probe; anything longer is cut.
pub const MAX_CHAIN: usize = 8;

/// One pin: the SHA-256 of a DER `SubjectPublicKeyInfo`. The digest is
/// public: it names a public key, it does not unlock anything.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpkiPin(pub [u8; 32]);

impl SpkiPin {
    /// Parse an operator-written pin. Accepted forms (surrounding whitespace
    /// ignored):
    ///
    /// * `sha256:<64 hex digits>` — the canonical form this crate and the GUI
    ///   write. The prefix is optional and case-insensitive, the hex any case,
    ///   and `:` between byte pairs is tolerated (`AB:CD:…`).
    /// * `sha256/<base64>` or curl's `sha256//<base64>` — the RFC 7469 /
    ///   `curl --pinnedpubkey` form: standard, padded base64 of the 32 bytes
    ///   (44 characters). Also accepted bare.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let s = raw.trim();
        if s.is_empty() {
            return Err("is empty".to_string());
        }
        // ASCII lower-casing keeps byte offsets, so `rest` maps back onto `s`.
        let lower = s.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("sha256//").or_else(|| lower.strip_prefix("sha256/")) {
            // Base64 is case-sensitive: decode the original text.
            return Self::from_base64(&s[s.len() - rest.len()..]);
        }
        let prefixed = lower.starts_with("sha256:");
        let hex_part = lower.strip_prefix("sha256:").unwrap_or(&lower);
        if let Some(pin) = Self::from_hex(hex_part) {
            return Ok(pin);
        }
        if !prefixed && s.len() == 44 {
            return Self::from_base64(s);
        }
        Err("is not a SHA-256 public-key pin: give sha256:<64 hex digits> or sha256/<base64>".to_string())
    }

    fn from_hex(h: &str) -> Option<Self> {
        let compact = if h.contains(':') {
            let parts: Vec<&str> = h.split(':').collect();
            if parts.len() != 32 || parts.iter().any(|p| p.len() != 2) {
                return None;
            }
            parts.concat()
        } else {
            h.to_string()
        };
        if compact.len() != 64 {
            return None;
        }
        let bytes = hex::decode(&compact).ok()?;
        <[u8; 32]>::try_from(bytes.as_slice()).ok().map(Self)
    }

    fn from_base64(b: &str) -> Result<Self, String> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b)
            .map_err(|_| "is not valid base64 (standard alphabet, padded)".to_string())?;
        <[u8; 32]>::try_from(bytes.as_slice())
            .map(Self)
            .map_err(|_| format!("decodes to {} bytes; a SHA-256 pin is 32", bytes.len()))
    }

    /// The pin of a DER `SubjectPublicKeyInfo`.
    pub fn of_spki_der(spki: &[u8]) -> Self {
        Self(Sha256::digest(spki).into())
    }

    /// The pin of a DER certificate's public key, hashed over the
    /// `SubjectPublicKeyInfo` bytes exactly as they appear in the certificate.
    pub fn of_certificate(der: &[u8]) -> Result<Self, String> {
        let (_, cert) = x509_parser::parse_x509_certificate(der).map_err(|e| format!("unreadable certificate: {e}"))?;
        Ok(Self::of_spki_der(cert.public_key().raw))
    }

    /// RFC 7469 / curl form, without the `sha256/` prefix.
    pub fn to_base64(self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }
}

/// `sha256:<hex>`, the canonical form.
impl fmt::Display for SpkiPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", hex::encode(self.0))
    }
}

impl fmt::Debug for SpkiPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A profile's pins, deduplicated. Empty means "no pinning".
#[derive(Clone, Debug, Default)]
pub struct PinSet {
    pins: Vec<SpkiPin>,
}

impl PinSet {
    /// `web.tls_pin_sha256` as stored on the profile. Every entry must be a
    /// readable pin: one that is not refuses the whole list, because dropping
    /// it would hide a typo behind a session that then fails closed for no
    /// visible reason.
    pub fn from_json(values: &[Value]) -> Result<Self, String> {
        let mut strs = Vec::with_capacity(values.len());
        for (i, v) in values.iter().enumerate() {
            strs.push(v.as_str().ok_or_else(|| format!("web.tls_pin_sha256[{i}] must be a string"))?);
        }
        Self::from_strs(&strs)
    }

    pub fn from_strs<S: AsRef<str>>(values: &[S]) -> Result<Self, String> {
        if values.len() > MAX_PINS {
            return Err(format!("web.tls_pin_sha256 has {} pins; at most {MAX_PINS} are allowed", values.len()));
        }
        let mut pins: Vec<SpkiPin> = Vec::with_capacity(values.len());
        for (i, v) in values.iter().enumerate() {
            let pin = SpkiPin::parse(v.as_ref()).map_err(|e| format!("web.tls_pin_sha256[{i}] {e}"))?;
            if !pins.contains(&pin) {
                pins.push(pin);
            }
        }
        Ok(Self { pins })
    }

    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }

    pub fn len(&self) -> usize {
        self.pins.len()
    }

    pub fn contains(&self, pin: &SpkiPin) -> bool {
        self.pins.contains(pin)
    }
}

/// Comma-separated pins, for an audit line.
impl fmt::Display for PinSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, p) in self.pins.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{p}")?;
        }
        Ok(())
    }
}

/// Which pin let a rejected certificate through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PinMatch {
    /// The leaf's own key.
    Leaf,
    /// A presented issuer's key (`depth` in the chain, 1 = the leaf's
    /// issuer), after WebPKI verification against it alone.
    Issuer { depth: usize },
}

/// Why a rejected certificate on a session origin stays rejected.
/// [`check`](Self::check) is the `aborted:<check>` name (server rule:
/// `[a-z0-9_]{1,32}`) and the audit reason; [`notice`](Self::notice) the
/// operator-facing text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PinRefusal {
    /// The platform reported no certificate.
    NoCertificate,
    /// The leaf certificate could not be parsed.
    Malformed,
    /// No presented key is pinned.
    Mismatch,
    /// An issuer's key is pinned, but the leaf does not verify under it for
    /// this host (wrong host, expired, not signed by it, …).
    IssuerUnverified,
}

impl PinRefusal {
    pub fn check(self) -> &'static str {
        match self {
            Self::NoCertificate => "tls_pin_no_certificate",
            Self::Malformed => "tls_pin_malformed",
            Self::Mismatch => "tls_pin_mismatch",
            Self::IssuerUnverified => "tls_pin_issuer",
        }
    }

    /// Fixed text only: never a name from the certificate.
    pub fn notice(self) -> &'static str {
        match self {
            Self::NoCertificate | Self::Malformed => "unreadable TLS certificate \u{2014} refused",
            Self::Mismatch => "TLS certificate does not match the pinned key \u{2014} refused",
            Self::IssuerUnverified => "TLS certificate is not valid for this host under the pinned CA \u{2014} refused",
        }
    }
}

/// The verdict on one certificate the platform rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PinDecision {
    /// Not an https origin of this session, or no pins: the platform's
    /// rejection stands, unaudited here.
    NotApplicable,
    /// Override the platform's rejection for this certificate.
    Accept(PinMatch),
    /// Keep the rejection; audited and shown.
    Refuse(PinRefusal),
}

impl PinDecision {
    pub fn accepts(self) -> bool {
        matches!(self, Self::Accept(_))
    }
}

/// Decide one rejected certificate.
///
/// `host` is the origin's host — a DNS name, an IPv4 literal, or an IPv6
/// literal with or without brackets — and is `Some` only when the caller has
/// established that the origin is one of the session's **https** origins;
/// `None` answers [`PinDecision::NotApplicable`]. `chain` is DER, leaf
/// first, as the server presented it; `now` is the time issuer verification
/// checks validity periods against.
pub fn decide(pins: &PinSet, host: Option<&str>, chain: &[Vec<u8>], now: UnixTime) -> PinDecision {
    if pins.is_empty() {
        return PinDecision::NotApplicable;
    }
    let Some(host) = host else {
        return PinDecision::NotApplicable;
    };
    let Some(leaf) = chain.first() else {
        return PinDecision::Refuse(PinRefusal::NoCertificate);
    };
    let Ok(leaf_pin) = SpkiPin::of_certificate(leaf) else {
        return PinDecision::Refuse(PinRefusal::Malformed);
    };
    if pins.contains(&leaf_pin) {
        return PinDecision::Accept(PinMatch::Leaf);
    }
    let presented = &chain[1..chain.len().min(MAX_CHAIN)];
    let mut issuer_pinned = false;
    for (i, der) in presented.iter().enumerate() {
        let Ok(pin) = SpkiPin::of_certificate(der) else { continue };
        if !pins.contains(&pin) {
            continue;
        }
        issuer_pinned = true;
        if issuer_vouches_for(der, leaf, presented, host, now) {
            return PinDecision::Accept(PinMatch::Issuer { depth: i + 1 });
        }
    }
    PinDecision::Refuse(if issuer_pinned { PinRefusal::IssuerUnverified } else { PinRefusal::Mismatch })
}

/// rustls' standard WebPKI server-certificate verification of `leaf` for
/// `host`, with `anchor` as the only trust anchor: chain signatures,
/// validity, `serverAuth` usage and the host name. No revocation check (no
/// CRLs are configured), as for the webviews' own default.
fn issuer_vouches_for(anchor: &[u8], leaf: &[u8], intermediates: &[Vec<u8>], host: &str, now: UnixTime) -> bool {
    let mut roots = RootCertStore::empty();
    if roots.add(CertificateDer::from(anchor.to_vec())).is_err() {
        return false;
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let Ok(verifier) = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider).build() else {
        return false;
    };
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let Ok(name) = ServerName::try_from(bare) else {
        return false;
    };
    let intermediates: Vec<CertificateDer<'static>> =
        intermediates.iter().map(|d| CertificateDer::from(d.clone())).collect();
    verifier.verify_server_cert(&CertificateDer::from(leaf.to_vec()), &intermediates, &name, &[], now).is_ok()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
        PublicKeyData,
    };
    use serde_json::json;

    use super::*;

    const HOST: &str = "appliance.example.com";

    fn now() -> UnixTime {
        UnixTime::now()
    }

    struct Ca {
        params: CertificateParams,
        key: KeyPair,
        der: Vec<u8>,
    }

    fn ca(name: &str) -> Ca {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, name);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let der = params.self_signed(&key).unwrap().der().to_vec();
        Ca { params, key, der }
    }

    fn leaf_params(names: &[&str]) -> CertificateParams {
        let mut p = CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        p.distinguished_name.push(DnType::CommonName, "FortiGate");
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p
    }

    fn issued(ca: &Ca, names: &[&str]) -> Vec<u8> {
        let key = KeyPair::generate().unwrap();
        let issuer = Issuer::from_params(&ca.params, &ca.key);
        leaf_params(names).signed_by(&key, &issuer).unwrap().der().to_vec()
    }

    fn self_signed() -> (Vec<u8>, KeyPair) {
        let key = KeyPair::generate().unwrap();
        (leaf_params(&["fortigate.local"]).self_signed(&key).unwrap().der().to_vec(), key)
    }

    fn pin_of(der: &[u8]) -> SpkiPin {
        SpkiPin::of_certificate(der).unwrap()
    }

    fn pins(list: &[SpkiPin]) -> PinSet {
        PinSet::from_strs(&list.iter().map(|p| p.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn every_accepted_form_parses_to_the_same_pin() {
        let bytes: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(5));
        let pin = SpkiPin(bytes);
        let hex = hex::encode(bytes);
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        for form in [format!("sha256:{hex}"), hex.clone(), format!("sha256/{b64}"), format!("sha256//{b64}"), b64] {
            assert_eq!(SpkiPin::parse(&form), Ok(pin), "{form}");
        }
        assert_eq!(pin.to_string(), format!("sha256:{hex}"));
        assert!(SpkiPin::parse("sha256:").is_err() && SpkiPin::parse("not a pin").is_err());
    }

    #[test]
    fn pin_lists_are_strict_bounded_and_deduplicated() {
        let a = format!("sha256:{}", "aa".repeat(32));
        let set = PinSet::from_json(&[json!(a.clone()), json!(a.to_uppercase())]).unwrap();
        assert_eq!(set.len(), 1);
        assert!(PinSet::from_json(&[json!(5)]).unwrap_err().contains("must be a string"));
        let too_many: Vec<String> = (0..=MAX_PINS).map(|i| format!("sha256:{i:064x}")).collect();
        assert!(PinSet::from_strs(&too_many).unwrap_err().contains("at most"));
    }

    #[test]
    fn the_pin_is_the_sha256_of_the_certificates_spki_bytes() {
        let (der, key) = self_signed();
        assert_eq!(pin_of(&der), SpkiPin::of_spki_der(&key.subject_public_key_info()));
        assert!(SpkiPin::of_certificate(b"not a certificate").is_err());
    }

    #[test]
    fn a_pinned_leaf_is_accepted_without_host_or_validity_checks() {
        let key = KeyPair::generate().unwrap();
        let mut params = leaf_params(&["fortigate.local"]);
        params.not_before = rcgen::date_time_ymd(2015, 1, 1);
        params.not_after = rcgen::date_time_ymd(2016, 1, 1);
        let der = params.self_signed(&key).unwrap().der().to_vec();
        let p = pins(&[pin_of(&der)]);
        assert_eq!(decide(&p, Some(HOST), std::slice::from_ref(&der), now()), PinDecision::Accept(PinMatch::Leaf));
        let later = UnixTime::since_unix_epoch(Duration::from_secs(4_000_000_000));
        assert_eq!(decide(&p, Some(HOST), &[der], later), PinDecision::Accept(PinMatch::Leaf));
    }

    /// No host (not a session https origin) or no pins: not the pins'
    /// business, and the platform's rejection stands.
    #[test]
    fn out_of_scope_or_unpinned_is_not_applicable() {
        let (der, _) = self_signed();
        let p = pins(&[pin_of(&der)]);
        assert_eq!(decide(&p, None, std::slice::from_ref(&der), now()), PinDecision::NotApplicable);
        assert_eq!(decide(&PinSet::default(), Some(HOST), &[der], now()), PinDecision::NotApplicable);
    }

    #[test]
    fn an_unpinned_or_unreadable_certificate_is_refused() {
        let (pinned, _) = self_signed();
        let (other, _) = self_signed();
        let p = pins(&[pin_of(&pinned)]);
        assert_eq!(decide(&p, Some(HOST), &[other], now()), PinDecision::Refuse(PinRefusal::Mismatch));
        assert_eq!(decide(&p, Some(HOST), &[], now()), PinDecision::Refuse(PinRefusal::NoCertificate));
        assert_eq!(
            decide(&p, Some(HOST), &[b"\x30\x03\x02\x01\x00".to_vec()], now()),
            PinDecision::Refuse(PinRefusal::Malformed)
        );
        let (attacker, _) = self_signed();
        assert_eq!(
            decide(&p, Some(HOST), &[attacker, pinned], now()),
            PinDecision::Refuse(PinRefusal::IssuerUnverified)
        );
    }

    #[test]
    fn a_pinned_issuer_vouches_only_for_its_own_leaf_for_this_host() {
        let ca = ca("Appliance CA");
        let leaf = issued(&ca, &[HOST]);
        let p = pins(&[pin_of(&ca.der)]);
        assert_eq!(
            decide(&p, Some(HOST), &[leaf.clone(), ca.der.clone()], now()),
            PinDecision::Accept(PinMatch::Issuer { depth: 1 })
        );
        assert_eq!(
            decide(&p, Some(HOST), std::slice::from_ref(&leaf), now()),
            PinDecision::Refuse(PinRefusal::Mismatch)
        );
        // Another host under the same CA, and a foreign leaf with the CA appended.
        assert_eq!(
            decide(&p, Some("other.example.com"), &[leaf, ca.der.clone()], now()),
            PinDecision::Refuse(PinRefusal::IssuerUnverified)
        );
        let (attacker, _) = self_signed();
        assert_eq!(
            decide(&p, Some(HOST), &[attacker, ca.der.clone()], now()),
            PinDecision::Refuse(PinRefusal::IssuerUnverified)
        );
        // An IP-literal origin verifies against the certificate's IP SAN.
        let ip_leaf = issued(&ca, &["127.0.0.1"]);
        assert_eq!(
            decide(&p, Some("127.0.0.1"), &[ip_leaf, ca.der.clone()], now()),
            PinDecision::Accept(PinMatch::Issuer { depth: 1 })
        );
    }
}
