//! Web Application Connect, TLS SPKI pinning — the decisions
//! (features/web-application-connect.md §8; T96 Phase 4).
//!
//! Appliances commonly serve self-signed or private-CA certificates, which the
//! webviews reject. A `web` profile may carry `tls_pin_sha256`: SHA-256
//! digests of a certificate's DER `SubjectPublicKeyInfo`. The platform shims
//! in `commands/connect_web_tls_pin.rs` (WKWebView's server-trust challenge,
//! WebView2's `ServerCertificateErrorDetected`, WebKitGTK's
//! `load-failed-with-tls-errors`) only read the presented chain and apply the
//! verdict; every decision is made here, without Tauri or a webview, so it is
//! unit-tested.
//!
//! The rules:
//!
//! * **A pin is an override, never a restriction.** It is consulted only for
//!   a certificate the platform has already rejected. A certificate the
//!   platform trusts is used as before, pin or not: WebView2 and WebKitGTK
//!   raise their events for errors only, so a restrictive pin could not be
//!   enforced on two of the three platforms, and a pin that means different
//!   things per platform is worse than none. (macOS evaluates first to keep
//!   the same meaning.)
//! * **Only for this session's https origins.** A rejected certificate on an
//!   origin outside the session's set — the server's scope for a `form` /
//!   `http-auth` launch — is [`PinDecision::NotApplicable`]: the platform's
//!   rejection stands and nothing is overridden.
//! * **Leaf pin:** the leaf's SPKI is in the set. The TLS handshake has
//!   proven the server holds that key, so nothing else is checked — not the
//!   host name, not the validity period. Appliance certificates commonly name
//!   the vendor rather than the host and carry long-expired dates; the pin
//!   names the exact key the operator confirmed.
//! * **Issuer pin:** the SPKI of a CA / intermediate certificate the server
//!   presented is in the set. A presented issuer certificate proves nothing by
//!   itself — it is public, and anyone can append it to their own chain — so
//!   the leaf must then pass rustls' WebPKI verification with that certificate
//!   as the **only** trust anchor: chain signatures, validity periods,
//!   `serverAuth` usage, and the host name of the origin. This is what lets a
//!   pin on a PKI-issued appliance survive certificate renewal. The issuer
//!   must be among the certificates the server presents (an SPKI digest alone
//!   is not a trust anchor).
//! * **Anything else is refused**, audited (origin, reason and the observed
//!   leaf's pin — never a URL path, a certificate body or a name from it) and
//!   shown in the window title. There is no "accept any certificate" path.
//!
//! Pins are public-key digests, not secrets; they are compared with `==`.

use std::collections::HashSet;
use std::fmt;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use rustls::client::danger::ServerCertVerifier as _;
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::RootCertStore;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::web::{OriginSet, WebOrigin};

/// Most pins one profile may carry. A profile needs one or two (the current
/// key and the next); the bound keeps a pasted list from growing unnoticed.
pub const MAX_PINS: usize = 16;

/// Longest chain read off a platform or a probe; anything longer is cut.
pub const MAX_CHAIN: usize = 8;

/// Longest subject / issuer text the fingerprint helper returns. The text is
/// server-chosen, so it is cut rather than trusted to be short.
const MAX_NAME_CHARS: usize = 256;

/// One pin: the SHA-256 of a DER `SubjectPublicKeyInfo`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpkiPin([u8; 32]);

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

/// Comma-separated pins, for the `session.open` audit line.
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
/// operator-facing title text.
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

/// Whether `origin` is one a pin may override a rejection for.
fn pinnable(origins: &OriginSet, origin: Option<&WebOrigin>) -> Option<WebOrigin> {
    origin.filter(|o| o.scheme() == "https" && origins.contains(o)).cloned()
}

/// Decide one rejected certificate. `chain` is DER, leaf first, as the
/// platform presented it; `now` is the time issuer verification checks
/// validity periods against.
pub fn decide(
    pins: &PinSet,
    origins: &OriginSet,
    origin: Option<&WebOrigin>,
    chain: &[Vec<u8>],
    now: UnixTime,
) -> PinDecision {
    if pins.is_empty() {
        return PinDecision::NotApplicable;
    }
    let Some(origin) = pinnable(origins, origin) else {
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
        if issuer_vouches_for(der, leaf, presented, origin.host(), now) {
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

/// Names for the gate's audit lines.
#[derive(Debug, Clone)]
pub struct PinAudit {
    pub resource: String,
    pub token: String,
    /// `form` / `http-auth` launches only.
    pub launch_id_hash: Option<String>,
}

/// What the platform shim gets back for one rejected certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustVerdict {
    pub decision: PinDecision,
    /// The first time this session saw this (origin, leaf key, decision).
    /// WebKitGTK uses it to retry a load at most once per accepted
    /// certificate; the audit line is written only then.
    pub first: bool,
}

type RefusalHook = Box<dyn Fn(PinRefusal) + Send + Sync>;

/// The pins and origin set of one session window, shared with its platform
/// handler (main thread). The lock is held for bookkeeping only.
pub struct TlsPinGate {
    pins: PinSet,
    origins: OriginSet,
    audit: PinAudit,
    seen: Mutex<HashSet<(WebOrigin, Option<SpkiPin>, PinDecision)>>,
    on_refusal: RefusalHook,
}

impl fmt::Debug for TlsPinGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsPinGate").field("pins", &self.pins).field("audit", &self.audit).finish_non_exhaustive()
    }
}

impl TlsPinGate {
    /// `origins` is the session's effective set (the server's scope for a
    /// launch). `on_refusal` runs once per refused (origin, key): the command
    /// layer shows the notice in the title and records the abort reason.
    pub fn new(pins: PinSet, origins: OriginSet, audit: PinAudit, on_refusal: RefusalHook) -> Arc<Self> {
        Arc::new(Self { pins, origins, audit, seen: Mutex::new(HashSet::new()), on_refusal })
    }

    /// Whether a rejection on `origin` is this gate's to decide. The macOS
    /// shim asks before evaluating trust itself, so an origin outside the
    /// session never costs an evaluation.
    pub fn applies_to(&self, origin: Option<&WebOrigin>) -> bool {
        !self.pins.is_empty() && pinnable(&self.origins, origin).is_some()
    }

    /// Whether this session accepted a certificate for `origin` on a pin
    /// (the platform had rejected it). Read-only, for the session toolbar's
    /// lock indicator (Phase 5); decides nothing.
    pub fn accepted_on_pin(&self, origin: &WebOrigin) -> bool {
        self.seen
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .any(|(o, _, d)| o == origin && matches!(d, PinDecision::Accept(_)))
    }

    /// Decide a certificate the platform rejected for `origin`.
    pub fn server_trust(&self, origin: Option<&WebOrigin>, chain: &[Vec<u8>]) -> TrustVerdict {
        self.server_trust_at(origin, chain, UnixTime::now())
    }

    fn server_trust_at(&self, origin: Option<&WebOrigin>, chain: &[Vec<u8>], now: UnixTime) -> TrustVerdict {
        let decision = decide(&self.pins, &self.origins, origin, chain, now);
        let Some(origin) = origin.filter(|_| decision != PinDecision::NotApplicable) else {
            return TrustVerdict { decision, first: true };
        };
        let leaf_pin = chain.first().and_then(|d| SpkiPin::of_certificate(d).ok());
        let first = self.seen.lock().unwrap_or_else(|p| p.into_inner()).insert((origin.clone(), leaf_pin, decision));
        if first {
            self.write_audit(origin, leaf_pin, decision, chain);
            if let PinDecision::Refuse(r) = decision {
                (self.on_refusal)(r);
            }
        }
        TrustVerdict { decision, first }
    }

    fn write_audit(&self, origin: &WebOrigin, leaf_pin: Option<SpkiPin>, decision: PinDecision, chain: &[Vec<u8>]) {
        let a = &self.audit;
        let launch = a.launch_id_hash.as_deref().map(|h| format!(" launch_id_hash={h}")).unwrap_or_default();
        let observed = leaf_pin.map(|p| p.to_string()).unwrap_or_else(|| "unreadable".to_string());
        match decision {
            PinDecision::Accept(PinMatch::Leaf) => log::info!(
                target: "audit",
                "connect.web.tls_pin_accepted: resource={} token={}{launch} origin={origin} match=leaf pin={observed}",
                a.resource,
                a.token,
            ),
            PinDecision::Accept(PinMatch::Issuer { depth }) => {
                let pin = chain
                    .get(depth)
                    .and_then(|d| SpkiPin::of_certificate(d).ok())
                    .map(|p| p.to_string())
                    .unwrap_or_default();
                log::info!(
                    target: "audit",
                    "connect.web.tls_pin_accepted: resource={} token={}{launch} origin={origin} match=issuer \
                     depth={depth} pin={pin} observed_leaf={observed}",
                    a.resource,
                    a.token,
                )
            }
            PinDecision::Refuse(r) => log::warn!(
                target: "audit",
                "connect.web.tls_pin_refused: resource={} token={}{launch} origin={origin} reason={} \
                 observed_leaf={observed}",
                a.resource,
                a.token,
                r.check(),
            ),
            PinDecision::NotApplicable => {}
        }
    }
}

/// Leaf PEM plus WebView2's issuer chain (whose first entry may be the leaf
/// itself) as DER, leaf first, the leaf not repeated, cut at [`MAX_CHAIN`].
// Only the WebView2 shim calls this outside the tests.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn chain_from_pem(leaf_pem: &str, issuer_pems: &[String]) -> Result<Vec<Vec<u8>>, String> {
    let one = |text: &str| -> Result<Vec<u8>, String> {
        let p = pem::parse(text.trim()).map_err(|e| format!("unreadable PEM certificate: {e}"))?;
        if p.tag() != "CERTIFICATE" {
            return Err(format!("expected a CERTIFICATE PEM block, got {}", p.tag()));
        }
        Ok(p.into_contents())
    };
    let leaf = one(leaf_pem)?;
    let mut chain = vec![leaf];
    for text in issuer_pems {
        if chain.len() >= MAX_CHAIN {
            break;
        }
        let der = one(text)?;
        if der != chain[0] {
            chain.push(der);
        }
    }
    Ok(chain)
}

/// One presented certificate, as the fingerprint helper shows it. Server
/// text (`subject`, `issuer`) is cut at [`MAX_NAME_CHARS`]; the GUI renders
/// it as text.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PresentedCertificate {
    /// 0 = the server's own (leaf) certificate.
    pub depth: usize,
    /// `sha256:<hex>`, ready to store in `tls_pin_sha256`.
    pub pin: String,
    /// The same digest in RFC 7469 / curl base64, for comparing with tools
    /// that print that form.
    pub pin_base64: String,
    pub subject: String,
    pub issuer: String,
    /// Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    /// Subject equals issuer.
    pub self_issued: bool,
    /// Basic constraints `cA`.
    pub ca: bool,
}

fn bounded(s: String) -> String {
    if s.chars().count() <= MAX_NAME_CHARS {
        s
    } else {
        let mut cut: String = s.chars().take(MAX_NAME_CHARS).collect();
        cut.push('\u{2026}');
        cut
    }
}

/// Describe a presented chain (DER, leaf first) for the fingerprint helper.
pub fn describe_chain(chain: &[Vec<u8>]) -> Result<Vec<PresentedCertificate>, String> {
    if chain.is_empty() {
        return Err("the server presented no certificate".to_string());
    }
    chain
        .iter()
        .take(MAX_CHAIN)
        .enumerate()
        .map(|(depth, der)| {
            let (_, cert) = x509_parser::parse_x509_certificate(der)
                .map_err(|e| format!("certificate {depth} is unreadable: {e}"))?;
            let pin = SpkiPin::of_spki_der(cert.public_key().raw);
            Ok(PresentedCertificate {
                depth,
                pin: pin.to_string(),
                pin_base64: pin.to_base64(),
                subject: bounded(cert.subject().to_string()),
                issuer: bounded(cert.issuer().to_string()),
                not_before: cert.validity().not_before.timestamp(),
                not_after: cert.validity().not_after.timestamp(),
                self_issued: cert.subject().as_raw() == cert.issuer().as_raw(),
                ca: cert.is_ca(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
        PublicKeyData,
    };
    use serde_json::json;
    use std::time::Duration;

    const HOST: &str = "appliance.example.com";

    fn origin(s: &str) -> WebOrigin {
        WebOrigin::parse_config(s, true).unwrap()
    }

    fn set() -> OriginSet {
        OriginSet::new(vec![origin("https://appliance.example.com"), origin("https://appliance.example.com:8443")])
    }

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

    /// A leaf for `names` signed by `ca`, and its key.
    fn issued(ca: &Ca, names: &[&str]) -> (Vec<u8>, KeyPair) {
        let key = KeyPair::generate().unwrap();
        let issuer = Issuer::from_params(&ca.params, &ca.key);
        (leaf_params(names).signed_by(&key, &issuer).unwrap().der().to_vec(), key)
    }

    /// A self-signed appliance certificate: vendor CN, no matching SAN.
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

    // ── Parsing ────────────────────────────────────────────────────

    #[test]
    fn every_accepted_form_parses_to_the_same_pin() {
        let bytes: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(5));
        let pin = SpkiPin(bytes);
        let hex = hex::encode(bytes);
        let colons = bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":");
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        for form in [
            format!("sha256:{hex}"),
            format!("SHA256:{}", hex.to_uppercase()),
            hex.clone(),
            format!("  sha256:{hex}\n"),
            format!("sha256:{colons}"),
            colons.clone(),
            format!("sha256/{b64}"),
            format!("sha256//{b64}"),
            format!("SHA256/{b64}"),
            b64.clone(),
        ] {
            assert_eq!(SpkiPin::parse(&form), Ok(pin), "{form}");
        }
        // Canonical text round-trips, in both encodings.
        assert_eq!(pin.to_string(), format!("sha256:{hex}"));
        assert_eq!(SpkiPin::parse(&pin.to_string()), Ok(pin));
        assert_eq!(SpkiPin::parse(&format!("sha256/{}", pin.to_base64())), Ok(pin));
    }

    #[test]
    fn malformed_pins_are_refused() {
        let hex = "ab".repeat(32);
        let b64 = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        for bad in [
            String::new(),
            "   ".into(),
            "sha256:".into(),
            "sha256/".into(),
            "ab".repeat(31),
            "ab".repeat(33),
            format!("sha256:{}zz", &hex[..62]),
            format!("sha1:{hex}"),
            format!("sha256:{b64}"),
            format!("sha256/{}", &b64[..40]),
            format!("sha256/{}", base64::engine::general_purpose::STANDARD.encode([7u8; 20])),
            format!("sha256/{}", b64.replace('=', "")),
            "AB:CD".into(),
            format!("{}:", "ab:".repeat(31)),
            "ab:cd:".repeat(16),
            "not a pin".into(),
        ] {
            assert!(SpkiPin::parse(&bad).is_err(), "{bad:?}");
        }
        // Non-canonical base64 (the last character's two spare bits set) is
        // refused, as the GUI's mirror refuses it.
        const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let v = ALPHABET.find(&b64[42..43]).unwrap();
        let non_canonical = format!("{}{}=", &b64[..42], &ALPHABET[v + 1..v + 2]);
        assert!(SpkiPin::parse(&non_canonical).is_err());
        assert!(SpkiPin::parse(&format!("sha256/{non_canonical}")).is_err());
    }

    #[test]
    fn pin_lists_are_strict_bounded_and_deduplicated() {
        let a = format!("sha256:{}", "aa".repeat(32));
        let b = format!("sha256:{}", "bb".repeat(32));
        let set = PinSet::from_json(&[json!(a.clone()), json!(b.clone()), json!(a.to_uppercase())]).unwrap();
        assert_eq!(set.len(), 2);
        assert_eq!(set.to_string(), format!("{a},{b}"));
        for (bad, why) in [
            (vec![json!(a.clone()), json!(5)], "tls_pin_sha256[1] must be a string"),
            (vec![json!(null)], "tls_pin_sha256[0] must be a string"),
            (vec![json!(a.clone()), json!("nope")], "tls_pin_sha256[1] is not"),
        ] {
            let err = PinSet::from_json(&bad).unwrap_err();
            assert!(err.contains(why), "{err}");
        }
        let too_many: Vec<String> = (0..=MAX_PINS).map(|i| format!("sha256:{:064x}", i)).collect();
        assert!(PinSet::from_strs(&too_many).unwrap_err().contains("at most"));
        assert_eq!(PinSet::from_strs(&too_many[..MAX_PINS]).unwrap().len(), MAX_PINS);
    }

    #[test]
    fn the_pin_is_the_sha256_of_the_certificates_spki_bytes() {
        let (der, key) = self_signed();
        assert_eq!(pin_of(&der), SpkiPin::of_spki_der(&key.subject_public_key_info()));
        assert_ne!(pin_of(&der), SpkiPin::of_spki_der(&der), "not a whole-certificate fingerprint");
        assert!(SpkiPin::of_certificate(b"not a certificate").is_err());
    }

    // ── Decisions ──────────────────────────────────────────────────

    #[test]
    fn a_pinned_leaf_is_accepted_without_host_or_validity_checks() {
        // An appliance default: vendor name instead of the host, long expired.
        let key = KeyPair::generate().unwrap();
        let mut params = leaf_params(&["fortigate.local"]);
        params.not_before = rcgen::date_time_ymd(2015, 1, 1);
        params.not_after = rcgen::date_time_ymd(2016, 1, 1);
        let der = params.self_signed(&key).unwrap().der().to_vec();
        let p = pins(&[pin_of(&der)]);
        let o = origin("https://appliance.example.com");
        assert_eq!(decide(&p, &set(), Some(&o), &[der.clone()], now()), PinDecision::Accept(PinMatch::Leaf));
        let later = UnixTime::since_unix_epoch(Duration::from_secs(4_000_000_000));
        assert_eq!(decide(&p, &set(), Some(&o), &[der], later), PinDecision::Accept(PinMatch::Leaf));
    }

    #[test]
    fn origins_outside_the_session_and_plain_http_are_not_the_pins_business() {
        let (der, _) = self_signed();
        let p = pins(&[pin_of(&der)]);
        for o in [
            origin("https://evil.example"),
            origin("https://appliance.example.com:9443"),
            origin("http://appliance.example.com"),
        ] {
            assert_eq!(decide(&p, &set(), Some(&o), &[der.clone()], now()), PinDecision::NotApplicable, "{o}");
        }
        assert_eq!(decide(&p, &set(), None, &[der.clone()], now()), PinDecision::NotApplicable);
        // http in the set still never takes a pin.
        let with_http = OriginSet::new(vec![origin("http://appliance.example.com")]);
        let o = origin("http://appliance.example.com");
        assert_eq!(decide(&p, &with_http, Some(&o), &[der.clone()], now()), PinDecision::NotApplicable);
        // No pins at all: nothing to override.
        let o = origin("https://appliance.example.com");
        assert_eq!(decide(&PinSet::default(), &set(), Some(&o), &[der], now()), PinDecision::NotApplicable);
    }

    #[test]
    fn an_unpinned_or_unreadable_certificate_is_refused() {
        let (pinned, _) = self_signed();
        let (other, _) = self_signed();
        let p = pins(&[pin_of(&pinned)]);
        let o = origin("https://appliance.example.com:8443");
        assert_eq!(decide(&p, &set(), Some(&o), &[other], now()), PinDecision::Refuse(PinRefusal::Mismatch));
        assert_eq!(decide(&p, &set(), Some(&o), &[], now()), PinDecision::Refuse(PinRefusal::NoCertificate));
        assert_eq!(
            decide(&p, &set(), Some(&o), &[b"\x30\x03\x02\x01\x00".to_vec()], now()),
            PinDecision::Refuse(PinRefusal::Malformed)
        );
        // Further down the chain a pinned key is only an anchor candidate: a
        // pinned (public) self-signed certificate appended to another leaf
        // does not vouch for it.
        let (attacker, _) = self_signed();
        assert_eq!(
            decide(&p, &set(), Some(&o), &[attacker, pinned], now()),
            PinDecision::Refuse(PinRefusal::IssuerUnverified),
            "a pinned self-signed leaf appended to another chain is not an issuer of it"
        );
    }

    #[test]
    fn a_pinned_issuer_is_accepted_only_when_the_leaf_verifies_under_it_for_the_host() {
        let ca = ca("Appliance CA");
        let (leaf, _) = issued(&ca, &[HOST]);
        let p = pins(&[pin_of(&ca.der)]);
        let o = origin("https://appliance.example.com");
        assert_eq!(
            decide(&p, &set(), Some(&o), &[leaf.clone(), ca.der.clone()], now()),
            PinDecision::Accept(PinMatch::Issuer { depth: 1 })
        );
        // Without the CA in the presented chain there is no anchor to verify against.
        assert_eq!(decide(&p, &set(), Some(&o), &[leaf], now()), PinDecision::Refuse(PinRefusal::Mismatch));
    }

    #[test]
    fn appending_the_public_pinned_ca_to_a_foreign_chain_does_not_pass() {
        let ca = ca("Appliance CA");
        let p = pins(&[pin_of(&ca.der)]);
        let o = origin("https://appliance.example.com");
        // The attacker's own self-signed leaf, with the (public) CA appended.
        let (attacker, _) = self_signed();
        assert_eq!(
            decide(&p, &set(), Some(&o), &[attacker, ca.der.clone()], now()),
            PinDecision::Refuse(PinRefusal::IssuerUnverified)
        );
        // A leaf for the right host, but from another CA, with the pinned CA appended.
        let rogue = self::ca("Rogue CA");
        let (rogue_leaf, _) = issued(&rogue, &[HOST]);
        assert_eq!(
            decide(&p, &set(), Some(&o), &[rogue_leaf, rogue.der.clone(), ca.der.clone()], now()),
            PinDecision::Refuse(PinRefusal::IssuerUnverified)
        );
    }

    #[test]
    fn an_issuer_pin_checks_the_host_name_and_the_validity_period() {
        let ca = ca("Appliance CA");
        let p = pins(&[pin_of(&ca.der)]);
        // Issued by the pinned CA — for another appliance.
        let (other_host, _) = issued(&ca, &["other.example.com"]);
        let o = origin("https://appliance.example.com");
        assert_eq!(
            decide(&p, &set(), Some(&o), &[other_host, ca.der.clone()], now()),
            PinDecision::Refuse(PinRefusal::IssuerUnverified)
        );
        // Right host, expired.
        let key = KeyPair::generate().unwrap();
        let mut params = leaf_params(&[HOST]);
        params.not_before = rcgen::date_time_ymd(2019, 1, 1);
        params.not_after = rcgen::date_time_ymd(2020, 1, 1);
        let expired = params.signed_by(&key, &Issuer::from_params(&ca.params, &ca.key)).unwrap().der().to_vec();
        assert_eq!(
            decide(&p, &set(), Some(&o), &[expired, ca.der.clone()], now()),
            PinDecision::Refuse(PinRefusal::IssuerUnverified)
        );
    }

    #[test]
    fn an_intermediate_can_be_the_pinned_anchor() {
        let root = ca("Root");
        let inter_key = KeyPair::generate().unwrap();
        let mut inter_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        inter_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        inter_params.distinguished_name.push(DnType::CommonName, "Issuing CA");
        inter_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let inter_der =
            inter_params.signed_by(&inter_key, &Issuer::from_params(&root.params, &root.key)).unwrap().der().to_vec();
        let inter = Ca { params: inter_params, key: inter_key, der: inter_der };
        let (leaf, _) = issued(&inter, &[HOST]);
        let o = origin("https://appliance.example.com");
        let chain = vec![leaf, inter.der.clone(), root.der.clone()];
        assert_eq!(
            decide(&pins(&[pin_of(&inter.der)]), &set(), Some(&o), &chain, now()),
            PinDecision::Accept(PinMatch::Issuer { depth: 1 })
        );
        assert_eq!(
            decide(&pins(&[pin_of(&root.der)]), &set(), Some(&o), &chain, now()),
            PinDecision::Accept(PinMatch::Issuer { depth: 2 })
        );
    }

    // ── The gate ───────────────────────────────────────────────────

    fn gate(p: PinSet) -> (Arc<TlsPinGate>, Arc<Mutex<Vec<PinRefusal>>>) {
        let refusals = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&refusals);
        let g = TlsPinGate::new(
            p,
            set(),
            PinAudit { resource: "fw01".into(), token: "sess_x".into(), launch_id_hash: None },
            Box::new(move |r| sink.lock().unwrap().push(r)),
        );
        (g, refusals)
    }

    #[test]
    fn the_gate_reports_each_refusal_once_and_marks_first_sightings() {
        let (pinned, _) = self_signed();
        let (other, _) = self_signed();
        let (g, refusals) = gate(pins(&[pin_of(&pinned)]));
        let o = origin("https://appliance.example.com");
        assert!(g.applies_to(Some(&o)));
        assert!(!g.applies_to(Some(&origin("https://evil.example"))));
        assert!(!g.applies_to(None));

        let v = g.server_trust(Some(&o), &[pinned.clone()]);
        assert_eq!(v, TrustVerdict { decision: PinDecision::Accept(PinMatch::Leaf), first: true });
        assert!(!g.server_trust(Some(&o), &[pinned.clone()]).first, "WebKit asks per connection");

        assert!(!g.server_trust(Some(&o), &[other.clone()]).decision.accepts());
        assert!(!g.server_trust(Some(&o), &[other.clone()]).first);
        assert_eq!(*refusals.lock().unwrap(), vec![PinRefusal::Mismatch], "one notice per refused key");

        // Out of the session: nothing recorded, nothing shown.
        let foreign = g.server_trust(Some(&origin("https://evil.example")), &[other]);
        assert_eq!(foreign.decision, PinDecision::NotApplicable);
        assert_eq!(refusals.lock().unwrap().len(), 1);
        assert!(!format!("{g:?}").is_empty());
    }

    #[test]
    fn accepted_on_pin_reports_only_accepted_origins() {
        let (pinned, _) = self_signed();
        let (other, _) = self_signed();
        let (g, _) = gate(pins(&[pin_of(&pinned)]));
        let o = origin("https://appliance.example.com");
        assert!(!g.accepted_on_pin(&o), "nothing decided yet");
        g.server_trust(Some(&o), &[other]);
        assert!(!g.accepted_on_pin(&o), "a refusal is not an acceptance");
        g.server_trust(Some(&o), &[pinned]);
        assert!(g.accepted_on_pin(&o));
        assert!(!g.accepted_on_pin(&origin("https://evil.example")));
    }

    #[test]
    fn an_empty_gate_never_overrides() {
        let (der, _) = self_signed();
        let (g, refusals) = gate(PinSet::default());
        let o = origin("https://appliance.example.com");
        assert!(!g.applies_to(Some(&o)));
        assert_eq!(g.server_trust(Some(&o), &[der]).decision, PinDecision::NotApplicable);
        assert!(refusals.lock().unwrap().is_empty());
    }

    #[test]
    fn refusal_checks_are_valid_abort_names() {
        for r in [PinRefusal::NoCertificate, PinRefusal::Malformed, PinRefusal::Mismatch, PinRefusal::IssuerUnverified]
        {
            let c = r.check();
            assert!(
                (1..=32).contains(&c.len())
                    && c.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{c}"
            );
            assert!(crate::session::web_recipe::HOST_ABORT_CHECKS.contains(&c), "{c} missing from HOST_ABORT_CHECKS");
            assert!(!r.notice().is_empty());
        }
    }

    // ── Helpers for the shims and the fingerprint helper ───────────

    #[test]
    fn webview2_pem_chains_become_der_leaf_first_without_repeating_the_leaf() {
        let ca = ca("Appliance CA");
        let (leaf, _) = issued(&ca, &[HOST]);
        let pem_of = |der: &[u8]| pem::encode(&pem::Pem::new("CERTIFICATE", der.to_vec()));
        // WebView2 documents the issuer chain as starting with the certificate itself.
        let chain = chain_from_pem(&pem_of(&leaf), &[pem_of(&leaf), pem_of(&ca.der)]).unwrap();
        assert_eq!(chain, vec![leaf.clone(), ca.der.clone()]);
        let chain = chain_from_pem(&pem_of(&leaf), &[pem_of(&ca.der)]).unwrap();
        assert_eq!(chain, vec![leaf.clone(), ca.der.clone()]);
        assert!(chain_from_pem("garbage", &[]).is_err());
        let key_block = pem::encode(&pem::Pem::new("PRIVATE KEY", vec![1, 2, 3]));
        assert!(chain_from_pem(&key_block, &[]).unwrap_err().contains("CERTIFICATE"));
        let long: Vec<String> = (0..20).map(|_| pem_of(&ca.der)).collect();
        assert_eq!(chain_from_pem(&pem_of(&leaf), &long).unwrap().len(), MAX_CHAIN);
    }

    #[test]
    fn describe_chain_reports_pins_names_and_roles() {
        let ca = ca("Appliance CA");
        let (leaf, key) = issued(&ca, &[HOST]);
        let out = describe_chain(&[leaf, ca.der.clone()]).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].depth, 0);
        assert_eq!(out[0].pin, SpkiPin::of_spki_der(&key.subject_public_key_info()).to_string());
        assert_eq!(SpkiPin::parse(&format!("sha256/{}", out[0].pin_base64)).unwrap().to_string(), out[0].pin);
        assert!(out[0].subject.contains("FortiGate"));
        assert!(out[0].issuer.contains("Appliance CA"));
        assert!(!out[0].ca && !out[0].self_issued);
        assert!(out[0].not_after > out[0].not_before);
        assert_eq!(out[1].pin, pin_of(&ca.der).to_string());
        assert!(out[1].ca && out[1].self_issued);
        assert!(describe_chain(&[]).is_err());
        assert!(describe_chain(&[b"junk".to_vec()]).is_err());
    }

    #[test]
    fn long_server_names_are_cut() {
        assert_eq!(bounded("a".repeat(10)), "a".repeat(10));
        let cut = bounded("é".repeat(MAX_NAME_CHARS + 5));
        assert_eq!(cut.chars().count(), MAX_NAME_CHARS + 1);
        assert!(cut.ends_with('\u{2026}'));
    }
}
