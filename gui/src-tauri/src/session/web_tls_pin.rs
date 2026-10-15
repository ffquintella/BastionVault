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
//! unit-tested. The pin decision itself ([`decide`] below the session-origin
//! scope check) is `bastion_vault::utils::tls_pin`, shared with the vault's
//! agent web fetch so the two cannot disagree about what a pin admits.
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

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};

use rustls::pki_types::UnixTime;
use serde::Serialize;

use super::web::{OriginSet, WebOrigin};
use super::web_load::{LoadFailure, PageFailure};

// The pin decision is shared with the vault's agent web fetch
// (features/mcp-brokered-sessions.md §6.3): it lives in `bv-utils` and is
// re-exported here under the names this crate has always used.
pub use bastion_vault::utils::tls_pin::{PinDecision, PinMatch, PinRefusal, PinSet, SpkiPin, MAX_CHAIN};

/// Longest subject / issuer text the fingerprint helper returns. The text is
/// server-chosen, so it is cut rather than trusted to be short.
const MAX_NAME_CHARS: usize = 256;

/// Whether `origin` is one a pin may override a rejection for.
fn pinnable(origins: &OriginSet, origin: Option<&WebOrigin>) -> Option<WebOrigin> {
    origin.filter(|o| o.scheme() == "https" && origins.contains(o)).cloned()
}

/// Decide one rejected certificate. `chain` is DER, leaf first, as the
/// platform presented it; `now` is the time issuer verification checks
/// validity periods against. Only an https origin of this session's set is
/// the pins' business ([`pinnable`]); the decision itself is the shared one
/// (`bastion_vault::utils::tls_pin::decide`).
pub fn decide(
    pins: &PinSet,
    origins: &OriginSet,
    origin: Option<&WebOrigin>,
    chain: &[Vec<u8>],
    now: UnixTime,
) -> PinDecision {
    let scoped = pinnable(origins, origin);
    bastion_vault::utils::tls_pin::decide(pins, scoped.as_ref().map(|o| o.host()), chain, now)
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

#[cfg_attr(not(any(target_os = "macos", windows, target_os = "linux")), allow(dead_code))]
/// What a certificate the platform rejected comes to on a window that may
/// ask the operator (T139, [`TlsPinGate::with_operator_override`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverrideVerdict {
    /// Not the operator's to decide: an origin outside the session, or a
    /// profile with pins. A pin is the standing decision for that resource,
    /// so a certificate that does not match one is never offered.
    NotApplicable,
    /// The leaf certificate could not be read: refuse, nothing to show.
    Unreadable,
    /// The operator accepted this exact key for this origin, this session.
    Accepted,
    /// The operator declined this key for this origin, this session; not
    /// asked again.
    Declined,
    /// Not decided yet: ask about this key.
    Ask(SpkiPin),
}

/// The pins and origin set of one session window, shared with its platform
/// handler (main thread). The lock is held for bookkeeping only.
pub struct TlsPinGate {
    pins: PinSet,
    origins: OriginSet,
    audit: PinAudit,
    seen: Mutex<HashSet<(WebOrigin, Option<SpkiPin>, PinDecision)>>,
    on_refusal: RefusalHook,
    /// A window without pins may ask the operator about a rejected
    /// certificate (T139; every platform shim consults it).
    operator_override: bool,
    /// The operator's answers, per (origin, leaf key), for this session
    /// only. Never persisted: the next session asks again.
    overrides: Mutex<HashMap<(WebOrigin, SpkiPin), bool>>,
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
        Self::build(pins, origins, audit, on_refusal, false)
    }

    /// As [`Self::new`], and a window whose profile has **no** pins may ask
    /// the operator about a certificate the platform rejected on one of the
    /// session's https origins ([`Self::operator_override`]). An accepted
    /// key is accepted for that origin until the session ends, nothing else.
    pub fn with_operator_override(
        pins: PinSet,
        origins: OriginSet,
        audit: PinAudit,
        on_refusal: RefusalHook,
    ) -> Arc<Self> {
        Self::build(pins, origins, audit, on_refusal, true)
    }

    fn build(
        pins: PinSet,
        origins: OriginSet,
        audit: PinAudit,
        on_refusal: RefusalHook,
        operator_override: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            pins,
            origins,
            audit,
            seen: Mutex::new(HashSet::new()),
            on_refusal,
            operator_override,
            overrides: Mutex::new(HashMap::new()),
        })
    }

    /// Whether a rejection on `origin` is this gate's to decide. The macOS
    /// shim asks before evaluating trust itself, so an origin outside the
    /// session never costs an evaluation.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn applies_to(&self, origin: Option<&WebOrigin>) -> bool {
        (!self.pins.is_empty() || self.operator_override) && pinnable(&self.origins, origin).is_some()
    }

    /// Whether this gate decides with its pins ([`Self::server_trust`]) —
    /// otherwise, on a window that may ask, with the operator
    /// ([`Self::operator_override`]).
    #[cfg_attr(not(any(target_os = "macos", windows, target_os = "linux")), allow(dead_code))]
    pub fn has_pins(&self) -> bool {
        !self.pins.is_empty()
    }

    /// The operator's standing for a certificate the platform rejected on
    /// `origin` (`chain` DER, leaf first).
    #[cfg_attr(not(any(target_os = "macos", windows, target_os = "linux")), allow(dead_code))]
    pub fn operator_override(&self, origin: Option<&WebOrigin>, chain: &[Vec<u8>]) -> OverrideVerdict {
        if !self.operator_override || !self.pins.is_empty() {
            return OverrideVerdict::NotApplicable;
        }
        let Some(origin) = pinnable(&self.origins, origin) else {
            return OverrideVerdict::NotApplicable;
        };
        let Some(leaf) = chain.first().and_then(|d| SpkiPin::of_certificate(d).ok()) else {
            return OverrideVerdict::Unreadable;
        };
        match self.overrides.lock().unwrap_or_else(|p| p.into_inner()).get(&(origin, leaf)) {
            Some(true) => OverrideVerdict::Accepted,
            Some(false) => OverrideVerdict::Declined,
            None => OverrideVerdict::Ask(leaf),
        }
    }

    /// Record the operator's answer about `leaf` on `origin`, for this
    /// session. The first answer stands and is the one audited; a later
    /// call for the same key changes nothing. Returns the standing answer.
    #[cfg_attr(not(any(target_os = "macos", windows, target_os = "linux")), allow(dead_code))]
    pub fn record_override(&self, origin: &WebOrigin, leaf: SpkiPin, accepted: bool) -> bool {
        if !self.operator_override || !self.pins.is_empty() || pinnable(&self.origins, Some(origin)).is_none() {
            return false;
        }
        let mut overrides = self.overrides.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(standing) = overrides.get(&(origin.clone(), leaf)) {
            return *standing;
        }
        overrides.insert((origin.clone(), leaf), accepted);
        drop(overrides);
        let a = &self.audit;
        let launch = a.launch_id_hash.as_deref().map(|h| format!(" launch_id_hash={h}")).unwrap_or_default();
        if accepted {
            log::warn!(
                target: "audit",
                "connect.web.tls_override: resource={} token={}{launch} origin={origin} decision=accepted \
                 scope=session pin={leaf}",
                a.resource,
                a.token,
            );
        } else {
            log::info!(
                target: "audit",
                "connect.web.tls_override: resource={} token={}{launch} origin={origin} decision=declined pin={leaf}",
                a.resource,
                a.token,
            );
        }
        accepted
    }

    /// Whether this session accepted a certificate for `origin` on a pin
    /// (the platform had rejected it). Read-only, for the session toolbar's
    /// lock indicator (Phase 5); decides nothing.
    pub fn accepted_on_pin(&self, origin: &WebOrigin) -> bool {
        let on_pin = self
            .seen
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .any(|(o, _, d)| o == origin && matches!(d, PinDecision::Accept(_)));
        // An operator override is shown the same way: the platform rejected
        // the certificate and this session accepted it anyway.
        on_pin
            || self
                .overrides
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .iter()
                .any(|((o, _), accepted)| o == origin && *accepted)
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

/// What a platform shim does with one certificate the platform rejected on
/// a session window ([`TlsPinGate::decide_rejected`], T139).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectedAction {
    /// Override the rejection. `retry` is true only the first time this
    /// session accepts this (origin, key) on a pin: WebKitGTK, which accepts
    /// by adding an exception and reloading, reloads only then, so an
    /// exception that does not take cannot loop.
    Accept { retry: bool },
    /// Keep the rejection.
    Refuse,
    /// Ask the operator about this key on this origin (a window without
    /// pins, not asked yet). The shim holds or suspends the load until the
    /// answer ([`TlsPinGate::record_override`]).
    Ask { origin: WebOrigin, leaf: SpkiPin },
}

impl TlsPinGate {
    /// Decide a certificate the platform rejected on `origin` (`chain` DER,
    /// leaf first) — the one decision every platform shim makes:
    ///
    /// * a profile **with** pins: the pins decide ([`Self::server_trust`]);
    ///   a mismatch is never offered to the operator;
    /// * **no** pins: the operator's answer for this exact key on this
    ///   origin this session ([`Self::operator_override`]) — accepted,
    ///   declined, or not asked yet ([`RejectedAction::Ask`] when the shim
    ///   `can_ask`, a refusal otherwise).
    ///
    /// `refused` runs when this refuses a session origin with a reason the
    /// window should report (a pin refusal, a declined key), so the cancelled
    /// or failed load that follows names it ([`super::web::WebShared::note_tls_refused`]).
    pub fn decide_rejected(
        &self,
        origin: Option<&WebOrigin>,
        chain: &[Vec<u8>],
        can_ask: bool,
        refused: impl FnOnce(&WebOrigin, PageFailure),
    ) -> RejectedAction {
        if self.has_pins() {
            let verdict = self.server_trust(origin, chain);
            return match (verdict.decision, origin) {
                (d, _) if d.accepts() => RejectedAction::Accept { retry: verdict.first },
                (PinDecision::Refuse(r), Some(o)) => {
                    refused(o, PageFailure { check: r.check(), notice: r.notice() });
                    RejectedAction::Refuse
                }
                _ => RejectedAction::Refuse,
            };
        }
        match self.operator_override(origin, chain) {
            // Accepted earlier in this session (the reload, or another
            // connection): already applied once, so no reload.
            OverrideVerdict::Accepted => RejectedAction::Accept { retry: false },
            OverrideVerdict::Declined => {
                if let Some(o) = origin {
                    refused(o, LoadFailure::TlsDeclined.page_failure());
                }
                RejectedAction::Refuse
            }
            OverrideVerdict::NotApplicable | OverrideVerdict::Unreadable => RejectedAction::Refuse,
            OverrideVerdict::Ask(leaf) => match origin {
                Some(o) if can_ask => RejectedAction::Ask { origin: o.clone(), leaf },
                _ => RejectedAction::Refuse,
            },
        }
    }
}

/// (window label, origin, leaf key): one question, however many
/// connections or loads ask about the same key while it is open.
pub type PendingKey = (String, WebOrigin, SpkiPin);

/// The platform loads held while the operator is asked about a certificate
/// (T139). Every held item must be answered exactly once — WebKit raises an
/// exception for a completion handler released uncalled, and WebView2 waits
/// on an uncompleted deferral — so items leave only through [`Self::take`]
/// (the answer) or [`Self::take_window`] (the window is being destroyed).
/// Each shim keeps one in a main-thread `thread_local!`: the platform
/// objects it holds are not `Send`.
pub struct PendingQuestions<H> {
    held: HashMap<PendingKey, Vec<H>>,
}

impl<H> Default for PendingQuestions<H> {
    fn default() -> Self {
        Self { held: HashMap::new() }
    }
}

impl<H> PendingQuestions<H> {
    /// Hold `item` until `key` is answered. True for the first item of a
    /// key: the caller asks the question; later ones wait for that answer.
    pub fn hold(&mut self, key: PendingKey, item: H) -> bool {
        let waiting = self.held.entry(key).or_default();
        waiting.push(item);
        waiting.len() == 1
    }

    /// Everything held for `key`, now answered.
    pub fn take(&mut self, key: &PendingKey) -> Vec<H> {
        self.held.remove(key).unwrap_or_default()
    }

    /// Everything held for the window `label`, which is going away.
    pub fn take_window(&mut self, label: &str) -> Vec<H> {
        let keys: Vec<PendingKey> = self.held.keys().filter(|(l, _, _)| l == label).cloned().collect();
        keys.into_iter().filter_map(|k| self.held.remove(&k)).flatten().collect()
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
    use base64::Engine as _;
    use bastion_vault::utils::tls_pin::MAX_PINS;
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

    fn prompting_gate(p: PinSet) -> Arc<TlsPinGate> {
        let set = OriginSet::new(vec![origin("https://appliance.example.com")]);
        let audit = PinAudit { resource: "km".into(), token: "sess_t".into(), launch_id_hash: Some("h".into()) };
        TlsPinGate::with_operator_override(p, set, audit, Box::new(|_| {}))
    }

    #[test]
    fn the_operator_is_asked_once_per_key_and_the_answer_is_per_key() {
        let (der, _) = self_signed();
        let (other, _) = self_signed();
        let g = prompting_gate(PinSet::default());
        let o = origin("https://appliance.example.com");
        assert!(g.applies_to(Some(&o)), "a window without pins may ask");
        assert!(!g.has_pins());
        let OverrideVerdict::Ask(leaf) = g.operator_override(Some(&o), &[der.clone()]) else {
            panic!("expected a question")
        };
        assert_eq!(leaf, pin_of(&der));
        assert!(!g.accepted_on_pin(&o));
        assert!(g.record_override(&o, leaf, true));
        assert_eq!(g.operator_override(Some(&o), &[der.clone()]), OverrideVerdict::Accepted);
        assert!(g.accepted_on_pin(&o), "shown like a pin acceptance");
        // The first answer stands.
        assert!(g.record_override(&o, leaf, false));
        assert_eq!(g.operator_override(Some(&o), &[der]), OverrideVerdict::Accepted);
        // A different key on the same origin is a new question: accepting
        // one key never accepts another.
        let OverrideVerdict::Ask(other_leaf) = g.operator_override(Some(&o), &[other.clone()]) else {
            panic!("a new key is asked about")
        };
        assert!(!g.record_override(&o, other_leaf, false));
        assert_eq!(g.operator_override(Some(&o), &[other]), OverrideVerdict::Declined);
    }

    #[test]
    fn the_operator_is_never_asked_outside_the_session_or_over_a_pin() {
        let (der, _) = self_signed();
        let (pinned, _) = self_signed();
        let g = prompting_gate(PinSet::default());
        let foreign = origin("https://evil.example");
        assert_eq!(g.operator_override(Some(&foreign), &[der.clone()]), OverrideVerdict::NotApplicable);
        assert_eq!(g.operator_override(None, &[der.clone()]), OverrideVerdict::NotApplicable);
        let leaf = SpkiPin::of_certificate(&der).unwrap();
        assert!(!g.record_override(&foreign, leaf, true), "nothing recorded off the session");
        assert!(!g.accepted_on_pin(&foreign));
        let http = origin("http://appliance.example.com");
        assert_eq!(g.operator_override(Some(&http), &[der.clone()]), OverrideVerdict::NotApplicable);

        // A profile with pins: a mismatch is refused, never offered.
        let pinned_gate = prompting_gate(pins(&[pin_of(&pinned)]));
        let o = origin("https://appliance.example.com");
        assert!(pinned_gate.has_pins());
        assert_eq!(pinned_gate.operator_override(Some(&o), &[der.clone()]), OverrideVerdict::NotApplicable);
        assert!(!pinned_gate.record_override(&o, leaf, true));
        assert!(!pinned_gate.server_trust(Some(&o), &[der.clone()]).decision.accepts());

        // A gate built without the override never asks.
        let (plain, _) = gate(PinSet::default());
        assert!(!plain.applies_to(Some(&o)));
        assert_eq!(plain.operator_override(Some(&o), &[der]), OverrideVerdict::NotApplicable);
    }

    #[test]
    fn decide_rejected_asks_once_then_follows_the_answer() {
        let (der, _) = self_signed();
        let g = prompting_gate(PinSet::default());
        let o = origin("https://appliance.example.com");
        let noted = std::cell::RefCell::new(Vec::new());
        let note = |o: &WebOrigin, f: PageFailure| noted.borrow_mut().push((o.clone(), f.check));

        let RejectedAction::Ask { origin: asked, leaf } = g.decide_rejected(Some(&o), &[der.clone()], true, note)
        else {
            panic!("expected a question")
        };
        assert_eq!(asked, o);
        assert_eq!(g.decide_rejected(Some(&o), &[der.clone()], false, note), RejectedAction::Refuse, "cannot ask");
        assert!(noted.borrow().is_empty(), "not asking is not a declined key");

        g.record_override(&o, leaf, true);
        assert_eq!(g.decide_rejected(Some(&o), &[der.clone()], true, note), RejectedAction::Accept { retry: false });

        let (other, _) = self_signed();
        let RejectedAction::Ask { leaf: other_leaf, .. } = g.decide_rejected(Some(&o), &[other.clone()], true, note)
        else {
            panic!("a new key is asked about")
        };
        g.record_override(&o, other_leaf, false);
        assert_eq!(g.decide_rejected(Some(&o), &[other], true, note), RejectedAction::Refuse);
        assert_eq!(*noted.borrow(), vec![(o.clone(), "tls_declined")]);

        // Outside the session: refused, nothing noted, never asked.
        let foreign = origin("https://evil.example");
        assert_eq!(g.decide_rejected(Some(&foreign), &[der.clone()], true, note), RejectedAction::Refuse);
        assert_eq!(g.decide_rejected(None, &[der], true, note), RejectedAction::Refuse);
        assert_eq!(noted.borrow().len(), 1);
    }

    #[test]
    fn decide_rejected_lets_pins_decide_and_retries_once() {
        let (pinned, _) = self_signed();
        let (other, _) = self_signed();
        let g = prompting_gate(pins(&[pin_of(&pinned)]));
        let o = origin("https://appliance.example.com");
        let noted = std::cell::RefCell::new(Vec::new());
        let note = |o: &WebOrigin, f: PageFailure| noted.borrow_mut().push((o.clone(), f.check));
        assert_eq!(g.decide_rejected(Some(&o), &[pinned.clone()], true, note), RejectedAction::Accept { retry: true });
        assert_eq!(g.decide_rejected(Some(&o), &[pinned], true, note), RejectedAction::Accept { retry: false });
        assert_eq!(g.decide_rejected(Some(&o), &[other], true, note), RejectedAction::Refuse, "never asked");
        assert_eq!(*noted.borrow(), vec![(o, "tls_pin_mismatch")]);
    }

    #[test]
    fn pending_questions_are_answered_once_per_key_and_per_window() {
        let (a, _) = self_signed();
        let (b, _) = self_signed();
        let o = origin("https://appliance.example.com");
        let key_a = ("web-1".to_string(), o.clone(), pin_of(&a));
        let key_b = ("web-1".to_string(), o.clone(), pin_of(&b));
        let key_other = ("web-2".to_string(), o, pin_of(&a));
        let mut p = PendingQuestions::default();
        assert!(p.hold(key_a.clone(), 1), "first item asks");
        assert!(!p.hold(key_a.clone(), 2), "second waits for the same answer");
        assert!(p.hold(key_b.clone(), 3));
        assert!(p.hold(key_other.clone(), 4), "another window asks for itself");
        assert_eq!(p.take(&key_a), vec![1, 2]);
        assert!(p.take(&key_a).is_empty(), "answered once");
        let mut gone = p.take_window("web-1");
        gone.sort();
        assert_eq!(gone, vec![3]);
        assert_eq!(p.take(&key_other), vec![4]);
    }

    #[test]
    fn an_unreadable_leaf_is_refused_not_asked() {
        let g = prompting_gate(PinSet::default());
        let o = origin("https://appliance.example.com");
        assert_eq!(g.operator_override(Some(&o), &[b"not a certificate".to_vec()]), OverrideVerdict::Unreadable);
        assert_eq!(g.operator_override(Some(&o), &[]), OverrideVerdict::Unreadable);
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
