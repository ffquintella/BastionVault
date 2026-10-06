//! Web Application Connect, `http-auth` login mode — the decisions
//! (features/web-application-connect.md §7; T96 Phase 3).
//!
//! The desktop host answers HTTP Basic / Digest / NTLM challenges for a web
//! session natively — WKWebView's navigation delegate, WebView2's
//! `BasicAuthenticationRequested`, WebKitGTK's `authenticate` signal — and
//! never through the page. The platform shims in
//! `commands/connect_web_http_auth.rs` only translate a platform challenge
//! into a [`Challenge`] and a [`GateAnswer`] back into the platform's
//! disposition; every decision is made here, without Tauri or a webview, so
//! it is unit-tested.
//!
//! The rules (§7, §6):
//!
//! * **Answer** only a Basic, Digest or NTLM challenge whose protection space
//!   is an exact origin of the server's scope (`fill_scope.origins`: scheme,
//!   host and port), over https — or plain http when the profile sets
//!   `allow_insecure_http`, which the server only launches at a `dom` cap.
//! * **At most once per (origin, realm).** A second challenge for a pair
//!   already answered means the credential was rejected: it is refused, the
//!   outcome is `failure`, and the credential is dropped. The handler never
//!   loops.
//! * **Refused explicitly** (and audited, and shown in the window title):
//!   Kerberos / Negotiate, client-certificate requests, proxy challenges, any
//!   other scheme, an origin outside the scope, plain http without the opt-in.
//! * **Server trust** (the TLS certificate check) is never touched: it falls
//!   through to the platform's default evaluation. Phase 4 owns pinning;
//!   nothing here can accept a certificate.
//!
//! Outcome, reported once like a form recipe's (`v2/connect/web/result`,
//! `web-session-outcome`, the title): `success` on the first finished
//! top-frame load of a scope origin after an answer, with no repeat
//! challenge before it; `failure` on a repeat challenge; when the answer
//! window ([`ANSWER_WINDOW`]) closes first, `timeout` — or
//! `aborted:<refusal>` when no challenge was ever answered but one was
//! refused.
//!
//! The credential (a username and a password in `Zeroizing` buffers) is held
//! only for the answer window, and is dropped earlier on a failure and when
//! the session ends. Each answer hands the platform a zeroizing copy; the
//! platform's own copy (an `NSURLCredential`, WebView2's response strings, a
//! `WebKitCredential`) is the webview's, cached for the session in its
//! ephemeral store, and not something the host can scrub. Never logged:
//! the username, the password, the realm beyond a bounded quoted string.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tauri::Url;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::web::{OriginSet, WebOrigin};
use super::web_recipe::Outcome;

/// How long the credential is held to answer challenges, from the moment the
/// session window starts loading: the server's login window
/// (`LOGIN_WINDOW_SECS`). A challenge after it is refused (`auth_released`).
pub const ANSWER_WINDOW: Duration = Duration::from_secs(60);

/// Longest realm kept for the audit line; the rest is cut. The realm is
/// server-chosen text, so it never reaches the window title at all.
const MAX_AUDIT_REALM: usize = 64;

/// The authentication method of a challenge, as the platform reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    Basic,
    Digest,
    Ntlm,
    /// Kerberos / SPNEGO. Refused (§7, and out of scope for the feature).
    Negotiate,
    /// A TLS client-certificate request. Refused.
    ClientCertificate,
    /// The TLS server-trust evaluation. Always the platform default.
    ServerTrust,
    /// Anything else (HTML form, a platform "default" method, unknown).
    Other,
}

impl AuthMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::Digest => "digest",
            Self::Ntlm => "ntlm",
            Self::Negotiate => "negotiate",
            Self::ClientCertificate => "client_certificate",
            Self::ServerTrust => "server_trust",
            Self::Other => "other",
        }
    }

    /// The method named by the first auth-scheme token of a
    /// `WWW-Authenticate` value (RFC 9110 §11.6.1; case-insensitive). Used
    /// on WebView2, which reports the challenge as that header's text.
    // Only the WebView2 shim calls this outside the tests.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn from_scheme_token(token: &str) -> Self {
        match token.to_ascii_lowercase().as_str() {
            "basic" => Self::Basic,
            "digest" => Self::Digest,
            "ntlm" => Self::Ntlm,
            "negotiate" | "kerberos" => Self::Negotiate,
            _ => Self::Other,
        }
    }
}

/// One challenge, as the platform shim read it off the protection space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub method: AuthMethod,
    /// The protection space's scheme (`https` / `http`), any case.
    pub scheme: String,
    pub host: String,
    /// The port. `0` (unknown) never matches an origin.
    pub port: u16,
    pub realm: Option<String>,
    /// A proxy challenge. Refused: answering it would hand the application
    /// credential to the proxy.
    pub is_proxy: bool,
}

impl Challenge {
    /// The exact origin of the protection space, or `None` when it is not an
    /// http(s) origin with a plain ASCII host and a known port. Built through
    /// the same URL parser as the window's allow-list, then held to the host
    /// it was given, so nothing the parser would re-interpret can match.
    pub fn origin(&self) -> Option<WebOrigin> {
        WebOrigin::from_parts(&self.scheme, &self.host, self.port)
    }

    /// WebView2 reports the request URI and the `WWW-Authenticate` text. A URI
    /// that does not parse yields a challenge no origin can match.
    // Only the WebView2 shim calls this outside the tests.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn from_uri_and_header(uri: &str, www_authenticate: &str) -> Self {
        let (method, realm) = parse_www_authenticate(www_authenticate);
        let url = Url::parse(uri.trim()).ok().filter(|u| u.username().is_empty() && u.password().is_none());
        Self {
            method,
            scheme: url.as_ref().map(|u| u.scheme().to_string()).unwrap_or_default(),
            host: url.as_ref().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default(),
            port: url.as_ref().and_then(Url::port_or_known_default).unwrap_or(0),
            realm,
            is_proxy: false,
        }
    }
}

/// The method and realm of a `WWW-Authenticate` value. Only the first
/// challenge is read: if a server offers several (`Negotiate, Basic …`), the
/// platform asks about the first, and refusing it is the safe reading.
// Only the WebView2 shim reaches this outside the tests.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn parse_www_authenticate(header: &str) -> (AuthMethod, Option<String>) {
    let header = header.trim();
    let token_end = header.find(|c: char| c.is_ascii_whitespace() || c == ',').unwrap_or(header.len());
    let method = AuthMethod::from_scheme_token(&header[..token_end]);
    let params = &header[token_end..];
    // `realm=` as a parameter name: at the start of the parameter list or
    // after a comma / space, case-insensitive.
    let lower = params.to_ascii_lowercase();
    let mut realm = None;
    let mut from = 0;
    while let Some(i) = lower[from..].find("realm") {
        let at = from + i;
        let before_ok = at == 0 || matches!(lower.as_bytes()[at - 1], b' ' | b'\t' | b',');
        let rest = params[at + "realm".len()..].trim_start();
        if before_ok && rest.starts_with('=') {
            realm = Some(read_param_value(rest[1..].trim_start()));
            break;
        }
        from = at + "realm".len();
    }
    (method, realm)
}

/// A quoted-string (with `\` escapes) or a token.
#[cfg_attr(not(windows), allow(dead_code))]
fn read_param_value(v: &str) -> String {
    let mut out = String::new();
    if let Some(quoted) = v.strip_prefix('"') {
        let mut chars = quoted.chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => break,
                '\\' => {
                    if let Some(n) = chars.next() {
                        out.push(n);
                    }
                }
                c => out.push(c),
            }
        }
    } else {
        out.extend(v.chars().take_while(|c| !c.is_ascii_whitespace() && *c != ','));
    }
    out
}

/// Why a challenge was refused. [`check`](Self::check) is the
/// `aborted:<check>` name (server rule: `[a-z0-9_]{1,32}`) and the audit
/// reason; [`notice`](Self::notice) the operator-facing title text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Proxy,
    Negotiate,
    ClientCertificate,
    Scheme,
    Insecure,
    Origin,
    /// A pair already answered: the credential was rejected.
    Repeat,
    /// The credential is no longer held (answer window over, a failure, or
    /// the session is ending).
    Released,
}

impl Refusal {
    pub fn check(self) -> &'static str {
        match self {
            Self::Proxy => "auth_proxy",
            Self::Negotiate => "auth_negotiate",
            Self::ClientCertificate => "auth_client_certificate",
            Self::Scheme => "auth_scheme",
            Self::Insecure => "auth_insecure",
            Self::Origin => "auth_origin",
            Self::Repeat => "auth_repeat",
            Self::Released => "auth_released",
        }
    }

    /// Fixed text only: never the realm, which the server chooses.
    pub fn notice(self) -> &'static str {
        match self {
            Self::Proxy => "refused a proxy sign-in challenge",
            Self::Negotiate => "Kerberos / Negotiate sign-in is not supported — refused",
            Self::ClientCertificate => "refused a client-certificate request",
            Self::Scheme => "refused an unsupported sign-in challenge",
            Self::Insecure => "refused a sign-in challenge over plain http",
            Self::Origin => "refused a sign-in challenge from an origin outside this profile",
            Self::Repeat => "the server rejected the credential",
            Self::Released => "sign-in window over — reconnect to sign in again",
        }
    }
}

/// What to tell the platform about one challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Supply the launch credential.
    Answer,
    /// Supply nothing and do not show the platform's own prompt.
    Refuse(Refusal),
    /// The platform's default handling (server trust only).
    Default,
}

/// The pure state machine behind one http-auth session.
#[derive(Debug)]
pub struct HttpAuthState {
    origins: OriginSet,
    allow_insecure_http: bool,
    /// (origin, realm) pairs answered once. `""` stands for no realm.
    answered: Vec<(WebOrigin, String)>,
    /// An answer was given and no outcome has been judged yet.
    awaiting_load: bool,
    first_refusal: Option<Refusal>,
    outcome: Option<Outcome>,
    /// The credential is gone; nothing is answered any more.
    released: bool,
}

impl HttpAuthState {
    /// `origins` / `allow_insecure_http` are the server's scope for this
    /// launch (`fill_scope`), never the host's own copy of the profile.
    pub fn new(origins: OriginSet, allow_insecure_http: bool) -> Self {
        Self {
            origins,
            allow_insecure_http,
            answered: Vec::new(),
            awaiting_load: false,
            first_refusal: None,
            outcome: None,
            released: false,
        }
    }

    #[cfg(test)]
    pub fn outcome(&self) -> Option<Outcome> {
        self.outcome
    }

    pub fn holds_credential(&self) -> bool {
        !self.released
    }

    fn refuse(&mut self, r: Refusal) -> (Decision, Option<Outcome>) {
        self.first_refusal.get_or_insert(r);
        (Decision::Refuse(r), None)
    }

    /// Decide one challenge. Returns the decision and the outcome it
    /// settles, if any (only a repeat challenge settles one: `failure`).
    pub fn on_challenge(&mut self, ch: &Challenge) -> (Decision, Option<Outcome>) {
        match ch.method {
            AuthMethod::ServerTrust => return (Decision::Default, None),
            _ if ch.is_proxy => return self.refuse(Refusal::Proxy),
            AuthMethod::Negotiate => return self.refuse(Refusal::Negotiate),
            AuthMethod::ClientCertificate => return self.refuse(Refusal::ClientCertificate),
            AuthMethod::Other => return self.refuse(Refusal::Scheme),
            AuthMethod::Basic | AuthMethod::Digest | AuthMethod::Ntlm => {}
        }
        if ch.scheme.eq_ignore_ascii_case("http") && !self.allow_insecure_http {
            return self.refuse(Refusal::Insecure);
        }
        let Some(origin) = ch.origin() else {
            return self.refuse(Refusal::Origin);
        };
        if !self.origins.contains(&origin) {
            return self.refuse(Refusal::Origin);
        }
        let key = (origin, ch.realm.clone().unwrap_or_default());
        if self.answered.contains(&key) {
            // Answered once already: the credential was rejected. Never
            // answered again, here or for any other pair.
            self.awaiting_load = false;
            self.released = true;
            if self.outcome.is_none() {
                self.outcome = Some(Outcome::Failure);
                return (Decision::Refuse(Refusal::Repeat), Some(Outcome::Failure));
            }
            return (Decision::Refuse(Refusal::Repeat), None);
        }
        if self.released {
            return self.refuse(Refusal::Released);
        }
        self.answered.push(key);
        if self.outcome.is_none() {
            self.awaiting_load = true;
        }
        (Decision::Answer, None)
    }

    /// A finished top-frame load the host observed. Settles `success` when an
    /// answer is awaiting it and the page is on a scope origin.
    pub fn on_top_frame_finished(&mut self, url: &Url) -> Option<Outcome> {
        let on_scope = WebOrigin::of_url(url).is_some_and(|o| self.origins.contains(&o));
        if !on_scope || !self.awaiting_load || self.outcome.is_some() {
            return None;
        }
        self.awaiting_load = false;
        self.outcome = Some(Outcome::Success);
        self.outcome
    }

    /// The answer window closed. Drops the credential and settles the outcome
    /// if nothing did: `timeout` when an answer was given (or nothing was
    /// asked), `aborted:<first refusal>` when challenges came and every one
    /// was refused.
    pub fn on_deadline(&mut self) -> Option<Outcome> {
        self.released = true;
        if self.outcome.is_some() {
            return None;
        }
        let outcome = match (self.answered.is_empty(), self.first_refusal) {
            (true, Some(r)) => Outcome::Aborted(r.check()),
            _ => Outcome::Timeout,
        };
        self.awaiting_load = false;
        self.outcome = Some(outcome);
        self.outcome
    }

    /// The session is ending: drop the credential. The teardown reports its
    /// own `aborted:<reason>` if no outcome was settled.
    pub fn release(&mut self) {
        self.released = true;
        self.awaiting_load = false;
    }
}

/// The released credential of an http-auth launch. Both parts are required;
/// `Debug` never prints them.
pub struct HttpAuthCredential {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl HttpAuthCredential {
    pub fn new(username: Zeroizing<String>, password: Zeroizing<String>) -> Self {
        Self { username, password }
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    fn zeroizing_copy(&self) -> Self {
        Self {
            username: Zeroizing::new(self.username.to_string()),
            password: Zeroizing::new(self.password.to_string()),
        }
    }
}

impl fmt::Debug for HttpAuthCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HttpAuthCredential(<redacted>)")
    }
}

/// What the platform shim does with a challenge.
#[derive(Debug)]
pub enum GateAnswer {
    /// Use this credential. A zeroizing copy, dropped by the shim right after
    /// it built the platform's credential object.
    Answer(HttpAuthCredential),
    Refuse(Refusal),
    Default,
}

/// Something the session's reporter task acts on (title, `result`, event).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateEvent {
    Outcome(Outcome),
    Notice(&'static str),
}

/// Names for the gate's audit lines. Never a credential, a realm in full, a
/// path or a query.
#[derive(Debug, Clone)]
pub struct GateAudit {
    pub resource: String,
    pub token: String,
    pub launch_id_hash: String,
}

/// The state machine plus the credential, shared between the platform
/// handler (main thread) and the session's reporter task. Locks are held for
/// a decision only, never across an `.await`.
pub struct HttpAuthGate {
    state: Mutex<HttpAuthState>,
    credential: Mutex<Option<HttpAuthCredential>>,
    events: mpsc::UnboundedSender<GateEvent>,
    audit: GateAudit,
}

impl fmt::Debug for HttpAuthGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpAuthGate").field("audit", &self.audit).finish_non_exhaustive()
    }
}

fn audit_realm(realm: Option<&str>) -> String {
    let r: String = realm.unwrap_or("").chars().take(MAX_AUDIT_REALM).collect();
    format!("{r:?}")
}

fn audit_origin(ch: &Challenge) -> String {
    ch.origin().map(|o| o.to_string()).unwrap_or_else(|| format!("{}:", ch.scheme.to_ascii_lowercase()))
}

impl HttpAuthGate {
    pub fn new(
        state: HttpAuthState,
        credential: HttpAuthCredential,
        audit: GateAudit,
    ) -> (Arc<Self>, mpsc::UnboundedReceiver<GateEvent>) {
        let (events, rx) = mpsc::unbounded_channel();
        let gate = Self { state: Mutex::new(state), credential: Mutex::new(Some(credential)), events, audit };
        (Arc::new(gate), rx)
    }

    fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Drop the credential once the state no longer holds it. Its buffers are
    /// zeroized on drop.
    fn settle_credential(&self, state: &HttpAuthState) {
        if !state.holds_credential() {
            Self::lock(&self.credential).take();
        }
    }

    fn send(&self, ev: GateEvent) {
        // The reporter is gone only once the session is over.
        let _ = self.events.send(ev);
    }

    /// Decide one platform challenge.
    pub fn challenge(&self, ch: &Challenge) -> GateAnswer {
        let (decision, outcome) = {
            let mut state = Self::lock(&self.state);
            let r = state.on_challenge(ch);
            self.settle_credential(&state);
            r
        };
        let a = &self.audit;
        let answer = match decision {
            Decision::Default => return GateAnswer::Default,
            Decision::Answer => match Self::lock(&self.credential).as_ref().map(HttpAuthCredential::zeroizing_copy) {
                Some(c) => {
                    log::info!(
                        target: "audit",
                        "connect.web.http_auth_answered: resource={} token={} launch_id_hash={} origin={} scheme={} \
                         realm={}",
                        a.resource,
                        a.token,
                        a.launch_id_hash,
                        audit_origin(ch),
                        ch.method.as_str(),
                        audit_realm(ch.realm.as_deref()),
                    );
                    GateAnswer::Answer(c)
                }
                // Not reachable while the state and the credential are
                // released together; refused rather than assumed.
                None => GateAnswer::Refuse(Refusal::Released),
            },
            Decision::Refuse(r) => GateAnswer::Refuse(r),
        };
        if let GateAnswer::Refuse(r) = &answer {
            log::warn!(
                target: "audit",
                "connect.web.http_auth_refused: resource={} token={} launch_id_hash={} origin={} scheme={} realm={} \
                 reason={}",
                a.resource,
                a.token,
                a.launch_id_hash,
                audit_origin(ch),
                ch.method.as_str(),
                audit_realm(ch.realm.as_deref()),
                r.check(),
            );
            self.send(GateEvent::Notice(r.notice()));
        }
        if let Some(o) = outcome {
            self.send(GateEvent::Outcome(o));
        }
        answer
    }

    /// A finished top-frame load.
    pub fn page_finished(&self, url: &Url) {
        let outcome = Self::lock(&self.state).on_top_frame_finished(url);
        if let Some(o) = outcome {
            self.send(GateEvent::Outcome(o));
        }
    }

    /// The answer window closed. Returns the outcome it settled, if any.
    pub fn expire(&self) -> Option<Outcome> {
        let outcome = {
            let mut state = Self::lock(&self.state);
            let o = state.on_deadline();
            self.settle_credential(&state);
            o
        };
        if outcome.is_some() {
            log::info!(
                target: "audit",
                "connect.web.http_auth_window_closed: resource={} token={} launch_id_hash={} credential=dropped",
                self.audit.resource,
                self.audit.token,
                self.audit.launch_id_hash,
            );
        }
        outcome
    }

    /// The session is ending: drop the credential now.
    pub fn release(&self) {
        let mut state = Self::lock(&self.state);
        state.release();
        self.settle_credential(&state);
    }

    #[cfg(test)]
    fn holds_credential(&self) -> bool {
        Self::lock(&self.credential).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(s: &str) -> WebOrigin {
        WebOrigin::parse_config(s, true).unwrap()
    }

    fn scope() -> OriginSet {
        OriginSet::new(vec![origin("https://bmc.example.com"), origin("https://bmc.example.com:8443")])
    }

    fn ch(method: AuthMethod, scheme: &str, host: &str, port: u16, realm: Option<&str>) -> Challenge {
        Challenge {
            method,
            scheme: scheme.into(),
            host: host.into(),
            port,
            realm: realm.map(str::to_string),
            is_proxy: false,
        }
    }

    fn basic(realm: &str) -> Challenge {
        ch(AuthMethod::Basic, "https", "bmc.example.com", 443, Some(realm))
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn answers_basic_digest_and_ntlm_on_a_scope_origin_once_per_realm() {
        for m in [AuthMethod::Basic, AuthMethod::Digest, AuthMethod::Ntlm] {
            let mut s = HttpAuthState::new(scope(), false);
            assert_eq!(s.on_challenge(&ch(m, "https", "bmc.example.com", 443, Some("r"))), (Decision::Answer, None));
            // Another realm, and another scope origin, are separate pairs.
            assert_eq!(s.on_challenge(&ch(m, "https", "bmc.example.com", 443, Some("r2"))).0, Decision::Answer);
            assert_eq!(s.on_challenge(&ch(m, "HTTPS", "BMC.example.com", 8443, None)).0, Decision::Answer);
        }
    }

    #[test]
    fn a_second_challenge_for_an_answered_pair_is_a_failure_never_a_loop() {
        let mut s = HttpAuthState::new(scope(), false);
        assert_eq!(s.on_challenge(&basic("admin")).0, Decision::Answer);
        assert_eq!(s.on_challenge(&basic("admin")), (Decision::Refuse(Refusal::Repeat), Some(Outcome::Failure)));
        // Settled once; the credential is gone, so nothing else is answered.
        assert_eq!(s.on_challenge(&basic("admin")), (Decision::Refuse(Refusal::Repeat), None));
        assert_eq!(s.on_challenge(&basic("other")).0, Decision::Refuse(Refusal::Released));
        assert!(!s.holds_credential());
        assert_eq!(s.on_top_frame_finished(&url("https://bmc.example.com/")), None);
        assert_eq!(s.on_deadline(), None);
        assert_eq!(s.outcome(), Some(Outcome::Failure));
    }

    #[test]
    fn success_is_the_first_finished_scope_load_after_an_answer() {
        let mut s = HttpAuthState::new(scope(), false);
        // A load before any answer settles nothing.
        assert_eq!(s.on_top_frame_finished(&url("https://bmc.example.com/")), None);
        assert_eq!(s.on_challenge(&basic("admin")).0, Decision::Answer);
        // about:blank (the window's first page) and foreign origins do not count.
        assert_eq!(s.on_top_frame_finished(&url("about:blank")), None);
        assert_eq!(s.on_top_frame_finished(&url("https://other.example/")), None);
        assert_eq!(s.on_top_frame_finished(&url("https://bmc.example.com/index.html")), Some(Outcome::Success));
        assert_eq!(s.on_top_frame_finished(&url("https://bmc.example.com/x")), None, "once");
        // Still answers another realm inside the window, never a repeat.
        assert_eq!(s.on_challenge(&basic("other")).0, Decision::Answer);
        assert_eq!(s.on_challenge(&basic("admin")), (Decision::Refuse(Refusal::Repeat), None));
        assert_eq!(s.outcome(), Some(Outcome::Success), "a later rejection does not rewrite the outcome");
    }

    #[test]
    fn wrong_host_port_or_scheme_is_refused() {
        let mut s = HttpAuthState::new(scope(), false);
        for c in [
            ch(AuthMethod::Basic, "https", "evil.example", 443, Some("r")),
            ch(AuthMethod::Basic, "https", "bmc.example.com", 9443, Some("r")),
            ch(AuthMethod::Basic, "https", "bmc.example.com.evil.example", 443, Some("r")),
            ch(AuthMethod::Basic, "https", "bmc.example.com", 0, Some("r")),
            ch(AuthMethod::Basic, "https", "", 443, Some("r")),
            ch(AuthMethod::Basic, "https", "bmc.example.com@evil.example", 443, Some("r")),
            ch(AuthMethod::Basic, "https", "bmc.example.com/x", 443, Some("r")),
            ch(AuthMethod::Basic, "ftp", "bmc.example.com", 443, Some("r")),
        ] {
            assert_eq!(s.on_challenge(&c).0, Decision::Refuse(Refusal::Origin), "{c:?}");
        }
        // Plain http without the opt-in, even for the scope host.
        let http = ch(AuthMethod::Basic, "http", "bmc.example.com", 80, Some("r"));
        assert_eq!(s.on_challenge(&http).0, Decision::Refuse(Refusal::Insecure));
        // With the opt-in, http still needs its exact origin in the scope.
        let mut s = HttpAuthState::new(OriginSet::new(vec![origin("http://bmc.example.com")]), true);
        assert_eq!(s.on_challenge(&http).0, Decision::Answer);
        let https = ch(AuthMethod::Basic, "https", "bmc.example.com", 443, Some("r"));
        assert_eq!(s.on_challenge(&https).0, Decision::Refuse(Refusal::Origin));
    }

    #[test]
    fn negotiate_client_certificates_proxies_and_unknown_schemes_are_refused() {
        let mut s = HttpAuthState::new(scope(), false);
        let on_scope = |m| ch(m, "https", "bmc.example.com", 443, Some("r"));
        assert_eq!(s.on_challenge(&on_scope(AuthMethod::Negotiate)).0, Decision::Refuse(Refusal::Negotiate));
        assert_eq!(
            s.on_challenge(&on_scope(AuthMethod::ClientCertificate)).0,
            Decision::Refuse(Refusal::ClientCertificate)
        );
        assert_eq!(s.on_challenge(&on_scope(AuthMethod::Other)).0, Decision::Refuse(Refusal::Scheme));
        let mut proxy = on_scope(AuthMethod::Basic);
        proxy.is_proxy = true;
        assert_eq!(s.on_challenge(&proxy).0, Decision::Refuse(Refusal::Proxy));
        // None of these used up the pair: Basic for it is still answered.
        assert_eq!(s.on_challenge(&on_scope(AuthMethod::Basic)).0, Decision::Answer);
    }

    #[test]
    fn server_trust_always_falls_through_to_the_platform_default() {
        let mut s = HttpAuthState::new(scope(), false);
        for c in [
            ch(AuthMethod::ServerTrust, "https", "bmc.example.com", 443, None),
            ch(AuthMethod::ServerTrust, "https", "evil.example", 443, None),
        ] {
            assert_eq!(s.on_challenge(&c), (Decision::Default, None));
        }
        s.release();
        assert_eq!(s.on_challenge(&ch(AuthMethod::ServerTrust, "https", "x.example", 443, None)).0, Decision::Default);
        assert_eq!(s.on_deadline(), Some(Outcome::Timeout), "server trust is never a refusal");
    }

    #[test]
    fn the_deadline_drops_the_credential_and_settles_the_outcome() {
        // Nothing asked: timeout.
        let mut s = HttpAuthState::new(scope(), false);
        assert_eq!(s.on_deadline(), Some(Outcome::Timeout));
        assert_eq!(s.on_challenge(&basic("admin")).0, Decision::Refuse(Refusal::Released));

        // Only refusals: aborted with the first one.
        let mut s = HttpAuthState::new(scope(), false);
        s.on_challenge(&ch(AuthMethod::Negotiate, "https", "bmc.example.com", 443, None));
        s.on_challenge(&ch(AuthMethod::Basic, "https", "evil.example", 443, None));
        assert_eq!(s.on_deadline(), Some(Outcome::Aborted("auth_negotiate")));

        // Answered, no finished load seen: timeout.
        let mut s = HttpAuthState::new(scope(), false);
        s.on_challenge(&basic("admin"));
        assert_eq!(s.on_deadline(), Some(Outcome::Timeout));
        assert_eq!(s.on_top_frame_finished(&url("https://bmc.example.com/")), None);

        // Teardown releases without settling anything.
        let mut s = HttpAuthState::new(scope(), false);
        s.release();
        assert_eq!(s.outcome(), None);
        assert_eq!(s.on_challenge(&basic("admin")).0, Decision::Refuse(Refusal::Released));
    }

    #[test]
    fn refusal_checks_are_valid_abort_names() {
        for r in [
            Refusal::Proxy,
            Refusal::Negotiate,
            Refusal::ClientCertificate,
            Refusal::Scheme,
            Refusal::Insecure,
            Refusal::Origin,
            Refusal::Repeat,
            Refusal::Released,
        ] {
            let c = r.check();
            assert!(
                (1..=32).contains(&c.len())
                    && c.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{c}"
            );
            assert!(crate::session::web_recipe::HOST_ABORT_CHECKS.contains(&c), "{c} missing from HOST_ABORT_CHECKS");
        }
    }

    #[test]
    fn www_authenticate_values_parse_to_method_and_realm() {
        assert_eq!(parse_www_authenticate(r#"Basic realm="iDRAC""#), (AuthMethod::Basic, Some("iDRAC".into())));
        assert_eq!(
            parse_www_authenticate(r#"Digest qop="auth", realm="a \"b\" c", nonce="xyz""#),
            (AuthMethod::Digest, Some(r#"a "b" c"#.into()))
        );
        assert_eq!(parse_www_authenticate("NTLM"), (AuthMethod::Ntlm, None));
        assert_eq!(parse_www_authenticate("negotiate"), (AuthMethod::Negotiate, None));
        assert_eq!(parse_www_authenticate("Negotiate, Basic realm=\"x\""), (AuthMethod::Negotiate, Some("x".into())));
        assert_eq!(parse_www_authenticate("Bearer realm=api"), (AuthMethod::Other, Some("api".into())));
        assert_eq!(parse_www_authenticate("Basic xrealm=\"no\""), (AuthMethod::Basic, None));
        assert_eq!(parse_www_authenticate(""), (AuthMethod::Other, None));
    }

    #[test]
    fn webview2_challenges_take_their_origin_from_the_request_uri() {
        let c = Challenge::from_uri_and_header("https://BMC.example.com/redfish/v1?x=1", r#"Basic realm="r""#);
        assert_eq!(c.origin(), Some(origin("https://bmc.example.com")));
        assert_eq!((c.method, c.realm.as_deref()), (AuthMethod::Basic, Some("r")));
        let c = Challenge::from_uri_and_header("https://bmc.example.com:8443/", "Basic");
        assert_eq!(c.origin(), Some(origin("https://bmc.example.com:8443")));
        for bad in ["not a uri", "https://bmc.example.com@evil.example/", "file:///etc/passwd", ""] {
            let c = Challenge::from_uri_and_header(bad, "Basic");
            let mut s = HttpAuthState::new(scope(), false);
            assert_eq!(s.on_challenge(&c).0, Decision::Refuse(Refusal::Origin), "{bad}");
        }
    }

    fn gate() -> (Arc<HttpAuthGate>, mpsc::UnboundedReceiver<GateEvent>) {
        HttpAuthGate::new(
            HttpAuthState::new(scope(), false),
            HttpAuthCredential::new(Zeroizing::new("admin".into()), Zeroizing::new("hunter2".into())),
            GateAudit { resource: "bmc01".into(), token: "sess_x".into(), launch_id_hash: "ab".into() },
        )
    }

    #[test]
    fn the_gate_hands_out_copies_and_drops_the_credential_on_failure() {
        let (g, mut rx) = gate();
        let GateAnswer::Answer(c) = g.challenge(&basic("admin")) else { panic!("expected an answer") };
        assert_eq!((c.username(), c.password()), ("admin", "hunter2"));
        assert!(!format!("{c:?} {g:?}").contains("hunter2"), "Debug never prints the credential");
        drop(c);
        assert!(g.holds_credential());
        assert!(matches!(g.challenge(&basic("admin")), GateAnswer::Refuse(Refusal::Repeat)));
        assert!(!g.holds_credential(), "a rejected credential is dropped at once");
        assert_eq!(rx.try_recv(), Ok(GateEvent::Notice(Refusal::Repeat.notice())));
        assert_eq!(rx.try_recv(), Ok(GateEvent::Outcome(Outcome::Failure)));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn the_gate_reports_success_and_releases_at_the_deadline_or_teardown() {
        let (g, mut rx) = gate();
        assert!(matches!(g.challenge(&ch(AuthMethod::ServerTrust, "https", "x", 443, None)), GateAnswer::Default));
        assert!(matches!(g.challenge(&basic("admin")), GateAnswer::Answer(_)));
        g.page_finished(&url("https://bmc.example.com/"));
        assert_eq!(rx.try_recv(), Ok(GateEvent::Outcome(Outcome::Success)));
        assert!(g.holds_credential(), "kept for other realms until the window closes");
        assert_eq!(g.expire(), None, "already settled");
        assert!(!g.holds_credential());

        let (g, _rx) = gate();
        g.release();
        assert!(!g.holds_credential());
        assert!(matches!(g.challenge(&basic("admin")), GateAnswer::Refuse(Refusal::Released)));
    }
}
