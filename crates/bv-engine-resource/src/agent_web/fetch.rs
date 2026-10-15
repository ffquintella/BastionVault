//! The vault-side HTTPS client behind `bv_resource_web_fetch`
//! (`features/mcp-brokered-sessions.md` §6.2-6.3, §11): one `GET` or `HEAD`
//! of the confirmed path, from the profile's start origin, and nothing the
//! model could steer beyond that.
//!
//! **What it dials.** Only addresses the destination policy has checked: the
//! start origin's (checked by the handler before any credential was read)
//! and, for each redirect, the new hop's, resolved once and checked address
//! by address before anything is sent there. reqwest is given those
//! addresses as the only answer for that one name, and a resolver that
//! answers nothing else; no proxy (the environment's included), no
//! redirects of its own, no retries, no connection pool.
//!
//! **Redirects** are followed by this loop, at most [`MAX_REDIRECTS`], only
//! to https origins the profile lists (`web.start_url`'s and
//! `web.allowed_origins`). An off-list redirect stops the fetch; its target
//! is never returned or logged.
//!
//! **The credential** (`http-auth`, Basic only) is sent only in answer to a
//! `401` Basic challenge from an allowed https origin, at most once per
//! (origin, realm) in a call — never pre-emptively, never to Digest, NTLM or
//! Negotiate. A second challenge after an answer is the target refusing the
//! credential: that `401` is the result; the client does not loop.
//!
//! **Request headers are fixed**: a `User-Agent`, `Accept`,
//! `Accept-Encoding: identity`, and the call's own cookies back to the
//! origin that set them. The agent supplies none.
//!
//! **The body** of the final response only is read, at most the raw cap.

use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};

use base64::Engine as _;
use bv_kernel_api::{
    mcp_events::AbortCause,
    mcp_sessions::BrokeredSessionEnv,
    mcp_transcripts::{WebTranscriptHop, MAX_TRANSCRIPT_HOP_PATH_BYTES},
};
use bv_utils::destination_policy::{CheckedTarget, DestinationPolicy};
use reqwest::{
    dns::{Name, Resolve, Resolving},
    header::{self, HeaderMap, HeaderValue},
    Method, StatusCode, Url,
};
use tokio::{sync::watch, time::Instant};
use zeroize::Zeroizing;

use super::{
    cookies::CookieJar,
    profile::WebOrigin,
    tls::{AgentCertVerifier, TlsVerdict},
    MAX_REDIRECTS,
};
use crate::agent_session::{check_destination, SessionRefusal};

/// `User-Agent` of every agent fetch: the product and this engine's
/// major.minor, nothing about the call.
pub const USER_AGENT: &str =
    concat!("BastionVault-Agent/", env!("CARGO_PKG_VERSION_MAJOR"), ".", env!("CARGO_PKG_VERSION_MINOR"));

/// `Accept` of every agent fetch: what the result can show as text first.
pub const ACCEPT: &str = "text/html,application/xhtml+xml,application/json;q=0.9,text/*;q=0.8,*/*;q=0.1";

/// Longest `Content-Type` value kept; a server chooses it.
pub const MAX_CONTENT_TYPE_CHARS: usize = 256;

/// The stored HTTP Basic credential of an `http-auth` profile, in memory
/// that is wiped when it drops.
pub struct BasicCredential {
    pub username: Zeroizing<String>,
    pub password: Zeroizing<String>,
}

impl BasicCredential {
    fn header(&self) -> Zeroizing<String> {
        let pair = Zeroizing::new(format!("{}:{}", self.username.as_str(), self.password.as_str()));
        Zeroizing::new(format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(pair.as_bytes())))
    }
}

/// One fetch to run.
pub struct FetchSpec {
    /// `GET` or `HEAD`.
    pub method: String,
    /// The confirmed origin-relative path, with its query.
    pub path: String,
    pub start: WebOrigin,
    /// Origin keys a redirect may go to.
    pub allowed: Vec<String>,
    /// The start origin's checked addresses.
    pub first_target: CheckedTarget,
    /// The policy every redirect hop is checked against.
    pub policy: DestinationPolicy,
    /// For the resolver every redirect hop is resolved through.
    pub env: Arc<dyn BrokeredSessionEnv>,
    pub verifier: Arc<AgentCertVerifier>,
    pub credential: Option<BasicCredential>,
    pub deadline: Instant,
    /// Budget to connect and handshake, per request, inside the deadline.
    pub connect_budget: Duration,
    /// Raw body bytes read, at most.
    pub raw_limit: usize,
}

/// What a fetch did, whatever its outcome: for the transcript and events.
#[derive(Default)]
pub struct FetchTrace {
    /// Every request sent.
    pub hops: Vec<WebTranscriptHop>,
    /// The address the first request dialed.
    pub first_target: Option<SocketAddr>,
    /// How the last certificate was trusted.
    pub tls: Option<TlsVerdict>,
    /// The profile's credential answered a challenge.
    pub credential_sent: bool,
    /// The call's cookies; their values are scrubbed from what is returned
    /// and recorded.
    pub jar: CookieJar,
}

/// The final response.
pub struct Fetched {
    pub status: u16,
    pub content_type: Option<String>,
    /// The origin that answered.
    pub final_origin: String,
    /// Its path, without the query or `;` parameters: never a session URL.
    pub final_path: String,
    pub redirects: u32,
    /// At most the raw cap.
    pub body: Vec<u8>,
    /// The body was longer than the raw cap.
    pub body_truncated: bool,
}

/// Why a fetch ended without a final response.
#[derive(Debug)]
pub enum FetchStop {
    /// Stopped by a rule after it had dialed: an off-list redirect, a
    /// refused hop destination, a refused certificate, too many redirects.
    Refused(SessionRefusal),
    /// Revoked or switched off.
    Aborted(AbortCause),
    /// The call's deadline passed.
    TimedOut,
    /// The network or the server failed it.
    Failed(String),
}

fn origin_refused(message: impl Into<String>) -> FetchStop {
    FetchStop::Refused(SessionRefusal::new("mcp_web_origin_refused", 403, message))
}

/// `https://host[:port]` of a URL, in the profile's origin-key form
/// (lower-case host, default port dropped). `None` for anything but https.
pub fn origin_key(url: &Url) -> Option<String> {
    if url.scheme() != "https" {
        return None;
    }
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("https://{host}:{port}"),
        None => format!("https://{host}"),
    })
}

/// The URL of the first request: the start origin plus the confirmed path,
/// which must come out of URL parsing byte for byte — what the operator
/// confirmed is what is sent. The dispatcher refuses every path the parser
/// would rewrite; this holds the line if one ever got past it.
pub fn first_url(start: &WebOrigin, path: &str) -> Result<Url, SessionRefusal> {
    let invalid = |m: String| SessionRefusal::new("mcp_invalid_argument", 400, m);
    let url =
        Url::parse(&format!("{}{path}", start.key)).map_err(|e| invalid(format!("`path` does not parse: {e}")))?;
    if origin_key(&url).as_deref() != Some(start.key.as_str()) {
        return Err(invalid("`path` would change the origin it is fetched from".into()));
    }
    let sent = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };
    if sent != path {
        return Err(invalid(format!("`path` is not in normal form; it would be sent as {sent:?}")));
    }
    Ok(url)
}

/// The path of the final response as returned: no query, no `;` path
/// parameters (`;jsessionid=…`).
pub fn final_path(url: &Url) -> String {
    url.path().split('/').map(|segment| segment.split(';').next().unwrap_or_default()).collect::<Vec<_>>().join("/")
}

/// A hop's path with its query, for the transcript, cut at its limit.
fn hop_path(url: &Url) -> String {
    let mut p = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };
    if p.len() > MAX_TRANSCRIPT_HOP_PATH_BYTES {
        let mut end = MAX_TRANSCRIPT_HOP_PATH_BYTES;
        while !p.is_char_boundary(end) {
            end -= 1;
        }
        p.truncate(end);
    }
    p
}

/// Where a redirect may go: an https origin the profile lists, no userinfo,
/// no fragment. Anything else stops the fetch; the target is not repeated.
fn redirect_target(current: &Url, location: &HeaderValue, allowed: &[String]) -> Result<Url, FetchStop> {
    let off_list = || {
        origin_refused(
            "the target redirected outside the profile's https origins (web.start_url, web.allowed_origins); the \
             fetch was stopped and the redirect target is not returned",
        )
    };
    let raw = location.to_str().map_err(|_| off_list())?;
    if raw.len() > MAX_TRANSCRIPT_HOP_PATH_BYTES {
        return Err(off_list());
    }
    let mut next = current.join(raw).map_err(|_| off_list())?;
    next.set_fragment(None);
    if !next.username().is_empty() || next.password().is_some() {
        return Err(off_list());
    }
    match origin_key(&next) {
        Some(key) if allowed.contains(&key) => Ok(next),
        _ => Err(off_list()),
    }
}

/// The realm of a `Basic` challenge among the response's
/// `WWW-Authenticate` headers (`""` when it names none); `None` when no
/// challenge is Basic — Digest, NTLM and Negotiate are never answered.
pub fn basic_realm(headers: &HeaderMap) -> Option<String> {
    for value in headers.get_all(header::WWW_AUTHENTICATE) {
        let Ok(text) = value.to_str() else { continue };
        let trimmed = text.trim_start();
        let Some((scheme, params)) = trimmed.split_once(char::is_whitespace).or(Some((trimmed, ""))) else {
            continue;
        };
        if !scheme.eq_ignore_ascii_case("basic") {
            continue;
        }
        let lower = params.to_ascii_lowercase();
        let realm = match lower.find("realm=") {
            Some(at) => {
                let rest = &params[at + "realm=".len()..];
                match rest.strip_prefix('"') {
                    Some(quoted) => quoted.split('"').next().unwrap_or_default().to_string(),
                    None => rest.split([',', ' ']).next().unwrap_or_default().to_string(),
                }
            }
            None => String::new(),
        };
        return Some(realm);
    }
    None
}

/// The resolver reqwest gets: it answers nothing. Every name a request may
/// use is given its checked addresses as an override, so a name this
/// resolver is asked about is one nobody checked.
struct NoResolution;

impl Resolve for NoResolution {
    fn resolve(&self, name: Name) -> Resolving {
        let name = name.as_str().to_string();
        Box::pin(async move {
            Err(format!("{name:?} was not checked by the destination policy; it is not resolved").into())
        })
    }
}

fn client_for(
    spec: &FetchSpec,
    url: &Url,
    target: &CheckedTarget,
    remaining: Duration,
) -> Result<reqwest::Client, FetchStop> {
    let tls = spec.verifier.client_config().map_err(|e| FetchStop::Failed(format!("TLS could not be set up: {e}")))?;
    let mut builder = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .referer(false)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .http1_only()
        .https_only(true)
        .pool_max_idle_per_host(0)
        .connect_timeout(remaining.min(spec.connect_budget))
        .timeout(remaining)
        .user_agent(USER_AGENT)
        .dns_resolver(Arc::new(NoResolution));
    // A name gets its checked addresses as the only answer; an IP literal
    // is dialed as itself (and was checked as itself).
    if let Some(host) = url.host_str().filter(|h| !h.starts_with('[') && h.parse::<std::net::IpAddr>().is_err()) {
        builder = builder.resolve_to_addrs(host, target.addrs());
    }
    builder.build().map_err(|e| FetchStop::Failed(format!("the HTTP client could not be built: {}", e.without_url())))
}

/// What a failed request amounts to: a refused certificate by its code,
/// the deadline, or a plain failure. Never the URL.
fn classify(e: reqwest::Error, verifier: &AgentCertVerifier, target: &CheckedTarget) -> FetchStop {
    match verifier.take_verdict() {
        Some(TlsVerdict::Unpinned) => {
            return FetchStop::Refused(SessionRefusal::new(
                "mcp_web_tls_unpinned",
                403,
                "the target's TLS certificate is not trusted by the platform roots, and the profile pins no key \
                 (web.tls_pin_sha256); an agent fetch never trusts a certificate on first use",
            ))
        }
        Some(TlsVerdict::PinRefused(r)) => {
            return FetchStop::Refused(SessionRefusal::new(
                "mcp_web_tls_pin_mismatch",
                403,
                format!(
                    "the target's TLS certificate is not trusted by the platform roots and no pinned key admits it \
                     ({})",
                    r.check()
                ),
            ))
        }
        _ => {}
    }
    if e.is_timeout() {
        return FetchStop::TimedOut;
    }
    if e.is_connect() {
        return FetchStop::Failed(format!("could not connect to {}", target.primary()));
    }
    // The causes, then the error without its URL: a path may carry a query
    // the agent should not see echoed into an audit line.
    let mut causes = Vec::new();
    let mut source = std::error::Error::source(&e);
    while let Some(s) = source {
        causes.push(s.to_string());
        source = s.source();
    }
    let mut message = e.without_url().to_string();
    for cause in causes {
        message.push_str(": ");
        message.push_str(&cause);
    }
    FetchStop::Failed(format!("the request failed: {message}"))
}

/// Read at most `limit` bytes of the body. `true` when there was more.
async fn read_body(response: &mut reqwest::Response, limit: usize) -> Result<(Vec<u8>, bool), reqwest::Error> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let room = limit - body.len();
        if chunk.len() > room {
            body.extend_from_slice(&chunk[..room]);
            return Ok((body, true));
        }
        body.extend_from_slice(&chunk);
        if body.len() == limit {
            // Exactly at the cap: is there more?
            let more = response.chunk().await?.is_some_and(|c| !c.is_empty());
            return Ok((body, more));
        }
    }
    Ok((body, false))
}

/// Run the fetch until it answers, stops, times out or is aborted.
pub async fn run(
    spec: FetchSpec,
    mut abort: watch::Receiver<Option<AbortCause>>,
) -> (FetchTrace, Result<Fetched, FetchStop>) {
    let mut trace = FetchTrace::default();
    let deadline = spec.deadline;
    let outcome = {
        let work = fetch(&spec, &mut trace);
        tokio::select! {
            outcome = work => outcome,
            cause = abort.wait_for(Option::is_some) => {
                Err(FetchStop::Aborted(cause.ok().and_then(|c| *c).unwrap_or(AbortCause::ExecutorError)))
            }
            _ = tokio::time::sleep_until(deadline) => Err(FetchStop::TimedOut),
        }
    };
    (trace, outcome)
}

async fn fetch(spec: &FetchSpec, trace: &mut FetchTrace) -> Result<Fetched, FetchStop> {
    let mut url = first_url(&spec.start, &spec.path).map_err(FetchStop::Refused)?;
    let method = match spec.method.as_str() {
        "GET" => Method::GET,
        "HEAD" => Method::HEAD,
        other => return Err(FetchStop::Failed(format!("{other:?} is not a method an agent fetch sends"))),
    };
    let mut target = Some(spec.first_target.clone());
    let mut answered: HashSet<(String, String)> = HashSet::new();
    let mut redirects: u32 = 0;
    loop {
        let origin = origin_key(&url).ok_or_else(|| origin_refused("an agent fetch is https only"))?;
        let checked = match target.take() {
            Some(t) => t,
            None => {
                let host = url.host_str().unwrap_or_default().to_string();
                let port = url.port_or_known_default().unwrap_or(443);
                check_destination(&spec.env, &spec.policy, host, port).await.map_err(FetchStop::Refused)?
            }
        };
        trace.first_target.get_or_insert(checked.primary());
        let remaining = spec.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(FetchStop::TimedOut);
        }
        let client = client_for(spec, &url, &checked, remaining)?;

        let mut authorization: Option<Zeroizing<String>> = None;
        let mut response = loop {
            let mut request = client
                .request(method.clone(), url.clone())
                .header(header::ACCEPT, ACCEPT)
                .header(header::ACCEPT_ENCODING, "identity");
            if let Some(cookie) = trace.jar.header_for(&origin) {
                let mut value = HeaderValue::from_str(cookie.as_str())
                    .map_err(|_| FetchStop::Failed("a cookie the target set cannot be sent back".into()))?;
                value.set_sensitive(true);
                request = request.header(header::COOKIE, value);
            }
            if let Some(auth) = &authorization {
                let mut value = HeaderValue::from_str(auth.as_str())
                    .map_err(|_| FetchStop::Failed("the stored credential cannot be sent in a header".into()))?;
                value.set_sensitive(true);
                request = request.header(header::AUTHORIZATION, value);
            }
            // Recorded before it is sent, so a request cut short by the
            // deadline or a revocation is still in the transcript.
            trace.hops.push(WebTranscriptHop {
                origin: origin.clone(),
                path: hop_path(&url),
                status: None,
                answered_challenge: authorization.is_some(),
            });
            let response = match request.send().await {
                Ok(r) => r,
                Err(e) => return Err(classify(e, &spec.verifier, &checked)),
            };
            if let Some(verdict) = spec.verifier.take_verdict() {
                trace.tls = Some(verdict);
            }
            if let Some(hop) = trace.hops.last_mut() {
                hop.status = Some(response.status().as_u16());
            }
            let set_cookies: Vec<String> = response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok().map(str::to_string))
                .collect();
            trace.jar.absorb(&origin, set_cookies.iter().map(String::as_str));
            if response.status() == StatusCode::UNAUTHORIZED && authorization.is_none() {
                if let (Some(credential), Some(realm)) = (&spec.credential, basic_realm(response.headers())) {
                    if answered.insert((origin.clone(), realm)) {
                        authorization = Some(credential.header());
                        trace.credential_sent = true;
                        continue;
                    }
                }
            }
            break response;
        };

        let status = response.status();
        let follows = matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308);
        if let (true, Some(location)) = (follows, response.headers().get(header::LOCATION).cloned()) {
            if redirects as usize >= MAX_REDIRECTS {
                return Err(FetchStop::Refused(SessionRefusal::new(
                    "mcp_session_failed",
                    502,
                    format!("the target redirected more than {MAX_REDIRECTS} times; the fetch was stopped"),
                )));
            }
            url = redirect_target(&url, &location, &spec.allowed)?;
            redirects += 1;
            // GET and HEAD stay what they are across every redirect status.
            continue;
        }

        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.chars().take(MAX_CONTENT_TYPE_CHARS).collect::<String>());
        let (body, body_truncated) = if method == Method::HEAD {
            (Vec::new(), false)
        } else {
            read_body(&mut response, spec.raw_limit).await.map_err(|e| classify(e, &spec.verifier, &checked))?
        };
        return Ok(Fetched {
            status: status.as_u16(),
            content_type,
            final_origin: origin,
            final_path: final_path(&url),
            redirects,
            body,
            body_truncated,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start() -> WebOrigin {
        WebOrigin::from_key("https://grafana.internal:8443").unwrap()
    }

    #[test]
    fn the_first_url_is_the_start_origin_plus_the_confirmed_bytes() {
        let url = first_url(&start(), "/api/health?verbose=1&x=%2F").unwrap();
        assert_eq!(url.as_str(), "https://grafana.internal:8443/api/health?verbose=1&x=%2F");
        // What a URL parser would rewrite is refused, not sent changed.
        for path in ["/a/./b", "/a/%2e/b", "/q?x=it's"] {
            assert_eq!(first_url(&start(), path).unwrap_err().code, "mcp_invalid_argument", "{path}");
        }
        let v6 = WebOrigin::from_key("https://[fd00::9]").unwrap();
        assert_eq!(first_url(&v6, "/").unwrap().as_str(), "https://[fd00::9]/");
    }

    #[test]
    fn redirects_stay_on_the_profiles_https_origins() {
        let here = Url::parse("https://grafana.internal:8443/login").unwrap();
        let allowed = vec!["https://grafana.internal:8443".to_string(), "https://sso.internal".to_string()];
        let to = |loc: &str| redirect_target(&here, &HeaderValue::from_str(loc).unwrap(), &allowed);
        assert_eq!(to("/d/abc#frag").unwrap().as_str(), "https://grafana.internal:8443/d/abc");
        assert_eq!(to("https://SSO.internal/start").unwrap().as_str(), "https://sso.internal/start");
        assert_eq!(to("../home").unwrap().as_str(), "https://grafana.internal:8443/home");
        for off in [
            "https://evil.example/",
            "http://grafana.internal:8443/",
            "https://grafana.internal/",
            "https://user:pw@grafana.internal:8443/",
            "//evil.example/x",
            "https://169.254.169.254/latest/meta-data/",
            "javascript:alert(1)",
        ] {
            match to(off) {
                Err(FetchStop::Refused(r)) => {
                    assert_eq!(r.code, "mcp_web_origin_refused", "{off}");
                    assert!(!r.message.contains("evil") && !r.message.contains("169.254"), "never echoes the target");
                }
                other => panic!("{off}: expected a refusal, got {:?}", other.map(|u| u.to_string())),
            }
        }
    }

    #[test]
    fn only_a_basic_challenge_is_answered() {
        let mut h = HeaderMap::new();
        h.append(header::WWW_AUTHENTICATE, HeaderValue::from_static("Negotiate"));
        h.append(header::WWW_AUTHENTICATE, HeaderValue::from_static("NTLM"));
        assert_eq!(basic_realm(&h), None);
        h.append(header::WWW_AUTHENTICATE, HeaderValue::from_static("Digest realm=\"x\", nonce=\"y\""));
        assert_eq!(basic_realm(&h), None);
        h.append(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"iDRAC\", charset=\"UTF-8\""));
        assert_eq!(basic_realm(&h).as_deref(), Some("iDRAC"));
        let mut bare = HeaderMap::new();
        bare.append(header::WWW_AUTHENTICATE, HeaderValue::from_static("basic"));
        assert_eq!(basic_realm(&bare).as_deref(), Some(""));
    }

    #[test]
    fn the_final_path_carries_no_query_or_session_parameter() {
        let url = Url::parse("https://app/app;jsessionid=ABC123/home;x=1?token=s3cr3t").unwrap();
        assert_eq!(final_path(&url), "/app/home");
        assert_eq!(hop_path(&url), "/app;jsessionid=ABC123/home;x=1?token=s3cr3t");
        let credential =
            BasicCredential { username: Zeroizing::new("ops".into()), password: Zeroizing::new("pw".into()) };
        assert_eq!(credential.header().as_str(), "Basic b3BzOnB3");
        assert!(USER_AGENT.starts_with("BastionVault-Agent/"));
    }
}

/// The executor against a real HTTPS server on loopback (`test_server`),
/// through the destination policy's test seam and a fixed resolver.
#[cfg(test)]
mod server_tests {
    use std::{
        collections::HashMap,
        net::{IpAddr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use bv_errors::RvError;
    use bv_kernel_api::mcp_sessions::{BrokeredSessionEnv, BrokeredSessionRuntime, BrokeredSessionSettings};
    use bv_utils::{
        destination_policy::{parse_target_cidrs, DestinationPolicy, Resolver, TargetCidrSource, TargetCidrs},
        tls_pin::PinSet,
    };
    use tokio::{sync::watch, time::Instant};
    use zeroize::Zeroizing;

    use super::{run, BasicCredential, FetchSpec, FetchStop, FetchTrace, Fetched};
    use crate::agent_web::{
        profile::WebOrigin,
        test_server::{unrelated_pin, RecordedRequest, TestResponse, TestWebServer},
        tls::{AgentCertVerifier, TlsVerdict},
    };

    /// Names answered from a table: what a DNS server under an attacker's
    /// control could answer.
    struct Names(HashMap<String, Vec<IpAddr>>);

    impl Resolver for Names {
        fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
            self.0
                .get(host)
                .map(|ips| ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect())
                .ok_or_else(|| std::io::Error::other("NXDOMAIN"))
        }
    }

    struct Env(Arc<Names>);

    #[maybe_async::maybe_async]
    impl BrokeredSessionEnv for Env {
        fn settings(&self) -> BrokeredSessionSettings {
            BrokeredSessionSettings::default()
        }
        async fn runtime(&self) -> Result<BrokeredSessionRuntime, RvError> {
            Ok(BrokeredSessionRuntime {
                enabled: true,
                allowed_target_cidrs: vec![],
                source: TargetCidrSource::Default,
            })
        }
        fn destination_policy(&self, allowed: TargetCidrs) -> DestinationPolicy {
            DestinationPolicy::new(allowed, [], []).permit_loopback_for_tests()
        }
        fn resolver(&self) -> Arc<dyn Resolver> {
            self.0.clone()
        }
    }

    const PASSWORD: &str = "hunter2-Qx7";

    struct Call {
        path: String,
        method: &'static str,
        pins: Vec<String>,
        allowed: Vec<String>,
        names: Vec<(&'static str, Vec<&'static str>)>,
        credential: bool,
        raw_limit: usize,
        timeout: Duration,
    }

    impl Call {
        fn new(path: &str) -> Self {
            Self {
                path: path.into(),
                method: "GET",
                pins: vec![],
                allowed: vec![],
                names: vec![("app.test", vec!["127.0.0.1"])],
                credential: false,
                raw_limit: 2 << 20,
                timeout: Duration::from_secs(10),
            }
        }

        async fn run(self, server: &TestWebServer) -> (FetchTrace, Result<Fetched, FetchStop>) {
            let port = server.addr().port();
            let names = Arc::new(Names(
                self.names
                    .iter()
                    .map(|(n, ips)| (n.to_string(), ips.iter().map(|i| i.parse().unwrap()).collect()))
                    .collect(),
            ));
            let env: Arc<dyn BrokeredSessionEnv> = Arc::new(Env(names.clone()));
            let policy = env.destination_policy(parse_target_cidrs(&["10.0.0.0/8"]).unwrap().cidrs);
            let start = WebOrigin::from_key(&format!("https://app.test:{port}")).unwrap();
            let first_target = policy.resolve_and_check(names.as_ref(), "app.test", port).unwrap();
            let mut allowed = vec![start.key.clone()];
            allowed.extend(self.allowed);
            let spec = FetchSpec {
                method: self.method.into(),
                path: self.path,
                start,
                allowed,
                first_target,
                policy,
                env,
                verifier: AgentCertVerifier::new(
                    Arc::new(rustls::RootCertStore::empty()),
                    PinSet::from_strs(&self.pins).unwrap(),
                ),
                credential: self.credential.then(|| BasicCredential {
                    username: Zeroizing::new("ops".into()),
                    password: Zeroizing::new(PASSWORD.into()),
                }),
                deadline: Instant::now() + self.timeout,
                connect_budget: Duration::from_secs(5),
                raw_limit: self.raw_limit,
            };
            let (_keep, abort) = watch::channel(None);
            let out = run(spec, abort).await;
            drop(_keep);
            out
        }
    }

    fn stop_code(outcome: &Result<Fetched, FetchStop>) -> &'static str {
        match outcome {
            Err(FetchStop::Refused(r)) => r.code,
            Err(FetchStop::TimedOut) => "timed_out",
            Err(FetchStop::Aborted(_)) => "aborted",
            Err(FetchStop::Failed(_)) => "failed",
            Ok(_) => "ok",
        }
    }

    fn page(req: &RecordedRequest) -> TestResponse {
        match req.path.as_str() {
            "/" => TestResponse::new(200, "text/html", "<h1>Home</h1>"),
            "/hop" => TestResponse::redirect(302, "/landing?from=hop"),
            "/landing?from=hop" => TestResponse::new(200, "text/plain", "landed"),
            "/big" => TestResponse::new(200, "text/plain", vec![b'x'; 5000]),
            "/slow" => {
                TestResponse { delay: Some(Duration::from_secs(30)), ..TestResponse::new(200, "text/plain", "late") }
            }
            "/loop" => TestResponse::redirect(302, "/loop"),
            _ => TestResponse::new(404, "text/plain", "not here"),
        }
    }

    async fn server() -> TestWebServer {
        TestWebServer::start(&["app.test", "other.test", "127.0.0.1"], page).await
    }

    /// A leaf pin admits the self-signed test server; the request carries
    /// only the fixed headers.
    #[tokio::test]
    async fn a_pinned_leaf_is_fetched_with_fixed_headers_only() {
        let s = server().await;
        let mut call = Call::new("/");
        call.pins = vec![s.leaf_pin()];
        let (trace, outcome) = call.run(&s).await;
        let fetched = outcome.unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!((fetched.status, fetched.body.as_slice()), (200, b"<h1>Home</h1>".as_slice()));
        assert_eq!(trace.tls, Some(TlsVerdict::Pinned(bv_utils::tls_pin::PinMatch::Leaf)));
        let seen = s.requests();
        assert_eq!(seen.len(), 1);
        let r = &seen[0];
        assert_eq!((r.method.as_str(), r.path.as_str()), ("GET", "/"));
        assert!(r.header("user-agent").unwrap().starts_with("BastionVault-Agent/"));
        assert_eq!(r.header("accept-encoding"), Some("identity"));
        assert!(r.header("authorization").is_none() && r.header("cookie").is_none());
        let names: Vec<&str> = r.headers.iter().map(|(n, _)| n.as_str()).collect();
        for n in &names {
            assert!(
                ["host", "user-agent", "accept", "accept-encoding"].contains(n),
                "unexpected header {n}: {names:?}"
            );
        }
    }

    /// The TLS pin: an issuer pin admits the CA's leaf; a mismatch and no
    /// pin at all refuse before any request is sent.
    #[tokio::test]
    async fn the_certificate_needs_a_matching_pin() {
        let s = server().await;
        let mut issuer = Call::new("/");
        issuer.pins = vec![s.ca_pin()];
        assert_eq!(stop_code(&issuer.run(&s).await.1), "ok");
        let mut wrong = Call::new("/");
        wrong.pins = vec![unrelated_pin()];
        assert_eq!(stop_code(&wrong.run(&s).await.1), "mcp_web_tls_pin_mismatch");
        let (trace, outcome) = Call::new("/").run(&s).await;
        assert_eq!(stop_code(&outcome), "mcp_web_tls_unpinned");
        assert_eq!(trace.hops.len(), 1, "the attempt is recorded");
        assert_eq!(trace.hops[0].status, None);
        assert_eq!(s.requests().len(), 1, "only the issuer-pinned call reached the server");
    }

    /// Redirects within the origin are followed and re-checked; the final
    /// path carries no query.
    #[tokio::test]
    async fn redirects_are_followed_within_the_allowed_origins() {
        let s = server().await;
        let mut call = Call::new("/hop");
        call.pins = vec![s.leaf_pin()];
        let (trace, outcome) = call.run(&s).await;
        let fetched = outcome.unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(
            (fetched.redirects, fetched.final_path.as_str(), fetched.body.as_slice()),
            (1, "/landing", b"landed".as_slice())
        );
        let paths: Vec<&str> = trace.hops.iter().map(|h| h.path.as_str()).collect();
        assert_eq!(paths, vec!["/hop", "/landing?from=hop"]);
    }

    /// A redirect off the list stops the fetch; one to a listed origin whose
    /// name resolves to a refused address (link-local, or a mixed answer as
    /// a rebinding DNS server would give) stops it too, before anything is
    /// sent there.
    #[tokio::test]
    async fn redirect_hops_are_held_to_the_origins_and_the_destination_policy() {
        let s = TestWebServer::start(&["app.test", "127.0.0.1"], |req| match req.path.as_str() {
            "/off" => TestResponse::redirect(302, "https://evil.example/steal"),
            "/meta" => TestResponse::redirect(302, "https://meta.test/latest"),
            "/rebind" => TestResponse::redirect(307, "https://rebind.test/x"),
            "/private" => TestResponse::redirect(301, "https://private.test/"),
            _ => TestResponse::new(200, "text/plain", "ok"),
        })
        .await;
        for (path, expected) in [
            ("/off", "mcp_web_origin_refused"),
            ("/meta", "mcp_session_destination_refused"),
            ("/rebind", "mcp_session_destination_refused"),
            ("/private", "mcp_session_destination_refused"),
        ] {
            let mut call = Call::new(path);
            call.pins = vec![s.leaf_pin()];
            call.allowed =
                vec!["https://meta.test".into(), "https://rebind.test".into(), "https://private.test".into()];
            call.names.push(("meta.test", vec!["169.254.169.254"]));
            call.names.push(("rebind.test", vec!["127.0.0.1", "169.254.169.254"]));
            call.names.push(("private.test", vec!["192.168.1.5"]));
            let (trace, outcome) = call.run(&s).await;
            assert_eq!(stop_code(&outcome), expected, "{path}");
            assert_eq!(trace.hops.len(), 1, "{path}: nothing was sent to the redirect target");
        }
        assert_eq!(s.requests().len(), 4);
    }

    #[tokio::test]
    async fn too_many_redirects_stop_the_fetch() {
        let s = server().await;
        let mut call = Call::new("/loop");
        call.pins = vec![s.leaf_pin()];
        let (trace, outcome) = call.run(&s).await;
        assert_eq!(stop_code(&outcome), "mcp_session_failed");
        assert_eq!(trace.hops.len(), 1 + super::MAX_REDIRECTS);
    }

    /// The credential is sent only in answer to a Basic challenge, once per
    /// (origin, realm); never to NTLM or Negotiate; a second challenge after
    /// an answer is the result.
    #[tokio::test]
    async fn the_credential_answers_a_basic_challenge_once() {
        let s = TestWebServer::start(&["app.test"], |req| {
            let authorized = req.header("authorization").is_some();
            match (req.path.as_str(), authorized) {
                ("/basic", false) => TestResponse::new(401, "text/plain", "who?")
                    .with_header("www-authenticate", "Basic realm=\"iDRAC\""),
                ("/basic", true) => TestResponse::new(
                    200,
                    "text/plain",
                    format!("hello; seen {}", req.header("authorization").unwrap()),
                ),
                ("/rejecting", _) => {
                    TestResponse::new(401, "text/plain", "nope").with_header("www-authenticate", "Basic realm=\"r\"")
                }
                ("/ntlm", _) => TestResponse::new(401, "text/plain", "ntlm").with_header("www-authenticate", "NTLM"),
                _ => TestResponse::new(404, "text/plain", ""),
            }
        })
        .await;
        let call = |path: &str| {
            let mut c = Call::new(path);
            c.pins = vec![s.leaf_pin()];
            c.credential = true;
            c
        };
        let (trace, outcome) = call("/basic").run(&s).await;
        let fetched = outcome.unwrap();
        assert_eq!(fetched.status, 200);
        assert!(trace.credential_sent && trace.hops[1].answered_challenge);
        let seen = s.requests();
        assert!(seen[0].header("authorization").is_none(), "never pre-emptive");
        assert_eq!(seen[1].header("authorization"), Some("Basic b3BzOmh1bnRlcjItUXg3"));

        let (trace, outcome) = call("/rejecting").run(&s).await;
        assert_eq!(outcome.unwrap().status, 401, "a rejected answer is the result, not a loop");
        assert_eq!(trace.hops.len(), 2);

        let (trace, outcome) = call("/ntlm").run(&s).await;
        assert_eq!(outcome.unwrap().status, 401);
        assert!(!trace.credential_sent);
        assert!(s.requests().iter().filter(|r| r.path == "/ntlm").all(|r| r.header("authorization").is_none()));

        // An `open` profile never answers.
        let mut open = call("/basic");
        open.credential = false;
        assert_eq!(open.run(&s).await.1.unwrap().status, 401);
    }

    /// Cookies a target sets go back to it on the call's next request, and
    /// their values are kept for the scrubber.
    #[tokio::test]
    async fn the_call_cookie_jar_carries_a_login_redirect() {
        let s = TestWebServer::start(&["app.test"], |req| match (req.path.as_str(), req.header("cookie")) {
            ("/start", _) => {
                TestResponse::redirect(302, "/app").with_header("set-cookie", "sid=S3ss10nValue42; Path=/; HttpOnly")
            }
            ("/app", Some("sid=S3ss10nValue42")) => TestResponse::new(200, "text/plain", "welcome S3ss10nValue42"),
            _ => TestResponse::new(403, "text/plain", "no session"),
        })
        .await;
        let mut call = Call::new("/start");
        call.pins = vec![s.leaf_pin()];
        let (trace, outcome) = call.run(&s).await;
        assert_eq!(outcome.unwrap().status, 200);
        let values = trace.jar.into_seen_values();
        assert_eq!(values.iter().map(|v| v.as_str()).collect::<Vec<_>>(), vec!["S3ss10nValue42"]);
    }

    /// HEAD reads no body; the raw cap cuts and says so; the deadline stops
    /// a hanging server.
    #[tokio::test]
    async fn head_caps_and_the_deadline() {
        let s = server().await;
        let mut head = Call::new("/big");
        head.pins = vec![s.leaf_pin()];
        head.method = "HEAD";
        let fetched = head.run(&s).await.1.unwrap();
        assert!(fetched.body.is_empty() && !fetched.body_truncated);
        assert_eq!(s.requests().last().unwrap().method, "HEAD");

        let mut capped = Call::new("/big");
        capped.pins = vec![s.leaf_pin()];
        capped.raw_limit = 1000;
        let fetched = capped.run(&s).await.1.unwrap();
        assert_eq!((fetched.body.len(), fetched.body_truncated), (1000, true));

        let mut exact = Call::new("/big");
        exact.pins = vec![s.leaf_pin()];
        exact.raw_limit = 5000;
        let fetched = exact.run(&s).await.1.unwrap();
        assert_eq!((fetched.body.len(), fetched.body_truncated), (5000, false));

        let mut slow = Call::new("/slow");
        slow.pins = vec![s.leaf_pin()];
        slow.timeout = Duration::from_millis(1500);
        let started = std::time::Instant::now();
        assert_eq!(stop_code(&slow.run(&s).await.1), "timed_out");
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
