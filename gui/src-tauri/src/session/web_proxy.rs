//! Web Application Connect, form-login proxy mode — the decisions
//! (features/web-application-connect.md §10; T106 step 1).
//!
//! In proxy mode the recipe fills a random per-launch placeholder instead of
//! the password. The host-local proxy replaces it with the real secret only in
//! the outgoing submit request, and scrubs the secret back out of that
//! request's response. Everything here is pure: no Tauri, no sockets, no TLS,
//! so the rules are unit-tested. The listener
//! ([`super::web_proxy_listener`], T106 step 2) and the platform wiring call
//! into these functions.

// Proxy mode has no caller yet: the webview is pointed at the listener by the
// platform wiring (T106 step 4, `proxy_url` + `tauri/macos-proxy`), which is
// the next step. Until that lands nothing in the GUI constructs a
// `WebProxy`, so every item in the proxy modules reads as dead to the
// compiler even though the tests drive all of it end to end. Remove this
// (here and in `web_proxy_ca` / `web_proxy_listener` / `web_proxy_upstream`)
// with step 4.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::fmt;

use rand::distr::{Alphanumeric, SampleString};
use zeroize::{Zeroize, Zeroizing};

pub const PLACEHOLDER_LEN: usize = 32;

#[derive(Clone, PartialEq, Eq)]
pub struct SessionSecret {
    placeholder: String,
    secret: String,
}

impl Drop for SessionSecret {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl std::fmt::Debug for SessionSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionSecret").field("placeholder", &self.placeholder).field("secret", &"<redacted>").finish()
    }
}

impl SessionSecret {
    /// The placeholder is fixed-length alphanumeric, so form and JSON encoding
    /// leave it intact and it says nothing about the secret's length.
    pub fn new(secret: String) -> Result<Self, String> {
        if secret.is_empty() {
            return Err("proxy secret is empty".to_string());
        }
        let placeholder = Alphanumeric.sample_string(&mut rand::rng(), PLACEHOLDER_LEN);
        Ok(Self { placeholder, secret })
    }

    pub fn placeholder(&self) -> &str {
        &self.placeholder
    }
}

/// `(host, port)` of an https origin, lower-cased host.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HttpsOrigin {
    host: String,
    port: u16,
}

impl HttpsOrigin {
    /// Parse an `https://host[:port]` origin. Anything else is an error:
    /// proxy mode terminates https only.
    pub fn parse(url: &str) -> Result<Self, String> {
        let rest = url.strip_prefix("https://").ok_or_else(|| format!("proxy origin `{url}` is not https"))?;
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        if authority.is_empty() || authority.contains('@') {
            return Err(format!("proxy origin `{url}` has no plain host"));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !authority.ends_with(']') => {
                let port = p.parse::<u16>().map_err(|_| format!("proxy origin `{url}` has an invalid port"))?;
                (h, port)
            }
            _ => (authority, 443),
        };
        if host.is_empty() {
            return Err(format!("proxy origin `{url}` has no host"));
        }
        Ok(Self { host: host.to_ascii_lowercase(), port })
    }

    /// The host as it is matched: lower-cased, and an IPv6 literal still
    /// bracketed. [`bare_host`] strips the brackets for the places that
    /// need the address itself (a certificate SAN, a TLS server name).
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether a `CONNECT` authority (or a terminated request's `Host`)
    /// names this origin. Host and port together, never one of the two.
    pub fn matches(&self, host: &str, port: u16) -> bool {
        self.port == port && self.host.eq_ignore_ascii_case(host)
    }
}

/// An IPv6 literal without its brackets; any other host unchanged.
pub fn bare_host(host: &str) -> &str {
    host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host)
}

/// The https origins a session terminates. A `CONNECT` outside this set is
/// tunnelled, never terminated, so it is not a question for this type.
#[derive(Debug, Clone, Default)]
pub struct TerminationScope {
    origins: BTreeSet<HttpsOrigin>,
}

impl TerminationScope {
    pub fn new<'a>(origins: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        let origins = origins.into_iter().map(HttpsOrigin::parse).collect::<Result<BTreeSet<_>, _>>()?;
        Ok(Self { origins })
    }

    /// Host and port are matched together; a CONNECT to the same host on
    /// another port is not terminated.
    pub fn terminates(&self, host: &str, port: u16) -> bool {
        self.origins.contains(&HttpsOrigin { host: host.to_ascii_lowercase(), port })
    }

    pub fn is_empty(&self) -> bool {
        self.origins.is_empty()
    }

    pub fn origins(&self) -> impl Iterator<Item = &HttpsOrigin> {
        self.origins.iter()
    }

    /// The distinct hosts the session's certificates must cover. Two origins
    /// on the same host and different ports share one leaf: a certificate
    /// names hosts, not ports.
    pub fn hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self.origins.iter().map(|o| o.host.clone()).collect();
        hosts.dedup();
        hosts
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyType {
    Form,
    Json,
}

impl BodyType {
    /// Parses a `Content-Type` value; parameters and case are ignored.
    pub fn of_content_type(value: &str) -> Option<Self> {
        let essence = value.split(';').next()?.trim().to_ascii_lowercase();
        match essence.as_str() {
            "application/x-www-form-urlencoded" => Some(Self::Form),
            "application/json" => Some(Self::Json),
            other if other.ends_with("+json") => Some(Self::Json),
            _ => None,
        }
    }

    fn encode(self, secret: &str) -> String {
        match self {
            Self::Form => urlencoding::encode(secret).replace("%20", "+"),
            Self::Json => {
                let quoted = serde_json::to_string(secret).unwrap_or_default();
                quoted[1..quoted.len() - 1].to_string()
            }
        }
    }
}

/// The recipe's submit target: the origin and path whose POST may carry the
/// real secret. The query string is not part of the match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitTarget {
    origin: HttpsOrigin,
    path: String,
}

impl SubmitTarget {
    pub fn new(origin_url: &str, path: &str) -> Result<Self, String> {
        if !path.starts_with('/') {
            return Err(format!("submit path `{path}` is not absolute"));
        }
        Ok(Self { origin: HttpsOrigin::parse(origin_url)?, path: path.to_string() })
    }

    pub fn origin(&self) -> &HttpsOrigin {
        &self.origin
    }

    /// Whether a request on `host:port` for `path` is the submit request.
    /// The listener uses this to decide which request bodies it buffers at
    /// all; [`substitute_submit`] applies the same test before touching one.
    pub fn matches(&self, host: &str, port: u16, path: &str) -> bool {
        self.origin.matches(host, port) && self.path == path
    }
}

/// A request as the proxy sees it after parsing, before it is forwarded.
#[derive(Debug, Clone)]
pub struct OutgoingRequest<'a> {
    pub host: &'a str,
    pub port: u16,
    pub method: &'a str,
    /// Path without the query string.
    pub path: &'a str,
    pub content_type: Option<&'a str>,
    pub body: &'a [u8],
}

/// A request body that carries the real secret. Its bytes are zeroized when
/// dropped, and `Debug` never shows them.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBody(Zeroizing<Vec<u8>>);

impl SecretBody {
    fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBody(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Substitution {
    /// Not the submit request, or no placeholder in it: forward untouched.
    Unchanged,
    /// Forward this body in place of the original, with the secret in it.
    Substituted(SecretBody),
    /// The submit request cannot be substituted safely: do not send it.
    Refused(RefuseReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefuseReason {
    NotPost,
    UnsupportedBodyType,
    PlaceholderRepeated,
    BodyNotUtf8,
    /// The body is larger than the listener will buffer, so the placeholder
    /// rule cannot be applied to it. Raised by the listener, not by
    /// [`substitute_submit`].
    BodyTooLarge,
}

impl RefuseReason {
    /// A fixed, logged name for the refusal — the `aborted:<check>` shape the
    /// rest of the feature uses (`[a-z0-9_]{1,32}`). Never carries anything
    /// from the request.
    pub fn check(self) -> &'static str {
        match self {
            Self::NotPost => "proxy_submit_not_post",
            Self::UnsupportedBodyType => "proxy_submit_body_type",
            Self::PlaceholderRepeated => "proxy_submit_placeholder_repeated",
            Self::BodyNotUtf8 => "proxy_submit_body_not_utf8",
            Self::BodyTooLarge => "proxy_submit_body_too_large",
        }
    }
}

/// Replaces the placeholder with the secret in a submit request body.
pub fn substitute_submit(secret: &SessionSecret, target: &SubmitTarget, request: &OutgoingRequest<'_>) -> Substitution {
    let is_target = target.matches(request.host, request.port, request.path);
    let occurrences = count_occurrences(request.body, secret.placeholder.as_bytes());
    if !is_target || occurrences == 0 {
        return Substitution::Unchanged;
    }
    if !request.method.eq_ignore_ascii_case("POST") {
        return Substitution::Refused(RefuseReason::NotPost);
    }
    let Some(body_type) = request.content_type.and_then(BodyType::of_content_type) else {
        return Substitution::Refused(RefuseReason::UnsupportedBodyType);
    };
    if occurrences > 1 {
        return Substitution::Refused(RefuseReason::PlaceholderRepeated);
    }
    if std::str::from_utf8(request.body).is_err() {
        return Substitution::Refused(RefuseReason::BodyNotUtf8);
    }
    let encoded = Zeroizing::new(body_type.encode(&secret.secret));
    Substitution::Substituted(SecretBody::new(replace_all(
        request.body,
        secret.placeholder.as_bytes(),
        encoded.as_bytes(),
    )))
}

/// Replaces every form of the secret in a response body with the placeholder.
pub fn scrub_response(secret: &SessionSecret, body: &[u8]) -> Vec<u8> {
    let mut out = body.to_vec();
    for variant in secret_variants(&secret.secret) {
        out = replace_all(&out, variant.as_bytes(), secret.placeholder.as_bytes());
    }
    out
}

/// Response headers the proxy strips from every terminated response.
pub fn is_stripped_response_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("alt-svc")
}

fn secret_variants(secret: &str) -> Vec<String> {
    let html = secret
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;");
    let json = BodyType::Json.encode(secret);
    let form = BodyType::Form.encode(secret);
    let raw_percent = urlencoding::encode(secret).into_owned();

    let mut seen = BTreeSet::new();
    let mut variants = Vec::new();
    // Longest-first is not needed: each variant is a distinct encoding of the
    // same value, and none can contain another as a substring unless equal.
    for v in [secret.to_string(), form, json, html, raw_percent] {
        if seen.insert(v.clone()) {
            variants.push(v);
        }
    }
    variants
}

fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    haystack.windows(needle.len()).filter(|w| *w == needle).count()
}

fn replace_all(haystack: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack.to_vec();
    }
    let occurrences = count_occurrences(haystack, needle);
    let capacity = haystack.len() - occurrences * needle.len() + occurrences * with.len();
    let mut out = Vec::with_capacity(capacity);
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i..].starts_with(needle) {
            out.extend_from_slice(with);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(value: &str) -> SessionSecret {
        SessionSecret::new(value.to_string()).unwrap()
    }

    fn target() -> SubmitTarget {
        SubmitTarget::new("https://app.example.test", "/login").unwrap()
    }

    fn post<'a>(path: &'a str, content_type: Option<&'a str>, body: &'a [u8]) -> OutgoingRequest<'a> {
        OutgoingRequest { host: "app.example.test", port: 443, method: "POST", path, content_type, body }
    }

    #[test]
    fn placeholder_is_fixed_length_alphanumeric_and_unique() {
        let a = secret("pw");
        let b = secret("pw");
        assert_eq!(a.placeholder().len(), PLACEHOLDER_LEN);
        assert!(a.placeholder().bytes().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(a.placeholder(), b.placeholder());
    }

    #[test]
    fn empty_secret_is_rejected() {
        assert!(SessionSecret::new(String::new()).is_err());
    }

    #[test]
    fn debug_does_not_print_secret() {
        let s = secret("hunter2-unique");
        assert!(!format!("{s:?}").contains("hunter2-unique"));
    }

    #[test]
    fn origin_parse_defaults_port_and_lowercases_host() {
        let o = HttpsOrigin::parse("https://App.Example.TEST/x?y").unwrap();
        assert_eq!(o, HttpsOrigin::parse("https://app.example.test:443").unwrap());
        assert!(HttpsOrigin::parse("http://app.example.test").is_err());
        assert!(HttpsOrigin::parse("https://user@app.example.test").is_err());
        assert!(HttpsOrigin::parse("https://app.example.test:notaport").is_err());
    }

    #[test]
    fn scope_matches_host_and_port_together() {
        let scope = TerminationScope::new(["https://app.example.test"]).unwrap();
        assert!(scope.terminates("APP.example.test", 443));
        assert!(!scope.terminates("app.example.test", 8443));
        assert!(!scope.terminates("cdn.example.test", 443));
    }

    #[test]
    fn body_type_ignores_parameters_and_case() {
        assert_eq!(BodyType::of_content_type("Application/X-WWW-Form-Urlencoded; charset=utf-8"), Some(BodyType::Form));
        assert_eq!(BodyType::of_content_type("application/json"), Some(BodyType::Json));
        assert_eq!(BodyType::of_content_type("application/vnd.api+json"), Some(BodyType::Json));
        assert_eq!(BodyType::of_content_type("text/plain"), None);
    }

    #[test]
    fn form_body_gets_form_encoded_secret() {
        let s = secret("a&b=c d+é");
        let body = format!("user=alice&password={}", s.placeholder());
        let out = substitute_submit(
            &s,
            &target(),
            &post("/login", Some("application/x-www-form-urlencoded"), body.as_bytes()),
        );
        let expected = format!("user=alice&password={}", "a%26b%3Dc+d%2B%C3%A9");
        assert_eq!(out, Substitution::Substituted(SecretBody::new(expected.into_bytes())));
    }

    #[test]
    fn json_body_gets_json_escaped_secret() {
        let s = secret("q\"u\\o");
        let body = format!(r#"{{"password":"{}"}}"#, s.placeholder());
        let out = substitute_submit(&s, &target(), &post("/login", Some("application/json"), body.as_bytes()));
        assert_eq!(out, Substitution::Substituted(SecretBody::new(br#"{"password":"q\"u\\o"}"#.to_vec())));
    }

    #[test]
    fn query_string_is_not_part_of_the_match() {
        let s = secret("pw");
        let body = format!("password={}", s.placeholder());
        let req = post("/login", Some("application/x-www-form-urlencoded"), body.as_bytes());
        assert!(matches!(substitute_submit(&s, &target(), &req), Substitution::Substituted(_)));
    }

    #[test]
    fn other_hosts_paths_and_ports_pass_through_unchanged() {
        let s = secret("pw");
        let body = format!("password={}", s.placeholder());
        let ct = Some("application/x-www-form-urlencoded");
        let other_path = post("/other", ct, body.as_bytes());
        assert_eq!(substitute_submit(&s, &target(), &other_path), Substitution::Unchanged);
        let mut other_host = post("/login", ct, body.as_bytes());
        other_host.host = "cdn.example.test";
        assert_eq!(substitute_submit(&s, &target(), &other_host), Substitution::Unchanged);
        let mut other_port = post("/login", ct, body.as_bytes());
        other_port.port = 8443;
        assert_eq!(substitute_submit(&s, &target(), &other_port), Substitution::Unchanged);
    }

    #[test]
    fn target_without_placeholder_is_unchanged() {
        let s = secret("pw");
        let req = post("/login", Some("application/json"), b"{}");
        assert_eq!(substitute_submit(&s, &target(), &req), Substitution::Unchanged);
    }

    #[test]
    fn non_post_on_target_is_refused() {
        let s = secret("pw");
        let body = format!("password={}", s.placeholder());
        let mut req = post("/login", Some("application/x-www-form-urlencoded"), body.as_bytes());
        req.method = "GET";
        assert_eq!(substitute_submit(&s, &target(), &req), Substitution::Refused(RefuseReason::NotPost));
    }

    #[test]
    fn unsupported_body_type_is_refused() {
        let s = secret("pw");
        let body = format!("password={}", s.placeholder());
        let req = post("/login", Some("multipart/form-data"), body.as_bytes());
        assert_eq!(substitute_submit(&s, &target(), &req), Substitution::Refused(RefuseReason::UnsupportedBodyType));
        let no_ct = post("/login", None, body.as_bytes());
        assert_eq!(substitute_submit(&s, &target(), &no_ct), Substitution::Refused(RefuseReason::UnsupportedBodyType));
    }

    #[test]
    fn repeated_placeholder_is_refused() {
        let s = secret("pw");
        let body = format!("a={0}&b={0}", s.placeholder());
        let req = post("/login", Some("application/x-www-form-urlencoded"), body.as_bytes());
        assert_eq!(substitute_submit(&s, &target(), &req), Substitution::Refused(RefuseReason::PlaceholderRepeated));
    }

    #[test]
    fn scrub_replaces_every_encoding_of_the_secret() {
        let s = secret("a&\"<'b");
        let body =
            format!("raw=a&\"<'b form=a%26%22%3C%27b json=a&\\\"<'b html=a&amp;&quot;&lt;&#x27;b again={}", "a&\"<'b");
        let scrubbed = String::from_utf8(scrub_response(&s, body.as_bytes())).unwrap();
        assert!(!scrubbed.contains("a&\"<'b"));
        assert!(!scrubbed.contains("a%26%22%3C%27b"));
        assert!(!scrubbed.contains("&quot;&lt;&#x27;b"));
        assert!(scrubbed.contains(s.placeholder()));
    }

    #[test]
    fn scrub_leaves_unrelated_bodies_alone() {
        let s = secret("hunter2-unique");
        let body = b"<html>welcome</html>";
        assert_eq!(scrub_response(&s, body), body.to_vec());
    }

    #[test]
    fn alt_svc_is_stripped_case_insensitively() {
        assert!(is_stripped_response_header("Alt-Svc"));
        assert!(!is_stripped_response_header("Set-Cookie"));
    }

    #[test]
    fn submit_target_rejects_relative_path() {
        assert!(SubmitTarget::new("https://app.example.test", "login").is_err());
    }
}
