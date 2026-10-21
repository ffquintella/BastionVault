//! Web Application Connect, form-login proxy mode — the decisions
//! (features/web-application-connect.md §10; T106 step 1).
//!
//! In proxy mode the recipe fills a random per-launch placeholder instead of
//! the password. The host-local proxy replaces it with the real secret only in
//! the outgoing submit request, and scrubs the secret back out of that
//! request's response. Everything here is pure: no Tauri, no sockets, no TLS,
//! so the rules are unit-tested. The listener
//! ([`super::web_proxy_listener`], T106 step 2) and the platform wiring
//! ([`super::web_proxy_webview`], step 4) call into these functions.

use std::collections::BTreeSet;
use std::fmt;

use bastion_vault::modules::resource::connect_web::recipe::SubmitBody;
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

impl From<SubmitBody> for BodyType {
    fn from(body: SubmitBody) -> Self {
        match body {
            SubmitBody::Form => Self::Form,
            SubmitBody::Json => Self::Json,
        }
    }
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

    /// The secret as it appears inside a body of this type. Written straight
    /// into a zeroizing buffer, so no intermediate copy of the secret is left
    /// behind in freed memory.
    fn encode(self, secret: &str) -> Zeroizing<String> {
        match self {
            Self::Form => percent_encode(secret, true),
            Self::Json => json_escape(secret),
        }
    }
}

/// `application/x-www-form-urlencoded` (`space_as_plus`) or plain percent
/// encoding: every byte outside `A-Za-z0-9-._~` as `%XX` — what
/// `urlencoding::encode` produces, with a space as `+` for form bodies.
fn percent_encode(secret: &str, space_as_plus: bool) -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Zeroizing::new(String::with_capacity(secret.len() * 3));
    for &b in secret.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(char::from(b)),
            b' ' if space_as_plus => out.push('+'),
            _ => {
                out.push('%');
                out.push(char::from(HEX[usize::from(b >> 4)]));
                out.push(char::from(HEX[usize::from(b & 0x0f)]));
            }
        }
    }
    out
}

/// The inside of a JSON string literal, escaped as `serde_json` escapes it:
/// `"` and `\`, the short forms for `\b \f \n \r \t`, `\u00XX` for any other
/// control character below U+0020, everything else verbatim.
fn json_escape(secret: &str) -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Zeroizing::new(String::with_capacity(secret.len() + 8));
    for c in secret.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let b = u32::from(c) as u8;
                out.push_str("\\u00");
                out.push(char::from(HEX[usize::from(b >> 4)]));
                out.push(char::from(HEX[usize::from(b & 0x0f)]));
            }
            c => out.push(c),
        }
    }
    out
}

/// The secret as HTML text or attribute content (`&`, `<`, `>`, `"`, `'`).
fn html_escape(secret: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(secret.len() + 8));
    for c in secret.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            c => out.push(c),
        }
    }
    out
}

/// The recipe's submit target: the origin and path whose POST may carry the
/// real secret, and the body type it must have. The query string is not part
/// of the match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitTarget {
    origin: HttpsOrigin,
    path: String,
    body: BodyType,
}

impl SubmitTarget {
    pub fn new(origin_url: &str, path: &str, body: BodyType) -> Result<Self, String> {
        if !path.starts_with('/') {
            // The path itself stays out of the message: errors can reach an audit
            // line, which names origins only.
            return Err("the submit path is not absolute".to_string());
        }
        Ok(Self { origin: HttpsOrigin::parse(origin_url)?, path: path.to_string(), body })
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
            Self::PlaceholderRepeated => "proxy_submit_placeholder_twice",
            Self::BodyNotUtf8 => "proxy_submit_body_not_utf8",
            Self::BodyTooLarge => "proxy_submit_body_too_large",
        }
    }

    /// The fixed operator-facing text for the window title.
    pub fn notice(self) -> &'static str {
        match self {
            Self::NotPost => "the session proxy did not send the sign-in: it was not a POST",
            Self::UnsupportedBodyType => {
                "the session proxy did not send the sign-in: its body type is not the recipe's submit target's"
            }
            Self::PlaceholderRepeated => "the session proxy did not send the sign-in: the placeholder appeared twice",
            Self::BodyNotUtf8 => "the session proxy did not send the sign-in: its body is not text",
            Self::BodyTooLarge => "the session proxy did not send the sign-in: its body is too large",
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
    // The recipe names the body type; a request that arrives as the other
    // one is not the request the operator configured, so it is refused
    // rather than encoded for whatever the page chose.
    let Some(body_type) = request.content_type.and_then(BodyType::of_content_type).filter(|t| *t == target.body) else {
        return Substitution::Refused(RefuseReason::UnsupportedBodyType);
    };
    if occurrences > 1 {
        return Substitution::Refused(RefuseReason::PlaceholderRepeated);
    }
    if std::str::from_utf8(request.body).is_err() {
        return Substitution::Refused(RefuseReason::BodyNotUtf8);
    }
    let encoded = body_type.encode(&secret.secret);
    Substitution::Substituted(SecretBody::new(replace_all(
        request.body,
        secret.placeholder.as_bytes(),
        encoded.as_bytes(),
    )))
}

/// A scrubbed response body and how many copies of the secret (in any of
/// its encodings) were replaced — a count for the audit line, never the
/// value.
pub struct Scrubbed {
    pub body: Vec<u8>,
    pub replaced: usize,
}

/// Replaces every form of the secret in a response body with the placeholder.
pub fn scrub_response(secret: &SessionSecret, body: &[u8]) -> Scrubbed {
    let mut out = body.to_vec();
    let mut replaced = 0;
    for variant in secret_variants(&secret.secret) {
        replaced += count_occurrences(&out, variant.as_bytes());
        // The previous buffer may hold the secret: it is wiped when this
        // wrapper drops, before the allocation is freed.
        let previous = Zeroizing::new(std::mem::take(&mut out));
        out = replace_all(&previous, variant.as_bytes(), secret.placeholder.as_bytes());
    }
    Scrubbed { body: out, replaced }
}

/// Response headers the proxy strips from every terminated response.
pub fn is_stripped_response_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("alt-svc")
}

/// Every encoding of the secret the scrub looks for, each in a zeroizing
/// buffer, duplicates dropped.
fn secret_variants(secret: &str) -> Vec<Zeroizing<String>> {
    let candidates = [
        Zeroizing::new(secret.to_string()),
        BodyType::Form.encode(secret),
        BodyType::Json.encode(secret),
        html_escape(secret),
        percent_encode(secret, false),
    ];
    let mut variants: Vec<Zeroizing<String>> = Vec::with_capacity(candidates.len());
    // Longest-first is not needed: each variant is a distinct encoding of the
    // same value, and none can contain another as a substring unless equal.
    for v in candidates {
        if !variants.iter().any(|seen| **seen == *v) {
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
        SubmitTarget::new("https://app.example.test", "/login", BodyType::Form).unwrap()
    }

    fn json_target() -> SubmitTarget {
        SubmitTarget::new("https://app.example.test", "/login", BodyType::Json).unwrap()
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
        let out = substitute_submit(&s, &json_target(), &post("/login", Some("application/json"), body.as_bytes()));
        assert_eq!(out, Substitution::Substituted(SecretBody::new(br#"{"password":"q\"u\\o"}"#.to_vec())));
    }

    /// The recipe's `submit_target.body` is part of the rule: a JSON post to a
    /// form target (or the reverse) is refused, never encoded for the type
    /// the page picked.
    #[test]
    fn a_body_of_the_other_type_is_refused() {
        let s = secret("pw");
        let form = format!("password={}", s.placeholder());
        let json = format!(r#"{{"password":"{}"}}"#, s.placeholder());
        let as_json = post("/login", Some("application/json"), json.as_bytes());
        assert_eq!(
            substitute_submit(&s, &target(), &as_json),
            Substitution::Refused(RefuseReason::UnsupportedBodyType)
        );
        let as_form = post("/login", Some("application/x-www-form-urlencoded"), form.as_bytes());
        assert_eq!(
            substitute_submit(&s, &json_target(), &as_form),
            Substitution::Refused(RefuseReason::UnsupportedBodyType)
        );
    }

    /// The zeroizing encoders are written by hand; they must produce exactly
    /// what the crates the page side is compared with produce, or the scrub
    /// would miss an encoding and the substitution would send a different
    /// password.
    #[test]
    fn the_encoders_match_urlencoding_and_serde_json() {
        for s in ["pw", "a b+c&d=e", "é ü 中", "q\"u\\o", "tab\tnl\ncr\r\u{1}\u{7f}", "~-._!*'()/?#[]@", ""] {
            assert_eq!(*percent_encode(s, false), urlencoding::encode(s), "{s:?}");
            assert_eq!(*percent_encode(s, true), urlencoding::encode(s).replace("%20", "+"), "{s:?}");
            let quoted = serde_json::to_string(s).unwrap();
            assert_eq!(*json_escape(s), quoted[1..quoted.len() - 1], "{s:?}");
        }
        assert_eq!(*html_escape("a&<>\"'b"), "a&amp;&lt;&gt;&quot;&#x27;b");
    }

    #[test]
    fn every_check_name_fits_the_abort_vocabulary() {
        for r in [
            RefuseReason::NotPost,
            RefuseReason::UnsupportedBodyType,
            RefuseReason::PlaceholderRepeated,
            RefuseReason::BodyNotUtf8,
            RefuseReason::BodyTooLarge,
        ] {
            let c = r.check();
            assert!(
                (1..=32).contains(&c.len())
                    && c.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{c}"
            );
            assert!(!r.notice().is_empty());
        }
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
        let out = scrub_response(&s, body.as_bytes());
        assert_eq!(out.replaced, 5, "raw twice, form, json and html once each");
        let scrubbed = String::from_utf8(out.body).unwrap();
        assert!(!scrubbed.contains("a&\"<'b"));
        assert!(!scrubbed.contains("a%26%22%3C%27b"));
        assert!(!scrubbed.contains("&quot;&lt;&#x27;b"));
        assert!(scrubbed.contains(s.placeholder()));
    }

    #[test]
    fn scrub_leaves_unrelated_bodies_alone() {
        let s = secret("hunter2-unique");
        let body = b"<html>welcome</html>";
        let out = scrub_response(&s, body);
        assert_eq!((out.body, out.replaced), (body.to_vec(), 0));
    }

    #[test]
    fn alt_svc_is_stripped_case_insensitively() {
        assert!(is_stripped_response_header("Alt-Svc"));
        assert!(!is_stripped_response_header("Set-Cookie"));
    }

    #[test]
    fn submit_target_rejects_relative_path() {
        assert!(SubmitTarget::new("https://app.example.test", "login", BodyType::Form).is_err());
    }
}
