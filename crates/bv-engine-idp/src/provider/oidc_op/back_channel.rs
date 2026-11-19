//! The relying party's back channel on the wire (T546; design in
//! features/identity-provider.md "Back channel"): raw discovery and JWKS,
//! and RFC 6749 §4.1.3 form token requests (`client_secret_basic` or
//! `client_secret_post`) answered per §5.1 / §5.2. Wire format only: the
//! unchanged [`token`](super::token) flow makes every decision, and
//! bv-server's `idp_routes` sends an [`HttpAnswer`] as it is, so the bytes
//! an RP library is tested against here are the bytes the server sends.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use super::TokenRequest;
use crate::errors::RvError;

/// The largest token request body read. A legitimate one is a few hundred
/// bytes; a 2048-character `redirect_uri` percent-encoded in full is ~6 KiB.
pub const TOKEN_BODY_LIMIT: usize = 16 * 1024;

pub const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";
const JSON_CONTENT_TYPE: &str = "application/json";

/// Discovery changes only when an operator edits the OIDC config.
pub const DISCOVERY_CACHE_CONTROL: &str = "public, max-age=3600";
/// `keys/rotate` signs with the new key at once; an RP that does not
/// refetch on an unknown `kid` fails for at most this long.
pub const JWKS_CACHE_CONTROL: &str = "public, max-age=300";

/// What `invalid_client` asks an HTTP Basic client for (RFC 6749 §5.2).
pub const BASIC_CHALLENGE: &str = "Basic realm=\"oidc-token\", charset=\"UTF-8\"";

/// The parameters the token endpoint reads (RFC 6749 §4.1.3, §2.3.1;
/// RFC 7636 §4.5). Any other is ignored (RFC 6749 §3.2).
const PARAMS: [&str; 6] = ["grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier"];

/// A status, headers and body, for the HTTP layer to send as they are.
pub struct HttpAnswer {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Zeroizing<Vec<u8>>,
}

/// How the client authenticated, which decides how `invalid_client` is
/// answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth {
    /// `Authorization: Basic` (`client_secret_basic`).
    Basic,
    /// The body (`client_secret_post`), or no credential at all.
    Post,
}

/// A parsed form token request.
pub struct FormTokenRequest {
    pub request: TokenRequest,
    pub auth: ClientAuth,
}

impl FormTokenRequest {
    /// The body of the logical `oidc/token` write: the fields the JSON API
    /// takes, those present only. The caller zeroizes it after the request.
    pub fn logical_body(&self) -> Map<String, Value> {
        let r = &self.request;
        let fields = [
            ("grant_type", r.grant_type.as_str()),
            ("code", r.code.as_str()),
            ("redirect_uri", r.redirect_uri.as_str()),
            ("client_id", r.client_id.as_str()),
            ("client_secret", r.client_secret.as_str()),
            ("code_verifier", r.code_verifier.as_str()),
        ];
        fields
            .into_iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| (k.to_string(), Value::String(v.to_string())))
            .collect()
    }
}

/// An RFC 6749 §5.2 error response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthError {
    pub status: u16,
    pub error: &'static str,
    pub description: Option<String>,
    /// Answer with `WWW-Authenticate: Basic`: the client tried HTTP Basic.
    pub challenge: bool,
}

impl OAuthError {
    fn new(status: u16, error: &'static str, description: Option<String>) -> Self {
        let description = description.filter(|d| valid_description(d));
        Self { status, error, description, challenge: false }
    }

    pub fn invalid_request(description: &str) -> Self {
        Self::new(400, "invalid_request", Some(description.to_string()))
    }

    /// `401` with a Basic challenge when the client used the Authorization
    /// header, `400` otherwise (RFC 6749 §5.2).
    pub fn invalid_client(auth: ClientAuth, description: Option<String>) -> Self {
        match auth {
            ClientAuth::Basic => Self { challenge: true, ..Self::new(401, "invalid_client", description) },
            ClientAuth::Post => Self::new(400, "invalid_client", description),
        }
    }

    /// A bare `500`: the cause is logged by the caller, never sent.
    pub fn server_error() -> Self {
        Self::new(500, "server_error", None)
    }

    /// `413`, before the body is read or parsed.
    pub fn too_large() -> Self {
        Self::new(413, "invalid_request", Some(format!("the request body is larger than {TOKEN_BODY_LIMIT} bytes")))
    }

    /// The answer for an error from the logical `oidc/token` path (or a
    /// discovery / JWKS read). Only the flow's own `Refusal` codes become
    /// OAuth codes, with their fixed reason as the description; any other
    /// error keeps its status with a bare `invalid_request`/`server_error`.
    pub fn from_flow(err: &RvError, auth: ClientAuth) -> Self {
        if let RvError::ErrResponseStatus(status, text) = err {
            if let Some((code, detail)) = text.split_once(": ") {
                let detail = Some(detail.to_string());
                match code {
                    "invalid_client" => return Self::invalid_client(auth, detail),
                    "invalid_request" => return Self::new(400, "invalid_request", detail),
                    "invalid_grant" => return Self::new(400, "invalid_grant", detail),
                    "unsupported_grant_type" => return Self::new(400, "unsupported_grant_type", detail),
                    "invalid_scope" => return Self::new(400, "invalid_scope", detail),
                    // The gate refused at redemption: the grant was revoked.
                    "access_denied" => return Self::new(400, "invalid_grant", detail),
                    // Not enabled (404) or an internal failure (500).
                    "server_error" => return Self::new(error_status(*status), "server_error", detail),
                    _ => {}
                }
            }
        }
        let status = error_status(match err {
            RvError::ErrResponseStatus(status, _) => *status,
            other => other.response_status(),
        });
        Self::new(status, if status >= 500 { "server_error" } else { "invalid_request" }, None)
    }

    pub fn answer(&self) -> HttpAnswer {
        let mut body = Map::new();
        body.insert("error".into(), self.error.into());
        if let Some(d) = &self.description {
            body.insert("error_description".into(), d.as_str().into());
        }
        let mut headers = no_store_headers();
        if self.challenge {
            headers.push(("www-authenticate", BASIC_CHALLENGE.to_string()));
        }
        HttpAnswer { status: self.status, headers, body: json_body(&body) }
    }
}

/// A 4xx or 5xx status, or 500.
fn error_status(status: u16) -> u16 {
    if (400..=599).contains(&status) {
        status
    } else {
        500
    }
}

/// RFC 6749 §5.2: `error_description` is %x20-21 / %x23-5B / %x5D-7E.
fn valid_description(d: &str) -> bool {
    !d.is_empty() && d.bytes().all(|b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\')
}

fn no_store_headers() -> Vec<(&'static str, String)> {
    vec![
        ("content-type", JSON_CONTENT_TYPE.to_string()),
        ("cache-control", "no-store".to_string()),
        ("pragma", "no-cache".to_string()),
        ("x-content-type-options", "nosniff".to_string()),
    ]
}

fn json_body(m: &Map<String, Value>) -> Zeroizing<Vec<u8>> {
    // A `Map` of strings and numbers always serialises.
    Zeroizing::new(serde_json::to_vec(m).unwrap_or_default())
}

/// Whether `content_type` is `application/x-www-form-urlencoded`, with no
/// charset or UTF-8 (RFC 6749 Appendix B).
fn is_form(content_type: Option<&str>) -> bool {
    let Some(ct) = content_type else { return false };
    let mut parts = ct.split(';');
    if !parts.next().unwrap_or("").trim().eq_ignore_ascii_case(FORM_CONTENT_TYPE) {
        return false;
    }
    parts.all(|p| match p.split_once('=') {
        Some((k, v)) if k.trim().eq_ignore_ascii_case("charset") => {
            v.trim().trim_matches('"').eq_ignore_ascii_case("utf-8")
        }
        _ => true,
    })
}

/// Parse a form token request. In order: content type, size, UTF-8, each
/// known parameter at most once (empty counts as absent), the client
/// credentials (Basic or body, never both), `grant_type`, and for
/// `authorization_code` also `code` and `redirect_uri`. Nothing here reads
/// stored state: the client, secret, code and PKCE are the flow's to judge.
pub fn parse_token_request(
    content_type: Option<&str>,
    authorization: Option<&str>,
    body: &[u8],
) -> Result<FormTokenRequest, OAuthError> {
    if !is_form(content_type) {
        return Err(OAuthError::invalid_request("Content-Type must be application/x-www-form-urlencoded (UTF-8)"));
    }
    if body.len() > TOKEN_BODY_LIMIT {
        return Err(OAuthError::too_large());
    }
    if std::str::from_utf8(body).is_err() {
        return Err(OAuthError::invalid_request("the request body is not UTF-8"));
    }
    let mut seen = [false; PARAMS.len()];
    let mut values: [Option<Zeroizing<String>>; PARAMS.len()] = Default::default();
    for (name, value) in url::form_urlencoded::parse(body) {
        let Some(i) = PARAMS.iter().position(|p| *p == name) else { continue };
        if std::mem::replace(&mut seen[i], true) {
            return Err(OAuthError::invalid_request("a parameter is repeated"));
        }
        let value = Zeroizing::new(value.into_owned());
        if !value.is_empty() {
            values[i] = Some(value);
        }
    }
    let [grant_type, code, redirect_uri, body_client_id, body_secret, code_verifier] = values;

    let (auth, client_id, client_secret) = match authorization {
        Some(header) => {
            let (id, secret) = parse_basic(header)?;
            if body_secret.is_some() {
                return Err(OAuthError::invalid_request("use one client authentication method, not two"));
            }
            if body_client_id.as_deref().is_some_and(|b| b.as_str() != id.as_str()) {
                return Err(OAuthError::invalid_request("client_id does not match the Authorization header"));
            }
            (ClientAuth::Basic, id, secret)
        }
        None => (ClientAuth::Post, body_client_id.unwrap_or_default(), body_secret.unwrap_or_default()),
    };

    let grant_type = grant_type.ok_or_else(|| OAuthError::invalid_request("grant_type is missing"))?;
    if grant_type.as_str() == "authorization_code" {
        if code.is_none() {
            return Err(OAuthError::invalid_request("code is missing"));
        }
        if redirect_uri.is_none() {
            return Err(OAuthError::invalid_request("redirect_uri is missing"));
        }
    }
    Ok(FormTokenRequest {
        request: TokenRequest {
            grant_type: grant_type.to_string(),
            code: code.unwrap_or_default(),
            redirect_uri: redirect_uri.map(|u| u.to_string()).unwrap_or_default(),
            client_id: client_id.to_string(),
            client_secret,
            code_verifier: code_verifier.unwrap_or_default(),
        },
        auth,
    })
}

/// `Authorization: Basic base64(urlencode(id) ":" urlencode(secret))`
/// (RFC 6749 §2.3.1). Any other scheme, or a malformed credential, is a
/// failed client authentication.
fn parse_basic(header: &str) -> Result<(Zeroizing<String>, Zeroizing<String>), OAuthError> {
    let fail = |why: &str| OAuthError::invalid_client(ClientAuth::Basic, Some(why.to_string()));
    let malformed = || fail("malformed Basic credentials");
    let (scheme, credentials) = header.trim().split_once(' ').ok_or_else(|| fail("malformed Authorization header"))?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return Err(fail("only the Basic authorization scheme is supported"));
    }
    let raw = Zeroizing::new(B64.decode(credentials.trim()).map_err(|_| malformed())?);
    let text = std::str::from_utf8(&raw).map_err(|_| malformed())?;
    let (id, secret) = text.split_once(':').ok_or_else(malformed)?;
    let id = form_decode(id).ok_or_else(malformed)?;
    let secret = form_decode(secret).ok_or_else(malformed)?;
    if id.is_empty() || secret.is_empty() {
        return Err(malformed());
    }
    Ok((id, secret))
}

/// Form-urlencoded decoding of one component: `+` is a space, `%XX` a
/// byte, the result UTF-8. A stray `%` is refused, never kept.
fn form_decode(s: &str) -> Option<Zeroizing<String>> {
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let bytes = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let (hi, lo) = (hex(*bytes.get(i + 1)?)?, hex(*bytes.get(i + 2)?)?);
                out.push(hi << 4 | lo);
                i += 2;
            }
            b => out.push(b),
        }
        i += 1;
    }
    let text = std::str::from_utf8(&out).ok()?;
    Some(Zeroizing::new(text.to_string()))
}

/// The RFC 6749 §5.1 success response from the logical `oidc/token` data:
/// exactly `access_token`, `token_type`, `expires_in`, `id_token` and
/// `scope`, never cached.
pub fn token_answer(data: &Map<String, Value>) -> Result<HttpAnswer, OAuthError> {
    let missing = OAuthError::server_error;
    let mut body = Map::new();
    for key in ["access_token", "token_type", "id_token", "scope"] {
        body.insert(key.into(), data.get(key).and_then(Value::as_str).ok_or_else(missing)?.into());
    }
    body.insert("expires_in".into(), data.get("expires_in").and_then(Value::as_u64).ok_or_else(missing)?.into());
    let answer = HttpAnswer { status: 200, headers: no_store_headers(), body: json_body(&body) };
    for v in body.values_mut() {
        if let Value::String(s) = v {
            zeroize::Zeroize::zeroize(s);
        }
    }
    Ok(answer)
}

/// The discovery document or the JWKS as the bare JSON object.
pub fn document_answer(data: &Map<String, Value>, cache_control: &'static str) -> HttpAnswer {
    HttpAnswer {
        status: 200,
        headers: vec![
            ("content-type", JSON_CONTENT_TYPE.to_string()),
            ("cache-control", cache_control.to_string()),
            ("x-content-type-options", "nosniff".to_string()),
        ],
        body: json_body(data),
    }
}

#[cfg(test)]
mod tests {
    //! The wire format alone; the flow behind it, with an RP library over
    //! these answers, is `oidc_op::tests::back_channel`.

    use super::*;
    use crate::provider::oidc_op::Refusal;

    const FORM: Option<&str> = Some(FORM_CONTENT_TYPE);
    const BODY: &str = "grant_type=authorization_code&code=c0de&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb\
                        &client_id=app&client_secret=s3cret&code_verifier=v";

    fn basic(id: &str, secret: &str) -> String {
        format!("Basic {}", B64.encode(format!("{id}:{secret}")))
    }

    fn refused(ct: Option<&str>, auth: Option<&str>, body: &str) -> OAuthError {
        match parse_token_request(ct, auth, body.as_bytes()) {
            Ok(_) => panic!("accepted {body:?}"),
            Err(e) => e,
        }
    }

    fn without(name: &str) -> String {
        BODY.split('&').filter(|p| !p.starts_with(&format!("{name}="))).collect::<Vec<_>>().join("&")
    }

    fn without_client() -> String {
        BODY.split('&').filter(|p| !p.starts_with("client_")).collect::<Vec<_>>().join("&")
    }

    #[test]
    fn a_post_request_parses_into_the_flow_request() {
        let form = parse_token_request(FORM, None, BODY.as_bytes()).unwrap();
        assert_eq!(form.auth, ClientAuth::Post);
        let r = &form.request;
        assert_eq!((r.grant_type.as_str(), r.code.as_str()), ("authorization_code", "c0de"));
        assert_eq!(r.redirect_uri, "https://app.example.com/cb");
        assert_eq!((r.client_id.as_str(), r.client_secret.as_str()), ("app", "s3cret"));
        assert_eq!(r.code_verifier.as_str(), "v");
        let body = form.logical_body();
        assert_eq!(body.len(), 6);
        assert_eq!(body["client_secret"], "s3cret");
    }

    #[test]
    fn content_type_must_be_a_utf8_form() {
        for ct in [
            None,
            Some("application/json"),
            Some("text/plain"),
            Some("multipart/form-data; boundary=x"),
            Some("application/x-www-form-urlencoded; charset=ISO-8859-1"),
            Some("application/x-www-form-urlencodedx"),
        ] {
            let e = refused(ct, None, BODY);
            assert_eq!((e.status, e.error), (400, "invalid_request"), "{ct:?}");
        }
        for ct in [
            "application/x-www-form-urlencoded",
            "Application/X-WWW-Form-Urlencoded",
            "application/x-www-form-urlencoded; charset=UTF-8",
            "application/x-www-form-urlencoded;charset=\"utf-8\"",
        ] {
            assert!(parse_token_request(Some(ct), None, BODY.as_bytes()).is_ok(), "{ct}");
        }
    }

    #[test]
    fn oversized_and_non_utf8_bodies_are_refused() {
        let big = format!("{BODY}&pad={}", "a".repeat(TOKEN_BODY_LIMIT));
        let e = refused(FORM, None, &big);
        assert_eq!((e.status, e.error), (413, "invalid_request"));
        let e = parse_token_request(FORM, None, b"grant_type=authorization_code&code=\xff").err().unwrap();
        assert_eq!((e.status, e.error), (400, "invalid_request"));
    }

    #[test]
    fn a_repeated_parameter_is_refused_even_encoded_or_empty() {
        for extra in ["&code=other", "&client%5Fid=other", "&code_verifier=", "&grant_type=authorization_code"] {
            let e = refused(FORM, None, &format!("{BODY}{extra}"));
            assert_eq!((e.status, e.error), (400, "invalid_request"), "{extra}");
            assert_eq!(e.description.as_deref(), Some("a parameter is repeated"));
        }
        // Unknown parameters are ignored, repeated or not (RFC 6749 §3.2).
        assert!(parse_token_request(FORM, None, format!("{BODY}&scope=a&scope=b&x").as_bytes()).is_ok());
    }

    #[test]
    fn missing_parameters_are_invalid_request_and_empty_counts_as_missing() {
        for name in ["grant_type", "code", "redirect_uri"] {
            let e = refused(FORM, None, &without(name));
            assert_eq!((e.status, e.error), (400, "invalid_request"), "{name}");
            assert_eq!(e.description, Some(format!("{name} is missing")));
            let e = refused(FORM, None, &format!("{}&{name}=", without(name)));
            assert_eq!(e.description, Some(format!("{name} is missing")), "empty {name}");
        }
        // Client credentials and the verifier are the flow's to refuse
        // (invalid_client, and invalid_grant per RFC 7636 §4.6).
        for name in ["client_id", "client_secret", "code_verifier"] {
            let form = parse_token_request(FORM, None, without(name).as_bytes()).unwrap();
            assert!(!form.logical_body().contains_key(name), "{name}");
        }
        // Another grant type reaches the flow, which answers unsupported_grant_type.
        let form = parse_token_request(FORM, None, b"grant_type=refresh_token&refresh_token=x").unwrap();
        assert_eq!(form.request.grant_type, "refresh_token");
    }

    #[test]
    fn basic_credentials_are_form_decoded_and_exclusive() {
        let body = format!("{}&client_id=app", without_client());
        let form = parse_token_request(FORM, Some(&basic("app", "s3cret")), body.as_bytes()).unwrap();
        assert_eq!(form.auth, ClientAuth::Basic);
        assert_eq!((form.request.client_id.as_str(), form.request.client_secret.as_str()), ("app", "s3cret"));
        // RFC 6749 §2.3.1: both halves are form-urlencoded first.
        let form =
            parse_token_request(FORM, Some(&basic("my%3Aapp", "a+b%2Bc%25")), without_client().as_bytes()).unwrap();
        assert_eq!((form.request.client_id.as_str(), form.request.client_secret.as_str()), ("my:app", "a b+c%"));
        let lower = basic("app", "s").replace("Basic", "basic");
        assert!(parse_token_request(FORM, Some(&lower), body.as_bytes()).is_ok());

        // Both methods at once, or another client id in the body.
        let e = refused(FORM, Some(&basic("app", "s3cret")), BODY);
        assert_eq!((e.status, e.error, e.challenge), (400, "invalid_request", false));
        let e = refused(FORM, Some(&basic("other", "s3cret")), &body);
        assert_eq!((e.status, e.error), (400, "invalid_request"));
    }

    #[test]
    fn malformed_basic_or_another_scheme_is_invalid_client_with_a_challenge() {
        let body = without_client();
        let bad = [
            "Bearer abc".to_string(),
            "Basic".to_string(),
            "Basic !!!".to_string(),
            format!("Basic {}", B64.encode("no-colon")),
            format!("Basic {}", B64.encode(b"app:\xff")),
            basic("app", ""),
            basic("", "s3cret"),
            basic("app", "50%"),
            basic("app", "%zz"),
            String::new(),
        ];
        for header in bad {
            let e = refused(FORM, Some(&header), &body);
            assert_eq!((e.status, e.error, e.challenge), (401, "invalid_client", true), "{header:?}");
            assert!(e.answer().headers.contains(&("www-authenticate", BASIC_CHALLENGE.to_string())));
        }
    }

    #[test]
    fn flow_refusals_map_to_rfc6749_errors() {
        use crate::entitlement::gate::DenyReason;

        let cases = [
            (Refusal::InvalidClient, ClientAuth::Post, 400, "invalid_client", false),
            (Refusal::InvalidClient, ClientAuth::Basic, 401, "invalid_client", true),
            (Refusal::UnsupportedGrantType, ClientAuth::Post, 400, "unsupported_grant_type", false),
            (Refusal::InvalidGrant("unknown_or_used_code"), ClientAuth::Basic, 400, "invalid_grant", false),
            (Refusal::InvalidGrant("pkce_verification_failed"), ClientAuth::Post, 400, "invalid_grant", false),
            (Refusal::InvalidRequest("x"), ClientAuth::Post, 400, "invalid_request", false),
            (Refusal::InvalidScope, ClientAuth::Post, 400, "invalid_scope", false),
            (Refusal::Denied(DenyReason::IdentityDisabled), ClientAuth::Post, 400, "invalid_grant", false),
            (Refusal::NotEnabled, ClientAuth::Post, 404, "server_error", false),
            (Refusal::Internal, ClientAuth::Basic, 500, "server_error", false),
        ];
        for (refusal, auth, status, error, challenge) in cases {
            let e = OAuthError::from_flow(&RvError::from(refusal), auth);
            assert_eq!((e.status, e.error, e.challenge), (status, error, challenge), "{refusal:?}");
            let RvError::ErrResponseStatus(_, text) = RvError::from(refusal) else { unreachable!() };
            assert_eq!(e.description.as_deref(), text.split_once(": ").map(|(_, d)| d), "{refusal:?}");
        }
        // Anything else keeps its status and says nothing more.
        let other =
            OAuthError::from_flow(&RvError::ErrResponseStatus(403, "permission denied".into()), ClientAuth::Post);
        assert_eq!((other.status, other.error, other.description), (403, "invalid_request", None));
        let sealed = OAuthError::from_flow(&RvError::ErrBarrierSealed, ClientAuth::Post);
        assert_eq!((sealed.error, sealed.description), ("server_error", None));
        assert!(sealed.status >= 500);
        let quoted =
            OAuthError::from_flow(&RvError::ErrResponseStatus(400, "invalid_grant: a \"b\"".into()), ClientAuth::Post);
        assert_eq!(quoted.description, None, "a description outside RFC 6749's charset is dropped");
    }

    #[test]
    fn answers_are_json_and_never_cached() {
        let e = OAuthError::invalid_request("code is missing").answer();
        assert_eq!(e.status, 400);
        let body: Value = serde_json::from_slice(&e.body).unwrap();
        assert_eq!(body, serde_json::json!({"error": "invalid_request", "error_description": "code is missing"}));
        for h in [("content-type", "application/json"), ("cache-control", "no-store"), ("pragma", "no-cache")] {
            assert!(e.headers.contains(&(h.0, h.1.to_string())), "{h:?}");
        }
        assert!(!e.headers.iter().any(|(n, _)| *n == "www-authenticate"));

        let data: Map<String, Value> = serde_json::from_value(serde_json::json!({
            "access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": "it",
            "scope": "openid", "extra": "not passed on"
        }))
        .unwrap();
        let ok = token_answer(&data).unwrap();
        assert_eq!(ok.status, 200);
        assert!(ok.headers.contains(&("cache-control", "no-store".to_string())));
        assert!(ok.headers.contains(&("pragma", "no-cache".to_string())));
        let body: Value = serde_json::from_slice(&ok.body).unwrap();
        let want = serde_json::json!({"access_token": "at", "token_type": "Bearer", "expires_in": 300,
            "id_token": "it", "scope": "openid"});
        assert_eq!(body, want);
        let missing = token_answer(&Map::new()).err().unwrap();
        assert_eq!((missing.status, missing.error), (500, "server_error"));

        let doc = document_answer(&data, DISCOVERY_CACHE_CONTROL);
        assert!(doc.headers.contains(&("cache-control", DISCOVERY_CACHE_CONTROL.to_string())));
        assert_eq!(serde_json::from_slice::<Value>(&doc.body).unwrap(), Value::Object(data));
    }
}
