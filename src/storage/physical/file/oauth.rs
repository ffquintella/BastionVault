//! OAuth 2.0 Authorization Code + PKCE helper infrastructure — the
//! shared foundation for the consumer-drive `FileTarget`s (OneDrive,
//! Google Drive, Dropbox in Phases 4–6).
//!
//! What this module does:
//!
//!   1. Generate RFC 7636-compliant PKCE code verifier + challenge.
//!   2. Build the provider-specific authorization URL.
//!   3. Spin up a loopback HTTP listener on `127.0.0.1:<random port>`
//!      to receive the `GET /callback?code=...&state=...` redirect.
//!   4. Exchange the authorization code for `{access, refresh}` tokens
//!      by POSTing to the provider's token endpoint.
//!   5. Refresh an access token using a stored refresh token.
//!
//! What this module does **not** do:
//!
//!   * Open the user's browser — the caller decides what to do with
//!     the consent URL. A CLI prints it + shells out to `open` /
//!     `xdg-open` / `rundll32`; the GUI hands it off to Tauri's
//!     `shell.open`. This keeps the module testable (no system
//!     interaction) and portable (no per-OS browser-launch code).
//!   * Persist tokens. The `credentials_ref` resolver already owns
//!     that story; callers write the returned refresh token wherever
//!     their configured `credentials_ref` points.
//!   * Ship any client secrets. Public-client OAuth is assumed; the
//!     spec explicitly forbids redistributing consumer-provider
//!     client secrets in a signed binary.
//!
//! HTTP: reuses the existing `ureq` dep (same one `S3Target` uses)
//! so no new transitive-dep surface is added for this phase.
//!
//! All public functions are synchronous. Async consumers invoke via
//! `tokio::task::spawn_blocking`, matching the pattern already in
//! place for the S3 target.

use std::{
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    time::Duration,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::Rng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

use crate::errors::RvError;

/// Per-provider endpoints + scope configuration. Instances are
/// built once per target kind (OneDrive / Google Drive / Dropbox)
/// and shared across consent + refresh flows.
#[derive(Debug, Clone)]
pub struct OAuthProvider {
    /// Full URL of the authorization endpoint (where the browser
    /// sends the user for consent).
    pub authorization_url: String,
    /// Full URL of the token endpoint (where we exchange codes and
    /// refresh tokens for access tokens).
    pub token_url: String,
    /// OAuth scopes to request. Joined with a single space.
    pub scopes: Vec<String>,
    /// Extra provider-specific query params added to the
    /// authorization URL (e.g. `prompt=consent` for Google,
    /// `token_access_type=offline` for Dropbox).
    pub extra_auth_params: Vec<(String, String)>,
}

/// Caller-supplied client identity. `client_secret` is optional:
/// public clients (the common shape for a distributed desktop app)
/// rely on PKCE + client_id only. Server-style clients that have a
/// secret pass it here and the module sends it on every token
/// request.
#[derive(Debug, Clone)]
pub struct OAuthCredentials {
    pub client_id: String,
    pub client_secret: Option<String>,
}

/// The shape the three target providers all return on successful
/// `authorization_code` and `refresh_token` grants.
///
/// `refresh_token` is `None` on refresh-grant responses when the
/// provider opted not to rotate it (all three consumer drives do
/// this sometimes). Callers should keep their stored refresh token
/// unchanged in that case.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// The callback params pulled out of the redirect. `state` is what
/// we sent in the authorization URL; callers compare it against
/// their expected value to foil CSRF.
#[derive(Debug, Clone)]
pub struct CallbackParams {
    pub code: String,
    pub state: String,
}

/// Return the `OAuthProvider` config for a well-known consumer
/// drive. Keeps the CLI / GUI from hard-coding per-provider URLs
/// and scopes in multiple places, and provides one obvious place
/// to update when a provider changes its endpoints.
///
/// Scopes are the narrowest available per the design doc's security
/// considerations: app-folder / app-data for every consumer drive.
pub fn well_known_provider(name: &str) -> Result<OAuthProvider, RvError> {
    match name {
        "onedrive" => Ok(OAuthProvider {
            // Microsoft v2 endpoint. `common` accepts both work and
            // personal accounts; operators who want to restrict to a
            // specific tenant build their own `OAuthProvider`.
            authorization_url:
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".into(),
            token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token".into(),
            scopes: vec!["Files.ReadWrite.AppFolder".into(), "offline_access".into()],
            extra_auth_params: vec![],
        }),
        "gdrive" => Ok(OAuthProvider {
            authorization_url: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            token_url: "https://oauth2.googleapis.com/token".into(),
            scopes: vec!["https://www.googleapis.com/auth/drive.appdata".into()],
            // `access_type=offline` is how Google returns a
            // refresh token; `prompt=consent` forces a fresh one
            // on reconnect (otherwise Google sometimes withholds
            // it on repeat consents).
            extra_auth_params: vec![
                ("access_type".into(), "offline".into()),
                ("prompt".into(), "consent".into()),
            ],
        }),
        "dropbox" => Ok(OAuthProvider {
            authorization_url: "https://www.dropbox.com/oauth2/authorize".into(),
            token_url: "https://api.dropboxapi.com/oauth2/token".into(),
            // Dropbox App Folder scope is baked into the app's type
            // at developer-console registration time, so the scope
            // list here is empty; `token_access_type=offline` is
            // what turns on refresh-token issuance.
            scopes: vec![],
            extra_auth_params: vec![("token_access_type".into(), "offline".into())],
        }),
        other => Err(RvError::ErrString(format!(
            "oauth: unknown provider `{other}` (expected `onedrive` / `gdrive` / `dropbox`)"
        ))),
    }
}

// ── PKCE helpers ──────────────────────────────────────────────────

/// Generate a URL-safe base64 PKCE code verifier. RFC 7636 allows
/// 43..=128 characters; we pick 96 (matches Google / Microsoft /
/// Dropbox examples and leaves no ambiguity about the length).
pub fn pkce_verifier() -> String {
    let mut bytes = [0u8; 72]; // 72 bytes → 96 base64url chars
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// PKCE S256 challenge = BASE64URL(SHA256(verifier)).
pub fn pkce_challenge(verifier: &str) -> String {
    let mut h = Sha256::new();
    h.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(h.finalize())
}

/// Per-flow random state value — 128 bits, base64url-encoded.
pub fn random_state() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

// ── URL composition ───────────────────────────────────────────────

/// Build the authorization URL the user's browser is sent to for
/// consent. Carries `client_id`, `redirect_uri`, `scope`, `state`,
/// `code_challenge` (S256), `response_type=code`, plus whatever the
/// provider's `extra_auth_params` adds on top.
pub fn build_authorization_url(
    provider: &OAuthProvider,
    creds: &OAuthCredentials,
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
) -> Result<Url, RvError> {
    let mut url = Url::parse(&provider.authorization_url)
        .map_err(|e| RvError::ErrString(format!("oauth: bad authorization_url: {e}")))?;
    let scope = provider.scopes.join(" ");
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("client_id", &creds.client_id);
        q.append_pair("response_type", "code");
        q.append_pair("redirect_uri", redirect_uri);
        q.append_pair("scope", &scope);
        q.append_pair("state", state);
        q.append_pair("code_challenge", code_challenge);
        q.append_pair("code_challenge_method", "S256");
        for (k, v) in &provider.extra_auth_params {
            q.append_pair(k, v);
        }
    }
    Ok(url)
}

// ── Callback listener ─────────────────────────────────────────────

/// Handle to the active consent session. Holds the bound loopback
/// listener so the port stays reserved between `build` and
/// `wait_for_callback`.
pub struct ConsentSession {
    pub consent_url: Url,
    pub verifier: String,
    pub state: String,
    pub redirect_uri: String,
    listener: TcpListener,
}

/// Default fixed loopback port for the OAuth consent callback.
///
/// Why fixed: OAuth providers require the redirect URI to exactly
/// match a pre-registered value. Google and Microsoft special-case
/// loopback URIs per RFC 8252 § 7.3 (any port works once you
/// register `http://127.0.0.1` / `http://localhost`), but Dropbox
/// doesn't — the registered URI must include the exact port. An
/// ephemeral OS-assigned port (`port 0`) means the user would have
/// to re-register their app every launch, which is unusable.
///
/// A single fixed port means the user registers the redirect URI
/// once at the provider's dev console and every subsequent consent
/// flow uses the same URL. Port collisions surface as a clear
/// error at `begin_consent` time rather than silently degrading.
///
/// 8472 was picked because it's well outside the reserved + common
/// app ranges and doesn't clash with BastionVault's own reserved
/// ports (8200 Vault server, 8210 Raft, 8220 Raft API).
pub const DEFAULT_LOOPBACK_PORT: u16 = 8472;

/// Start a consent session: bind a loopback port, compose the
/// authorization URL, return a handle the caller uses to (a) open
/// the URL in a browser and (b) wait for the callback.
///
/// `bind_host` is typically `"127.0.0.1"`. Callers that need IPv6
/// can pass `"[::1]"`; both OAuth providers and `open` /
/// `xdg-open` handle either cleanly.
///
/// `preferred_port` is the port to try first. Pass `Some(n)` for
/// a stable redirect URI the user can register at the provider
/// once; pass `None` for an OS-assigned ephemeral port (useful in
/// tests). On collision with a fixed port we surface a clear error
/// rather than silently falling back, so the user knows the
/// registered redirect URI won't match.
pub fn begin_consent(
    provider: &OAuthProvider,
    creds: &OAuthCredentials,
    bind_host: &str,
    preferred_port: Option<u16>,
) -> Result<ConsentSession, RvError> {
    let listener = match preferred_port {
        Some(p) => TcpListener::bind((bind_host, p)).map_err(|e| {
            RvError::ErrString(format!(
                "oauth: bind {bind_host}:{p}: {e}. This port needs to stay free \
                 for the consent callback — close whichever process is holding \
                 it (you can check with `netstat -ano | findstr {p}` on Windows \
                 or `lsof -i :{p}` on Unix) and try again."
            ))
        })?,
        None => TcpListener::bind((bind_host, 0))
            .map_err(|e| RvError::ErrString(format!("oauth: bind loopback: {e}")))?,
    };
    let port = listener
        .local_addr()
        .map_err(|e| RvError::ErrString(format!("oauth: local_addr: {e}")))?
        .port();
    let redirect_uri = format!("http://{bind_host}:{port}/callback");

    let verifier = pkce_verifier();
    let challenge = pkce_challenge(&verifier);
    let state = random_state();
    let consent_url = build_authorization_url(provider, creds, &redirect_uri, &state, &challenge)?;

    Ok(ConsentSession {
        consent_url,
        verifier,
        state,
        redirect_uri,
        listener,
    })
}

impl ConsentSession {
    /// Block until the browser hits `GET /callback?...`. The
    /// returned `CallbackParams` carry the provider-supplied code
    /// and the state we sent; callers must compare state against
    /// `self.state` before trusting the code (this method *does*
    /// do that comparison and errors on mismatch).
    ///
    /// A timeout guards against a user who closes the browser tab
    /// without completing consent. The default `Duration` suggested
    /// by this module is 5 minutes.
    pub fn wait_for_callback(self, timeout: Duration) -> Result<CallbackParams, RvError> {
        self.listener
            .set_nonblocking(false)
            .map_err(|e| RvError::ErrString(format!("oauth: set blocking: {e}")))?;

        // Poll-style accept with a small sleep so the overall
        // timeout is honoured without requiring tokio or async.
        let deadline = std::time::Instant::now() + timeout;
        self.listener
            .set_nonblocking(true)
            .map_err(|e| RvError::ErrString(format!("oauth: set nonblocking: {e}")))?;

        loop {
            if std::time::Instant::now() > deadline {
                return Err(RvError::ErrString(
                    "oauth: consent flow timed out waiting for browser callback".into(),
                ));
            }
            match self.listener.accept() {
                Ok((stream, _addr)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(10)))
                        .ok();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(10)))
                        .ok();
                    return Self::handle_callback(stream, &self.state);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    return Err(RvError::ErrString(format!("oauth: accept: {e}")));
                }
            }
        }
    }

    fn handle_callback(mut stream: TcpStream, expected_state: &str) -> Result<CallbackParams, RvError> {
        // Read the request line + headers. We only need the request
        // line (the query string carries the params); slurping the
        // header block through the first blank line is enough.
        let mut reader = BufReader::new(&mut stream);
        let mut request_line = String::new();
        reader
            .read_line(&mut request_line)
            .map_err(|e| RvError::ErrString(format!("oauth: read request: {e}")))?;
        // Drain the rest of the header block so the peer doesn't
        // get ECONNRESET when we start writing the response.
        loop {
            let mut line = String::new();
            let n = reader
                .read_line(&mut line)
                .map_err(|e| RvError::ErrString(format!("oauth: read headers: {e}")))?;
            if n == 0 || line == "\r\n" || line == "\n" {
                break;
            }
        }

        let params = parse_request_line(&request_line)?;
        // Send a minimal success page before we validate state, so
        // the user always sees a friendly message even if we then
        // error on state mismatch. The err is surfaced to the
        // caller, not the browser.
        let _ = respond_ok(&mut stream);

        if params.state != expected_state {
            return Err(RvError::ErrString(
                "oauth: callback state mismatch — possible CSRF, aborting".into(),
            ));
        }
        Ok(params)
    }
}

/// Parse `GET /callback?code=...&state=... HTTP/1.1` into the
/// `code` and `state` values. Returns a clear error when the
/// request shape is unexpected or the query lacks one of the two
/// required params.
fn parse_request_line(line: &str) -> Result<CallbackParams, RvError> {
    let trimmed = line.trim_end_matches(&['\r', '\n']);
    let mut it = trimmed.splitn(3, ' ');
    let method = it
        .next()
        .ok_or_else(|| RvError::ErrString("oauth: empty request line".into()))?;
    let path_and_query = it
        .next()
        .ok_or_else(|| RvError::ErrString("oauth: malformed request line".into()))?;
    if method != "GET" {
        return Err(RvError::ErrString(format!(
            "oauth: expected GET, got {method}"
        )));
    }
    // The path is relative; construct an absolute URL just to use
    // `url`'s query parser. The host part is arbitrary.
    let absolute = format!("http://loopback{path_and_query}");
    let parsed = Url::parse(&absolute)
        .map_err(|e| RvError::ErrString(format!("oauth: bad callback path: {e}")))?;

    // Surface provider-sent errors rather than silently ignoring them.
    let mut code: Option<String> = None;
    let mut state: Option<String> = None;
    let mut err_param: Option<String> = None;
    let mut err_description: Option<String> = None;
    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            "error" => err_param = Some(v.into_owned()),
            "error_description" => err_description = Some(v.into_owned()),
            _ => {}
        }
    }

    if let Some(e) = err_param {
        let desc = err_description.unwrap_or_default();
        return Err(RvError::ErrString(format!(
            "oauth: provider returned error `{e}`: {desc}"
        )));
    }

    let code = code.ok_or_else(|| RvError::ErrString("oauth: callback missing `code`".into()))?;
    let state = state.ok_or_else(|| RvError::ErrString("oauth: callback missing `state`".into()))?;
    Ok(CallbackParams { code, state })
}

fn respond_ok(stream: &mut TcpStream) -> std::io::Result<()> {
    let body = "<!doctype html><html><head><meta charset=\"utf-8\"><title>BastionVault</title>\
<style>body{font-family:sans-serif;text-align:center;padding:3em;color:#333}</style></head>\
<body><h1>\u{2713} Connected</h1><p>You can close this window and return to BastionVault.</p></body></html>";
    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
        body = body,
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()?;
    Ok(())
}

// ── Token exchange ────────────────────────────────────────────────

/// Exchange an authorization code for an access + refresh token.
/// Runs against the provider's `token_url` with a form-encoded
/// POST per RFC 6749 §4.1.3.
pub fn exchange_code(
    provider: &OAuthProvider,
    creds: &OAuthCredentials,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<TokenResponse, RvError> {
    let mut form: Vec<(&str, String)> = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("redirect_uri", redirect_uri.to_string()),
        ("client_id", creds.client_id.clone()),
        ("code_verifier", verifier.to_string()),
    ];
    if let Some(secret) = &creds.client_secret {
        form.push(("client_secret", secret.clone()));
    }
    post_token_endpoint(&provider.token_url, &form)
}

/// Refresh an access token using a stored refresh token.
pub fn refresh_access_token(
    provider: &OAuthProvider,
    creds: &OAuthCredentials,
    refresh_token: &str,
) -> Result<TokenResponse, RvError> {
    let mut form: Vec<(&str, String)> = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token.to_string()),
        ("client_id", creds.client_id.clone()),
    ];
    if let Some(secret) = &creds.client_secret {
        form.push(("client_secret", secret.clone()));
    }
    // Some providers (Google) reject scope on refresh grants;
    // others (Microsoft) allow but don't require it. We omit scope
    // on refresh — matches the most broadly compatible behaviour.
    post_token_endpoint(&provider.token_url, &form)
}

fn post_token_endpoint(url: &str, form: &[(&str, String)]) -> Result<TokenResponse, RvError> {
    let agent: ureq::Agent = ureq::config::Config::builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .http_status_as_error(false)
        .build()
        .into();
    let form_pairs: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let resp = agent
        .post(url)
        .send_form(form_pairs)
        .map_err(|e| RvError::ErrString(format!("oauth: token endpoint transport: {e}")))?;
    let status = resp.status().as_u16();
    let body = resp
        .into_body()
        .read_to_string()
        .map_err(|e| RvError::ErrString(format!("oauth: token endpoint body: {e}")))?;
    if !(200..300).contains(&status) {
        return Err(RvError::ErrString(format!(
            "oauth: token endpoint returned {status}: {body}"
        )));
    }
    let parsed: TokenResponse = serde_json::from_str(&body).map_err(|e| {
        RvError::ErrString(format!("oauth: token response parse: {e}; body={body}"))
    })?;
    Ok(parsed)
}

// ── Loopback addr helper ──────────────────────────────────────────

/// Return a `SocketAddr` pointing at the session's bound loopback
/// port. Used by callers that want to log or display the listener's
/// endpoint (e.g. the CLI printing "Waiting for browser on :54231").
impl ConsentSession {
    #[allow(dead_code)]
    pub fn listener_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_verifier_length_and_charset() {
        let v = pkce_verifier();
        // 72 random bytes → 96 base64url chars (RFC 7636-compliant:
        // must be 43..=128 chars and match [A-Z a-z 0-9 - . _ ~]).
        assert_eq!(v.len(), 96);
        for c in v.chars() {
            assert!(
                c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~'),
                "bad char {c:?}"
            );
        }
    }

    #[test]
    fn pkce_challenge_matches_rfc7636_test_vector() {
        // RFC 7636 Appendix B test vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = pkce_challenge(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn build_authorization_url_has_all_required_params() {
        let provider = OAuthProvider {
            authorization_url: "https://example.com/oauth/authorize".to_string(),
            token_url: "https://example.com/oauth/token".to_string(),
            scopes: vec!["files.read".to_string(), "files.write".to_string()],
            extra_auth_params: vec![("prompt".into(), "consent".into())],
        };
        let creds = OAuthCredentials {
            client_id: "my-client".into(),
            client_secret: None,
        };
        let url = build_authorization_url(
            &provider,
            &creds,
            "http://127.0.0.1:54231/callback",
            "st8",
            "cc",
        )
        .unwrap();
        let q: std::collections::HashMap<String, String> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(q.get("client_id").unwrap(), "my-client");
        assert_eq!(q.get("response_type").unwrap(), "code");
        assert_eq!(
            q.get("redirect_uri").unwrap(),
            "http://127.0.0.1:54231/callback"
        );
        assert_eq!(q.get("scope").unwrap(), "files.read files.write");
        assert_eq!(q.get("state").unwrap(), "st8");
        assert_eq!(q.get("code_challenge").unwrap(), "cc");
        assert_eq!(q.get("code_challenge_method").unwrap(), "S256");
        assert_eq!(q.get("prompt").unwrap(), "consent");
    }

    #[test]
    fn parse_request_line_extracts_code_and_state() {
        let params = parse_request_line("GET /callback?code=abc123&state=xyz HTTP/1.1\r\n").unwrap();
        assert_eq!(params.code, "abc123");
        assert_eq!(params.state, "xyz");
    }

    #[test]
    fn parse_request_line_url_decodes() {
        let params = parse_request_line(
            "GET /callback?code=a%2Bb%2Fc%3Dd&state=x%20y HTTP/1.1\r\n",
        )
        .unwrap();
        assert_eq!(params.code, "a+b/c=d");
        assert_eq!(params.state, "x y");
    }

    #[test]
    fn parse_request_line_surfaces_provider_error() {
        let err = parse_request_line(
            "GET /callback?error=access_denied&error_description=user%20cancelled HTTP/1.1\r\n",
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("access_denied"), "got: {msg}");
        assert!(msg.contains("user cancelled"), "got: {msg}");
    }

    #[test]
    fn parse_request_line_requires_get() {
        let err = parse_request_line("POST /callback?code=a&state=b HTTP/1.1\r\n").unwrap_err();
        assert!(format!("{err}").contains("expected GET"));
    }

    #[test]
    fn parse_request_line_requires_code() {
        let err = parse_request_line("GET /callback?state=x HTTP/1.1\r\n").unwrap_err();
        assert!(format!("{err}").contains("missing `code`"));
    }

    #[test]
    fn parse_request_line_requires_state() {
        let err = parse_request_line("GET /callback?code=a HTTP/1.1\r\n").unwrap_err();
        assert!(format!("{err}").contains("missing `state`"));
    }

    #[test]
    fn token_response_deserializes_minimal_body() {
        let body = r#"{"access_token":"AT","token_type":"Bearer"}"#;
        let tr: TokenResponse = serde_json::from_str(body).unwrap();
        assert_eq!(tr.access_token, "AT");
        assert!(tr.refresh_token.is_none());
        assert!(tr.expires_in.is_none());
    }

    #[test]
    fn token_response_deserializes_full_body() {
        let body = r#"{
            "access_token":"AT",
            "refresh_token":"RT",
            "expires_in":3600,
            "token_type":"Bearer",
            "scope":"files.read files.write"
        }"#;
        let tr: TokenResponse = serde_json::from_str(body).unwrap();
        assert_eq!(tr.access_token, "AT");
        assert_eq!(tr.refresh_token.as_deref(), Some("RT"));
        assert_eq!(tr.expires_in, Some(3600));
        assert_eq!(tr.scope.as_deref(), Some("files.read files.write"));
    }

    /// End-to-end in-process test. Starts a consent session (which
    /// binds a real loopback port), then on a worker thread we
    /// synthesize the browser: fetch the callback URL with ureq and
    /// verify `wait_for_callback` returns the right code.
    ///
    /// This exercises the real TCP accept + HTTP parse path without
    /// touching any network or any external provider.
    #[test]
    fn consent_session_roundtrip_in_process() {
        let provider = OAuthProvider {
            authorization_url: "https://example.com/authorize".into(),
            token_url: "https://example.com/token".into(),
            scopes: vec!["s".into()],
            extra_auth_params: vec![],
        };
        let creds = OAuthCredentials {
            client_id: "c".into(),
            client_secret: None,
        };
        // Tests pass `None` so each test gets an ephemeral port
        // — the fixed `DEFAULT_LOOPBACK_PORT` would race if two
        // tests ran in parallel against the same machine.
        let session = begin_consent(&provider, &creds, "127.0.0.1", None).unwrap();
        let port = session.listener_addr().unwrap().port();
        let state_expected = session.state.clone();
        let state_for_worker = session.state.clone();

        // Drive the "browser" in another thread so the main thread
        // can block on `wait_for_callback`.
        let handle = std::thread::spawn(move || {
            // Tiny delay to make sure the listener has switched to
            // non-blocking and is polling. Even without this, the
            // accept loop would pick up a slightly-early connect.
            std::thread::sleep(Duration::from_millis(50));
            let url = format!(
                "http://127.0.0.1:{port}/callback?code=the-code&state={}",
                urlencoding(&state_for_worker)
            );
            let agent: ureq::Agent = ureq::config::Config::builder()
                .http_status_as_error(false)
                .build()
                .into();
            let resp = agent.get(&url).call().expect("callback GET");
            assert_eq!(resp.status().as_u16(), 200);
        });

        let params = session
            .wait_for_callback(Duration::from_secs(5))
            .expect("callback received");
        handle.join().expect("worker");
        assert_eq!(params.code, "the-code");
        assert_eq!(params.state, state_expected);
    }

    #[test]
    fn consent_session_rejects_state_mismatch() {
        let provider = OAuthProvider {
            authorization_url: "https://example.com/authorize".into(),
            token_url: "https://example.com/token".into(),
            scopes: vec!["s".into()],
            extra_auth_params: vec![],
        };
        let creds = OAuthCredentials {
            client_id: "c".into(),
            client_secret: None,
        };
        // Tests pass `None` so each test gets an ephemeral port
        // — the fixed `DEFAULT_LOOPBACK_PORT` would race if two
        // tests ran in parallel against the same machine.
        let session = begin_consent(&provider, &creds, "127.0.0.1", None).unwrap();
        let port = session.listener_addr().unwrap().port();

        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            let url = format!("http://127.0.0.1:{port}/callback?code=c&state=WRONG");
            let agent: ureq::Agent = ureq::config::Config::builder()
                .http_status_as_error(false)
                .build()
                .into();
            let _ = agent.get(&url).call();
        });

        let err = session
            .wait_for_callback(Duration::from_secs(5))
            .unwrap_err();
        handle.join().ok();
        assert!(
            format!("{err}").contains("state mismatch"),
            "got: {err}"
        );
    }

    #[test]
    fn well_known_onedrive_shape() {
        let p = well_known_provider("onedrive").unwrap();
        assert!(p.authorization_url.contains("login.microsoftonline.com"));
        assert!(p.token_url.contains("login.microsoftonline.com"));
        assert!(p.scopes.iter().any(|s| s == "Files.ReadWrite.AppFolder"));
        assert!(p.scopes.iter().any(|s| s == "offline_access"));
    }

    #[test]
    fn well_known_gdrive_shape() {
        let p = well_known_provider("gdrive").unwrap();
        assert!(p.authorization_url.contains("accounts.google.com"));
        assert!(p.scopes.iter().any(|s| s.contains("drive.appdata")));
        // Google needs `access_type=offline` + `prompt=consent` for
        // reliable refresh-token issuance.
        assert!(p
            .extra_auth_params
            .iter()
            .any(|(k, v)| k == "access_type" && v == "offline"));
        assert!(p
            .extra_auth_params
            .iter()
            .any(|(k, v)| k == "prompt" && v == "consent"));
    }

    #[test]
    fn well_known_dropbox_shape() {
        let p = well_known_provider("dropbox").unwrap();
        assert!(p.authorization_url.contains("dropbox.com"));
        assert!(p
            .extra_auth_params
            .iter()
            .any(|(k, v)| k == "token_access_type" && v == "offline"));
    }

    #[test]
    fn well_known_unknown_provider_errors() {
        let err = well_known_provider("icloud").unwrap_err();
        assert!(format!("{err}").contains("unknown provider"));
    }

    fn urlencoding(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{:02X}", b));
            }
        }
        out
    }
}
