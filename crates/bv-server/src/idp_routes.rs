//! The OpenID Provider over plain HTTP, on the documented `idp/` mount: the
//! browser-facing authorization endpoint (T545, `GET /v2/idp/oidc/authorize`
//! with a launch-session cookie, answered with a `302` or a plain page) and
//! a standard relying party's back channel (T546: raw discovery and JWKS,
//! RFC 6749 form token requests). Each adapter relays to the logical path
//! the engine decides on and only translates HTTP; nothing here trusts input.

use std::sync::Arc;

use actix_web::{
    cookie::{Cookie, SameSite},
    http::{header, StatusCode},
    web, HttpRequest, HttpResponse,
};
use serde_json::{Map, Value};
use zeroize::Zeroize;

use crate::routes::{resource, route, ResourceSpec};
use crate::{
    client_ip::{ClientIp, TrustedProxies},
    core::Core,
    errors::RvError,
    logical::{Connection as ReqConnection, Operation, Request, Response},
    modules::idp::provider::oidc_op::{
        back_channel::{self, ClientAuth, HttpAnswer, OAuthError},
        launch::{COOKIE_NAME, COOKIE_PATH},
    },
    Connection,
};

/// The engine's browser authorization path, on the documented `idp/` mount.
const LOGICAL_PATH: &str = "idp/oidc/launch-session/authorize";
/// The relying party's back channel, on the same mount.
const TOKEN_PATH: &str = "idp/oidc/token";
const JWKS_PATH: &str = "idp/oidc/jwks";
const DISCOVERY_PATH: &str = "idp/oidc/.well-known/openid-configuration";

/// The authorization request parameters passed on; RFC 6749 §3.1 has the
/// server ignore any other (`prompt`, `login_hint`, ...).
const PARAMS: &[&str] = &[
    "client_id",
    "redirect_uri",
    "response_type",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
];

/// As route-table entries (see [`crate::routes`]), registered ahead of the
/// `/v2/{path:.*}` catch-all. Each claims only its own method (and the token
/// endpoint only a non-JSON body), so the logical API keeps every other
/// request to these paths: the token-authenticated JSON `POST` to
/// `authorize` and the vault's own JSON `POST` to `token`.
pub(crate) const RESOURCES: &[ResourceSpec] = &[
    resource!("/v2/idp/oidc/authorize", fallback: PassThrough => [
        route!(routed_unauthenticated Get => oidc_browser_authorize, "idp/oidc/launch-session/authorize",
            "OIDC authorization endpoint a relying party redirects the browser to: no vault token is read; the single-use launch-session cookie minted by v2/idp/oidc/launch-session is the credential, and the engine checks client, exact redirect_uri, PKCE and the issue gate before the 302; other methods fall through to the logical API"),
    ]),
    resource!("/v2/idp/oidc/token", fallback: PassThroughJson => [
        route!(routed_unauthenticated Post => oidc_token, "idp/oidc/token",
            "OIDC token endpoint for a standard relying party (RFC 6749 4.1.3): no vault token is read; a form body of at most 16 KiB authenticated by client_secret_basic or client_secret_post, and the engine's token flow checks the client secret, the single-use code, redirect_uri, PKCE and the issue gate; raw OAuth JSON answers, never cached; a JSON body and other methods fall through to the logical API"),
    ]),
    resource!("/v2/idp/oidc/jwks", fallback: PassThrough => [
        route!(routed_unauthenticated Get => oidc_jwks, "idp/oidc/jwks",
            "the OP's public signing keys as a bare JWK Set: public by design, relying parties verify ID tokens with them; never a private member; 404 until OIDC is enabled; other methods fall through to the logical API"),
    ]),
    resource!("/v2/idp/oidc/.well-known/openid-configuration", fallback: PassThrough => [
        route!(routed_unauthenticated Get => oidc_discovery, "idp/oidc/.well-known/openid-configuration",
            "OpenID Connect discovery document as bare JSON: public by design (OIDC Discovery 4), names only the issuer, endpoints and supported methods; 404 until OIDC is enabled; other methods fall through to the logical API"),
    ]),
];

pub fn init_idp_service(cfg: &mut web::ServiceConfig) {
    crate::routes::register(cfg, crate::routes::IDP);
}

async fn handle(core: &Core, r: &mut Request) -> Result<Option<Response>, RvError> {
    #[cfg(feature = "sync_handler")]
    let result = core.handle_request(r);
    #[cfg(not(feature = "sync_handler"))]
    let result = core.handle_request(r).await;
    result
}

/// A tokenless v2 logical request on `path`, with the caller's addresses.
fn logical_request(req: &HttpRequest, trusted: &TrustedProxies, path: &str, operation: Operation) -> Request {
    let mut r = Request::new(path);
    r.operation = operation;
    r.api_version = 2;
    if let Some(conn) = req.conn_data::<Connection>() {
        let cip = ClientIp::resolve(conn.peer, req, trusted);
        r.connection = Some(ReqConnection {
            peer_addr: conn.peer.to_string(),
            peer_addr_derived: cip.derived.to_string(),
            ..Default::default()
        });
    }
    r
}

fn zeroize_strings(map: Option<&mut Map<String, Value>>) {
    for v in map.into_iter().flat_map(|m| m.values_mut()) {
        if let Value::String(s) = v {
            s.zeroize();
        }
    }
}

async fn oidc_browser_authorize(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
    trusted: web::Data<TrustedProxies>,
) -> HttpResponse {
    let mut logical = match browser_request(&req, trusted.get_ref()) {
        Ok(r) => r,
        Err(message) => return error_page(StatusCode::BAD_REQUEST, message),
    };
    let result = handle(&core, &mut logical).await;
    if let Some(Value::String(secret)) = logical.body.as_mut().and_then(|b| b.get_mut("launch_session")) {
        secret.zeroize();
    }
    match result {
        Ok(Some(resp)) => redirect(&resp),
        Ok(None) => internal_error("the engine returned no response"),
        Err(e) => refusal_page(e),
    }
}

/// The RFC 6749 §4.1.3 token request: read at most
/// [`back_channel::TOKEN_BODY_LIMIT`] bytes, parse the form and the Basic
/// credentials, relay the fields to the engine's token flow (which decides),
/// and send its answer as RFC 6749 §5.1 / §5.2 JSON.
async fn oidc_token(
    req: HttpRequest,
    payload: web::Payload,
    core: web::Data<Arc<Core>>,
    trusted: web::Data<TrustedProxies>,
) -> HttpResponse {
    let one = |name: header::HeaderName| {
        let mut all = req.headers().get_all(name);
        match (all.next(), all.next()) {
            (_, Some(_)) => Err(OAuthError::invalid_request("a header is repeated")),
            // A header that is not visible ASCII reads as empty: refused
            // as a content type, a failed authentication as credentials.
            (v, None) => Ok(v.map(|v| v.to_str().unwrap_or(""))),
        }
    };
    let (content_type, authorization) = match (one(header::CONTENT_TYPE), one(header::AUTHORIZATION)) {
        (Ok(ct), Ok(auth)) => (ct, auth),
        (Err(e), _) | (_, Err(e)) => return send(e.answer()),
    };
    let declared = req.headers().get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()?.parse::<usize>().ok());
    if declared.is_some_and(|n| n > back_channel::TOKEN_BODY_LIMIT) {
        return send(OAuthError::too_large().answer());
    }
    let body = match payload.to_bytes_limited(back_channel::TOKEN_BODY_LIMIT).await {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => return send(OAuthError::invalid_request("the request body could not be read").answer()),
        Err(_) => return send(OAuthError::too_large().answer()),
    };
    let parsed = back_channel::parse_token_request(content_type, authorization, &body);
    // The raw form held the secret, the code and the verifier.
    if let Ok(mut raw) = body.try_into_mut() {
        raw.as_mut().zeroize();
    }
    let form = match parsed {
        Ok(form) => form,
        Err(e) => return send(e.answer()),
    };

    let mut logical = logical_request(&req, trusted.get_ref(), TOKEN_PATH, Operation::Write);
    logical.body = Some(form.logical_body());
    let result = handle(&core, &mut logical).await;
    zeroize_strings(logical.body.as_mut());
    let answer = match result {
        Ok(Some(mut resp)) => {
            let answer = resp.data.as_ref().map(back_channel::token_answer);
            zeroize_strings(resp.data.as_mut());
            match answer {
                Some(Ok(answer)) => answer,
                _ => return send(back_channel_failure("token endpoint: the engine returned no token response")),
            }
        }
        Ok(None) => return send(back_channel_failure("token endpoint: the engine returned no response")),
        Err(e) => flow_error(&e, form.auth),
    };
    send(answer)
}

async fn oidc_jwks(req: HttpRequest, core: web::Data<Arc<Core>>, trusted: web::Data<TrustedProxies>) -> HttpResponse {
    document(&req, &core, trusted.get_ref(), JWKS_PATH, back_channel::JWKS_CACHE_CONTROL).await
}

async fn oidc_discovery(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
    trusted: web::Data<TrustedProxies>,
) -> HttpResponse {
    document(&req, &core, trusted.get_ref(), DISCOVERY_PATH, back_channel::DISCOVERY_CACHE_CONTROL).await
}

/// A public document (discovery, JWKS) as its bare JSON object.
async fn document(
    req: &HttpRequest,
    core: &Core,
    trusted: &TrustedProxies,
    path: &str,
    cache_control: &'static str,
) -> HttpResponse {
    let mut logical = logical_request(req, trusted, path, Operation::Read);
    let answer = match handle(core, &mut logical).await {
        Ok(Some(Response { data: Some(data), .. })) => back_channel::document_answer(&data, cache_control),
        Ok(_) => back_channel_failure("discovery or JWKS: the engine returned no document"),
        Err(e) => flow_error(&e, ClientAuth::Post),
    };
    send(answer)
}

/// The OAuth error for a logical error. A server-side failure is logged
/// (its text never carries a request value) and sent with at most the
/// flow's fixed reason.
fn flow_error(e: &RvError, auth: ClientAuth) -> HttpAnswer {
    let oauth = OAuthError::from_flow(e, auth);
    if oauth.status >= 500 {
        log::warn!(target: "idp", "back channel request failed: {e}");
    }
    oauth.answer()
}

fn back_channel_failure(why: &str) -> HttpAnswer {
    log::error!(target: "idp", "{why}");
    OAuthError::server_error().answer()
}

/// Send an engine-built answer as it is.
fn send(mut answer: HttpAnswer) -> HttpResponse {
    let mut resp =
        HttpResponse::build(StatusCode::from_u16(answer.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
    for (name, value) in &answer.headers {
        resp.insert_header((*name, value.as_str()));
    }
    resp.body(std::mem::take(&mut *answer.body))
}

/// The logical request: allow-listed query parameters (each at most once)
/// and the launch-session cookie (at most one). Never a vault token: the
/// `token` cookie rides on a cross-site top-level `GET` and must not
/// authenticate anything here.
fn browser_request(req: &HttpRequest, trusted: &TrustedProxies) -> Result<Request, &'static str> {
    let pairs = web::Query::<Vec<(String, String)>>::from_query(req.query_string())
        .map_err(|_| "invalid_request: the query string is malformed")?
        .into_inner();
    let mut body = Map::new();
    for (name, value) in pairs {
        if PARAMS.contains(&name.as_str()) && body.insert(name, Value::String(value)).is_some() {
            return Err("invalid_request: a parameter is repeated");
        }
    }
    let cookies = req.cookies().map_err(|_| "invalid_request: the Cookie header is malformed")?;
    let mut launch = cookies.iter().filter(|c| c.name() == COOKIE_NAME);
    if let Some(cookie) = launch.next() {
        if launch.next().is_some() {
            return Err("invalid_request: more than one launch-session cookie");
        }
        body.insert("launch_session".into(), Value::String(cookie.value().to_string()));
    }

    let mut r = logical_request(req, trusted, LOGICAL_PATH, Operation::Write);
    r.body = Some(body);
    Ok(r)
}

/// `302` to the engine's `redirect_to`, which it built from the client's
/// registered `https` URI. Anything else is a bug, never a destination.
fn redirect(resp: &Response) -> HttpResponse {
    let to = resp.data.as_ref().and_then(|d| d.get("redirect_to")).and_then(Value::as_str);
    let Some(location) = to.filter(|u| u.starts_with("https://")).and_then(|u| header::HeaderValue::from_str(u).ok())
    else {
        return internal_error("the engine returned no usable redirect");
    };
    HttpResponse::Found()
        .insert_header((header::LOCATION, location))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header((header::PRAGMA, "no-cache"))
        .insert_header((header::REFERRER_POLICY, "no-referrer"))
        .cookie(removal_cookie())
        .finish()
}

/// A refusal is a page, never a redirect. Only the engine's fixed
/// `error_code: reason` text is shown; no request value is echoed.
fn refusal_page(e: RvError) -> HttpResponse {
    match e {
        RvError::ErrResponseStatus(status, text) => {
            error_page(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), &text)
        }
        other => {
            let status = StatusCode::from_u16(other.response_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            if status.is_server_error() {
                log::warn!(target: "idp", "browser authorization failed: {other}");
            }
            error_page(status, status.canonical_reason().unwrap_or("error"))
        }
    }
}

fn internal_error(why: &str) -> HttpResponse {
    log::error!(target: "idp", "browser authorization: {why}");
    error_page(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
}

fn error_page(status: StatusCode, message: &str) -> HttpResponse {
    HttpResponse::build(status)
        .content_type("text/plain; charset=utf-8")
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header((header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .insert_header((header::CONTENT_SECURITY_POLICY, "default-src 'none'; frame-ancestors 'none'"))
        .insert_header((header::REFERRER_POLICY, "no-referrer"))
        .cookie(removal_cookie())
        .body(format!("{message}\n"))
}

/// Every answer tells the browser to drop the cookie: the session is
/// single use whatever happened, so a copy left behind is only clutter.
fn removal_cookie() -> Cookie<'static> {
    let mut c =
        Cookie::build(COOKIE_NAME, "").path(COOKIE_PATH).secure(true).http_only(true).same_site(SameSite::Lax).finish();
    c.make_removal();
    c
}

#[cfg(all(test, not(feature = "sync_handler")))]
mod tests {
    //! Both adapters end to end over a real vault: a launch session minted
    //! with a userpass token, the browser's `GET` answered with a `302`, and
    //! the code redeemed by a relying party's form request (T546) or the
    //! JSON API (T545); then replay, wrong credentials, malformed requests,
    //! the fall-through to the logical API and what the audit log holds.

    use actix_web::{
        cookie::Cookie,
        dev::ServiceResponse,
        http::header,
        test::{call_service, init_service, read_body, TestRequest},
        App,
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use serde_json::{json, Value};

    use super::*;
    use crate::{
        kernel_api::VaultCtx,
        modules::idp::provider::oidc_op::{jwt::verify_rs256, s256},
        test_utils::{new_unseal_test_bastion_vault, test_mount_api, test_mount_auth_api, test_write_api},
    };

    const ISSUER: &str = "https://vault.example.com/v2/idp/oidc";
    const ORIGIN: &str = "https://vault.example.com";
    const REDIRECT: &str = "https://app.example.com/cb";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const LAUNCH_ID: &str = "L4unch-1d_of_a_host_session_0123456789abcde";
    const FORM: &str = "application/x-www-form-urlencoded";

    async fn v2(ctx: &dyn VaultCtx, token: &str, path: &str, body: Value) -> Result<Option<Response>, RvError> {
        let mut req = Request::new(path);
        req.operation = Operation::Write;
        req.client_token = token.to_string();
        req.api_version = 2;
        req.body = body.as_object().cloned();
        ctx.handle_request(&mut req).await
    }

    fn data(r: Result<Option<Response>, RvError>) -> Map<String, Value> {
        r.expect("request failed").expect("no response").data.expect("no data")
    }

    /// A vault with a file audit device, the `idp` mount, an entitled
    /// userpass user `alice`, OIDC enabled and the client `app`.
    struct Vault {
        _bvault: bastion_vault::BastionVault,
        core: Arc<Core>,
        root: String,
        /// Alice's own token, which may mint launch sessions.
        token: String,
        alice: String,
        client_secret: String,
        audit_dir: std::path::PathBuf,
        audit_log: std::path::PathBuf,
    }

    impl Vault {
        fn ctx(&self) -> &dyn VaultCtx {
            self.core.as_ref()
        }

        async fn mint(&self) -> Result<Option<Response>, RvError> {
            v2(self.ctx(), &self.token, "idp/oidc/launch-session", json!({"client_id": "app", "launch_id": LAUNCH_ID}))
                .await
        }

        async fn launch_session(&self) -> String {
            data(self.mint().await)["launch_session"].as_str().unwrap().to_string()
        }

        /// The audit log's event entries named `name`, as their data.
        fn events(&self, name: &str) -> Vec<Value> {
            std::fs::read_to_string(&self.audit_log)
                .unwrap()
                .lines()
                .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                .filter(|e| e["type"] == "event" && e["request"]["path"] == name)
                .map(|e| e["request"]["data"].clone())
                .collect()
        }
    }

    impl Drop for Vault {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.audit_dir);
        }
    }

    async fn signed_in_vault(name: &str) -> Vault {
        let (bvault, core, root) = new_unseal_test_bastion_vault(name).await;
        let ctx: &dyn VaultCtx = core.as_ref();
        let audit_dir = std::env::temp_dir().join(format!("bv-{name}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&audit_dir).unwrap();
        let audit_log = audit_dir.join("audit.log");
        let options = std::collections::HashMap::from([("file_path".to_string(), audit_log.display().to_string())]);
        let device = crate::audit::AuditDeviceConfig {
            path: "idp-http".into(),
            device_type: "file".into(),
            description: String::new(),
            options,
            namespace: String::new(),
            mirror: false,
        };
        ctx.audit_broker().expect("broker installed at unseal").enable_device(device).await.unwrap();
        test_mount_api(ctx, &root, "idp", "idp").await;
        test_mount_auth_api(ctx, &root, "userpass", "userpass").await;
        let policy = r#"path "idp/oidc/launch-session" { capabilities = ["create", "update"] }"#;
        test_write_api(ctx, &root, "sys/policy/idp-launch", true, json!({"policy": policy}).as_object().cloned())
            .await
            .unwrap();
        let user = json!({"password": "pw-123456", "policies": "idp-launch"});
        test_write_api(ctx, &root, "auth/userpass/users/alice", true, user.as_object().cloned()).await.unwrap();
        let mut login = Request::new("auth/userpass/login/alice");
        login.operation = Operation::Write;
        login.body = json!({"password": "pw-123456"}).as_object().cloned();
        let auth = ctx.handle_request(&mut login).await.unwrap().unwrap().auth.unwrap();
        let (token, alice) = (auth.client_token.clone(), auth.metadata["entity_id"].clone());
        data(v2(ctx, &root, &format!("idp/identities/{alice}"), json!({"login": "alice"})).await);
        data(v2(ctx, &root, "idp/environments/apps", json!({"namespace": "", "roles": {"ops": ["ops"]}})).await);
        data(v2(ctx, &root, &format!("idp/entitlements/{alice}/apps"), json!({"roles": ["ops"]})).await);
        data(v2(ctx, &root, "idp/oidc/config", json!({"enabled": true, "issuer": ISSUER})).await);
        let client = data(
            v2(ctx, &root, "idp/oidc/clients/app", json!({"environment": "apps", "redirect_uris": [REDIRECT]})).await,
        );
        let client_secret = client["client_secret"].as_str().unwrap().to_string();
        Vault { _bvault: bvault, core, root, token, alice, client_secret, audit_dir, audit_log }
    }

    /// The listener over the vault (a macro: actix's test request type
    /// cannot be named here, so the service cannot be a function's type).
    macro_rules! listener {
        ($v:expr) => {
            init_service(
                App::new()
                    .app_data(web::Data::new($v.core.clone()))
                    .app_data(web::Data::new(TrustedProxies::default()))
                    .configure(crate::init_service),
            )
            .await
        };
    }

    /// The code the browser carries back to the RP after a launch session.
    macro_rules! browser_code {
        ($app:expr, $v:expr) => {{
            let session = $v.launch_session().await;
            let resp = call_service($app, browser_get(Some(&session), &authorize_uri(REDIRECT)).to_request()).await;
            assert_eq!(resp.status(), StatusCode::FOUND);
            let location = header_of(&resp, header::LOCATION).unwrap();
            location.strip_prefix(&format!("{REDIRECT}?code=")).unwrap().split('&').next().unwrap().to_string()
        }};
    }

    fn authorize_uri(redirect: &str) -> String {
        format!(
            "/v2/idp/oidc/authorize?client_id=app&redirect_uri={redirect}&response_type=code&scope=openid\
             &state=s1&nonce=n1&code_challenge={}&code_challenge_method=S256&prompt=none",
            s256(VERIFIER)
        )
    }

    fn browser_get(cookie: Option<&str>, uri: &str) -> TestRequest {
        let req = TestRequest::get().uri(uri);
        match cookie {
            Some(c) => req.cookie(Cookie::new(COOKIE_NAME, c.to_string())),
            None => req,
        }
    }

    fn header_of<B>(resp: &ServiceResponse<B>, name: header::HeaderName) -> Option<String> {
        resp.headers().get(name).map(|v| v.to_str().unwrap().to_string())
    }

    /// An `application/x-www-form-urlencoded` body, everything but the
    /// unreserved characters percent-encoded, as RP libraries send it.
    fn form(pairs: &[(&str, &str)]) -> String {
        let enc = |s: &str| -> String {
            s.bytes()
                .map(|b| match b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    true => (b as char).to_string(),
                    false => format!("%{b:02X}"),
                })
                .collect()
        };
        pairs.iter().map(|(k, v)| format!("{}={}", enc(k), enc(v))).collect::<Vec<_>>().join("&")
    }

    fn redeem<'a>(code: &'a str, secret: &'a str) -> Vec<(&'a str, &'a str)> {
        vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("client_id", "app"),
            ("client_secret", secret),
            ("code_verifier", VERIFIER),
        ]
    }

    fn token_post(body: String) -> TestRequest {
        TestRequest::post().uri("/v2/idp/oidc/token").insert_header((header::CONTENT_TYPE, FORM)).set_payload(body)
    }

    fn basic(id: &str, secret: &str) -> (header::HeaderName, String) {
        (header::AUTHORIZATION, format!("Basic {}", B64.encode(format!("{id}:{secret}"))))
    }

    /// Status, the RFC 6749 §5.2 `error`, and the body; every token
    /// endpoint answer is JSON and never cached.
    async fn oauth(resp: ServiceResponse) -> (StatusCode, Option<String>, Value, Option<String>) {
        let status = resp.status();
        assert_eq!(header_of(&resp, header::CONTENT_TYPE).as_deref(), Some("application/json"));
        assert_eq!(header_of(&resp, header::CACHE_CONTROL).as_deref(), Some("no-store"));
        assert_eq!(header_of(&resp, header::PRAGMA).as_deref(), Some("no-cache"));
        let challenge = header_of(&resp, header::WWW_AUTHENTICATE);
        let body: Value = serde_json::from_slice(&read_body(resp).await).unwrap();
        let error = body.get("error").and_then(Value::as_str).map(str::to_string);
        (status, error, body, challenge)
    }

    #[actix_web::test]
    async fn the_browser_endpoint_signs_in_once_with_a_launch_session() {
        let v = signed_in_vault("test_idp_browser_authorize").await;
        let (ctx, token, client_secret) = (v.ctx(), v.token.clone(), v.client_secret.clone());

        // The contract the host plants the cookie from.
        let minted = data(v.mint().await);
        let secret = minted["launch_session"].as_str().unwrap().to_string();
        assert_eq!(
            minted["cookie"],
            json!({"name": COOKIE_NAME, "path": "/", "secure": true, "http_only": true, "same_site": "Lax", "max_age": 120})
        );
        assert_eq!(minted["cookie_origin"], json!(ORIGIN));
        assert_eq!(minted["authorization_endpoint"], json!(format!("{ISSUER}/authorize")));

        let app = listener!(v);

        // The browser: a 302 to the registered URI with code and state.
        let resp = call_service(&app, browser_get(Some(&secret), &authorize_uri(REDIRECT)).to_request()).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = header_of(&resp, header::LOCATION).unwrap();
        let code = location.strip_prefix(&format!("{REDIRECT}?code=")).unwrap().split('&').next().unwrap().to_string();
        assert!(location.ends_with("&state=s1"), "{location}");
        assert!(!location.contains(&secret));
        assert_eq!(header_of(&resp, header::CACHE_CONTROL).as_deref(), Some("no-store"));
        let cleared = header_of(&resp, header::SET_COOKIE).unwrap();
        assert!(cleared.starts_with(&format!("{COOKIE_NAME}=;")) && cleared.contains("Max-Age=0"), "{cleared}");

        // The relying party redeems the code with its secret and verifier.
        let redeem = json!({"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
            "client_id": "app", "client_secret": client_secret, "code_verifier": VERIFIER});
        let issued = data(v2(ctx, "", "idp/oidc/token", redeem).await);
        assert!(issued["id_token"].as_str().is_some_and(|t| t.split('.').count() == 3));

        // Replay: a plain page, no redirect.
        let resp = call_service(&app, browser_get(Some(&secret), &authorize_uri(REDIRECT)).to_request()).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(header_of(&resp, header::LOCATION).is_none());
        assert_eq!(header_of(&resp, header::CONTENT_TYPE).as_deref(), Some("text/plain; charset=utf-8"));
        assert_eq!(header_of(&resp, header::X_CONTENT_TYPE_OPTIONS).as_deref(), Some("nosniff"));
        let body = read_body(resp).await;
        assert!(body.starts_with(b"login_required: unknown or used launch session"), "{body:?}");

        // An unregistered redirect_uri is never a destination.
        let burned = v.launch_session().await;
        let resp =
            call_service(&app, browser_get(Some(&burned), &authorize_uri("https://evil.example.com/cb")).to_request())
                .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(header_of(&resp, header::LOCATION).is_none());
        assert!(read_body(resp).await.starts_with(b"invalid_request: redirect uri mismatch"));
        let resp = call_service(&app, browser_get(Some(&burned), &authorize_uri(REDIRECT)).to_request()).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "the refused request burned the session");

        // A vault token, in a header or the `token` cookie, is not a login here.
        let req = TestRequest::get()
            .uri(&authorize_uri(REDIRECT))
            .insert_header(("X-BastionVault-Token", token.as_str()))
            .cookie(Cookie::new(crate::AUTH_COOKIE_NAME, token.clone()))
            .to_request();
        let resp = call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(read_body(resp).await.starts_with(b"login_required: launch session missing"));

        // Malformed: a repeated parameter or two launch cookies are refused
        // before the engine sees them, so the session survives.
        let fresh = v.launch_session().await;
        let repeated = format!("{}&client_id=other", authorize_uri(REDIRECT));
        let resp = call_service(&app, browser_get(Some(&fresh), &repeated).to_request()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let two = format!("{COOKIE_NAME}={fresh}; {COOKIE_NAME}=other");
        let req = TestRequest::get().uri(&authorize_uri(REDIRECT)).insert_header((header::COOKIE, two)).to_request();
        assert_eq!(call_service(&app, req).await.status(), StatusCode::BAD_REQUEST);
        let resp = call_service(&app, browser_get(Some(&fresh), &authorize_uri(REDIRECT)).to_request()).await;
        assert_eq!(resp.status(), StatusCode::FOUND);

        // Any other method is the logical API's, not this endpoint's.
        let req = TestRequest::post()
            .uri("/v2/idp/oidc/authorize")
            .insert_header(("X-BastionVault-Token", token.as_str()))
            .set_json(json!({"client_id": "app"}))
            .to_request();
        let resp = call_service(&app, req).await;
        assert_ne!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(header_of(&resp, header::CONTENT_TYPE).as_deref(), Some("application/json"));

        // Audited: three mints, two consumptions, the refusals; never a
        // session secret, launch id, code, client secret or token.
        assert_eq!(v.events("idp.oidc.launch-session").len(), 3);
        assert_eq!(v.events("idp.oidc.launch-session-consumed").len(), 2);
        let refused: Vec<Value> = v.events("idp.oidc.refused").iter().map(|e| e["reason"].clone()).collect();
        for reason in ["unknown_or_used_launch_session", "redirect_uri_mismatch", "launch_session_missing"] {
            assert!(refused.contains(&json!(reason)), "{reason} in {refused:?}");
        }
        let log = std::fs::read_to_string(&v.audit_log).unwrap();
        let id_token = issued["id_token"].as_str().unwrap();
        for value in [secret.as_str(), &burned, &fresh, LAUNCH_ID, &code, &client_secret, id_token] {
            assert!(!log.contains(value), "the audit log holds {value}");
        }
    }

    /// T546: what an off-the-shelf RP does after the browser comes back —
    /// discovery and JWKS from the URLs discovery itself names, the code
    /// redeemed with a form request (`client_secret_post`, then Basic), the
    /// ID token verified against the raw JWKS — and the RFC 6749 §5.2
    /// answers for replay, wrong secrets, a bad verifier and a wrong
    /// redirect URI.
    #[actix_web::test]
    async fn a_relying_party_redeems_the_code_over_the_back_channel() {
        let v = signed_in_vault("test_idp_back_channel").await;
        let app = listener!(v);
        let get_json = |path: String| {
            let app = &app;
            async move {
                let resp = call_service(app, TestRequest::get().uri(&path).to_request()).await;
                assert_eq!(resp.status(), StatusCode::OK, "{path}");
                assert_eq!(header_of(&resp, header::CONTENT_TYPE).as_deref(), Some("application/json"), "{path}");
                let cache = header_of(&resp, header::CACHE_CONTROL);
                (serde_json::from_slice::<Value>(&read_body(resp).await).unwrap(), cache)
            }
        };

        // Discovery at <issuer>/.well-known/openid-configuration, bare.
        let (disco, cache) = get_json(format!("{}/.well-known/openid-configuration", &ISSUER[ORIGIN.len()..])).await;
        assert_eq!(cache.as_deref(), Some(back_channel::DISCOVERY_CACHE_CONTROL));
        assert!(disco.get("data").is_none() && disco.get("lease_id").is_none(), "no envelope: {disco}");
        assert_eq!(disco["issuer"], json!(ISSUER));
        assert_eq!(
            disco["token_endpoint_auth_methods_supported"],
            json!(["client_secret_basic", "client_secret_post"])
        );
        let local = |field: &str| disco[field].as_str().unwrap().strip_prefix(ORIGIN).unwrap().to_string();
        assert_eq!(local("token_endpoint"), "/v2/idp/oidc/token");
        assert_eq!(local("authorization_endpoint"), "/v2/idp/oidc/authorize");

        // The JWKS at the jwks_uri discovery names.
        let (jwks, cache) = get_json(local("jwks_uri")).await;
        assert_eq!(cache.as_deref(), Some(back_channel::JWKS_CACHE_CONTROL));
        assert_eq!(jwks["keys"].as_array().map(Vec::len), Some(1));
        assert!(jwks["keys"][0].get("d").is_none(), "no private member");

        // client_secret_post: the RFC 6749 §5.1 answer, the token verified
        // against the JWKS the RP just fetched.
        let code = browser_code!(&app, v);
        let req = token_post(form(&redeem(&code, &v.client_secret))).to_request();
        let (status, error, body, _) = oauth(call_service(&app, req).await).await;
        assert_eq!((status, error), (StatusCode::OK, None));
        let keys: Vec<&str> = body.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, ["access_token", "expires_in", "id_token", "scope", "token_type"]);
        assert_eq!((body["token_type"].as_str(), body["expires_in"].as_u64()), (Some("Bearer"), Some(300)));
        assert_eq!(body["scope"], json!("openid"));
        let id_token = body["id_token"].as_str().unwrap().to_string();
        let access_token = body["access_token"].as_str().unwrap().to_string();
        let (_, claims) = verify_rs256(&id_token, &jwks).unwrap();
        assert_eq!((claims["iss"].as_str(), claims["aud"].as_str()), (Some(ISSUER), Some("app")));
        assert_eq!((claims["sub"].as_str(), claims["nonce"].as_str()), (Some(v.alice.as_str()), Some("n1")));

        // Replay.
        let req = token_post(form(&redeem(&code, &v.client_secret))).to_request();
        let (status, _, body, _) = oauth(call_service(&app, req).await).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"error": "invalid_grant", "error_description": "unknown or used code"}));

        // client_secret_basic: a wrong secret is 401 with a challenge and
        // leaves the code alone (the client authenticates first); the right
        // one redeems it.
        let code = browser_code!(&app, v);
        let without_client: Vec<(&str, &str)> =
            redeem(&code, "").into_iter().filter(|(k, _)| !k.starts_with("client_")).collect();
        let req = token_post(form(&without_client)).insert_header(basic("app", "wrong")).to_request();
        let (status, error, _, challenge) = oauth(call_service(&app, req).await).await;
        assert_eq!((status, error.as_deref()), (StatusCode::UNAUTHORIZED, Some("invalid_client")));
        assert_eq!(challenge.as_deref(), Some(back_channel::BASIC_CHALLENGE));
        let req = token_post(form(&without_client)).insert_header(basic("app", &v.client_secret)).to_request();
        let (status, _, body, challenge) = oauth(call_service(&app, req).await).await;
        assert_eq!((status, challenge), (StatusCode::OK, None));
        assert!(verify_rs256(body["id_token"].as_str().unwrap(), &jwks).is_ok());

        // client_secret_post with a wrong secret: 400, no challenge. Then a
        // wrong verifier burns the code.
        let code = browser_code!(&app, v);
        let req = token_post(form(&redeem(&code, "wrong"))).to_request();
        let (status, error, _, challenge) = oauth(call_service(&app, req).await).await;
        assert_eq!((status, error.as_deref(), challenge), (StatusCode::BAD_REQUEST, Some("invalid_client"), None));
        let mut bad_pkce = redeem(&code, &v.client_secret);
        bad_pkce[5].1 = "x0000000000000000000000000000000000000000000";
        let (status, _, body, _) = oauth(call_service(&app, token_post(form(&bad_pkce)).to_request()).await).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"error": "invalid_grant", "error_description": "pkce verification failed"}));
        let req = token_post(form(&redeem(&code, &v.client_secret))).to_request();
        assert_eq!(oauth(call_service(&app, req).await).await.1.as_deref(), Some("invalid_grant"), "burned");

        // A redirect_uri other than the code's.
        let code = browser_code!(&app, v);
        let mut other = redeem(&code, &v.client_secret);
        other[2].1 = "https://app.example.com/other";
        let (status, _, body, _) = oauth(call_service(&app, token_post(form(&other)).to_request()).await).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"error": "invalid_grant", "error_description": "redirect uri mismatch"}));

        // Audited: two tokens, each refusal by reason; never a code, a
        // secret, the verifier or a token.
        assert_eq!(v.events("idp.oidc.token").len(), 2);
        let refused: Vec<Value> = v.events("idp.oidc.refused").iter().map(|e| e["reason"].clone()).collect();
        for reason in ["unknown_or_used_code", "invalid_client", "pkce_verification_failed", "redirect_uri_mismatch"] {
            assert!(refused.contains(&json!(reason)), "{reason} in {refused:?}");
        }
        let log = std::fs::read_to_string(&v.audit_log).unwrap();
        for value in [code.as_str(), &v.client_secret, VERIFIER, &id_token, &access_token] {
            assert!(!log.contains(value), "the audit log holds {value}");
        }
    }

    /// T546: what the token endpoint refuses before the engine sees it
    /// (so the code survives), what the engine refuses without consuming
    /// it, what falls through to the logical API, and a disabled OP.
    #[actix_web::test]
    async fn the_token_endpoint_refuses_malformed_requests_and_leaves_json_to_the_logical_api() {
        let v = signed_in_vault("test_idp_back_channel_malformed").await;
        let app = listener!(v);
        let code = browser_code!(&app, v);
        let good = redeem(&code, &v.client_secret);
        let refused = |req, want: (StatusCode, &'static str)| {
            let app = &app;
            async move {
                let (status, error, body, _) = oauth(call_service(app, req).await).await;
                assert_eq!((status, error.as_deref()), (want.0, Some(want.1)), "{body}");
                body
            }
        };
        let invalid_request = (StatusCode::BAD_REQUEST, "invalid_request");

        // Not a UTF-8 form.
        for ct in ["text/plain", "multipart/form-data; boundary=x", "application/x-www-form-urlencoded; charset=latin1"]
        {
            let req = TestRequest::post()
                .uri("/v2/idp/oidc/token")
                .insert_header((header::CONTENT_TYPE, ct))
                .set_payload(form(&good))
                .to_request();
            refused(req, invalid_request).await;
        }
        let req = TestRequest::post().uri("/v2/idp/oidc/token").set_payload(form(&good)).to_request();
        refused(req, invalid_request).await;

        // Too large, by declaration and by content.
        let big = format!("{}&pad={}", form(&good), "a".repeat(back_channel::TOKEN_BODY_LIMIT));
        refused(token_post(big).to_request(), (StatusCode::PAYLOAD_TOO_LARGE, "invalid_request")).await;

        // Repeated, missing and empty parameters; two Authorization headers.
        let body = refused(token_post(format!("{}&code=again", form(&good))).to_request(), invalid_request).await;
        assert_eq!(body["error_description"], json!("a parameter is repeated"));
        for name in ["grant_type", "code", "redirect_uri"] {
            let without: Vec<_> = good.iter().copied().filter(|(k, _)| *k != name).collect();
            let body = refused(token_post(form(&without)).to_request(), invalid_request).await;
            assert_eq!(body["error_description"], json!(format!("{name} is missing")));
            let body = refused(token_post(format!("{}&{name}=", form(&without))).to_request(), invalid_request).await;
            assert_eq!(body["error_description"], json!(format!("{name} is missing")));
        }
        let req = token_post(form(&good))
            .append_header(basic("app", &v.client_secret))
            .append_header(basic("app", &v.client_secret))
            .to_request();
        refused(req, invalid_request).await;
        let req = token_post(form(&good)).insert_header(basic("app", &v.client_secret)).to_request();
        let body = refused(req, invalid_request).await;
        assert_eq!(body["error_description"], json!("use one client authentication method, not two"));
        let req = token_post(form(&good)).insert_header((header::AUTHORIZATION, "Bearer abc")).to_request();
        refused(req, (StatusCode::UNAUTHORIZED, "invalid_client")).await;

        // The engine refuses these before it takes the code.
        let mut grant = good.clone();
        grant[0].1 = "refresh_token";
        refused(token_post(form(&grant)).to_request(), (StatusCode::BAD_REQUEST, "unsupported_grant_type")).await;
        let no_secret: Vec<_> = good.iter().copied().filter(|(k, _)| *k != "client_secret").collect();
        refused(token_post(form(&no_secret)).to_request(), (StatusCode::BAD_REQUEST, "invalid_client")).await;
        let mut ghost = good.clone();
        ghost[3].1 = "ghost";
        let body = refused(token_post(form(&ghost)).to_request(), (StatusCode::BAD_REQUEST, "invalid_client")).await;
        assert_eq!(body["error_description"], json!("invalid client"), "an unknown client reads as a wrong secret");

        // So the code still redeems.
        let (status, _, _, _) = oauth(call_service(&app, token_post(form(&good)).to_request()).await).await;
        assert_eq!(status, StatusCode::OK);

        // A JSON body, and other methods, are the logical API's.
        let json_post = TestRequest::post().uri("/v2/idp/oidc/token").set_json(json!({"grant_type": "x"})).to_request();
        let jwks_post = TestRequest::post().uri("/v2/idp/oidc/jwks").set_json(json!({})).to_request();
        let token_get = TestRequest::get().uri("/v2/idp/oidc/token").to_request();
        for req in [json_post, jwks_post, token_get] {
            let resp = call_service(&app, req).await;
            assert_ne!(header_of(&resp, header::CACHE_CONTROL).as_deref(), Some("no-store"));
            assert_ne!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        }

        // A disabled OP: discovery, JWKS and token answer 404, never cached.
        data(v2(v.ctx(), &v.root, "idp/oidc/config", json!({"enabled": false})).await);
        for req in [
            TestRequest::get().uri("/v2/idp/oidc/.well-known/openid-configuration").to_request(),
            TestRequest::get().uri("/v2/idp/oidc/jwks").to_request(),
            token_post(form(&good)).to_request(),
        ] {
            let (status, _, body, _) = oauth(call_service(&app, req).await).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert_eq!(body, json!({"error": "server_error", "error_description": "not enabled"}));
        }
    }
}
