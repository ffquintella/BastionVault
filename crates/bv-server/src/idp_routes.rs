//! The OpenID Provider's browser-facing authorization endpoint (T545,
//! features/identity-provider.md "Launch sessions"). A relying party sends
//! the browser to `GET /v2/idp/oidc/authorize`; this adapter hands the query
//! and the launch-session cookie to the logical path the engine decides on,
//! and answers with the `302` (or a plain error page) the logical layer
//! cannot express. Every check is the engine's: nothing here trusts input.

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
    modules::idp::provider::oidc_op::launch::{COOKIE_NAME, COOKIE_PATH},
    Connection,
};

/// The engine's browser authorization path, on the documented `idp/` mount.
const LOGICAL_PATH: &str = "idp/oidc/launch-session/authorize";

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

/// As a route-table entry (see [`crate::routes`]). Registered ahead of the
/// `/v2/{path:.*}` catch-all and claiming `GET` only, so the token-
/// authenticated JSON `POST` to the same path still reaches the logical API.
pub(crate) const RESOURCES: &[ResourceSpec] = &[resource!("/v2/idp/oidc/authorize", fallback: PassThrough => [
    route!(routed_unauthenticated Get => oidc_browser_authorize, "idp/oidc/launch-session/authorize",
        "OIDC authorization endpoint a relying party redirects the browser to: no vault token is read; the single-use launch-session cookie minted by v2/idp/oidc/launch-session is the credential, and the engine checks client, exact redirect_uri, PKCE and the issue gate before the 302; other methods fall through to the logical API"),
])];

pub fn init_idp_service(cfg: &mut web::ServiceConfig) {
    crate::routes::register(cfg, crate::routes::IDP);
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
    #[cfg(feature = "sync_handler")]
    let result = core.handle_request(&mut logical);
    #[cfg(not(feature = "sync_handler"))]
    let result = core.handle_request(&mut logical).await;
    if let Some(Value::String(secret)) = logical.body.as_mut().and_then(|b| b.get_mut("launch_session")) {
        secret.zeroize();
    }
    match result {
        Ok(Some(resp)) => redirect(&resp),
        Ok(None) => internal_error("the engine returned no response"),
        Err(e) => refusal_page(e),
    }
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

    let mut r = Request::new(LOGICAL_PATH);
    r.operation = Operation::Write;
    r.api_version = 2;
    r.body = Some(body);
    if let Some(conn) = req.conn_data::<Connection>() {
        let cip = ClientIp::resolve(conn.peer, req, trusted);
        r.connection = Some(ReqConnection {
            peer_addr: conn.peer.to_string(),
            peer_addr_derived: cip.derived.to_string(),
            ..Default::default()
        });
    }
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
    //! The browser endpoint end to end over a real vault: a launch session
    //! minted with a userpass token, the browser's `GET` answered with a
    //! `302`, the code redeemed with PKCE, then replay, a wrong redirect, a
    //! vault token in place of the cookie, malformed requests and the `POST`
    //! fall-through to the logical API.

    use actix_web::{
        cookie::Cookie,
        http::header,
        test::{call_service, init_service, read_body, TestRequest},
        App,
    };
    use serde_json::{json, Value};

    use super::*;
    use crate::{
        kernel_api::VaultCtx,
        modules::idp::provider::oidc_op::s256,
        test_utils::{new_unseal_test_bastion_vault, test_mount_api, test_mount_auth_api, test_write_api},
    };

    const ISSUER: &str = "https://vault.example.com/v2/idp/oidc";
    const REDIRECT: &str = "https://app.example.com/cb";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const LAUNCH_ID: &str = "L4unch-1d_of_a_host_session_0123456789abcde";

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

    fn authorize_uri(redirect: &str) -> String {
        format!(
            "/v2/idp/oidc/authorize?client_id=app&redirect_uri={redirect}&response_type=code&scope=openid\
             &state=s1&nonce=n1&code_challenge={}&code_challenge_method=S256&prompt=none",
            s256(VERIFIER)
        )
    }

    fn header_of<B>(resp: &actix_web::dev::ServiceResponse<B>, name: header::HeaderName) -> Option<String> {
        resp.headers().get(name).map(|v| v.to_str().unwrap().to_string())
    }

    #[actix_web::test]
    async fn the_browser_endpoint_signs_in_once_with_a_launch_session() {
        let (_bvault, core, root) = new_unseal_test_bastion_vault("test_idp_browser_authorize").await;
        let ctx: &dyn VaultCtx = core.as_ref();
        let audit_dir = std::env::temp_dir().join(format!("bv-idp-browser-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&audit_dir).unwrap();
        let audit_log = audit_dir.join("audit.log");
        let options = std::collections::HashMap::from([("file_path".to_string(), audit_log.display().to_string())]);
        let device = crate::audit::AuditDeviceConfig {
            path: "idp-browser".into(),
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
        let mint = || v2(ctx, &token, "idp/oidc/launch-session", json!({"client_id": "app", "launch_id": LAUNCH_ID}));

        // The contract the host plants the cookie from.
        let minted = data(mint().await);
        let secret = minted["launch_session"].as_str().unwrap().to_string();
        assert_eq!(
            minted["cookie"],
            json!({"name": COOKIE_NAME, "path": "/", "secure": true, "http_only": true, "same_site": "Lax", "max_age": 120})
        );
        assert_eq!(minted["cookie_origin"], json!("https://vault.example.com"));
        assert_eq!(minted["authorization_endpoint"], json!(format!("{ISSUER}/authorize")));

        let app = init_service(
            App::new()
                .app_data(web::Data::new(core.clone()))
                .app_data(web::Data::new(TrustedProxies::default()))
                .configure(crate::init_service),
        )
        .await;
        let get = |cookie: Option<&str>, uri: &str| {
            let req = TestRequest::get().uri(uri);
            match cookie {
                Some(c) => req.cookie(Cookie::new(COOKIE_NAME, c.to_string())),
                None => req,
            }
            .to_request()
        };

        // The browser: a 302 to the registered URI with code and state.
        let resp = call_service(&app, get(Some(&secret), &authorize_uri(REDIRECT))).await;
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
        let resp = call_service(&app, get(Some(&secret), &authorize_uri(REDIRECT))).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(header_of(&resp, header::LOCATION).is_none());
        assert_eq!(header_of(&resp, header::CONTENT_TYPE).as_deref(), Some("text/plain; charset=utf-8"));
        assert_eq!(header_of(&resp, header::X_CONTENT_TYPE_OPTIONS).as_deref(), Some("nosniff"));
        let body = read_body(resp).await;
        assert!(body.starts_with(b"login_required: unknown or used launch session"), "{body:?}");

        // An unregistered redirect_uri is never a destination.
        let burned = data(mint().await)["launch_session"].as_str().unwrap().to_string();
        let resp = call_service(&app, get(Some(&burned), &authorize_uri("https://evil.example.com/cb"))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(header_of(&resp, header::LOCATION).is_none());
        assert!(read_body(resp).await.starts_with(b"invalid_request: redirect uri mismatch"));
        let resp = call_service(&app, get(Some(&burned), &authorize_uri(REDIRECT))).await;
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
        let fresh = data(mint().await)["launch_session"].as_str().unwrap().to_string();
        let repeated = format!("{}&client_id=other", authorize_uri(REDIRECT));
        let resp = call_service(&app, get(Some(&fresh), &repeated)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let two = format!("{COOKIE_NAME}={fresh}; {COOKIE_NAME}=other");
        let req = TestRequest::get().uri(&authorize_uri(REDIRECT)).insert_header((header::COOKIE, two)).to_request();
        assert_eq!(call_service(&app, req).await.status(), StatusCode::BAD_REQUEST);
        let resp = call_service(&app, get(Some(&fresh), &authorize_uri(REDIRECT))).await;
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
        let log = std::fs::read_to_string(&audit_log).unwrap();
        let events = |name: &str| {
            log.lines()
                .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                .filter(|e| e["type"] == "event" && e["request"]["path"] == name)
                .map(|e| e["request"]["data"].clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(events("idp.oidc.launch-session").len(), 3);
        assert_eq!(events("idp.oidc.launch-session-consumed").len(), 2);
        let refused: Vec<Value> = events("idp.oidc.refused").iter().map(|e| e["reason"].clone()).collect();
        for reason in ["unknown_or_used_launch_session", "redirect_uri_mismatch", "launch_session_missing"] {
            assert!(refused.contains(&json!(reason)), "{reason} in {refused:?}");
        }
        let id_token = issued["id_token"].as_str().unwrap();
        for value in [secret.as_str(), &burned, &fresh, LAUNCH_ID, &code, &client_secret, id_token] {
            assert!(!log.contains(value), "the audit log holds {value}");
        }
        let _ = std::fs::remove_dir_all(audit_dir);
    }
}
