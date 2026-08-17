//! This crate handles almost everything related to BastionVault's HTTP(S) server, including basic
//! connection, HTTP request reading, HTTP response writing, data encoding/decoding, TLS stuffs, etc.
//! This crate utilize `actix_web` crate as the underlying provider.
//!
//! # Where it sits
//!
//! Tier 4 of the workspace decomposition, and the first crate that sits
//! **above** [`bastion_vault`] rather than below it. That direction is not a
//! compromise — the HTTP surface is the assembly layer: it mounts the kernel,
//! the plugin runtime, the exchange, the backup and the scheduled-export
//! subsystems, and something has to name all of them. What it buys is that
//! `actix-web` and `actix-tls` are no longer dependencies of the library, so
//! the Tauri host and every consumer that embeds a vault without serving HTTP
//! stops building a web framework.
//!
//! `bastion_vault` keeps a **dev-dependency** on this crate so
//! `test_utils::TestHttpServer` — and the ~50 root-crate tests that drive a
//! real server through it — stay exactly where they are. Cargo permits
//! dev-dependency cycles; see roadmaps/workspace-decomposition.md § Phase 4.
//!
//! [`bastion_vault`]: bastion_vault

use std::{any::Any, net::SocketAddr, sync::Arc};

use actix_tls::accept::rustls_0_23::TlsStream as RustlsTlsStream;
use actix_web::{
    cookie::Cookie,
    dev::Extensions,
    rt::net::TcpStream,
    web,
    HttpRequest,
    HttpResponse,
    ResponseError,
    http::{StatusCode, header},
};
use rustls::pki_types::CertificateDer;
use serde::Serialize;
use serde_json::{json, Map, Value};

// The library, under the names this code has always spelled them. Private:
// none of it leaks into this crate's public API, and every one of these
// resolves the `crate::<name>::` paths the moved files still use. Same alias
// preamble the Phase 3 engine crates carry, one tier up.
// `logical` and `metrics` are here even though this crate also has route
// modules by those names — the routes were renamed `logical_routes` and
// `metrics_routes` so the library's meaning wins. `bv-engine-pki` hit the same
// collision with `storage` in Phase 3 and resolved it the other way; either
// works, and the collision is a compile error, never a silent shadow.
use bastion_vault::{
    audit, backup, config, core, errors, exchange, handler, kernel_api, logical, metrics, modules,
    plugins, scheduled_exports, server_info,
};

// `bv_error_response_status!` and friends are `#[macro_export]`ed by
// `bv-errors`, which places them at *that* crate's root; the call sites in
// this crate reach them as `crate::bv_error_*`.
pub use bastion_vault::{bv_error_response, bv_error_response_status, bv_error_string};

use crate::{core::Core, errors::RvError, logical::Request};

pub mod batch;
pub mod client_ip;
/// The `/v1/{path}` logical catch-all routes. Named `logical_routes`, not
/// `logical`, so `crate::logical` unambiguously means the library's
/// request/response types — this crate needs both.
pub mod logical_routes;
/// The `/metrics` Prometheus scrape endpoint. Named `metrics_routes` for the
/// same reason `logical_routes` is: `crate::metrics` is the library's.
pub mod metrics_routes;
pub mod middleware;
pub mod proxy_protocol;
pub mod rustion_webhook;
pub mod sys;

/// The in-process HTTP test harness, behind a feature so it never reaches a
/// shipped build. `bastion_vault` dev-depends on this crate with the feature
/// on — a dev-dependency cycle, which cargo allows — so its ~50 tests that
/// drive a real server keep working unchanged.
#[cfg(feature = "test-support")]
pub mod test_support;

/// `sys.rs`'s cluster-peer test builds a `crate::api::Client`.
#[cfg(test)]
use bastion_vault::api;

/// The fixtures this crate's own tests use, gathered under the name they had
/// when these files were `bastion_vault::http`. `TestHttpServer` is local
/// (it configures this crate's routes); everything else comes from the
/// library's `test-support` feature.
#[cfg(test)]
mod test_utils {
    pub use bastion_vault::test_utils::*;

    pub use crate::test_support::TestHttpServer;
}

pub const AUTH_COOKIE_NAME: &str = "token";
pub const AUTH_HEADER_NAME: &str = "X-BastionVault-Token";
pub const VAULT_AUTH_HEADER_NAME: &str = "X-Vault-Token";

#[derive(Debug, Clone)]
pub struct TlsClientInfo {
    pub client_cert_chain: Option<Vec<CertificateDer<'static>>>,
}

impl TlsClientInfo {
    pub fn new() -> Self {
        TlsClientInfo { client_cert_chain: None }
    }
}

#[derive(Debug, Clone)]
pub struct Connection {
    pub bind: SocketAddr,
    pub peer: SocketAddr,
    pub ttl: Option<u32>,
    pub tls: Option<TlsClientInfo>,
}

impl Connection {
    pub fn new() -> Self {
        Self {
            bind: SocketAddr::from(([0, 0, 0, 0], 8080)),
            peer: SocketAddr::from(([127, 0, 0, 1], 8888)),
            ttl: None,
            tls: None,
        }
    }
}

pub fn request_on_connect_handler(conn: &dyn Any, ext: &mut Extensions) {
    if let Some(tls_stream) = conn.downcast_ref::<RustlsTlsStream<TcpStream>>() {
        let (socket, session) = tls_stream.get_ref();
        let peer_addr = socket.peer_addr();
        if peer_addr.is_err() {
            return;
        }

        let cert_chain = session.peer_certificates().map(|certs| certs.to_vec());

        ext.insert(Connection {
            bind: socket.local_addr().unwrap(),
            peer: peer_addr.unwrap(),
            ttl: socket.ttl().ok(),
            tls: Some(TlsClientInfo { client_cert_chain: cert_chain }),
        });
    } else if let Some(socket) = conn.downcast_ref::<TcpStream>() {
        let peer_addr = socket.peer_addr();
        if peer_addr.is_err() {
            return;
        }

        ext.insert(Connection {
            bind: socket.local_addr().unwrap(),
            peer: peer_addr.unwrap(),
            ttl: socket.ttl().ok(),
            tls: None,
        });
    } else {
        unreachable!("socket should be TLS or plaintext");
    }
}

pub fn init_service(cfg: &mut web::ServiceConfig) {
    sys::init_sys_service(cfg);
    // Must precede the `/v1/{path:.*}` logical catch-all so the Rustion
    // recording.ready webhook is handled by its purpose-built receiver
    // (raw body + X-Rustion-Signature header) rather than the generic
    // logical plumbing, which can neither recover the signed bytes nor
    // read the signature header.
    rustion_webhook::init_rustion_webhook_service(cfg);
    logical_routes::init_logical_service(cfg);
    metrics_routes::init_metrics_service(cfg);
}

/// The HTTP layer's error type: a newtype around [`RvError`].
///
/// `RvError` lives in the `bv-errors` crate so that the Tier 0 substrate does
/// not depend on a web framework, and `ResponseError` comes from `actix-web`.
/// Both are therefore foreign to this crate, and the orphan rule forbids
/// `impl ResponseError for RvError` here. Wrapping it locally is the standard
/// way out, and it also confines actix to the assembly layer, which is where
/// Phase 4 of the decomposition wants it.
///
/// Handlers return `Result<HttpResponse, HttpError>`. The `From<RvError>` impl
/// below means `?` on any `RvError`-returning call still works untouched; only
/// explicit `return Err(e)` sites need `.into()`, because `return` does not
/// apply `From`.
pub struct HttpError(pub RvError);

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

// Both formats forward to the wrapped error rather than being derived, so the
// wrapper is invisible in output. `Debug` matters as much as `Display` here:
// actix's error middleware logs the boxed `ResponseError` with `{:?}`, and a
// derived impl would have rewritten every such log line from
// `ErrPermissionDenied` to `HttpError(ErrPermissionDenied)`.
impl std::fmt::Debug for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl std::error::Error for HttpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(&self.0)
    }
}

impl<E: Into<RvError>> From<E> for HttpError {
    fn from(err: E) -> Self {
        HttpError(err.into())
    }
}

impl HttpError {
    /// The wrapped error, for the handful of call sites that need to inspect or
    /// re-wrap it rather than return it.
    pub fn into_inner(self) -> RvError {
        self.0
    }
}

impl ResponseError for HttpError {
    // builds the actual response to send back when an error occurs
    fn error_response(&self) -> HttpResponse {
        // `response_status()` returns a bare u16 so `bv-errors` stays free of any
        // web framework (Tier 0 of the decomposition). Mapping it to actix's
        // `StatusCode` is this layer's job. `from_u16` only rejects codes outside
        // 100..600, which the table cannot produce, so the fallback is unreachable
        // -- it is there so a future bad entry degrades to a 500 instead of panicking.
        let mut status =
            StatusCode::from_u16(self.0.response_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let text: String;
        if let RvError::ErrResponse(resp_text) = &self.0 {
            status = StatusCode::from_u16(400).unwrap();
            text = resp_text.clone();
        } else if let RvError::ErrResponseStatus(status_code, resp_text) = &self.0 {
            status = StatusCode::from_u16(*status_code).unwrap();
            text = resp_text.clone();
        } else {
            text = self.0.to_string();
        }
        HttpResponse::build(status).json(json!({ "error": text }))
    }
}

pub fn get_token_from_req(req: &HttpRequest) -> Result<String, RvError> {
    if let Some(token) = req.headers().get(AUTH_HEADER_NAME) {
        return Ok(token.to_str().map_err(|e| RvError::ErrHeaderValueNotUtf8(e.to_string()))?.to_string());
    } else if let Some(vault_token) = req.headers().get(VAULT_AUTH_HEADER_NAME) {
        return Ok(vault_token.to_str().map_err(|e| RvError::ErrHeaderValueNotUtf8(e.to_string()))?.to_string());
    } else if let Some(auth) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            if auth_str.starts_with("Bearer ") {
                return Ok(auth_str.trim_start_matches("Bearer ").to_string());
            }
        }
    } else if let Some(cookie_token) = req.cookie(AUTH_COOKIE_NAME) {
        return Ok(cookie_token.value().to_string());
    }

    Err(RvError::ErrResponse("missing client token".to_string()))
}

pub fn request_auth(req: &HttpRequest) -> Request {
    let mut r = Request::default();
    if let Ok(token) = get_token_from_req(req) {
        r.client_token = token;
    }
    r
}

pub fn response_error(status: StatusCode, msg: &str) -> HttpResponse {
    if msg.is_empty() {
        HttpResponse::build(status).finish()
    } else {
        let err_json = json!({ "error": msg.to_string() });
        HttpResponse::build(status).json(err_json)
    }
}

pub fn response_ok(cookie: Option<Cookie>, body: Option<&Map<String, Value>>) -> HttpResponse {
    if body.is_none() {
        let mut resp = HttpResponse::NoContent();
        if cookie.is_some() {
            resp.cookie(cookie.unwrap());
        }
        resp.finish()
    } else {
        let mut resp = HttpResponse::Ok();
        if cookie.is_some() {
            resp.cookie(cookie.unwrap());
        }
        resp.json(body.as_ref().unwrap())
    }
}

pub fn response_json<T: Serialize>(status: StatusCode, cookie: Option<Cookie>, body: T) -> HttpResponse {
    let mut resp = HttpResponse::build(status);
    if cookie.is_some() {
        resp.cookie(cookie.unwrap());
    }
    resp.json(body)
}

pub fn response_json_ok<T: Serialize>(cookie: Option<Cookie>, body: T) -> HttpResponse {
    response_json(StatusCode::OK, cookie, body)
}

pub async fn handle_request(core: web::Data<Arc<Core>>, req: &mut Request) -> Result<HttpResponse, HttpError> {
    #[cfg(feature = "sync_handler")]
    let resp = core.handle_request(req)?;
    #[cfg(not(feature = "sync_handler"))]
    let resp = core.handle_request(req).await?;
    if resp.is_none() {
        Ok(response_ok(None, None))
    } else {
        let data = resp.unwrap().data;
        if data.is_none() {
            Ok(response_ok(None, None))
        } else {
            Ok(response_ok(None, data.as_ref()))
        }
    }
}
