//! Authorization witnesses: the type-level half of the HTTP layer's single
//! authorization point.
//!
//! Phase 1 of `roadmaps/formal-verification-and-type-driven-security.md`
//! (T31, S65). Before it, a `sys` handler that did its work inline was
//! privileged only because its body happened to start with a call to the
//! authorization helper; delete that line and the handler still compiled and
//! still served (finding F1). Here the call is an *argument*:
//!
//! - [`Authorized<R>`] is an actix extractor, so it runs before the handler
//!   body — no privileged code can precede it.
//! - Its fields are private to this module, so nothing else can construct one:
//!   a handler that holds an `Authorized<R>` provably ran after the chokepoint.
//! - It is generic over the route marker `R`, which carries the policy path
//!   *and* the operation, so the pair cannot drift apart the way two arguments
//!   to a function call can.
//! - [`privileged`] only accepts a handler whose **first** argument is
//!   `Authorized<R>` for the *same* `R`, and whose other arguments cannot read
//!   the request payload ([`PayloadFree`]). A handler that drops the witness
//!   does not fail at run time; its registration does not compile.
//!
//! `authorize_sys_request` stays the one place that clears a request — this
//! module adds no authorization logic of its own, it makes the existing call
//! unskippable — and its only caller is the [`FromRequest`] impl below.
//!
//! The guarantee is regression-tested by the doctests below (`make test-doc`):
//! the first compiles, and each `compile_fail` case differs from it by exactly
//! the mistake it names. The error codes are checked only on a nightly
//! toolchain; on stable, the compiling first case is what shows the others fail
//! for their stated reason and not for a typo.
//!
//! ```
//! use actix_web::{http::Method, HttpResponse};
//! use bv_server::{authz::{privileged, Authorized}, sys::SysSeal};
//!
//! async fn seal(_authz: Authorized<SysSeal>) -> HttpResponse {
//!     HttpResponse::NoContent().finish()
//! }
//!
//! let _route = privileged::<SysSeal, _, _>(Method::POST, seal);
//! ```
//!
//! A handler without the witness cannot be registered as privileged:
//!
//! ```compile_fail,E0277
//! use actix_web::{http::Method, HttpResponse};
//! use bv_server::{authz::{privileged, Authorized}, sys::SysSeal};
//!
//! async fn seal() -> HttpResponse {
//!     HttpResponse::NoContent().finish()
//! }
//!
//! let _route = privileged::<SysSeal, _, _>(Method::POST, seal);
//! ```
//!
//! Nor can a handler holding the witness for a *different* route:
//!
//! ```compile_fail,E0631
//! use actix_web::{http::Method, HttpResponse};
//! use bv_server::{authz::{privileged, Authorized}, sys::{SysBackup, SysSeal}};
//!
//! async fn seal(_authz: Authorized<SysBackup>) -> HttpResponse {
//!     HttpResponse::NoContent().finish()
//! }
//!
//! let _route = privileged::<SysSeal, _, _>(Method::POST, seal);
//! ```
//!
//! Nor one that reads the payload itself instead of through the witness, which
//! would race the witness for the body and see an empty one:
//!
//! ```compile_fail,E0277
//! use actix_web::{http::Method, web, HttpResponse};
//! use bv_server::{authz::{privileged, Authorized}, sys::SysRestore};
//!
//! async fn restore(_authz: Authorized<SysRestore>, _body: web::Bytes) -> HttpResponse {
//!     HttpResponse::NoContent().finish()
//! }
//!
//! let _route = privileged::<SysRestore, _, _>(Method::POST, restore);
//! ```
//!
//! And no code outside this module can forge a witness:
//!
//! ```compile_fail,E0451
//! use bv_server::{authz::Authorized, sys::SysSeal};
//!
//! let _forged = Authorized::<SysSeal> {
//!     policy_path: "sys/seal".to_string(),
//!     body: (),
//!     _route: std::marker::PhantomData,
//! };
//! ```

use std::{future::Future, marker::PhantomData, pin::Pin, sync::Arc};

use actix_web::{dev::Payload, http::Method, web, FromRequest, Handler, HttpRequest, HttpResponse, Responder, Route};
use serde_json::{Map, Value};

use crate::{core::Core, errors::RvError, logical::Operation, request_auth, HttpError};

/// The future every witness extractor returns.
pub type WitnessFuture<T> = Pin<Box<dyn Future<Output = Result<T, actix_web::Error>>>>;

/// Whether a refused request is written to the audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialAudit {
    /// The refusal is audited under the route's policy path and operation,
    /// with the request body HMAC-redacted like any other audit entry.
    Recorded,
    /// The refusal returns 403 with no audit entry of its own. The eight
    /// routes in this state (`seal`, `backup`, `restore`, `export`, `import`
    /// and the three cluster-membership calls) did not audit refusals before
    /// Phase 1 either; Phase 1 is a pure refactor, so it keeps that.
    NotRecorded,
}

/// Compile-time description of a privileged route.
///
/// Implementors are uninhabited marker types, one per route, declared with
/// `sys_route!` next to their handler. The trait binds the route to the policy
/// path *and* the operation it is judged on.
pub trait SysRoute: 'static {
    /// The operation the ACL judges.
    const OPERATION: Operation;

    /// The mount-relative policy path, as a template. Every `{name}` is
    /// replaced with the route segment captured under that name (empty when
    /// absent, exactly as the handlers' `unwrap_or("")` did), so a route with
    /// dynamic segments is judged on the path the caller actually asked for
    /// rather than on a prefix that would grant more than the operator wrote.
    /// The same string is what the route inventory prints, so the documented
    /// policy path and the judged one cannot differ.
    const POLICY_PATH: &'static str;

    /// Whether a refusal is audited.
    const DENIAL_AUDIT: DenialAudit;

    /// Whether the witness reads the request body ([`WithBody`]) before it
    /// authorizes, or leaves the payload untouched ([`NoBody`]).
    type Body: WitnessBody;
}

pub(crate) mod sealed {
    /// Closes [`super::WitnessBody`] and [`super::Witness`] to this crate.
    pub trait Sealed {}
}

/// How a witness treats the request body. Sealed: [`NoBody`] or [`WithBody`].
///
/// A route that needs its body has the witness read it, so the body is read
/// to completion — under the resource's `PayloadConfig` limit — *before* the
/// authorization check, exactly as when it was a handler argument, and the
/// refusal audit can carry it. The handler then takes it from the witness.
pub trait WitnessBody: sealed::Sealed + 'static {
    /// What the witness holds: `()` or the body bytes.
    type Stored: 'static;

    #[doc(hidden)]
    fn start(req: &HttpRequest, payload: &mut Payload) -> WitnessFuture<Self::Stored>;

    #[doc(hidden)]
    fn audit_map(stored: &Self::Stored) -> Option<Map<String, Value>>;
}

/// The witness leaves the payload unread.
pub enum NoBody {}

/// The witness reads the payload, as `web::Bytes` would, before authorizing.
pub enum WithBody {}

impl sealed::Sealed for NoBody {}
impl sealed::Sealed for WithBody {}

impl WitnessBody for NoBody {
    type Stored = ();

    fn start(_req: &HttpRequest, _payload: &mut Payload) -> WitnessFuture<()> {
        Box::pin(std::future::ready(Ok(())))
    }

    fn audit_map(_stored: &()) -> Option<Map<String, Value>> {
        None
    }
}

impl WitnessBody for WithBody {
    type Stored = web::Bytes;

    fn start(req: &HttpRequest, payload: &mut Payload) -> WitnessFuture<web::Bytes> {
        Box::pin(<web::Bytes as FromRequest>::from_request(req, payload))
    }

    fn audit_map(body: &web::Bytes) -> Option<Map<String, Value>> {
        body_to_audit_map(body)
    }
}

/// An extractor whose successful extraction is proof that the request was
/// authorized. Sealed: implemented only by [`Authorized`] and by the two
/// non-`sys` gates (`metrics_routes::ScrapeAuthorized`,
/// `rustion_webhook::SignatureVerified`).
pub trait Witness: FromRequest + sealed::Sealed + 'static {}

/// Proof that the current request cleared `pre_auth → check_token →
/// post_auth` for route `R`.
///
/// The private fields are the security property: no code outside this module
/// can construct one. `PhantomData<fn() -> R>` keeps the marker invariant
/// without making `Authorized` inherit `R`'s auto-traits.
pub struct Authorized<R: SysRoute> {
    policy_path: String,
    body: <R::Body as WitnessBody>::Stored,
    _route: PhantomData<fn() -> R>,
}

impl<R: SysRoute> Authorized<R> {
    /// The path the caller was actually cleared for.
    pub fn policy_path(&self) -> &str {
        &self.policy_path
    }
}

impl<R: SysRoute<Body = WithBody>> Authorized<R> {
    /// The request body — read before the request was authorized — consuming
    /// the witness. Build any `SysAuditCtx` from the witness first: it
    /// captures the policy path and the body to audit.
    pub fn into_body(self) -> web::Bytes {
        self.body
    }
}

impl<R: SysRoute> sealed::Sealed for Authorized<R> {}
impl<R: SysRoute> Witness for Authorized<R> {}

impl<R: SysRoute> FromRequest for Authorized<R> {
    type Error = actix_web::Error;
    type Future = WitnessFuture<Self>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let req = req.clone();
        // Started here, synchronously, so the witness owns the payload before
        // any other handler argument is extracted.
        let body = R::Body::start(&req, payload);
        Box::pin(async move {
            // The same extraction, and so the same 500 on a missing
            // registration, as the `web::Data<Arc<Core>>` argument every one
            // of these handlers takes.
            let core = web::Data::<Arc<Core>>::extract(&req).await?;
            let body = body.await?;
            let policy_path = expand_policy_path(R::POLICY_PATH, &req);

            match authorize_sys_request(&core, &req, &policy_path, R::OPERATION).await {
                Ok(()) => Ok(Authorized { policy_path, body, _route: PhantomData }),
                Err(err) => {
                    let err = HttpError(err);
                    if R::DENIAL_AUDIT == DenialAudit::Recorded {
                        // A rejected call against a privileged `sys` route is
                        // precisely the event an operator needs to see.
                        let audit = SysAuditCtx {
                            core: core.get_ref().clone(),
                            token: request_auth(&req).client_token,
                            body_for_audit: R::Body::audit_map(&body),
                            path: policy_path,
                            operation: R::OPERATION,
                        };
                        audit.emit(Some(err.to_string())).await;
                    }
                    Err(err.into())
                }
            }
        })
    }
}

/// Fill a [`SysRoute::POLICY_PATH`] template from the matched route segments.
///
/// A `{` with no closing `}` is copied verbatim, which names a path no policy
/// grants: a malformed template fails closed. A test checks every template in
/// the route table is well formed and names only captured segments.
pub(crate) fn expand_policy_path(template: &str, req: &HttpRequest) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let Some(len) = rest[open..].find('}') else {
            break;
        };
        out.push_str(&rest[..open]);
        let name = &rest[open + 1..open + len];
        out.push_str(req.match_info().get(name).unwrap_or(""));
        rest = &rest[open + len + 1..];
    }
    out.push_str(rest);
    out
}

/// The `{name}` segments a policy-path template substitutes.
#[cfg(test)]
pub(crate) fn template_params(template: &str) -> Vec<&str> {
    let mut params = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let Some(len) = rest[open..].find('}') else {
            break;
        };
        params.push(&rest[open + 1..open + len]);
        rest = &rest[open + len + 1..];
    }
    params
}

/// Run the real authentication + ACL gate for `path` / `operation` without
/// dispatching a logical request.
///
/// Nearly every `sys` handler reaches the policy engine through
/// [`crate::handle_request`], which crosses `TokenStore::pre_route` — the single
/// chokepoint that validates the presented token and asks the ACL whether the
/// operation is permitted. The handlers that do their work inline (binary
/// backup streams, plugin uploads, filesystem exports, cluster membership
/// calls) never call it, so before this gate existed they executed for *any*
/// caller who could reach the listener: `POST /v1/sys/backup` handed a full
/// vault dump to an anonymous client and `POST /v1/sys/seal` sealed the vault.
/// Running this first makes them behave exactly like a logical path — same
/// token validation, same policy evaluation, same `root_paths` sudo rules, same
/// denial bookkeeping.
///
/// `path` must be the mount-relative logical path (`"sys/backup"`), matching
/// what a policy author writes in `path "sys/backup" { ... }`.
///
/// Its one caller is `Authorized::from_request`; a test keeps it that way.
async fn authorize_sys_request(
    core: &web::Data<Arc<Core>>,
    req: &HttpRequest,
    path: &str,
    operation: Operation,
) -> Result<(), RvError> {
    let mut r = request_auth(req);
    r.path = path.to_string();
    r.operation = operation;
    // Namespaced callers must be judged in their own namespace, exactly as the
    // handle_request-backed siblings are.
    crate::sys::copy_namespace_header(req, &mut r);
    // ...and from the same source address, so a token carrying a
    // `token_bound_cidrs` restriction is judged against the address it
    // actually arrived from. `request_auth` builds a bare `Request` with no
    // connection, and `check_token` fails closed on an unknown address — so
    // without this a legitimately bound token would be refused on every
    // route that authorizes through this helper (`sys/backup`, `sys/seal`,
    // plugin uploads, filesystem exports, cluster membership). Mirrors the
    // resolution in `logical_routes::logical_request_handler_inner`.
    r.connection = sys_request_connection(req);

    let auth_module = core
        .module_manager()
        .get_module::<crate::modules::auth::AuthModule>("auth")
        .ok_or(RvError::ErrPermissionDenied)?;
    let token_store = auth_module.token_store.load_full().ok_or(RvError::ErrPermissionDenied)?;

    // `pre_route` runs pre_auth → check_token → post_auth (the ACL check in
    // `PolicyStore::post_auth`). `Ok(_)` means the caller is cleared.
    match crate::handler::Handler::pre_route(token_store.as_ref(), &mut r).await {
        Ok(_) => Ok(()),
        // A privileged route reached with no token at all is a permission
        // failure, not a malformed request: `ErrRequestClientTokenMissing`
        // renders as 400, which tells a client to fix its body when what it
        // actually needs to do is authenticate. Collapse it onto the 403 every
        // other refusal on these routes returns.
        Err(RvError::ErrRequestClientTokenMissing) => Err(RvError::ErrPermissionDenied),
        Err(e) => Err(e),
    }
}

/// The logical `Connection` for an inline `sys` handler, resolved the same way
/// [`crate::logical_routes`] resolves it for a routed request: the socket peer
/// from the on-connect hook (falling back to actix's `peer_addr` when that hook
/// did not run, as in the test harness), plus the trusted-proxy-aware derived
/// client IP.
///
/// Returns `None` only when no peer address can be determined at all, which
/// `TokenStore::check_token` treats as a refusal for any token that carries a
/// source-address binding.
fn sys_request_connection(req: &HttpRequest) -> Option<crate::logical::Connection> {
    let hook_conn = req.conn_data::<crate::Connection>();
    let socket_peer = hook_conn.map(|c| c.peer).or_else(|| req.peer_addr())?;

    let default_trusted;
    let trusted = match req.app_data::<web::Data<crate::client_ip::TrustedProxies>>() {
        Some(d) => d.get_ref(),
        None => {
            default_trusted = crate::client_ip::TrustedProxies::default();
            &default_trusted
        }
    };

    Some(crate::logical::Connection {
        peer_addr: socket_peer.to_string(),
        peer_addr_derived: crate::client_ip::ClientIp::resolve(socket_peer, req, trusted).derived.to_string(),
        peer_tls_cert: hook_conn.and_then(|c| c.tls.as_ref()).and_then(|tls| tls.client_cert_chain.clone()),
    })
}

/// Parse the bytes that will be audit-logged into a JSON map, when
/// possible. Audit redaction (HMAC-per-string-leaf) runs against this
/// map inside `AuditEntry::from_response`, so passwords, file_b64,
/// payloads, etc. are HMAC'd in the persisted entry without us having
/// to teach the audit layer anything about exchange/plugin schemas.
fn body_to_audit_map(body: &web::Bytes) -> Option<Map<String, Value>> {
    serde_json::from_slice::<Value>(body).ok().and_then(|v| v.as_object().cloned())
}

/// The audit context of one privileged `sys` call: everything the single
/// audit entry it produces needs, captured from the witness so the audited
/// path and operation are the ones the caller was authorized for.
pub(crate) struct SysAuditCtx {
    core: Arc<Core>,
    token: String,
    body_for_audit: Option<Map<String, Value>>,
    path: String,
    operation: Operation,
}

impl SysAuditCtx {
    /// Build before the handler body consumes the request body.
    pub(crate) fn new<R: SysRoute>(authz: &Authorized<R>, req: &HttpRequest, core: &web::Data<Arc<Core>>) -> Self {
        Self {
            core: core.get_ref().clone(),
            token: request_auth(req).client_token,
            body_for_audit: R::Body::audit_map(&authz.body),
            path: authz.policy_path.clone(),
            operation: R::OPERATION,
        }
    }

    /// Emit the call's one audit entry, success or failure.
    pub(crate) async fn finish(self, result: &Result<HttpResponse, HttpError>) {
        self.emit(result.as_ref().err().map(|e| format!("{e}"))).await;
    }

    async fn emit(&self, error: Option<String>) {
        crate::audit::emit_sys_audit(
            self.core.as_ref(),
            &self.token,
            &self.path,
            self.operation,
            self.body_for_audit.clone(),
            error.as_deref(),
        )
        .await;
    }
}

/// Extractors that never read the request payload, and so may follow a
/// witness in a guarded handler's argument list. Deliberately short: a
/// payload-reading extractor (`web::Bytes`, `web::Json`, `String`,
/// `web::Payload`) there would race the witness for the body.
pub trait PayloadFree: FromRequest {}

impl PayloadFree for HttpRequest {}
impl<T: ?Sized + 'static> PayloadFree for web::Data<T> {}

/// Implemented for a handler's argument tuple when its first element is the
/// witness `W` and every other element is [`PayloadFree`].
pub trait StartsWith<W: Witness> {}

macro_rules! starts_with {
    ($($rest:ident),*) => {
        impl<W: Witness, $($rest: PayloadFree),*> StartsWith<W> for (W, $($rest,)*) {}
    };
}

starts_with!();
starts_with!(A);
starts_with!(A, B);
starts_with!(A, B, C);
starts_with!(A, B, C, D);
starts_with!(A, B, C, D, E);

/// Register a handler that cannot be *written* without witness `W` as its
/// first argument.
///
/// The enforcement is `Args: StartsWith<W>`: actix implements `Handler<Args>`
/// for a function only with `Args` equal to its argument tuple, so a handler
/// missing the witness in position 0 does not typecheck at this call site.
pub fn guarded<W, H, Args>(method: Method, handler: H) -> Route
where
    W: Witness,
    H: Handler<Args>,
    Args: FromRequest + StartsWith<W> + 'static,
    H::Output: Responder + 'static,
{
    web::method(method).to(handler)
}

/// Register a privileged `sys` handler: one whose first argument is
/// [`Authorized<R>`] for exactly this `R`.
pub fn privileged<R, H, Args>(method: Method, handler: H) -> Route
where
    R: SysRoute,
    H: Handler<Args>,
    Args: FromRequest + StartsWith<Authorized<R>> + 'static,
    H::Output: Responder + 'static,
{
    guarded::<Authorized<R>, H, Args>(method, handler)
}

/// Declare a privileged route marker next to its handler.
///
/// ```text
/// sys_route! {
///     /// `POST /v{1,2}/sys/seal` — seals the vault.
///     SysSeal { op: Write, path: "sys/seal", body: NoBody, denial: NotRecorded }
/// }
/// ```
macro_rules! sys_route {
    ($( $(#[$doc:meta])* $name:ident { op: $op:ident, path: $path:literal, body: $body:ident, denial: $denial:ident } )+) => {
        $(
            $(#[$doc])*
            pub enum $name {}

            impl $crate::authz::SysRoute for $name {
                const OPERATION: $crate::logical::Operation = $crate::logical::Operation::$op;
                const POLICY_PATH: &'static str = $path;
                const DENIAL_AUDIT: $crate::authz::DenialAudit = $crate::authz::DenialAudit::$denial;
                type Body = $crate::authz::$body;
            }
        )+
    };
}

pub(crate) use sys_route;

#[cfg(test)]
mod tests {
    use actix_web::test::TestRequest;
    use serde_json::{json, Value};

    use super::{expand_policy_path, template_params};
    use crate::test_utils::TestHttpServer;

    #[test]
    fn templates_expand_exactly_like_the_handlers_format_calls_did() {
        let req = TestRequest::default()
            .param("name", "xca-import")
            .param("version", "1.2.0")
            .param("sha256", "ab")
            .to_http_request();
        assert_eq!(expand_policy_path("sys/plugins/{name}/config", &req), "sys/plugins/xca-import/config");
        assert_eq!(
            expand_policy_path("sys/plugins/{name}/{version}/asset/{sha256}", &req),
            format!("sys/plugins/{}/{}/asset/{}", "xca-import", "1.2.0", "ab"),
        );
        assert_eq!(expand_policy_path("sys/seal", &req), "sys/seal");
        // A segment the route did not capture becomes empty — the
        // `unwrap_or("")` every handler used — never the template text.
        assert_eq!(expand_policy_path("sys/scheduled-exports/{id}", &req), "sys/scheduled-exports/");
    }

    #[test]
    fn a_malformed_template_fails_closed_rather_than_widening() {
        let req = TestRequest::default().param("name", "x").to_http_request();
        assert_eq!(expand_policy_path("sys/plugins/{name", &req), "sys/plugins/{name");
        assert_eq!(template_params("sys/plugins/{name"), Vec::<&str>::new());
        assert_eq!(template_params("sys/plugins/{name}/versions/{version}"), vec!["name", "version"]);
    }

    /// `authorize_sys_request` must stay the single chokepoint, called from one
    /// place: the witness. A second caller is a second authorization path,
    /// which is how a handler ends up authorized on a path it does not act on.
    #[test]
    fn authorize_sys_request_has_exactly_one_caller() {
        let mut callers = Vec::new();
        for (file, source) in crate::routes::tests::crate_sources() {
            for (line_no, code) in crate::routes::tests::production_part(&source).lines().enumerate() {
                if code.contains("authorize_sys_request(") && !code.contains("fn authorize_sys_request(") {
                    callers.push(format!("{file}:{}", line_no + 1));
                }
            }
        }
        assert_eq!(callers.len(), 1, "expected only the witness to call authorize_sys_request: {callers:?}");
        assert!(callers[0].starts_with("authz.rs:"), "{callers:?}");
    }

    /// Phase 1 DoD: for five sampled privileged routes, an unauthenticated
    /// request returns 403 *and* appears on the denial audit trail, under the
    /// path and operation the route is judged on.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn unauthenticated_privileged_requests_are_refused_and_audited() {
        let mut server = TestHttpServer::new("test_authz_denial_audit", true).await;
        server.token = server.root_token.clone();

        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let log_path = std::env::temp_dir().join(format!("bv-authz-denials-{nanos}.log"));
        let (status, resp) = server
            .write(
                "sys/audit/denials",
                json!({ "type": "file", "options": { "file_path": log_path.display().to_string() } })
                    .as_object()
                    .cloned(),
                None,
            )
            .unwrap();
        assert!(status == 200 || status == 204, "enabling the audit device failed: {status} {resp:?}");

        let sampled = [
            ("GET", "sys/plugins", "sys/plugins", "list"),
            ("GET", "sys/scheduled-exports", "sys/scheduled-exports", "list"),
            ("POST", "sys/exchange/export", "sys/exchange/export", "write"),
            ("GET", "sys/plugins/quarantine", "sys/plugins/quarantine", "read"),
            ("DELETE", "sys/plugins/some-plugin/grants", "sys/plugins/some-plugin/grants", "delete"),
        ];
        for (method, path, _, _) in sampled {
            let (status, resp) = server.request(method, path, None, Some(""), None).unwrap();
            assert_eq!(status, 403, "{method} {path} must refuse an anonymous caller: {resp:?}");
        }

        let log = std::fs::read_to_string(&log_path).unwrap();
        let entries: Vec<Value> = log.lines().map(|l| serde_json::from_str(l).expect("audit line is JSON")).collect();
        for (method, _, policy_path, operation) in sampled {
            assert!(
                entries.iter().any(|e| e["request"]["path"] == policy_path
                    && e["request"]["operation"] == operation
                    && e["error"].as_str().is_some_and(|s| !s.is_empty())),
                "{method} {policy_path} refusal is missing from the audit trail: {entries:?}"
            );
        }
        let _ = std::fs::remove_file(&log_path);
    }
}
