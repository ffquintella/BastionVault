//! Web Application Connect, proxy mode — the listener
//! (features/web-application-connect.md §10; T106 steps 2 and 3).
//!
//! One listener per web session, bound to `127.0.0.1` on an ephemeral port.
//! The session's webview is pointed at it with `proxy_url`, so every load the
//! window makes arrives here as an HTTP `CONNECT`.
//!
//! What it does with one, and nothing else:
//!
//! * **`CONNECT` inside the session's termination scope** — answered `200`,
//!   TLS terminated with the session leaf for that host
//!   ([`super::web_proxy_ca`]), and the inner HTTP/1.1 requests read. The
//!   upstream origin is dialled and verified first
//!   ([`super::web_proxy_upstream`]): if its certificate is not admitted the
//!   `CONNECT` fails and nothing is ever written into the tunnel. Requests
//!   stream through untouched except the recipe's submit request, where the
//!   placeholder becomes the real secret
//!   ([`super::web_proxy::substitute_submit`]) and that request's response is
//!   scrubbed back ([`super::web_proxy::scrub_response`]). `Alt-Svc` is
//!   stripped from every terminated response, so the page cannot be steered
//!   onto HTTP/3 around the proxy. `101` upgrades (WebSocket) are relayed
//!   byte for byte.
//! * **`CONNECT` outside the scope** — blind-tunnelled, never terminated, so
//!   sub-resources from other hosts load as they do today and the webview
//!   validates them itself. Refusing them was rejected: an egress allow-list
//!   is a separate control, and it would break CDN-backed applications.
//! * **Anything else** — refused with an error status and closed. There is no
//!   absolute-form proxying: a plain `http://` load arrives as
//!   `CONNECT host:80`, which the scope (https origins, host *and* port) does
//!   not match, so it is tunnelled, not terminated.
//!
//! Nothing here logs the secret, the placeholder, a request or response body,
//! or a path — only `host:port` and fixed check names (`proxy_*`), as §11
//! requires.
//!
//! This file is Tauri-free: the platform wiring (T106 step 4) owns
//! [`WebProxy::proxy_url`], [`WebProxy::ca_pin`] and [`WebProxy::leaf_pin`].

// See the note in `web_proxy.rs`: nothing constructs a session proxy until
// the platform wiring of T106 step 4. The tests below drive all of it.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bastion_vault::utils::tls_pin::{PinSet, SpkiPin};
use bytes::{Buf, Bytes};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::header::{
    HeaderMap, HeaderName, HeaderValue, ACCEPT_ENCODING, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE,
    HOST, TRANSFER_ENCODING, UPGRADE,
};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::Zeroizing;

use super::web_proxy::{
    bare_host, is_stripped_response_header, scrub_response, substitute_submit, OutgoingRequest, RefuseReason,
    SecretBody, SessionSecret, SubmitTarget, Substitution, TerminationScope,
};
use super::web_proxy_ca::SessionCa;
use super::web_proxy_upstream::UpstreamVerifier;

/// Largest `CONNECT` request head the listener reads before giving up. The
/// client is the session's own webview on loopback; this is a bound, not a
/// budget.
const MAX_HEAD: usize = 8 * 1024;

/// The submit request's body is buffered so the placeholder rule can be
/// applied to it. A login form is a few hundred bytes; anything past this is
/// refused rather than forwarded unexamined.
const MAX_SUBMIT_REQUEST_BODY: usize = 1024 * 1024;

/// The substituted request's response is buffered so it can be scrubbed.
/// Beyond this the response is refused: streaming it would mean shipping the
/// secret to the page unscrubbed.
const MAX_SCRUBBED_RESPONSE_BODY: usize = 8 * 1024 * 1024;

const HEAD_TIMEOUT: Duration = Duration::from_secs(15);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const TLS_TIMEOUT: Duration = Duration::from_secs(20);

const CONNECTION_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

/// Hop-by-hop headers (RFC 9110 §7.6.1), which a gateway must not forward.
/// `connection` and `upgrade` are kept on an upgrade exchange, where they
/// are the mechanism rather than framing noise.
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// What the proxy may put into the outgoing submit request. Absent for a
/// session that terminates TLS but releases no credential (an `open`-mode
/// window behind the proxy, or a header-injection profile later on).
pub struct ProxyInjection {
    pub secret: SessionSecret,
    pub target: SubmitTarget,
}

/// One session's proxy, as the launch path describes it.
pub struct ProxyConfig {
    /// The https origins this session terminates. Everything else is
    /// tunnelled.
    pub scope: TerminationScope,
    pub injection: Option<ProxyInjection>,
    /// The profile's `tls_pin_sha256`, as the override on the upstream leg.
    pub pins: PinSet,
}

/// A running session proxy. Dropping it stops the listener; connections
/// already open end with it.
pub struct WebProxy {
    addr: SocketAddr,
    ca: Arc<SessionCa>,
    terminated: Arc<Mutex<BTreeSet<(String, u16)>>>,
    stop: Mutex<Option<oneshot::Sender<()>>>,
}

impl WebProxy {
    /// Mint the session's certificates, bind the loopback listener and start
    /// accepting. Must be called on a tokio runtime; the accept loop is
    /// spawned onto it.
    pub async fn start(config: ProxyConfig) -> Result<Self, String> {
        if config.scope.is_empty() {
            return Err("web proxy: the session terminates no origin".to_string());
        }
        if let Some(injection) = &config.injection {
            let origin = injection.target.origin();
            if !config.scope.terminates(origin.host(), origin.port()) {
                // Otherwise the submit request would leave through a blind
                // tunnel and the placeholder — not the password — would reach
                // the application. Fail at launch, visibly, not at sign-in.
                return Err(format!(
                    "web proxy: the submit target {}:{} is not one of the session's terminated origins",
                    origin.host(),
                    origin.port()
                ));
            }
        }

        let ca = Arc::new(SessionCa::mint(&config.scope.hosts())?);
        let verifier = UpstreamVerifier::new(config.pins.clone())?;
        let connector = TlsConnector::from(verifier.client_config()?);

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|e| format!("web proxy: could not bind a loopback listener: {e}"))?;
        let addr = listener.local_addr().map_err(|e| format!("web proxy: listener address: {e}"))?;

        let terminated = Arc::new(Mutex::new(BTreeSet::new()));
        let ctx = Arc::new(ProxyCtx {
            scope: config.scope,
            injection: config.injection,
            ca: Arc::clone(&ca),
            connector,
            terminated: Arc::clone(&terminated),
        });
        let (stop_tx, stop_rx) = oneshot::channel();
        tokio::spawn(accept_loop(listener, ctx, stop_rx));
        log::debug!("web proxy: listening on {addr}");
        Ok(Self { addr, ca, terminated, stop: Mutex::new(Some(stop_tx)) })
    }

    /// What `proxy_url` is set to on the session window.
    pub fn proxy_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The session CA's DER certificate — the Linux shim registers it per
    /// host before the first load.
    pub fn ca_der(&self) -> &[u8] {
        self.ca.ca_der()
    }

    /// The two pins the Phase 4 gate is given for this session: the CA's
    /// (issuer path, host-bound) and the leaves' shared key (leaf path).
    pub fn ca_pin(&self) -> SpkiPin {
        self.ca.ca_pin()
    }

    pub fn leaf_pin(&self) -> SpkiPin {
        self.ca.leaf_pin()
    }

    /// Whether the proxy has actually terminated this origin. The bypass
    /// check (T106 step 6) reads it: the recipe fills only once the proxy
    /// says it owns the page's origin.
    pub fn has_terminated(&self, host: &str, port: u16) -> bool {
        self.terminated.lock().unwrap_or_else(|p| p.into_inner()).contains(&(host.to_ascii_lowercase(), port))
    }

    /// Stop accepting. Idempotent; [`Drop`] does the same.
    pub fn shutdown(&self) {
        if let Some(tx) = self.stop.lock().unwrap_or_else(|p| p.into_inner()).take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for WebProxy {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct ProxyCtx {
    scope: TerminationScope,
    injection: Option<ProxyInjection>,
    ca: Arc<SessionCa>,
    connector: TlsConnector,
    terminated: Arc<Mutex<BTreeSet<(String, u16)>>>,
}

impl ProxyCtx {
    fn note_terminated(&self, host: &str, port: u16) {
        self.terminated.lock().unwrap_or_else(|p| p.into_inner()).insert((host.to_ascii_lowercase(), port));
    }
}

async fn accept_loop(listener: TcpListener, ctx: Arc<ProxyCtx>, mut stop: oneshot::Receiver<()>) {
    loop {
        tokio::select! {
            _ = &mut stop => break,
            accepted = listener.accept() => match accepted {
                Ok((sock, peer)) => {
                    // The listener is bound to 127.0.0.1, so this can only
                    // fail if the OS handed us something unexpected.
                    if !peer.ip().is_loopback() {
                        log::warn!("web proxy: refused a non-loopback peer");
                        continue;
                    }
                    let ctx = Arc::clone(&ctx);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(sock, ctx).await {
                            log::debug!("web proxy: {e}");
                        }
                    });
                }
                Err(e) => {
                    log::warn!("web proxy: accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
        }
    }
    log::debug!("web proxy: listener stopped");
}

async fn handle_connection(sock: TcpStream, ctx: Arc<ProxyCtx>) -> Result<(), String> {
    let _ = sock.set_nodelay(true);
    let mut client = BufReader::new(sock);

    let head = match timeout(HEAD_TIMEOUT, read_head(&mut client)).await {
        Err(_) => return refuse(&mut client, StatusCode::REQUEST_TIMEOUT, "proxy_head_timeout").await,
        Ok(Err(check)) => return refuse(&mut client, StatusCode::BAD_REQUEST, check).await,
        Ok(Ok(head)) => head,
    };

    let (host, port) = match parse_connect(&head) {
        Ok(authority) => authority,
        Err(PrefaceError::NotConnect) => {
            return refuse(&mut client, StatusCode::METHOD_NOT_ALLOWED, "proxy_connect_only").await;
        }
        Err(PrefaceError::Malformed(check)) => return refuse(&mut client, StatusCode::BAD_REQUEST, check).await,
    };

    if ctx.scope.terminates(&host, port) {
        terminate(client, host, port, ctx).await
    } else {
        tunnel(client, host, port).await
    }
}

/// Blind tunnel: no termination, no inspection, the webview validates the
/// far end itself.
async fn tunnel(mut client: BufReader<TcpStream>, host: String, port: u16) -> Result<(), String> {
    let mut upstream = match dial(&host, port).await {
        Ok(stream) => stream,
        Err(e) => {
            log::debug!("web proxy: tunnel to {host}:{port} failed: {e}");
            return refuse(&mut client, StatusCode::BAD_GATEWAY, "proxy_tunnel_unreachable").await;
        }
    };
    client.write_all(CONNECTION_ESTABLISHED).await.map_err(|e| format!("tunnel reply to {host}:{port}: {e}"))?;
    client.flush().await.map_err(|e| format!("tunnel reply to {host}:{port}: {e}"))?;
    match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("tunnel to {host}:{port} ended: {e}")),
    }
}

/// Terminate TLS for a session origin and proxy its HTTP/1.1 requests.
async fn terminate(
    mut client: BufReader<TcpStream>,
    host: String,
    port: u16,
    ctx: Arc<ProxyCtx>,
) -> Result<(), String> {
    let server_config = match ctx.ca.server_config(&host) {
        Ok(config) => config,
        Err(e) => {
            log::warn!("web proxy: {e}");
            return refuse(&mut client, StatusCode::BAD_GATEWAY, "proxy_no_session_certificate").await;
        }
    };

    // The upstream leg is established and verified *before* the tunnel is
    // opened, so a server whose certificate is not admitted never gets a
    // request — and the webview sees the refusal as a failed CONNECT rather
    // than as a page error inside a tunnel we vouched for.
    let upstream = match connect_upstream(&ctx, &host, port).await {
        Ok(stream) => stream,
        Err(e) => {
            log::warn!("web proxy: upstream {host}:{port} not established ({e})");
            return refuse(&mut client, StatusCode::BAD_GATEWAY, "proxy_upstream_unavailable").await;
        }
    };

    // Recorded before the `200` goes out: from the webview's point of view
    // the origin is this proxy's the moment the tunnel opens, and the bypass
    // check must never see "not terminated" for a page that is already
    // loading through it.
    ctx.note_terminated(&host, port);
    client.write_all(CONNECTION_ESTABLISHED).await.map_err(|e| format!("CONNECT reply to {host}:{port}: {e}"))?;
    client.flush().await.map_err(|e| format!("CONNECT reply to {host}:{port}: {e}"))?;

    let tls = TlsAcceptor::from(server_config)
        .accept(client)
        .await
        .map_err(|e| format!("terminated handshake with the webview for {host}:{port} failed: {e}"))?;

    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(upstream))
        .await
        .map_err(|e| format!("upstream HTTP/1.1 handshake with {host}:{port} failed: {e}"))?;
    let conn_label = format!("{host}:{port}");
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            log::debug!("web proxy: upstream connection to {conn_label} ended: {e}");
        }
    });

    let label = format!("{host}:{port}");
    let sender = Arc::new(AsyncMutex::new(sender));
    let host: Arc<str> = Arc::from(host.as_str());
    let service = service_fn(move |req| {
        let ctx = Arc::clone(&ctx);
        let sender = Arc::clone(&sender);
        let host = Arc::clone(&host);
        async move { Ok::<_, Infallible>(proxy_request(req, ctx, sender, host, port).await) }
    });

    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(tls), service)
        .with_upgrades()
        .await
        .map_err(|e| format!("terminated connection to {label} ended: {e}"))
}

/// A chunk of a proxied body. The secret-carrying variant owns its bytes and
/// zeroizes them when hyper drops it after writing them to the upstream.
enum Chunk {
    Plain(Bytes),
    Secret { body: SecretBody, pos: usize },
}

impl Buf for Chunk {
    fn remaining(&self) -> usize {
        match self {
            Self::Plain(bytes) => bytes.remaining(),
            Self::Secret { body, pos } => body.as_slice().len() - pos,
        }
    }

    fn chunk(&self) -> &[u8] {
        match self {
            Self::Plain(bytes) => bytes.chunk(),
            Self::Secret { body, pos } => &body.as_slice()[*pos..],
        }
    }

    fn advance(&mut self, cnt: usize) {
        match self {
            Self::Plain(bytes) => bytes.advance(cnt),
            Self::Secret { body, pos } => {
                assert!(cnt <= body.as_slice().len() - *pos, "advance past the end of the body");
                *pos += cnt;
            }
        }
    }
}

type ProxyBody = BoxBody<Chunk, hyper::Error>;

fn stream_body(body: Incoming) -> ProxyBody {
    body.map_frame(|frame| frame.map_data(Chunk::Plain)).boxed()
}

fn chunk_body(chunk: Chunk) -> ProxyBody {
    Full::new(chunk).map_err(|never: Infallible| match never {}).boxed()
}

fn bytes_body(data: Vec<u8>) -> ProxyBody {
    chunk_body(Chunk::Plain(Bytes::from(data)))
}

fn empty_body() -> ProxyBody {
    bytes_body(Vec::new())
}

async fn proxy_request(
    mut req: Request<Incoming>,
    ctx: Arc<ProxyCtx>,
    sender: Arc<AsyncMutex<SendRequest<ProxyBody>>>,
    host: Arc<str>,
    port: u16,
) -> Response<ProxyBody> {
    let upgrade_requested = wants_upgrade(req.headers());
    let client_upgrade = if upgrade_requested { Some(hyper::upgrade::on(&mut req)) } else { None };

    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let content_type = req.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(str::to_string);
    // Only a request to the recipe's own submit target is ever buffered or
    // rewritten; everything else streams through.
    let injection = ctx.injection.as_ref().filter(|inj| inj.target.matches(&host, port, &path));

    let (mut parts, body) = req.into_parts();
    let mut scrub = false;

    let out_body: ProxyBody = if let Some(injection) = injection {
        let buffered = match collect_bounded(body, MAX_SUBMIT_REQUEST_BODY).await {
            Ok(bytes) => bytes,
            Err(CollectError::TooLarge) => return refused_submit(&host, port, RefuseReason::BodyTooLarge),
            Err(CollectError::Read(e)) => return gateway_error("proxy_submit_body_read", &host, port, &e),
        };
        let outgoing = OutgoingRequest {
            host: &host,
            port,
            method: method.as_str(),
            path: &path,
            content_type: content_type.as_deref(),
            body: &buffered,
        };
        let forwarded = match substitute_submit(&injection.secret, &injection.target, &outgoing) {
            Substitution::Unchanged => Chunk::Plain(Bytes::from(buffered)),
            Substitution::Refused(reason) => return refused_submit(&host, port, reason),
            Substitution::Substituted(body) => {
                scrub = true;
                // The response has to be searchable for the secret, so ask
                // for it uncompressed. A server that compresses anyway is
                // refused below rather than scrubbed blind.
                parts.headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
                Chunk::Secret { body, pos: 0 }
            }
        };
        parts.headers.remove(TRANSFER_ENCODING);
        parts.headers.insert(CONTENT_LENGTH, HeaderValue::from(forwarded.remaining()));
        chunk_body(forwarded)
    } else {
        stream_body(body)
    };

    strip_hop_by_hop(&mut parts.headers, upgrade_requested);
    ensure_host(&mut parts.headers, &host, port);

    let mut res = {
        let mut guard = sender.lock().await;
        if let Err(e) = guard.ready().await {
            return gateway_error("proxy_upstream_closed", &host, port, &e.to_string());
        }
        match guard.send_request(Request::from_parts(parts, out_body)).await {
            Ok(res) => res,
            Err(e) => return gateway_error("proxy_upstream_failed", &host, port, &e.to_string()),
        }
    };

    if res.status() == StatusCode::SWITCHING_PROTOCOLS {
        let Some(client_upgrade) = client_upgrade else {
            return gateway_error("proxy_unrequested_upgrade", &host, port, "the upstream switched protocols unasked");
        };
        let server_upgrade = hyper::upgrade::on(&mut res);
        let label = format!("{host}:{port}");
        tokio::spawn(relay_upgrade(client_upgrade, server_upgrade, label));
        let (mut parts, _discarded) = res.into_parts();
        strip_response_headers(&mut parts.headers, true);
        return Response::from_parts(parts, empty_body());
    }

    let (mut parts, body) = res.into_parts();
    strip_response_headers(&mut parts.headers, false);
    let Some(injection) = injection.filter(|_| scrub) else {
        return Response::from_parts(parts, stream_body(body));
    };

    if let Some(encoding) = parts.headers.get(CONTENT_ENCODING) {
        if !encoding.as_bytes().eq_ignore_ascii_case(b"identity") {
            return gateway_error(
                "proxy_response_encoded",
                &host,
                port,
                "the sign-in response was compressed and could not be scrubbed",
            );
        }
    }
    let received = match collect_bounded(body, MAX_SCRUBBED_RESPONSE_BODY).await {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(CollectError::TooLarge) => return gateway_error("proxy_response_too_large", &host, port, "over the cap"),
        Err(CollectError::Read(e)) => return gateway_error("proxy_response_read", &host, port, &e),
    };
    let scrubbed = scrub_response(&injection.secret, &received);
    parts.headers.remove(TRANSFER_ENCODING);
    parts.headers.insert(CONTENT_LENGTH, HeaderValue::from(scrubbed.len()));
    Response::from_parts(parts, bytes_body(scrubbed))
}

/// Relay an upgraded (WebSocket) connection in both directions until either
/// side closes.
async fn relay_upgrade(client: hyper::upgrade::OnUpgrade, server: hyper::upgrade::OnUpgrade, label: String) {
    let (client, server) = match tokio::try_join!(client, server) {
        Ok(pair) => pair,
        Err(e) => {
            log::debug!("web proxy: upgrade to {label} failed: {e}");
            return;
        }
    };
    let mut client = TokioIo::new(client);
    let mut server = TokioIo::new(server);
    if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut server).await {
        log::debug!("web proxy: upgraded connection to {label} ended: {e}");
    }
}

enum CollectError {
    TooLarge,
    Read(String),
}

async fn collect_bounded<B>(mut body: B, limit: usize) -> Result<Vec<u8>, CollectError>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| CollectError::Read(e.to_string()))?;
        if let Ok(data) = frame.into_data() {
            if out.len().saturating_add(data.len()) > limit {
                return Err(CollectError::TooLarge);
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(out)
}

fn refused_submit(host: &str, port: u16, reason: RefuseReason) -> Response<ProxyBody> {
    log::warn!("web proxy: did not forward the sign-in request to {host}:{port} ({})", reason.check());
    plain_response(StatusCode::BAD_GATEWAY, reason.check())
}

/// `detail` goes to the log, never to the page, and carries no path, query,
/// body or credential — only an upstream error string.
fn gateway_error(check: &'static str, host: &str, port: u16, detail: &str) -> Response<ProxyBody> {
    log::warn!("web proxy: {check} for {host}:{port} ({detail})");
    plain_response(StatusCode::BAD_GATEWAY, check)
}

fn plain_response(status: StatusCode, check: &str) -> Response<ProxyBody> {
    let body = format!("BastionVault session proxy: {check}\n");
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CONTENT_LENGTH, body.len())
        .header(CONNECTION, "close")
        .body(bytes_body(body.into_bytes()))
        .unwrap_or_else(|_| {
            let mut fallback = Response::new(empty_body());
            *fallback.status_mut() = StatusCode::BAD_GATEWAY;
            fallback
        })
}

fn wants_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key(UPGRADE)
        && headers
            .get_all(CONNECTION)
            .iter()
            .any(|v| v.to_str().is_ok_and(|s| s.split(',').any(|token| token.trim().eq_ignore_ascii_case("upgrade"))))
}

fn strip_hop_by_hop(headers: &mut HeaderMap, keep_upgrade: bool) {
    let listed = connection_tokens(headers);
    remove_matching(headers, |name| {
        !(keep_upgrade && is_upgrade_header(name)) && (HOP_BY_HOP.contains(&name) || listed.iter().any(|t| t == name))
    });
}

fn strip_response_headers(headers: &mut HeaderMap, keep_upgrade: bool) {
    let listed = connection_tokens(headers);
    remove_matching(headers, |name| {
        (!(keep_upgrade && is_upgrade_header(name))
            && (HOP_BY_HOP.contains(&name) || listed.iter().any(|t| t == name)))
            || is_stripped_response_header(name)
    });
}

/// The header names a `Connection` header lists; RFC 9110 §7.6.1 makes each of
/// them hop-by-hop for this connection.
fn connection_tokens(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

fn is_upgrade_header(name: &str) -> bool {
    name == "connection" || name == "upgrade"
}

fn remove_matching(headers: &mut HeaderMap, predicate: impl Fn(&str) -> bool) {
    let doomed: Vec<HeaderName> = headers.keys().filter(|n| predicate(n.as_str())).cloned().collect();
    for name in doomed {
        headers.remove(&name);
    }
}

/// HTTP/1.1 requires a `Host`; the webview always sends one, but a request
/// without it would otherwise go upstream headerless.
fn ensure_host(headers: &mut HeaderMap, host: &str, port: u16) {
    if headers.contains_key(HOST) {
        return;
    }
    let authority = if port == 443 { host.to_string() } else { format!("{host}:{port}") };
    if let Ok(value) = HeaderValue::from_str(&authority) {
        headers.insert(HOST, value);
    }
}

async fn connect_upstream(
    ctx: &ProxyCtx,
    host: &str,
    port: u16,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let tcp = dial(host, port).await?;
    let name = ServerName::try_from(bare_host(host).to_string())
        .map_err(|e| format!("`{host}` is not a valid TLS server name: {e}"))?;
    timeout(TLS_TIMEOUT, ctx.connector.connect(name, tcp))
        .await
        .map_err(|_| "the TLS handshake timed out".to_string())?
        .map_err(|e| format!("the TLS handshake failed: {e}"))
}

async fn dial(host: &str, port: u16) -> Result<TcpStream, String> {
    let bare = bare_host(host);
    let addrs: Vec<SocketAddr> = timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((bare, port)))
        .await
        .map_err(|_| format!("resolving {host} timed out"))?
        .map_err(|e| format!("could not resolve {host}: {e}"))?
        .collect();
    let mut last: Option<String> = None;
    for addr in addrs {
        match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Ok(Err(e)) => last = Some(e.to_string()),
            Err(_) => last = Some("the connection timed out".to_string()),
        }
    }
    Err(format!("could not connect to {host}:{port}: {}", last.unwrap_or_else(|| "no address".to_string())))
}

/// Write a short refusal and close. The body carries a fixed check name and
/// nothing from the request.
async fn refuse(client: &mut BufReader<TcpStream>, status: StatusCode, check: &'static str) -> Result<(), String> {
    let body = format!("BastionVault session proxy: {check}\n");
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or("Error"),
        body.len()
    );
    client.write_all(head.as_bytes()).await.map_err(|e| format!("refusal reply: {e}"))?;
    client.write_all(body.as_bytes()).await.map_err(|e| format!("refusal reply: {e}"))?;
    client.flush().await.map_err(|e| format!("refusal reply: {e}"))?;
    Ok(())
}

/// Read the request head up to and including the blank line, leaving
/// anything after it in the reader's buffer — a client that sends its TLS
/// `ClientHello` without waiting for the `200` keeps its bytes.
async fn read_head(client: &mut BufReader<TcpStream>) -> Result<Vec<u8>, &'static str> {
    let mut head: Vec<u8> = Vec::with_capacity(256);
    loop {
        let (consumed, done, overflow) = {
            let available = match client.fill_buf().await {
                Ok(bytes) => bytes,
                Err(_) => return Err("proxy_head_unreadable"),
            };
            if available.is_empty() {
                return Err("proxy_head_truncated");
            }
            let mut consumed = 0usize;
            let mut done = false;
            let mut overflow = false;
            for &byte in available {
                consumed += 1;
                head.push(byte);
                if head.len() > MAX_HEAD {
                    overflow = true;
                    break;
                }
                if head.ends_with(b"\r\n\r\n") {
                    done = true;
                    break;
                }
            }
            (consumed, done, overflow)
        };
        client.consume(consumed);
        if overflow {
            return Err("proxy_head_too_large");
        }
        if done {
            return Ok(head);
        }
    }
}

enum PrefaceError {
    /// A method other than `CONNECT`: absolute-form proxying is not offered.
    NotConnect,
    Malformed(&'static str),
}

/// Parse the request line of a `CONNECT`. Returns the authority as the
/// termination scope matches it: lower-cased host, an IPv6 literal still
/// bracketed.
fn parse_connect(head: &[u8]) -> Result<(String, u16), PrefaceError> {
    let line = head.split(|&b| b == b'\n').next().unwrap_or_default();
    let line = std::str::from_utf8(line)
        .map_err(|_| PrefaceError::Malformed("proxy_head_not_utf8"))?
        .trim_end_matches(['\r', '\n']);
    let mut fields = line.split(' ');
    let (Some(method), Some(target), Some(version)) = (fields.next(), fields.next(), fields.next()) else {
        return Err(PrefaceError::Malformed("proxy_request_line"));
    };
    if fields.next().is_some() {
        return Err(PrefaceError::Malformed("proxy_request_line"));
    }
    if !version.starts_with("HTTP/1.") {
        return Err(PrefaceError::Malformed("proxy_http_version"));
    }
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(PrefaceError::NotConnect);
    }
    split_authority(target).ok_or(PrefaceError::Malformed("proxy_connect_authority"))
}

fn split_authority(target: &str) -> Option<(String, u16)> {
    let (host, port) = if target.starts_with('[') {
        let close = target.find(']')?;
        let port = target[close + 1..].strip_prefix(':')?;
        (target[..=close].to_string(), port)
    } else {
        let (host, port) = target.rsplit_once(':')?;
        if host.contains(':') {
            // An unbracketed IPv6 literal is not a valid CONNECT authority.
            return None;
        }
        (host.to_string(), port)
    };
    let port: u16 = port.parse().ok()?;
    if host.is_empty() || host.len() > 255 || port == 0 || !host.is_ascii() {
        return None;
    }
    Some((host.to_ascii_lowercase(), port))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use bastion_vault::utils::tls_pin::SpkiPin;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio::io::AsyncReadExt;

    use super::*;

    /// The session's own loopback host. `localhost` resolves everywhere the
    /// GUI builds, which lets the proxy exercise its real resolver and TLS
    /// server-name path instead of a dialling seam.
    const HOST: &str = "localhost";

    // ---- a local https origin standing in for the application ------------

    struct Upstream {
        port: u16,
        cert_der: Vec<u8>,
        /// Request bodies the upstream received, in order.
        received: Arc<StdMutex<Vec<Vec<u8>>>>,
    }

    /// An https server on 127.0.0.1 that echoes the request body back in its
    /// response — so a secret that reaches it shows up in the reply and the
    /// scrub has something to remove.
    async fn start_upstream() -> Upstream {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec![HOST.to_string()]).unwrap().self_signed(&key).unwrap();
        let cert_der = cert.der().to_vec();
        let config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert_der.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let received: Arc<StdMutex<Vec<Vec<u8>>>> = Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::clone(&received);

        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else { return };
                let acceptor = acceptor.clone();
                let sink = Arc::clone(&sink);
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(sock).await else { return };
                    let service = service_fn(move |req: Request<Incoming>| {
                        let sink = Arc::clone(&sink);
                        async move {
                            let upgrade = wants_upgrade(req.headers());
                            let mut req = req;
                            let on_upgrade = hyper::upgrade::on(&mut req);
                            let body = req.into_body().collect().await.unwrap().to_bytes().to_vec();
                            sink.lock().unwrap().push(body.clone());
                            if upgrade {
                                tokio::spawn(async move {
                                    if let Ok(upgraded) = on_upgrade.await {
                                        let mut io = TokioIo::new(upgraded);
                                        let mut buf = [0u8; 64];
                                        if let Ok(n) = io.read(&mut buf).await {
                                            let _ = io.write_all(&buf[..n]).await;
                                        }
                                    }
                                });
                                let res = Response::builder()
                                    .status(StatusCode::SWITCHING_PROTOCOLS)
                                    .header(CONNECTION, "upgrade")
                                    .header(UPGRADE, "websocket")
                                    .body(empty_body())
                                    .unwrap();
                                return Ok::<_, Infallible>(res);
                            }
                            let echoed = format!("<html>received: {}</html>", String::from_utf8_lossy(&body));
                            let res = Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "text/html")
                                // Advertise HTTP/3 so the strip is exercised.
                                .header("alt-svc", "h3=\":443\"")
                                .body(bytes_body(echoed.into_bytes()))
                                .unwrap();
                            Ok::<_, Infallible>(res)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .with_upgrades()
                        .await;
                });
            }
        });

        Upstream { port, cert_der, received }
    }

    /// A plain TCP echo server, to prove an out-of-scope `CONNECT` is
    /// tunnelled rather than terminated.
    async fn start_echo() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { return };
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    if let Ok(n) = sock.read(&mut buf).await {
                        let _ = sock.write_all(&buf[..n]).await;
                    }
                });
            }
        });
        port
    }

    // ---- the test client, standing in for the session webview ------------

    fn pins_of(der: &[u8]) -> PinSet {
        PinSet::from_strs(&[SpkiPin::of_certificate(der).unwrap().to_string()]).unwrap()
    }

    async fn open_connect(proxy: &WebProxy, authority: &str) -> (BufReader<TcpStream>, String) {
        let mut sock = BufReader::new(TcpStream::connect(proxy.local_addr()).await.unwrap());
        sock.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes()).await.unwrap();
        sock.flush().await.unwrap();
        let status = read_status_line(&mut sock).await;
        (sock, status)
    }

    async fn read_status_line(sock: &mut BufReader<TcpStream>) -> String {
        let mut head = Vec::new();
        loop {
            let (consumed, done) = {
                let available = sock.fill_buf().await.unwrap();
                if available.is_empty() {
                    break;
                }
                let mut consumed = 0;
                let mut done = false;
                for &b in available {
                    consumed += 1;
                    head.push(b);
                    if head.ends_with(b"\r\n\r\n") {
                        done = true;
                        break;
                    }
                }
                (consumed, done)
            };
            sock.consume(consumed);
            if done {
                break;
            }
        }
        String::from_utf8_lossy(&head).lines().next().unwrap_or_default().to_string()
    }

    /// A TLS client that trusts only this session's CA — what the webview is
    /// told to trust through the Phase 4 gate.
    fn session_client_config(proxy: &WebProxy) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(proxy.ca_der().to_vec())).unwrap();
        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }

    async fn start_proxy(upstream: &Upstream, secret: &str, pins: PinSet) -> (WebProxy, String) {
        let origin = format!("https://{HOST}:{}", upstream.port);
        let secret = SessionSecret::new(secret.to_string()).unwrap();
        let placeholder = secret.placeholder().to_string();
        let proxy = WebProxy::start(ProxyConfig {
            scope: TerminationScope::new([origin.as_str()]).unwrap(),
            injection: Some(ProxyInjection { secret, target: SubmitTarget::new(&origin, "/login").unwrap() }),
            pins,
        })
        .await
        .unwrap();
        (proxy, placeholder)
    }

    // ---- tests -----------------------------------------------------------

    #[tokio::test]
    async fn a_non_connect_request_is_refused() {
        let upstream = start_upstream().await;
        let (proxy, _) = start_proxy(&upstream, "pw", pins_of(&upstream.cert_der)).await;

        let mut sock = BufReader::new(TcpStream::connect(proxy.local_addr()).await.unwrap());
        sock.write_all(b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n").await.unwrap();
        sock.flush().await.unwrap();
        let status = read_status_line(&mut sock).await;
        assert!(status.starts_with("HTTP/1.1 405"), "{status}");
    }

    #[tokio::test]
    async fn a_connect_outside_the_scope_is_tunnelled_not_terminated() {
        let upstream = start_upstream().await;
        let (proxy, _) = start_proxy(&upstream, "pw", pins_of(&upstream.cert_der)).await;
        let echo = start_echo().await;

        let (mut sock, status) = open_connect(&proxy, &format!("{HOST}:{echo}")).await;
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        // Raw bytes, no TLS: the proxy did not terminate this one.
        sock.write_all(b"ping").await.unwrap();
        sock.flush().await.unwrap();
        let mut buf = [0u8; 4];
        sock.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        assert!(!proxy.has_terminated(HOST, echo));
    }

    #[tokio::test]
    async fn the_submit_request_carries_the_secret_and_the_reply_carries_the_placeholder() {
        let secret = "s3cret-value";
        let upstream = start_upstream().await;
        let (proxy, placeholder) = start_proxy(&upstream, secret, pins_of(&upstream.cert_der)).await;

        let authority = format!("{HOST}:{}", upstream.port);
        let (sock, status) = open_connect(&proxy, &authority).await;
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        // What the bypass check (T106 step 6) reads: the proxy owns this
        // origin, so the recipe may fill.
        assert!(proxy.has_terminated(HOST, upstream.port));

        let tls = TlsConnector::from(session_client_config(&proxy))
            .connect(ServerName::try_from(HOST).unwrap(), sock)
            .await
            .expect("the webview trusts the session CA");
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let body = format!("user=alice&password={placeholder}");
        let req = Request::builder()
            .method("POST")
            .uri("/login")
            .header(HOST, &authority)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(bytes_body(body.into_bytes()))
            .unwrap();
        let res = sender.send_request(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        // Alt-Svc never reaches the page: it could steer it onto HTTP/3,
        // which does not go through this proxy.
        assert!(res.headers().get("alt-svc").is_none());
        let seen = String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();

        let received = upstream.received.lock().unwrap().clone();
        assert_eq!(received.len(), 1);
        let received = String::from_utf8(received[0].clone()).unwrap();
        assert_eq!(received, format!("user=alice&password={secret}"));
        assert!(!received.contains(&placeholder));

        assert!(!seen.contains(secret), "the secret came back to the page");
        assert!(seen.contains(&placeholder), "the secret was not scrubbed back to the placeholder: {seen}");
    }

    #[tokio::test]
    async fn a_non_submit_request_streams_through_untouched() {
        let upstream = start_upstream().await;
        let (proxy, placeholder) = start_proxy(&upstream, "s3cret-value", pins_of(&upstream.cert_der)).await;

        let authority = format!("{HOST}:{}", upstream.port);
        let (sock, _) = open_connect(&proxy, &authority).await;
        let tls = TlsConnector::from(session_client_config(&proxy))
            .connect(ServerName::try_from(HOST).unwrap(), sock)
            .await
            .unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        // Same body, different path: the placeholder goes out verbatim.
        let body = format!("user=alice&password={placeholder}");
        let req = Request::builder()
            .method("POST")
            .uri("/elsewhere")
            .header(HOST, &authority)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(bytes_body(body.into_bytes()))
            .unwrap();
        assert_eq!(sender.send_request(req).await.unwrap().status(), StatusCode::OK);

        let received = String::from_utf8(upstream.received.lock().unwrap()[0].clone()).unwrap();
        assert_eq!(received, format!("user=alice&password={placeholder}"));
    }

    /// Two placeholders is the ambiguous case §10 refuses: the request must
    /// not reach the upstream at all.
    #[tokio::test]
    async fn a_repeated_placeholder_is_refused_before_the_upstream_sees_it() {
        let upstream = start_upstream().await;
        let (proxy, placeholder) = start_proxy(&upstream, "s3cret-value", pins_of(&upstream.cert_der)).await;

        let authority = format!("{HOST}:{}", upstream.port);
        let (sock, _) = open_connect(&proxy, &authority).await;
        let tls = TlsConnector::from(session_client_config(&proxy))
            .connect(ServerName::try_from(HOST).unwrap(), sock)
            .await
            .unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let body = format!("a={placeholder}&b={placeholder}");
        let req = Request::builder()
            .method("POST")
            .uri("/login")
            .header(HOST, &authority)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(bytes_body(body.into_bytes()))
            .unwrap();
        let res = sender.send_request(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
        assert!(upstream.received.lock().unwrap().is_empty());
    }

    /// The upstream leg is not optional: with no pin and a self-signed
    /// certificate the platform rejects, the `CONNECT` itself fails and the
    /// tunnel is never opened.
    #[tokio::test]
    async fn an_unverifiable_upstream_fails_the_connect() {
        let upstream = start_upstream().await;
        let (proxy, _) = start_proxy(&upstream, "pw", PinSet::default()).await;

        let (_sock, status) = open_connect(&proxy, &format!("{HOST}:{}", upstream.port)).await;
        assert!(status.starts_with("HTTP/1.1 502"), "{status}");
        assert!(!proxy.has_terminated(HOST, upstream.port));
    }

    /// A `CONNECT` naming one host, an SNI naming another: the leaf is bound
    /// to the authority, so the handshake is refused rather than answered
    /// with this host's certificate.
    #[tokio::test]
    async fn an_sni_other_than_the_connect_authority_is_refused() {
        let upstream = start_upstream().await;
        let (proxy, _) = start_proxy(&upstream, "pw", pins_of(&upstream.cert_der)).await;

        let (sock, status) = open_connect(&proxy, &format!("{HOST}:{}", upstream.port)).await;
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        let result = TlsConnector::from(session_client_config(&proxy))
            .connect(ServerName::try_from("other.example.test").unwrap(), sock)
            .await;
        assert!(result.is_err(), "the proxy served a certificate for an SNI it was not asked about");
    }

    #[tokio::test]
    async fn a_websocket_upgrade_is_relayed() {
        let upstream = start_upstream().await;
        let (proxy, _) = start_proxy(&upstream, "pw", pins_of(&upstream.cert_der)).await;

        let authority = format!("{HOST}:{}", upstream.port);
        let (sock, _) = open_connect(&proxy, &authority).await;
        let tls = TlsConnector::from(session_client_config(&proxy))
            .connect(ServerName::try_from(HOST).unwrap(), sock)
            .await
            .unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });

        let req = Request::builder()
            .method("GET")
            .uri("/socket")
            .header(HOST, &authority)
            .header(CONNECTION, "upgrade")
            .header(UPGRADE, "websocket")
            .body(empty_body())
            .unwrap();
        let mut res = sender.send_request(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::SWITCHING_PROTOCOLS);
        let upgraded = hyper::upgrade::on(&mut res).await.unwrap();
        let mut io = TokioIo::new(upgraded);
        io.write_all(b"frame").await.unwrap();
        let mut buf = [0u8; 5];
        io.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"frame");
    }

    // ---- unit tests for the pieces that need no sockets ------------------

    #[test]
    fn the_request_line_is_parsed_strictly() {
        assert_eq!(
            parse_connect(b"CONNECT app.example.test:443 HTTP/1.1\r\n\r\n").ok(),
            Some(("app.example.test".to_string(), 443))
        );
        assert_eq!(parse_connect(b"CONNECT [::1]:8443 HTTP/1.1\r\n\r\n").ok(), Some(("[::1]".to_string(), 8443)));
        assert_eq!(
            parse_connect(b"CONNECT APP.Example.TEST:443 HTTP/1.1\r\n\r\n").ok(),
            Some(("app.example.test".to_string(), 443))
        );
        assert!(matches!(
            parse_connect(b"GET http://app.example.test/ HTTP/1.1\r\n\r\n"),
            Err(PrefaceError::NotConnect)
        ));
        for bad in [
            &b"CONNECT app.example.test HTTP/1.1\r\n\r\n"[..],
            b"CONNECT app.example.test:0 HTTP/1.1\r\n\r\n",
            b"CONNECT app.example.test:99999 HTTP/1.1\r\n\r\n",
            b"CONNECT ::1:443 HTTP/1.1\r\n\r\n",
            b"CONNECT app.example.test:443 RTSP/1.0\r\n\r\n",
            b"CONNECT app.example.test:443\r\n\r\n",
        ] {
            assert!(
                matches!(parse_connect(bad), Err(PrefaceError::Malformed(_))),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn hop_by_hop_headers_are_stripped_but_an_upgrade_survives() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        headers.insert("x-keep", HeaderValue::from_static("yes"));

        let mut plain = headers.clone();
        strip_hop_by_hop(&mut plain, false);
        assert!(plain.get(CONNECTION).is_none());
        assert!(plain.get(UPGRADE).is_none());
        assert!(plain.get("x-keep").is_some());

        let mut upgrading = headers.clone();
        strip_hop_by_hop(&mut upgrading, true);
        assert!(upgrading.get(CONNECTION).is_some());
        assert!(upgrading.get(UPGRADE).is_some());
        assert!(upgrading.get(TRANSFER_ENCODING).is_none());
    }

    #[test]
    fn headers_named_in_connection_are_hop_by_hop_too() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("Keep-Alive, X-Session-Hop"));
        headers.insert("x-session-hop", HeaderValue::from_static("secret-route"));
        headers.insert("x-keep", HeaderValue::from_static("yes"));
        let mut request = headers.clone();
        strip_hop_by_hop(&mut request, false);
        assert!(request.get("x-session-hop").is_none());
        assert!(request.get("x-keep").is_some());

        let mut response = headers.clone();
        strip_response_headers(&mut response, false);
        assert!(response.get("x-session-hop").is_none());
        assert!(response.get("x-keep").is_some());

        let mut upgrading = HeaderMap::new();
        upgrading.insert(CONNECTION, HeaderValue::from_static("upgrade, x-session-hop"));
        upgrading.insert(UPGRADE, HeaderValue::from_static("websocket"));
        upgrading.insert("x-session-hop", HeaderValue::from_static("secret-route"));
        strip_hop_by_hop(&mut upgrading, true);
        assert!(upgrading.get("x-session-hop").is_none());
        assert!(upgrading.get(UPGRADE).is_some());
        assert!(upgrading.get(CONNECTION).is_some());
    }

    #[test]
    fn alt_svc_is_stripped_from_every_terminated_response() {
        let mut headers = HeaderMap::new();
        headers.insert("alt-svc", HeaderValue::from_static("h3=\":443\""));
        headers.insert("set-cookie", HeaderValue::from_static("a=b"));
        strip_response_headers(&mut headers, false);
        assert!(headers.get("alt-svc").is_none());
        assert!(headers.get("set-cookie").is_some());
    }

    #[tokio::test]
    async fn a_submit_target_outside_the_termination_scope_is_refused_at_launch() {
        let err = WebProxy::start(ProxyConfig {
            scope: TerminationScope::new(["https://app.example.test"]).unwrap(),
            injection: Some(ProxyInjection {
                secret: SessionSecret::new("pw".to_string()).unwrap(),
                target: SubmitTarget::new("https://sso.example.test", "/login").unwrap(),
            }),
            pins: PinSet::default(),
        })
        .await
        .err()
        .expect("a submit target outside the scope must not start a proxy");
        assert!(err.contains("not one of the session's terminated origins"), "{err}");
    }
}
