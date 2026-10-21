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
//! * **Header injection** (recipe version 3, T106 step 7) — on a terminated
//!   request whose origin and path prefix an `inject_headers` entry covers,
//!   the proxy sets that header from the session's header secret
//!   ([`super::web_proxy::HeaderInjector`]), replacing a value the page sent
//!   (reported once per origin), asks for an identity-encoded response and
//!   scrubs the secret out of the response's body and header values before
//!   the page sees it. An upgrade on such a path, or a `Host` that is not the
//!   terminated authority, is refused rather than sent the secret. The header
//!   secret is held for the session's lifetime (the password only for its
//!   sign-in), replaced by a re-run login and dropped at shutdown.
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
//! requires. What the listener *did* (termination, substitution, scrubbing,
//! refusal) is reported through [`ProxyEvents`], in the same terms, and the
//! command layer writes the audit lines from it (T106 step 6).
//!
//! This file is Tauri-free: the platform wiring
//! ([`super::web_proxy_webview`], T106 step 4) owns [`WebProxy::proxy_url`],
//! [`WebProxy::ca_pin`] and [`WebProxy::leaf_pin`].

use std::collections::{BTreeMap, BTreeSet};
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
    bare_host, host_header_matches, is_stripped_response_header, scrub_header_value, scrub_response, substitute_submit,
    HeaderInjection, HeaderInjector, HeaderRefusal, OutgoingRequest, RefuseReason, SecretBody, SessionSecret,
    SubmitTarget, Substitution, TerminationScope,
};
use super::web_proxy_ca::SessionCa;
use super::web_proxy_upstream::{UpstreamRefusal, UpstreamTrust, UpstreamVerifier};

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

/// What the proxy may put into the outgoing submit request, for one sign-in
/// ([`WebProxy::arm`]). Between sign-ins — and once a sign-in ended and its
/// secret was released ([`WebProxy::release`]) — the proxy holds none and
/// substitutes nothing.
pub struct ProxyInjection {
    pub secret: SessionSecret,
    pub target: SubmitTarget,
}

/// Names one [`WebProxy::arm`]: releasing it drops that sign-in's secret and
/// nothing a later sign-in armed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InjectionTicket(u64);

#[derive(Default)]
struct InjectionSlot {
    /// Bumped by every arm.
    generation: u64,
    /// Behind an `Arc` so a request that took it keeps it until its response
    /// is scrubbed, even if the sign-in ends meanwhile.
    current: Option<Arc<ProxyInjection>>,
}

/// What the listener did, for the audit lines and the window (T106 step 6).
/// Origins (`host`, `port`) and fixed names only: never the secret, the
/// placeholder, a path, a body or anything read from a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyEvent {
    /// The proxy terminated a session origin for the first time — or the
    /// way its upstream was admitted changed since the last time.
    Terminated { host: String, port: u16, upstream: UpstreamTrust },
    /// The placeholder in the submit request was replaced by the secret.
    Substituted { host: String, port: u16 },
    /// The substituted request's response was scrubbed; `replaced` copies of
    /// the secret (in any encoding) became the placeholder.
    Scrubbed { host: String, port: u16, replaced: usize },
    /// The proxy refused the sign-in request or its response, or refused an
    /// upstream certificate on a session origin. `check` is the
    /// `aborted:<check>` name (`[a-z0-9_]{1,32}`), `notice` fixed text for
    /// the title.
    Refused { host: String, port: u16, check: &'static str, notice: &'static str },
    /// The proxy set an injected header on a request to this origin — the
    /// first time per origin in the session.
    HeaderInjected { host: String, port: u16 },
    /// The page itself sent a header the proxy injects, and the proxy
    /// replaced it — the first time per origin in the session.
    HeaderReplaced { host: String, port: u16 },
    /// The proxy refused a request it would have injected a header into, or
    /// that request's response (`check` as for [`Self::Refused`]). Not a
    /// sign-in failure: the fill is told through [`Self::Refused`] when the
    /// request was the sign-in.
    HeaderRefused { host: String, port: u16, check: &'static str },
}

type EventHook = Arc<dyn Fn(ProxyEvent) + Send + Sync>;

/// Where a session's proxy reports [`ProxyEvent`]s. Called from the proxy's
/// own tasks; the hook must not block.
#[derive(Clone, Default)]
pub struct ProxyEvents(Option<EventHook>);

impl ProxyEvents {
    pub fn new(hook: impl Fn(ProxyEvent) + Send + Sync + 'static) -> Self {
        Self(Some(Arc::new(hook)))
    }

    fn emit(&self, event: ProxyEvent) {
        if let Some(hook) = &self.0 {
            hook(event);
        }
    }
}

impl ProxyEvent {
    /// The event's origin as the audit lines print one (`https://host`, the
    /// port only when it is not 443).
    pub fn origin(&self) -> String {
        let (Self::Terminated { host, port, .. }
        | Self::Substituted { host, port }
        | Self::Scrubbed { host, port, .. }
        | Self::Refused { host, port, .. }
        | Self::HeaderInjected { host, port }
        | Self::HeaderReplaced { host, port }
        | Self::HeaderRefused { host, port, .. }) = self;
        if *port == 443 {
            format!("https://{host}")
        } else {
            format!("https://{host}:{port}")
        }
    }
}

/// One session's proxy, as the launch path describes it. The secret is not
/// part of it: each sign-in arms its own ([`WebProxy::arm`]).
pub struct ProxyConfig {
    /// The https origins this session terminates. Everything else is
    /// tunnelled.
    pub scope: TerminationScope,
    /// The profile's `tls_pin_sha256`, as the override on the upstream leg.
    pub pins: PinSet,
    pub events: ProxyEvents,
}

/// A running session proxy. Dropping it stops the listener; connections
/// already open end with it.
pub struct WebProxy {
    addr: SocketAddr,
    ctx: Arc<ProxyCtx>,
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

        let ca = Arc::new(SessionCa::mint(&config.scope.hosts())?);
        let verifier = UpstreamVerifier::new(config.pins.clone())?;
        let connector = TlsConnector::from(verifier.client_config()?);

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|e| format!("web proxy: could not bind a loopback listener: {e}"))?;
        let addr = listener.local_addr().map_err(|e| format!("web proxy: listener address: {e}"))?;

        let ctx = Arc::new(ProxyCtx {
            scope: config.scope,
            injection: Mutex::new(InjectionSlot::default()),
            headers: Mutex::new(None),
            header_reported: Mutex::new(BTreeSet::new()),
            ca,
            connector,
            verifier,
            terminated: Mutex::new(BTreeMap::new()),
            events: config.events,
        });
        let (stop_tx, stop_rx) = oneshot::channel();
        tokio::spawn(accept_loop(listener, Arc::clone(&ctx), stop_rx));
        log::debug!("web proxy: listening on {addr}");
        Ok(Self { addr, ctx, stop: Mutex::new(Some(stop_tx)) })
    }

    /// What `proxy_url` is set to on the session window.
    pub fn proxy_url(&self) -> String {
        format!("http://{}", self.local_addr())
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The session CA's DER certificate, for a test client that trusts only
    /// this session's CA (what the webview is told to trust through the
    /// Phase 4 gate).
    #[cfg(test)]
    pub fn ca_der(&self) -> &[u8] {
        self.ctx.ca.ca_der()
    }

    /// The two pins the Phase 4 gate is given for this session: the CA's
    /// (issuer path, host-bound) and the leaves' shared key (leaf path).
    pub fn ca_pin(&self) -> SpkiPin {
        self.ctx.ca.ca_pin()
    }

    pub fn leaf_pin(&self) -> SpkiPin {
        self.ctx.ca.leaf_pin()
    }

    /// Every terminated host with its session leaf (DER, public data): what
    /// the WebKitGTK shim allows per host before the first load
    /// (`web_proxy_webview::pre_register_leaves`).
    // Read by the WebKitGTK shim only; macOS and Windows trust the leaves
    // through the pin gate.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn session_leaves(&self) -> &[(String, Vec<u8>)] {
        self.ctx.ca.leaves()
    }

    /// Whether the proxy has actually terminated this origin. The bypass
    /// check (T106 step 6) reads it: the recipe fills only once the proxy
    /// says it owns the page's origin.
    pub fn has_terminated(&self, host: &str, port: u16) -> bool {
        self.upstream_trust(host, port).is_some()
    }

    /// How the upstream of a terminated origin was admitted (the last
    /// termination's), for the toolbar's lock state. `None` when the proxy
    /// has not terminated it.
    pub fn upstream_trust(&self, host: &str, port: u16) -> Option<UpstreamTrust> {
        self.ctx.terminated.lock().unwrap_or_else(|p| p.into_inner()).get(&(host.to_ascii_lowercase(), port)).copied()
    }

    /// Give the proxy one sign-in's secret and submit target, replacing any
    /// earlier one (a re-run login). The target must be a terminated origin.
    /// The replaced secret is zeroized once no request still uses it.
    pub fn arm(&self, injection: ProxyInjection) -> Result<InjectionTicket, String> {
        check_injection_scope(&self.ctx.scope, &injection)?;
        let mut slot = self.ctx.injection.lock().unwrap_or_else(|p| p.into_inner());
        slot.generation += 1;
        slot.current = Some(Arc::new(injection));
        Ok(InjectionTicket(slot.generation))
    }

    /// The sign-in `ticket` armed has ended: drop its secret. A no-op when a
    /// later sign-in has armed its own since, so a retiring sign-in can never
    /// take its successor's secret away.
    pub fn release(&self, ticket: InjectionTicket) -> bool {
        let mut slot = self.ctx.injection.lock().unwrap_or_else(|p| p.into_inner());
        if slot.generation == ticket.0 && slot.current.is_some() {
            slot.current = None;
            true
        } else {
            false
        }
    }

    /// Whether the proxy still holds a secret to substitute.
    #[cfg(test)]
    pub fn holds_secret(&self) -> bool {
        self.ctx.injection.lock().unwrap_or_else(|p| p.into_inner()).current.is_some()
    }

    /// Give the proxy the session's header injections and their secret
    /// (recipe version 3, T106 step 7), replacing any earlier set (a re-run
    /// login). Every entry must name a terminated origin: one that does not
    /// would never be injected, so it is refused here — at launch — rather
    /// than skipped. Held until a later arm or [`Self::shutdown`], not
    /// released when the sign-in ends: the headers are for the session.
    pub fn arm_headers(&self, injector: HeaderInjector) -> Result<(), String> {
        for entry in injector.entries() {
            let origin = entry.origin();
            if !self.ctx.scope.terminates(origin.host(), origin.port()) {
                // `injector` drops here, and its secret with it.
                return Err(format!(
                    "web proxy: the `{}` header injection for {}:{} is not one of the session's terminated origins",
                    entry.name(),
                    origin.host(),
                    origin.port()
                ));
            }
        }
        *self.ctx.headers.lock().unwrap_or_else(|p| p.into_inner()) = Some(Arc::new(injector));
        Ok(())
    }

    /// Whether the proxy holds a header secret.
    #[cfg(test)]
    pub fn holds_header_secret(&self) -> bool {
        self.ctx.headers.lock().unwrap_or_else(|p| p.into_inner()).is_some()
    }

    /// Stop accepting and drop the secrets. Idempotent; [`Drop`] does the same.
    pub fn shutdown(&self) {
        self.ctx.injection.lock().unwrap_or_else(|p| p.into_inner()).current = None;
        *self.ctx.headers.lock().unwrap_or_else(|p| p.into_inner()) = None;
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

/// The submit target must be a terminated origin. Otherwise the submit
/// request would leave through a blind tunnel and the placeholder — not the
/// password — would reach the application. Fail at launch, visibly, not at
/// sign-in.
fn check_injection_scope(scope: &TerminationScope, injection: &ProxyInjection) -> Result<(), String> {
    let origin = injection.target.origin();
    if scope.terminates(origin.host(), origin.port()) {
        Ok(())
    } else {
        Err(format!(
            "web proxy: the submit target {}:{} is not one of the session's terminated origins",
            origin.host(),
            origin.port()
        ))
    }
}

struct ProxyCtx {
    scope: TerminationScope,
    injection: Mutex<InjectionSlot>,
    /// Behind an `Arc` for the same reason as the submit injection: a
    /// request that took it keeps it until its response is scrubbed.
    headers: Mutex<Option<Arc<HeaderInjector>>>,
    /// `(host, port, replaced)` already reported, so the audit gets one
    /// `HeaderInjected` / `HeaderReplaced` per origin, not one per request.
    header_reported: Mutex<BTreeSet<(String, u16, bool)>>,
    ca: Arc<SessionCa>,
    connector: TlsConnector,
    verifier: Arc<UpstreamVerifier>,
    terminated: Mutex<BTreeMap<(String, u16), UpstreamTrust>>,
    events: ProxyEvents,
}

impl ProxyCtx {
    /// Record a termination; reported the first time per origin and when
    /// its upstream's admission changes, not on every `CONNECT`.
    fn note_terminated(&self, host: &str, port: u16, upstream: UpstreamTrust) {
        let changed = self
            .terminated
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert((host.to_ascii_lowercase(), port), upstream)
            != Some(upstream);
        if changed {
            self.events.emit(ProxyEvent::Terminated { host: host.to_string(), port, upstream });
        }
    }

    fn current_injection(&self) -> Option<Arc<ProxyInjection>> {
        self.injection.lock().unwrap_or_else(|p| p.into_inner()).current.clone()
    }

    fn refused(&self, host: &str, port: u16, check: &'static str, notice: &'static str) {
        self.events.emit(ProxyEvent::Refused { host: host.to_string(), port, check, notice });
    }

    fn current_headers(&self) -> Option<Arc<HeaderInjector>> {
        self.headers.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn header_refused(&self, host: &str, port: u16, check: &'static str) {
        self.events.emit(ProxyEvent::HeaderRefused { host: host.to_string(), port, check });
    }

    /// Report an injection, and a replacement of the page's own header, the
    /// first time each happens on an origin.
    fn note_header(&self, host: &str, port: u16, replaced: bool) {
        let (first_injected, first_replaced) = {
            let mut seen = self.header_reported.lock().unwrap_or_else(|p| p.into_inner());
            let host = host.to_ascii_lowercase();
            (seen.insert((host.clone(), port, false)), replaced && seen.insert((host, port, true)))
        };
        if first_injected {
            self.events.emit(ProxyEvent::HeaderInjected { host: host.to_string(), port });
        }
        if first_replaced {
            self.events.emit(ProxyEvent::HeaderReplaced { host: host.to_string(), port });
        }
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
    let (upstream, trust) = match connect_upstream(&ctx, &host, port).await {
        Ok(established) => established,
        Err(e) => {
            log::warn!("web proxy: upstream {host}:{port} not established ({e})");
            // A certificate nothing admits is the one failure the window
            // should name: the webview only sees a failed CONNECT.
            if let Some(refusal) = ctx.verifier.take_refusal(bare_host(&host)) {
                ctx.refused(&host, port, refusal.check(), refusal_notice(refusal));
            }
            return refuse(&mut client, StatusCode::BAD_GATEWAY, "proxy_upstream_unavailable").await;
        }
    };

    // Recorded before the `200` goes out: from the webview's point of view
    // the origin is this proxy's the moment the tunnel opens, and the bypass
    // check must never see "not terminated" for a page that is already
    // loading through it.
    ctx.note_terminated(&host, port, trust);
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
    // rewritten; everything else streams through. The injection is taken
    // once, so a sign-in that ends mid-request cannot leave this request
    // half-substituted or its response unscrubbed.
    let injection = ctx.current_injection().filter(|inj| inj.target.matches(&host, port, &path));
    let injection = injection.as_deref();

    // Header injection: the entries covering this origin and path, decided
    // once per request like the submit injection (the `Arc` keeps the
    // secret until the response is scrubbed, even across a re-arm).
    let header_arm = ctx.current_headers();
    let header_entries: Vec<&HeaderInjection> =
        header_arm.as_deref().map(|h| h.applicable(&host, port, &path)).unwrap_or_default();
    let injector = header_arm.as_deref().filter(|_| !header_entries.is_empty());
    if injector.is_some() {
        // Both checked before anything is read or sent: the secret never
        // goes onto a stream the scrub cannot see, or to another authority.
        if upgrade_requested {
            return refused_header(&ctx, &host, port, HeaderRefusal::Upgrade, injection.is_some());
        }
        if !host_header_matches(req.headers().get(HOST).map(HeaderValue::as_bytes), &host, port) {
            return refused_header(&ctx, &host, port, HeaderRefusal::HostMismatch, injection.is_some());
        }
    }

    let (mut parts, body) = req.into_parts();
    let mut scrub = false;

    let out_body: ProxyBody = if let Some(injection) = injection {
        let buffered = match collect_bounded(body, MAX_SUBMIT_REQUEST_BODY).await {
            // The page's body: it holds the placeholder, never the secret.
            Ok(bytes) => bytes,
            Err(CollectError::TooLarge) => return refused_submit(&ctx, &host, port, RefuseReason::BodyTooLarge),
            Err(CollectError::Read(e)) => {
                ctx.refused(&host, port, "proxy_submit_body_read", "the session proxy could not read the sign-in");
                return gateway_error("proxy_submit_body_read", &host, port, &e);
            }
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
            Substitution::Refused(reason) => return refused_submit(&ctx, &host, port, reason),
            Substitution::Substituted(body) => {
                scrub = true;
                // The response has to be searchable for the secret, so ask
                // for it uncompressed. A server that compresses anyway is
                // refused below rather than scrubbed blind.
                parts.headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
                ctx.events.emit(ProxyEvent::Substituted { host: host.to_string(), port });
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

    // After the hop-by-hop strip, so a `Connection` token naming the header
    // cannot remove what the proxy sets. The page's own value is replaced:
    // the operator configured this header on purpose.
    if let Some(injector) = injector {
        let mut replaced = false;
        for entry in &header_entries {
            let Ok(name) = HeaderName::from_bytes(entry.name().as_bytes()) else {
                return refused_header(&ctx, &host, port, HeaderRefusal::Value, injection.is_some());
            };
            replaced |= parts.headers.remove(&name).is_some();
            // Backed by the zeroizing buffer itself (no copy into a plain
            // `Bytes`), and marked sensitive so no `Debug` of these headers
            // can print it.
            let Ok(mut value) = HeaderValue::from_maybe_shared(Bytes::from_owner(injector.value(entry))) else {
                return refused_header(&ctx, &host, port, HeaderRefusal::Value, injection.is_some());
            };
            value.set_sensitive(true);
            parts.headers.insert(name, value);
        }
        // The response is searched for the secret, so ask for it
        // uncompressed; a compressed one is refused below.
        parts.headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        ctx.note_header(&host, port, replaced);
    }

    // A failure on the sign-in request itself is the window's business: the
    // fill ends with it instead of waiting out its deadline.
    let sign_in_failed = |check: &'static str, notice: &'static str| {
        if injection.is_some() {
            ctx.refused(&host, port, check, notice);
        }
    };
    let mut res = {
        let mut guard = sender.lock().await;
        if let Err(e) = guard.ready().await {
            sign_in_failed("proxy_upstream_closed", "the session proxy could not deliver the sign-in");
            return gateway_error("proxy_upstream_closed", &host, port, &e.to_string());
        }
        match guard.send_request(Request::from_parts(parts, out_body)).await {
            Ok(res) => res,
            Err(e) => {
                sign_in_failed("proxy_upstream_failed", "the session proxy could not deliver the sign-in");
                return gateway_error("proxy_upstream_failed", &host, port, &e.to_string());
            }
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
    // Every secret this request carried is scrubbed from what it returns:
    // the password of a substituted sign-in, the header secret of an
    // injected request (a server may echo either back).
    let submit_secret = injection.filter(|_| scrub).map(|inj| &inj.secret);
    let header_secret = injector.map(HeaderInjector::secret);
    let secrets: Vec<&SessionSecret> = submit_secret.into_iter().chain(header_secret).collect();
    if secrets.is_empty() {
        return Response::from_parts(parts, stream_body(body));
    }
    // A failure to check the response withholds it. On the sign-in request
    // the fill ends with it; on an injected one it is audited.
    let withheld = |check: &'static str, notice: &'static str| {
        if submit_secret.is_some() {
            sign_in_failed(check, notice);
        } else {
            ctx.header_refused(&host, port, check);
        }
    };

    if let Some(encoding) = parts.headers.get(CONTENT_ENCODING) {
        if !encoding.as_bytes().eq_ignore_ascii_case(b"identity") {
            withheld(
                "proxy_response_encoded",
                "the session proxy withheld the sign-in response: it was compressed and could not be checked",
            );
            return gateway_error(
                "proxy_response_encoded",
                &host,
                port,
                "the response was compressed and could not be scrubbed",
            );
        }
    }
    let received = match collect_bounded(body, MAX_SCRUBBED_RESPONSE_BODY).await {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(CollectError::TooLarge) => {
            withheld(
                "proxy_response_too_large",
                "the session proxy withheld the sign-in response: it was too large to check",
            );
            return gateway_error("proxy_response_too_large", &host, port, "over the cap");
        }
        Err(CollectError::Read(e)) => {
            withheld("proxy_response_read", "the session proxy could not read the sign-in response");
            return gateway_error("proxy_response_read", &host, port, &e);
        }
    };
    let (body, replaced) = scrub_body(&secrets, received);
    let replaced = replaced + scrub_response_headers(&secrets, &mut parts.headers);
    // A sign-in's scrub is always reported; an injected request's only when
    // it found something, so ordinary API traffic writes no line per call.
    if submit_secret.is_some() || replaced > 0 {
        ctx.events.emit(ProxyEvent::Scrubbed { host: host.to_string(), port, replaced });
    }
    parts.headers.remove(TRANSFER_ENCODING);
    parts.headers.insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
    Response::from_parts(parts, bytes_body(body))
}

/// Scrub every secret from a buffered response body. Intermediate buffers
/// may hold a later secret, so each is wiped as it is replaced; the result
/// holds none.
fn scrub_body(secrets: &[&SessionSecret], received: Zeroizing<Vec<u8>>) -> (Vec<u8>, usize) {
    let mut current = received;
    let mut replaced = 0;
    for secret in secrets {
        let scrubbed = scrub_response(secret, &current);
        replaced += scrubbed.replaced;
        current = Zeroizing::new(scrubbed.body);
    }
    (std::mem::take(&mut *current), replaced)
}

/// Scrub every secret from the response's header values; returns how many
/// values changed. A value that cannot be rebuilt is dropped rather than
/// forwarded.
fn scrub_response_headers(secrets: &[&SessionSecret], headers: &mut HeaderMap) -> usize {
    let names: Vec<HeaderName> = headers.keys().cloned().collect();
    let mut changed = 0;
    for name in names {
        let values: Vec<HeaderValue> = headers.get_all(&name).iter().cloned().collect();
        let mut rebuilt: Vec<HeaderValue> = Vec::with_capacity(values.len());
        let mut touched = false;
        for value in values {
            let mut bytes = Zeroizing::new(value.as_bytes().to_vec());
            for secret in secrets {
                if let Some(scrubbed) = scrub_header_value(secret, &bytes) {
                    bytes = Zeroizing::new(scrubbed);
                    touched = true;
                    changed += 1;
                }
            }
            if let Ok(v) = HeaderValue::from_bytes(&bytes) {
                rebuilt.push(v);
            }
        }
        if touched {
            headers.remove(&name);
            for v in rebuilt {
                headers.append(name.clone(), v);
            }
        }
    }
    changed
}

/// A request the proxy would have injected a header into, refused: audited
/// by origin and check name, and — when it was the sign-in itself — the
/// fill ends with it.
fn refused_header(ctx: &ProxyCtx, host: &str, port: u16, refusal: HeaderRefusal, sign_in: bool) -> Response<ProxyBody> {
    log::warn!("web proxy: did not send a header-injected request to {host}:{port} ({})", refusal.check());
    ctx.header_refused(host, port, refusal.check());
    if sign_in {
        ctx.refused(host, port, refusal.check(), refusal.notice());
    }
    plain_response(StatusCode::BAD_GATEWAY, refusal.check())
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

fn refused_submit(ctx: &ProxyCtx, host: &str, port: u16, reason: RefuseReason) -> Response<ProxyBody> {
    log::warn!("web proxy: did not forward the sign-in request to {host}:{port} ({})", reason.check());
    ctx.refused(host, port, reason.check(), reason.notice());
    plain_response(StatusCode::BAD_GATEWAY, reason.check())
}

/// The window's text for an upstream certificate the proxy refused. Fixed:
/// never a name from the certificate.
fn refusal_notice(refusal: UpstreamRefusal) -> &'static str {
    match refusal {
        UpstreamRefusal::Unpinned => {
            "the session proxy refused the server's certificate: this computer does not trust it and the profile \
             pins none"
        }
        UpstreamRefusal::Pin(_) => {
            "the session proxy refused the server's certificate: it matches none of the profile's pins"
        }
    }
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
        (!(keep_upgrade && is_upgrade_header(name)) && (HOP_BY_HOP.contains(&name) || listed.iter().any(|t| t == name)))
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

/// Dial and verify the upstream origin, and say how it was admitted. The
/// verdict is the one the session's verifier recorded for the leaf this
/// connection presented (a resumed session presents its original chain).
async fn connect_upstream(
    ctx: &ProxyCtx,
    host: &str,
    port: u16,
) -> Result<(tokio_rustls::client::TlsStream<TcpStream>, UpstreamTrust), String> {
    let tcp = dial(host, port).await?;
    let name = ServerName::try_from(bare_host(host).to_string())
        .map_err(|e| format!("`{host}` is not a valid TLS server name: {e}"))?;
    let tls = timeout(TLS_TIMEOUT, ctx.connector.connect(name, tcp))
        .await
        .map_err(|_| "the TLS handshake timed out".to_string())?
        .map_err(|e| format!("the TLS handshake failed: {e}"))?;
    // Never reached without a verdict: the handshake succeeded only through
    // the verifier. Should it happen anyway, the origin is not reported as
    // verified — the connection is refused.
    let trust = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .and_then(|leaf| ctx.verifier.verdict(bare_host(host), leaf.as_ref()))
        .ok_or_else(|| "the upstream's verdict is missing; refusing it as unverified".to_string())?;
    Ok((tls, trust))
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

    use bastion_vault::modules::resource::connect_web::recipe::HeaderFormat;

    use super::*;
    use crate::session::web_proxy::BodyType;

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
        /// Request headers the upstream received, in the same order.
        received_headers: Arc<StdMutex<Vec<HeaderMap>>>,
    }

    /// Bytes of filler in front of the `/api/big` echo: one past the scrub cap.
    const BIG_RESPONSE: usize = MAX_SCRUBBED_RESPONSE_BODY + 1;

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
        let received_headers: Arc<StdMutex<Vec<HeaderMap>>> = Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::clone(&received);
        let header_sink = Arc::clone(&received_headers);

        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else { return };
                let acceptor = acceptor.clone();
                let sink = Arc::clone(&sink);
                let header_sink = Arc::clone(&header_sink);
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(sock).await else { return };
                    let service = service_fn(move |req: Request<Incoming>| {
                        let sink = Arc::clone(&sink);
                        let header_sink = Arc::clone(&header_sink);
                        async move {
                            let upgrade = wants_upgrade(req.headers());
                            let path = req.uri().path().to_string();
                            // The application echoes the `Authorization` it
                            // received, in its body and in a header — so an
                            // injected secret that reaches it comes back, and
                            // the scrub has something to remove.
                            let auth = req
                                .headers()
                                .get("authorization")
                                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
                            header_sink.lock().unwrap().push(req.headers().clone());
                            let mut req = req;
                            let on_upgrade = hyper::upgrade::on(&mut req);
                            let body = req.into_body().collect().await.unwrap().to_bytes().to_vec();
                            sink.lock().unwrap().push(body.clone());
                            if let Some(auth) = auth.as_deref().filter(|_| !upgrade) {
                                let echoed = format!("<html>auth: {auth}</html>");
                                let mut res = Response::builder()
                                    .status(StatusCode::OK)
                                    .header(CONTENT_TYPE, "text/html")
                                    .header("x-echo-authorization", auth);
                                let echoed = if path.starts_with("/api/gzip") {
                                    // Compressed despite the identity request.
                                    res = res.header(CONTENT_ENCODING, "gzip");
                                    echoed.into_bytes()
                                } else if path.starts_with("/api/big") {
                                    let mut big = vec![b'a'; BIG_RESPONSE];
                                    big.extend_from_slice(echoed.as_bytes());
                                    big
                                } else {
                                    echoed.into_bytes()
                                };
                                return Ok::<_, Infallible>(res.body(bytes_body(echoed)).unwrap());
                            }
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

        Upstream { port, cert_der, received, received_headers }
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

    type EventLog = Arc<StdMutex<Vec<ProxyEvent>>>;

    fn injection_for(origin: &str, secret: &str) -> (ProxyInjection, String) {
        let secret = SessionSecret::new(secret.to_string()).unwrap();
        let placeholder = secret.placeholder().to_string();
        let target = SubmitTarget::new(origin, "/login", BodyType::Form).unwrap();
        (ProxyInjection { secret, target }, placeholder)
    }

    async fn start_proxy_logged(upstream: &Upstream, secret: &str, pins: PinSet) -> (WebProxy, String, EventLog) {
        let origin = format!("https://{HOST}:{}", upstream.port);
        let (injection, placeholder) = injection_for(&origin, secret);
        let log: EventLog = Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::clone(&log);
        let proxy = WebProxy::start(ProxyConfig {
            scope: TerminationScope::new([origin.as_str()]).unwrap(),
            pins,
            events: ProxyEvents::new(move |e| sink.lock().unwrap().push(e)),
        })
        .await
        .unwrap();
        proxy.arm(injection).unwrap();
        (proxy, placeholder, log)
    }

    async fn start_proxy(upstream: &Upstream, secret: &str, pins: PinSet) -> (WebProxy, String) {
        let (proxy, placeholder, _) = start_proxy_logged(upstream, secret, pins).await;
        (proxy, placeholder)
    }

    /// A terminated, TLS-wrapped HTTP/1.1 client for the upstream's origin,
    /// as the session webview would hold one.
    async fn session_client(proxy: &WebProxy, upstream: &Upstream) -> SendRequest<ProxyBody> {
        let authority = format!("{HOST}:{}", upstream.port);
        let (sock, status) = open_connect(proxy, &authority).await;
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        let tls = TlsConnector::from(session_client_config(proxy))
            .connect(ServerName::try_from(HOST).unwrap(), sock)
            .await
            .unwrap();
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender
    }

    fn login_post(upstream: &Upstream, body: String) -> Request<ProxyBody> {
        Request::builder()
            .method("POST")
            .uri("/login")
            .header(HOST, format!("{HOST}:{}", upstream.port))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(bytes_body(body.into_bytes()))
            .unwrap()
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
        let proxy = WebProxy::start(ProxyConfig {
            scope: TerminationScope::new(["https://app.example.test"]).unwrap(),
            pins: PinSet::default(),
            events: ProxyEvents::default(),
        })
        .await
        .unwrap();
        let (injection, _) = injection_for("https://sso.example.test", "pw");
        let err = proxy.arm(injection).err().expect("a submit target outside the scope must not be armed");
        assert!(err.contains("not one of the session's terminated origins"), "{err}");
        assert!(!proxy.holds_secret());
    }

    /// What the audit lines are written from (T106 step 6): one termination
    /// per origin with how its upstream was admitted, then the substitution
    /// and the scrub — origins and counts only.
    #[tokio::test]
    async fn termination_substitution_and_scrubbing_are_reported() {
        let upstream = start_upstream().await;
        let (proxy, placeholder, log) =
            start_proxy_logged(&upstream, "s3cret-value", pins_of(&upstream.cert_der)).await;
        let port = upstream.port;
        let mut sender = session_client(&proxy, &upstream).await;
        // A second CONNECT to the same origin is not a second termination.
        let _again = session_client(&proxy, &upstream).await;
        let res = sender.send_request(login_post(&upstream, format!("password={placeholder}"))).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let _ = res.into_body().collect().await.unwrap();

        // The upstream's self-signed certificate is admitted by the profile's
        // leaf pin, not by the platform.
        let upstream_trust = UpstreamTrust::Pinned(bastion_vault::utils::tls_pin::PinMatch::Leaf);
        assert_eq!(proxy.upstream_trust(HOST, port), Some(upstream_trust));
        let events = log.lock().unwrap().clone();
        assert_eq!(
            events,
            vec![
                ProxyEvent::Terminated { host: HOST.into(), port, upstream: upstream_trust },
                ProxyEvent::Substituted { host: HOST.into(), port },
                // The upstream echoes the body, so the secret came back once.
                ProxyEvent::Scrubbed { host: HOST.into(), port, replaced: 1 },
            ]
        );
        for e in &events {
            let shown = format!("{e:?}");
            assert!(!shown.contains("s3cret-value") && !shown.contains(&placeholder), "{shown}");
        }
    }

    #[tokio::test]
    async fn a_refused_sign_in_and_an_untrusted_upstream_are_reported() {
        let upstream = start_upstream().await;
        let (proxy, placeholder, log) =
            start_proxy_logged(&upstream, "s3cret-value", pins_of(&upstream.cert_der)).await;
        let mut sender = session_client(&proxy, &upstream).await;
        let res = sender.send_request(login_post(&upstream, format!("a={placeholder}&b={placeholder}"))).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
        let refused = RefuseReason::PlaceholderRepeated;
        assert!(log.lock().unwrap().contains(&ProxyEvent::Refused {
            host: HOST.into(),
            port: upstream.port,
            check: refused.check(),
            notice: refused.notice(),
        }));

        // No pin, self-signed: the CONNECT fails and the refusal is named.
        let (unpinned, _, log) = start_proxy_logged(&upstream, "pw", PinSet::default()).await;
        let (_sock, status) = open_connect(&unpinned, &format!("{HOST}:{}", upstream.port)).await;
        assert!(status.starts_with("HTTP/1.1 502"), "{status}");
        assert_eq!(
            *log.lock().unwrap(),
            vec![ProxyEvent::Refused {
                host: HOST.into(),
                port: upstream.port,
                check: "proxy_upstream_untrusted",
                notice: refusal_notice(UpstreamRefusal::Unpinned),
            }]
        );
    }

    /// Once the sign-in ends the host drops the secret: the same request then
    /// goes out with the placeholder — the proxy no longer holds anything to
    /// put in its place.
    #[tokio::test]
    async fn a_released_secret_is_never_substituted_again() {
        let upstream = start_upstream().await;
        let origin = format!("https://{HOST}:{}", upstream.port);
        let (proxy, _) = start_proxy(&upstream, "unused", pins_of(&upstream.cert_der)).await;
        let (injection, placeholder) = injection_for(&origin, "s3cret-value");
        let ticket = proxy.arm(injection).unwrap();
        assert!(proxy.holds_secret());
        assert!(proxy.release(ticket));
        assert!(!proxy.holds_secret());
        let mut sender = session_client(&proxy, &upstream).await;
        let res = sender.send_request(login_post(&upstream, format!("password={placeholder}"))).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let received = String::from_utf8(upstream.received.lock().unwrap()[0].clone()).unwrap();
        assert_eq!(received, format!("password={placeholder}"));
    }

    /// A re-run login arms a new secret while the previous sign-in is being
    /// retired: the retiring one's release must not take the new secret away.
    #[tokio::test]
    async fn a_release_never_drops_a_later_sign_ins_secret() {
        let upstream = start_upstream().await;
        let origin = format!("https://{HOST}:{}", upstream.port);
        let (proxy, _) = start_proxy(&upstream, "unused", pins_of(&upstream.cert_der)).await;
        let (first, _) = injection_for(&origin, "first");
        let (second, _) = injection_for(&origin, "second");
        let old = proxy.arm(first).unwrap();
        let new = proxy.arm(second).unwrap();
        assert_ne!(old, new);
        assert!(!proxy.release(old), "the retired sign-in's ticket no longer names the armed secret");
        assert!(proxy.holds_secret());
        assert!(proxy.release(new));
        assert!(!proxy.release(new), "released once");
        // Shutting the proxy down drops whatever it held.
        let (third, _) = injection_for(&origin, "third");
        proxy.arm(third).unwrap();
        proxy.shutdown();
        assert!(!proxy.holds_secret());
    }

    // ---- header injection (T106 step 7) ----------------------------------

    const HEADER_SECRET: &str = "hdr-S3CRET-token-0001";

    fn bearer_on(origin: &str, prefix: &str) -> HeaderInjection {
        HeaderInjection::new("Authorization", HeaderFormat::Bearer, origin, prefix).unwrap()
    }

    /// A proxy armed with a sign-in (as every proxy-mode session is) and with
    /// `Authorization: Bearer <HEADER_SECRET>` on `/api` of the upstream.
    async fn start_injecting(upstream: &Upstream) -> (WebProxy, String, EventLog) {
        let (proxy, password_placeholder, log) =
            start_proxy_logged(upstream, "s3cret-password", pins_of(&upstream.cert_der)).await;
        let origin = format!("https://{HOST}:{}", upstream.port);
        let injector = HeaderInjector::new(HEADER_SECRET.to_string(), vec![bearer_on(&origin, "/api")]).unwrap();
        proxy.arm_headers(injector).unwrap();
        (proxy, password_placeholder, log)
    }

    /// `hyper::header::HOST` spelled out: inside this module `HOST` is the
    /// test host name, not the header.
    fn get(upstream: &Upstream, path: &str, auth: Option<&str>) -> Request<ProxyBody> {
        let mut req =
            Request::builder().method("GET").uri(path).header(hyper::header::HOST, format!("{HOST}:{}", upstream.port));
        if let Some(auth) = auth {
            req = req.header("authorization", auth);
        }
        req.body(empty_body()).unwrap()
    }

    async fn body_text(res: Response<Incoming>) -> String {
        String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
    }

    fn assert_no_secret(log: &EventLog) {
        for e in log.lock().unwrap().iter() {
            let shown = format!("{e:?} {}", e.origin());
            assert!(!shown.contains(HEADER_SECRET), "{shown}");
        }
    }

    #[tokio::test]
    async fn an_injected_header_reaches_the_upstream_and_is_scrubbed_from_the_reply() {
        let upstream = start_upstream().await;
        let (proxy, _, log) = start_injecting(&upstream).await;
        let mut sender = session_client(&proxy, &upstream).await;

        let res = sender.send_request(get(&upstream, "/api/v1/items", None)).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        // Echoed in a response header too: scrubbed there as well.
        let echoed_header = res.headers().get("x-echo-authorization").unwrap().to_str().unwrap().to_string();
        assert!(!echoed_header.contains(HEADER_SECRET), "{echoed_header}");
        assert!(echoed_header.starts_with("Bearer "), "{echoed_header}");
        let seen = body_text(res).await;
        assert!(!seen.contains(HEADER_SECRET), "the header secret came back to the page: {seen}");

        let got = upstream.received_headers.lock().unwrap()[0].clone();
        assert_eq!(got.get_all("authorization").iter().count(), 1);
        assert_eq!(got.get("authorization").unwrap(), format!("Bearer {HEADER_SECRET}").as_str());
        assert_eq!(got.get(ACCEPT_ENCODING).unwrap(), "identity");

        let port = upstream.port;
        let events = log.lock().unwrap().clone();
        assert!(events.contains(&ProxyEvent::HeaderInjected { host: HOST.into(), port }), "{events:?}");
        assert!(!events.iter().any(|e| matches!(e, ProxyEvent::HeaderReplaced { .. })), "{events:?}");
        // Body and header copies, both scrubbed.
        assert!(events.contains(&ProxyEvent::Scrubbed { host: HOST.into(), port, replaced: 2 }), "{events:?}");

        // A second request injects again but is not reported again.
        let res = sender.send_request(get(&upstream, "/api", None)).await.unwrap();
        let _ = body_text(res).await;
        let injected = log.lock().unwrap().iter().filter(|e| matches!(e, ProxyEvent::HeaderInjected { .. })).count();
        assert_eq!(injected, 1);
        assert_no_secret(&log);
    }

    /// The page sending the header itself: the proxy's value replaces it —
    /// the upstream sees one header, the operator's — and that is audited.
    #[tokio::test]
    async fn a_header_the_page_sent_is_replaced_and_reported() {
        let upstream = start_upstream().await;
        let (proxy, _, log) = start_injecting(&upstream).await;
        let mut sender = session_client(&proxy, &upstream).await;

        let res = sender.send_request(get(&upstream, "/api/me", Some("Bearer page-chosen-token"))).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let _ = body_text(res).await;
        let got = upstream.received_headers.lock().unwrap()[0].clone();
        let values: Vec<_> = got.get_all("authorization").iter().collect();
        assert_eq!(values, vec![format!("Bearer {HEADER_SECRET}").as_str()]);
        assert!(log.lock().unwrap().contains(&ProxyEvent::HeaderReplaced { host: HOST.into(), port: upstream.port }));
        assert_no_secret(&log);
    }

    /// Outside the path prefix — including `/apix`, which `/api` must not
    /// cover — the request goes out exactly as the page sent it, and its
    /// response streams unscrubbed (it never carried the secret).
    #[tokio::test]
    async fn a_request_outside_the_injection_scope_is_untouched() {
        let upstream = start_upstream().await;
        let (proxy, _, log) = start_injecting(&upstream).await;
        let mut sender = session_client(&proxy, &upstream).await;

        for (i, path) in ["/apix", "/apix/v1", "/", "/login-page"].into_iter().enumerate() {
            let res = sender.send_request(get(&upstream, path, Some("Bearer page-chosen-token"))).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK, "{path}");
            let seen = body_text(res).await;
            assert!(seen.contains("page-chosen-token"), "{path}: {seen}");
            let got = upstream.received_headers.lock().unwrap()[i].clone();
            assert_eq!(got.get("authorization").unwrap(), "Bearer page-chosen-token", "{path}");
            assert!(got.get(ACCEPT_ENCODING).is_none(), "{path}");
        }
        // No header requests: nothing injected at all.
        let res = sender.send_request(get(&upstream, "/apix", None)).await.unwrap();
        let _ = body_text(res).await;
        assert!(upstream.received_headers.lock().unwrap().last().unwrap().get("authorization").is_none());
        let events = log.lock().unwrap().clone();
        assert!(
            !events.iter().any(|e| matches!(
                e,
                ProxyEvent::HeaderInjected { .. } | ProxyEvent::HeaderReplaced { .. } | ProxyEvent::Scrubbed { .. }
            )),
            "{events:?}"
        );
    }

    /// The secret never goes onto a stream the scrub cannot see (an upgrade)
    /// or to another authority (`Host` mismatch): both are refused before
    /// the upstream sees anything.
    #[tokio::test]
    async fn an_upgrade_or_a_foreign_host_on_an_injected_path_is_refused() {
        let upstream = start_upstream().await;
        let (proxy, _, log) = start_injecting(&upstream).await;
        let authority = format!("{HOST}:{}", upstream.port);

        let mut sender = session_client(&proxy, &upstream).await;
        let ws = Request::builder()
            .method("GET")
            .uri("/api/socket")
            .header(hyper::header::HOST, &authority)
            .header(CONNECTION, "upgrade")
            .header(UPGRADE, "websocket")
            .body(empty_body())
            .unwrap();
        let res = sender.send_request(ws).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
        assert!(!body_text(res).await.contains(HEADER_SECRET));

        let mut sender = session_client(&proxy, &upstream).await;
        let foreign = Request::builder()
            .method("GET")
            .uri("/api/v1")
            .header(hyper::header::HOST, "other.example.test")
            .body(empty_body())
            .unwrap();
        let res = sender.send_request(foreign).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_GATEWAY);

        assert!(upstream.received_headers.lock().unwrap().is_empty(), "the upstream saw a refused request");
        let port = upstream.port;
        let events = log.lock().unwrap().clone();
        for check in [HeaderRefusal::Upgrade.check(), HeaderRefusal::HostMismatch.check()] {
            assert!(events.contains(&ProxyEvent::HeaderRefused { host: HOST.into(), port, check }), "{events:?}");
        }
        // Not the sign-in: the fill is not told.
        assert!(!events.iter().any(|e| matches!(e, ProxyEvent::Refused { .. })), "{events:?}");
        assert_no_secret(&log);
    }

    /// Regression: when the response to an injected request cannot be
    /// checked (compressed despite the identity request, or over the cap),
    /// it is withheld — the page gets a fixed refusal, never the echoed
    /// secret — and the refusal is audited without it.
    #[tokio::test]
    async fn an_unscrubbable_response_to_an_injected_request_is_withheld() {
        let upstream = start_upstream().await;
        let (proxy, _, log) = start_injecting(&upstream).await;
        let mut sender = session_client(&proxy, &upstream).await;

        for (path, check) in [("/api/gzip", "proxy_response_encoded"), ("/api/big", "proxy_response_too_large")] {
            let res = sender.send_request(get(&upstream, path, None)).await.unwrap();
            assert_eq!(res.status(), StatusCode::BAD_GATEWAY, "{path}");
            assert!(res.headers().get("x-echo-authorization").is_none(), "{path}");
            let seen = body_text(res).await;
            assert!(!seen.contains(HEADER_SECRET), "{path}: {seen}");
            assert_eq!(seen, format!("BastionVault session proxy: {check}\n"));
            assert!(
                log.lock().unwrap().contains(&ProxyEvent::HeaderRefused {
                    host: HOST.into(),
                    port: upstream.port,
                    check
                }),
                "{path}"
            );
            // The connection closes after a refusal; reconnect for the next.
            sender = session_client(&proxy, &upstream).await;
        }
        assert_no_secret(&log);
    }

    /// Entries outside the termination scope are refused at launch, never
    /// skipped, and the refusal carries neither secret.
    #[tokio::test]
    async fn header_injection_outside_the_termination_scope_is_refused_at_launch() {
        let proxy = WebProxy::start(ProxyConfig {
            scope: TerminationScope::new(["https://app.example.test"]).unwrap(),
            pins: PinSet::default(),
            events: ProxyEvents::default(),
        })
        .await
        .unwrap();
        for origin in ["https://api.example.test", "https://app.example.test:8443"] {
            let injector = HeaderInjector::new(
                HEADER_SECRET.to_string(),
                vec![bearer_on("https://app.example.test", "/api"), bearer_on(origin, "/")],
            )
            .unwrap();
            let err = proxy.arm_headers(injector).unwrap_err();
            assert!(err.contains("not one of the session's terminated origins"), "{err}");
            assert!(!err.contains(HEADER_SECRET), "{err}");
            assert!(!proxy.holds_header_secret());
        }
        let ok = HeaderInjector::new(HEADER_SECRET.to_string(), vec![bearer_on("https://app.example.test", "/")]);
        proxy.arm_headers(ok.unwrap()).unwrap();
        assert!(proxy.holds_header_secret());
        proxy.shutdown();
        assert!(!proxy.holds_header_secret(), "shutdown drops the header secret");
    }

    /// The header secret is for the session: releasing the sign-in's
    /// password leaves the injection in place.
    #[tokio::test]
    async fn the_header_secret_outlives_the_sign_in() {
        let upstream = start_upstream().await;
        let origin = format!("https://{HOST}:{}", upstream.port);
        let (proxy, _, _) = start_injecting(&upstream).await;
        let (injection, _) = injection_for(&origin, "another-password");
        let ticket = proxy.arm(injection).unwrap();
        assert!(proxy.release(ticket));
        assert!(!proxy.holds_secret() && proxy.holds_header_secret());

        let mut sender = session_client(&proxy, &upstream).await;
        let res = sender.send_request(get(&upstream, "/api/after-sign-in", None)).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(!body_text(res).await.contains(HEADER_SECRET));
        let got = upstream.received_headers.lock().unwrap()[0].clone();
        assert_eq!(got.get("authorization").unwrap(), format!("Bearer {HEADER_SECRET}").as_str());
    }

    /// The sign-in request inside an injection scope gets both: the password
    /// substituted into its body and the header set, and both secrets are
    /// scrubbed from its response.
    #[tokio::test]
    async fn a_sign_in_on_an_injected_path_carries_both_and_returns_neither() {
        let upstream = start_upstream().await;
        let origin = format!("https://{HOST}:{}", upstream.port);
        let (proxy, placeholder, _) =
            start_proxy_logged(&upstream, "s3cret-password", pins_of(&upstream.cert_der)).await;
        let injector = HeaderInjector::new(HEADER_SECRET.to_string(), vec![bearer_on(&origin, "/")]).unwrap();
        proxy.arm_headers(injector).unwrap();
        let mut sender = session_client(&proxy, &upstream).await;

        let res = sender.send_request(login_post(&upstream, format!("password={placeholder}"))).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let seen = body_text(res).await;
        assert!(!seen.contains(HEADER_SECRET) && !seen.contains("s3cret-password"), "{seen}");
        assert_eq!(
            String::from_utf8(upstream.received.lock().unwrap()[0].clone()).unwrap(),
            "password=s3cret-password"
        );
        let got = upstream.received_headers.lock().unwrap()[0].clone();
        assert_eq!(got.get("authorization").unwrap(), format!("Bearer {HEADER_SECRET}").as_str());
    }
}
