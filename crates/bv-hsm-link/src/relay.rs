//! The node-side relay: `yubihsm` 0.42 speaks only plain HTTP, so each
//! `yubihsm::Client` talks to a relay on `127.0.0.1:<ephemeral>`, which
//! forwards over a pooled mTLS connection to the member's gateway.

use std::{
    fmt, io,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Arc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use bv_errors::RvError;
use log::{debug, info, warn};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::{
    config::{GatewayUrl, RelayConfig, RelayLimits},
    http::{
        encode_request, encode_response, BodyFraming, HttpConn, ReadError, Request, Response, ResponseError, Version,
    },
    tls,
};

/// Counters since start; for tests and future `bv_hsm_link_*` metrics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayStats {
    pub local_connections: u64,
    pub requests_forwarded: u64,
    /// Rejected locally, or the gateway was unreachable or answered badly.
    pub requests_failed: u64,
    /// mTLS connections opened to the gateway.
    pub gateway_connects: u64,
}

#[derive(Default)]
struct Counters {
    local_connections: AtomicU64,
    requests_forwarded: AtomicU64,
    requests_failed: AtomicU64,
    gateway_connects: AtomicU64,
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

struct RelayState {
    connector: TlsConnector,
    gateway: GatewayUrl,
    limits: RelayLimits,
    counters: Arc<Counters>,
}

/// A running relay. It owns a thread with its own current-thread runtime, so
/// it works the same from blocking and async callers. Dropping it stops it.
/// Use one relay per `yubihsm::Client`: it serves one connection at a time.
pub struct Relay {
    local_addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
    counters: Arc<Counters>,
}

impl Relay {
    /// Builds the TLS client, binds `127.0.0.1:0` and starts serving. Every
    /// configuration error is returned here, before anything listens.
    pub fn start(config: RelayConfig) -> Result<Self, RvError> {
        config.validate()?;
        let connector = TlsConnector::from(tls::client_config(&config.tls)?);
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let local_addr = listener.local_addr()?;
        let counters = Arc::new(Counters::default());
        let state =
            RelayState { connector, gateway: config.gateway, limits: config.limits, counters: counters.clone() };
        let gateway = state.gateway.to_string();
        let (stop_tx, stop_rx) = oneshot::channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let thread = std::thread::Builder::new()
            .name(format!("bv-hsm-relay-{}", local_addr.port()))
            .spawn(move || run(listener, state, stop_rx, ready_tx))
            .map_err(|e| RvError::ErrHsm(format!("HSM relay thread could not start: {e}")))?;
        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(RvError::ErrHsm(format!("HSM relay could not start: {e}"))),
            Err(_) => return Err(RvError::ErrHsm("HSM relay thread exited during start".into())),
        }
        info!("hsm-link relay: listening on {local_addr} for gateway {gateway}");
        Ok(Self { local_addr, stop: Some(stop_tx), thread: Some(thread), counters })
    }

    /// Where the `yubihsm` HTTP connector should point (`127.0.0.1:<port>`).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn stats(&self) -> RelayStats {
        let c = &self.counters;
        RelayStats {
            local_connections: c.local_connections.load(Ordering::Relaxed),
            requests_forwarded: c.requests_forwarded.load(Ordering::Relaxed),
            requests_failed: c.requests_failed.load(Ordering::Relaxed),
            gateway_connects: c.gateway_connects.load(Ordering::Relaxed),
        }
    }

    /// Stops serving, closes every connection and waits for the thread.
    pub fn shutdown(mut self) {
        self.stop_and_join();
    }

    fn stop_and_join(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                warn!("hsm-link relay: thread for {} panicked", self.local_addr);
            }
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

fn run(
    listener: std::net::TcpListener,
    state: RelayState,
    stop: oneshot::Receiver<()>,
    ready: mpsc::SyncSender<Result<(), String>>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_io().enable_time().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            let _ = ready.send(Err(format!("runtime: {e}")));
            return;
        }
    };
    runtime.block_on(async move {
        let listener = match TcpListener::from_std(listener) {
            Ok(listener) => listener,
            Err(e) => {
                let _ = ready.send(Err(format!("listener: {e}")));
                return;
            }
        };
        let _ = ready.send(Ok(()));
        // Dropping the loop future cancels whatever it was doing.
        tokio::select! {
            _ = stop => {}
            _ = relay_loop(&listener, &state) => {}
        }
    });
}

struct Local {
    conn: HttpConn<TcpStream>,
    peer: SocketAddr,
}

/// Same-host loopback peers only. The listener is bound to 127.0.0.1, so
/// this is a second check, not the only one.
fn admit_local(accepted: io::Result<(TcpStream, SocketAddr)>, state: &RelayState) -> Option<Local> {
    match accepted {
        Ok((stream, peer)) if peer.ip().is_loopback() => {
            let _ = stream.set_nodelay(true);
            bump(&state.counters.local_connections);
            debug!("hsm-link relay: local connection from {peer}");
            Some(Local { conn: HttpConn::new(stream), peer })
        }
        Ok((_, peer)) => {
            warn!("hsm-link relay: refusing non-loopback peer {peer}");
            None
        }
        Err(e) => {
            warn!("hsm-link relay: accept failed: {e}");
            None
        }
    }
}

enum Event {
    Accepted(io::Result<(TcpStream, SocketAddr)>),
    Read(io::Result<usize>),
}

/// One local connection at a time. A newcomer replaces an idle connection
/// at once (a stale or squatting one cannot block the node's client) and
/// waits for the answer if a request is in progress. Never two at once.
async fn relay_loop(listener: &TcpListener, state: &RelayState) {
    let mut gateway: Option<Upstream> = None;
    let mut current: Option<Local> = None;
    let mut waiting: Option<Local> = None;
    loop {
        let Some(local) = current.as_mut() else {
            current = match waiting.take() {
                Some(next) => Some(next),
                None => {
                    let accepted = listener.accept().await;
                    if accepted.is_err() {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    admit_local(accepted, state)
                }
            };
            continue;
        };
        let event = tokio::select! {
            accepted = listener.accept(), if waiting.is_none() => Event::Accepted(accepted),
            read = local.conn.fill() => Event::Read(read),
        };
        match event {
            Event::Accepted(accepted) => {
                let Some(next) = admit_local(accepted, state) else { continue };
                if local.conn.has_buffered() {
                    waiting = Some(next);
                } else {
                    debug!("hsm-link relay: {} replaces idle local connection {}", next.peer, local.peer);
                    current = Some(next);
                }
            }
            Event::Read(Ok(0)) | Event::Read(Err(_)) => {
                debug!("hsm-link relay: local connection {} closed", local.peer);
                current = None;
            }
            Event::Read(Ok(_)) => {
                let keep_open = serve_request(local, &mut gateway, state).await;
                if !keep_open || waiting.is_some() {
                    current = None;
                }
            }
        }
    }
}

/// Finishes the request whose first bytes have arrived, forwards it and
/// answers. Returns whether the local connection may carry another one.
async fn serve_request(local: &mut Local, gateway: &mut Option<Upstream>, state: &RelayState) -> bool {
    let request = match local.conn.read_request(state.limits.request_timeout).await {
        Ok(request) => request,
        Err(ReadError::Reject(rejection)) => {
            bump(&state.counters.requests_failed);
            warn!("hsm-link relay: local request rejected with {}: {}", rejection.status, rejection.why);
            local.conn.reject_and_close(rejection.status).await;
            return false;
        }
        Err(ReadError::Timeout) => {
            bump(&state.counters.requests_failed);
            warn!("hsm-link relay: local request not complete within the request timeout");
            local.conn.reject_and_close(408).await;
            return false;
        }
        Err(ReadError::Truncated) => return false,
        Err(ReadError::Io(e)) => {
            debug!("hsm-link relay: local read failed: {e}");
            return false;
        }
    };
    let (status, body) = match forward(gateway, state, &request).await {
        Ok(response) => {
            bump(&state.counters.requests_forwarded);
            (response.status, response.body)
        }
        Err(e) => {
            bump(&state.counters.requests_failed);
            warn!("hsm-link relay: gateway {} request failed: {e}", state.gateway);
            (e.status(), Vec::new())
        }
    };
    let reply = encode_response(status, &body, request.close);
    let written = timeout(state.limits.request_timeout, local.conn.write_all(&reply)).await;
    matches!(written, Ok(Ok(()))) && !request.close
}

/// A pooled mTLS connection to the gateway.
struct Upstream {
    conn: HttpConn<TlsStream<TcpStream>>,
    idle_since: Instant,
}

impl Upstream {
    /// False if the gateway closed it, reset it or sent something unasked.
    /// One poll of the socket and no waiting: a pending read means alive.
    async fn still_open(&mut self) -> bool {
        if self.conn.has_buffered() {
            return false;
        }
        timeout(Duration::ZERO, self.conn.fill()).await.is_err()
    }
}

#[derive(Debug)]
enum LinkError {
    Resolve(io::Error),
    Connect(io::Error),
    Handshake(io::Error),
    Send(io::Error),
    Response(ResponseError),
    Timeout,
}

impl LinkError {
    fn status(&self) -> u16 {
        match self {
            LinkError::Timeout => 504,
            _ => 502,
        }
    }
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkError::Resolve(e) => write!(f, "cannot resolve: {e}"),
            LinkError::Connect(e) => write!(f, "cannot connect: {e}"),
            LinkError::Handshake(e) => write!(f, "TLS handshake failed: {e}"),
            LinkError::Send(e) => write!(f, "send failed: {e}"),
            LinkError::Response(e) => write!(f, "{e}"),
            LinkError::Timeout => f.write_str("timed out"),
        }
    }
}

async fn connect(state: &RelayState) -> Result<Upstream, LinkError> {
    let server_name = state.gateway.server_name().map_err(|e| LinkError::Resolve(io::Error::other(e.to_string())))?;
    let attempt = async {
        let addrs = state.gateway.resolve().await.map_err(LinkError::Resolve)?;
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no address");
        let mut tcp = None;
        for addr in addrs {
            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    tcp = Some(stream);
                    break;
                }
                Err(e) => last = e,
            }
        }
        let tcp = tcp.ok_or(LinkError::Connect(last))?;
        let _ = tcp.set_nodelay(true);
        let tls = state.connector.connect(server_name, tcp).await.map_err(LinkError::Handshake)?;
        bump(&state.counters.gateway_connects);
        debug!("hsm-link relay: connected to gateway {}", state.gateway);
        Ok(Upstream { conn: HttpConn::new(tls), idle_since: Instant::now() })
    };
    timeout(state.limits.connect_timeout, attempt).await.unwrap_or(Err(LinkError::Timeout))
}

/// Sends one request over the pooled connection, opening one if needed. A
/// failed exchange is not retried: a command the device may have run must
/// not be replayed, so the node's client sees the error and decides.
async fn forward(gateway: &mut Option<Upstream>, state: &RelayState, request: &Request) -> Result<Response, LinkError> {
    if let Some(existing) = gateway.as_mut() {
        if existing.idle_since.elapsed() >= state.limits.pool_idle_timeout || !existing.still_open().await {
            debug!("hsm-link relay: replacing a stale gateway connection");
            *gateway = None;
        }
    }
    let upstream = match gateway {
        Some(upstream) => upstream,
        None => gateway.insert(connect(state).await?),
    };
    let bytes = encode_request(request.endpoint, &state.gateway.host_header(), &request.body, Version::Http11);
    let exchange = async {
        upstream.conn.write_all(&bytes).await.map_err(LinkError::Send)?;
        upstream.conn.read_response(BodyFraming::ContentLength).await.map_err(LinkError::Response)
    };
    let result = timeout(state.limits.exchange_timeout, exchange).await.unwrap_or(Err(LinkError::Timeout));
    match &result {
        Ok(response) if !response.close => upstream.idle_since = Instant::now(),
        _ => *gateway = None,
    }
    result
}
