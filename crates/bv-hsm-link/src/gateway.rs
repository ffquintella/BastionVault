//! The gateway (`bvault hsm-gateway`): mTLS in front of a loopback
//! `yubihsm-connector`. It has no storage and no tokens; it authenticates
//! nodes, bounds them, and passes bodies through untouched.

use std::{
    collections::HashMap,
    fmt,
    future::Future,
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, PoisonError,
    },
    time::{Duration, Instant},
};

use bv_errors::RvError;
use log::{debug, info, warn};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use crate::{
    config::{ConnectorUrl, GatewayConfig, GatewayLimits},
    http::{
        encode_request, encode_response, BodyFraming, HttpConn, ReadError, Request, Response, ResponseError, Version,
    },
    ratelimit::TokenBucket,
    tls,
};

/// Counters since start; for tests and future metrics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GatewayStats {
    /// Connections that passed TLS and the `allowed_clients` check.
    pub connections_accepted: u64,
    /// Over capacity, failed handshake, or client not allowed.
    pub connections_refused: u64,
    pub requests_forwarded: u64,
    /// Malformed, over a limit, rate-limited or concurrent.
    pub requests_rejected: u64,
    /// The connector could not be reached, timed out or answered badly.
    pub upstream_failures: u64,
}

#[derive(Default)]
struct Counters {
    connections_accepted: AtomicU64,
    connections_refused: AtomicU64,
    requests_forwarded: AtomicU64,
    requests_rejected: AtomicU64,
    upstream_failures: AtomicU64,
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// Per allowed client: one request in flight, and a request-rate bucket.
struct ClientSlot {
    in_flight: Arc<Semaphore>,
    bucket: Mutex<TokenBucket>,
}

struct Shared {
    acceptor: TlsAcceptor,
    connector: ConnectorUrl,
    clients: HashMap<String, ClientSlot>,
    limits: GatewayLimits,
    connection_slots: Arc<Semaphore>,
    counters: Counters,
}

/// A bound gateway. [`Gateway::serve`] runs it until the shutdown future
/// completes.
pub struct Gateway {
    listener: TcpListener,
    local_addr: SocketAddr,
    shared: Arc<Shared>,
}

impl Gateway {
    /// Validates `config`, builds the TLS acceptor and binds the listener.
    pub async fn bind(config: GatewayConfig) -> Result<Self, RvError> {
        config.validate()?;
        let acceptor = TlsAcceptor::from(tls::server_config(&config.tls)?);
        let now = Instant::now();
        let clients = config
            .allowed_clients
            .iter()
            .map(|id| {
                let slot = ClientSlot {
                    in_flight: Arc::new(Semaphore::new(1)),
                    bucket: Mutex::new(TokenBucket::new(config.max_rps_per_client, now)),
                };
                (id.clone(), slot)
            })
            .collect();
        let listener = TcpListener::bind(config.listen)
            .await
            .map_err(|e| RvError::ErrHsm(format!("hsm-gateway cannot listen on {}: {e}", config.listen)))?;
        let local_addr = listener.local_addr()?;
        let shared = Shared {
            acceptor,
            connector: config.connector,
            clients,
            connection_slots: Arc::new(Semaphore::new(config.limits.max_connections)),
            limits: config.limits,
            counters: Counters::default(),
        };
        Ok(Self { listener, local_addr, shared: Arc::new(shared) })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn stats(&self) -> GatewayStats {
        let c = &self.shared.counters;
        GatewayStats {
            connections_accepted: c.connections_accepted.load(Ordering::Relaxed),
            connections_refused: c.connections_refused.load(Ordering::Relaxed),
            requests_forwarded: c.requests_forwarded.load(Ordering::Relaxed),
            requests_rejected: c.requests_rejected.load(Ordering::Relaxed),
            upstream_failures: c.upstream_failures.load(Ordering::Relaxed),
        }
    }

    /// Accepts connections until `shutdown` completes, then aborts the open
    /// ones. A request cut off this way fails on the node like any transport
    /// error, and the node's pool fails over.
    pub async fn serve<F: Future<Output = ()>>(&self, shutdown: F) -> Result<(), RvError> {
        info!(
            "hsm-gateway: listening on {} for {} client(s), connector {}",
            self.local_addr,
            self.shared.clients.len(),
            self.shared.connector
        );
        tokio::pin!(shutdown);
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
                accepted = self.listener.accept() => match accepted {
                    Ok((tcp, peer)) => {
                        let Ok(permit) = self.shared.connection_slots.clone().try_acquire_owned() else {
                            bump(&self.shared.counters.connections_refused);
                            warn!(
                                "hsm-gateway: refusing connection from {peer}: {} connections already open",
                                self.shared.limits.max_connections
                            );
                            continue;
                        };
                        connections.spawn(handle_connection(self.shared.clone(), tcp, peer, permit));
                    }
                    Err(e) => {
                        warn!("hsm-gateway: accept failed: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                },
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        info!("hsm-gateway: stopped");
        Ok(())
    }
}

#[derive(Debug)]
enum UpstreamError {
    Connect(io::Error),
    Send(io::Error),
    Response(ResponseError),
    Timeout,
}

impl UpstreamError {
    fn status(&self) -> u16 {
        match self {
            UpstreamError::Timeout => 504,
            _ => 502,
        }
    }
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpstreamError::Connect(e) => write!(f, "connect failed: {e}"),
            UpstreamError::Send(e) => write!(f, "send failed: {e}"),
            UpstreamError::Response(e) => write!(f, "{e}"),
            UpstreamError::Timeout => f.write_str("no complete response within the upstream timeout"),
        }
    }
}

/// One fresh connector connection per request, written as HTTP/1.0 so the
/// connector (Go net/http) frames its reply by Content-Length or by close,
/// never chunked. Only `Host` and the framing are sent; client headers are not.
async fn forward(shared: &Shared, request: &Request) -> Result<Response, UpstreamError> {
    let exchange = async {
        let tcp = TcpStream::connect(shared.connector.socket_addr()).await.map_err(UpstreamError::Connect)?;
        let _ = tcp.set_nodelay(true);
        let mut conn = HttpConn::new(tcp);
        let bytes = encode_request(request.endpoint, &shared.connector.host_header(), &request.body, Version::Http10);
        conn.write_all(&bytes).await.map_err(UpstreamError::Send)?;
        conn.read_response(BodyFraming::ContentLengthOrClose).await.map_err(UpstreamError::Response)
    };
    timeout(shared.limits.upstream_timeout, exchange).await.unwrap_or(Err(UpstreamError::Timeout))
}

/// One in flight, then the rate. The permit is held until the response has
/// been written, so "in flight" covers the whole exchange.
fn admit(slot: &ClientSlot) -> Result<OwnedSemaphorePermit, &'static str> {
    let permit =
        slot.in_flight.clone().try_acquire_owned().map_err(|_| "another request from this client is in flight")?;
    // The bucket is plain numbers; a panic elsewhere cannot leave it unsafe.
    let mut bucket = slot.bucket.lock().unwrap_or_else(PoisonError::into_inner);
    if bucket.try_take(Instant::now()) {
        Ok(permit)
    } else {
        Err("max_rps_per_client exceeded")
    }
}

async fn handle_connection(shared: Arc<Shared>, tcp: TcpStream, peer: SocketAddr, _slot: OwnedSemaphorePermit) {
    let _ = tcp.set_nodelay(true);
    let tls = match timeout(shared.limits.handshake_timeout, shared.acceptor.accept(tcp)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            bump(&shared.counters.connections_refused);
            warn!("hsm-gateway: TLS handshake with {peer} failed: {e}");
            return;
        }
        Err(_) => {
            bump(&shared.counters.connections_refused);
            warn!("hsm-gateway: TLS handshake with {peer} timed out");
            return;
        }
    };
    let mut conn = HttpConn::new(tls);
    let identity =
        tls::client_identity(conn.get_ref().get_ref().1.peer_certificates(), |name| shared.clients.contains_key(name));
    let client = match identity {
        Ok(client) => client,
        Err(e) => {
            bump(&shared.counters.connections_refused);
            warn!("hsm-gateway: refusing {peer}: {e}");
            conn.shutdown().await;
            return;
        }
    };
    let Some(slot) = shared.clients.get(&client) else {
        return;
    };
    bump(&shared.counters.connections_accepted);
    info!("hsm-gateway: connection opened peer={peer} client={client}");
    let (requests, errors, reason) = serve_client(&shared, &mut conn, slot, &client).await;
    conn.shutdown().await;
    info!(
        "hsm-gateway: connection closed peer={peer} client={client} requests={requests} errors={errors} reason={reason}"
    );
}

/// The request loop of one authenticated connection. Returns the request
/// and error counts and why it ended.
async fn serve_client(
    shared: &Shared,
    conn: &mut HttpConn<TlsStream<TcpStream>>,
    slot: &ClientSlot,
    client: &str,
) -> (u64, u64, &'static str) {
    let (mut requests, mut errors) = (0u64, 0u64);
    let reason = loop {
        if !conn.has_buffered() {
            match timeout(shared.limits.idle_timeout, conn.fill()).await {
                Err(_) => break "idle timeout",
                Ok(Ok(0)) => break "closed by client",
                Ok(Err(_)) => break "read error",
                Ok(Ok(_)) => {}
            }
        }
        let request = match conn.read_request(shared.limits.request_timeout).await {
            Ok(request) => request,
            Err(ReadError::Reject(rejection)) => {
                errors += 1;
                bump(&shared.counters.requests_rejected);
                warn!("hsm-gateway: client={client} request rejected with {}: {}", rejection.status, rejection.why);
                conn.reject_and_close(rejection.status).await;
                break "protocol error";
            }
            Err(ReadError::Timeout) => {
                errors += 1;
                bump(&shared.counters.requests_rejected);
                warn!("hsm-gateway: client={client} request not complete within the request timeout");
                conn.reject_and_close(408).await;
                break "request timeout";
            }
            Err(ReadError::Truncated) => break "closed mid-request",
            Err(ReadError::Io(e)) => {
                debug!("hsm-gateway: client={client} read failed: {e}");
                break "read error";
            }
        };
        requests += 1;
        let started = Instant::now();
        let admission = admit(slot);
        let (status, body) = match &admission {
            Err(why) => {
                errors += 1;
                bump(&shared.counters.requests_rejected);
                warn!("hsm-gateway: client={client} request refused with 429: {why}");
                (429, Vec::new())
            }
            Ok(_) => match forward(shared, &request).await {
                Ok(response) => {
                    bump(&shared.counters.requests_forwarded);
                    (response.status, response.body)
                }
                Err(e) => {
                    errors += 1;
                    bump(&shared.counters.upstream_failures);
                    warn!("hsm-gateway: client={client} connector request failed: {e}");
                    (e.status(), Vec::new())
                }
            },
        };
        let reply = encode_response(status, &body, request.close);
        let written = matches!(timeout(shared.limits.request_timeout, conn.write_all(&reply)).await, Ok(Ok(())));
        drop(admission);
        debug!(
            "hsm-gateway: client={client} {} {} -> {status} ({} bytes in, {} bytes out, {} ms)",
            request.endpoint.method(),
            request.endpoint.path(),
            request.body.len(),
            body.len(),
            started.elapsed().as_millis()
        );
        if !written {
            break "write error";
        }
        if request.close {
            break "client asked to close";
        }
    };
    (requests, errors, reason)
}
