//! The RADIUS listeners and their supervisor. The supervisor reads
//! `idp/radius/config` every tick (or at once after a write), binds or
//! stops the RadSec and UDP listeners to match, and refreshes the set of
//! known NAS clients. Requests are rate limited per source address before
//! any work, bounded in flight, and deduplicated by client, source,
//! identifier and authenticator, so a retransmit gets the cached reply.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex, Weak,
    },
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use chrono::Utc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{watch, Semaphore},
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;

use super::{
    answer, audit_unattributed,
    packet::{frame_len, AUTHENTICATOR_LEN, HEADER_LEN, MAX_PACKET_LEN},
    store::{canonical_ip, RadiusClient, Transport, DEFAULT_RATE_LIMIT_PER_MINUTE},
    tls::cert_fingerprint,
    BrokerRadiusAudit, Exchange, RadiusAudit, RadiusDeps, RadiusRuntime, Refusal,
};
use crate::{
    entitlement::EntitlementStoreSlot, kernel_api::VaultCtx, posix::store::PosixStore, provider::Authorizer,
    IssuanceSlot, IssuanceStores, PosixStoreSlot,
};

pub const SUPERVISOR_TICK: Duration = Duration::from_secs(30);
pub const RATE_WINDOW: Duration = Duration::from_secs(60);
pub const DUPLICATE_WINDOW: Duration = Duration::from_secs(30);
const MAX_UDP_IN_FLIGHT: usize = 64;
const MAX_TLS_CONNECTIONS: usize = 128;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const TLS_READ_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_TRACKED_SOURCES: usize = 4096;
const MAX_DUPLICATE_ENTRIES: usize = 4096;
/// Audit events for requests no NAS record vouches for, across all sources.
const UNATTRIBUTED_EVENTS_PER_MINUTE: u32 = 30;
/// The rate limiter's key for [`UNATTRIBUTED_EVENTS_PER_MINUTE`].
const UNATTRIBUTED_KEY: IpAddr = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);

/// The stores, gate and audit sink for one request.
pub(crate) struct Opened {
    pub posix: Arc<PosixStore>,
    pub stores: Arc<IssuanceStores>,
    pub gate: Box<dyn Authorizer>,
    pub audit: Arc<dyn RadiusAudit>,
}

/// Where the listeners get their dependencies. `None` while sealed.
pub(crate) trait RadiusSource: Send + Sync + 'static {
    fn open(&self) -> Option<Opened>;
    /// False once the vault is gone: the supervisor then stops.
    fn alive(&self) -> bool;
}

/// The vault: its store slots, the issue gate and the audit broker. Holds
/// the kernel weakly so the supervisor never keeps a dropped vault alive.
pub(crate) struct VaultSource {
    pub ctx: Weak<dyn VaultCtx>,
    pub posix: Arc<PosixStoreSlot>,
    pub authz: Arc<EntitlementStoreSlot>,
    pub issuance: Arc<IssuanceSlot>,
}

impl RadiusSource for VaultSource {
    fn open(&self) -> Option<Opened> {
        let ctx = self.ctx.upgrade()?;
        if ctx.sealed() {
            return None;
        }
        let posix = self.posix.load().as_ref().clone()?;
        let stores = self.issuance.load().as_ref().clone()?;
        let gate = crate::issue_gate(&ctx, &self.posix, &self.authz);
        Some(Opened { posix, stores, gate: Box::new(gate), audit: Arc::new(BrokerRadiusAudit { ctx }) })
    }

    fn alive(&self) -> bool {
        self.ctx.strong_count() > 0
    }
}

/// Fixed-window request counter per source address. Bounded: when full and
/// nothing has expired, a new source is refused (fail closed under flood).
pub(crate) struct RateLimiter {
    windows: HashMap<IpAddr, (Instant, u32)>,
    max_sources: usize,
}

impl RateLimiter {
    pub fn new(max_sources: usize) -> Self {
        Self { windows: HashMap::new(), max_sources }
    }

    pub fn allow(&mut self, ip: IpAddr, limit: u32, now: Instant) -> bool {
        if let Some((start, count)) = self.windows.get_mut(&ip) {
            if now.duration_since(*start) >= RATE_WINDOW {
                *start = now;
                *count = 1;
                return true;
            }
            if *count >= limit {
                return false;
            }
            *count += 1;
            return true;
        }
        if self.windows.len() >= self.max_sources {
            self.windows.retain(|_, (start, _)| now.duration_since(*start) < RATE_WINDOW);
            if self.windows.len() >= self.max_sources {
                return false;
            }
        }
        self.windows.insert(ip, (now, 1));
        true
    }
}

type DuplicateKey = (String, SocketAddr, u8, [u8; AUTHENTICATOR_LEN]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DuplicateCheck {
    New,
    /// The same request is being answered: drop this copy.
    InFlight,
    /// Answered already: send the same reply again.
    Replay(Vec<u8>),
    /// The cache is full: drop (fail closed).
    Full,
}

/// RFC 2865 §3 / RFC 5080 §2.2.2: a retransmission (same client, source,
/// identifier and Request Authenticator) is answered from the cache, never
/// re-run; a passcode is single-use, so re-running would turn a lost
/// Access-Accept into an Access-Reject.
pub(crate) struct DuplicateCache {
    entries: HashMap<DuplicateKey, (Instant, Option<Vec<u8>>)>,
    max: usize,
}

impl DuplicateCache {
    pub fn new(max: usize) -> Self {
        Self { entries: HashMap::new(), max }
    }

    pub fn begin(&mut self, key: &DuplicateKey, now: Instant) -> DuplicateCheck {
        match self.entries.get(key) {
            Some((at, _)) if now.duration_since(*at) >= DUPLICATE_WINDOW => {}
            Some((_, None)) => return DuplicateCheck::InFlight,
            Some((_, Some(reply))) => return DuplicateCheck::Replay(reply.clone()),
            None => {}
        }
        if self.entries.len() >= self.max {
            // An in-flight marker older than the window is a request that
            // never finished; it is reclaimed like a stale reply.
            self.entries.retain(|_, (at, _)| now.duration_since(*at) < DUPLICATE_WINDOW);
            if self.entries.len() >= self.max {
                return DuplicateCheck::Full;
            }
        }
        self.entries.insert(key.clone(), (now, None));
        DuplicateCheck::New
    }

    /// Cache a reply. A request that got none (a discard) is forgotten, so
    /// a forged copy cannot block the genuine one.
    pub fn finish(&mut self, key: &DuplicateKey, reply: Option<Vec<u8>>, now: Instant) {
        match reply {
            Some(r) => {
                self.entries.insert(key.clone(), (now, Some(r)));
            }
            None => {
                self.entries.remove(key);
            }
        }
    }
}

fn duplicate_key(client: &str, peer: SocketAddr, packet: &[u8]) -> Option<DuplicateKey> {
    if packet.len() < HEADER_LEN {
        return None;
    }
    let mut auth = [0u8; AUTHENTICATOR_LEN];
    auth.copy_from_slice(&packet[4..HEADER_LEN]);
    Some((client.to_string(), peer, packet[1], auth))
}

/// The NAS identities the listeners admit before reading any store.
#[derive(Default)]
struct KnownClients {
    udp: HashSet<IpAddr>,
    certs: HashSet<String>,
}

enum ClientKey {
    Udp(IpAddr),
    Cert(String),
}

/// State shared by the listeners of one supervisor.
pub(crate) struct Shared {
    source: Arc<dyn RadiusSource>,
    known: ArcSwap<KnownClients>,
    limiter: Mutex<RateLimiter>,
    duplicates: Mutex<DuplicateCache>,
    rate_limit: AtomicU32,
    udp_in_flight: Arc<Semaphore>,
    tls_connections: Arc<Semaphore>,
}

impl Shared {
    fn new(source: Arc<dyn RadiusSource>) -> Self {
        Self {
            source,
            known: ArcSwap::from_pointee(KnownClients::default()),
            limiter: Mutex::new(RateLimiter::new(MAX_TRACKED_SOURCES)),
            duplicates: Mutex::new(DuplicateCache::new(MAX_DUPLICATE_ENTRIES)),
            rate_limit: AtomicU32::new(DEFAULT_RATE_LIMIT_PER_MINUTE),
            udp_in_flight: Arc::new(Semaphore::new(MAX_UDP_IN_FLIGHT)),
            tls_connections: Arc::new(Semaphore::new(MAX_TLS_CONNECTIONS)),
        }
    }

    fn allow(&self, ip: IpAddr) -> bool {
        let limit = self.rate_limit.load(Ordering::Relaxed);
        match self.limiter.lock() {
            Ok(mut l) => l.allow(ip, limit, Instant::now()),
            Err(_) => false,
        }
    }

    fn knows(&self, key: &ClientKey) -> bool {
        let known = self.known.load();
        match key {
            ClientKey::Udp(ip) => known.udp.contains(ip),
            ClientKey::Cert(fp) => known.certs.contains(fp),
        }
    }

    /// Audit a request dropped before a NAS record was read (unknown,
    /// rate limited, busy), at most [`UNATTRIBUTED_EVENTS_PER_MINUTE`] times
    /// a minute in all, so a flood cannot flood the audit log.
    async fn unattributed(&self, transport: Transport, peer: IpAddr, refusal: Refusal) {
        let allowed = match self.limiter.lock() {
            Ok(mut l) => l.allow(UNATTRIBUTED_KEY, UNATTRIBUTED_EVENTS_PER_MINUTE, Instant::now()),
            Err(_) => false,
        };
        if let Some(opened) = self.source.open().filter(|_| allowed) {
            audit_unattributed(opened.audit.as_ref(), transport.as_str(), peer, refusal).await;
        }
    }

    /// One request. `None`: send nothing.
    async fn handle(&self, transport: Transport, key: ClientKey, peer: SocketAddr, packet: &[u8]) -> Option<Vec<u8>> {
        if !self.knows(&key) {
            self.unattributed(transport, peer.ip(), Refusal::UnknownClient).await;
            return None;
        }
        let opened = self.source.open()?;
        let looked_up = match &key {
            ClientKey::Udp(ip) => opened.stores.radius.client_for_udp(*ip).await,
            ClientKey::Cert(fp) => opened.stores.radius.client_for_cert(fp).await,
        };
        let client: RadiusClient = match looked_up {
            Ok(Some(c)) => c,
            Ok(None) => {
                self.unattributed(transport, peer.ip(), Refusal::UnknownClient).await;
                return None;
            }
            Err(e) => {
                log::error!(target: "idp", "idp.radius: cannot read the client record for {peer}: {e}");
                return None;
            }
        };
        let dup = duplicate_key(&client.name, peer, packet);
        if let Some(k) = &dup {
            let check = match self.duplicates.lock() {
                Ok(mut d) => d.begin(k, Instant::now()),
                Err(_) => DuplicateCheck::Full,
            };
            match check {
                DuplicateCheck::New => {}
                DuplicateCheck::Replay(reply) => return Some(reply),
                DuplicateCheck::InFlight => return None,
                DuplicateCheck::Full => {
                    self.unattributed(transport, peer.ip(), Refusal::Busy).await;
                    return None;
                }
            }
        }
        let deps = RadiusDeps {
            authorizer: opened.gate.as_ref(),
            posix: &opened.posix,
            radius: &opened.stores.radius,
            audit: opened.audit.as_ref(),
        };
        let ex = Exchange { client: &client, peer: canonical_ip(peer.ip()), packet };
        let answered = answer(&deps, &ex, Utc::now()).await;
        if let Some(k) = &dup {
            if let Ok(mut d) = self.duplicates.lock() {
                d.finish(k, answered.reply.clone(), Instant::now());
            }
        }
        answered.reply
    }
}

/// A running listener: its stop signal and task.
struct Listener {
    configured: SocketAddr,
    tls_digest: Option<String>,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl Listener {
    fn stop(self) {
        let _ = self.stop.send(true);
        self.task.abort();
    }
}

#[derive(Default)]
struct Running {
    radsec: Option<Listener>,
    udp: Option<Listener>,
}

impl RadiusRuntime {
    /// Start the supervisor once; later calls (every unseal) only ask it to
    /// reconcile.
    pub(crate) fn start(self: &Arc<Self>, source: Arc<dyn RadiusSource>) {
        if self.started.swap(true, Ordering::SeqCst) {
            self.reconcile_soon();
            return;
        }
        let runtime = self.clone();
        drop(tokio::spawn(supervise(runtime, Arc::new(Shared::new(source)))));
    }

    fn set_status(&self, f: impl FnOnce(&mut super::ListenerStatus)) {
        if let Ok(mut s) = self.status.lock() {
            f(&mut s);
        }
    }
}

async fn supervise(runtime: Arc<RadiusRuntime>, shared: Arc<Shared>) {
    let mut running = Running::default();
    loop {
        if !shared.source.alive() {
            break;
        }
        reconcile(&runtime, &shared, &mut running).await;
        tokio::select! {
            _ = runtime.notify.notified() => {}
            _ = tokio::time::sleep(SUPERVISOR_TICK) => {}
        }
    }
    for l in [running.radsec.take(), running.udp.take()].into_iter().flatten() {
        l.stop();
    }
    runtime.set_status(|s| *s = super::ListenerStatus::default());
}

async fn reconcile(runtime: &RadiusRuntime, shared: &Arc<Shared>, running: &mut Running) {
    let mut error = None;
    let config = match shared.source.open() {
        None => None,
        Some(opened) => {
            match opened.stores.radius.list_clients().await {
                Ok(clients) => {
                    let mut known = KnownClients::default();
                    for c in &clients {
                        match c.transport {
                            Transport::Udp => {
                                if let Some(ip) = c.address.as_deref().and_then(|a| a.parse::<IpAddr>().ok()) {
                                    known.udp.insert(canonical_ip(ip));
                                }
                            }
                            Transport::Radsec => {
                                if let Some(fp) = &c.cert_sha256 {
                                    known.certs.insert(fp.clone());
                                }
                            }
                        }
                    }
                    shared.known.store(Arc::new(known));
                }
                Err(e) => {
                    shared.known.store(Arc::new(KnownClients::default()));
                    error = Some(format!("cannot list RADIUS clients: {e}"));
                }
            }
            match opened.stores.radius.config().await {
                Ok(cfg) => cfg.filter(|c| c.enabled),
                Err(e) => {
                    error = Some(format!("cannot read the RADIUS config: {e}"));
                    None
                }
            }
        }
    };
    if let Some(cfg) = &config {
        shared.rate_limit.store(cfg.rate_limit_per_minute, Ordering::Relaxed);
    }

    // RadSec.
    let want_radsec = config.as_ref().and_then(|c| c.radsec_addr().map(|a| (a, c.tls_digest())));
    let keep = match (&running.radsec, &want_radsec) {
        (Some(l), Some((addr, digest))) => l.configured == *addr && l.tls_digest.as_ref() == Some(digest),
        (None, None) => true,
        _ => false,
    };
    if !keep {
        if let Some(l) = running.radsec.take() {
            l.stop();
            runtime.set_status(|s| s.radsec = None);
        }
        if let (Some(cfg), Some((addr, digest))) = (&config, want_radsec) {
            match start_radsec(shared, cfg, addr, digest).await {
                Ok((listener, bound)) => {
                    log::info!(target: "idp", "idp.radius: RadSec listening on {bound}");
                    running.radsec = Some(listener);
                    runtime.set_status(|s| s.radsec = Some(bound));
                }
                Err(e) => error = Some(e),
            }
        }
    }

    // UDP.
    let want_udp = config.as_ref().and_then(|c| c.udp_addr());
    let keep = match (&running.udp, want_udp) {
        (Some(l), Some(addr)) => l.configured == addr,
        (None, None) => true,
        _ => false,
    };
    if !keep {
        if let Some(l) = running.udp.take() {
            l.stop();
            runtime.set_status(|s| s.udp = None);
        }
        if let Some(addr) = want_udp {
            match start_udp(shared, addr).await {
                Ok((listener, bound)) => {
                    log::warn!(
                        target: "security",
                        "idp.radius: classic UDP RADIUS listening on {bound}; trusted segments only"
                    );
                    running.udp = Some(listener);
                    runtime.set_status(|s| s.udp = Some(bound));
                }
                Err(e) => error = Some(e),
            }
        }
    }
    if let Some(e) = &error {
        log::error!(target: "idp", "idp.radius: {e}");
    }
    runtime.set_status(|s| s.last_error = error);
}

async fn start_udp(shared: &Arc<Shared>, addr: SocketAddr) -> Result<(Listener, SocketAddr), String> {
    let socket = UdpSocket::bind(addr).await.map_err(|e| format!("cannot bind UDP {addr}: {e}"))?;
    let bound = socket.local_addr().map_err(|e| format!("UDP {addr}: {e}"))?;
    let (stop, stop_rx) = watch::channel(false);
    let task = tokio::spawn(udp_loop(Arc::new(socket), shared.clone(), stop_rx));
    Ok((Listener { configured: addr, tls_digest: None, stop, task }, bound))
}

async fn udp_loop(socket: Arc<UdpSocket>, shared: Arc<Shared>, mut stop: watch::Receiver<bool>) {
    // One octet more than the largest packet, so an oversized one is seen.
    let mut buf = vec![0u8; MAX_PACKET_LEN + 1];
    loop {
        let (n, peer) = tokio::select! {
            r = socket.recv_from(&mut buf) => match r {
                Ok(v) => v,
                Err(e) => {
                    log::debug!(target: "idp", "idp.radius: UDP receive error: {e}");
                    continue;
                }
            },
            _ = stop.changed() => break,
        };
        let ip = canonical_ip(peer.ip());
        // Unknown sources first, so spoofed ones never reach the limiter's table.
        if !shared.knows(&ClientKey::Udp(ip)) {
            shared.unattributed(Transport::Udp, ip, Refusal::UnknownClient).await;
            continue;
        }
        if !shared.allow(ip) {
            shared.unattributed(Transport::Udp, ip, Refusal::RateLimited).await;
            continue;
        }
        let Ok(permit) = shared.udp_in_flight.clone().try_acquire_owned() else {
            shared.unattributed(Transport::Udp, ip, Refusal::Busy).await;
            continue;
        };
        let datagram = buf[..n].to_vec();
        let (socket, shared) = (socket.clone(), shared.clone());
        drop(tokio::spawn(async move {
            let _permit = permit;
            if let Some(reply) = shared.handle(Transport::Udp, ClientKey::Udp(ip), peer, &datagram).await {
                if let Err(e) = socket.send_to(&reply, peer).await {
                    log::debug!(target: "idp", "idp.radius: UDP send to {peer} failed: {e}");
                }
            }
        }));
    }
}

async fn start_radsec(
    shared: &Arc<Shared>,
    cfg: &super::store::RadiusConfig,
    addr: SocketAddr,
    digest: String,
) -> Result<(Listener, SocketAddr), String> {
    let tls = cfg.tls_server_config().map_err(|e| format!("RadSec TLS configuration: {e}"))?;
    let listener = TcpListener::bind(addr).await.map_err(|e| format!("cannot bind RadSec {addr}: {e}"))?;
    let bound = listener.local_addr().map_err(|e| format!("RadSec {addr}: {e}"))?;
    let (stop, stop_rx) = watch::channel(false);
    let task = tokio::spawn(tls_loop(listener, TlsAcceptor::from(tls), shared.clone(), stop_rx));
    Ok((Listener { configured: addr, tls_digest: Some(digest), stop, task }, bound))
}

async fn tls_loop(listener: TcpListener, acceptor: TlsAcceptor, shared: Arc<Shared>, mut stop: watch::Receiver<bool>) {
    loop {
        let (tcp, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => {
                    log::debug!(target: "idp", "idp.radius: RadSec accept error: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            _ = stop.changed() => break,
        };
        let ip = canonical_ip(peer.ip());
        if !shared.allow(ip) {
            shared.unattributed(Transport::Radsec, ip, Refusal::RateLimited).await;
            continue;
        }
        let Ok(permit) = shared.tls_connections.clone().try_acquire_owned() else {
            shared.unattributed(Transport::Radsec, ip, Refusal::Busy).await;
            continue;
        };
        let (acceptor, shared, stop) = (acceptor.clone(), shared.clone(), stop.clone());
        drop(tokio::spawn(async move {
            let _permit = permit;
            serve_tls(tcp, peer, acceptor, shared, stop).await;
        }));
    }
}

async fn serve_tls(
    tcp: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) {
    // rustls refuses a NAS whose certificate does not chain to client_ca_pem.
    let mut tls = match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            log::info!(target: "idp", "idp.radius: RadSec handshake from {peer} refused: {e}");
            return;
        }
        Err(_) => return,
    };
    let fingerprint = match tls.get_ref().1.peer_certificates().and_then(|c| c.first()) {
        Some(cert) => cert_fingerprint(cert.as_ref()),
        None => return,
    };
    let ip = canonical_ip(peer.ip());
    if !shared.knows(&ClientKey::Cert(fingerprint.clone())) {
        shared.unattributed(Transport::Radsec, ip, Refusal::UnknownClient).await;
        let _ = tls.shutdown().await;
        return;
    }
    loop {
        let mut header = [0u8; 4];
        let read = tokio::select! {
            r = tokio::time::timeout(TLS_IDLE_TIMEOUT, tls.read_exact(&mut header)) => r,
            _ = stop.changed() => break,
        };
        if !matches!(read, Ok(Ok(_))) {
            break;
        }
        let len = match frame_len(&header) {
            Ok(len) => len,
            Err(_) => {
                // A stream cannot be resynchronised: audit the header, close.
                let _ = shared.handle(Transport::Radsec, ClientKey::Cert(fingerprint.clone()), peer, &header).await;
                break;
            }
        };
        let mut packet = vec![0u8; len];
        packet[..4].copy_from_slice(&header);
        match tokio::time::timeout(TLS_READ_TIMEOUT, tls.read_exact(&mut packet[4..])).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        if !shared.allow(ip) {
            shared.unattributed(Transport::Radsec, ip, Refusal::RateLimited).await;
            continue;
        }
        let key = ClientKey::Cert(fingerprint.clone());
        if let Some(reply) = shared.handle(Transport::Radsec, key, peer, &packet).await {
            if tls.write_all(&reply).await.is_err() || tls.flush().await.is_err() {
                break;
            }
        }
    }
    let _ = tls.shutdown().await;
}
