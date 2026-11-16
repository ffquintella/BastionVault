//! The directory's listeners and their supervisor, on the RADIUS pattern:
//! `idp/ldap/config` is read every tick (or at once after a write) and the
//! LDAPS and cleartext/StartTLS listeners are bound or stopped to match.
//! Connections are capped, rate limited per source, idle-timed-out, and
//! each PDU's size is checked from its header before the body is read.

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex, Weak,
    },
    time::Duration,
};

use arc_swap::ArcSwap;
use chrono::Utc;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{watch, Semaphore},
    task::JoinHandle,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use super::{
    audit_unattributed,
    ber::{self, BerError},
    proto::{self, Op, ResultCode, OID_STARTTLS},
    serve,
    store::{LdapConfig, Transport, DEFAULT_RATE_LIMIT_PER_MINUTE},
    After, BrokerDirectoryAudit, Channel, DirectoryAudit, DirectoryView, LdapDeps, LdapRuntime, ListenerStatus,
    Recognised, Session,
};
use crate::{
    entitlement::EntitlementStoreSlot,
    kernel_api::VaultCtx,
    posix::store::PosixStore,
    provider::{
        radius::{server::RateLimiter, store::canonical_ip, tls::cert_fingerprint},
        Authorizer,
    },
    IssuanceSlot, IssuanceStores, PosixStoreSlot,
};

pub const SUPERVISOR_TICK: Duration = Duration::from_secs(30);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub const MAX_CONNECTIONS: usize = 128;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_TRACKED_SOURCES: usize = 4096;
/// Audit events for refusals no client record vouches for, across all
/// sources, so a flood cannot flood the audit log.
const UNATTRIBUTED_EVENTS_PER_MINUTE: u32 = 30;
const UNATTRIBUTED_KEY: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// The stores, gate and audit sink for one operation.
pub(crate) struct Opened {
    pub posix: Arc<PosixStore>,
    pub stores: Arc<IssuanceStores>,
    pub gate: Box<dyn Authorizer>,
    pub view: Box<dyn DirectoryView>,
    pub audit: Arc<dyn DirectoryAudit>,
}

/// Where the listeners get their dependencies. `None` while sealed.
pub(crate) trait LdapSource: Send + Sync + 'static {
    fn open(&self) -> Option<Opened>;
    /// False once the vault is gone: the supervisor then stops.
    fn alive(&self) -> bool;
}

/// The vault, held weakly so the supervisor never keeps it alive.
pub(crate) struct VaultSource {
    pub ctx: Weak<dyn VaultCtx>,
    pub posix: Arc<PosixStoreSlot>,
    pub authz: Arc<EntitlementStoreSlot>,
    pub issuance: Arc<IssuanceSlot>,
}

impl LdapSource for VaultSource {
    fn open(&self) -> Option<Opened> {
        let ctx = self.ctx.upgrade()?;
        if ctx.sealed() {
            return None;
        }
        let posix = self.posix.load().as_ref().clone()?;
        let stores = self.issuance.load().as_ref().clone()?;
        let gate = crate::issue_gate(&ctx, &self.posix, &self.authz);
        let view = crate::issue_gate(&ctx, &self.posix, &self.authz);
        Some(Opened {
            posix,
            stores,
            gate: Box::new(gate),
            view: Box::new(view),
            audit: Arc::new(BrokerDirectoryAudit { ctx }),
        })
    }

    fn alive(&self) -> bool {
        self.ctx.strong_count() > 0
    }
}

/// The client identities the listeners admit before reading any store.
#[derive(Default)]
struct KnownClients {
    certs: HashSet<String>,
    plain: HashSet<IpAddr>,
}

pub(crate) struct Shared {
    source: Arc<dyn LdapSource>,
    known: ArcSwap<KnownClients>,
    limiter: Mutex<RateLimiter>,
    rate_limit: AtomicU32,
    connections: Arc<Semaphore>,
}

impl Shared {
    fn new(source: Arc<dyn LdapSource>) -> Self {
        Self {
            source,
            known: ArcSwap::from_pointee(KnownClients::default()),
            limiter: Mutex::new(RateLimiter::new(MAX_TRACKED_SOURCES)),
            rate_limit: AtomicU32::new(DEFAULT_RATE_LIMIT_PER_MINUTE),
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        }
    }

    fn allow(&self, ip: IpAddr) -> bool {
        let limit = self.rate_limit.load(Ordering::Relaxed);
        match self.limiter.lock() {
            Ok(mut l) => l.allow(ip, limit, std::time::Instant::now()),
            Err(_) => false,
        }
    }

    async fn unattributed(&self, channel: &str, peer: IpAddr, reason: &str) {
        let allowed = match self.limiter.lock() {
            Ok(mut l) => l.allow(UNATTRIBUTED_KEY, UNATTRIBUTED_EVENTS_PER_MINUTE, std::time::Instant::now()),
            Err(_) => false,
        };
        if let Some(opened) = self.source.open().filter(|_| allowed) {
            audit_unattributed(opened.audit.as_ref(), channel, peer, reason).await;
        }
    }
}

// ─── Framing ────────────────────────────────────────────────────────

enum ReadError {
    Closed,
    Malformed(BerError),
}

/// One PDU. The idle timeout applies before its first octet, the read
/// timeout after it; the size is known (and bounded) before the body.
async fn read_pdu<S: AsyncRead + Unpin>(s: &mut S, stop: &mut watch::Receiver<bool>) -> Result<Vec<u8>, ReadError> {
    let mut byte = [0u8; 1];
    tokio::select! {
        r = tokio::time::timeout(IDLE_TIMEOUT, s.read_exact(&mut byte)) => {
            if !matches!(r, Ok(Ok(_))) {
                return Err(ReadError::Closed);
            }
        }
        _ = stop.changed() => return Err(ReadError::Closed),
    }
    if byte[0] != proto::tag::SEQUENCE {
        return Err(ReadError::Malformed(BerError::UnexpectedTag));
    }
    let mut head = vec![byte[0]];
    loop {
        match ber::pdu_len(&head) {
            Ok(Some(total)) => {
                let mut pdu = vec![0u8; total];
                pdu[..head.len()].copy_from_slice(&head);
                return match tokio::time::timeout(READ_TIMEOUT, s.read_exact(&mut pdu[head.len()..])).await {
                    Ok(Ok(_)) => Ok(pdu),
                    _ => Err(ReadError::Closed),
                };
            }
            Ok(None) => match tokio::time::timeout(READ_TIMEOUT, s.read_exact(&mut byte)).await {
                Ok(Ok(_)) => head.push(byte[0]),
                _ => return Err(ReadError::Closed),
            },
            Err(e) => return Err(ReadError::Malformed(e)),
        }
    }
}

async fn send<S: AsyncWrite + Unpin>(s: &mut S, pdus: &[Vec<u8>]) -> bool {
    if pdus.is_empty() {
        return true;
    }
    let out = pdus.concat();
    let write = async {
        s.write_all(&out).await?;
        s.flush().await
    };
    matches!(tokio::time::timeout(WRITE_TIMEOUT, write).await, Ok(Ok(())))
}

// ─── Connections ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Ldaps,
    Ldap,
}

enum Exit {
    Closed,
    /// StartTLS was asked for (message id); upgrade the stream.
    StartTls(i32),
}

/// The pinned client behind a TLS session, or `None` (audited) after which
/// the connection is closed.
async fn admit_tls(shared: &Shared, tls: &TlsStream<TcpStream>, peer: SocketAddr, channel: Channel) -> Option<Session> {
    let ip = canonical_ip(peer.ip());
    let fp = cert_fingerprint(tls.get_ref().1.peer_certificates()?.first()?.as_ref());
    if !shared.known.load().certs.contains(&fp) {
        shared.unattributed(channel.as_str(), ip, "unknown_client").await;
        return None;
    }
    let opened = shared.source.open()?;
    match opened.stores.ldap.client_for_cert(&fp).await {
        Ok(Some(c)) => Some(Session {
            client: c.name,
            recognised: Recognised::Certificate(fp),
            channel,
            peer: ip,
            bound: super::Bound::Anonymous,
        }),
        Ok(None) => {
            shared.unattributed(channel.as_str(), ip, "unknown_client").await;
            None
        }
        Err(e) => {
            log::error!(target: "idp", "idp.ldap: cannot read the client record for {peer}: {e}");
            None
        }
    }
}

/// A cleartext session: only for a `plain` client while the operator's
/// opt-in stands. Anyone else may still ask for StartTLS.
async fn admit_plain(shared: &Shared, peer: SocketAddr) -> Option<Session> {
    let ip = canonical_ip(peer.ip());
    if !shared.known.load().plain.contains(&ip) {
        return None;
    }
    let opened = shared.source.open()?;
    let cfg: LdapConfig = opened.stores.ldap.config().await.ok().flatten()?;
    if !cfg.enabled || !cfg.plaintext_enabled {
        return None;
    }
    let client = opened.stores.ldap.client_for_addr(ip).await.ok().flatten()?;
    Some(Session {
        client: client.name,
        recognised: Recognised::Address(ip),
        channel: Channel::Plain,
        peer: ip,
        bound: super::Bound::Anonymous,
    })
}

async fn handshake(acceptor: &TlsAcceptor, tcp: TcpStream, peer: SocketAddr) -> Option<TlsStream<TcpStream>> {
    // rustls refuses a client whose certificate does not chain to client_ca_pem.
    match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
        Ok(Ok(s)) => Some(s),
        Ok(Err(e)) => {
            log::info!(target: "idp", "idp.ldap: TLS handshake from {peer} refused: {e}");
            None
        }
        Err(_) => None,
    }
}

async fn serve_connection(
    tcp: TcpStream,
    peer: SocketAddr,
    mode: Mode,
    acceptor: Option<TlsAcceptor>,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) {
    match (mode, acceptor) {
        (Mode::Ldaps, Some(acceptor)) => {
            let Some(mut tls) = handshake(&acceptor, tcp, peer).await else { return };
            if let Some(session) = admit_tls(&shared, &tls, peer, Channel::Ldaps).await {
                run(&mut tls, Some(session), false, peer, &shared, &mut stop).await;
            }
            let _ = tls.shutdown().await;
        }
        (Mode::Ldaps, None) => {}
        (Mode::Ldap, acceptor) => {
            let mut tcp = tcp;
            let session = admit_plain(&shared, peer).await;
            let exit = run(&mut tcp, session, acceptor.is_some(), peer, &shared, &mut stop).await;
            let (Exit::StartTls(id), Some(acceptor)) = (exit, acceptor) else { return };
            let ok = proto::extended_response(id, ResultCode::Success, "", Some(OID_STARTTLS));
            if !send(&mut tcp, &[ok]).await {
                return;
            }
            let Some(mut tls) = handshake(&acceptor, tcp, peer).await else { return };
            if let Some(session) = admit_tls(&shared, &tls, peer, Channel::StartTls).await {
                run(&mut tls, Some(session), false, peer, &shared, &mut stop).await;
            }
            let _ = tls.shutdown().await;
        }
    }
}

/// The operation loop. Before a session exists (cleartext, not admitted)
/// only StartTLS, Unbind and Abandon are honoured.
async fn run<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    mut session: Option<Session>,
    allow_starttls: bool,
    peer: SocketAddr,
    shared: &Shared,
    stop: &mut watch::Receiver<bool>,
) -> Exit {
    let ip = canonical_ip(peer.ip());
    let channel = session.as_ref().map(|s| s.channel).unwrap_or(Channel::Plain);
    loop {
        let pdu = match read_pdu(stream, stop).await {
            Ok(pdu) => pdu,
            Err(ReadError::Closed) => return Exit::Closed,
            Err(ReadError::Malformed(e)) => {
                malformed(shared, session.as_ref(), channel, ip, e).await;
                let _ =
                    send(stream, &[proto::notice_of_disconnection(ResultCode::ProtocolError, "malformed PDU")]).await;
                return Exit::Closed;
            }
        };
        let msg = match proto::decode_message(&pdu) {
            Ok(m) => m,
            Err(e) => {
                malformed(shared, session.as_ref(), channel, ip, e.error).await;
                let _ =
                    send(stream, &[proto::notice_of_disconnection(ResultCode::ProtocolError, "malformed PDU")]).await;
                return Exit::Closed;
            }
        };
        if !shared.allow(ip) {
            shared.unattributed(channel.as_str(), ip, "rate_limited").await;
            if matches!(msg.op, Op::Unbind) {
                return Exit::Closed;
            }
            let busy = proto::refusal(msg.id, &msg.op, ResultCode::Busy, "rate limited");
            if !send(stream, &busy.into_iter().collect::<Vec<_>>()).await {
                return Exit::Closed;
            }
            continue;
        }
        let starttls = matches!(&msg.op, Op::Extended { oid } if oid == OID_STARTTLS);
        let Some(sess) = session.as_mut() else {
            let reply = match &msg.op {
                _ if starttls && allow_starttls => return Exit::StartTls(msg.id),
                Op::Unbind => return Exit::Closed,
                Op::Abandon => continue,
                _ if starttls => {
                    shared.unattributed(channel.as_str(), ip, "starttls_not_configured").await;
                    proto::refusal(msg.id, &msg.op, ResultCode::Unavailable, "StartTLS is not configured")
                }
                op => {
                    shared.unattributed(channel.as_str(), ip, "tls_required").await;
                    proto::refusal(msg.id, op, ResultCode::ConfidentialityRequired, "use LDAPS or StartTLS")
                }
            };
            if !send(stream, &reply.into_iter().collect::<Vec<_>>()).await {
                return Exit::Closed;
            }
            continue;
        };
        if starttls && allow_starttls && sess.channel == Channel::Plain {
            return Exit::StartTls(msg.id);
        }
        let Some(opened) = shared.source.open() else {
            let _ = send(stream, &[proto::notice_of_disconnection(ResultCode::Unavailable, "sealed")]).await;
            return Exit::Closed;
        };
        let deps = LdapDeps {
            authorizer: opened.gate.as_ref(),
            view: opened.view.as_ref(),
            posix: &opened.posix,
            ldap: &opened.stores.ldap,
            audit: opened.audit.as_ref(),
        };
        let served = serve(&deps, sess, msg, Utc::now()).await;
        if !send(stream, &served.pdus).await || served.after == After::Close {
            return Exit::Closed;
        }
    }
}

async fn malformed(shared: &Shared, session: Option<&Session>, channel: Channel, ip: IpAddr, e: BerError) {
    let reason = format!("malformed_pdu:{}", e.as_str());
    match (session, shared.source.open()) {
        (Some(s), Some(opened)) => {
            let mut f = super::session_fields(s, None, "unknown");
            f.insert("decision".into(), "refused".into());
            f.insert("reason".into(), reason.into());
            super::record(opened.audit.as_ref(), super::events::REFUSED, f).await;
        }
        _ => shared.unattributed(channel.as_str(), ip, &reason).await,
    }
}

// ─── Supervisor ─────────────────────────────────────────────────────

struct Listener {
    configured: SocketAddr,
    digest: String,
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
    ldaps: Option<Listener>,
    ldap: Option<Listener>,
}

impl LdapRuntime {
    /// Start the supervisor once; later calls only ask it to reconcile.
    pub(crate) fn start(self: &Arc<Self>, source: Arc<dyn LdapSource>) {
        if self.started.swap(true, Ordering::SeqCst) {
            self.reconcile_soon();
            return;
        }
        let runtime = self.clone();
        drop(tokio::spawn(supervise(runtime, Arc::new(Shared::new(source)))));
    }

    fn set_status(&self, f: impl FnOnce(&mut ListenerStatus)) {
        if let Ok(mut s) = self.status.lock() {
            f(&mut s);
        }
    }
}

async fn supervise(runtime: Arc<LdapRuntime>, shared: Arc<Shared>) {
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
    for l in [running.ldaps.take(), running.ldap.take()].into_iter().flatten() {
        l.stop();
    }
    runtime.set_status(|s| *s = ListenerStatus::default());
}

async fn reconcile(runtime: &LdapRuntime, shared: &Arc<Shared>, running: &mut Running) {
    let mut error = None;
    let config = match shared.source.open() {
        None => None,
        Some(opened) => {
            match opened.stores.ldap.list_clients().await {
                Ok(clients) => {
                    let mut known = KnownClients::default();
                    for c in &clients {
                        match c.transport {
                            Transport::Tls => {
                                if let Some(fp) = &c.cert_sha256 {
                                    known.certs.insert(fp.clone());
                                }
                            }
                            Transport::Plain => {
                                if let Some(ip) = c.address.as_deref().and_then(|a| a.parse::<IpAddr>().ok()) {
                                    known.plain.insert(canonical_ip(ip));
                                }
                            }
                        }
                    }
                    shared.known.store(Arc::new(known));
                }
                Err(e) => {
                    shared.known.store(Arc::new(KnownClients::default()));
                    error = Some(format!("cannot list LDAP clients: {e}"));
                }
            }
            match opened.stores.ldap.config().await {
                Ok(cfg) => cfg.filter(|c| c.enabled),
                Err(e) => {
                    error = Some(format!("cannot read the LDAP config: {e}"));
                    None
                }
            }
        }
    };
    if let Some(cfg) = &config {
        shared.rate_limit.store(cfg.rate_limit_per_minute, Ordering::Relaxed);
    }
    let want_ldaps = config.as_ref().and_then(|c| c.ldaps_addr().map(|a| (a, c.tls_digest())));
    let want_ldap =
        config.as_ref().and_then(|c| c.ldap_addr().map(|a| (a, format!("{}:{}", c.tls_digest(), c.has_tls()))));
    for (mode, want) in [(Mode::Ldaps, want_ldaps), (Mode::Ldap, want_ldap)] {
        let slot = match mode {
            Mode::Ldaps => &mut running.ldaps,
            Mode::Ldap => &mut running.ldap,
        };
        let keep = match (&*slot, &want) {
            (Some(l), Some((addr, digest))) => l.configured == *addr && l.digest == *digest,
            (None, None) => true,
            _ => false,
        };
        if keep {
            continue;
        }
        if let Some(l) = slot.take() {
            l.stop();
            runtime.set_status(|s| match mode {
                Mode::Ldaps => s.ldaps = None,
                Mode::Ldap => s.ldap = None,
            });
        }
        let (Some(cfg), Some((addr, digest))) = (&config, want) else { continue };
        match start_listener(shared, cfg, mode, addr, digest).await {
            Ok((listener, bound)) => {
                if mode == Mode::Ldap && cfg.plaintext_enabled {
                    log::warn!(
                        target: "security",
                        "idp.ldap: cleartext LDAP listening on {bound}; trusted segments only"
                    );
                } else {
                    log::info!(target: "idp", "idp.ldap: {mode:?} listening on {bound}");
                }
                *slot = Some(listener);
                runtime.set_status(|s| match mode {
                    Mode::Ldaps => s.ldaps = Some(bound),
                    Mode::Ldap => s.ldap = Some(bound),
                });
            }
            Err(e) => error = Some(e),
        }
    }
    if let Some(e) = &error {
        log::error!(target: "idp", "idp.ldap: {e}");
    }
    runtime.set_status(|s| s.last_error = error);
}

async fn start_listener(
    shared: &Arc<Shared>,
    cfg: &LdapConfig,
    mode: Mode,
    addr: SocketAddr,
    digest: String,
) -> Result<(Listener, SocketAddr), String> {
    let acceptor = match (mode, cfg.has_tls()) {
        (_, true) => Some(TlsAcceptor::from(cfg.tls_server_config().map_err(|e| format!("LDAP TLS: {e}"))?)),
        (Mode::Ldaps, false) => return Err("LDAPS needs the TLS material".into()),
        (Mode::Ldap, false) => None,
    };
    let listener = TcpListener::bind(addr).await.map_err(|e| format!("cannot bind LDAP {addr}: {e}"))?;
    let bound = listener.local_addr().map_err(|e| format!("LDAP {addr}: {e}"))?;
    let (stop, stop_rx) = watch::channel(false);
    let task = tokio::spawn(accept_loop(listener, mode, acceptor, shared.clone(), stop_rx));
    Ok((Listener { configured: addr, digest, stop, task }, bound))
}

async fn accept_loop(
    listener: TcpListener,
    mode: Mode,
    acceptor: Option<TlsAcceptor>,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) {
    let channel = if mode == Mode::Ldaps { Channel::Ldaps } else { Channel::Plain };
    loop {
        let (tcp, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => {
                    log::debug!(target: "idp", "idp.ldap: accept error: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            _ = stop.changed() => break,
        };
        let ip = canonical_ip(peer.ip());
        if !shared.allow(ip) {
            shared.unattributed(channel.as_str(), ip, "rate_limited").await;
            continue;
        }
        let Ok(permit) = shared.connections.clone().try_acquire_owned() else {
            shared.unattributed(channel.as_str(), ip, "busy").await;
            continue;
        };
        let (acceptor, shared, stop) = (acceptor.clone(), shared.clone(), stop.clone());
        drop(tokio::spawn(async move {
            let _permit = permit;
            serve_connection(tcp, peer, mode, acceptor, shared, stop).await;
        }));
    }
}
