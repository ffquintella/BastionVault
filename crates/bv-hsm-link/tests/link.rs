//! End to end over real sockets: a fake plain-HTTP connector, the gateway
//! with mTLS (rcgen certificates), and the relay in front of it.

use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use bv_hsm_link::{
    ConnectorUrl, Gateway, GatewayConfig, GatewayLimits, GatewayUrl, LinkTls, Relay, RelayConfig, RelayLimits,
};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName},
    ClientConfig, RootCertStore,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};
use tokio_rustls::TlsConnector;

// ---- PKI ----

struct Pki {
    ca_pem: String,
    issuer: CertifiedIssuer<'static, KeyPair>,
}

#[derive(Clone)]
struct Leaf {
    cert_pem: String,
    key_pem: String,
}

impl Pki {
    fn new(name: &str) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, name);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let issuer = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
        Self { ca_pem: issuer.pem(), issuer }
    }

    fn leaf(&self, sans: &[&str]) -> Leaf {
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        let cert = params.signed_by(&key, &*self.issuer).unwrap();
        Leaf { cert_pem: cert.pem(), key_pem: key.serialize_pem() }
    }
}

fn link_tls(leaf: &Leaf, ca_pem: &str) -> LinkTls {
    LinkTls::from_pem(leaf.cert_pem.clone(), leaf.key_pem.clone(), ca_pem.to_string())
}

// ---- fake yubihsm-connector ----

#[derive(Clone, Debug)]
struct Seen {
    head: String,
    body: Vec<u8>,
}

#[derive(Clone)]
struct FakeConnector {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl FakeConnector {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fake = Self { addr: listener.local_addr().unwrap(), seen: Arc::default() };
        let handle = fake.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(handle.clone().serve(stream));
            }
        });
        fake
    }

    fn url(&self) -> ConnectorUrl {
        ConnectorUrl::parse(&format!("http://{}", self.addr)).unwrap()
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// Waits until `n` requests have reached the connector.
    async fn wait_for(&self, n: usize) {
        for _ in 0..500 {
            if self.seen.lock().unwrap().len() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the connector never received {n} requests");
    }

    /// Answers `ack:` + body; a few bodies trigger misbehaviour.
    async fn serve(self, mut stream: TcpStream) {
        let mut buf = Vec::new();
        let head_end = loop {
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break p + 4;
            }
            let mut chunk = [0u8; 4096];
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        let length = head
            .lines()
            .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap()))
            .unwrap_or(0usize);
        while buf.len() < head_end + length {
            let mut chunk = [0u8; 4096];
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let body = buf[head_end..head_end + length].to_vec();
        self.seen.lock().unwrap().push(Seen { head: head.clone(), body: body.clone() });
        let reply = if head.starts_with("GET /connector/status ") {
            ok_response(b"status=OK\nserial=0012345678\n")
        } else {
            match body.as_slice() {
                b"hang" => {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    return;
                }
                b"slow" => {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                    ok_response(b"ack:slow")
                }
                b"nolen" => {
                    b"HTTP/1.0 200 OK\r\nContent-Type: application/octet-stream\r\n\r\nclose-delimited".to_vec()
                }
                b"chunked" => b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec(),
                b"err" => b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 6\r\n\r\nno hsm".to_vec(),
                other => {
                    let mut ack = b"ack:".to_vec();
                    ack.extend_from_slice(other);
                    ok_response(&ack)
                }
            }
        };
        let _ = stream.write_all(&reply).await;
        let _ = stream.shutdown().await;
    }
}

fn ok_response(body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    out.extend_from_slice(body);
    out
}

// ---- gateway harness ----

struct RunningGateway {
    addr: SocketAddr,
    gateway: Arc<Gateway>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl RunningGateway {
    async fn start(config: GatewayConfig) -> Self {
        let gateway = Arc::new(Gateway::bind(config).await.unwrap());
        let (stop, stopped) = oneshot::channel::<()>();
        let serving = gateway.clone();
        let task = tokio::spawn(async move {
            serving
                .serve(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        Self { addr: gateway.local_addr(), gateway, stop: Some(stop), task: Some(task) }
    }

    async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.task.take().unwrap().await.unwrap();
    }
}

struct Fixture {
    pki: Pki,
    connector: FakeConnector,
    gateway: RunningGateway,
}

fn gateway_config(pki: &Pki, connector: &FakeConnector, allowed: &[&str]) -> GatewayConfig {
    let server = pki.leaf(&["hsm-a.test", "127.0.0.1"]);
    GatewayConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        connector: connector.url(),
        tls: link_tls(&server, &pki.ca_pem),
        allowed_clients: allowed.iter().map(|s| s.to_string()).collect(),
        max_rps_per_client: 1000,
        limits: GatewayLimits::default(),
    }
}

async fn fixture_with(edit: impl FnOnce(&mut GatewayConfig)) -> Fixture {
    let pki = Pki::new("link-ca");
    let connector = FakeConnector::start().await;
    let mut config = gateway_config(&pki, &connector, &["vault-1", "vault-2"]);
    edit(&mut config);
    let gateway = RunningGateway::start(config).await;
    Fixture { pki, connector, gateway }
}

async fn fixture() -> Fixture {
    fixture_with(|_| {}).await
}

// ---- TLS client for the gateway ----

type ClientTls = tokio_rustls::client::TlsStream<TcpStream>;

async fn connect_tls(addr: SocketAddr, ca_pem: &str, client: Option<&Leaf>, name: &str) -> io::Result<ClientTls> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots);
    let config = match client {
        Some(leaf) => {
            let chain: Vec<_> =
                CertificateDer::pem_slice_iter(leaf.cert_pem.as_bytes()).collect::<Result<_, _>>().unwrap();
            let key = PrivateKeyDer::from_pem_slice(leaf.key_pem.as_bytes()).unwrap();
            builder.with_client_auth_cert(chain, key).unwrap()
        }
        None => builder.with_no_client_auth(),
    };
    let tcp = TcpStream::connect(addr).await?;
    let name = ServerName::try_from(name).unwrap().to_owned();
    TlsConnector::from(Arc::new(config)).connect(name, tcp).await
}

async fn client(f: &Fixture, node: &str) -> ClientTls {
    let leaf = f.pki.leaf(&[node]);
    connect_tls(f.gateway.addr, &f.pki.ca_pem, Some(&leaf), "hsm-a.test").await.unwrap()
}

#[derive(Debug, PartialEq, Eq)]
struct Reply {
    status: u16,
    head: String,
    body: Vec<u8>,
}

/// Writes `raw` and reads one response; `None` if the connection ended or
/// failed before a complete response head.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, raw: &[u8]) -> Option<Reply> {
    if stream.write_all(raw).await.is_err() || stream.flush().await.is_err() {
        return None;
    }
    read_reply(stream).await
}

async fn read_reply<S: AsyncRead + Unpin>(stream: &mut S) -> Option<Reply> {
    let mut buf = Vec::new();
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8(buf[..head_end].to_vec()).unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    let length: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: ").map(|v| v.parse().unwrap()))
        .expect("every response carries Content-Length");
    while buf.len() < head_end + length {
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    Some(Reply { status, head, body: buf[head_end..head_end + length].to_vec() })
}

fn api(body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "POST /connector/api HTTP/1.1\r\nHost: hsm-a.test:8250\r\nUser-Agent: yubihsm.rs 0.42.1\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

const STATUS: &[u8] = b"GET /connector/status HTTP/1.1\r\nHost: hsm-a.test:8250\r\n\r\n";

// ---- log capture ----

struct Capture(Mutex<Vec<String>>);

impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &log::Record<'_>) {
        self.0.lock().unwrap().push(format!("{} {} {}", record.level(), record.target(), record.args()));
    }
    fn flush(&self) {}
}

fn captured_logs() -> &'static Capture {
    static CAPTURE: OnceLock<&'static Capture> = OnceLock::new();
    CAPTURE.get_or_init(|| {
        let capture: &'static Capture = Box::leak(Box::new(Capture(Mutex::new(Vec::new()))));
        let _ = log::set_logger(capture);
        log::set_max_level(log::LevelFilter::Trace);
        capture
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---- gateway ----

#[tokio::test]
async fn gateway_forwards_api_and_status_bodies_verbatim() {
    let f = fixture().await;
    let mut c = client(&f, "vault-1").await;

    let command = [0x03u8, 0x00, 0x08, 0xff, 0x00, 0x10, 0x7f, b'\r', b'\n', 0x00, 0x01];
    let reply = exchange(&mut c, &api(&command)).await.unwrap();
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, [b"ack:".as_slice(), &command].concat());
    // Keep-alive: the same connection carries the next requests.
    let status = exchange(&mut c, STATUS).await.unwrap();
    assert_eq!((status.status, status.body.as_slice()), (200, &b"status=OK\nserial=0012345678\n"[..]));
    assert_eq!(exchange(&mut c, &api(b"abc")).await.unwrap().body, b"ack:abc");

    let seen = f.connector.seen();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].body, command);
    let expected_host = format!("Host: {}\r\n", f.connector.addr);
    assert_eq!(seen[0].head, format!("POST /connector/api HTTP/1.0\r\n{expected_host}Content-Length: 11\r\n\r\n"));
    assert_eq!(seen[1].head, format!("GET /connector/status HTTP/1.0\r\n{expected_host}\r\n"));
    assert!(seen.iter().all(|s| !s.head.contains("yubihsm.rs")), "client headers must not reach the connector");
    assert_eq!(f.gateway.gateway.stats().requests_forwarded, 3);
    f.gateway.stop().await;
}

#[tokio::test]
async fn gateway_refuses_clients_outside_the_ca_or_the_allow_list() {
    let f = fixture().await;
    let other_ca = Pki::new("other-ca");

    // A certificate from another CA, no certificate, a SAN not on the list,
    // and a certificate naming two allowed clients at once.
    let foreign = other_ca.leaf(&["vault-1"]);
    let attempts = [
        (Some(foreign), "foreign CA"),
        (None, "no client certificate"),
        (Some(f.pki.leaf(&["vault-9"])), "SAN not allowed"),
        (Some(f.pki.leaf(&["VAULT-1"])), "SAN differs in case"),
        (Some(f.pki.leaf(&["vault-1", "vault-2"])), "two allowed SANs"),
    ];
    for (leaf, label) in attempts {
        match connect_tls(f.gateway.addr, &f.pki.ca_pem, leaf.as_ref(), "hsm-a.test").await {
            Err(_) => {}
            Ok(mut stream) => assert_eq!(exchange(&mut stream, &api(b"abc")).await, None, "{label}"),
        }
    }
    assert!(f.connector.seen().is_empty(), "a refused client reached the connector");
    let stats = f.gateway.gateway.stats();
    assert_eq!((stats.connections_accepted, stats.connections_refused), (0, 5));
    f.gateway.stop().await;
}

#[tokio::test]
async fn gateway_enforces_the_connector_body_bounds() {
    let f = fixture().await;
    for (len, want) in [(2usize, 400u16), (3, 200), (3139, 200), (3140, 413)] {
        let mut c = client(&f, "vault-1").await;
        let reply = exchange(&mut c, &api(&vec![0x5a; len])).await.unwrap();
        assert_eq!(reply.status, want, "body of {len} bytes");
    }
    let bodies: Vec<usize> = f.connector.seen().iter().map(|s| s.body.len()).collect();
    assert_eq!(bodies, [3, 3139]);
    f.gateway.stop().await;
}

#[tokio::test]
async fn gateway_refuses_smuggling_and_malformed_requests() {
    let f = fixture().await;
    let host = "Host: hsm-a.test\r\n";
    let mut pipelined = api(b"abc");
    pipelined.extend_from_slice(&api(b"def"));
    let oversize_head =
        format!("POST /connector/api HTTP/1.1\r\n{host}X-Pad: {}\r\nContent-Length: 3\r\n\r\nabc", "a".repeat(9000));
    let cases: Vec<(Vec<u8>, u16)> = vec![
        (
            format!("POST /connector/api HTTP/1.1\r\n{host}Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
                .into_bytes(),
            501,
        ),
        (
            format!("POST /connector/api HTTP/1.1\r\n{host}Content-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\nabc")
                .into_bytes(),
            501,
        ),
        (
            format!("POST /connector/api HTTP/1.1\r\n{host}Content-Length: 3\r\nContent-Length: 4\r\n\r\nabcd")
                .into_bytes(),
            400,
        ),
        (format!("POST /connector/api HTTP/1.1\r\n{host}Content-Length: 3, 3\r\n\r\nabc").into_bytes(), 400),
        (b"POST /connector/api HTTP/1.1\nHost: hsm-a.test\nContent-Length: 3\r\n\r\nabc".to_vec(), 400),
        (b"POST /connector/api HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc".to_vec(), 400),
        (format!("POST /connector/api HTTP/1.0\r\n{host}Content-Length: 3\r\n\r\nabc").into_bytes(), 505),
        (
            format!("POST /connector/api HTTP/1.1\r\n{host}Expect: 100-continue\r\nContent-Length: 3\r\n\r\nabc")
                .into_bytes(),
            417,
        ),
        (format!("POST /connector/api HTTP/1.1\r\n{host}\r\nabc").into_bytes(), 411),
        (format!("POST /connector/other HTTP/1.1\r\n{host}Content-Length: 3\r\n\r\nabc").into_bytes(), 404),
        (
            format!("POST http://127.0.0.1:12345/connector/api HTTP/1.1\r\n{host}Content-Length: 3\r\n\r\nabc")
                .into_bytes(),
            404,
        ),
        (format!("PUT /connector/api HTTP/1.1\r\n{host}Content-Length: 3\r\n\r\nabc").into_bytes(), 405),
        (format!("GET /connector/status HTTP/1.1\r\n{host}Content-Length: 3\r\n\r\nabc").into_bytes(), 400),
        (oversize_head.into_bytes(), 431),
        (pipelined, 400),
    ];
    for (raw, want) in cases {
        let mut c = client(&f, "vault-1").await;
        let reply = exchange(&mut c, &raw).await;
        assert_eq!(reply.map(|r| r.status), Some(want), "{}", String::from_utf8_lossy(&raw[..raw.len().min(80)]));
        // Every refusal closes the connection.
        assert_eq!(read_reply(&mut c).await, None);
    }
    assert!(f.connector.seen().is_empty(), "a refused request reached the connector");
    f.gateway.stop().await;
}

#[tokio::test]
async fn gateway_allows_one_request_in_flight_per_client() {
    let f = fixture().await;
    let mut first = client(&f, "vault-1").await;
    let mut second = client(&f, "vault-1").await;
    let mut other = client(&f, "vault-2").await;

    let slow = tokio::spawn(async move { exchange(&mut first, &api(b"slow")).await });
    f.connector.wait_for(1).await;
    let refused = exchange(&mut second, &api(b"abc")).await.unwrap();
    assert_eq!(refused.status, 429);
    // Another client is not affected.
    assert_eq!(exchange(&mut other, &api(b"xyz")).await.unwrap().status, 200);
    assert_eq!(slow.await.unwrap().unwrap().body, b"ack:slow");
    // After the first one completes, the second connection may proceed.
    assert_eq!(exchange(&mut second, &api(b"abc")).await.unwrap().status, 200);
    f.gateway.stop().await;
}

#[tokio::test]
async fn gateway_rate_limits_each_client() {
    let f = fixture_with(|c| c.max_rps_per_client = 2).await;
    let mut c = client(&f, "vault-1").await;
    let statuses = [
        exchange(&mut c, &api(b"r-1")).await.unwrap().status,
        exchange(&mut c, &api(b"r-2")).await.unwrap().status,
        exchange(&mut c, &api(b"r-3")).await.unwrap().status,
    ];
    assert_eq!(statuses, [200, 200, 429]);
    let mut other = client(&f, "vault-2").await;
    assert_eq!(exchange(&mut other, &api(b"o-1")).await.unwrap().status, 200);
    assert_eq!(f.connector.seen().len(), 3);
    f.gateway.stop().await;
}

#[tokio::test]
async fn gateway_bounds_and_maps_the_upstream() {
    let f = fixture_with(|c| c.limits.upstream_timeout = Duration::from_millis(300)).await;
    let mut c = client(&f, "vault-1").await;
    let started = std::time::Instant::now();
    assert_eq!(exchange(&mut c, &api(b"hang")).await.unwrap().status, 504);
    assert!(started.elapsed() < Duration::from_secs(3));
    // A close-delimited reply is accepted, chunked is not, an error status is passed through.
    assert_eq!(exchange(&mut c, &api(b"nolen")).await.unwrap().body, b"close-delimited");
    assert_eq!(exchange(&mut c, &api(b"chunked")).await.unwrap().status, 502);
    let err = exchange(&mut c, &api(b"err")).await.unwrap();
    assert_eq!((err.status, err.body.as_slice()), (503, &b"no hsm"[..]));
    assert_eq!(f.gateway.gateway.stats().upstream_failures, 2);
    f.gateway.stop().await;

    // Nothing listening on the connector port: 502, not a hang.
    let pki = Pki::new("ca");
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = FakeConnector { addr: unused.local_addr().unwrap(), seen: Arc::default() };
    drop(unused);
    let gateway = RunningGateway::start(gateway_config(&pki, &dead, &["vault-1"])).await;
    let leaf = pki.leaf(&["vault-1"]);
    let mut c = connect_tls(gateway.addr, &pki.ca_pem, Some(&leaf), "hsm-a.test").await.unwrap();
    assert_eq!(exchange(&mut c, &api(b"abc")).await.unwrap().status, 502);
    gateway.stop().await;
}

#[tokio::test]
async fn gateway_closes_idle_connections() {
    let f = fixture_with(|c| c.limits.idle_timeout = Duration::from_millis(200)).await;
    let mut c = client(&f, "vault-1").await;
    assert_eq!(exchange(&mut c, &api(b"abc")).await.unwrap().status, 200);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(read_reply(&mut c).await, None);
    f.gateway.stop().await;
}

#[test]
fn gateway_bind_refuses_an_invalid_config() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let pki = Pki::new("ca");
        let connector = FakeConnector::start().await;
        let mut config = gateway_config(&pki, &connector, &[]);
        assert!(Gateway::bind(config).await.is_err(), "empty allow-list");
        config = gateway_config(&pki, &connector, &["vault-1"]);
        config.tls = LinkTls::from_pem(pki.ca_pem.clone(), "not a key", pki.ca_pem.clone());
        let err = Gateway::bind(config).await.err().unwrap().to_string();
        assert!(err.contains("key") && !err.contains("not a key"), "{err}");
    });
}

// ---- relay ----

fn relay_config(f: &Fixture, node: &str, gateway_url: &str) -> RelayConfig {
    RelayConfig {
        gateway: GatewayUrl::parse(gateway_url).unwrap(),
        tls: link_tls(&f.pki.leaf(&[node]), &f.pki.ca_pem),
        limits: RelayLimits::default(),
    }
}

fn gateway_url(f: &Fixture) -> String {
    format!("https://127.0.0.1:{}", f.gateway.addr.port())
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_forwards_through_the_gateway_on_one_pooled_connection() {
    let f = fixture().await;
    let relay = Relay::start(relay_config(&f, "vault-1", &gateway_url(&f))).unwrap();
    assert!(relay.local_addr().ip().is_loopback());

    let mut local = TcpStream::connect(relay.local_addr()).await.unwrap();
    let first = exchange(&mut local, &api(b"\x01\x00\x01\x2a")).await.unwrap();
    // Exactly what `yubihsm` 0.42's reader matches on.
    assert_eq!(first.head, "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n");
    assert_eq!(first.body, b"ack:\x01\x00\x01\x2a");
    assert_eq!(exchange(&mut local, STATUS).await.unwrap().status, 200);
    assert_eq!(exchange(&mut local, &api(b"abc")).await.unwrap().body, b"ack:abc");

    let stats = relay.stats();
    assert_eq!((stats.requests_forwarded, stats.gateway_connects, stats.local_connections), (3, 1, 1));
    assert_eq!(f.gateway.gateway.stats().connections_accepted, 1);
    relay.shutdown();
    f.gateway.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_replaces_a_pooled_connection_the_gateway_closed() {
    let f = fixture_with(|c| c.limits.idle_timeout = Duration::from_millis(200)).await;
    let relay = Relay::start(relay_config(&f, "vault-1", &gateway_url(&f))).unwrap();
    let mut local = TcpStream::connect(relay.local_addr()).await.unwrap();
    assert_eq!(exchange(&mut local, &api(b"one")).await.unwrap().status, 200);
    tokio::time::sleep(Duration::from_millis(600)).await;
    // The gateway has closed the idle mTLS connection; the relay notices
    // before sending, so the node's client sees no error.
    assert_eq!(exchange(&mut local, &api(b"two")).await.unwrap().body, b"ack:two");
    assert_eq!(relay.stats().gateway_connects, 2);
    assert_eq!(relay.stats().requests_failed, 0);
    drop(relay);
    f.gateway.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_answers_502_when_the_gateway_cannot_be_trusted_or_refuses_it() {
    let f = fixture().await;
    let other = Pki::new("other-ca");
    let cases = [
        // The relay trusts another CA than the one that issued the gateway's certificate.
        RelayConfig {
            gateway: GatewayUrl::parse(&gateway_url(&f)).unwrap(),
            tls: link_tls(&other.leaf(&["vault-1"]), &other.ca_pem),
            limits: RelayLimits::default(),
        },
        // The gateway's certificate does not name the host the relay dialled.
        relay_config(&f, "vault-1", &format!("https://localhost:{}", f.gateway.addr.port())),
        // The gateway does not allow this node.
        relay_config(&f, "vault-9", &gateway_url(&f)),
    ];
    for config in cases {
        let relay = Relay::start(config).unwrap();
        let mut local = TcpStream::connect(relay.local_addr()).await.unwrap();
        assert_eq!(exchange(&mut local, &api(b"abc")).await.unwrap().status, 502);
        assert_eq!(relay.stats().requests_failed, 1);
    }
    assert!(f.connector.seen().is_empty());
    f.gateway.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_serves_one_local_connection_at_a_time() {
    let f = fixture().await;
    let relay = Relay::start(relay_config(&f, "vault-1", &gateway_url(&f))).unwrap();

    // An idle connection is replaced by a newcomer.
    let mut idle = TcpStream::connect(relay.local_addr()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut newcomer = TcpStream::connect(relay.local_addr()).await.unwrap();
    assert_eq!(exchange(&mut newcomer, &api(b"new")).await.unwrap().status, 200);
    assert_eq!(read_reply(&mut idle).await, None, "the idle connection must be closed");

    // A connection with a request in progress is answered first; the
    // newcomer waits, then takes over.
    let addr = relay.local_addr();
    let busy = tokio::spawn(async move {
        let mut busy = TcpStream::connect(addr).await.unwrap();
        exchange(&mut busy, &api(b"slow")).await
    });
    f.connector.wait_for(2).await;
    let mut waiting = TcpStream::connect(relay.local_addr()).await.unwrap();
    let waiting_reply = exchange(&mut waiting, &api(b"next")).await.unwrap();
    assert_eq!(busy.await.unwrap().unwrap().body, b"ack:slow");
    assert_eq!(waiting_reply.body, b"ack:next");
    drop(relay);
    f.gateway.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_refuses_malformed_local_requests_without_contacting_the_gateway() {
    let f = fixture().await;
    let relay = Relay::start(relay_config(&f, "vault-1", &gateway_url(&f))).unwrap();
    let cases: [(Vec<u8>, u16); 3] = [
        (b"POST /connector/api HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec(), 501),
        (api(&[0u8; 4000]), 413),
        (b"POST /elsewhere HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc".to_vec(), 404),
    ];
    for (raw, want) in cases {
        let mut local = TcpStream::connect(relay.local_addr()).await.unwrap();
        assert_eq!(exchange(&mut local, &raw).await.map(|r| r.status), Some(want));
    }
    assert_eq!(relay.stats().gateway_connects, 0);
    assert!(f.connector.seen().is_empty());
    drop(relay);
    f.gateway.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_shutdown_releases_its_port() {
    let f = fixture().await;
    let relay = Relay::start(relay_config(&f, "vault-1", &gateway_url(&f))).unwrap();
    let addr = relay.local_addr();
    relay.shutdown();
    assert!(TcpStream::connect(addr).await.is_err());
    f.gateway.stop().await;
}

#[test]
fn relay_start_refuses_bad_tls_material() {
    let pki = Pki::new("ca");
    let config = RelayConfig {
        gateway: GatewayUrl::parse("https://hsm-a.test:8250").unwrap(),
        tls: LinkTls::from_pem("no cert here", pki.leaf(&["vault-1"]).key_pem, pki.ca_pem.clone()),
        limits: RelayLimits::default(),
    };
    assert!(Relay::start(config).is_err());
}

// ---- logs ----

#[tokio::test(flavor = "multi_thread")]
async fn payloads_never_reach_the_logs() {
    let capture = captured_logs();
    let marker = b"PAYLOAD-MARKER-7f3a9c";
    let f = fixture().await;
    let relay = Relay::start(relay_config(&f, "vault-1", &gateway_url(&f))).unwrap();
    let mut local = TcpStream::connect(relay.local_addr()).await.unwrap();
    assert_eq!(exchange(&mut local, &api(marker)).await.unwrap().status, 200);
    // Rejected and failed paths log too; none of them may quote the body.
    let mut direct = client(&f, "vault-1").await;
    let mut smuggled =
        format!("POST /connector/api HTTP/1.1\r\nHost: h\r\nContent-Length: {}\r\n\r\n", marker.len()).into_bytes();
    smuggled.extend_from_slice(marker);
    smuggled.extend_from_slice(marker);
    assert_eq!(exchange(&mut direct, &smuggled).await.unwrap().status, 400);
    drop(relay);
    f.gateway.stop().await;

    let logs = capture.0.lock().unwrap().clone();
    let needles = [String::from_utf8_lossy(marker).to_string(), hex(marker)];
    for line in &logs {
        for needle in &needles {
            assert!(!line.contains(needle.as_str()), "payload in log: {line}");
        }
    }
    assert!(logs.iter().any(|l| l.contains("client=vault-1")), "expected connection logs, got {logs:#?}");
}
