//! An in-process HTTPS server for tests of the agent web executor: it
//! answers each request from a script and records **every** request it
//! receives — method, path and headers — so a test can assert what the
//! vault's client sent (no credential before a challenge, no agent header,
//! the confirmed path byte for byte) and what it never sent.
//!
//! Its certificate is issued by a CA minted per server, for the names it is
//! started with, so a test can pin the leaf, pin the CA, or pin nothing.
//! Neither is in any platform store.
//!
//! Compiled only for tests (`cfg(test)`, or the `test-support` feature,
//! which only the facade's dev-dependency turns on). It listens on loopback,
//! which the destination policy refuses unless a test opens its seam.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use bv_utils::tls_pin::SpkiPin;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

/// One request as the server saw it.
#[derive(Debug, Clone, Default)]
pub struct RecordedRequest {
    pub method: String,
    /// The request target, as sent.
    pub path: String,
    /// Lower-case names.
    pub headers: Vec<(String, String)>,
}

impl RecordedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }
}

/// What the server answers.
#[derive(Debug, Clone, Default)]
pub struct TestResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Wait this long before answering at all.
    pub delay: Option<Duration>,
}

impl TestResponse {
    pub fn new(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Self { status, headers: vec![("content-type".into(), content_type.into())], body: body.into(), delay: None }
    }

    pub fn redirect(status: u16, location: &str) -> Self {
        Self { status, headers: vec![("location".into(), location.into())], ..Default::default() }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

type Responder = Arc<dyn Fn(&RecordedRequest) -> TestResponse + Send + Sync>;

/// A running server. Dropping it stops accepting.
pub struct TestWebServer {
    addr: SocketAddr,
    leaf_pin: SpkiPin,
    ca_pin: SpkiPin,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestWebServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A pin of a key no server here presents.
pub fn unrelated_pin() -> String {
    let key = KeyPair::generate().expect("key");
    let der = CertificateParams::new(vec!["unrelated.test".to_string()])
        .expect("params")
        .self_signed(&key)
        .expect("cert")
        .der()
        .to_vec();
    SpkiPin::of_certificate(&der).expect("pin").to_string()
}

const MAX_HEAD_BYTES: usize = 64 * 1024;

impl TestWebServer {
    /// Listen on `127.0.0.1`, with a certificate for `names` (DNS names or IP
    /// literals) issued by a fresh CA; the chain presented is leaf then CA.
    pub async fn start(
        names: &[&str],
        responder: impl Fn(&RecordedRequest) -> TestResponse + Send + Sync + 'static,
    ) -> Self {
        let ca_key = KeyPair::generate().expect("CA key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, "BastionVault test CA");
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca_der = ca_params.self_signed(&ca_key).expect("CA cert").der().to_vec();
        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf_der = CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
            .expect("leaf params")
            .signed_by(&leaf_key, &Issuer::from_params(&ca_params, &ca_key))
            .expect("leaf cert")
            .der()
            .to_vec();
        let leaf_pin = SpkiPin::of_certificate(&leaf_der).expect("leaf pin");
        let ca_pin = SpkiPin::of_certificate(&ca_der).expect("CA pin");

        let config =
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("protocol versions")
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(leaf_der), CertificateDer::from(ca_der)],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
                )
                .expect("server config");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let responder: Responder = Arc::new(responder);
        let recorded = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                let acceptor = acceptor.clone();
                let responder = responder.clone();
                let recorded = recorded.clone();
                tokio::spawn(async move {
                    // A client that refuses the certificate ends here.
                    let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                    let Some(request) = read_head(&mut tls).await else { return };
                    recorded.lock().expect("requests").push(request.clone());
                    let response = responder(&request);
                    if let Some(delay) = response.delay {
                        tokio::time::sleep(delay).await;
                    }
                    let mut out = format!("HTTP/1.1 {} Test\r\n", response.status);
                    out.push_str(&format!("content-length: {}\r\nconnection: close\r\n", response.body.len()));
                    for (name, value) in &response.headers {
                        out.push_str(&format!("{name}: {value}\r\n"));
                    }
                    out.push_str("\r\n");
                    let mut bytes = out.into_bytes();
                    if request.method != "HEAD" {
                        bytes.extend_from_slice(&response.body);
                    }
                    let _ = tls.write_all(&bytes).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        Self { addr, leaf_pin, ca_pin, requests, task }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `sha256:<hex>` of the leaf's key.
    pub fn leaf_pin(&self) -> String {
        self.leaf_pin.to_string()
    }

    /// `sha256:<hex>` of the issuing CA's key (presented in the chain).
    pub fn ca_pin(&self) -> String {
        self.ca_pin.to_string()
    }

    /// Every request received so far, in order.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("requests").clone()
    }
}

async fn read_head<S: AsyncReadExt + Unpin>(stream: &mut S) -> Option<RecordedRequest> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 || buf.len() + n > MAX_HEAD_BYTES {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&buf);
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split(' ');
    let method = request_line.next()?.to_string();
    let path = request_line.next()?.to_string();
    let headers = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':').map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string())))
        .collect();
    Some(RecordedRequest { method, path, headers })
}
