//! The Windows bar's own request for the shown document.
//!
//! WebView2 has no API that saves the document it shows, so the bar fetches
//! it again: one `GET` of the shown URL, over HTTP/1.1, carrying the cookies
//! the webview's cookie manager holds for that URL and the webview's
//! `User-Agent`. Everything a download must pass is the shared model's
//! (`transfer`): the session's allow-list and `allow_downloads` before a
//! connection is opened (spec A6), then the response's status, type,
//! disposition and announced size before a byte is written, the 2 GiB cap on
//! every chunk, and the placeholder + private staging file the bytes land in.
//!
//! What this request is *not*, and how that is kept from becoming a silent
//! downgrade:
//! - **No redirect is followed.** A `3xx` is not the document, so it is
//!   refused as `unavailable`, and no second origin is ever contacted.
//! - **TLS is the platform's verdict only** (`rustls-platform-verifier`, the
//!   OS trust store), with no pin and no operator override. Sessions whose
//!   webview needed either, or whose TLS profile is unknown, never get here
//!   (`windows_model::refetch_gate`), so the request is never trusted with
//!   less than the page was.
//! - **No proxy.** The request goes straight to the origin. Proxy-mode
//!   sessions are refused by the same gate. A system proxy (WinINET / PAC)
//!   is not applied either: on a network that requires one, the connection
//!   fails and the download is refused as `transfer_failed`.
//! - **No HTTP authentication and no request body**: a document that needs
//!   either does not come back as a `2xx` downloadable response and is
//!   refused as `unavailable`.
//!
//! Nothing here is logged but a fixed stage name: no URL, no header, no
//! cookie, no error text (which can carry the host). The `Cookie` value is
//! kept in a zeroizing buffer until it is copied into the request.
//!
//! Not `cfg`-gated: it is plain tokio / hyper / rustls, so it is tested on
//! every host against a local server.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use rustls_platform_verifier::BuilderVerifierExt;
use tauri::Url;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::timeout;
use zeroize::Zeroizing;

use super::reason;
use super::transfer::{url_policy, ResponseFacts, Settled, Transfer};
use super::windows_model::disposition_filename;
use crate::session::web::OriginSet;

/// Longest wait for a TCP connection or a TLS handshake.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Longest wait for the response head once the request is sent.
pub(crate) const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest silence between two body frames.
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// What the bar asks for.
pub(crate) struct Refetch {
    /// The shown URL (fragment ignored).
    pub url: Url,
    /// The webview's cookies for `url`, as one `Cookie` header value.
    pub cookie: Option<Zeroizing<String>>,
    /// The webview's `User-Agent`.
    pub user_agent: Option<String>,
}

/// The session's download policy, as `RemotePolicy::on_download` applies it.
pub(crate) struct Policy {
    pub allow_downloads: bool,
    pub origins: Arc<OriginSet>,
}

/// A client configuration that trusts exactly what the OS trust store
/// trusts, for HTTP/1.1.
pub(crate) fn platform_tls() -> Result<Arc<ClientConfig>, rustls::Error> {
    // The provider the rest of this crate's TLS uses (`web_proxy_upstream`).
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_platform_verifier()?
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// The request for `refetch`: `GET` of the origin-form target (path and
/// query, never the fragment or any user info), `Host`, `Accept: */*`,
/// `Accept-Encoding: identity` (the bytes are saved as they come),
/// `Connection: close`, the `User-Agent` when it is a valid header value and
/// the `Cookie` header marked sensitive. `Err` is the refusal reason.
pub(crate) fn request(refetch: &Refetch) -> Result<hyper::Request<Empty<Bytes>>, &'static str> {
    let url = &refetch.url;
    let host = url.host_str().filter(|h| !h.is_empty()).ok_or(reason::UNAVAILABLE)?;
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let mut target = url.path().to_string();
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    let target: hyper::Uri = target.parse().map_err(|_| reason::UNAVAILABLE)?;
    let mut builder = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(target)
        .version(hyper::Version::HTTP_11)
        .header(header::HOST, authority)
        .header(header::ACCEPT, "*/*")
        .header(header::ACCEPT_ENCODING, "identity")
        .header(header::CONNECTION, "close");
    if let Some(agent) = refetch.user_agent.as_deref().and_then(|a| HeaderValue::from_str(a).ok()) {
        builder = builder.header(header::USER_AGENT, agent);
    }
    if let Some(cookie) = &refetch.cookie {
        // `from_str` refuses control characters, so no value can end the
        // header early. The copy hyper keeps is not zeroized.
        let mut value = HeaderValue::from_str(cookie).map_err(|_| reason::TRANSFER_FAILED)?;
        value.set_sensitive(true);
        builder = builder.header(header::COOKIE, value);
    }
    builder.body(Empty::new()).map_err(|_| reason::TRANSFER_FAILED)
}

/// The response facts the shared checks want. The URL is the request's: no
/// redirect is followed.
pub(crate) fn response_facts(url: &Url, status: u16, headers: &HeaderMap) -> ResponseFacts {
    let text = |name: header::HeaderName| {
        headers
            .get(name)
            .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    };
    let content_disposition = text(header::CONTENT_DISPOSITION);
    ResponseFacts {
        url: Some(url.clone()),
        status: Some(i64::from(status)),
        mime: text(header::CONTENT_TYPE),
        suggested_filename: content_disposition.as_deref().and_then(disposition_filename),
        content_disposition,
        expected_length: text(header::CONTENT_LENGTH).and_then(|v| v.parse().ok()),
    }
}

/// Fetch `refetch` into `transfer` and return how it settled — exactly once,
/// whatever happens: a refusal, a transport failure, `cancel` turning true or
/// its sender being dropped (the bar is gone), or the file in place.
pub(crate) async fn run(
    refetch: Refetch,
    mut transfer: Transfer,
    policy: Policy,
    tls: Arc<ClientConfig>,
    mut cancel: watch::Receiver<bool>,
) -> Settled {
    let fetched = tokio::select! {
        biased;
        () = cancelled(&mut cancel) => Err("cancelled"),
        step = fetch(&refetch, &mut transfer, &policy, tls) => step,
    };
    // The cookie is zeroized here, whatever happened.
    drop(refetch);
    match fetched {
        Ok(Some(settled)) => settled,
        // The last byte is in the staging file: move it into place off the
        // async workers (a copy when Downloads is on another volume).
        Ok(None) => match tokio::task::spawn_blocking(move || transfer.finish()).await {
            Ok(Some(settled)) => settled,
            _ => Settled::Refused(reason::TRANSFER_FAILED),
        },
        Err(stage) => {
            // A fixed stage name only: an error's text can carry the host.
            log::warn!("connect.web.nav_bar: the download request stopped ({stage})");
            transfer.fail(reason::TRANSFER_FAILED).unwrap_or(Settled::Refused(reason::TRANSFER_FAILED))
        }
    }
}

/// Resolves when `cancel` turns true or its sender is dropped.
async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow_and_update() {
            return;
        }
        if cancel.changed().await.is_err() {
            return;
        }
    }
}

/// The connection's driver task, stopped when the exchange is over.
struct Connection(tokio::task::JoinHandle<()>);

impl Drop for Connection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// `Ok(Some)`: settled (refused) on the way. `Ok(None)`: the whole body is
/// in the staging file. `Err`: a transport failure, by stage.
async fn fetch(
    refetch: &Refetch,
    transfer: &mut Transfer,
    policy: &Policy,
    tls: Arc<ClientConfig>,
) -> Result<Option<Settled>, &'static str> {
    // The webview's own download policy, again, before a connection is
    // opened (A6): the caller checked it on the click too.
    if let Err(refusal) = url_policy(policy.allow_downloads, &policy.origins, &refetch.url) {
        return Ok(transfer.fail(refusal));
    }
    let request = match request(refetch) {
        Ok(request) => request,
        Err(refusal) => return Ok(transfer.fail(refusal)),
    };
    let Some((host, port)) = endpoint(&refetch.url) else { return Ok(transfer.fail(reason::UNAVAILABLE)) };
    let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| "connect")?
        .map_err(|_| "connect")?;
    let _ = tcp.set_nodelay(true);
    if refetch.url.scheme() == "https" {
        let name = ServerName::try_from(host).map_err(|_| "tls")?;
        let stream = timeout(CONNECT_TIMEOUT, tokio_rustls::TlsConnector::from(tls).connect(name, tcp))
            .await
            .map_err(|_| "tls")?
            .map_err(|_| "tls")?;
        exchange(stream, request, refetch, transfer, policy).await
    } else {
        // `url_policy` admits only http(s), and plain http only when the
        // session's allow-list names the http origin.
        exchange(tcp, request, refetch, transfer, policy).await
    }
}

/// The host to connect to (IPv6 without brackets) and the port.
fn endpoint(url: &Url) -> Option<(String, u16)> {
    let host = url.host_str().filter(|h| !h.is_empty())?;
    // `host_str` writes an IPv6 address in brackets; connecting and TLS
    // server names want it bare.
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    Some((bare.to_string(), url.port_or_known_default()?))
}

async fn exchange<T>(
    io: T,
    request: hyper::Request<Empty<Bytes>>,
    refetch: &Refetch,
    transfer: &mut Transfer,
    policy: &Policy,
) -> Result<Option<Settled>, &'static str>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await.map_err(|_| "handshake")?;
    let _connection = Connection(tokio::spawn(async move {
        let _ = conn.await;
    }));
    let response = timeout(RESPONSE_TIMEOUT, sender.send_request(request))
        .await
        .map_err(|_| "response")?
        .map_err(|_| "response")?;
    let facts = response_facts(&refetch.url, response.status().as_u16(), response.headers());
    let now = chrono::Local::now().naive_local();
    if let Some(settled) = transfer.begin(&facts, policy.allow_downloads, &policy.origins, now) {
        return Ok(Some(settled));
    }
    if let Some(settled) = transfer.open_writer() {
        return Ok(Some(settled));
    }
    let mut body = response.into_body();
    loop {
        let frame = match timeout(IDLE_TIMEOUT, body.frame()).await {
            Err(_) | Ok(Some(Err(_))) => return Err("body"),
            Ok(None) => return Ok(None),
            Ok(Some(Ok(frame))) => frame,
        };
        if let Ok(data) = frame.into_data() {
            if let Some(settled) = transfer.write_chunk(&data) {
                return Ok(Some(settled));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use hyper::header::HeaderValue;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::RootCertStore;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use super::*;
    use crate::session::web::WebOrigin;
    use crate::session::web_nav_bar::transfer::Destination;
    use crate::session::web_nav_bar::{reason, DownloadLimiter, DOWNLOAD_SOFT_CAP_BYTES};

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn tempdir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "bv-nav-refetch-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn dest(tag: &str) -> Destination {
        let root = tempdir(tag);
        let downloads_dir = root.join("Downloads");
        let staging_root = root.join("staging");
        std::fs::create_dir_all(&downloads_dir).unwrap();
        std::fs::create_dir_all(&staging_root).unwrap();
        Destination { downloads_dir, staging_root }
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> =
            std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    fn policy_for(origin: &str) -> Policy {
        let o = WebOrigin::of_url(&url(origin)).unwrap();
        Policy { allow_downloads: true, origins: Arc::new(OriginSet::new(vec![o])) }
    }

    fn transfer(limiter: &Arc<DownloadLimiter>, d: &Destination) -> Transfer {
        Transfer::new(limiter.try_acquire().expect("slot"), d.clone())
    }

    fn refetch(u: &str) -> Refetch {
        Refetch {
            url: url(u),
            cookie: Some(Zeroizing::new("SID=s3cr3t; theme=dark".to_string())),
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0) Edg/130".to_string()),
        }
    }

    /// Keeps the test's cancel sender alive for the transfer's lifetime.
    fn never_cancelled() -> (watch::Sender<bool>, watch::Receiver<bool>) {
        watch::channel(false)
    }

    fn plain_tls() -> Arc<ClientConfig> {
        trusting(&[])
    }

    /// A client configuration trusting exactly `roots`.
    fn trusting(roots: &[&[u8]]) -> Arc<ClientConfig> {
        let mut store = RootCertStore::empty();
        for der in roots {
            store.add(CertificateDer::from(der.to_vec())).unwrap();
        }
        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(store)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }

    /// Read one request head from `stream`, answer `response`, then keep the
    /// connection open for `hold`. Returns the head.
    async fn answer<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, response: Vec<u8>, hold: Duration) -> String {
        let mut head = Vec::new();
        let mut chunk = [0u8; 1024];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => head.extend_from_slice(&chunk[..n]),
            }
        }
        let _ = stream.write_all(&response).await;
        let _ = stream.flush().await;
        tokio::time::sleep(hold).await;
        String::from_utf8_lossy(&head).into_owned()
    }

    /// A plain HTTP server for one connection on 127.0.0.1.
    async fn http_server(response: Vec<u8>, hold: Duration) -> (u16, JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            answer(stream, response, hold).await
        });
        (port, task)
    }

    fn ok(content_type: &str, extra: &str, body: &[u8]) -> Vec<u8> {
        let mut r = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        r.extend_from_slice(body);
        r
    }

    // ── request / response mapping ──

    #[test]
    fn the_request_is_a_plain_get_of_the_shown_document() {
        let r = refetch("https://fw.example.com/exports/q3.pdf?sig=abc#page=2");
        let req = request(&r).unwrap();
        assert_eq!(req.method(), hyper::Method::GET);
        assert_eq!(req.version(), hyper::Version::HTTP_11);
        assert_eq!(req.uri().to_string(), "/exports/q3.pdf?sig=abc", "origin form, no fragment");
        let h = req.headers();
        assert_eq!(h[header::HOST], "fw.example.com");
        assert_eq!(h[header::ACCEPT], "*/*");
        assert_eq!(h[header::ACCEPT_ENCODING], "identity");
        assert_eq!(h[header::CONNECTION], "close");
        assert_eq!(h[header::USER_AGENT], "Mozilla/5.0 (Windows NT 10.0) Edg/130");
        assert_eq!(h[header::COOKIE], "SID=s3cr3t; theme=dark");
        assert!(h[header::COOKIE].is_sensitive(), "never printed by hyper");
        assert!(!format!("{req:?}").contains("s3cr3t"), "the Debug form hides the cookie");
    }

    #[test]
    fn the_host_header_carries_a_non_default_port_and_ipv6_brackets() {
        let r = Refetch { url: url("https://fw.example.com:8443/"), cookie: None, user_agent: None };
        let req = request(&r).unwrap();
        assert_eq!(req.headers()[header::HOST], "fw.example.com:8443");
        assert_eq!(req.uri().to_string(), "/");
        assert!(req.headers().get(header::COOKIE).is_none());
        assert!(req.headers().get(header::USER_AGENT).is_none());
        let r = Refetch { url: url("http://[::1]:8080/a.pdf"), cookie: None, user_agent: None };
        assert_eq!(request(&r).unwrap().headers()[header::HOST], "[::1]:8080");
    }

    #[test]
    fn user_info_is_never_sent_and_a_bad_user_agent_is_dropped() {
        let r = Refetch {
            url: url("https://op:pw@fw.example.com/a.pdf"),
            cookie: None,
            user_agent: Some("bad\r\nX-Evil: 1".into()),
        };
        let req = request(&r).unwrap();
        assert_eq!(req.headers()[header::HOST], "fw.example.com");
        assert!(req.headers().get(header::AUTHORIZATION).is_none());
        assert!(req.headers().get(header::USER_AGENT).is_none());
        assert!(!format!("{:?}", req.headers()).contains("pw"));
        // A cookie value that is not a valid header value is refused, not sent.
        let r = Refetch { cookie: Some(Zeroizing::new("a=1\r\nX: y".into())), ..refetch("https://fw.example.com/") };
        assert_eq!(request(&r).err(), Some(reason::TRANSFER_FAILED));
    }

    #[test]
    fn response_headers_map_to_the_shared_facts() {
        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/pdf"));
        h.insert(header::CONTENT_LENGTH, HeaderValue::from_static("4096"));
        h.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment; filename=\"q3.pdf\"; filename*=UTF-8''Q3%20r%C3%A9sum%C3%A9.pdf"),
        );
        let u = url("https://fw.example.com/r?id=1");
        let f = response_facts(&u, 200, &h);
        assert_eq!(f.url, Some(u.clone()));
        assert_eq!(f.status, Some(200));
        assert_eq!(f.mime.as_deref(), Some("application/pdf"));
        assert_eq!(f.expected_length, Some(4096));
        assert_eq!(f.suggested_filename.as_deref(), Some("Q3 résumé.pdf"));
        assert!(f.content_disposition.as_deref().unwrap().starts_with("attachment"));
        // Nothing announced: nothing assumed.
        let f = response_facts(&u, 204, &HeaderMap::new());
        assert_eq!((f.mime, f.expected_length, f.suggested_filename), (None, None, None));
        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_LENGTH, HeaderValue::from_static("not-a-number"));
        assert_eq!(response_facts(&u, 200, &h).expected_length, None);
    }

    #[test]
    fn the_request_can_run_on_the_async_runtime() {
        // The Windows shim spawns it with `tauri::async_runtime::spawn`.
        fn spawnable<T: std::future::Future + Send + 'static>(_: T) {}
        let d = dest("send");
        let limiter = Arc::new(DownloadLimiter::new());
        let (_keep, cancel) = never_cancelled();
        spawnable(run(
            refetch("https://fw.example.com/a.pdf"),
            transfer(&limiter, &d),
            policy_for("https://fw.example.com"),
            plain_tls(),
            cancel,
        ));
        assert_eq!(limiter.in_flight(), 0, "an unpolled request releases its slot when dropped");
    }

    #[test]
    fn the_platform_tls_configuration_can_be_built_and_speaks_http_1_1() {
        let c = platform_tls().expect("the OS trust store opens");
        assert_eq!(c.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    // ── end to end, against a local server ──

    #[tokio::test]
    async fn an_allowed_pdf_is_saved_with_the_webviews_cookies() {
        let (port, server) = http_server(ok("application/pdf", "", b"%PDF-1.7 hello"), Duration::ZERO).await;
        let origin = format!("http://127.0.0.1:{port}");
        let d = dest("saved");
        let limiter = Arc::new(DownloadLimiter::new());
        let (_keep, cancel) = never_cancelled();
        let settled = run(
            refetch(&format!("{origin}/files/Q3%20report.pdf?sig=1#p=2")),
            transfer(&limiter, &d),
            policy_for(&origin),
            plain_tls(),
            cancel,
        )
        .await;
        match settled {
            Settled::Saved(s) => {
                assert_eq!(s.filename, "Q3 report.pdf");
                assert_eq!(s.mime, "application/pdf");
                assert_eq!(s.bytes, 14);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(std::fs::read(d.downloads_dir.join("Q3 report.pdf")).unwrap(), b"%PDF-1.7 hello");
        assert!(entries(&d.staging_root).is_empty(), "staging removed");
        assert_eq!(limiter.in_flight(), 0);
        let head = server.await.unwrap();
        assert!(head.starts_with("GET /files/Q3%20report.pdf?sig=1 HTTP/1.1\r\n"), "{head}");
        let lower = head.to_ascii_lowercase();
        assert!(lower.contains(&format!("host: 127.0.0.1:{port}\r\n")), "{head}");
        assert!(lower.contains("cookie: sid=s3cr3t; theme=dark\r\n"), "{head}");
        assert!(lower.contains("accept-encoding: identity\r\n"), "{head}");
        assert!(!head.contains("p=2"), "no fragment on the wire");
    }

    #[tokio::test]
    async fn a_url_outside_the_allow_list_is_refused_before_any_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let d = dest("offlist");
        let limiter = Arc::new(DownloadLimiter::new());
        let (_keep, cancel) = never_cancelled();
        let settled = run(
            refetch(&format!("http://127.0.0.1:{port}/a.pdf")),
            transfer(&limiter, &d),
            policy_for("https://fw.example.com"),
            plain_tls(),
            cancel,
        )
        .await;
        assert_eq!(settled, Settled::Refused(reason::OUTSIDE_ALLOWLIST));
        assert!(
            tokio::time::timeout(Duration::from_millis(200), listener.accept()).await.is_err(),
            "nothing connected"
        );
        assert!(entries(&d.downloads_dir).is_empty());
        assert_eq!(limiter.in_flight(), 0);
        // A profile without downloads is refused the same way.
        let (_keep, cancel) = never_cancelled();
        let origin = format!("http://127.0.0.1:{port}");
        let off = Policy { allow_downloads: false, ..policy_for(&origin) };
        let settled = run(refetch(&format!("{origin}/a.pdf")), transfer(&limiter, &d), off, plain_tls(), cancel).await;
        assert_eq!(settled, Settled::Refused(reason::DOWNLOADS_DISABLED));
        assert!(tokio::time::timeout(Duration::from_millis(200), listener.accept()).await.is_err());
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let response = b"HTTP/1.1 302 Found\r\nLocation: https://evil.example.net/a.pdf\r\nContent-Length: 0\r\n\r\n";
        let (port, server) = http_server(response.to_vec(), Duration::ZERO).await;
        let origin = format!("http://127.0.0.1:{port}");
        let d = dest("redirect");
        let limiter = Arc::new(DownloadLimiter::new());
        let (_keep, cancel) = never_cancelled();
        let settled =
            run(refetch(&format!("{origin}/a.pdf")), transfer(&limiter, &d), policy_for(&origin), plain_tls(), cancel)
                .await;
        assert_eq!(settled, Settled::Refused(reason::UNAVAILABLE));
        assert!(server.await.unwrap().starts_with("GET /a.pdf "));
        assert!(entries(&d.downloads_dir).is_empty());
    }

    #[tokio::test]
    async fn a_page_or_an_oversized_announcement_is_refused_before_a_byte_is_written() {
        let (port, _server) = http_server(ok("text/html", "", b"<html>login</html>"), Duration::ZERO).await;
        let origin = format!("http://127.0.0.1:{port}");
        let d = dest("html");
        let limiter = Arc::new(DownloadLimiter::new());
        let (_keep, cancel) = never_cancelled();
        let settled =
            run(refetch(&format!("{origin}/a.pdf")), transfer(&limiter, &d), policy_for(&origin), plain_tls(), cancel)
                .await;
        assert_eq!(settled, Settled::Refused(reason::UNAVAILABLE));
        assert!(entries(&d.downloads_dir).is_empty());

        let big = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: {}\r\n\r\nPK",
            DOWNLOAD_SOFT_CAP_BYTES + 1
        );
        let (port, _server) = http_server(big.into_bytes(), Duration::from_millis(500)).await;
        let origin = format!("http://127.0.0.1:{port}");
        let (_keep, cancel) = never_cancelled();
        let settled =
            run(refetch(&format!("{origin}/a.zip")), transfer(&limiter, &d), policy_for(&origin), plain_tls(), cancel)
                .await;
        assert_eq!(settled, Settled::Refused(reason::SIZE_EXCEEDED));
        assert!(entries(&d.downloads_dir).is_empty());
        assert!(entries(&d.staging_root).is_empty());
        assert_eq!(limiter.in_flight(), 0);
    }

    #[tokio::test]
    async fn an_attachment_html_is_saved_under_its_disposition_name() {
        let extra = "Content-Disposition: attachment; filename=\"..\\\\report.html\"\r\n";
        let (port, _server) = http_server(ok("text/html", extra, b"<p>r</p>"), Duration::ZERO).await;
        let origin = format!("http://127.0.0.1:{port}");
        let d = dest("attach");
        let limiter = Arc::new(DownloadLimiter::new());
        let (_keep, cancel) = never_cancelled();
        let settled =
            run(refetch(&format!("{origin}/export")), transfer(&limiter, &d), policy_for(&origin), plain_tls(), cancel)
                .await;
        match settled {
            Settled::Saved(s) => assert_eq!(s.filename, "report.html"),
            other => panic!("{other:?}"),
        }
        assert_eq!(entries(&d.downloads_dir), ["report.html"]);
    }

    #[tokio::test]
    async fn a_truncated_body_is_a_failed_transfer_and_leaves_nothing() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nContent-Length: 100\r\n\r\n%PDF".to_vec();
        let (port, _server) = http_server(response, Duration::ZERO).await;
        let origin = format!("http://127.0.0.1:{port}");
        let d = dest("truncated");
        let limiter = Arc::new(DownloadLimiter::new());
        let (_keep, cancel) = never_cancelled();
        let settled =
            run(refetch(&format!("{origin}/a.pdf")), transfer(&limiter, &d), policy_for(&origin), plain_tls(), cancel)
                .await;
        assert_eq!(settled, Settled::Refused(reason::TRANSFER_FAILED));
        assert!(entries(&d.downloads_dir).is_empty(), "placeholder removed");
        assert!(entries(&d.staging_root).is_empty(), "staging removed");
        assert_eq!(limiter.in_flight(), 0);
    }

    #[tokio::test]
    async fn closing_the_window_cancels_a_stalled_transfer() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nContent-Length: 1000\r\n\r\n%PDF".to_vec();
        let (port, _server) = http_server(response, Duration::from_secs(30)).await;
        let origin = format!("http://127.0.0.1:{port}");
        let d = dest("cancel");
        let limiter = Arc::new(DownloadLimiter::new());
        let (tx, cancel) = watch::channel(false);
        let task = tokio::spawn(run(
            refetch(&format!("{origin}/a.pdf")),
            transfer(&limiter, &d),
            policy_for(&origin),
            plain_tls(),
            cancel,
        ));
        tokio::time::sleep(Duration::from_millis(300)).await;
        // The bar's teardown drops the sender.
        drop(tx);
        let settled = tokio::time::timeout(Duration::from_secs(5), task).await.expect("cancelled promptly").unwrap();
        assert_eq!(settled, Settled::Refused(reason::TRANSFER_FAILED));
        assert!(entries(&d.downloads_dir).is_empty());
        assert!(entries(&d.staging_root).is_empty());
        assert_eq!(limiter.in_flight(), 0);
    }

    #[tokio::test]
    async fn an_unreachable_origin_is_a_failed_transfer() {
        // Bound then dropped: nothing listens on the port any more.
        let port = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
        let origin = format!("http://127.0.0.1:{port}");
        let d = dest("refused");
        let limiter = Arc::new(DownloadLimiter::new());
        let (_keep, cancel) = never_cancelled();
        let settled =
            run(refetch(&format!("{origin}/a.pdf")), transfer(&limiter, &d), policy_for(&origin), plain_tls(), cancel)
                .await;
        assert_eq!(settled, Settled::Refused(reason::TRANSFER_FAILED));
        assert!(entries(&d.downloads_dir).is_empty());
    }

    // ── TLS ──

    struct Ca {
        params: CertificateParams,
        key: KeyPair,
        der: Vec<u8>,
    }

    fn ca(name: &str) -> Ca {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, name);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let der = params.self_signed(&key).unwrap().der().to_vec();
        Ca { params, key, der }
    }

    /// An HTTPS server for one connection on 127.0.0.1, as `localhost`,
    /// with a leaf signed by `issuer`.
    async fn https_server(issuer: &Ca, response: Vec<u8>) -> (u16, JoinHandle<Option<String>>) {
        let key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .signed_by(&key, &Issuer::from_params(&issuer.params, &issuer.key))
            .unwrap()
            .der()
            .to_vec();
        let config =
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(leaf), CertificateDer::from(issuer.der.clone())],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                )
                .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            // `None`: the client refused the handshake, so no request came.
            let tls = acceptor.accept(tcp).await.ok()?;
            Some(answer(tls, response, Duration::ZERO).await)
        });
        (port, task)
    }

    #[tokio::test]
    async fn https_is_saved_only_from_a_server_the_trust_store_vouches_for() {
        let trusted = ca("Refetch test CA");
        let (port, server) = https_server(&trusted, ok("application/pdf", "", b"%PDF")).await;
        let origin = format!("https://localhost:{port}");
        let d = dest("tls");
        let limiter = Arc::new(DownloadLimiter::new());
        let (_keep, cancel) = never_cancelled();
        let settled = run(
            refetch(&format!("{origin}/a.pdf")),
            transfer(&limiter, &d),
            policy_for(&origin),
            trusting(&[&trusted.der]),
            cancel,
        )
        .await;
        assert!(matches!(settled, Settled::Saved(ref s) if s.bytes == 4), "{settled:?}");
        assert!(server.await.unwrap().is_some());

        // A certificate the trust store does not vouch for: the handshake is
        // refused, so the request (and its cookies) never leaves.
        let stranger = ca("Somebody else's CA");
        let (port, server) = https_server(&stranger, ok("application/pdf", "", b"%PDF")).await;
        let origin = format!("https://localhost:{port}");
        let (_keep, cancel) = never_cancelled();
        let settled = run(
            refetch(&format!("{origin}/a.pdf")),
            transfer(&limiter, &d),
            policy_for(&origin),
            trusting(&[&trusted.der]),
            cancel,
        )
        .await;
        assert_eq!(settled, Settled::Refused(reason::TRANSFER_FAILED));
        assert_eq!(server.await.unwrap(), None, "no request was sent");
        assert_eq!(entries(&d.downloads_dir), ["a.pdf"], "only the first, trusted download");
        assert_eq!(limiter.in_flight(), 0);
    }
}
