//! A minimal HTTP/1.1 client over [`LegacyTlsStream`]: `GET` and `POST`
//! only, one request per connection (`Connection: close`), no redirects,
//! bounded headers and body, a timeout on every phase.

use std::{fmt, io, net::IpAddr, time::Duration};

use http::{header, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version};
use rustls_pki_types::{DnsName, ServerName};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Instant},
};

use crate::{
    error::TlsError,
    handshake::ClientConfig,
    stream::{connect, LegacyTlsStream},
    verify::TrustAnchors,
};

/// Timeouts and size caps of one exchange.
#[derive(Clone, Debug)]
pub struct HttpLimits {
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    /// From the end of the request to the end of the response head.
    pub header_timeout: Duration,
    /// For the whole response body.
    pub body_timeout: Duration,
    pub max_header_bytes: usize,
    pub max_headers: usize,
    pub max_body_bytes: usize,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
            header_timeout: Duration::from_secs(15),
            body_timeout: Duration::from_secs(30),
            max_header_bytes: 64 * 1024,
            max_headers: 100,
            max_body_bytes: 1024 * 1024,
        }
    }
}

/// A failed exchange. Messages never include request or response bodies.
#[derive(Debug)]
#[non_exhaustive]
pub enum HttpError {
    /// The request cannot be sent by this client (scheme, method, URI).
    InvalidRequest(String),
    /// DNS resolution or the TCP connect failed.
    Connect(io::Error),
    ConnectTimeout,
    /// The TLS handshake or record layer failed.
    Tls(TlsError),
    /// The transport failed while sending or receiving HTTP.
    Io(io::Error),
    HeaderTimeout,
    BodyTimeout,
    /// The response is not well-formed HTTP/1.x or uses unsupported framing.
    InvalidResponse(String),
    HeadersTooLarge,
    BodyTooLarge,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpError::InvalidRequest(why) => write!(f, "legacy TLS HTTP client: request refused: {why}"),
            HttpError::Connect(e) => write!(f, "legacy TLS HTTP client: connect failed: {e}"),
            HttpError::ConnectTimeout => f.write_str("legacy TLS HTTP client: connect timed out"),
            HttpError::Tls(e) => write!(f, "{e}"),
            HttpError::Io(e) => write!(f, "legacy TLS HTTP client: transport error: {e}"),
            HttpError::HeaderTimeout => f.write_str("legacy TLS HTTP client: timed out waiting for the response head"),
            HttpError::BodyTimeout => f.write_str("legacy TLS HTTP client: timed out reading the response body"),
            HttpError::InvalidResponse(why) => write!(f, "legacy TLS HTTP client: invalid response: {why}"),
            HttpError::HeadersTooLarge => f.write_str("legacy TLS HTTP client: response head exceeds the size limit"),
            HttpError::BodyTooLarge => f.write_str("legacy TLS HTTP client: response body exceeds the size limit"),
        }
    }
}

impl std::error::Error for HttpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HttpError::Connect(e) | HttpError::Io(e) => Some(e),
            HttpError::Tls(e) => e.source(),
            _ => None,
        }
    }
}

/// A transport error during the exchange: a TLS failure surfaced through
/// `AsyncRead`/`AsyncWrite` comes back out as [`HttpError::Tls`].
fn transport(e: io::Error) -> HttpError {
    if e.get_ref().is_some_and(|inner| inner.is::<TlsError>()) {
        return HttpError::Tls(TlsError::from(e));
    }
    HttpError::Io(e)
}

fn invalid(why: impl Into<String>) -> HttpError {
    HttpError::InvalidResponse(why.into())
}

/// Where a request goes.
struct Target {
    /// Host for DNS / the socket (no brackets around an IPv6 literal).
    connect_host: String,
    port: u16,
    server_name: ServerName<'static>,
    host_header: String,
}

fn target_of(request: &Request<Vec<u8>>) -> Result<Target, HttpError> {
    let uri = request.uri();
    match uri.scheme_str() {
        Some("https") => {}
        Some(other) => {
            return Err(HttpError::InvalidRequest(format!("the legacy TLS client only speaks https, not `{other}`")))
        }
        None => return Err(HttpError::InvalidRequest("the URL has no scheme".into())),
    }
    let authority = uri.authority().ok_or_else(|| HttpError::InvalidRequest("the URL has no host".into()))?;
    if authority.as_str().contains('@') {
        return Err(HttpError::InvalidRequest("credentials in the URL are not supported".into()));
    }
    let host = authority.host();
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let server_name = match bare.parse::<IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::DnsName(
            DnsName::try_from(bare.to_string())
                .map_err(|_| HttpError::InvalidRequest("the URL host is not a valid DNS name".into()))?,
        ),
    };
    let port = authority.port_u16().unwrap_or(443);
    let host_header = if port == 443 { host.to_string() } else { format!("{host}:{port}") };
    Ok(Target { connect_host: bare.to_string(), port, server_name, host_header })
}

/// Headers this client sets itself; a caller's copy is dropped.
fn is_hop_or_framing(name: &HeaderName) -> bool {
    [
        header::HOST,
        header::CONNECTION,
        header::CONTENT_LENGTH,
        header::TRANSFER_ENCODING,
        header::TE,
        header::UPGRADE,
        header::EXPECT,
    ]
    .contains(name)
        || name.as_str() == "keep-alive"
        || name.as_str() == "proxy-connection"
}

fn serialize_request(request: &Request<Vec<u8>>, host_header: &str) -> Result<Vec<u8>, HttpError> {
    let method = request.method();
    if method != Method::GET && method != Method::POST {
        return Err(HttpError::InvalidRequest(format!("method {method} is not supported (GET and POST only)")));
    }
    if method == Method::GET && !request.body().is_empty() {
        return Err(HttpError::InvalidRequest("a GET request with a body".into()));
    }
    let target = request.uri().path_and_query().map(|p| p.as_str()).filter(|p| !p.is_empty()).unwrap_or("/");
    let mut out = Vec::with_capacity(256 + request.body().len());
    out.extend_from_slice(
        format!("{method} {target} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n").as_bytes(),
    );
    for (name, value) in request.headers() {
        if is_hop_or_framing(name) {
            continue;
        }
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if method == Method::POST || !request.body().is_empty() {
        out.extend_from_slice(format!("Content-Length: {}\r\n", request.body().len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(request.body());
    Ok(out)
}

/// Send `request` to its `https` URL over a new legacy TLS connection and
/// return the response. Redirects are returned, not followed.
pub async fn send(
    request: Request<Vec<u8>>,
    trust: &TrustAnchors,
    limits: &HttpLimits,
) -> Result<Response<Vec<u8>>, HttpError> {
    let target = target_of(&request)?;
    let tcp = timeout(limits.connect_timeout, TcpStream::connect((target.connect_host.as_str(), target.port)))
        .await
        .map_err(|_| HttpError::ConnectTimeout)?
        .map_err(HttpError::Connect)?;
    let config = ClientConfig { handshake_timeout: limits.handshake_timeout };
    let mut tls = connect(tcp, target.server_name.clone(), trust, &config).await.map_err(HttpError::Tls)?;
    let response = exchange(&mut tls, &request, &target.host_header, limits).await;
    // Best-effort close_notify; the response is complete either way.
    let _ = timeout(Duration::from_millis(500), tls.shutdown()).await;
    response
}

/// One request/response over an established stream.
pub(crate) async fn exchange<IO: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut LegacyTlsStream<IO>,
    request: &Request<Vec<u8>>,
    host_header: &str,
    limits: &HttpLimits,
) -> Result<Response<Vec<u8>>, HttpError> {
    let raw = serialize_request(request, host_header)?;
    timeout(limits.header_timeout, async {
        stream.write_all(&raw).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| HttpError::HeaderTimeout)?
    .map_err(transport)?;

    let mut buf = Vec::new();
    let head = timeout(limits.header_timeout, read_head(stream, &mut buf, limits))
        .await
        .map_err(|_| HttpError::HeaderTimeout)??;
    let body_deadline = Instant::now() + limits.body_timeout;
    let body = match head.framing {
        Framing::Empty => Vec::new(),
        Framing::Length(n) => tokio::time::timeout_at(body_deadline, read_length(stream, buf, n))
            .await
            .map_err(|_| HttpError::BodyTimeout)??,
        Framing::Chunked => tokio::time::timeout_at(body_deadline, read_chunked(stream, buf, limits))
            .await
            .map_err(|_| HttpError::BodyTimeout)??,
        Framing::UntilClose => tokio::time::timeout_at(body_deadline, read_until_close(stream, buf, limits))
            .await
            .map_err(|_| HttpError::BodyTimeout)??,
    };
    let mut builder = Response::builder().status(head.status).version(head.version);
    for (name, value) in head.headers {
        builder = builder.header(name, value);
    }
    builder.body(body).map_err(|e| invalid(e.to_string()))
}

enum Framing {
    Empty,
    Length(usize),
    Chunked,
    UntilClose,
}

struct Head {
    status: StatusCode,
    version: Version,
    headers: Vec<(HeaderName, HeaderValue)>,
    framing: Framing,
}

async fn read_more<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut Vec<u8>) -> Result<usize, HttpError> {
    let mut chunk = [0u8; 8192];
    let n = stream.read(&mut chunk).await.map_err(transport)?;
    buf.extend_from_slice(&chunk[..n]);
    Ok(n)
}

/// Read and parse the response head; `buf` keeps whatever followed it.
async fn read_head<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    limits: &HttpLimits,
) -> Result<Head, HttpError> {
    // 1xx interim responses (other than 101) are skipped, a bounded number of times.
    for _ in 0..5 {
        let (status, version, headers, consumed) = loop {
            let mut slots = vec![httparse::EMPTY_HEADER; limits.max_headers];
            let mut parsed = httparse::Response::new(&mut slots);
            match parsed.parse(buf) {
                Ok(httparse::Status::Complete(consumed)) => {
                    let code = parsed.code.ok_or_else(|| invalid("no status code"))?;
                    let status = StatusCode::from_u16(code).map_err(|_| invalid("bad status code"))?;
                    let version = if parsed.version == Some(0) { Version::HTTP_10 } else { Version::HTTP_11 };
                    let mut headers = Vec::with_capacity(parsed.headers.len());
                    for h in parsed.headers.iter() {
                        let name = HeaderName::from_bytes(h.name.as_bytes()).map_err(|_| invalid("bad header name"))?;
                        let value = HeaderValue::from_bytes(h.value).map_err(|_| invalid("bad header value"))?;
                        headers.push((name, value));
                    }
                    break (status, version, headers, consumed);
                }
                Ok(httparse::Status::Partial) => {}
                Err(httparse::Error::TooManyHeaders) => return Err(HttpError::HeadersTooLarge),
                Err(e) => return Err(invalid(format!("malformed response head: {e}"))),
            }
            if buf.len() > limits.max_header_bytes {
                return Err(HttpError::HeadersTooLarge);
            }
            if read_more(stream, buf).await? == 0 {
                return Err(invalid("connection closed before the response head ended"));
            }
        };
        if consumed > limits.max_header_bytes {
            return Err(HttpError::HeadersTooLarge);
        }
        buf.drain(..consumed);
        if status.is_informational() {
            if status == StatusCode::SWITCHING_PROTOCOLS {
                return Err(invalid("101 Switching Protocols is not supported"));
            }
            continue;
        }
        let framing = framing_of(status, &headers, limits)?;
        return Ok(Head { status, version, headers, framing });
    }
    Err(invalid("too many interim (1xx) responses"))
}

/// RFC 9112 §6.3 message-body length, strictly: `Transfer-Encoding` must be
/// exactly `chunked`, never together with `Content-Length`, and repeated
/// `Content-Length` values must agree.
fn framing_of(
    status: StatusCode,
    headers: &[(HeaderName, HeaderValue)],
    limits: &HttpLimits,
) -> Result<Framing, HttpError> {
    if status == StatusCode::NO_CONTENT || status == StatusCode::NOT_MODIFIED {
        return Ok(Framing::Empty);
    }
    let te: Vec<&HeaderValue> =
        headers.iter().filter(|(n, _)| n == header::TRANSFER_ENCODING).map(|(_, v)| v).collect();
    let cl: Vec<&HeaderValue> = headers.iter().filter(|(n, _)| n == header::CONTENT_LENGTH).map(|(_, v)| v).collect();
    if !te.is_empty() {
        if !cl.is_empty() {
            return Err(invalid("both Transfer-Encoding and Content-Length"));
        }
        let chunked_only =
            te.len() == 1 && te[0].to_str().map(|v| v.trim().eq_ignore_ascii_case("chunked")).unwrap_or(false);
        if !chunked_only {
            return Err(invalid("unsupported Transfer-Encoding (only `chunked`)"));
        }
        return Ok(Framing::Chunked);
    }
    if let Some(first) = cl.first() {
        if cl.iter().any(|v| v.as_bytes() != first.as_bytes()) {
            return Err(invalid("conflicting Content-Length values"));
        }
        let text = first.to_str().map_err(|_| invalid("bad Content-Length"))?.trim();
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid("bad Content-Length"));
        }
        let n: usize = text.parse().map_err(|_| HttpError::BodyTooLarge)?;
        if n > limits.max_body_bytes {
            return Err(HttpError::BodyTooLarge);
        }
        return Ok(Framing::Length(n));
    }
    Ok(Framing::UntilClose)
}

async fn read_length<S: AsyncRead + Unpin>(stream: &mut S, mut buf: Vec<u8>, n: usize) -> Result<Vec<u8>, HttpError> {
    while buf.len() < n {
        if read_more(stream, &mut buf).await? == 0 {
            return Err(invalid("connection closed before the Content-Length body ended"));
        }
    }
    if buf.len() > n {
        return Err(invalid("more data than Content-Length after a Connection: close request"));
    }
    Ok(buf)
}

/// The body up to the peer's `close_notify`. The stream errors on a transport
/// EOF without one, so a truncated body is never returned as complete.
async fn read_until_close<S: AsyncRead + Unpin>(
    stream: &mut S,
    mut buf: Vec<u8>,
    limits: &HttpLimits,
) -> Result<Vec<u8>, HttpError> {
    loop {
        if buf.len() > limits.max_body_bytes {
            return Err(HttpError::BodyTooLarge);
        }
        if read_more(stream, &mut buf).await? == 0 {
            return Ok(buf);
        }
    }
}

async fn read_chunked<S: AsyncRead + Unpin>(
    stream: &mut S,
    mut buf: Vec<u8>,
    limits: &HttpLimits,
) -> Result<Vec<u8>, HttpError> {
    let mut body = Vec::new();
    loop {
        // Chunk size line.
        let (consumed, size) = loop {
            match httparse::parse_chunk_size(&buf) {
                Ok(httparse::Status::Complete((consumed, size))) => break (consumed, size),
                Ok(httparse::Status::Partial) => {
                    if buf.len() > 1024 {
                        return Err(invalid("chunk size line too long"));
                    }
                    if read_more(stream, &mut buf).await? == 0 {
                        return Err(invalid("connection closed inside a chunked body"));
                    }
                }
                Err(_) => return Err(invalid("malformed chunk size")),
            }
        };
        buf.drain(..consumed);
        let size = usize::try_from(size).map_err(|_| HttpError::BodyTooLarge)?;
        if size == 0 {
            break;
        }
        if body.len().saturating_add(size) > limits.max_body_bytes {
            return Err(HttpError::BodyTooLarge);
        }
        while buf.len() < size + 2 {
            if read_more(stream, &mut buf).await? == 0 {
                return Err(invalid("connection closed inside a chunk"));
            }
        }
        if &buf[size..size + 2] != b"\r\n" {
            return Err(invalid("chunk not terminated by CRLF"));
        }
        body.extend_from_slice(&buf[..size]);
        buf.drain(..size + 2);
    }
    // Trailers (ignored), up to the empty line.
    loop {
        if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
            let empty = pos == 0;
            buf.drain(..pos + 2);
            if empty {
                return Ok(body);
            }
            continue;
        }
        if buf.len() > limits.max_header_bytes {
            return Err(HttpError::HeadersTooLarge);
        }
        if read_more(stream, &mut buf).await? == 0 {
            return Err(invalid("connection closed inside the chunked trailer"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: Method, uri: &str, body: &[u8]) -> Request<Vec<u8>> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_LENGTH, "999")
            .header(header::CONNECTION, "keep-alive")
            .body(body.to_vec())
            .unwrap()
    }

    #[test]
    fn targets_are_https_only_and_names_are_typed() {
        let t = target_of(&req(Method::GET, "https://idp.example/.well-known/openid-configuration", b"")).unwrap();
        assert_eq!((t.connect_host.as_str(), t.port, t.host_header.as_str()), ("idp.example", 443, "idp.example"));
        assert!(matches!(t.server_name, ServerName::DnsName(_)));
        let t = target_of(&req(Method::GET, "https://127.0.0.1:8443/x", b"")).unwrap();
        assert_eq!((t.port, t.host_header.as_str()), (8443, "127.0.0.1:8443"));
        assert!(matches!(t.server_name, ServerName::IpAddress(_)));
        let t = target_of(&req(Method::GET, "https://[::1]:9/x", b"")).unwrap();
        assert_eq!(t.connect_host, "::1");
        assert!(matches!(target_of(&req(Method::GET, "http://idp.example/", b"")), Err(HttpError::InvalidRequest(_))));
        assert!(matches!(
            target_of(&req(Method::GET, "https://u:p@idp.example/", b"")),
            Err(HttpError::InvalidRequest(_))
        ));
    }

    #[test]
    fn requests_are_serialized_with_our_framing_only() {
        let raw =
            serialize_request(&req(Method::POST, "https://idp.example/token?x=1", b"a=b"), "idp.example").unwrap();
        let text = String::from_utf8(raw).unwrap();
        assert!(text.starts_with("POST /token?x=1 HTTP/1.1\r\nHost: idp.example\r\nConnection: close\r\n"), "{text}");
        assert!(text.contains("accept: application/json\r\n"));
        assert!(text.ends_with("Content-Length: 3\r\n\r\na=b"));
        assert!(!text.contains("999") && !text.contains("keep-alive"));
        let raw = serialize_request(&req(Method::GET, "https://idp.example", b""), "idp.example").unwrap();
        assert!(String::from_utf8(raw).unwrap().starts_with("GET / HTTP/1.1\r\n"));
        assert!(serialize_request(&req(Method::PUT, "https://idp.example/", b""), "h").is_err());
        assert!(serialize_request(&req(Method::GET, "https://idp.example/", b"x"), "h").is_err());
    }

    fn headers(pairs: &[(&str, &str)]) -> Vec<(HeaderName, HeaderValue)> {
        pairs
            .iter()
            .map(|(n, v)| (HeaderName::from_bytes(n.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap()))
            .collect()
    }

    #[test]
    fn framing_is_strict() {
        let l = HttpLimits::default();
        assert!(matches!(
            framing_of(StatusCode::OK, &headers(&[("content-length", "12")]), &l),
            Ok(Framing::Length(12))
        ));
        assert!(matches!(
            framing_of(StatusCode::OK, &headers(&[("transfer-encoding", "Chunked")]), &l),
            Ok(Framing::Chunked)
        ));
        assert!(matches!(framing_of(StatusCode::OK, &[], &l), Ok(Framing::UntilClose)));
        assert!(matches!(
            framing_of(StatusCode::NO_CONTENT, &headers(&[("content-length", "5")]), &l),
            Ok(Framing::Empty)
        ));
        for bad in [
            vec![("transfer-encoding", "chunked"), ("content-length", "3")],
            vec![("transfer-encoding", "gzip, chunked")],
            vec![("content-length", "3"), ("content-length", "4")],
            vec![("content-length", "-1")],
            vec![("content-length", "+3")],
            vec![("content-length", "")],
        ] {
            assert!(
                matches!(framing_of(StatusCode::OK, &headers(&bad), &l), Err(HttpError::InvalidResponse(_))),
                "{bad:?}"
            );
        }
        assert!(matches!(
            framing_of(StatusCode::OK, &headers(&[("content-length", "2000000")]), &l),
            Err(HttpError::BodyTooLarge)
        ));
        assert!(matches!(
            framing_of(StatusCode::OK, &headers(&[("content-length", "99999999999999999999999")]), &l),
            Err(HttpError::BodyTooLarge)
        ));
    }

    #[tokio::test]
    async fn chunked_bodies_decode_and_are_bounded() {
        let limits = HttpLimits::default();
        let mut empty: &[u8] = b"";
        let body =
            read_chunked(&mut empty, b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nx-trailer: 1\r\n\r\n".to_vec(), &limits)
                .await
                .unwrap();
        assert_eq!(body, b"hello world");
        let mut empty: &[u8] = b"";
        assert!(read_chunked(&mut empty, b"5\r\nhelloXX0\r\n\r\n".to_vec(), &limits).await.is_err());
        let mut empty: &[u8] = b"";
        assert!(read_chunked(&mut empty, b"zz\r\n".to_vec(), &limits).await.is_err());
        let mut empty: &[u8] = b"";
        assert!(read_chunked(&mut empty, b"5\r\nhel".to_vec(), &limits).await.is_err(), "truncated");
        let small = HttpLimits { max_body_bytes: 4, ..HttpLimits::default() };
        let mut empty: &[u8] = b"";
        assert!(matches!(
            read_chunked(&mut empty, b"5\r\nhello\r\n0\r\n\r\n".to_vec(), &small).await,
            Err(HttpError::BodyTooLarge)
        ));
    }

    #[tokio::test]
    async fn heads_are_bounded_and_interim_responses_skipped() {
        let limits = HttpLimits::default();
        let mut buf = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
        let mut empty: &[u8] = b"";
        let head = read_head(&mut empty, &mut buf, &limits).await.unwrap();
        assert_eq!(head.status, StatusCode::OK);
        assert_eq!(buf, b"ok");

        let many: String = (0..150).map(|i| format!("x-{i}: v\r\n")).collect();
        let mut buf = format!("HTTP/1.1 200 OK\r\n{many}\r\n").into_bytes();
        let mut empty: &[u8] = b"";
        assert!(matches!(read_head(&mut empty, &mut buf, &limits).await, Err(HttpError::HeadersTooLarge)));

        let small = HttpLimits { max_header_bytes: 64, ..HttpLimits::default() };
        let mut buf = b"HTTP/1.1 200 OK\r\nx-long: ".to_vec();
        buf.extend(std::iter::repeat_n(b'a', 200));
        let mut empty: &[u8] = b"";
        assert!(matches!(read_head(&mut empty, &mut buf, &small).await, Err(HttpError::HeadersTooLarge)));

        let mut buf = b"HTTP/1.1 101 Switching Protocols\r\n\r\n".to_vec();
        let mut empty: &[u8] = b"";
        assert!(read_head(&mut empty, &mut buf, &limits).await.is_err());
    }
}
