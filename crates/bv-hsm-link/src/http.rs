//! Strict HTTP/1.1 framing for both halves of the link. httparse tokenizes
//! the head; the rules on top are ours: one `Content-Length`, no
//! `Transfer-Encoding` or `Expect`, no pipelining, no bare CR or LF.

use std::{io, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

use crate::{CONNECTOR_API_PATH, CONNECTOR_STATUS_PATH, MAX_API_BODY_BYTES, MIN_API_BODY_BYTES};

/// Largest request or response head accepted, terminator included.
pub(crate) const MAX_HEAD_BYTES: usize = 8 * 1024;
/// Most header fields in one head.
const MAX_HEADERS: usize = 32;
/// Largest response body relayed. A device response is at most a few KiB;
/// the `yubihsm` client itself stops at 64 KiB.
pub(crate) const MAX_RESPONSE_BODY_BYTES: usize = 16 * 1024;
const READ_CHUNK: usize = 4096;
/// How long a connection is drained after an error response, so the client
/// reads that response instead of a reset.
const LINGER: Duration = Duration::from_secs(1);
const LINGER_MAX_BYTES: usize = 64 * 1024;

/// The only two requests the link carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Endpoint {
    Api,
    Status,
}

impl Endpoint {
    pub(crate) fn method(self) -> &'static str {
        match self {
            Endpoint::Api => "POST",
            Endpoint::Status => "GET",
        }
    }

    pub(crate) fn path(self) -> &'static str {
        match self {
            Endpoint::Api => CONNECTOR_API_PATH,
            Endpoint::Status => CONNECTOR_STATUS_PATH,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Request {
    pub(crate) endpoint: Endpoint,
    pub(crate) body: Vec<u8>,
    /// The client sent `Connection: close`.
    pub(crate) close: bool,
}

/// A request refused before anything is forwarded: the status to answer
/// with and an operator-facing reason that never quotes the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rejection {
    pub(crate) status: u16,
    pub(crate) why: &'static str,
}

const fn reject(status: u16, why: &'static str) -> Rejection {
    Rejection { status, why }
}

#[derive(Debug)]
pub(crate) enum ReadError {
    Reject(Rejection),
    Timeout,
    /// The peer closed the connection part-way through a request.
    Truncated,
    Io(io::Error),
}

#[derive(Debug)]
pub(crate) struct Response {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
    /// The connection cannot carry another request.
    pub(crate) close: bool,
}

#[derive(Debug)]
pub(crate) enum ResponseError {
    Io(io::Error),
    Truncated,
    Malformed(&'static str),
    TooLarge,
}

impl std::fmt::Display for ResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseError::Io(e) => write!(f, "read failed: {e}"),
            ResponseError::Truncated => f.write_str("connection closed before the response was complete"),
            ResponseError::Malformed(why) => write!(f, "malformed response: {why}"),
            ResponseError::TooLarge => write!(f, "response body over {MAX_RESPONSE_BODY_BYTES} bytes"),
        }
    }
}

/// How a response body may be delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyFraming {
    /// `Content-Length` only (a keep-alive connection).
    ContentLength,
    /// `Content-Length`, or the end of the connection when it is absent.
    ContentLengthOrClose,
}

/// The HTTP version a request is written with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Version {
    Http10,
    Http11,
}

/// A byte stream plus the bytes read from it but not yet consumed.
pub(crate) struct HttpConn<S> {
    stream: S,
    buf: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> HttpConn<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self { stream, buf: Vec::with_capacity(READ_CHUNK) }
    }

    pub(crate) fn get_ref(&self) -> &S {
        &self.stream
    }

    pub(crate) fn has_buffered(&self) -> bool {
        !self.buf.is_empty()
    }

    /// Reads whatever is available; `Ok(0)` is end of stream. Cancel-safe:
    /// a dropped call has read nothing.
    pub(crate) async fn fill(&mut self) -> io::Result<usize> {
        let mut chunk = [0u8; READ_CHUNK];
        let n = self.stream.read(&mut chunk).await?;
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(n)
    }

    pub(crate) async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stream.write_all(bytes).await?;
        self.stream.flush().await
    }

    /// Sends TLS `close_notify` (on a TLS stream) and closes the write side.
    pub(crate) async fn shutdown(&mut self) {
        let _ = self.stream.shutdown().await;
    }

    /// Writes an error response, then closes and drains the connection for a
    /// moment so the peer reads the response rather than a reset.
    pub(crate) async fn reject_and_close(&mut self, status: u16) {
        let _ = timeout(LINGER, async {
            let _ = self.write_all(&encode_response(status, &[], true)).await;
            let _ = self.stream.shutdown().await;
            let mut sink = [0u8; READ_CHUNK];
            let mut drained = 0usize;
            while drained < LINGER_MAX_BYTES {
                match self.stream.read(&mut sink).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => drained += n,
                }
            }
        })
        .await;
    }

    /// Reads one complete request within `limit`.
    pub(crate) async fn read_request(&mut self, limit: Duration) -> Result<Request, ReadError> {
        match timeout(limit, self.read_request_inner()).await {
            Ok(result) => result,
            Err(_) => Err(ReadError::Timeout),
        }
    }

    async fn read_request_inner(&mut self) -> Result<Request, ReadError> {
        let head_len = self.read_head().await.map_err(|e| match e {
            HeadError::TooLarge => ReadError::Reject(reject(431, "request head too large")),
            HeadError::Truncated => ReadError::Truncated,
            HeadError::Io(e) => ReadError::Io(e),
        })?;
        let head = parse_request_head(&self.buf[..head_len]).map_err(ReadError::Reject)?;
        let total = head_len + head.content_length;
        while self.buf.len() < total {
            if self.fill().await.map_err(ReadError::Io)? == 0 {
                return Err(ReadError::Truncated);
            }
        }
        // Bytes past the body are a second request sent before the first was
        // answered. Refuse rather than queue: one request in flight, always.
        if self.buf.len() > total {
            return Err(ReadError::Reject(reject(400, "pipelined request")));
        }
        let body = self.buf[head_len..total].to_vec();
        self.buf.clear();
        Ok(Request { endpoint: head.endpoint, body, close: head.close })
    }

    /// Reads one response. Bytes after a `Content-Length` body are an error:
    /// nothing was asked for them.
    pub(crate) async fn read_response(&mut self, framing: BodyFraming) -> Result<Response, ResponseError> {
        let head_len = self.read_head().await.map_err(|e| match e {
            HeadError::TooLarge => ResponseError::Malformed("response head too large"),
            HeadError::Truncated => ResponseError::Truncated,
            HeadError::Io(e) => ResponseError::Io(e),
        })?;
        let head = parse_response_head(&self.buf[..head_len]).map_err(ResponseError::Malformed)?;
        let (total, close) = match (head.content_length, framing) {
            (Some(length), _) => {
                if length > MAX_RESPONSE_BODY_BYTES {
                    return Err(ResponseError::TooLarge);
                }
                let total = head_len + length;
                while self.buf.len() < total {
                    if self.fill().await.map_err(ResponseError::Io)? == 0 {
                        return Err(ResponseError::Truncated);
                    }
                }
                if self.buf.len() > total {
                    return Err(ResponseError::Malformed("unexpected bytes after the response body"));
                }
                (total, head.close)
            }
            (None, BodyFraming::ContentLength) => return Err(ResponseError::Malformed("no Content-Length")),
            (None, BodyFraming::ContentLengthOrClose) => {
                loop {
                    if self.buf.len() - head_len > MAX_RESPONSE_BODY_BYTES {
                        return Err(ResponseError::TooLarge);
                    }
                    if self.fill().await.map_err(ResponseError::Io)? == 0 {
                        break;
                    }
                }
                (self.buf.len(), true)
            }
        };
        let body = self.buf[head_len..total].to_vec();
        self.buf.clear();
        Ok(Response { status: head.status, body, close })
    }

    /// Fills the buffer until it holds a complete head; returns its length.
    async fn read_head(&mut self) -> Result<usize, HeadError> {
        loop {
            if let Some(end) = find_head_end(&self.buf) {
                return if end > MAX_HEAD_BYTES { Err(HeadError::TooLarge) } else { Ok(end) };
            }
            if self.buf.len() >= MAX_HEAD_BYTES {
                return Err(HeadError::TooLarge);
            }
            if self.fill().await.map_err(HeadError::Io)? == 0 {
                return Err(HeadError::Truncated);
            }
        }
    }
}

enum HeadError {
    TooLarge,
    Truncated,
    Io(io::Error),
}

/// Length of the head including its blank line, if the terminator is present.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    let window = &buf[..buf.len().min(MAX_HEAD_BYTES + 4)];
    window.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Every LF must follow a CR and every CR must precede an LF. httparse
/// accepts bare LF; a parser that disagrees about line ends is a smuggling
/// primitive, so the link accepts only one reading.
fn check_line_endings(head: &[u8]) -> Result<(), &'static str> {
    for (i, &b) in head.iter().enumerate() {
        if b == b'\n' && (i == 0 || head[i - 1] != b'\r') {
            return Err("bare LF in head");
        }
        if b == b'\r' && head.get(i + 1) != Some(&b'\n') {
            return Err("bare CR in head");
        }
    }
    Ok(())
}

fn headers_named<'a>(headers: &'a [httparse::Header<'a>], name: &str) -> Vec<&'a [u8]> {
    headers.iter().filter(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value).collect()
}

fn trim_ows(value: &[u8]) -> &[u8] {
    let start = value.iter().position(|b| !matches!(b, b' ' | b'\t')).unwrap_or(value.len());
    let end = value.iter().rposition(|b| !matches!(b, b' ' | b'\t')).map_or(start, |p| p + 1);
    &value[start..end]
}

/// `1*DIGIT` and nothing else: no sign, no list, no whitespace inside.
fn parse_content_length(value: &[u8]) -> Option<usize> {
    let digits = trim_ows(value);
    if digits.is_empty() || digits.len() > 10 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse::<u64>().ok().and_then(|n| usize::try_from(n).ok())
}

fn content_length(headers: &[httparse::Header<'_>]) -> Result<Option<usize>, &'static str> {
    match headers_named(headers, "Content-Length").as_slice() {
        [] => Ok(None),
        [one] => parse_content_length(one).map(Some).ok_or("invalid Content-Length"),
        _ => Err("more than one Content-Length"),
    }
}

fn has_token(headers: &[httparse::Header<'_>], name: &str, token: &str) -> bool {
    headers_named(headers, name)
        .iter()
        .flat_map(|v| v.split(|b| *b == b','))
        .any(|t| trim_ows(t).eq_ignore_ascii_case(token.as_bytes()))
}

#[derive(Debug, PartialEq, Eq)]
struct RequestHead {
    endpoint: Endpoint,
    content_length: usize,
    close: bool,
}

fn parse_request_head(head: &[u8]) -> Result<RequestHead, Rejection> {
    check_line_endings(head).map_err(|why| reject(400, why))?;
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(head) {
        Ok(httparse::Status::Complete(n)) if n == head.len() => {}
        Ok(_) => return Err(reject(400, "incomplete request head")),
        Err(httparse::Error::TooManyHeaders) => return Err(reject(431, "too many header fields")),
        Err(_) => return Err(reject(400, "malformed request head")),
    }
    if req.version != Some(1) {
        return Err(reject(505, "only HTTP/1.1 is accepted"));
    }
    let endpoint = match (req.method, req.path) {
        (Some("POST"), Some(CONNECTOR_API_PATH)) => Endpoint::Api,
        (Some("GET"), Some(CONNECTOR_STATUS_PATH)) => Endpoint::Status,
        (_, Some(CONNECTOR_API_PATH | CONNECTOR_STATUS_PATH)) => return Err(reject(405, "method not allowed")),
        _ => return Err(reject(404, "unknown path")),
    };
    let headers: &[httparse::Header<'_>] = req.headers;
    if !headers_named(headers, "Transfer-Encoding").is_empty() {
        return Err(reject(501, "Transfer-Encoding is not supported"));
    }
    if !headers_named(headers, "Expect").is_empty() {
        return Err(reject(417, "Expect is not supported"));
    }
    match headers_named(headers, "Host").as_slice() {
        [host] if !trim_ows(host).is_empty() => {}
        _ => return Err(reject(400, "exactly one non-empty Host is required")),
    }
    let length = content_length(headers).map_err(|why| reject(400, why))?;
    let content_length = match endpoint {
        Endpoint::Api => {
            let n = length.ok_or(reject(411, "Content-Length is required"))?;
            if n < MIN_API_BODY_BYTES {
                return Err(reject(400, "body shorter than a connector command"));
            }
            if n > MAX_API_BODY_BYTES {
                return Err(reject(413, "body longer than a connector command"));
            }
            n
        }
        Endpoint::Status => match length {
            None | Some(0) => 0,
            Some(_) => return Err(reject(400, "status request with a body")),
        },
    };
    Ok(RequestHead { endpoint, content_length, close: has_token(headers, "Connection", "close") })
}

#[derive(Debug, PartialEq, Eq)]
struct ResponseHead {
    status: u16,
    content_length: Option<usize>,
    close: bool,
}

fn parse_response_head(head: &[u8]) -> Result<ResponseHead, &'static str> {
    check_line_endings(head)?;
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(head) {
        Ok(httparse::Status::Complete(n)) if n == head.len() => {}
        Ok(_) => return Err("incomplete response head"),
        Err(_) => return Err("unparseable response head"),
    }
    let status = resp.code.ok_or("no status code")?;
    if !(200..=599).contains(&status) {
        return Err("unexpected status code");
    }
    let http10 = resp.version == Some(0);
    let headers: &[httparse::Header<'_>] = resp.headers;
    if !headers_named(headers, "Transfer-Encoding").is_empty() {
        return Err("Transfer-Encoding is not supported");
    }
    let content_length = content_length(headers)?;
    Ok(ResponseHead { status, content_length, close: http10 || has_token(headers, "Connection", "close") })
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Content Too Large",
        417 => "Expectation Failed",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "Unknown",
    }
}

/// The whole response in one buffer, written with one call. `yubihsm` 0.42's
/// reader assumes a response arrives in a single read, and its status-line
/// and `Content-Length: ` matches are exact, so this format is load-bearing.
pub(crate) fn encode_response(status: u16, body: &[u8], close: bool) -> Vec<u8> {
    let mut head = format!("HTTP/1.1 {status} {}\r\nContent-Length: {}\r\n", reason(status), body.len());
    if close {
        head.push_str("Connection: close\r\n");
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

/// A fresh request carrying only `Host` and the framing: no header a client
/// sent is ever passed on. `host` comes from a parsed URL, so it holds no CR/LF.
pub(crate) fn encode_request(endpoint: Endpoint, host: &str, body: &[u8], version: Version) -> Vec<u8> {
    let version = match version {
        Version::Http10 => "HTTP/1.0",
        Version::Http11 => "HTTP/1.1",
    };
    let mut head = format!("{} {} {version}\r\nHost: {host}\r\n", endpoint.method(), endpoint.path());
    if endpoint == Endpoint::Api {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api(extra_headers: &str, body_len: usize) -> Vec<u8> {
        format!("POST /connector/api HTTP/1.1\r\nHost: h:1\r\n{extra_headers}Content-Length: {body_len}\r\n\r\n")
            .into_bytes()
    }

    fn status_of(head: &[u8]) -> u16 {
        parse_request_head(head).map(|_| 200).unwrap_or_else(|r| r.status)
    }

    #[test]
    fn accepts_the_two_connector_requests() {
        let head = parse_request_head(&api("User-Agent: yubihsm.rs 0.42.1\r\n", 10)).unwrap();
        assert_eq!(head, RequestHead { endpoint: Endpoint::Api, content_length: 10, close: false });

        let head =
            parse_request_head(b"GET /connector/status HTTP/1.1\r\nHost: h\r\nConnection: Close\r\n\r\n").unwrap();
        assert_eq!(head, RequestHead { endpoint: Endpoint::Status, content_length: 0, close: true });
    }

    #[test]
    fn enforces_the_connector_body_bounds() {
        assert_eq!(status_of(&api("", 2)), 400);
        assert_eq!(status_of(&api("", 3)), 200);
        assert_eq!(status_of(&api("", 3139)), 200);
        assert_eq!(status_of(&api("", 3140)), 413);
        assert_eq!(status_of(b"POST /connector/api HTTP/1.1\r\nHost: h\r\n\r\n"), 411);
        assert_eq!(status_of(b"GET /connector/status HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n"), 200);
        assert_eq!(status_of(b"GET /connector/status HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\n"), 400);
    }

    #[test]
    fn refuses_smuggling_and_malformed_heads() {
        let cases: &[(&[u8], u16)] = &[
            (b"POST /connector/api HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n", 501),
            (
                b"POST /connector/api HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
                501,
            ),
            (b"POST /connector/api HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n", 400),
            (b"POST /connector/api HTTP/1.1\r\nHost: h\r\nContent-Length: +5\r\n\r\n", 400),
            (b"POST /connector/api HTTP/1.1\r\nHost: h\r\nContent-Length: 5, 5\r\n\r\n", 400),
            (b"POST /connector/api HTTP/1.1\r\nHost: h\r\nContent-Length: 0x5\r\n\r\n", 400),
            (b"POST /connector/api HTTP/1.1\r\nHost: h\r\nContent-Length: 99999999999\r\n\r\n", 400),
            (b"POST /connector/api HTTP/1.1\r\nHost: h\nContent-Length: 5\r\n\r\n", 400),
            (b"POST /connector/api HTTP/1.1\r\nHost: h\rX: y\r\nContent-Length: 5\r\n\r\n", 400),
            (b"POST /connector/api HTTP/1.1\r\nContent-Length: 5\r\n\r\n", 400),
            (b"POST /connector/api HTTP/1.1\r\nHost: a\r\nHost: b\r\nContent-Length: 5\r\n\r\n", 400),
            (b"POST /connector/api HTTP/1.1\r\nHost: \r\nContent-Length: 5\r\n\r\n", 400),
            (b"POST /connector/api HTTP/1.0\r\nHost: h\r\nContent-Length: 5\r\n\r\n", 505),
            (b"POST /connector/api HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n", 417),
            (b"GET /connector/api HTTP/1.1\r\nHost: h\r\n\r\n", 405),
            (b"POST /connector/status HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n", 405),
            (b"POST /connector/api?x=1 HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n", 404),
            (b"POST http://h/connector/api HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n", 404),
            (b"POST /connector/../connector/api HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n", 404),
            (b"POST  /connector/api HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n", 400),
            (b"POST /connector/api HTTP/1.1\r\nHost: h\r\n Folded: x\r\nContent-Length: 5\r\n\r\n", 400),
            (b"POST /connector/api HTTP/1.1\r\nHost h\r\nContent-Length: 5\r\n\r\n", 400),
        ];
        for (head, want) in cases {
            assert_eq!(status_of(head), *want, "{}", String::from_utf8_lossy(head).escape_debug());
        }
    }

    #[test]
    fn too_many_headers_is_431() {
        let mut head = String::from("POST /connector/api HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n");
        for i in 0..MAX_HEADERS {
            head.push_str(&format!("X-{i}: v\r\n"));
        }
        head.push_str("\r\n");
        assert_eq!(status_of(head.as_bytes()), 431);
    }

    #[test]
    fn parses_responses_strictly() {
        let ok = parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n").unwrap();
        assert_eq!(ok, ResponseHead { status: 200, content_length: Some(4), close: false });
        let old = parse_response_head(b"HTTP/1.0 200 OK\r\nContent-Type: x\r\n\r\n").unwrap();
        assert_eq!(old, ResponseHead { status: 200, content_length: None, close: true });
        assert!(parse_response_head(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").is_err());
        assert!(parse_response_head(b"HTTP/1.1 100 Continue\r\n\r\n").is_err());
        assert!(parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n").is_err());
        assert!(parse_response_head(b"HTTP/1.1 200 OK\nContent-Length: 1\r\n\r\n").is_err());
    }

    #[test]
    fn encodes_the_exact_format_the_yubihsm_client_reads() {
        assert_eq!(encode_response(200, b"abc", false), b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc".to_vec());
        assert_eq!(
            encode_response(502, b"", true),
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
        );
        assert_eq!(
            encode_request(Endpoint::Api, "127.0.0.1:12345", b"\x01\x00\x00", Version::Http10),
            b"POST /connector/api HTTP/1.0\r\nHost: 127.0.0.1:12345\r\nContent-Length: 3\r\n\r\n\x01\x00\x00".to_vec()
        );
        assert_eq!(
            encode_request(Endpoint::Status, "gw:8250", b"", Version::Http11),
            b"GET /connector/status HTTP/1.1\r\nHost: gw:8250\r\n\r\n".to_vec()
        );
    }

    async fn read_one(bytes: &[u8]) -> Result<Request, ReadError> {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        client.write_all(bytes).await.unwrap();
        drop(client);
        HttpConn::new(server).read_request(Duration::from_secs(2)).await
    }

    #[tokio::test]
    async fn reads_a_body_and_refuses_a_pipelined_request() {
        let mut one = api("", 4);
        one.extend_from_slice(b"\x00\x01\x02\x03");
        let request = read_one(&one).await.unwrap();
        assert_eq!(request.body, b"\x00\x01\x02\x03");

        let mut two = one.clone();
        two.extend_from_slice(&one);
        match read_one(&two).await {
            Err(ReadError::Reject(r)) => assert_eq!(r.status, 400),
            other => panic!("pipelined request accepted: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_short_body_or_an_endless_head_is_not_a_request() {
        let mut short = api("", 10);
        short.extend_from_slice(b"abc");
        assert!(matches!(read_one(&short).await, Err(ReadError::Truncated)));

        let endless = vec![b'a'; MAX_HEAD_BYTES + 10];
        match read_one(&endless).await {
            Err(ReadError::Reject(r)) => assert_eq!(r.status, 431),
            other => panic!("oversize head accepted: {other:?}"),
        }
    }

    async fn response_of(bytes: &[u8], framing: BodyFraming) -> Result<Response, ResponseError> {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        client.write_all(bytes).await.unwrap();
        drop(client);
        HttpConn::new(server).read_response(framing).await
    }

    #[tokio::test]
    async fn reads_length_and_close_delimited_responses() {
        let r =
            response_of(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", BodyFraming::ContentLength).await.unwrap();
        assert_eq!((r.status, r.body.as_slice(), r.close), (200, &b"ok"[..], false));

        let r = response_of(b"HTTP/1.0 200 OK\r\n\r\nuntil-close", BodyFraming::ContentLengthOrClose).await.unwrap();
        assert_eq!((r.body.as_slice(), r.close), (&b"until-close"[..], true));

        let r = response_of(b"HTTP/1.1 200 OK\r\n\r\nuntil-close", BodyFraming::ContentLength).await;
        assert!(matches!(r, Err(ResponseError::Malformed(_))));

        let r = response_of(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokEXTRA", BodyFraming::ContentLength).await;
        assert!(matches!(r, Err(ResponseError::Malformed(_))));

        let big = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", MAX_RESPONSE_BODY_BYTES + 1);
        let r = response_of(big.as_bytes(), BodyFraming::ContentLength).await;
        assert!(matches!(r, Err(ResponseError::TooLarge)));
    }
}
