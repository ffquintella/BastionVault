//! Trusted-proxy / `X-Forwarded-For` resolution.
//!
//! Wave 2 / Phase 1.5 of the Packaging & Distribution roadmap.
//!
//! Behaviour (also documented in
//! `features/packaging-podman-server.md`, "Client IP visibility"):
//!
//! - The **socket-level peer** is always recorded. That's what
//!   `actix-web`'s `getpeername` saw — the proxy's IP if there is one,
//!   the client's IP otherwise.
//! - If `BASTIONVAULT_TRUSTED_PROXIES` is set to a CIDR list, the
//!   request's `X-Forwarded-For` is walked **right-to-left** and the
//!   first hop **not** in the trusted set becomes the derived client
//!   IP. This stops at the boundary between the trusted infrastructure
//!   and the public client; an attacker spoofing `X-Forwarded-For`
//!   from outside cannot impersonate an internal IP because the walk
//!   stops at the first untrusted hop and uses *that* address.
//! - With no trusted proxies configured (the default), the derived
//!   client IP equals the socket peer — bare-metal, direct-exposure
//!   behaviour.
//!
//! `Forwarded` (RFC 7239) is supported in addition to `X-Forwarded-For`.
//! When both are present, `Forwarded` takes precedence, since RFC 7239
//! is the standardised form.
//!
//! Importantly: **both** the socket peer and the derived client IP
//! are recorded on every audit entry. We never collapse them — a
//! reviewer must always be able to distinguish "the socket said X,
//! and the proxy attested Y" from "the socket said X and that's all
//! we know."

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use actix_web::HttpRequest;
use ipnetwork::IpNetwork;

/// CIDR list whose `X-Forwarded-For` / `Forwarded` headers may be
/// promoted to the canonical client IP. Constructed once at startup
/// from `BASTIONVAULT_TRUSTED_PROXIES` and cloned cheaply per request.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies {
    cidrs: Vec<IpNetwork>,
}

impl TrustedProxies {
    /// Parse a comma-separated CIDR list. Whitespace around entries is
    /// ignored; empty entries are skipped. Returns the parsed list and
    /// the indices of any entries that failed to parse, so the caller
    /// can log them at startup without aborting the server.
    pub fn parse(input: &str) -> (Self, Vec<String>) {
        let mut cidrs = Vec::new();
        let mut bad = Vec::new();
        for raw in input.split(',') {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            match IpNetwork::from_str(trimmed) {
                Ok(net) => cidrs.push(net),
                Err(_) => bad.push(trimmed.to_string()),
            }
        }
        (Self { cidrs }, bad)
    }

    /// Read `BASTIONVAULT_TRUSTED_PROXIES` from the environment.
    pub fn from_env() -> (Self, Vec<String>) {
        match std::env::var("BASTIONVAULT_TRUSTED_PROXIES") {
            Ok(v) => Self::parse(&v),
            Err(_) => (Self::default(), Vec::new()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty()
    }

    fn contains(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|c| c.contains(ip))
    }
}

/// Both views of "where this request came from."
///
/// `socket` is what the kernel saw on `accept()`. `derived` is the
/// origin client IP after walking the trusted-proxy chain — it equals
/// `socket` when no proxies are trusted or no forwarded headers are
/// present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIp {
    pub socket: SocketAddr,
    pub derived: IpAddr,
}

impl ClientIp {
    /// Resolve the client IP for an incoming request given the
    /// configured trusted-proxy set. Pure: the only inputs are the
    /// socket peer, the request headers, and the trusted-proxy list.
    pub fn resolve(socket: SocketAddr, req: &HttpRequest, trusted: &TrustedProxies) -> Self {
        let derived = if trusted.is_empty() {
            socket.ip()
        } else if let Some(ip) = derive_from_forwarded(req, trusted, socket.ip()) {
            ip
        } else if let Some(ip) = derive_from_xff(req, trusted, socket.ip()) {
            ip
        } else {
            socket.ip()
        };
        Self { socket, derived }
    }
}

/// Walk an X-Forwarded-For chain right-to-left, returning the first
/// hop *not* in `trusted`. The walk starts from the socket peer (the
/// rightmost hop, conceptually): if the socket peer itself is not in
/// the trusted set, the chain is irrelevant and we return `None` (the
/// caller will fall back to the socket peer). Otherwise we walk the
/// header values right-to-left, stopping at the first untrusted hop
/// or returning the leftmost hop if every recorded hop is trusted.
fn derive_from_xff(
    req: &HttpRequest,
    trusted: &TrustedProxies,
    socket_ip: IpAddr,
) -> Option<IpAddr> {
    if !trusted.contains(socket_ip) {
        return None;
    }

    // X-Forwarded-For may appear multiple times; flatten in order.
    let mut chain: Vec<IpAddr> = Vec::new();
    for hv in req.headers().get_all(actix_web::http::header::HeaderName::from_static(
        "x-forwarded-for",
    )) {
        let Ok(s) = hv.to_str() else { continue };
        for raw in s.split(',') {
            if let Ok(ip) = parse_ip_token(raw.trim()) {
                chain.push(ip);
            }
        }
    }
    if chain.is_empty() {
        return None;
    }

    // Right-to-left scan. Each entry was added by the proxy that
    // received the request from the previous hop; the rightmost is the
    // closest to us (added by our direct upstream). We trust an entry
    // only if the proxy that wrote it is itself trusted.
    for ip in chain.iter().rev() {
        if !trusted.contains(*ip) {
            return Some(*ip);
        }
    }
    // All hops trusted — the leftmost is the original client.
    chain.first().copied()
}

/// RFC 7239 `Forwarded:` header. The "for=" parameter is what we want;
/// values are quoted-pair-tolerant strings that may include port and
/// brackets for IPv6.
fn derive_from_forwarded(
    req: &HttpRequest,
    trusted: &TrustedProxies,
    socket_ip: IpAddr,
) -> Option<IpAddr> {
    if !trusted.contains(socket_ip) {
        return None;
    }
    let mut chain: Vec<IpAddr> = Vec::new();
    for hv in req
        .headers()
        .get_all(actix_web::http::header::HeaderName::from_static("forwarded"))
    {
        let Ok(s) = hv.to_str() else { continue };
        for elem in s.split(',') {
            for kv in elem.split(';') {
                let kv = kv.trim();
                let lower = kv.to_ascii_lowercase();
                if let Some(rest) = lower.strip_prefix("for=") {
                    // Strip optional surrounding quotes and brackets.
                    let stripped = rest.trim_matches('"').trim_start_matches('[');
                    let stripped = stripped.split(']').next().unwrap_or(stripped);
                    if let Ok(ip) = parse_ip_token(stripped) {
                        chain.push(ip);
                    }
                }
            }
        }
    }
    if chain.is_empty() {
        return None;
    }
    for ip in chain.iter().rev() {
        if !trusted.contains(*ip) {
            return Some(*ip);
        }
    }
    chain.first().copied()
}

/// Parse an IP-or-`IP:port`-or-`[IPv6]:port` token into a bare IpAddr.
fn parse_ip_token(s: &str) -> Result<IpAddr, ()> {
    let s = s.trim();
    if s.is_empty() {
        return Err(());
    }
    // Try as a SocketAddr first (covers `1.2.3.4:5678` and `[::1]:5678`).
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(sa.ip());
    }
    // Strip brackets if any (`[::1]`).
    let s = s.trim_start_matches('[').trim_end_matches(']');
    s.parse::<IpAddr>().map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn sock(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parse_skips_blanks_and_collects_bad() {
        let (tp, bad) = TrustedProxies::parse("10.0.0.0/8, ,not-a-cidr,2001:db8::/32");
        assert_eq!(tp.cidrs.len(), 2);
        assert_eq!(bad, vec!["not-a-cidr".to_string()]);
    }

    #[test]
    fn empty_trusted_returns_socket_peer() {
        let trusted = TrustedProxies::default();
        let req = TestRequest::default()
            .insert_header(("x-forwarded-for", "203.0.113.7"))
            .to_http_request();
        let cip = ClientIp::resolve(sock("10.0.0.1:443"), &req, &trusted);
        assert_eq!(cip.derived, ip("10.0.0.1"));
    }

    #[test]
    fn xff_promoted_when_socket_is_trusted() {
        let (trusted, _) = TrustedProxies::parse("10.0.0.0/8");
        let req = TestRequest::default()
            .insert_header(("x-forwarded-for", "203.0.113.7"))
            .to_http_request();
        let cip = ClientIp::resolve(sock("10.0.0.1:443"), &req, &trusted);
        assert_eq!(cip.derived, ip("203.0.113.7"));
    }

    #[test]
    fn xff_not_promoted_when_socket_is_untrusted() {
        // External attacker connects directly and forges an XFF header.
        // The socket peer is NOT in the trusted set, so the header
        // is ignored entirely.
        let (trusted, _) = TrustedProxies::parse("10.0.0.0/8");
        let req = TestRequest::default()
            .insert_header(("x-forwarded-for", "10.0.0.99"))
            .to_http_request();
        let cip = ClientIp::resolve(sock("198.51.100.7:443"), &req, &trusted);
        assert_eq!(cip.derived, ip("198.51.100.7"));
    }

    #[test]
    fn xff_walk_stops_at_first_untrusted_hop() {
        // 203.0.113.7 (real client) → 10.0.0.5 (edge) → 10.0.0.1 (us).
        // We trust 10/8; the rightmost untrusted hop is 203.0.113.7.
        let (trusted, _) = TrustedProxies::parse("10.0.0.0/8");
        let req = TestRequest::default()
            .insert_header(("x-forwarded-for", "203.0.113.7, 10.0.0.5"))
            .to_http_request();
        let cip = ClientIp::resolve(sock("10.0.0.1:443"), &req, &trusted);
        assert_eq!(cip.derived, ip("203.0.113.7"));
    }

    #[test]
    fn xff_walk_handles_attacker_injected_internal_ip() {
        // Attacker at 198.51.100.7 (untrusted) forges an XFF header
        // claiming "192.0.2.1, 10.0.0.99". Their request hits our edge
        // proxy 10.0.0.5, which appends the attacker's real address.
        // Final XFF the server sees: "192.0.2.1, 10.0.0.99, 198.51.100.7".
        // Walking right-to-left: 198.51.100.7 is the first untrusted
        // hop — that's the derived client IP, NOT the spoofed
        // "192.0.2.1" prefix.
        let (trusted, _) = TrustedProxies::parse("10.0.0.0/8");
        let req = TestRequest::default()
            .insert_header((
                "x-forwarded-for",
                "192.0.2.1, 10.0.0.99, 198.51.100.7",
            ))
            .to_http_request();
        let cip = ClientIp::resolve(sock("10.0.0.5:443"), &req, &trusted);
        assert_eq!(cip.derived, ip("198.51.100.7"));
    }

    #[test]
    fn rfc7239_forwarded_takes_precedence_over_xff() {
        let (trusted, _) = TrustedProxies::parse("10.0.0.0/8");
        let req = TestRequest::default()
            .insert_header(("forwarded", "for=203.0.113.7"))
            .insert_header(("x-forwarded-for", "198.51.100.7"))
            .to_http_request();
        let cip = ClientIp::resolve(sock("10.0.0.1:443"), &req, &trusted);
        assert_eq!(cip.derived, ip("203.0.113.7"));
    }

    #[test]
    fn rfc7239_handles_ipv6_brackets() {
        let (trusted, _) = TrustedProxies::parse("fc00::/7");
        let req = TestRequest::default()
            .insert_header(("forwarded", "for=\"[2001:db8::1]:443\""))
            .to_http_request();
        let cip = ClientIp::resolve(sock("[fd00::1]:443"), &req, &trusted);
        assert_eq!(cip.derived, ip("2001:db8::1"));
    }

    #[test]
    fn no_forward_headers_returns_socket_peer() {
        let (trusted, _) = TrustedProxies::parse("10.0.0.0/8");
        let req = TestRequest::default().to_http_request();
        let cip = ClientIp::resolve(sock("10.0.0.1:443"), &req, &trusted);
        assert_eq!(cip.derived, ip("10.0.0.1"));
    }
}
