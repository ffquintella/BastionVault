use rustls::pki_types::CertificateDer;

#[derive(Default, Clone)]
pub struct Connection {
    /// Socket-level peer address (string form, may include port).
    /// This is what `getpeername` returned at accept time — the proxy
    /// IP if the request came through a reverse proxy, the client IP
    /// otherwise. Always populated.
    pub peer_addr: String,
    /// Derived client IP after walking the `X-Forwarded-For` /
    /// `Forwarded` chain against the trusted-proxy CIDR list. When no
    /// trusted proxies are configured (the default) or no forwarded
    /// headers are present, this equals the IP portion of `peer_addr`.
    /// String form, no port.
    ///
    /// See `src/http/client_ip.rs` for the resolution logic and
    /// `features/packaging-podman-server.md` "Client IP visibility"
    /// for the threat model.
    ///
    /// Access-control checks should read this through
    /// [`Connection::client_ip`] rather than either field directly.
    pub peer_addr_derived: String,
    pub peer_tls_cert: Option<Vec<CertificateDer<'static>>>,
}

impl Connection {
    /// The client IP an access-control rule should be evaluated against,
    /// as a bare address with no port.
    ///
    /// Prefers [`peer_addr_derived`](Self::peer_addr_derived) — the
    /// post-`X-Forwarded-For` walk, which is already port-less and is the
    /// address an operator's rule means when BastionVault runs behind a
    /// trusted proxy — and falls back to the address portion of
    /// [`peer_addr`](Self::peer_addr).
    ///
    /// Returns an empty string when nothing is known; callers that enforce
    /// a source-address restriction must treat that as a refusal, not as
    /// "no restriction".
    ///
    /// This is the only correct input to an IP or CIDR parser. `peer_addr`
    /// carries the socket peer verbatim (`10.0.0.5:41222`), and handing that
    /// to a parser fails closed on every request. Audit records keep both
    /// fields raw and must not use this helper.
    pub fn client_ip(&self) -> String {
        let derived = strip_port(&self.peer_addr_derived);
        if !derived.is_empty() {
            return derived.to_string();
        }
        strip_port(&self.peer_addr).to_string()
    }
}

/// Return the address portion of a socket-address string.
///
/// Handles every form the connection fields can hold: `ip:port`,
/// `[ipv6]:port`, `[ipv6]`, and bare IPv4/IPv6 literals. A bare IPv6
/// literal is never split on a colon. A value that is not an address at
/// all is returned with any `:port` tail trimmed, so a caller quoting it
/// in an error still names what arrived.
fn strip_port(addr: &str) -> &str {
    let addr = addr.trim();
    if addr.is_empty() {
        return "";
    }

    // Bracketed IPv6, with or without a port: `[::1]` / `[::1]:8200`.
    if let Some(rest) = addr.strip_prefix('[') {
        return match rest.split_once(']') {
            Some((inside, _)) => inside,
            // No closing bracket — malformed; hand it back untouched.
            None => addr,
        };
    }

    match addr.rsplit_once(':') {
        // A remaining colon in the host means an unbracketed IPv6 literal,
        // whose last group is not a port. An empty host (`:8200`) is not an
        // address either. Both are returned verbatim.
        Some((host, _)) if !host.is_empty() && !host.contains(':') => host,
        _ => addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(peer: &str, derived: &str) -> Connection {
        Connection {
            peer_addr: peer.to_string(),
            peer_addr_derived: derived.to_string(),
            peer_tls_cert: None,
        }
    }

    #[test]
    fn client_ip_strips_the_port_from_the_socket_peer() {
        // The regression: an AppRole login arrives as `ip:port` and the
        // source-IP filter was handed the whole thing.
        assert_eq!(conn("10.60.64.212:41222", "").client_ip(), "10.60.64.212");
        assert_eq!(conn("127.0.0.1:8200", "").client_ip(), "127.0.0.1");
    }

    #[test]
    fn client_ip_accepts_a_bare_literal() {
        assert_eq!(conn("10.60.64.212", "").client_ip(), "10.60.64.212");
        assert_eq!(conn("2001:db8::1", "").client_ip(), "2001:db8::1");
        assert_eq!(conn("::1", "").client_ip(), "::1");
        assert_eq!(conn("::", "").client_ip(), "::");
    }

    #[test]
    fn client_ip_unwraps_bracketed_ipv6() {
        assert_eq!(conn("[2001:db8::1]:41222", "").client_ip(), "2001:db8::1");
        assert_eq!(conn("[2001:db8::1]", "").client_ip(), "2001:db8::1");
        assert_eq!(conn("[::1]:8200", "").client_ip(), "::1");
    }

    #[test]
    fn client_ip_prefers_the_derived_address() {
        // Behind a trusted proxy: the socket peer is the proxy, the derived
        // address is the client the operator's rule is about.
        let c = conn("10.0.0.5:443", "203.0.113.42");
        assert_eq!(c.client_ip(), "203.0.113.42");
        // Derived wins even for IPv6, and even when it somehow carries a port.
        assert_eq!(conn("10.0.0.5:443", "[2001:db8::9]:1234").client_ip(), "2001:db8::9");
        assert_eq!(conn("10.0.0.5:443", "2001:db8::9").client_ip(), "2001:db8::9");
    }

    #[test]
    fn client_ip_is_empty_when_nothing_is_known() {
        assert_eq!(conn("", "").client_ip(), "");
        assert_eq!(Connection::default().client_ip(), "");
        assert_eq!(conn("   ", "  ").client_ip(), "");
    }

    #[test]
    fn client_ip_returns_an_unparsable_value_with_its_port_trimmed() {
        // Not an address, but the caller's refusal message should still
        // name what arrived.
        assert_eq!(conn("runner.example:41222", "").client_ip(), "runner.example");
        assert_eq!(conn("garbage", "").client_ip(), "garbage");
        assert_eq!(conn(":8200", "").client_ip(), ":8200");
        assert_eq!(conn("[2001:db8::1", "").client_ip(), "[2001:db8::1");
    }
}
