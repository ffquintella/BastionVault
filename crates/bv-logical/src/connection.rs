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
    #[allow(dead_code)] // populated by the HTTP handler; consumers will land in audit/rate-limit layers.
    pub peer_addr_derived: String,
    pub peer_tls_cert: Option<Vec<CertificateDer<'static>>>,
}
