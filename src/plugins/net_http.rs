//! Shared SSRF-safe HTTP fetch for the `bvx.net_http` (client app
//! modules) and `bv.net_http` (server WASM plugins) host imports.
//!
//! The *policy* decisions live in [`super::net_gate`] (pure, exhaustively
//! tested); this module is the orchestration that calls the gate at every
//! hop and performs the actual request. Keeping one implementation shared
//! by both runtimes means the redirect/SSRF loop can't drift between them.
//!
//! Guarantees (per `features/plugin-app-extensions.md` § Network):
//! - scheme/host/port + host-allowlist checked on the initial URL and on
//!   every redirect `Location`;
//! - the resolved IPs are SSRF-checked (private/loopback refused unless
//!   the admin granted the literal IP or a `.internal` name);
//! - redirects are followed manually, capped at [`MAX_REDIRECTS`];
//! - the response body is streamed with a hard [`MAX_RESPONSE_BYTES`] cap;
//! - the timeout is clamped to [`TIMEOUT_MAX_MS`]; no cookie jar; no
//!   ambient proxy credentials.

use std::collections::BTreeMap;
use std::net::IpAddr;

use super::net_gate;

/// Response-body cap (4 MiB).
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Timeout ceiling (60 s).
pub const TIMEOUT_MAX_MS: u64 = 60_000;
/// Redirect-hop cap — every hop is re-validated.
pub const MAX_REDIRECTS: usize = 3;

/// A parsed outbound request. Callers build this from the guest's JSON.
#[derive(Debug, Clone)]
pub struct NetRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<Vec<u8>>,
    /// Requested timeout; clamped to [`TIMEOUT_MAX_MS`].
    pub timeout_ms: u64,
}

/// A successful terminal response.
#[derive(Debug, Clone)]
pub struct NetResponse {
    pub status: u16,
    pub body: Vec<u8>,
    /// Host of the terminal request (after any redirects).
    pub host: String,
}

/// Why a fetch was refused/failed. Callers map these to the guest ABI
/// return codes (`NET_NOT_GRANTED` = -6, `NET_HOST_DENIED` = -7,
/// internal = -4) and to their own logging/audit/ring surfaces.
#[derive(Debug, Clone)]
pub enum NetFetchError {
    /// No grant covers the request (empty allowlist).
    NotGranted { host: String },
    /// Scheme/host/port/redirect/SSRF/transport refusal.
    HostDenied { reason: &'static str, host: String },
    /// Malformed request (bad URL/method/body) — host-side, not a policy
    /// decision.
    Internal { reason: &'static str },
}

impl NetFetchError {
    /// A short, stable, non-sensitive reason string (for a call ring /
    /// audit event).
    pub fn reason(&self) -> &'static str {
        match self {
            NetFetchError::NotGranted { .. } => "not_granted",
            NetFetchError::HostDenied { reason, .. } => reason,
            NetFetchError::Internal { reason } => reason,
        }
    }

    pub fn host(&self) -> &str {
        match self {
            NetFetchError::NotGranted { host } => host,
            NetFetchError::HostDenied { host, .. } => host,
            NetFetchError::Internal { .. } => "",
        }
    }
}

/// Resolve `host:port` to its IP set on the blocking pool.
async fn resolve_ips(host: &str, port: u16) -> Result<Vec<IpAddr>, ()> {
    let hostport = format!("{host}:{port}");
    tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        hostport
            .to_socket_addrs()
            .map(|it| it.map(|s| s.ip()).collect::<Vec<_>>())
            .map_err(|_| ())
    })
    .await
    .map_err(|_| ())?
}

/// Execute `req` under the grant, following (and re-validating) up to
/// [`MAX_REDIRECTS`] redirects. `granted` is the admin-authorized host
/// allowlist; an empty slice means "no grant" → [`NetFetchError::NotGranted`].
pub async fn fetch(
    req: &NetRequest,
    granted: &[String],
    https_only: bool,
) -> Result<NetResponse, NetFetchError> {
    if granted.is_empty() {
        return Err(NetFetchError::NotGranted { host: String::new() });
    }

    let denied = |reason: &'static str, host: String| NetFetchError::HostDenied { reason, host };

    let mut url = reqwest::Url::parse(&req.url)
        .map_err(|_| NetFetchError::HostDenied { reason: "bad_url", host: String::new() })?;
    let method = reqwest::Method::from_bytes(req.method.to_uppercase().as_bytes())
        .map_err(|_| NetFetchError::Internal { reason: "bad_method" })?;
    let timeout = std::time::Duration::from_millis(req.timeout_ms.min(TIMEOUT_MAX_MS));

    // No automatic redirects (we re-validate manually), no cookie store
    // (reqwest default), explicit timeout.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()
        .map_err(|_| NetFetchError::Internal { reason: "client" })?;

    let mut hops = 0usize;
    loop {
        let host = url.host_str().unwrap_or_default().to_string();
        // Scheme / host allowlist / port.
        let target =
            net_gate::validate_url(url.scheme(), url.host_str(), url.port(), granted, https_only)
                .map_err(|e| match e {
                    net_gate::NetError::NotGranted => {
                        NetFetchError::NotGranted { host: host.clone() }
                    }
                    net_gate::NetError::HostDenied => denied("host_denied", host.clone()),
                })?;
        // SSRF: resolved IPs must be public unless explicitly granted.
        let port = url.port_or_known_default().unwrap_or(443);
        let ips = resolve_ips(&target.host, port)
            .await
            .map_err(|_| denied("dns", host.clone()))?;
        net_gate::check_resolved_ips(&target, &ips).map_err(|_| denied("ssrf", host.clone()))?;

        let mut rb = client.request(method.clone(), url.clone());
        for (k, v) in &req.headers {
            rb = rb.header(k, v);
        }
        if let Some(b) = &req.body {
            rb = rb.body(b.clone());
        }
        let mut resp = rb.send().await.map_err(|_| denied("send", host.clone()))?;
        let status = resp.status();

        if status.is_redirection() {
            if hops >= MAX_REDIRECTS {
                return Err(denied("too_many_redirects", host));
            }
            let loc = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|h| h.to_str().ok())
                .ok_or_else(|| denied("redirect_no_location", host.clone()))?;
            url = url.join(loc).map_err(|_| denied("bad_redirect", host.clone()))?;
            hops += 1;
            continue; // re-validate the new hop from the top
        }

        // Read the body incrementally via `chunk()` (no `stream` feature
        // / futures-util needed) so we can enforce the cap before
        // buffering an unbounded response.
        let code = status.as_u16();
        let mut buf: Vec<u8> = Vec::new();
        loop {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
                        return Err(denied("body_too_large", host));
                    }
                    buf.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(_) => return Err(denied("body", host.clone())),
            }
        }
        return Ok(NetResponse { status: code, body: buf, host });
    }
}
