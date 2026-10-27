//! Gateway and relay configuration, including the `hsm_gateway { ... }` HCL
//! block `bvault hsm-gateway --config` reads. Every check fails with an
//! explicit `ErrHsmConfigInvalid`; nothing is defaulted silently except
//! `max_rps_per_client`, whose default is documented.

use std::{
    collections::BTreeSet,
    fmt,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use bv_errors::RvError;
use rustls::pki_types::ServerName;
use serde::Deserialize;
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::{DEFAULT_MAX_RPS_PER_CLIENT, UPSTREAM_TIMEOUT};

/// Longest client id accepted; matches `bv_core::hsm::validate_node_id`.
const MAX_CLIENT_ID_LEN: usize = 128;
/// Upper bound on `max_rps_per_client`; far above what one device can serve.
const MAX_RPS_LIMIT: u32 = 10_000;

fn invalid(msg: impl Into<String>) -> RvError {
    RvError::ErrHsmConfigInvalid(msg.into())
}

/// A client id is a vault `node_id`: 1-128 characters of `[A-Za-z0-9._-]`,
/// not `.` or `..`. Same rule as `bv_core::hsm::validate_node_id` (this
/// Tier 0 crate cannot depend on bv-core). No `*`, so no wildcard SAN matches.
pub fn validate_client_id(id: &str) -> Result<(), RvError> {
    let ok_chars = id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if id.is_empty() || id.len() > MAX_CLIENT_ID_LEN || !ok_chars || id == "." || id == ".." {
        return Err(invalid(format!(
            "hsm_gateway client id {id:?} must be 1-{MAX_CLIENT_ID_LEN} characters of [A-Za-z0-9._-] and not \".\" or \"..\""
        )));
    }
    Ok(())
}

fn parse_url(what: &str, raw: &str) -> Result<Url, RvError> {
    let url = Url::parse(raw.trim()).map_err(|e| invalid(format!("{what} {raw:?} is not a URL: {e}")))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid(format!("{what} {raw:?} must not carry credentials")));
    }
    if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
        return Err(invalid(format!("{what} {raw:?} must be scheme://host:port with no path, query or fragment")));
    }
    Ok(url)
}

/// Where the gateway reaches `yubihsm-connector`: `http://` on a loopback
/// IP literal only. The connector has no client authentication, so a
/// non-loopback address (or a name that DNS could repoint) is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorUrl {
    addr: SocketAddr,
}

impl ConnectorUrl {
    pub fn parse(raw: &str) -> Result<Self, RvError> {
        let what = "hsm_gateway connector";
        let url = parse_url(what, raw)?;
        if url.scheme() != "http" {
            return Err(invalid(format!(
                "{what} {raw:?} must use http:// (the connector stays on loopback behind the gateway's mTLS)"
            )));
        }
        let ip = match url.host() {
            Some(Host::Ipv4(ip)) => IpAddr::V4(ip),
            Some(Host::Ipv6(ip)) => IpAddr::V6(ip),
            _ => return Err(invalid(format!("{what} {raw:?} must be a loopback IP literal such as 127.0.0.1"))),
        };
        if !ip.is_loopback() {
            return Err(invalid(format!(
                "{what} {raw:?} is not a loopback address; the connector must never be exposed"
            )));
        }
        let port = url.port_or_known_default().ok_or_else(|| invalid(format!("{what} {raw:?} has no port")))?;
        Ok(Self { addr: SocketAddr::new(ip, port) })
    }

    pub fn socket_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The `Host` header sent to the connector.
    pub(crate) fn host_header(&self) -> String {
        self.addr.to_string()
    }
}

impl fmt::Display for ConnectorUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "http://{}", self.addr)
    }
}

/// Where a relay reaches a member's gateway: `https://host[:port]`. The
/// gateway's certificate must chain to the link CA and name `host`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayUrl {
    host: Host<String>,
    port: u16,
}

impl GatewayUrl {
    pub fn parse(raw: &str) -> Result<Self, RvError> {
        let what = "HSM gateway URL";
        let url = parse_url(what, raw)?;
        if url.scheme() != "https" {
            return Err(invalid(format!("{what} {raw:?} must use https://")));
        }
        let host = url.host().ok_or_else(|| invalid(format!("{what} {raw:?} has no host")))?.to_owned();
        let port = url.port_or_known_default().ok_or_else(|| invalid(format!("{what} {raw:?} has no port")))?;
        Ok(Self { host, port })
    }

    pub(crate) fn server_name(&self) -> Result<ServerName<'static>, RvError> {
        match &self.host {
            Host::Domain(name) => ServerName::try_from(name.as_str())
                .map(|n| n.to_owned())
                .map_err(|_| invalid(format!("HSM gateway host {name:?} is not a valid TLS server name"))),
            Host::Ipv4(ip) => Ok(ServerName::IpAddress(IpAddr::V4(*ip).into())),
            Host::Ipv6(ip) => Ok(ServerName::IpAddress(IpAddr::V6(*ip).into())),
        }
    }

    /// Addresses to try, in resolver order.
    pub(crate) async fn resolve(&self) -> std::io::Result<Vec<SocketAddr>> {
        match &self.host {
            Host::Domain(name) => Ok(tokio::net::lookup_host((name.as_str(), self.port)).await?.collect()),
            Host::Ipv4(ip) => Ok(vec![SocketAddr::new(IpAddr::V4(*ip), self.port)]),
            Host::Ipv6(ip) => Ok(vec![SocketAddr::new(IpAddr::V6(*ip), self.port)]),
        }
    }

    /// The `Host` header sent to the gateway (IPv6 in brackets).
    pub(crate) fn host_header(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl fmt::Display for GatewayUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "https://{}:{}", self.host, self.port)
    }
}

/// PEM material for one end of the link: this end's certificate chain and
/// key, and the CA the other end must chain to. The key is wiped on drop and
/// never printed.
pub struct LinkTls {
    pub(crate) cert_chain_pem: Vec<u8>,
    pub(crate) key_pem: Zeroizing<Vec<u8>>,
    pub(crate) ca_pem: Vec<u8>,
}

impl LinkTls {
    pub fn from_pem(
        cert_chain_pem: impl Into<Vec<u8>>,
        key_pem: impl Into<Vec<u8>>,
        ca_pem: impl Into<Vec<u8>>,
    ) -> Self {
        Self { cert_chain_pem: cert_chain_pem.into(), key_pem: Zeroizing::new(key_pem.into()), ca_pem: ca_pem.into() }
    }

    pub fn from_files(cert_file: &Path, key_file: &Path, ca_file: &Path) -> Result<Self, RvError> {
        let read = |what: &str, path: &Path| {
            std::fs::read(path).map_err(|e| invalid(format!("cannot read {what} {}: {e}", path.display())))
        };
        Ok(Self {
            cert_chain_pem: read("certificate file", cert_file)?,
            key_pem: Zeroizing::new(read("key file", key_file)?),
            ca_pem: read("CA file", ca_file)?,
        })
    }
}

impl fmt::Debug for LinkTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkTls")
            .field("cert_chain_pem_bytes", &self.cert_chain_pem.len())
            .field("key_pem", &"<redacted>")
            .field("ca_pem_bytes", &self.ca_pem.len())
            .finish()
    }
}

/// Timeouts and caps of the gateway. Only the HCL fields are operator-set;
/// these defaults are the documented behaviour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayLimits {
    /// One connector exchange: connect, send, full response. Spec: 5 s.
    pub upstream_timeout: Duration,
    pub handshake_timeout: Duration,
    /// A connection with no request in progress is closed after this.
    pub idle_timeout: Duration,
    /// From the first byte of a request to its last, and for the response write.
    pub request_timeout: Duration,
    /// Open connections, authenticated or not, across all clients.
    pub max_connections: usize,
}

impl Default for GatewayLimits {
    fn default() -> Self {
        Self {
            upstream_timeout: UPSTREAM_TIMEOUT,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(60),
            request_timeout: Duration::from_secs(10),
            max_connections: 128,
        }
    }
}

/// Everything the gateway needs, with the TLS material already read.
#[derive(Debug)]
pub struct GatewayConfig {
    pub listen: SocketAddr,
    pub connector: ConnectorUrl,
    /// The gateway's server certificate and key; `ca` is the client CA.
    pub tls: LinkTls,
    /// Node ids; a client certificate's DNS SAN must equal exactly one.
    pub allowed_clients: Vec<String>,
    pub max_rps_per_client: u32,
    pub limits: GatewayLimits,
}

fn validate_allowed_clients(allowed: &[String]) -> Result<(), RvError> {
    if allowed.is_empty() {
        return Err(invalid("hsm_gateway allowed_clients is empty: no node could connect"));
    }
    let mut seen = BTreeSet::new();
    for id in allowed {
        validate_client_id(id)?;
        if !seen.insert(id.as_str()) {
            return Err(invalid(format!("hsm_gateway allowed_clients lists {id:?} twice")));
        }
    }
    Ok(())
}

fn validate_max_rps(max_rps: u32) -> Result<(), RvError> {
    if !(1..=MAX_RPS_LIMIT).contains(&max_rps) {
        return Err(invalid(format!("hsm_gateway max_rps_per_client must be 1-{MAX_RPS_LIMIT}, got {max_rps}")));
    }
    Ok(())
}

impl GatewayConfig {
    pub fn validate(&self) -> Result<(), RvError> {
        validate_allowed_clients(&self.allowed_clients)?;
        validate_max_rps(self.max_rps_per_client)?;
        let l = &self.limits;
        let zero =
            [l.upstream_timeout, l.handshake_timeout, l.idle_timeout, l.request_timeout].iter().any(Duration::is_zero);
        if zero || l.max_connections == 0 {
            return Err(invalid("hsm_gateway timeouts and max_connections must be non-zero"));
        }
        Ok(())
    }
}

/// Timeouts of the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayLimits {
    /// Resolve, TCP connect and TLS handshake to the gateway.
    pub connect_timeout: Duration,
    /// One exchange with the gateway: send and full response.
    pub exchange_timeout: Duration,
    /// From the first byte of a local request to its last, and the reply write.
    pub request_timeout: Duration,
    /// A pooled gateway connection idle this long is replaced, not reused.
    /// Keep it below the gateway's `idle_timeout`.
    pub pool_idle_timeout: Duration,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            exchange_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(10),
            pool_idle_timeout: Duration::from_secs(30),
        }
    }
}

/// One relay: one pool member's gateway, reached with the node's link identity.
#[derive(Debug)]
pub struct RelayConfig {
    pub gateway: GatewayUrl,
    /// The node's client certificate (SAN = node id) and key; `ca` verifies
    /// the gateway.
    pub tls: LinkTls,
    pub limits: RelayLimits,
}

impl RelayConfig {
    pub fn validate(&self) -> Result<(), RvError> {
        let l = &self.limits;
        if [l.connect_timeout, l.exchange_timeout, l.request_timeout, l.pool_idle_timeout].iter().any(Duration::is_zero)
        {
            return Err(invalid("HSM relay timeouts must be non-zero"));
        }
        self.gateway.server_name().map(|_| ())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayFile {
    hsm_gateway: GatewayBlock,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayBlock {
    listen: String,
    connector: String,
    tls_cert_file: String,
    tls_key_file: String,
    client_ca_file: String,
    allowed_clients: Vec<String>,
    #[serde(default)]
    max_rps_per_client: Option<u32>,
}

/// The validated `hsm_gateway` block, before the TLS files are read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewaySettings {
    pub listen: SocketAddr,
    pub connector: ConnectorUrl,
    pub tls_cert_file: PathBuf,
    pub tls_key_file: PathBuf,
    pub client_ca_file: PathBuf,
    pub allowed_clients: Vec<String>,
    pub max_rps_per_client: u32,
}

impl GatewaySettings {
    /// Parses and validates the HCL text. Unknown fields, missing fields, a
    /// second block, an empty or invalid allow-list and a non-loopback
    /// connector are all errors.
    pub fn from_hcl(text: &str) -> Result<Self, RvError> {
        let file: GatewayFile =
            hcl::from_str(text).map_err(|e| invalid(format!("hsm_gateway config does not parse: {e}")))?;
        let block = file.hsm_gateway;
        let required = |name: &str, value: &str| {
            if value.trim().is_empty() {
                Err(invalid(format!("hsm_gateway {name} is empty")))
            } else {
                Ok(PathBuf::from(value.trim()))
            }
        };
        let listen = block.listen.trim().parse::<SocketAddr>().map_err(|_| {
            invalid(format!("hsm_gateway listen {:?} must be an ip:port such as 0.0.0.0:8250", block.listen))
        })?;
        let max_rps_per_client = block.max_rps_per_client.unwrap_or(DEFAULT_MAX_RPS_PER_CLIENT);
        validate_allowed_clients(&block.allowed_clients)?;
        validate_max_rps(max_rps_per_client)?;
        Ok(Self {
            listen,
            connector: ConnectorUrl::parse(&block.connector)?,
            tls_cert_file: required("tls_cert_file", &block.tls_cert_file)?,
            tls_key_file: required("tls_key_file", &block.tls_key_file)?,
            client_ca_file: required("client_ca_file", &block.client_ca_file)?,
            allowed_clients: block.allowed_clients,
            max_rps_per_client,
        })
    }

    pub fn load(path: &Path) -> Result<Self, RvError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| invalid(format!("cannot read hsm_gateway config {}: {e}", path.display())))?;
        Self::from_hcl(&text)
    }

    /// Reads the TLS files and produces the runnable config.
    pub fn into_config(self) -> Result<GatewayConfig, RvError> {
        let tls = LinkTls::from_files(&self.tls_cert_file, &self.tls_key_file, &self.client_ca_file)?;
        let config = GatewayConfig {
            listen: self.listen,
            connector: self.connector,
            tls,
            allowed_clients: self.allowed_clients,
            max_rps_per_client: self.max_rps_per_client,
            limits: GatewayLimits::default(),
        };
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC_EXAMPLE: &str = r#"
hsm_gateway {
  listen           = "0.0.0.0:8250"
  connector        = "http://127.0.0.1:12345"
  tls_cert_file    = "/etc/bastionvault/hsm-link/hsm-a.pem"
  tls_key_file     = "/etc/bastionvault/hsm-link/hsm-a.key"
  client_ca_file   = "/etc/bastionvault/hsm-link/ca.pem"
  allowed_clients  = ["vault-1", "vault-2", "vault-3"]   # SAN match, exact
  max_rps_per_client = 50
}
"#;

    fn err_text(result: Result<GatewaySettings, RvError>) -> String {
        match result {
            Ok(s) => panic!("accepted: {s:?}"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn parses_the_spec_example() {
        let s = GatewaySettings::from_hcl(SPEC_EXAMPLE).unwrap();
        assert_eq!(s.listen, "0.0.0.0:8250".parse().unwrap());
        assert_eq!(s.connector.socket_addr(), "127.0.0.1:12345".parse().unwrap());
        assert_eq!(s.tls_key_file, PathBuf::from("/etc/bastionvault/hsm-link/hsm-a.key"));
        assert_eq!(s.allowed_clients, ["vault-1", "vault-2", "vault-3"]);
        assert_eq!(s.max_rps_per_client, 50);
    }

    #[test]
    fn max_rps_defaults_when_absent() {
        let text = SPEC_EXAMPLE.replace("max_rps_per_client = 50", "");
        assert_eq!(GatewaySettings::from_hcl(&text).unwrap().max_rps_per_client, DEFAULT_MAX_RPS_PER_CLIENT);
    }

    #[test]
    fn missing_unknown_and_empty_fields_fail_explicitly() {
        let missing = SPEC_EXAMPLE.replace("client_ca_file   = \"/etc/bastionvault/hsm-link/ca.pem\"", "");
        assert!(err_text(GatewaySettings::from_hcl(&missing)).contains("client_ca_file"));

        let unknown = SPEC_EXAMPLE.replace("max_rps_per_client = 50", "max_rps = 50");
        assert!(err_text(GatewaySettings::from_hcl(&unknown)).contains("max_rps"));

        let empty = SPEC_EXAMPLE.replace("/etc/bastionvault/hsm-link/hsm-a.key", " ");
        assert!(err_text(GatewaySettings::from_hcl(&empty)).contains("tls_key_file is empty"));

        let no_block = "listen = \"0.0.0.0:8250\"";
        assert!(err_text(GatewaySettings::from_hcl(no_block)).contains("hsm_gateway"));

        let twice = format!("{SPEC_EXAMPLE}\n{SPEC_EXAMPLE}");
        GatewaySettings::from_hcl(&twice).expect_err("two hsm_gateway blocks must not be merged silently");
    }

    #[test]
    fn allow_list_must_be_non_empty_valid_and_unique() {
        let empty = SPEC_EXAMPLE.replace(r#"["vault-1", "vault-2", "vault-3"]"#, "[]");
        assert!(err_text(GatewaySettings::from_hcl(&empty)).contains("allowed_clients is empty"));

        for bad in [r#"["*"]"#, r#"["vault 1"]"#, r#"[".."]"#, r#"[""]"#, r#"["*.example"]"#] {
            let text = SPEC_EXAMPLE.replace(r#"["vault-1", "vault-2", "vault-3"]"#, bad);
            assert!(err_text(GatewaySettings::from_hcl(&text)).contains("client id"), "{bad}");
        }

        let dup = SPEC_EXAMPLE.replace(r#"["vault-1", "vault-2", "vault-3"]"#, r#"["vault-1", "vault-1"]"#);
        assert!(err_text(GatewaySettings::from_hcl(&dup)).contains("twice"));
    }

    #[test]
    fn rate_and_listen_are_checked() {
        let zero = SPEC_EXAMPLE.replace("max_rps_per_client = 50", "max_rps_per_client = 0");
        assert!(err_text(GatewaySettings::from_hcl(&zero)).contains("max_rps_per_client"));
        let host = SPEC_EXAMPLE.replace("0.0.0.0:8250", "gateway.internal:8250");
        assert!(err_text(GatewaySettings::from_hcl(&host)).contains("listen"));
    }

    #[test]
    fn connector_must_be_plain_http_on_a_loopback_literal() {
        for good in ["http://127.0.0.1:12345", "http://127.0.0.2:1", "http://[::1]:12345", "http://127.0.0.1:12345/"] {
            ConnectorUrl::parse(good).unwrap_or_else(|e| panic!("{good}: {e}"));
        }
        for bad in [
            "https://127.0.0.1:12345",
            "http://10.0.0.5:12345",
            "http://0.0.0.0:12345",
            "http://[::]:12345",
            "http://localhost:12345",
            "http://hsm-a.internal:12345",
            "http://user:pw@127.0.0.1:12345",
            "http://127.0.0.1:12345/connector",
            "http://127.0.0.1:12345?x=1",
            "127.0.0.1:12345",
            "",
        ] {
            ConnectorUrl::parse(bad).expect_err(bad);
        }
        let text = SPEC_EXAMPLE.replace("http://127.0.0.1:12345", "http://192.168.1.10:12345");
        assert!(err_text(GatewaySettings::from_hcl(&text)).contains("loopback"));
    }

    #[test]
    fn gateway_url_must_be_https_without_path() {
        let url = GatewayUrl::parse("https://hsm-a.internal:8250").unwrap();
        assert_eq!(url.host_header(), "hsm-a.internal:8250");
        assert_eq!(url.to_string(), "https://hsm-a.internal:8250");
        assert!(matches!(url.server_name().unwrap(), ServerName::DnsName(_)));
        let v6 = GatewayUrl::parse("https://[::1]:8250").unwrap();
        assert_eq!(v6.host_header(), "[::1]:8250");
        assert!(matches!(v6.server_name().unwrap(), ServerName::IpAddress(_)));
        assert_eq!(GatewayUrl::parse("https://hsm-a.internal").unwrap().host_header(), "hsm-a.internal:443");
        for bad in ["http://hsm-a:8250", "https://hsm-a:8250/connector/api", "https://u@hsm-a:8250", "hsm-a:8250"] {
            GatewayUrl::parse(bad).expect_err(bad);
        }
    }

    #[test]
    fn link_tls_debug_never_prints_the_key() {
        let tls = LinkTls::from_pem("CERT", "-----BEGIN PRIVATE KEY-----SECRET", "CA");
        let shown = format!("{tls:?}");
        assert!(!shown.contains("SECRET") && shown.contains("redacted"), "{shown}");
    }

    #[test]
    fn client_ids_follow_the_node_id_rule() {
        for good in ["vault-1", "a", "node_7.dc1", &"x".repeat(128)] {
            validate_client_id(good).unwrap();
        }
        for bad in ["", ".", "..", "vault 1", "vault/1", "*", &"x".repeat(129), "vault-ü"] {
            validate_client_id(bad).expect_err(bad);
        }
    }
}
