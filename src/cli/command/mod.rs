//! This module provides different commands for the BastionVault application.
//! For instance, we have a 'server' command to indicate the application running in the server mode
//! and starts to accept HTTP request to do real BastionVault functionality.

use std::path::PathBuf;

use clap::{ArgAction, Args, ValueEnum, ValueHint};
use sysexits::ExitCode;

use crate::{
    api::{client::TLSConfigBuilder, Client},
    errors::RvError,
    EXIT_CODE_OK,
};

pub mod auth;
pub mod auth_disable;
pub mod cluster;
pub mod cluster_discover;
pub mod cluster_failover;
pub mod cluster_leader;
pub mod cluster_leave;
pub mod cluster_members;
pub mod cluster_remove_node;
pub mod cluster_status;
pub mod auth_enable;
pub mod auth_help;
pub mod auth_list;
pub mod auth_move;
pub mod delete;
pub mod format;
pub mod list;
pub mod login;
pub mod operator;
pub mod operator_cloud_target_connect;
#[cfg(not(feature = "sync_handler"))]
pub mod operator_cloud_target_rekey;
pub mod operator_init;
#[cfg(not(feature = "sync_handler"))]
pub mod operator_backup;
pub mod operator_export;
pub mod operator_ferrogate;
pub mod operator_hsm;
pub mod operator_import;
#[cfg(unix)]
pub mod ferrogate;
#[cfg(unix)]
pub mod ferrogate_mia;
pub mod exchange;
pub mod exchange_export;
pub mod exchange_import;
pub mod exchange_verify;
#[cfg(not(feature = "sync_handler"))]
pub mod operator_migrate;
#[cfg(not(feature = "sync_handler"))]
pub mod operator_restore;
pub mod operator_seal;
pub mod operator_unseal;
pub mod policy;
pub mod policy_delete;
pub mod policy_list;
pub mod policy_read;
pub mod policy_write;
pub mod read;
pub mod rustion;
pub mod rustion_master_export;
pub mod rustion_master_issue;
pub mod rustion_master_read;
pub mod rustion_master_rotate;
pub mod rustion_target_add;
pub mod rustion_target_delete;
pub mod rustion_target_health;
pub mod rustion_target_list;
pub mod rustion_target_read;
pub mod rustion_target_test;
pub mod secrets;
pub mod secrets_disable;
pub mod secrets_enable;
pub mod ssh_broker;
pub mod ssh_broker_policy_get;
pub mod ssh_broker_policy_set;
pub mod secrets_list;
pub mod secrets_move;
pub mod server;
pub mod status;
pub mod write;

pub use format::{LogicalOutputOptions, OutputOptions};

#[derive(Args, Default)]
#[group(required = false, multiple = true)]
pub struct HttpOptions {
    #[arg(
        long,
        next_line_help = true,
        value_name = "string",
        default_value = "https://127.0.0.1:8200",
        long_help = r#"Address of the BastionVault server. This can also be specified via the
VAULT_ADDR or RUSTY_VAULT_ADDR environment variable."#
    )]
    address: String,

    #[arg(
        long,
        next_line_help = true,
        value_name = "string",
        value_hint = ValueHint::FilePath,
        env = "VAULT_CACERT",
        long_help = r#"Path on the local disk to a single PEM-encoded CA certificate to verify
the BastionVault server's SSL certificate. This takes precedence over -ca-path.
This can also be specified via the VAULT_CACERT environment variable."#
    )]
    ca_cert: Option<PathBuf>,

    #[arg(
        long,
        next_line_help = true,
        value_name = "string",
        value_hint = ValueHint::DirPath,
        env = "VAULT_CAPATH",
        long_help = r#"Path on the local disk to a directory of PEM-encoded CA certificates to
verify the BastionVault server's SSL certificate. This can also be specified
via the VAULT_CAPATH environment variable."#
    )]
    ca_path: Option<PathBuf>,

    #[arg(
        long,
        next_line_help = true,
        value_name = "string",
        value_hint = ValueHint::FilePath,
        env = "VAULT_CLIENT_CERT",
        long_help = r#"Path on the local disk to a single PEM-encoded CA certificate to use
for TLS authentication to the Vault server. If this flag is specified,
-client-key is also required. This can also be specified via the VAULT_CLIENT_CERT
environment variable."#
    )]
    client_cert: Option<PathBuf>,

    #[arg(
        long,
        next_line_help = true,
        value_name = "string",
        value_hint = ValueHint::FilePath,
        env = "VAULT_CLIENT_KEY",
        long_help = r#"Path on the local disk to a single PEM-encoded private key matching the
client certificate from -client-cert. This can also be specified via the
VAULT_CLIENT_KEY environment variable."#
    )]
    client_key: Option<PathBuf>,

    #[arg(
        long,
        next_line_help = true,
        value_name = "string",
        long_help = r#"Name to use as the SNI host when connecting to the Vault server via TLS.
This can also be specified via the VAULT_TLS_SERVER_NAME environment variable."#
    )]
    tls_server_name: Option<String>,

    #[arg(
        long,
        next_line_help = true,
        env = "VAULT_SKIP_VERIFY",
        long_help = r#"Disable verification of TLS certificates. Using this option is highly
discouraged as it decreases the security of data transmissions to and
from the BastionVault server. The default is false. This can also be specified
via the VAULT_SKIP_VERIFY environment variable."#
    )]
    tls_skip_verify: bool,

    #[clap(
        long,
        value_name = "key=value",
        action = ArgAction::Append,
        long_help = r#"Key-value pair provided as key=value to provide http header added to any
request done by the CLI. Trying to add headers starting with 'X-Vault-'
is forbidden and will make the command fail. This can be specified multiple times.
        "#
    )]
    header: Vec<String>,

    #[clap(long, hide = true, required = false, env = "VAULT_TOKEN", default_value = "")]
    token: String,

    /// Disable SRV-based cluster discovery for this invocation. By
    /// default a bare DNS name in `--address` runs through
    /// `_bvault._tcp.<name>` SRV lookup + `/sys/health` scoring
    /// before the request fires; this flag forces literal-address
    /// mode for diagnostics against one HA node. URL-shaped values
    /// (`https://host:port`) always skip discovery regardless.
    #[arg(
        long,
        env = "VAULT_NO_CLUSTER_DISCOVERY",
        long_help = r#"Skip SRV-based cluster discovery and connect to --address as a literal
URL. By default a bare DNS hostname runs through cluster discovery
(_bvault._tcp.<name> SRV records + /sys/health scoring)."#
    )]
    no_cluster_discovery: bool,
}

#[derive(Args)]
#[group(required = false, multiple = true)]
pub struct CommandOptions {
    #[arg(
        long,
        next_line_help = true,
        value_name = "string",
        long_help = r#"Path to a configuration file or directory of configuration files. This
flag can be specified multiple times to load multiple configurations.
If the path is a directory, all files which end in .hcl or .json are loaded."#
    )]
    config: Option<PathBuf>,

    #[arg(
        long,
        next_line_help = true,
        value_name = "string",
        default_value = "false",
        long_help = "Path to the log file that Vault should use for logging"
    )]
    log_file: Option<PathBuf>,

    #[arg(
        long,
        next_line_help = true,
        value_name = "string",
        num_args = 0..=1,
        env = "VAULT_LOG_LEVEL",
        default_value_t = LogLevel::Warn,
        default_missing_value = "error",
        long_help = r#"Log verbosity level. This can also be specified via the VAULT_LOG_LEVEL
or RUSTY_VAULT_LOG_LEVEL environment variable.
"#,
        value_enum
    )]
    log_level: LogLevel,
}

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl HttpOptions {
    pub fn init(&mut self) -> Result<(), RvError> {
        Ok(())
    }

    pub fn client(&self) -> Result<Client, RvError> {
        // Default path: run cluster discovery if the user supplied a
        // bare hostname, else fall through to literal-mode. The
        // server-crate Client itself doesn't know about SRV, so we
        // resolve here and hand it a concrete URL.
        let resolved = self.resolved_address()?;
        self.client_at(&resolved)
    }

    /// Resolve `--address` into a concrete `scheme://host:port` URL.
    /// Returns the input unchanged for URL-shaped addresses or when
    /// `--no-cluster-discovery` was passed; otherwise runs SRV +
    /// `/sys/health` probing via the bv-client discovery module.
    pub fn resolved_address(&self) -> Result<String, RvError> {
        if self.no_cluster_discovery
            || self.address.starts_with("http://")
            || self.address.starts_with("https://")
        {
            return Ok(self.address.clone());
        }
        let selected = self
            .run_cluster_discovery()
            .map_err(|e| RvError::ErrString(format!("cluster discovery failed: {e}")))?;
        Ok(selected.candidate.url())
    }

    /// Build a `Client` aimed at an explicit URL. Used by
    /// [`Self::client`] after discovery resolves the cluster name,
    /// and by `cluster discover` for the diagnostics-only path.
    pub fn client_at(&self, url: &str) -> Result<Client, RvError> {
        // --tls-server-name rewrites the URL host to the supplied name so
        // rustls uses it as SNI, while a static resolver attached to the
        // ureq agent keeps the connection aimed at the original host's
        // IP. Lets you point at e.g. 127.0.0.1 but have rustls verify
        // against a SAN like `segdc1vds0005.fgv.br`.
        let (effective_url, override_addr) = match self.tls_server_name.as_deref() {
            Some(name) if !name.is_empty() => rewrite_url_for_sni(url, name)?,
            _ => (url.to_string(), None),
        };
        if std::env::var("BVAULT_TLS_DEBUG").is_ok() {
            eprintln!(
                "[bvault tls-debug] input_url={url} server_name={:?} effective_url={effective_url} override_addr={:?}",
                self.tls_server_name, override_addr
            );
        }
        // Token resolution order: explicit --client-token / VAULT_TOKEN (both
        // populated into self.token by clap), else the on-disk token helper
        // ($BVAULT_TOKEN_FILE or ~/.vault-token) written by `bvault login`.
        let token: std::borrow::Cow<'_, str> = if self.token.is_empty() {
            match crate::cli::util::read_persisted_token() {
                Some(t) => std::borrow::Cow::Owned(t),
                None => std::borrow::Cow::Borrowed(""),
            }
        } else {
            std::borrow::Cow::Borrowed(self.token.as_str())
        };
        let mut client = Client::new().with_addr(&effective_url).with_token(&token);
        if let Some(addr) = override_addr {
            client = client.with_override_socket_addr(addr);
        }

        if effective_url.starts_with("https://") {
            let mut tls_config_builder = TLSConfigBuilder::new().with_insecure(self.tls_skip_verify);
            let auto_ca = self.discovered_ca_cert();
            let ca_cert = self.ca_cert.as_ref().or(auto_ca.as_ref());
            if let Some(ca_cert) = ca_cert {
                tls_config_builder = tls_config_builder.with_server_ca_path(ca_cert)?;
            }
            if let (Some(client_cert), Some(client_key)) = (&self.client_cert, &self.client_key) {
                tls_config_builder = tls_config_builder.with_client_cert_path(client_cert, client_key)?;
            }
            let tls_config = tls_config_builder.build()?;
            client = client.with_tls_config(tls_config);
        }
        Ok(client.build())
    }

    /// Run the full discovery + health pipeline against `--address`
    /// and return the chosen node. Used by [`Self::client`] for the
    /// implicit path and by the `cluster discover` subcommand for
    /// the diagnostics-only path that also needs the raw probe
    /// table; that subcommand calls [`Self::probe_cluster`] instead.
    pub fn run_cluster_discovery(&self) -> Result<bv_client::health::Selected, String> {
        let probes = self.probe_cluster()?;
        bv_client::health::pick(&probes)
            .ok_or_else(|| format!("no healthy node found for `{}`", self.address))
    }

    /// Resolve the set of cluster nodes a cluster-wide operator command
    /// (e.g. `operator unseal` / `operator seal`) should target. Returns
    /// one `(url, Client)` per node.
    ///
    /// - `local == true`, a literal `http(s)://` URL, or
    ///   `--no-cluster-discovery` → a single entry for the resolved
    ///   address, preserving the original single-node behavior.
    /// - a bare cluster name with SRV records → one entry per discovered
    ///   node, so seal/unseal apply to the whole cluster. All candidates
    ///   are returned (including sealed/unreachable ones) — sealed nodes
    ///   are exactly the ones to unseal, and unreachable ones surface as
    ///   per-node failures the caller reports.
    pub fn cluster_clients(&self, local: bool) -> Result<Vec<(String, Client)>, RvError> {
        if local
            || self.no_cluster_discovery
            || self.address.starts_with("http://")
            || self.address.starts_with("https://")
        {
            let url = self.resolved_address()?;
            let client = self.client_at(&url)?;
            return Ok(vec![(url, client)]);
        }
        let probes = self.probe_cluster().map_err(RvError::ErrString)?;
        if probes.is_empty() {
            return Err(RvError::ErrString(format!("no nodes found for `{}`", self.address)));
        }
        probes
            .iter()
            .map(|p| {
                let url = p.candidate.url();
                self.client_at(&url).map(|c| (url, c))
            })
            .collect()
    }

    /// Resolve + probe without picking, so callers (e.g. the
    /// `cluster discover` subcommand) can render the full probe
    /// table even when no candidate is healthy.
    pub fn probe_cluster(&self) -> Result<Vec<bv_client::health::ProbeResult>, String> {
        use bv_client::discovery::{DiscoveryConfig, SystemResolver};
        use bv_client::health::HealthConfig;

        // Build the bv-client TLS config from the same CA / client
        // cert flags the legacy `Client` uses, so probes traverse
        // the same trust chain the eventual request will.
        let tls = self.bv_tls_for_probe().map_err(|e| e.to_string())?;

        let discovery_cfg = DiscoveryConfig::default();
        let health_cfg = HealthConfig::default();

        // hickory-resolver's async API needs a tokio runtime. We
        // build a single-threaded one on demand to keep the
        // otherwise-sync CLI fully sync from the caller's point of
        // view.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("tokio init: {e}"))?;
        rt.block_on(async {
            let resolver = SystemResolver::new();
            let resolved = bv_client::discovery::resolve(&self.address, &discovery_cfg, &resolver)
                .await
                .map_err(|e| format!("resolve: {e}"))?;
            let candidates = resolved.into_candidates();
            Ok(bv_client::health::probe_all(&candidates, &health_cfg, tls.as_ref()).await)
        })
    }

    fn bv_tls_for_probe(&self) -> Result<Option<bv_client::tls::ClientTlsConfig>, RvError> {
        // No HTTPS hint and no skip-verify? Then probes can go in
        // the clear, matching what `client()` would have built.
        let auto_ca = self.discovered_ca_cert();
        let likely_tls = self.tls_skip_verify
            || self.ca_cert.is_some()
            || auto_ca.is_some()
            || self.client_cert.is_some()
            || self.address.starts_with("https://");
        if !likely_tls {
            return Ok(None);
        }
        let mut b = bv_client::tls::TLSConfigBuilder::new().with_insecure(self.tls_skip_verify);
        if let Some(ca) = self.ca_cert.as_ref().or(auto_ca.as_ref()) {
            b = b
                .with_server_ca_path(ca)
                .map_err(|e| RvError::ErrString(format!("ca cert: {e}")))?;
        }
        if let (Some(cc), Some(ck)) = (&self.client_cert, &self.client_key) {
            b = b
                .with_client_cert_path(cc, ck)
                .map_err(|e| RvError::ErrString(format!("client cert: {e}")))?;
        }
        let cfg = b
            .build()
            .map_err(|e| RvError::ErrString(format!("tls build: {e}")))?;
        Ok(Some(cfg))
    }

    pub fn address_raw(&self) -> &str {
        &self.address
    }


    /// Look for a server-published serving certificate at a small set of
    /// conventional paths, used as a fallback when the user did not pass
    /// `--ca-cert` / `VAULT_CACERT`. Lets `bvault foo` against a TLS-enabled
    /// local (or bind-mounted-from-container) server work without
    /// `--tls-skip-verify`.
    ///
    /// Discovery order:
    /// 1. `$BVAULT_CACERT_AUTO` (explicit override).
    /// 2. `~/.bvault/ca.pem`.
    /// 3. `/etc/bvault/ca.pem` — populated by bare-metal installs that set the
    ///    listener's `tls_publish_ca_path` (see `publish_ca_for_local_clients`
    ///    in `cli::command::server`).
    /// 4. `/srv/application-config/bastionvault/tls/server.crt` — the
    ///    puppet-bastionvault layout where the serving cert is rendered
    ///    world-readable on the host and bind-mounted read-only into the
    ///    rootless podman container. The container itself cannot write
    ///    `ca.pem` back into that read-only mount, so we point straight at the
    ///    cert puppet already placed.
    fn discovered_ca_cert(&self) -> Option<PathBuf> {
        if self.tls_skip_verify {
            return None;
        }
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Ok(env_path) = std::env::var("BVAULT_CACERT_AUTO") {
            if !env_path.is_empty() {
                candidates.push(PathBuf::from(env_path));
            }
        }
        if let Some(home) = std::env::var_os("HOME") {
            candidates.push(PathBuf::from(home).join(".bvault").join("ca.pem"));
        }
        candidates.push(PathBuf::from("/etc/bvault/ca.pem"));
        candidates.push(PathBuf::from(
            "/srv/application-config/bastionvault/tls/server.crt",
        ));
        candidates.into_iter().find(|p| p.is_file())
    }
}

/// Replace the host in a `scheme://host[:port]/...` URL with `sni_name`,
/// returning the rewritten URL plus the original host's resolved
/// `SocketAddr` for the agent's static resolver. Returns `(url, None)` if
/// the original host couldn't be resolved — TLS will then attempt name
/// resolution as if the flag weren't passed, which surfaces a clearer
/// error than silently dropping the override.
fn rewrite_url_for_sni(
    url: &str,
    sni_name: &str,
) -> Result<(String, Option<std::net::SocketAddr>), RvError> {
    use std::net::ToSocketAddrs;

    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| RvError::ErrString(format!("malformed URL: {url}")))?;
    let (authority, path_suffix) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    // Strip optional userinfo (`user:pass@host:port`) — we never set it,
    // but be defensive.
    let host_port = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);

    // Extract port if present. IPv6 literals are wrapped in [].
    let (host, port) = if let Some(stripped) = host_port.strip_prefix('[') {
        let (h, rest) = stripped
            .split_once(']')
            .ok_or_else(|| RvError::ErrString(format!("malformed IPv6 host: {host_port}")))?;
        let p = rest.strip_prefix(':');
        (h.to_string(), p)
    } else if let Some((h, p)) = host_port.rsplit_once(':') {
        (h.to_string(), Some(p))
    } else {
        (host_port.to_string(), None)
    };
    let port_str = port.map(|s| s.to_string()).unwrap_or_else(|| match scheme {
        "https" => "443".to_string(),
        _ => "80".to_string(),
    });
    let port_num: u16 = port_str
        .parse()
        .map_err(|_| RvError::ErrString(format!("invalid port `{port_str}` in {url}")))?;

    // Resolve the original host to a SocketAddr. If it fails, fall back to
    // letting the default resolver try — the user gets a meaningful error
    // either way.
    let socket_addr = (host.as_str(), port_num).to_socket_addrs().ok().and_then(|mut it| it.next());

    let new_url = format!("{scheme}://{sni_name}:{port_num}{path_suffix}");
    Ok((new_url, socket_addr))
}

pub trait CommandExecutor {
    #[inline]
    fn execute(&mut self) -> ExitCode {
        match self.main() {
            Ok(_) => EXIT_CODE_OK,
            Err(RvError::ErrRequestNoData) => {
                std::process::exit(2);
            }
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    }

    fn main(&self) -> Result<(), RvError>;
}

#[cfg(test)]
mod sni_rewrite_tests {
    use super::rewrite_url_for_sni;

    #[test]
    fn rewrites_ipv4_host_preserves_port_and_path() {
        let (url, addr) = rewrite_url_for_sni("https://127.0.0.1:8200/v1/foo", "vault.example").unwrap();
        assert_eq!(url, "https://vault.example:8200/v1/foo");
        let addr = addr.expect("loopback should always resolve");
        assert_eq!(addr.port(), 8200);
        assert!(addr.ip().is_loopback());
    }

    #[test]
    fn rewrites_ipv6_host() {
        let (url, addr) = rewrite_url_for_sni("https://[::1]:4200", "vault.example").unwrap();
        assert_eq!(url, "https://vault.example:4200");
        let addr = addr.expect("loopback should always resolve");
        assert_eq!(addr.port(), 4200);
    }

    #[test]
    fn defaults_port_for_scheme_when_omitted() {
        let (url, _) = rewrite_url_for_sni("https://127.0.0.1/", "vault.example").unwrap();
        assert_eq!(url, "https://vault.example:443/");
    }

    #[test]
    fn returns_none_addr_for_unresolvable_host_but_still_rewrites() {
        let (url, addr) = rewrite_url_for_sni(
            "https://this-host-does-not-exist.invalid:8200/x",
            "vault.example",
        )
        .unwrap();
        assert_eq!(url, "https://vault.example:8200/x");
        assert!(addr.is_none());
    }

    #[test]
    fn rejects_malformed_url() {
        assert!(rewrite_url_for_sni("not-a-url", "vault.example").is_err());
    }

    /// Belt-and-braces: confirm the rewritten URL still parses as an http::Uri
    /// with the host we expect (this is what ureq's RustlsConnector reads via
    /// `details.uri.authority().host()` for the SNI / certificate name).
    #[test]
    fn rewritten_url_parses_as_http_uri_with_dns_host() {
        let (url, _) =
            rewrite_url_for_sni("https://127.0.0.1:8200/v1/sys/unseal", "vault.example").unwrap();
        let uri: ureq::http::Uri = url.parse().expect("URL must parse as http::Uri");
        let authority = uri.authority().expect("authority present");
        assert_eq!(authority.host(), "vault.example");
        assert_eq!(authority.port_u16(), Some(8200));
    }
}

#[cfg(test)]
mod test {
    use crate::{errors::RvError, bv_error_string, test_utils::TestHttpServer};

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_cli_logical() {
        let mut test_http_server = TestHttpServer::new("test_cli_read", true).await;
        test_http_server.token = test_http_server.root_token.clone();

        // There is no data by default, and reading should fail.
        let ret = test_http_server.cli(&["read"], &["kv/foo"]);
        assert!(ret.is_err());
        assert_eq!(ret.unwrap_err(), bv_error_string!("No value found at kv/foo\n"));

        // Without the mount kv engine, writing data should fail.
        let ret = test_http_server.cli(&["write"], &["kv/foo", "aa=bb", "cc=dd"]);
        assert!(ret.is_err());

        // Mount kv engine to path: kv/
        let ret = test_http_server.mount("kv", "kv");
        assert!(ret.is_ok());

        // Writing data should ok
        let ret = test_http_server.cli(&["write"], &["kv/foo", "aa=bb", "cc=dd"]);
        assert_eq!(ret, Ok("Success! Data written to: kv/foo\n".into()));

        // Reading data should ok
        let ret = test_http_server.cli(&["read"], &["kv/foo"]);
        #[cfg(windows)]
        assert_eq!(ret, Ok("Key    Value    \r\n---    -----    \r\naa     bb    \r\ncc     dd    \r\n".into()));
        #[cfg(not(windows))]
        assert_eq!(ret, Ok("Key    Value    \n---    -----    \naa     bb    \ncc     dd    \n".into()));

        let ret = test_http_server.cli(&["read"], &["--format=table", "kv/foo"]);
        #[cfg(windows)]
        assert_eq!(ret, Ok("Key    Value    \r\n---    -----    \r\naa     bb    \r\ncc     dd    \r\n".into()));
        #[cfg(not(windows))]
        assert_eq!(ret, Ok("Key    Value    \n---    -----    \naa     bb    \ncc     dd    \n".into()));

        let ret = test_http_server.cli(&["read"], &["--format=json", "kv/foo"]);
        assert_eq!(ret, Ok("{\n  \"aa\": \"bb\",\n  \"cc\": \"dd\"\n}\n".into()));

        let ret = test_http_server.cli(&["read"], &["--format=yaml", "kv/foo"]);
        assert_eq!(ret, Ok("aa: bb\ncc: dd\n".into()));

        let ret = test_http_server.cli(&["read"], &["--format=yml", "kv/foo"]);
        assert_eq!(ret, Ok("aa: bb\ncc: dd\n".into()));

        let ret = test_http_server.cli(&["read"], &["--format=raw", "kv/foo"]);
        assert_eq!(ret, Ok("{\"aa\":\"bb\",\"cc\":\"dd\"}\n".into()));

        let ret = test_http_server.cli(&["read"], &["--field=aa", "kv/foo"]);
        assert_eq!(ret, Ok("bb\n".into()));

        let ret = test_http_server.cli(&["read"], &["--field=gg", "kv/foo"]);
        assert_eq!(ret, Err(bv_error_string!("Error: Field \"gg\" not present in secret\n")));

        // list /
        let ret = test_http_server.cli(&["list"], &[]);
        assert!(ret.is_err());

        // list kv/
        let ret = test_http_server.cli(&["list"], &["kv/"]);
        #[cfg(windows)]
        assert_eq!(ret, Ok("Keys    \r\n----    \r\nfoo    \r\n".into()));
        #[cfg(not(windows))]
        assert_eq!(ret, Ok("Keys    \n----    \nfoo    \n".into()));

        // list kvv/
        let ret = test_http_server.cli(&["list"], &["kvv/"]);
        assert_eq!(ret, Err(bv_error_string!("No value found at kvv/\n")));

        // write kv/goo
        let ret = test_http_server.cli(&["write"], &["kv/goo", "aaa=bbb", "ccc=ddd"]);
        assert!(ret.is_ok());

        // list kv/ again
        let ret = test_http_server.cli(&["list"], &["kv/"]);
        #[cfg(windows)]
        assert_eq!(ret, Ok("Keys    \r\n----    \r\nfoo    \r\ngoo    \r\n".into()));
        #[cfg(not(windows))]
        assert_eq!(ret, Ok("Keys    \n----    \nfoo    \ngoo    \n".into()));

        // delete kv/goo
        let ret = test_http_server.cli(&["delete"], &["kv/goo"]);
        assert_eq!(ret, Ok("Success! Data deleted (if it existed) at: kv/goo\n".into()));

        // list kv/goo, again
        let ret = test_http_server.cli(&["list"], &["kv/goo"]);
        assert_eq!(ret, Err(bv_error_string!("No value found at kv/goo\n")));

        // delete kv/koo
        let ret = test_http_server.cli(&["delete"], &["kv/koo"]);
        assert_eq!(ret, Ok("Success! Data deleted (if it existed) at: kv/koo\n".into()));

        // delete kv/
        let ret = test_http_server.cli(&["delete"], &["kv/"]);
        assert_eq!(ret, Ok("Success! Data deleted (if it existed) at: kv/\n".into()));

        // list kv/ again
        let ret = test_http_server.cli(&["list"], &["kv/"]);
        #[cfg(windows)]
        assert_eq!(ret, Ok("Keys    \r\n----    \r\nfoo    \r\n".into()));
        #[cfg(not(windows))]
        assert_eq!(ret, Ok("Keys    \n----    \nfoo    \n".into()));
    }
}
