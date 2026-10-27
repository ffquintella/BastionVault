//! The host's PostgreSQL connector: tokio-postgres over rustls (`ring`).
//!
//! Same rules as the reference plugin's own dialler: the URL may carry no
//! user or password, TLS is required unless the operator set
//! `insecure_skip_tls_verify` (`sslmode=disable` is then refused, never
//! honoured), and only TCP hosts are dialled: a Unix socket would let the
//! server authenticate the vault process by its OS user (`peer`).

use std::{future::Future, io, pin::Pin, str::FromStr, sync::Arc};

use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::{
    config::{Host, SslMode},
    tls::{ChannelBinding, MakeTlsConnect, TlsConnect, TlsStream as PgTlsStream},
    Client, Config,
};

use super::{
    tls, BoxFuture, Connector, ConnectorParams, ConnectorSession, DEFAULT_CONNECT_TIMEOUT, MAX_CONNECT_TIMEOUT,
};
use crate::{pool::TlsPolicy, DynamicError};

/// PostgreSQL's identifier limit (NAMEDATALEN - 1), in bytes.
pub const MAX_IDENT_LEN: usize = 63;
const APPLICATION_NAME: &str = "bastionvault-host-connector";

/// `"name"`, with embedded `"` doubled. Refuses what PostgreSQL would
/// truncate or reject instead of letting a revoke drop a truncated name.
pub fn quote_ident(name: &str) -> Result<String, DynamicError> {
    if name.is_empty() || name.len() > MAX_IDENT_LEN || name.contains('\0') {
        return Err(DynamicError::invalid(
            "postgres identifier",
            format!("must be 1-{MAX_IDENT_LEN} bytes without NUL"),
        ));
    }
    Ok(format!("\"{}\"", name.replace('"', "\"\"")))
}

/// `'value'`, with embedded `'` doubled. Backslashes are refused: with
/// `standard_conforming_strings = off` they would escape the closing quote.
pub fn quote_literal(value: &str) -> Result<String, DynamicError> {
    if value.contains('\0') || value.contains('\\') {
        return Err(DynamicError::invalid("postgres literal", "may not contain NUL or backslash"));
    }
    Ok(format!("'{}'", value.replace('\'', "''")))
}

/// `YYYY-MM-DDTHH:MM:SSZ`, the host's `{{expiration}}` format.
fn check_expiration(value: &str) -> Result<(), DynamicError> {
    let b = value.as_bytes();
    let digits = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
    let ok = b.len() == 20
        && digits.iter().all(|&i| b[i].is_ascii_digit())
        && (b[4], b[7], b[10], b[13], b[16], b[19]) == (b'-', b'-', b'T', b':', b':', b'Z');
    if ok {
        Ok(())
    } else {
        Err(DynamicError::invalid("expiration", "not an RFC 3339 UTC timestamp"))
    }
}

/// The TLS mode to dial with. Under a verifying policy TLS is required:
/// `sslmode=prefer` would fall back to plaintext and `sslmode=disable` is
/// refused. Only the operator's insecure policy leaves the URL in charge.
pub fn effective_ssl_mode(url_mode: SslMode, policy: &TlsPolicy) -> Result<SslMode, DynamicError> {
    if !policy.verifies() {
        return Ok(url_mode);
    }
    match url_mode {
        SslMode::Disable => Err(DynamicError::invalid(
            "connection_url",
            "sets sslmode=disable but the connection verifies TLS; remove it, or set insecure_skip_tls_verify on \
             config/<name> for development",
        )),
        _ => Ok(SslMode::Require),
    }
}

/// The tokio-postgres configuration for `params` under `policy`, credentials
/// included. Checked before anything is dialled.
pub fn config_for(params: &ConnectorParams, policy: &TlsPolicy) -> Result<Config, DynamicError> {
    let endpoint = params.endpoint();
    // The parser's message can quote the URL; the URL is not secret, but keep
    // the error to its kind.
    let mut config = Config::from_str(&endpoint.url)
        .map_err(|_| DynamicError::invalid("connection_url", "not a libpq URL or key=value string"))?;
    if config.get_password().is_some() {
        return Err(DynamicError::invalid("connection_url", "must not carry a password"));
    }
    if config.get_user().is_some() {
        return Err(DynamicError::invalid("connection_url", "must not carry a user"));
    }
    if config.get_hosts().is_empty() {
        return Err(DynamicError::invalid("connection_url", "names no host"));
    }
    if config.get_hosts().iter().any(|h| !matches!(h, Host::Tcp(_))) {
        return Err(DynamicError::invalid("connection_url", "only TCP hosts are dialled, not Unix sockets"));
    }
    quote_ident(&endpoint.username)?;
    let timeout = match (params.connect_timeout(), config.get_connect_timeout()) {
        (Some(t), _) => t,
        (None, Some(t)) => (*t).min(MAX_CONNECT_TIMEOUT),
        (None, None) => DEFAULT_CONNECT_TIMEOUT,
    };
    let mode = effective_ssl_mode(config.get_ssl_mode(), policy)?;
    // tokio-postgres keeps the password in a plain buffer for the handshake;
    // the config is dropped as soon as the connection is up.
    config
        .user(&endpoint.username)
        .password(params.password())
        .ssl_mode(mode)
        .connect_timeout(timeout)
        .application_name(APPLICATION_NAME);
    Ok(config)
}

fn label(config: &Config) -> String {
    let host = match config.get_hosts().first() {
        Some(Host::Tcp(h)) => h.clone(),
        _ => "?".into(),
    };
    let port = config.get_ports().first().copied().unwrap_or(5432);
    format!("postgres://{host}:{port}")
}

/// A database error as the target's failure. The message may quote a
/// statement; [`super::execute`] redacts the call's secrets from it.
fn pg_error(e: tokio_postgres::Error) -> DynamicError {
    match e.as_db_error() {
        Some(db) => DynamicError::Execute(format!("postgres error {}: {}", db.code().code(), db.message())),
        None => DynamicError::Execute(format!("postgres: {e}")),
    }
}

/// The connector. `system_roots` is replaceable for tests.
pub struct PostgresConnector {
    system_roots: tls::RootSource,
}

impl Default for PostgresConnector {
    fn default() -> Self {
        Self { system_roots: tls::system_roots }
    }
}

impl PostgresConnector {
    pub fn with_system_roots(system_roots: tls::RootSource) -> Self {
        Self { system_roots }
    }
}

impl Connector for PostgresConnector {
    fn kind(&self) -> &'static str {
        "postgres"
    }

    fn connect<'a>(
        &'a self,
        params: &'a ConnectorParams,
        policy: &'a TlsPolicy,
    ) -> BoxFuture<'a, Result<Box<dyn ConnectorSession>, DynamicError>> {
        Box::pin(async move {
            let config = config_for(params, policy)?;
            let label = label(&config);
            let make_tls = MakeRustls(tls::client_config(policy, self.system_roots)?);
            let connected = config.connect(make_tls).await;
            drop(config);
            let (client, connection) =
                connected.map_err(|e| DynamicError::Connect { connection: label, reason: pg_error(e).to_string() })?;
            tokio::spawn(async move {
                // The connection's own error surfaces as the next statement's.
                let _ = connection.await;
            });
            Ok(Box::new(PgSession { client }) as Box<dyn ConnectorSession>)
        })
    }

    fn describe(&self, params: &ConnectorParams) -> String {
        Config::from_str(&params.endpoint().url).map(|c| label(&c)).unwrap_or_else(|_| "postgres://?".into())
    }

    fn default_revocation(&self, username: &str) -> Result<Vec<String>, DynamicError> {
        let ident = quote_ident(username)?;
        Ok(vec![format!("DROP OWNED BY {ident}"), format!("DROP ROLE IF EXISTS {ident}")])
    }

    fn default_renew(&self, username: &str, expiration: &str) -> Result<Vec<String>, DynamicError> {
        check_expiration(expiration)?;
        Ok(vec![format!("ALTER ROLE {} VALID UNTIL {}", quote_ident(username)?, quote_literal(expiration)?)])
    }

    fn default_root_rotation(&self, username: &str, password: &str) -> Result<Vec<String>, DynamicError> {
        if password.contains('\0') || password.contains('\\') {
            return Err(DynamicError::invalid("postgres literal", "may not contain NUL or backslash"));
        }
        let ident = quote_ident(username)?;
        // Built in place with room for the worst case (every character a
        // doubled `'`), so no reallocation leaves a copy of the secret behind.
        let mut out = String::with_capacity(ident.len() + 2 * password.len() + 32);
        out.push_str("ALTER ROLE ");
        out.push_str(&ident);
        out.push_str(" WITH PASSWORD '");
        for c in password.chars() {
            if c == '\'' {
                out.push_str("''");
            } else {
                out.push(c);
            }
        }
        out.push('\'');
        Ok(vec![out])
    }
}

struct PgSession {
    client: Client,
}

impl ConnectorSession for PgSession {
    fn validate(&mut self) -> BoxFuture<'_, Result<(), DynamicError>> {
        Box::pin(async move {
            if self.client.is_closed() {
                return Err(DynamicError::Execute("the pooled postgres connection is closed".into()));
            }
            self.client.simple_query("SELECT 1").await.map(|_| ()).map_err(pg_error)
        })
    }

    fn execute_in_transaction<'a>(&'a mut self, statements: &'a [&'a str]) -> BoxFuture<'a, Result<(), DynamicError>> {
        Box::pin(async move {
            let tx = self.client.transaction().await.map_err(pg_error)?;
            for s in statements {
                tx.batch_execute(s).await.map_err(pg_error)?;
            }
            tx.commit().await.map_err(pg_error)
        })
    }

    fn identity_exists<'a>(&'a mut self, name: &'a str) -> BoxFuture<'a, Result<bool, DynamicError>> {
        Box::pin(async move {
            let row = self
                .client
                .query_opt("SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1", &[&name])
                .await
                .map_err(pg_error)?;
            Ok(row.is_some())
        })
    }
}

/// tokio-postgres' TLS hook over [`tls::connect_tls`]. No channel binding is
/// offered (SCRAM-SHA-256 without `-PLUS`); certificate checks are rustls'.
#[derive(Clone)]
struct MakeRustls(Arc<ClientConfig>);

impl<S> MakeTlsConnect<S> for MakeRustls
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = PgStream<S>;
    type TlsConnect = RustlsConnect;
    type Error = io::Error;

    fn make_tls_connect(&mut self, domain: &str) -> Result<RustlsConnect, io::Error> {
        Ok(RustlsConnect { config: self.0.clone(), name: domain.to_string() })
    }
}

struct RustlsConnect {
    config: Arc<ClientConfig>,
    name: String,
}

impl<S> TlsConnect<S> for RustlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = PgStream<S>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<PgStream<S>>> + Send>>;

    fn connect(self, stream: S) -> Self::Future {
        match tls::connect_tls(self.config, &self.name, stream) {
            Ok(handshake) => Box::pin(async move { handshake.await.map(PgStream) }),
            Err(e) => Box::pin(async move { Err(e) }),
        }
    }
}

struct PgStream<S>(tls::TlsStream<S>);

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for PgStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for PgStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> PgTlsStream for PgStream<S> {
    fn channel_binding(&self) -> ChannelBinding {
        ChannelBinding::none()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn params(url: &str) -> ConnectorParams {
        ConnectorParams::parse(&json!({
            "kind": "postgres", "url": url, "username": "vault", "password": "root-secret-123"
        }))
        .unwrap()
    }

    #[test]
    fn urls_carrying_credentials_or_sockets_are_refused() {
        let verify = TlsPolicy::default();
        assert!(config_for(&params("postgres://db.internal:5432/app"), &verify).is_ok());
        assert!(config_for(&params("host=db.internal dbname=app"), &verify).is_ok());
        for bad in [
            "postgres://u:p@db.internal/app",
            "host=db.internal password=p",
            "host=db.internal user=u",
            "postgres:///app",
            "host=db.internal bogus_option=1",
            "host=/var/run/postgresql dbname=app",
        ] {
            let e = config_for(&params(bad), &verify).expect_err(bad);
            assert!(!e.to_string().contains("root-secret-123"), "{e}");
        }
        let c = config_for(&params("postgres://db.internal/app"), &verify).unwrap();
        assert_eq!(c.get_connect_timeout(), Some(&DEFAULT_CONNECT_TIMEOUT));
        assert_eq!(c.get_ssl_mode(), SslMode::Require, "a verifying policy requires TLS");
        assert!(!format!("{:?}", params("postgres://db.internal/app")).contains("root-secret-123"));
    }

    #[test]
    fn verified_policies_require_tls_and_refuse_disable() {
        let verify = TlsPolicy::default();
        assert_eq!(effective_ssl_mode(SslMode::Prefer, &verify).unwrap(), SslMode::Require);
        assert!(effective_ssl_mode(SslMode::Disable, &verify).is_err(), "no silent downgrade");
        assert!(config_for(&params("host=db.internal sslmode=disable"), &verify).is_err());
        let insecure = TlsPolicy::insecure_skip_verify();
        assert_eq!(effective_ssl_mode(SslMode::Disable, &insecure).unwrap(), SslMode::Disable);
        let c = config_for(&params("host=db.internal sslmode=disable"), &insecure).unwrap();
        assert_eq!(c.get_ssl_mode(), SslMode::Disable, "plaintext only under the operator's insecure policy");
    }

    #[test]
    fn default_statements_are_quoted() {
        let pg = PostgresConnector::default();
        assert_eq!(pg.default_revocation("v-u").unwrap(), ["DROP OWNED BY \"v-u\"", "DROP ROLE IF EXISTS \"v-u\""]);
        assert_eq!(
            pg.default_renew("v-u", "2026-10-26T18:32:11Z").unwrap(),
            ["ALTER ROLE \"v-u\" VALID UNTIL '2026-10-26T18:32:11Z'"]
        );
        assert!(pg.default_renew("v-u", "2026-10-26T18:32:11Z'; DROP ROLE x; --").is_err());
        assert!(pg.default_revocation(&"a".repeat(64)).is_err(), "would be truncated to another name");
        assert_eq!(quote_ident("a\"; DROP TABLE x; --").unwrap(), "\"a\"\"; DROP TABLE x; --\"");
        assert!(quote_literal("a\\'; DROP").is_err());
        assert_eq!(
            pg.default_root_rotation("vault", "it's-Ab1").unwrap(),
            ["ALTER ROLE \"vault\" WITH PASSWORD 'it''s-Ab1'"]
        );
        assert!(pg.default_root_rotation("vault", "back\\slash").is_err(), "refused, never mis-quoted");
    }

    /// Against a closed local port: the dial fails as a connect error, with
    /// the root secret nowhere in it. No server is needed.
    #[tokio::test]
    async fn a_failed_dial_names_the_target_not_the_secret() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let p = params(&format!("host=127.0.0.1 port={port} connect_timeout=2"));
        let err = match PostgresConnector::default().connect(&p, &TlsPolicy::insecure_skip_verify()).await {
            Ok(_) => panic!("nothing listens there"),
            Err(e) => e,
        };
        assert!(matches!(err, DynamicError::Connect { .. }), "{err}");
        assert!(err.to_string().contains("127.0.0.1"), "{err}");
        assert!(!err.to_string().contains("root-secret-123"), "{err}");
    }
}
