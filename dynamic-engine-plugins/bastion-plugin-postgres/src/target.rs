//! The PostgreSQL side: where a connection points, how to reach it, and the
//! two things the plugin does there (run statements in a transaction, check
//! whether a role exists). Behind [`Connector`] / [`Session`] so the engine
//! is tested against a fake without a database.

use std::{str::FromStr, time::Duration};

use async_trait::async_trait;
use bastion_plugin_dynamic_sdk::{Connection, DynamicError, SecretString, TlsPolicy};
use tokio_postgres::config::SslMode;

use crate::{sql::quote_ident, tls};

/// Used when `connect_timeout_secs` is unset: well inside the host's 30 s
/// per-call budget.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const APPLICATION_NAME: &str = "bastionvault-dynamic";

/// One connection's coordinates and root credential.
#[derive(Debug, Clone)]
pub struct Target {
    /// Parsed `connection_url`, never holding a user or password.
    pub config: tokio_postgres::Config,
    pub username: String,
    pub password: SecretString,
}

impl Target {
    /// Read and check a stored connection. The URL may not carry credentials:
    /// a read of `config/<name>` returns it, so a password there would leak.
    pub fn from_connection(conn: &Connection) -> Result<Self, DynamicError> {
        let url = conn.setting_str("connection_url").unwrap_or_default();
        let mut config = tokio_postgres::Config::from_str(url).map_err(|e| {
            DynamicError::invalid(format!("connection_url is not a libpq URL or key=value string: {e}"))
        })?;
        if config.get_password().is_some() {
            return Err(DynamicError::invalid("connection_url must not carry a password; set `password`"));
        }
        if config.get_user().is_some() {
            return Err(DynamicError::invalid("connection_url must not carry a user; set `username`"));
        }
        if config.get_hosts().is_empty() {
            return Err(DynamicError::invalid("connection_url names no host"));
        }
        let username = conn.setting_str("username").unwrap_or_default().to_string();
        quote_ident(&username)?;
        let password = conn.secret("password").cloned().unwrap_or_default();
        if password.is_empty() {
            return Err(DynamicError::invalid("the connection has no root `password`"));
        }
        match conn.setting("connect_timeout_secs").and_then(|v| v.as_u64()) {
            Some(0) => return Err(DynamicError::invalid("connect_timeout_secs must be positive")),
            Some(s) => {
                config.connect_timeout(Duration::from_secs(s.min(25)));
            }
            None if config.get_connect_timeout().is_none() => {
                config.connect_timeout(DEFAULT_CONNECT_TIMEOUT);
            }
            None => {}
        }
        Ok(Self { config, username, password })
    }
}

/// The TLS mode to dial with. When the host's policy verifies, TLS is
/// required: `sslmode=prefer` would fall back to plaintext and
/// `sslmode=disable` is refused, never silently honoured. Only the
/// operator's `insecure_skip_tls_verify` leaves the URL's sslmode in charge.
pub fn effective_ssl_mode(url_mode: SslMode, policy: &TlsPolicy) -> Result<SslMode, DynamicError> {
    if !policy.verify {
        return Ok(url_mode);
    }
    match url_mode {
        SslMode::Disable => Err(DynamicError::invalid(
            "connection_url sets sslmode=disable but the connection verifies TLS; remove it, or set \
             insecure_skip_tls_verify on config/<name> for development",
        )),
        _ => Ok(SslMode::Require),
    }
}

#[async_trait(?Send)]
pub trait Session {
    /// Run `statements` in one transaction: all or nothing.
    async fn execute_in_transaction(&mut self, statements: &[&str]) -> Result<(), DynamicError>;
    async fn role_exists(&mut self, name: &str) -> Result<bool, DynamicError>;
}

#[async_trait(?Send)]
pub trait Connector {
    async fn connect(&self, target: &Target, tls: &TlsPolicy) -> Result<Box<dyn Session>, DynamicError>;
}

/// A database error as the target's failure. The message may quote a
/// statement; the SDK redacts the call's secrets from it before it leaves.
pub fn sql_error(e: tokio_postgres::Error) -> DynamicError {
    match e.as_db_error() {
        Some(db) => DynamicError::target(format!("postgres error {}: {}", db.code().code(), db.message())),
        None => DynamicError::target(format!("postgres: {e}")),
    }
}

/// The real connector: tokio-postgres over rustls.
pub struct PgConnector {
    system_roots: tls::RootSource,
}

impl PgConnector {
    pub fn new(system_roots: tls::RootSource) -> Self {
        Self { system_roots }
    }
}

impl Default for PgConnector {
    fn default() -> Self {
        Self::new(tls::system_roots)
    }
}

#[async_trait(?Send)]
impl Connector for PgConnector {
    async fn connect(&self, target: &Target, policy: &TlsPolicy) -> Result<Box<dyn Session>, DynamicError> {
        let mode = effective_ssl_mode(target.config.get_ssl_mode(), policy)?;
        let make_tls = tls::MakeRustls::new(tls::client_config(policy, self.system_roots)?);
        // tokio-postgres keeps the password in a plain buffer for the
        // handshake; `config` is dropped as soon as it is connected.
        let mut config = target.config.clone();
        config
            .user(&target.username)
            .password(target.password.expose())
            .ssl_mode(mode)
            .application_name(APPLICATION_NAME);
        let (client, connection) = config.connect(make_tls).await.map_err(sql_error)?;
        drop(config);
        tokio::spawn(async move {
            // The connection's own error is the next statement's error.
            let _ = connection.await;
        });
        Ok(Box::new(PgSession { client }))
    }
}

struct PgSession {
    client: tokio_postgres::Client,
}

#[async_trait(?Send)]
impl Session for PgSession {
    async fn execute_in_transaction(&mut self, statements: &[&str]) -> Result<(), DynamicError> {
        let tx = self.client.transaction().await.map_err(sql_error)?;
        for s in statements {
            tx.batch_execute(s).await.map_err(sql_error)?;
        }
        tx.commit().await.map_err(sql_error)
    }

    async fn role_exists(&mut self, name: &str) -> Result<bool, DynamicError> {
        let row = self
            .client
            .query_opt("SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1", &[&name])
            .await
            .map_err(sql_error)?;
        Ok(row.is_some())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn conn(fields: serde_json::Value) -> Connection {
        let mut c = Connection::new("prod");
        c.apply_input(&crate::SCHEMA, fields.as_object().unwrap()).unwrap();
        c
    }

    #[test]
    fn urls_carrying_credentials_are_refused() {
        let base = json!({ "username": "vault", "password": "root-secret-123" });
        let with = |url: &str| {
            let mut v = base.clone();
            v["connection_url"] = json!(url);
            Target::from_connection(&conn(v))
        };
        assert!(with("postgres://db.internal:5432/app").is_ok());
        assert!(with("host=db.internal dbname=app").is_ok());
        assert!(with("postgres://u:p@db.internal/app").is_err());
        assert!(with("host=db.internal password=p").is_err());
        assert!(with("host=db.internal user=u").is_err());
        assert!(with("postgres:///app").is_err(), "no host");
        assert!(with("host=db.internal bogus_option=1").is_err());
        let t = with("postgres://db.internal/app").unwrap();
        assert_eq!(t.config.get_connect_timeout(), Some(&DEFAULT_CONNECT_TIMEOUT));
        assert!(!format!("{t:?}").contains("root-secret-123"));
    }

    #[test]
    fn verified_policies_require_tls_and_refuse_disable() {
        let verify = TlsPolicy::default();
        assert_eq!(effective_ssl_mode(SslMode::Prefer, &verify).unwrap(), SslMode::Require);
        assert_eq!(effective_ssl_mode(SslMode::Require, &verify).unwrap(), SslMode::Require);
        assert!(effective_ssl_mode(SslMode::Disable, &verify).is_err(), "no silent downgrade");
        let insecure = TlsPolicy { verify: false, ca_pem: None };
        assert_eq!(effective_ssl_mode(SslMode::Disable, &insecure).unwrap(), SslMode::Disable);
    }
}
