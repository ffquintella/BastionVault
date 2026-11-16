//! `idp/ldap/` on the root system view: the directory's configuration
//! (with the TLS key), client records (each bound to one environment) and
//! one-time bind passcodes. Records are JSON `version: 1`, unknown versions
//! and fields refused; no read path returns the key or a passcode. Writes
//! take a process-local mutex plus the storage lock, as the other stores do.

use std::{any::Any, fmt, net::IpAddr, sync::Arc};

use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::{directory::Layout, dn::Dn};
use crate::{
    entitlement::{
        model::{validate_description, EnvironmentState},
        store::EntitlementStore,
    },
    errors::RvError,
    posix::model::{decode_versioned, validate_entity_id, PosixError, RECORD_VERSION},
    provider::radius::{
        store::{
            canonical_ip, generate_passcode, is_passcode_format, validate_listen, validate_name, PasscodeRecord,
            DEFAULT_PASSCODE_MAX_TTL_SECS, DEFAULT_PASSCODE_TTL_SECS, MAX_OUTSTANDING_PASSCODES, MIN_PASSCODE_TTL_SECS,
            PASSCODE_TTL_CEILING_SECS,
        },
        tls::{self, hex, validate_fingerprint},
    },
    storage::{Storage, StorageEntry},
};

pub const STORAGE_LOCK_NAME: &str = "bv-idp/ldap";
const CONFIG_KEY: &str = "config";
pub const CLIENT_PREFIX: &str = "clients/";
const CERT_INDEX: &str = "index/cert/";
const ADDR_INDEX: &str = "index/addr/";
pub const PASSCODE_PREFIX: &str = "passcodes/";

pub const DEFAULT_BASE_DN: &str = "dc=bastionvault";
pub const DEFAULT_HOME_BASE: &str = "/home";
pub const DEFAULT_LOGIN_SHELL: &str = "/bin/bash";
pub const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 600;
pub const MAX_RATE_LIMIT_PER_MINUTE: u32 = 60_000;
pub const DEFAULT_SIZE_LIMIT: u32 = 1000;
pub const MAX_SIZE_LIMIT: u32 = 10_000;
pub const DEFAULT_TIME_LIMIT_SECS: u32 = 10;
pub const MAX_TIME_LIMIT_SECS: u32 = 60;
const MAX_PATH_LEN: usize = 128;
const MAX_BASE_RDNS: usize = 8;

static LOCAL_WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Both halves of the write lock; field order is drop order.
struct WriteLock {
    _cluster: Box<dyn Any + Send>,
    _local: tokio::sync::MutexGuard<'static, ()>,
}

/// How a client reaches the directory and is recognised: `tls` by the
/// SHA-256 of its certificate (LDAPS or StartTLS), `plain` by its source
/// address over cleartext LDAP, which only `plaintext_enabled` admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tls,
    Plain,
}

impl Transport {
    pub fn parse(s: &str) -> Result<Self, PosixError> {
        match s {
            "tls" => Ok(Self::Tls),
            "plain" => Ok(Self::Plain),
            _ => Err(PosixError::Invalid("transport must be `tls` or `plain`".into())),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Plain => "plain",
        }
    }
}

/// An absolute path for `homeDirectory` / `loginShell`.
fn validate_path(field: &str, p: &str) -> Result<String, PosixError> {
    let p = if p.len() > 1 { p.trim_end_matches('/') } else { p };
    let ok = p.len() > 1
        && p.len() <= MAX_PATH_LEN
        && p.starts_with('/')
        && p.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
        && p.split('/').skip(1).all(|seg| !seg.is_empty() && seg != "." && seg != "..");
    if ok {
        Ok(p.to_string())
    } else {
        Err(PosixError::Invalid(format!(
            "{field} must be an absolute path of [A-Za-z0-9/._-], without empty, `.` or `..` segments \
             (max {MAX_PATH_LEN})"
        )))
    }
}

fn validate_base_dn(s: &str) -> Result<Dn, PosixError> {
    let dn = Dn::parse(s).map_err(|_| {
        PosixError::Invalid("base_dn must be `type=value` RDNs of [A-Za-z0-9 ._-], without escapes".into())
    })?;
    if dn.is_root() || dn.rdn_count() > MAX_BASE_RDNS {
        return Err(PosixError::Invalid(format!("base_dn must have 1-{MAX_BASE_RDNS} RDNs")));
    }
    Ok(dn)
}

// ─── Configuration ──────────────────────────────────────────────────

/// `idp/ldap/config`. Absent means the directory is off. `Debug` never
/// prints the PEM fields.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LdapConfig {
    pub version: u32,
    pub enabled: bool,
    /// LDAPS (implicit TLS): the default transport.
    pub ldaps_listen: Option<String>,
    /// Cleartext port: StartTLS when the TLS material is set, and plain
    /// operations only with `plaintext_enabled`.
    pub ldap_listen: Option<String>,
    pub plaintext_enabled: bool,
    pub allow_unspecified_bind: bool,
    pub tls_cert_pem: Option<String>,
    pub tls_key_pem: Option<String>,
    pub client_ca_pem: Option<String>,
    pub base_dn: String,
    pub home_directory_base: String,
    pub login_shell: String,
    pub size_limit: u32,
    pub time_limit_secs: u32,
    pub rate_limit_per_minute: u32,
    pub passcode_default_ttl_secs: u64,
    pub passcode_max_ttl_secs: u64,
    pub updated_at: DateTime<Utc>,
}

impl Drop for LdapConfig {
    fn drop(&mut self) {
        if let Some(key) = self.tls_key_pem.as_mut() {
            key.zeroize();
        }
    }
}

impl fmt::Debug for LdapConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LdapConfig")
            .field("enabled", &self.enabled)
            .field("ldaps_listen", &self.ldaps_listen)
            .field("ldap_listen", &self.ldap_listen)
            .field("plaintext_enabled", &self.plaintext_enabled)
            .field("base_dn", &self.base_dn)
            .finish_non_exhaustive()
    }
}

impl LdapConfig {
    pub fn ldaps_addr(&self) -> Option<std::net::SocketAddr> {
        self.ldaps_listen.as_deref().and_then(|a| a.parse().ok())
    }

    pub fn ldap_addr(&self) -> Option<std::net::SocketAddr> {
        self.ldap_listen.as_deref().and_then(|a| a.parse().ok())
    }

    pub fn has_tls(&self) -> bool {
        self.tls_cert_pem.is_some() && self.tls_key_pem.is_some() && self.client_ca_pem.is_some()
    }

    pub fn layout(&self) -> Result<Layout, PosixError> {
        Ok(Layout {
            base: validate_base_dn(&self.base_dn)?,
            home_base: self.home_directory_base.clone(),
            shell: self.login_shell.clone(),
        })
    }

    /// Identifies the TLS material, in memory only, so a listener restarts
    /// when it changes.
    pub fn tls_digest(&self) -> String {
        let mut h = Sha256::new();
        for part in [&self.tls_cert_pem, &self.tls_key_pem, &self.client_ca_pem] {
            let bytes = part.as_deref().unwrap_or("").as_bytes();
            h.update((bytes.len() as u64).to_be_bytes());
            h.update(bytes);
        }
        hex(&h.finalize())
    }

    /// The listeners' TLS: a client certificate is required and must chain
    /// to `client_ca_pem` (the RadSec configuration, reused).
    pub fn tls_server_config(&self) -> Result<Arc<rustls::ServerConfig>, PosixError> {
        match (&self.tls_cert_pem, &self.tls_key_pem, &self.client_ca_pem) {
            (Some(cert), Some(key), Some(ca)) => tls::server_config(cert, key, ca),
            _ => Err(PosixError::Invalid("TLS needs tls_cert_pem, tls_key_pem and client_ca_pem".into())),
        }
    }

    pub fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("enabled".into(), self.enabled.into());
        m.insert("ldaps_listen".into(), self.ldaps_listen.clone().into());
        m.insert("ldap_listen".into(), self.ldap_listen.clone().into());
        m.insert("plaintext_enabled".into(), self.plaintext_enabled.into());
        m.insert("starttls".into(), (self.ldap_listen.is_some() && self.has_tls()).into());
        m.insert("allow_unspecified_bind".into(), self.allow_unspecified_bind.into());
        m.insert("tls_cert_pem".into(), self.tls_cert_pem.clone().into());
        m.insert("tls_key_set".into(), self.tls_key_pem.is_some().into());
        m.insert("client_ca_pem".into(), self.client_ca_pem.clone().into());
        m.insert("base_dn".into(), self.base_dn.clone().into());
        m.insert("home_directory_base".into(), self.home_directory_base.clone().into());
        m.insert("login_shell".into(), self.login_shell.clone().into());
        m.insert("size_limit".into(), self.size_limit.into());
        m.insert("time_limit".into(), self.time_limit_secs.into());
        m.insert("rate_limit_per_minute".into(), self.rate_limit_per_minute.into());
        m.insert("passcode_default_ttl".into(), self.passcode_default_ttl_secs.into());
        m.insert("passcode_max_ttl".into(), self.passcode_max_ttl_secs.into());
        m.insert("passcode_ttl_ceiling".into(), PASSCODE_TTL_CEILING_SECS.into());
        m.insert("updated_at".into(), self.updated_at.to_rfc3339().into());
        m
    }

    fn validate(&self) -> Result<(), PosixError> {
        let allow = self.allow_unspecified_bind;
        let any_tls = self.tls_cert_pem.is_some() || self.tls_key_pem.is_some() || self.client_ca_pem.is_some();
        if any_tls {
            self.tls_server_config()?;
        }
        if let Some(addr) = &self.ldaps_listen {
            validate_listen("ldaps_listen", addr, allow)?;
            if !self.has_tls() {
                return Err(PosixError::Invalid(
                    "ldaps_listen needs tls_cert_pem, tls_key_pem and client_ca_pem".into(),
                ));
            }
        }
        if let Some(addr) = &self.ldap_listen {
            validate_listen("ldap_listen", addr, allow)?;
            if !self.has_tls() && !self.plaintext_enabled {
                return Err(PosixError::Invalid(
                    "ldap_listen needs the TLS material (StartTLS) or plaintext_enabled".into(),
                ));
            }
        }
        if self.ldaps_addr().is_some_and(|a| a.port() != 0) && self.ldaps_addr() == self.ldap_addr() {
            return Err(PosixError::Invalid("ldaps_listen and ldap_listen must differ".into()));
        }
        if self.plaintext_enabled && self.ldap_listen.is_none() {
            return Err(PosixError::Invalid("plaintext_enabled needs ldap_listen".into()));
        }
        if self.enabled && self.ldaps_listen.is_none() && self.ldap_listen.is_none() {
            return Err(PosixError::Invalid("an enabled directory needs ldaps_listen or ldap_listen".into()));
        }
        self.layout()?;
        if !(1..=MAX_SIZE_LIMIT).contains(&self.size_limit) {
            return Err(PosixError::Invalid(format!("size_limit must lie within [1, {MAX_SIZE_LIMIT}]")));
        }
        if !(1..=MAX_TIME_LIMIT_SECS).contains(&self.time_limit_secs) {
            return Err(PosixError::Invalid(format!("time_limit must lie within [1, {MAX_TIME_LIMIT_SECS}] seconds")));
        }
        if !(1..=MAX_RATE_LIMIT_PER_MINUTE).contains(&self.rate_limit_per_minute) {
            return Err(PosixError::Invalid(format!(
                "rate_limit_per_minute must lie within [1, {MAX_RATE_LIMIT_PER_MINUTE}]"
            )));
        }
        let (default_ttl, max_ttl) = (self.passcode_default_ttl_secs, self.passcode_max_ttl_secs);
        if !(MIN_PASSCODE_TTL_SECS..=PASSCODE_TTL_CEILING_SECS).contains(&max_ttl)
            || !(MIN_PASSCODE_TTL_SECS..=max_ttl).contains(&default_ttl)
        {
            return Err(PosixError::Invalid(format!(
                "passcode TTLs must satisfy {MIN_PASSCODE_TTL_SECS} <= passcode_default_ttl <= passcode_max_ttl \
                 <= {PASSCODE_TTL_CEILING_SECS} seconds"
            )));
        }
        Ok(())
    }
}

/// A partial update. For the optional strings, `Some("")` clears the field.
#[derive(Default)]
pub struct ConfigUpdate {
    pub enabled: Option<bool>,
    pub ldaps_listen: Option<String>,
    pub ldap_listen: Option<String>,
    pub plaintext_enabled: Option<bool>,
    pub allow_unspecified_bind: Option<bool>,
    pub tls_cert_pem: Option<String>,
    pub tls_key_pem: Option<Zeroizing<String>>,
    pub client_ca_pem: Option<String>,
    pub base_dn: Option<String>,
    pub home_directory_base: Option<String>,
    pub login_shell: Option<String>,
    pub size_limit: Option<u32>,
    pub time_limit_secs: Option<u32>,
    pub rate_limit_per_minute: Option<u32>,
    pub passcode_default_ttl_secs: Option<u64>,
    pub passcode_max_ttl_secs: Option<u64>,
}

fn merge_text(update: Option<String>, current: Option<String>) -> Option<String> {
    match update {
        Some(s) if s.trim().is_empty() => None,
        Some(s) => Some(s),
        None => current,
    }
}

// ─── Clients ────────────────────────────────────────────────────────

/// `idp/ldap/clients/<name>`: one host or service, bound for life to one
/// environment, whose identities are the only ones it can see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LdapClient {
    pub version: u32,
    pub name: String,
    pub transport: Transport,
    pub environment: String,
    /// `tls`: SHA-256 of the client certificate (DER), lower-case hex.
    pub cert_sha256: Option<String>,
    /// `plain`: the source address, canonical form.
    pub address: Option<String>,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl LdapClient {
    fn index_key(&self) -> Option<String> {
        match self.transport {
            Transport::Tls => self.cert_sha256.as_ref().map(|fp| format!("{CERT_INDEX}{fp}")),
            Transport::Plain => self.address.as_ref().map(|a| format!("{ADDR_INDEX}{a}")),
        }
    }

    pub fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("name".into(), self.name.clone().into());
        m.insert("transport".into(), self.transport.as_str().into());
        m.insert("environment".into(), self.environment.clone().into());
        m.insert("cert_sha256".into(), self.cert_sha256.clone().into());
        m.insert("address".into(), self.address.clone().into());
        m.insert("description".into(), self.description.clone().into());
        m.insert("created_at".into(), self.created_at.to_rfc3339().into());
        m.insert("updated_at".into(), self.updated_at.to_rfc3339().into());
        m
    }
}

fn validate_client_address(addr: &str) -> Result<String, PosixError> {
    let ip: IpAddr =
        addr.trim().parse().map_err(|_| PosixError::Invalid("address must be the client's IP address".into()))?;
    let ip = canonical_ip(ip);
    if ip.is_unspecified() || ip.is_multicast() || ip == IpAddr::from([255, 255, 255, 255]) {
        return Err(PosixError::Invalid("address must be a unicast host address".into()));
    }
    Ok(ip.to_string())
}

/// Create-or-update of a client. `transport` and `environment` are fixed
/// at creation (an update may restate them).
#[derive(Default)]
pub struct ClientWrite {
    pub name: String,
    pub transport: Option<Transport>,
    pub environment: Option<String>,
    pub cert_sha256: Option<String>,
    pub address: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientIndex {
    version: u32,
    client: String,
}

// ─── Passcodes ──────────────────────────────────────────────────────

fn passcode_dir(entity_id: &str) -> String {
    format!("{PASSCODE_PREFIX}{entity_id}/")
}

fn passcode_key(entity_id: &str, code: &[u8]) -> String {
    format!("{}{}", passcode_dir(entity_id), hex(&Sha256::digest(code)))
}

// ─── Store ──────────────────────────────────────────────────────────

pub struct LdapStore {
    storage: Arc<dyn Storage>,
}

#[maybe_async::maybe_async]
impl LdapStore {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }

    async fn write_lock(&self) -> Result<WriteLock, RvError> {
        let local = LOCAL_WRITE_LOCK.lock().await;
        let cluster = self.storage.lock(STORAGE_LOCK_NAME).await?;
        Ok(WriteLock { _cluster: cluster, _local: local })
    }

    async fn get_record<T: DeserializeOwned>(&self, what: &str, key: &str) -> Result<Option<T>, RvError> {
        match self.storage.get(key).await? {
            None => Ok(None),
            Some(entry) => {
                let value = Zeroizing::new(entry.value);
                Ok(Some(decode_versioned(what, &value)?))
            }
        }
    }

    async fn put_record<T: Serialize + Sync>(&self, key: &str, value: &T) -> Result<(), RvError> {
        let mut entry = StorageEntry::new(key, value)?;
        let result = self.storage.put(&entry).await;
        entry.value.zeroize();
        result
    }

    // ─── Configuration ──────────────────────────────────────────

    pub async fn config(&self) -> Result<Option<LdapConfig>, RvError> {
        self.get_record("ldap config", CONFIG_KEY).await
    }

    pub async fn put_config(&self, update: ConfigUpdate, now: DateTime<Utc>) -> Result<LdapConfig, RvError> {
        let _lock = self.write_lock().await?;
        let current = self.config().await?;
        let cur = current.as_ref();
        let text = |u: Option<String>, c: Option<&String>, d: &str| -> String {
            match u {
                Some(s) if !s.trim().is_empty() => s.trim().to_string(),
                _ => c.cloned().unwrap_or_else(|| d.to_string()),
            }
        };
        let base_dn = text(update.base_dn, cur.map(|c| &c.base_dn), DEFAULT_BASE_DN);
        let home = text(update.home_directory_base, cur.map(|c| &c.home_directory_base), DEFAULT_HOME_BASE);
        let shell = text(update.login_shell, cur.map(|c| &c.login_shell), DEFAULT_LOGIN_SHELL);
        let mut cfg = LdapConfig {
            version: RECORD_VERSION,
            enabled: update.enabled.or(cur.map(|c| c.enabled)).unwrap_or(false),
            ldaps_listen: merge_text(update.ldaps_listen, cur.and_then(|c| c.ldaps_listen.clone())),
            ldap_listen: merge_text(update.ldap_listen, cur.and_then(|c| c.ldap_listen.clone())),
            plaintext_enabled: update.plaintext_enabled.or(cur.map(|c| c.plaintext_enabled)).unwrap_or(false),
            allow_unspecified_bind: update
                .allow_unspecified_bind
                .or(cur.map(|c| c.allow_unspecified_bind))
                .unwrap_or(false),
            tls_cert_pem: merge_text(update.tls_cert_pem, cur.and_then(|c| c.tls_cert_pem.clone())),
            tls_key_pem: merge_text(update.tls_key_pem.map(|k| k.to_string()), cur.and_then(|c| c.tls_key_pem.clone())),
            client_ca_pem: merge_text(update.client_ca_pem, cur.and_then(|c| c.client_ca_pem.clone())),
            base_dn,
            home_directory_base: validate_path("home_directory_base", &home)?,
            login_shell: validate_path("login_shell", &shell)?,
            size_limit: update.size_limit.or(cur.map(|c| c.size_limit)).unwrap_or(DEFAULT_SIZE_LIMIT),
            time_limit_secs: update
                .time_limit_secs
                .or(cur.map(|c| c.time_limit_secs))
                .unwrap_or(DEFAULT_TIME_LIMIT_SECS),
            rate_limit_per_minute: update
                .rate_limit_per_minute
                .or(cur.map(|c| c.rate_limit_per_minute))
                .unwrap_or(DEFAULT_RATE_LIMIT_PER_MINUTE),
            passcode_max_ttl_secs: update
                .passcode_max_ttl_secs
                .or(cur.map(|c| c.passcode_max_ttl_secs))
                .unwrap_or(DEFAULT_PASSCODE_MAX_TTL_SECS),
            passcode_default_ttl_secs: update
                .passcode_default_ttl_secs
                .or(cur.map(|c| c.passcode_default_ttl_secs))
                .unwrap_or(DEFAULT_PASSCODE_TTL_SECS),
            updated_at: now,
        };
        cfg.validate()?;
        // Stored in normalised form, so every DN served is stable.
        cfg.base_dn = cfg.layout()?.base.to_string();
        self.put_record(CONFIG_KEY, &cfg).await?;
        log::info!(
            target: "idp",
            "idp.ldap.config: enabled={} ldaps_listen={:?} ldap_listen={:?} plaintext_enabled={} base_dn={}",
            cfg.enabled,
            cfg.ldaps_listen,
            cfg.ldap_listen,
            cfg.plaintext_enabled,
            cfg.base_dn
        );
        if cfg.plaintext_enabled {
            log::warn!(
                target: "security",
                "idp.ldap.config: cleartext LDAP is enabled; directory data and bind passcodes cross the \
                 network unencrypted, use it on a trusted segment only"
            );
        }
        Ok(cfg)
    }

    // ─── Clients ────────────────────────────────────────────────

    pub async fn get_client(&self, name: &str) -> Result<Option<LdapClient>, RvError> {
        validate_name("client", name)?;
        let rec: Option<LdapClient> = self.get_record("ldap client", &format!("{CLIENT_PREFIX}{name}")).await?;
        if rec.as_ref().is_some_and(|r| r.name != name) {
            return Err(PosixError::Corrupt(format!("ldap client record `{name}` names another client")).into());
        }
        Ok(rec)
    }

    pub async fn list_clients(&self) -> Result<Vec<LdapClient>, RvError> {
        let mut out = Vec::new();
        for entry in self.storage.scan(CLIENT_PREFIX, None).await? {
            out.push(decode_versioned::<LdapClient>("ldap client", &entry.value)?);
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn client_by_index(&self, key: &str) -> Result<Option<LdapClient>, RvError> {
        let Some(idx) = self.get_record::<ClientIndex>("ldap client index", key).await? else {
            return Ok(None);
        };
        let Some(client) = self.get_client(&idx.client).await? else {
            return Ok(None);
        };
        // The index must agree with the record it points at.
        Ok((client.index_key().as_deref() == Some(key)).then_some(client))
    }

    /// The `tls` client pinned to a certificate fingerprint, read live.
    pub async fn client_for_cert(&self, fingerprint: &str) -> Result<Option<LdapClient>, RvError> {
        validate_fingerprint(fingerprint)?;
        let key = format!("{CERT_INDEX}{fingerprint}");
        Ok(self.client_by_index(&key).await?.filter(|c| c.transport == Transport::Tls))
    }

    /// The `plain` client registered for a source address, read live.
    pub async fn client_for_addr(&self, ip: IpAddr) -> Result<Option<LdapClient>, RvError> {
        let key = format!("{ADDR_INDEX}{}", canonical_ip(ip));
        Ok(self.client_by_index(&key).await?.filter(|c| c.transport == Transport::Plain))
    }

    pub async fn put_client(
        &self,
        authz: &EntitlementStore,
        w: ClientWrite,
        now: DateTime<Utc>,
    ) -> Result<(LdapClient, bool), RvError> {
        validate_name("client", &w.name)?;
        if let Some(d) = &w.description {
            validate_description(d)?;
        }
        let _lock = self.write_lock().await?;
        let current = self.get_client(&w.name).await?;
        let created = current.is_none();
        let cur = current.as_ref();
        let fixed = |what: &str| PosixError::Invalid(format!("a client's {what} is fixed at creation"));
        let transport = match (w.transport, cur) {
            (Some(t), Some(c)) if t != c.transport => return Err(fixed("transport").into()),
            (Some(t), _) => t,
            (None, Some(c)) => c.transport,
            (None, None) => return Err(PosixError::Invalid("transport is required to create a client".into()).into()),
        };
        let environment = match (w.environment, cur) {
            (Some(e), Some(c)) if e != c.environment => return Err(fixed("environment").into()),
            (Some(e), _) => e,
            (None, Some(c)) => c.environment.clone(),
            (None, None) => return Err(PosixError::Invalid("environment is required to create a client".into()).into()),
        };
        let env = authz
            .get_environment(&environment)
            .await?
            .ok_or_else(|| PosixError::NotFound(format!("no environment `{environment}`")))?;
        if env.state != EnvironmentState::Active {
            return Err(PosixError::Conflict(format!("environment `{environment}` is retired")).into());
        }
        let (cert_sha256, address) = match transport {
            Transport::Tls => {
                if w.address.is_some() {
                    return Err(PosixError::Invalid("address applies to plain clients only".into()).into());
                }
                let fp = match w.cert_sha256 {
                    Some(fp) => fp.trim().to_ascii_lowercase(),
                    None => cur
                        .and_then(|c| c.cert_sha256.clone())
                        .ok_or_else(|| PosixError::Invalid("a tls client needs cert_sha256".into()))?,
                };
                validate_fingerprint(&fp)?;
                (Some(fp), None)
            }
            Transport::Plain => {
                if w.cert_sha256.is_some() {
                    return Err(PosixError::Invalid("cert_sha256 applies to tls clients only".into()).into());
                }
                let address = match w.address {
                    Some(a) => validate_client_address(&a)?,
                    None => cur
                        .and_then(|c| c.address.clone())
                        .ok_or_else(|| PosixError::Invalid("a plain client needs its address".into()))?,
                };
                (None, Some(address))
            }
        };
        let rec = LdapClient {
            version: RECORD_VERSION,
            name: w.name.clone(),
            transport,
            environment,
            cert_sha256,
            address,
            description: w.description.or_else(|| cur.and_then(|c| c.description.clone())),
            created_at: cur.map(|c| c.created_at).unwrap_or(now),
            updated_at: now,
        };
        let new_index = rec.index_key().ok_or_else(|| PosixError::Invalid("client has no identity".into()))?;
        if let Some(idx) = self.get_record::<ClientIndex>("ldap client index", &new_index).await? {
            if idx.client != rec.name {
                return Err(PosixError::Conflict(format!(
                    "client `{}` is already registered for that {}",
                    idx.client,
                    if transport == Transport::Tls { "certificate" } else { "address" }
                ))
                .into());
            }
        }
        // Index first: a crash leaves an index entry the record does not
        // confirm, which every lookup ignores.
        self.put_record(&new_index, &ClientIndex { version: RECORD_VERSION, client: rec.name.clone() }).await?;
        self.put_record(&format!("{CLIENT_PREFIX}{}", rec.name), &rec).await?;
        if let Some(old) = cur.and_then(LdapClient::index_key).filter(|k| *k != new_index) {
            self.storage.delete(&old).await?;
        }
        log::info!(
            target: "idp",
            "idp.ldap.client: {} name={} transport={} environment={}",
            if created { "create" } else { "update" },
            rec.name,
            rec.transport.as_str(),
            rec.environment
        );
        Ok((rec, created))
    }

    pub async fn delete_client(&self, name: &str) -> Result<Option<LdapClient>, RvError> {
        validate_name("client", name)?;
        let _lock = self.write_lock().await?;
        let Some(rec) = self.get_client(name).await? else {
            return Ok(None);
        };
        self.storage.delete(&format!("{CLIENT_PREFIX}{name}")).await?;
        if let Some(idx) = rec.index_key() {
            self.storage.delete(&idx).await?;
        }
        log::info!(target: "idp", "idp.ldap.client: delete name={name}");
        Ok(Some(rec))
    }

    // ─── Passcodes ──────────────────────────────────────────────

    /// Mint a bind passcode. The caller has already passed the gate.
    /// Expired passcodes of the identity are pruned first; at most
    /// [`MAX_OUTSTANDING_PASSCODES`] may be outstanding.
    pub async fn mint_passcode(
        &self,
        entity_id: &str,
        login: &str,
        environment: &str,
        ttl_secs: u64,
        now: DateTime<Utc>,
    ) -> Result<(Zeroizing<String>, PasscodeRecord), RvError> {
        validate_entity_id(entity_id)?;
        let _lock = self.write_lock().await?;
        let dir = passcode_dir(entity_id);
        let mut outstanding = 0;
        for key in self.storage.list(&dir).await? {
            let full = format!("{dir}{key}");
            match self.get_record::<PasscodeRecord>("ldap passcode", &full).await? {
                Some(rec) if rec.expires_at > now => outstanding += 1,
                _ => self.storage.delete(&full).await?,
            }
        }
        if outstanding >= MAX_OUTSTANDING_PASSCODES {
            return Err(bv_errors::bv_error_response_status!(
                429,
                &format!("at most {MAX_OUTSTANDING_PASSCODES} unexpired LDAP passcodes per identity")
            ));
        }
        let code = generate_passcode();
        let ttl = i64::try_from(ttl_secs).map_err(|_| PosixError::Invalid("ttl is too large".into()))?;
        let rec = PasscodeRecord {
            version: RECORD_VERSION,
            entity_id: entity_id.to_string(),
            login: login.to_string(),
            environment: environment.to_string(),
            roles: None,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(ttl),
        };
        self.put_record(&passcode_key(entity_id, code.as_bytes()), &rec).await?;
        Ok((code, rec))
    }

    /// Take a passcode: whatever happens next, it is gone (single use).
    /// `None` if the identity holds no such passcode.
    pub async fn consume_passcode(&self, entity_id: &str, code: &[u8]) -> Result<Option<PasscodeRecord>, RvError> {
        validate_entity_id(entity_id)?;
        if !is_passcode_format(code) {
            return Ok(None);
        }
        let key = passcode_key(entity_id, code);
        let _lock = self.write_lock().await?;
        let rec = self.get_record::<PasscodeRecord>("ldap passcode", &key).await?;
        if rec.is_some() {
            self.storage.delete(&key).await?;
        }
        Ok(rec)
    }
}
