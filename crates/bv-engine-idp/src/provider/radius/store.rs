//! `idp/radius/` on the root system view: the provider configuration (with
//! the RadSec key), NAS client records (with UDP shared secrets), attribute
//! profiles and one-time passcodes. Everything is behind the barrier; no
//! read path returns a key or a secret. Records are JSON `version: 1`,
//! unknown versions and fields refused. Writes take a process-local mutex
//! plus the storage lock, as the other idp stores do.

use std::{
    any::Any,
    collections::BTreeMap,
    fmt,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::{
    tls::{self, hex, validate_fingerprint},
    vendor::{validate_role_attributes, VendorAttribute},
};
use crate::{
    entitlement::{
        model::{
            validate_description, validate_environment_name, validate_role_name, EnvironmentState,
            MAX_ROLES_PER_ENVIRONMENT,
        },
        store::EntitlementStore,
    },
    errors::RvError,
    posix::model::{decode_versioned, validate_entity_id, PosixError, RECORD_VERSION},
    storage::{Storage, StorageEntry},
};

pub const STORAGE_LOCK_NAME: &str = "bv-idp/radius";
const CONFIG_KEY: &str = "config";
pub const CLIENT_PREFIX: &str = "clients/";
pub const PROFILE_PREFIX: &str = "profiles/";
const UDP_INDEX: &str = "index/udp/";
const CERT_INDEX: &str = "index/cert/";
pub const PASSCODE_PREFIX: &str = "passcodes/";

pub const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 120;
pub const MAX_RATE_LIMIT_PER_MINUTE: u32 = 6000;
pub const MIN_PASSCODE_TTL_SECS: u64 = 30;
pub const DEFAULT_PASSCODE_TTL_SECS: u64 = 120;
pub const DEFAULT_PASSCODE_MAX_TTL_SECS: u64 = 300;
pub const PASSCODE_TTL_CEILING_SECS: u64 = 900;
/// Unexpired passcodes one identity may hold at once.
pub const MAX_OUTSTANDING_PASSCODES: usize = 8;
/// 128 random bits, 32 lower-case hex characters.
pub const PASSCODE_BYTES: usize = 16;
pub const PASSCODE_LEN: usize = PASSCODE_BYTES * 2;
pub const MIN_SECRET_LEN: usize = 16;
pub const MAX_SECRET_LEN: usize = 128;
/// RFC 6614 §2.3: the shared secret inside a RadSec session is fixed.
pub const RADSEC_SECRET: &[u8] = b"radsec";
const MAX_NAME_LEN: usize = 64;

static LOCAL_WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Both halves of the write lock; field order is drop order.
struct WriteLock {
    _cluster: Box<dyn Any + Send>,
    _local: tokio::sync::MutexGuard<'static, ()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Radsec,
    Udp,
}

impl Transport {
    pub fn parse(s: &str) -> Result<Self, PosixError> {
        match s {
            "radsec" => Ok(Self::Radsec),
            "udp" => Ok(Self::Udp),
            _ => Err(PosixError::Invalid("transport must be `radsec` or `udp`".into())),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Radsec => "radsec",
            Self::Udp => "udp",
        }
    }
}

/// Client and profile names: the environment-name rules.
pub fn validate_name(what: &str, name: &str) -> Result<(), PosixError> {
    validate_environment_name(name)
        .map_err(|_| PosixError::Invalid(format!("{what} name must match ^[a-z0-9][a-z0-9_-]*$ (max {MAX_NAME_LEN})")))
}

/// A listen address. The unspecified address binds every interface and is
/// refused unless the operator opts in.
pub fn validate_listen(field: &str, addr: &str, allow_unspecified: bool) -> Result<SocketAddr, PosixError> {
    let parsed: SocketAddr =
        addr.trim().parse().map_err(|_| PosixError::Invalid(format!("{field} must be an IP:port socket address")))?;
    if parsed.ip().is_unspecified() && !allow_unspecified {
        return Err(PosixError::Invalid(format!(
            "{field} binds every interface; name an explicit address or set allow_unspecified_bind"
        )));
    }
    Ok(parsed)
}

// ─── Configuration ──────────────────────────────────────────────────

/// `idp/radius/config`. Absent means the provider is off: no listener runs
/// and no passcode is minted. `Debug` never prints the PEM fields.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadiusConfig {
    pub version: u32,
    pub enabled: bool,
    pub radsec_listen: Option<String>,
    /// Classic UDP RADIUS: off unless set, for trusted segments only.
    pub udp_enabled: bool,
    pub udp_listen: Option<String>,
    pub allow_unspecified_bind: bool,
    pub tls_cert_pem: Option<String>,
    pub tls_key_pem: Option<String>,
    pub client_ca_pem: Option<String>,
    pub rate_limit_per_minute: u32,
    pub passcode_default_ttl_secs: u64,
    pub passcode_max_ttl_secs: u64,
    pub updated_at: DateTime<Utc>,
}

impl Drop for RadiusConfig {
    fn drop(&mut self) {
        if let Some(key) = self.tls_key_pem.as_mut() {
            key.zeroize();
        }
    }
}

impl fmt::Debug for RadiusConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RadiusConfig")
            .field("enabled", &self.enabled)
            .field("radsec_listen", &self.radsec_listen)
            .field("udp_enabled", &self.udp_enabled)
            .field("udp_listen", &self.udp_listen)
            .finish_non_exhaustive()
    }
}

impl RadiusConfig {
    pub fn radsec_addr(&self) -> Option<SocketAddr> {
        self.radsec_listen.as_deref().and_then(|a| a.parse().ok())
    }

    pub fn udp_addr(&self) -> Option<SocketAddr> {
        if !self.udp_enabled {
            return None;
        }
        self.udp_listen.as_deref().and_then(|a| a.parse().ok())
    }

    /// Identifies the TLS material, in memory only, so the listener restarts
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

    pub fn tls_server_config(&self) -> Result<Arc<rustls::ServerConfig>, PosixError> {
        match (&self.tls_cert_pem, &self.tls_key_pem, &self.client_ca_pem) {
            (Some(cert), Some(key), Some(ca)) => tls::server_config(cert, key, ca),
            _ => Err(PosixError::Invalid("RadSec needs tls_cert_pem, tls_key_pem and client_ca_pem".into())),
        }
    }

    pub fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("enabled".into(), self.enabled.into());
        m.insert("radsec_listen".into(), self.radsec_listen.clone().into());
        m.insert("udp_enabled".into(), self.udp_enabled.into());
        m.insert("udp_listen".into(), self.udp_listen.clone().into());
        m.insert("allow_unspecified_bind".into(), self.allow_unspecified_bind.into());
        m.insert("tls_cert_pem".into(), self.tls_cert_pem.clone().into());
        m.insert("tls_key_set".into(), self.tls_key_pem.is_some().into());
        m.insert("client_ca_pem".into(), self.client_ca_pem.clone().into());
        m.insert("rate_limit_per_minute".into(), self.rate_limit_per_minute.into());
        m.insert("passcode_default_ttl".into(), self.passcode_default_ttl_secs.into());
        m.insert("passcode_max_ttl".into(), self.passcode_max_ttl_secs.into());
        m.insert("passcode_ttl_ceiling".into(), PASSCODE_TTL_CEILING_SECS.into());
        m.insert("updated_at".into(), self.updated_at.to_rfc3339().into());
        m
    }

    fn validate(&self) -> Result<(), PosixError> {
        let allow = self.allow_unspecified_bind;
        if let Some(addr) = &self.radsec_listen {
            validate_listen("radsec_listen", addr, allow)?;
            self.tls_server_config()?;
        }
        match (&self.udp_listen, self.udp_enabled) {
            (Some(addr), true) => {
                validate_listen("udp_listen", addr, allow)?;
            }
            (Some(_), false) => {
                return Err(PosixError::Invalid(
                    "udp_listen needs udp_enabled=true; classic UDP RADIUS is off by default".into(),
                ))
            }
            (None, true) => return Err(PosixError::Invalid("udp_enabled needs udp_listen".into())),
            (None, false) => {}
        }
        if self.enabled && self.radsec_listen.is_none() && self.udp_addr().is_none() {
            return Err(PosixError::Invalid("an enabled provider needs radsec_listen or udp_listen".into()));
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
    pub radsec_listen: Option<String>,
    pub udp_enabled: Option<bool>,
    pub udp_listen: Option<String>,
    pub allow_unspecified_bind: Option<bool>,
    pub tls_cert_pem: Option<String>,
    pub tls_key_pem: Option<Zeroizing<String>>,
    pub client_ca_pem: Option<String>,
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

/// `idp/radius/clients/<name>`: one NAS. A NAS is bound to exactly one
/// environment and one profile of that environment. `Debug` never prints
/// the secret.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadiusClient {
    pub version: u32,
    pub name: String,
    pub transport: Transport,
    pub environment: String,
    pub profile: String,
    /// UDP only: the NAS source address, canonical form.
    pub address: Option<String>,
    /// UDP only: the shared secret.
    pub secret: Option<String>,
    /// RadSec only: SHA-256 of the NAS certificate (DER), lower-case hex.
    pub cert_sha256: Option<String>,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Drop for RadiusClient {
    fn drop(&mut self) {
        if let Some(secret) = self.secret.as_mut() {
            secret.zeroize();
        }
    }
}

impl fmt::Debug for RadiusClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RadiusClient")
            .field("name", &self.name)
            .field("transport", &self.transport)
            .field("environment", &self.environment)
            .field("profile", &self.profile)
            .field("address", &self.address)
            .field("cert_sha256", &self.cert_sha256)
            .finish_non_exhaustive()
    }
}

impl RadiusClient {
    /// The key Message-Authenticator and the authenticators are computed with.
    pub fn shared_secret(&self) -> Option<Zeroizing<Vec<u8>>> {
        match self.transport {
            Transport::Radsec => Some(Zeroizing::new(RADSEC_SECRET.to_vec())),
            Transport::Udp => self.secret.as_ref().map(|s| Zeroizing::new(s.as_bytes().to_vec())),
        }
    }

    fn index_key(&self) -> Option<String> {
        match self.transport {
            Transport::Udp => self.address.as_ref().map(|a| format!("{UDP_INDEX}{a}")),
            Transport::Radsec => self.cert_sha256.as_ref().map(|fp| format!("{CERT_INDEX}{fp}")),
        }
    }

    pub fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("name".into(), self.name.clone().into());
        m.insert("transport".into(), self.transport.as_str().into());
        m.insert("environment".into(), self.environment.clone().into());
        m.insert("profile".into(), self.profile.clone().into());
        m.insert("address".into(), self.address.clone().into());
        m.insert("secret_set".into(), self.secret.is_some().into());
        m.insert("cert_sha256".into(), self.cert_sha256.clone().into());
        m.insert("description".into(), self.description.clone().into());
        m.insert("created_at".into(), self.created_at.to_rfc3339().into());
        m.insert("updated_at".into(), self.updated_at.to_rfc3339().into());
        m
    }
}

/// A NAS source address, IPv4-mapped IPv6 folded to IPv4.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

fn validate_client_address(addr: &str) -> Result<String, PosixError> {
    let ip: IpAddr =
        addr.trim().parse().map_err(|_| PosixError::Invalid("address must be the NAS's IP address".into()))?;
    let ip = canonical_ip(ip);
    if ip.is_unspecified() || ip.is_multicast() || ip == IpAddr::from([255, 255, 255, 255]) {
        return Err(PosixError::Invalid("address must be a unicast host address".into()));
    }
    Ok(ip.to_string())
}

fn validate_secret(secret: &str) -> Result<(), PosixError> {
    let ok =
        (MIN_SECRET_LEN..=MAX_SECRET_LEN).contains(&secret.len()) && secret.bytes().all(|b| (0x21..=0x7e).contains(&b));
    if ok {
        Ok(())
    } else {
        Err(PosixError::Invalid(format!(
            "secret must be {MIN_SECRET_LEN}-{MAX_SECRET_LEN} printable ASCII characters without spaces"
        )))
    }
}

/// Create-or-update of a client. `transport` and `environment` are fixed at
/// creation (an update may restate them).
#[derive(Default)]
pub struct ClientWrite {
    pub name: String,
    pub transport: Option<Transport>,
    pub environment: Option<String>,
    pub profile: Option<String>,
    pub address: Option<String>,
    pub secret: Option<Zeroizing<String>>,
    pub cert_sha256: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientIndex {
    version: u32,
    client: String,
}

// ─── Profiles ───────────────────────────────────────────────────────

/// `idp/radius/profiles/<name>`: the attributes an Access-Accept carries
/// per environment role. Bound for life to one environment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadiusProfile {
    pub version: u32,
    pub name: String,
    pub environment: String,
    pub roles: BTreeMap<String, Vec<VendorAttribute>>,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl RadiusProfile {
    /// The attributes of `roles`, in role order, without repeats.
    pub fn attributes_for(&self, roles: &[String]) -> Vec<&VendorAttribute> {
        let mut out: Vec<&VendorAttribute> = Vec::new();
        for role in roles {
            for attr in self.roles.get(role).into_iter().flatten() {
                if !out.contains(&attr) {
                    out.push(attr);
                }
            }
        }
        out
    }

    pub fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("name".into(), self.name.clone().into());
        m.insert("environment".into(), self.environment.clone().into());
        let roles: Map<String, Value> = self
            .roles
            .iter()
            .map(|(r, attrs)| (r.clone(), Value::Array(attrs.iter().map(VendorAttribute::to_value).collect())))
            .collect();
        m.insert("roles".into(), Value::Object(roles));
        m.insert("description".into(), self.description.clone().into());
        m.insert("created_at".into(), self.created_at.to_rfc3339().into());
        m.insert("updated_at".into(), self.updated_at.to_rfc3339().into());
        m
    }
}

pub struct ProfileWrite {
    pub name: String,
    /// Required to create; an update may restate it.
    pub environment: Option<String>,
    /// Replaces the whole map when given; required to create.
    pub roles: Option<BTreeMap<String, Vec<VendorAttribute>>>,
    pub description: Option<String>,
}

// ─── Passcodes ──────────────────────────────────────────────────────

/// `idp/radius/passcodes/<entity_id>/<sha256(passcode)>`. The passcode
/// itself is never stored, only its hash, which is the key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasscodeRecord {
    pub version: u32,
    pub entity_id: String,
    pub login: String,
    pub environment: String,
    /// The roles asked for at mint time; `None` means every entitled role.
    pub roles: Option<Vec<String>>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// 32 lower-case hex characters: anything else is not a passcode and is
/// refused without a storage read.
pub fn is_passcode_format(code: &[u8]) -> bool {
    code.len() == PASSCODE_LEN && code.iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

fn passcode_dir(entity_id: &str) -> String {
    format!("{PASSCODE_PREFIX}{entity_id}/")
}

fn passcode_key(entity_id: &str, code: &[u8]) -> String {
    format!("{}{}", passcode_dir(entity_id), hex(&Sha256::digest(code)))
}

fn generate_passcode() -> Zeroizing<String> {
    use rand::RngExt;

    let mut bytes = Zeroizing::new([0u8; PASSCODE_BYTES]);
    rand::rng().fill(&mut bytes[..]);
    Zeroizing::new(hex(&bytes[..]))
}

// ─── Store ──────────────────────────────────────────────────────────

pub struct RadiusStore {
    storage: Arc<dyn Storage>,
}

#[maybe_async::maybe_async]
impl RadiusStore {
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

    pub async fn config(&self) -> Result<Option<RadiusConfig>, RvError> {
        self.get_record("radius config", CONFIG_KEY).await
    }

    pub async fn put_config(&self, update: ConfigUpdate, now: DateTime<Utc>) -> Result<RadiusConfig, RvError> {
        let _lock = self.write_lock().await?;
        let current = self.config().await?;
        let cur = current.as_ref();
        let cfg = RadiusConfig {
            version: RECORD_VERSION,
            enabled: update.enabled.or(cur.map(|c| c.enabled)).unwrap_or(false),
            radsec_listen: merge_text(update.radsec_listen, cur.and_then(|c| c.radsec_listen.clone())),
            udp_enabled: update.udp_enabled.or(cur.map(|c| c.udp_enabled)).unwrap_or(false),
            udp_listen: merge_text(update.udp_listen, cur.and_then(|c| c.udp_listen.clone())),
            allow_unspecified_bind: update
                .allow_unspecified_bind
                .or(cur.map(|c| c.allow_unspecified_bind))
                .unwrap_or(false),
            tls_cert_pem: merge_text(update.tls_cert_pem, cur.and_then(|c| c.tls_cert_pem.clone())),
            tls_key_pem: merge_text(update.tls_key_pem.map(|k| k.to_string()), cur.and_then(|c| c.tls_key_pem.clone())),
            client_ca_pem: merge_text(update.client_ca_pem, cur.and_then(|c| c.client_ca_pem.clone())),
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
        self.put_record(CONFIG_KEY, &cfg).await?;
        log::info!(
            target: "idp",
            "idp.radius.config: enabled={} radsec_listen={:?} udp_enabled={} udp_listen={:?}",
            cfg.enabled,
            cfg.radsec_listen,
            cfg.udp_enabled,
            cfg.udp_listen
        );
        if cfg.udp_addr().is_some() {
            log::warn!(
                target: "security",
                "idp.radius.config: classic UDP RADIUS is enabled; its MD5 shared-secret protection is weak, \
                 use it on a trusted segment only"
            );
        }
        Ok(cfg)
    }

    // ─── Clients ────────────────────────────────────────────────

    pub async fn get_client(&self, name: &str) -> Result<Option<RadiusClient>, RvError> {
        validate_name("client", name)?;
        let rec: Option<RadiusClient> = self.get_record("radius client", &format!("{CLIENT_PREFIX}{name}")).await?;
        if rec.as_ref().is_some_and(|r| r.name != name) {
            return Err(PosixError::Corrupt(format!("radius client record `{name}` names another client")).into());
        }
        Ok(rec)
    }

    pub async fn list_clients(&self) -> Result<Vec<RadiusClient>, RvError> {
        let mut out = Vec::new();
        for entry in self.storage.scan(CLIENT_PREFIX, None).await? {
            let value = Zeroizing::new(entry.value);
            out.push(decode_versioned::<RadiusClient>("radius client", &value)?);
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn client_by_index(&self, key: &str) -> Result<Option<RadiusClient>, RvError> {
        let Some(idx) = self.get_record::<ClientIndex>("radius client index", key).await? else {
            return Ok(None);
        };
        let Some(client) = self.get_client(&idx.client).await? else {
            return Ok(None);
        };
        // The index must agree with the record it points at.
        Ok((client.index_key().as_deref() == Some(key)).then_some(client))
    }

    /// The UDP client registered for a source address, read live.
    pub async fn client_for_udp(&self, ip: IpAddr) -> Result<Option<RadiusClient>, RvError> {
        let key = format!("{UDP_INDEX}{}", canonical_ip(ip));
        Ok(self.client_by_index(&key).await?.filter(|c| c.transport == Transport::Udp))
    }

    /// The RadSec client registered for a certificate fingerprint, read live.
    pub async fn client_for_cert(&self, fingerprint: &str) -> Result<Option<RadiusClient>, RvError> {
        validate_fingerprint(fingerprint)?;
        let key = format!("{CERT_INDEX}{fingerprint}");
        Ok(self.client_by_index(&key).await?.filter(|c| c.transport == Transport::Radsec))
    }

    pub async fn put_client(
        &self,
        authz: &EntitlementStore,
        w: ClientWrite,
        now: DateTime<Utc>,
    ) -> Result<(RadiusClient, bool), RvError> {
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
        let profile = w
            .profile
            .or_else(|| cur.map(|c| c.profile.clone()))
            .ok_or_else(|| PosixError::Invalid("profile is required to create a client".into()))?;
        validate_name("profile", &profile)?;
        let env = authz
            .get_environment(&environment)
            .await?
            .ok_or_else(|| PosixError::NotFound(format!("no environment `{environment}`")))?;
        if env.state != EnvironmentState::Active {
            return Err(PosixError::Conflict(format!("environment `{environment}` is retired")).into());
        }
        let prof = self
            .get_profile(&profile)
            .await?
            .ok_or_else(|| PosixError::NotFound(format!("no radius profile `{profile}`")))?;
        if prof.environment != environment {
            return Err(PosixError::Invalid(format!(
                "profile `{profile}` belongs to environment `{}`, not `{environment}`",
                prof.environment
            ))
            .into());
        }
        let (address, secret, cert_sha256) = match transport {
            Transport::Udp => {
                if w.cert_sha256.is_some() {
                    return Err(PosixError::Invalid("cert_sha256 applies to radsec clients only".into()).into());
                }
                let address = match w.address {
                    Some(a) => validate_client_address(&a)?,
                    None => cur
                        .and_then(|c| c.address.clone())
                        .ok_or_else(|| PosixError::Invalid("a udp client needs its address".into()))?,
                };
                let secret = match w.secret {
                    Some(s) => {
                        validate_secret(&s)?;
                        s.to_string()
                    }
                    None => cur
                        .and_then(|c| c.secret.clone())
                        .ok_or_else(|| PosixError::Invalid("a udp client needs a shared secret".into()))?,
                };
                (Some(address), Some(secret), None)
            }
            Transport::Radsec => {
                if w.address.is_some() || w.secret.is_some() {
                    return Err(PosixError::Invalid(
                        "a radsec client is identified by cert_sha256; address and secret apply to udp only".into(),
                    )
                    .into());
                }
                let fp = match w.cert_sha256 {
                    Some(fp) => fp.trim().to_ascii_lowercase(),
                    None => cur
                        .and_then(|c| c.cert_sha256.clone())
                        .ok_or_else(|| PosixError::Invalid("a radsec client needs cert_sha256".into()))?,
                };
                validate_fingerprint(&fp)?;
                (None, None, Some(fp))
            }
        };
        let rec = RadiusClient {
            version: RECORD_VERSION,
            name: w.name.clone(),
            transport,
            environment,
            profile,
            address,
            secret,
            cert_sha256,
            description: w.description.or_else(|| cur.and_then(|c| c.description.clone())),
            created_at: cur.map(|c| c.created_at).unwrap_or(now),
            updated_at: now,
        };
        let new_index = rec.index_key().ok_or_else(|| PosixError::Invalid("client has no identity".into()))?;
        if let Some(idx) = self.get_record::<ClientIndex>("radius client index", &new_index).await? {
            if idx.client != rec.name {
                return Err(PosixError::Conflict(format!(
                    "client `{}` is already registered for that {}",
                    idx.client,
                    if transport == Transport::Udp { "address" } else { "certificate" }
                ))
                .into());
            }
        }
        // Index first: a crash leaves an index entry the record does not
        // confirm, which every lookup ignores.
        self.put_record(&new_index, &ClientIndex { version: RECORD_VERSION, client: rec.name.clone() }).await?;
        self.put_record(&format!("{CLIENT_PREFIX}{}", rec.name), &rec).await?;
        if let Some(old) = cur.and_then(RadiusClient::index_key).filter(|k| *k != new_index) {
            self.storage.delete(&old).await?;
        }
        log::info!(
            target: "idp",
            "idp.radius.client: {} name={} transport={} environment={} profile={}",
            if created { "create" } else { "update" },
            rec.name,
            rec.transport.as_str(),
            rec.environment,
            rec.profile
        );
        Ok((rec, created))
    }

    pub async fn delete_client(&self, name: &str) -> Result<Option<RadiusClient>, RvError> {
        validate_name("client", name)?;
        let _lock = self.write_lock().await?;
        let Some(rec) = self.get_client(name).await? else {
            return Ok(None);
        };
        self.storage.delete(&format!("{CLIENT_PREFIX}{name}")).await?;
        if let Some(idx) = rec.index_key() {
            self.storage.delete(&idx).await?;
        }
        log::info!(target: "idp", "idp.radius.client: delete name={name}");
        Ok(Some(rec))
    }

    // ─── Profiles ───────────────────────────────────────────────

    pub async fn get_profile(&self, name: &str) -> Result<Option<RadiusProfile>, RvError> {
        validate_name("profile", name)?;
        let rec: Option<RadiusProfile> = self.get_record("radius profile", &format!("{PROFILE_PREFIX}{name}")).await?;
        if rec.as_ref().is_some_and(|r| r.name != name) {
            return Err(PosixError::Corrupt(format!("radius profile record `{name}` names another profile")).into());
        }
        Ok(rec)
    }

    pub async fn list_profiles(&self) -> Result<Vec<RadiusProfile>, RvError> {
        let mut out = Vec::new();
        for entry in self.storage.scan(PROFILE_PREFIX, None).await? {
            out.push(decode_versioned::<RadiusProfile>("radius profile", &entry.value)?);
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    pub async fn put_profile(
        &self,
        authz: &EntitlementStore,
        w: ProfileWrite,
        now: DateTime<Utc>,
    ) -> Result<(RadiusProfile, bool), RvError> {
        validate_name("profile", &w.name)?;
        if let Some(d) = &w.description {
            validate_description(d)?;
        }
        let _lock = self.write_lock().await?;
        let current = self.get_profile(&w.name).await?;
        let cur = current.as_ref();
        let environment = match (w.environment, cur) {
            (Some(e), Some(c)) if e != c.environment => {
                return Err(PosixError::Invalid("a profile's environment is fixed at creation".into()).into())
            }
            (Some(e), _) => e,
            (None, Some(c)) => c.environment.clone(),
            (None, None) => {
                return Err(PosixError::Invalid("environment is required to create a profile".into()).into())
            }
        };
        let env = authz
            .get_environment(&environment)
            .await?
            .ok_or_else(|| PosixError::NotFound(format!("no environment `{environment}`")))?;
        if env.state != EnvironmentState::Active {
            return Err(PosixError::Conflict(format!("environment `{environment}` is retired")).into());
        }
        let roles = match (w.roles, cur) {
            (Some(r), _) => r,
            (None, Some(c)) => c.roles.clone(),
            (None, None) => return Err(PosixError::Invalid("roles are required to create a profile".into()).into()),
        };
        if roles.is_empty() || roles.len() > MAX_ROLES_PER_ENVIRONMENT {
            return Err(PosixError::Invalid(format!("a profile maps 1-{MAX_ROLES_PER_ENVIRONMENT} roles")).into());
        }
        for (role, attrs) in &roles {
            validate_role_name(role)?;
            if !env.roles.contains_key(role) {
                return Err(PosixError::Invalid(format!(
                    "role `{role}` is not defined on environment `{environment}`"
                ))
                .into());
            }
            validate_role_attributes(role, attrs)?;
        }
        let rec = RadiusProfile {
            version: RECORD_VERSION,
            name: w.name.clone(),
            environment,
            roles,
            description: w.description.or_else(|| cur.and_then(|c| c.description.clone())),
            created_at: cur.map(|c| c.created_at).unwrap_or(now),
            updated_at: now,
        };
        self.put_record(&format!("{PROFILE_PREFIX}{}", rec.name), &rec).await?;
        log::info!(target: "idp", "idp.radius.profile: write name={} environment={}", rec.name, rec.environment);
        Ok((rec, cur.is_none()))
    }

    /// Refused while a client still names the profile.
    pub async fn delete_profile(&self, name: &str) -> Result<Option<RadiusProfile>, RvError> {
        validate_name("profile", name)?;
        let _lock = self.write_lock().await?;
        let Some(rec) = self.get_profile(name).await? else {
            return Ok(None);
        };
        if let Some(c) = self.list_clients().await?.into_iter().find(|c| c.profile == name) {
            return Err(PosixError::Conflict(format!("client `{}` still uses profile `{name}`", c.name)).into());
        }
        self.storage.delete(&format!("{PROFILE_PREFIX}{name}")).await?;
        log::info!(target: "idp", "idp.radius.profile: delete name={name}");
        Ok(Some(rec))
    }

    // ─── Passcodes ──────────────────────────────────────────────

    /// Mint a passcode. The caller has already passed the gate. Expired
    /// passcodes of the identity are pruned first; at most
    /// [`MAX_OUTSTANDING_PASSCODES`] may be outstanding.
    pub async fn mint_passcode(
        &self,
        entity_id: &str,
        login: &str,
        environment: &str,
        roles: Option<Vec<String>>,
        ttl_secs: u64,
        now: DateTime<Utc>,
    ) -> Result<(Zeroizing<String>, PasscodeRecord), RvError> {
        validate_entity_id(entity_id)?;
        let _lock = self.write_lock().await?;
        let dir = passcode_dir(entity_id);
        let mut outstanding = 0;
        for key in self.storage.list(&dir).await? {
            let full = format!("{dir}{key}");
            match self.get_record::<PasscodeRecord>("radius passcode", &full).await? {
                Some(rec) if rec.expires_at > now => outstanding += 1,
                _ => self.storage.delete(&full).await?,
            }
        }
        if outstanding >= MAX_OUTSTANDING_PASSCODES {
            return Err(bv_errors::bv_error_response_status!(
                429,
                &format!("at most {MAX_OUTSTANDING_PASSCODES} unexpired RADIUS passcodes per identity")
            ));
        }
        let code = generate_passcode();
        let ttl = i64::try_from(ttl_secs).map_err(|_| PosixError::Invalid("ttl is too large".into()))?;
        let rec = PasscodeRecord {
            version: RECORD_VERSION,
            entity_id: entity_id.to_string(),
            login: login.to_string(),
            environment: environment.to_string(),
            roles,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(ttl),
        };
        self.put_record(&passcode_key(entity_id, code.as_bytes()), &rec).await?;
        Ok((code, rec))
    }

    /// Take a passcode: whatever happens next, it is gone (single use, and
    /// a passcode presented anywhere is burnt). `None` if there is no such
    /// passcode for the identity.
    pub async fn consume_passcode(&self, entity_id: &str, code: &[u8]) -> Result<Option<PasscodeRecord>, RvError> {
        validate_entity_id(entity_id)?;
        if !is_passcode_format(code) {
            return Ok(None);
        }
        let key = passcode_key(entity_id, code);
        let _lock = self.write_lock().await?;
        let rec = self.get_record::<PasscodeRecord>("radius passcode", &key).await?;
        if rec.is_some() {
            self.storage.delete(&key).await?;
        }
        Ok(rec)
    }
}
