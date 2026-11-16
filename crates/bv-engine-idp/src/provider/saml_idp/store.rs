//! `idp/saml/` on the root system view: the IdP configuration, registered
//! service providers (each bound for life to one environment and one
//! entity ID), the AuthnRequest replay cache and the signing key ring.
//! Records are JSON `version: 1`, unknown versions and fields refused.

use std::{any::Any, sync::Arc};

use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::{
    entitlement::{
        model::{validate_description, EnvironmentState},
        store::EntitlementStore,
    },
    errors::RvError,
    posix::model::{decode_versioned, PosixError, RECORD_VERSION},
    provider::{
        federation::{keys::KeyRingStore, sha256_hex, validate_https_url, validate_url_list, MAX_URL_LEN},
        radius::store::validate_name,
    },
    storage::{Storage, StorageEntry},
};

pub const STORAGE_LOCK_NAME: &str = "bv-idp/saml";
const KEYS_LOCK_NAME: &str = "bv-idp/saml-keys";
const CONFIG_KEY: &str = "config";
const KEYS_KEY: &str = "keys";
pub const SP_PREFIX: &str = "sps/";
const ENTITY_INDEX: &str = "index/entity/";
pub const SEEN_PREFIX: &str = "seen/";
const KEY_COMMON_NAME: &str = "BastionVault SAML IdP signing key";

pub const DEFAULT_ASSERTION_TTL_SECS: u64 = 300;
pub const MIN_ASSERTION_TTL_SECS: u64 = 60;
pub const MAX_ASSERTION_TTL_SECS: u64 = 600;
pub const DEFAULT_REQUEST_MAX_AGE_SECS: u64 = 300;
pub const MIN_REQUEST_MAX_AGE_SECS: u64 = 60;
pub const MAX_REQUEST_MAX_AGE_SECS: u64 = 900;
pub const MAX_ACS_URLS: usize = 16;
pub const MAX_ENTITY_ID_LEN: usize = 1024;

static LOCAL_WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct WriteLock {
    _cluster: Box<dyn Any + Send>,
    _local: tokio::sync::MutexGuard<'static, ()>,
}

/// A SAML entity ID: an absolute URI (URL or URN), printable, bounded.
pub fn validate_entity_id_uri(field: &str, id: &str) -> Result<(), PosixError> {
    let ok = !id.is_empty() && id.len() <= MAX_ENTITY_ID_LEN && id.bytes().all(|b| (0x21..=0x7e).contains(&b));
    if !ok || url::Url::parse(id).is_err() {
        return Err(PosixError::Invalid(format!(
            "{field} must be an absolute URI of 1-{MAX_ENTITY_ID_LEN} printable characters without spaces"
        )));
    }
    Ok(())
}

// ─── Configuration ──────────────────────────────────────────────────

/// `idp/saml/config`. Absent or disabled: no assertion is issued and the
/// metadata is not served.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlConfig {
    pub version: u32,
    pub enabled: bool,
    /// The IdP's entity ID (the `Issuer` of every response).
    pub entity_id: String,
    /// The browser-facing SSO page that relays to `v2/idp/saml/sso`; an
    /// AuthnRequest `Destination`, when present, must equal it.
    pub sso_url: String,
    pub assertion_ttl_secs: u64,
    pub request_max_age_secs: u64,
    pub updated_at: DateTime<Utc>,
}

impl SamlConfig {
    pub fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("enabled".into(), self.enabled.into());
        m.insert("entity_id".into(), self.entity_id.clone().into());
        m.insert("sso_url".into(), self.sso_url.clone().into());
        m.insert("assertion_ttl".into(), self.assertion_ttl_secs.into());
        m.insert("request_max_age".into(), self.request_max_age_secs.into());
        m.insert("updated_at".into(), self.updated_at.to_rfc3339().into());
        m
    }

    fn validate(&self) -> Result<(), PosixError> {
        validate_entity_id_uri("entity_id", &self.entity_id)?;
        validate_https_url("sso_url", &self.sso_url)?;
        if !(MIN_ASSERTION_TTL_SECS..=MAX_ASSERTION_TTL_SECS).contains(&self.assertion_ttl_secs) {
            return Err(PosixError::Invalid(format!(
                "assertion_ttl must lie within [{MIN_ASSERTION_TTL_SECS}, {MAX_ASSERTION_TTL_SECS}] seconds"
            )));
        }
        if !(MIN_REQUEST_MAX_AGE_SECS..=MAX_REQUEST_MAX_AGE_SECS).contains(&self.request_max_age_secs) {
            return Err(PosixError::Invalid(format!(
                "request_max_age must lie within [{MIN_REQUEST_MAX_AGE_SECS}, {MAX_REQUEST_MAX_AGE_SECS}] seconds"
            )));
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct SamlConfigUpdate {
    pub enabled: Option<bool>,
    pub entity_id: Option<String>,
    pub sso_url: Option<String>,
    pub assertion_ttl_secs: Option<u64>,
    pub request_max_age_secs: Option<u64>,
}

// ─── Service providers ──────────────────────────────────────────────

/// `idp/saml/sps/<name>`: one SP, bound for life to one entity ID and one
/// environment. Responses go only to one of `acs_urls`, matched exactly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceProvider {
    pub version: u32,
    pub name: String,
    pub entity_id: String,
    /// The first is the default when an AuthnRequest names none.
    pub acs_urls: Vec<String>,
    pub environment: String,
    /// Whether `v2/idp/saml/initiate/<name>` may send unsolicited responses.
    pub allow_idp_initiated: bool,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ServiceProvider {
    pub fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("name".into(), self.name.clone().into());
        m.insert("entity_id".into(), self.entity_id.clone().into());
        m.insert("acs_urls".into(), Value::from(self.acs_urls.clone()));
        m.insert("environment".into(), self.environment.clone().into());
        m.insert("allow_idp_initiated".into(), self.allow_idp_initiated.into());
        m.insert("description".into(), self.description.clone().into());
        m.insert("created_at".into(), self.created_at.to_rfc3339().into());
        m.insert("updated_at".into(), self.updated_at.to_rfc3339().into());
        m
    }
}

#[derive(Default)]
pub struct SpWrite {
    pub name: String,
    /// Required to create; fixed afterwards.
    pub entity_id: Option<String>,
    /// Replaces the whole list; required to create.
    pub acs_urls: Option<Vec<String>>,
    /// Required to create; fixed afterwards.
    pub environment: Option<String>,
    pub allow_idp_initiated: Option<bool>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpIndex {
    version: u32,
    sp: String,
}

/// `idp/saml/seen/<expiry>-<sha256(sp, request id)>`: an AuthnRequest ID
/// already answered, kept until the request could no longer be accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SeenRequest {
    version: u32,
    sp: String,
    expires_at: DateTime<Utc>,
}

fn key_expiry(key: &str) -> Option<i64> {
    key.split_once('-').and_then(|(e, _)| e.parse::<i64>().ok())
}

// ─── Store ──────────────────────────────────────────────────────────

pub struct SamlStore {
    storage: Arc<dyn Storage>,
    pub keys: KeyRingStore,
}

#[maybe_async::maybe_async]
impl SamlStore {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        let keys = KeyRingStore::new(storage.clone(), KEYS_KEY, KEYS_LOCK_NAME, KEY_COMMON_NAME);
        Self { storage, keys }
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
        self.storage.put(&StorageEntry::new(key, value)?).await
    }

    // ─── Configuration ──────────────────────────────────────────

    pub async fn config(&self) -> Result<Option<SamlConfig>, RvError> {
        self.get_record("saml config", CONFIG_KEY).await
    }

    pub async fn put_config(&self, update: SamlConfigUpdate, now: DateTime<Utc>) -> Result<SamlConfig, RvError> {
        let _lock = self.write_lock().await?;
        let current = self.config().await?;
        let cur = current.as_ref();
        let required = |what: &str| PosixError::Invalid(format!("{what} is required"));
        let cfg = SamlConfig {
            version: RECORD_VERSION,
            enabled: update.enabled.or(cur.map(|c| c.enabled)).unwrap_or(false),
            entity_id: update
                .entity_id
                .or_else(|| cur.map(|c| c.entity_id.clone()))
                .ok_or_else(|| required("entity_id"))?,
            sso_url: update.sso_url.or_else(|| cur.map(|c| c.sso_url.clone())).ok_or_else(|| required("sso_url"))?,
            assertion_ttl_secs: update
                .assertion_ttl_secs
                .or(cur.map(|c| c.assertion_ttl_secs))
                .unwrap_or(DEFAULT_ASSERTION_TTL_SECS),
            request_max_age_secs: update
                .request_max_age_secs
                .or(cur.map(|c| c.request_max_age_secs))
                .unwrap_or(DEFAULT_REQUEST_MAX_AGE_SECS),
            updated_at: now,
        };
        cfg.validate()?;
        self.put_record(CONFIG_KEY, &cfg).await?;
        log::info!(target: "idp", "idp.saml.config: enabled={} entity_id={}", cfg.enabled, cfg.entity_id);
        Ok(cfg)
    }

    // ─── Service providers ──────────────────────────────────────

    pub async fn get_sp(&self, name: &str) -> Result<Option<ServiceProvider>, RvError> {
        validate_name("service provider", name)?;
        let rec: Option<ServiceProvider> =
            self.get_record("saml service provider", &format!("{SP_PREFIX}{name}")).await?;
        if rec.as_ref().is_some_and(|r| r.name != name) {
            return Err(PosixError::Corrupt(format!("saml service provider record `{name}` names another")).into());
        }
        Ok(rec)
    }

    pub async fn list_sps(&self) -> Result<Vec<ServiceProvider>, RvError> {
        let mut out = Vec::new();
        for entry in self.storage.scan(SP_PREFIX, None).await? {
            out.push(decode_versioned::<ServiceProvider>("saml service provider", &entry.value)?);
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// The SP registered for an AuthnRequest `Issuer`. The index must agree
    /// with the record it points at.
    pub async fn sp_for_entity(&self, entity_id: &str) -> Result<Option<ServiceProvider>, RvError> {
        if validate_entity_id_uri("issuer", entity_id).is_err() {
            return Ok(None);
        }
        let key = format!("{ENTITY_INDEX}{}", sha256_hex(entity_id.as_bytes()));
        let Some(idx) = self.get_record::<SpIndex>("saml entity index", &key).await? else {
            return Ok(None);
        };
        Ok(self.get_sp(&idx.sp).await?.filter(|sp| sp.entity_id == entity_id))
    }

    pub async fn put_sp(
        &self,
        authz: &EntitlementStore,
        w: SpWrite,
        now: DateTime<Utc>,
    ) -> Result<(ServiceProvider, bool), RvError> {
        validate_name("service provider", &w.name)?;
        if let Some(d) = &w.description {
            validate_description(d)?;
        }
        let _lock = self.write_lock().await?;
        let current = self.get_sp(&w.name).await?;
        let cur = current.as_ref();
        let fixed = |what: &str| PosixError::Invalid(format!("a service provider's {what} is fixed at creation"));
        let entity_id = match (w.entity_id, cur) {
            (Some(e), Some(c)) if e != c.entity_id => return Err(fixed("entity_id").into()),
            (Some(e), _) => e,
            (None, Some(c)) => c.entity_id.clone(),
            (None, None) => return Err(PosixError::Invalid("entity_id is required to create".into()).into()),
        };
        validate_entity_id_uri("entity_id", &entity_id)?;
        let environment = match (w.environment, cur) {
            (Some(e), Some(c)) if e != c.environment => return Err(fixed("environment").into()),
            (Some(e), _) => e,
            (None, Some(c)) => c.environment.clone(),
            (None, None) => return Err(PosixError::Invalid("environment is required to create".into()).into()),
        };
        let env = authz
            .get_environment(&environment)
            .await?
            .ok_or_else(|| PosixError::NotFound(format!("no environment `{environment}`")))?;
        if env.state != EnvironmentState::Active {
            return Err(PosixError::Conflict(format!("environment `{environment}` is retired")).into());
        }
        let acs_urls = match (w.acs_urls, cur) {
            (Some(a), _) => a,
            (None, Some(c)) => c.acs_urls.clone(),
            (None, None) => return Err(PosixError::Invalid("acs_urls are required to create".into()).into()),
        };
        validate_url_list("acs_urls", &acs_urls, MAX_ACS_URLS)?;
        let index_key = format!("{ENTITY_INDEX}{}", sha256_hex(entity_id.as_bytes()));
        if let Some(idx) = self.get_record::<SpIndex>("saml entity index", &index_key).await? {
            if idx.sp != w.name && self.get_sp(&idx.sp).await?.is_some_and(|sp| sp.entity_id == entity_id) {
                return Err(PosixError::Conflict(format!(
                    "service provider `{}` is already registered for that entity_id",
                    idx.sp
                ))
                .into());
            }
        }
        let rec = ServiceProvider {
            version: RECORD_VERSION,
            name: w.name.clone(),
            entity_id,
            acs_urls,
            environment,
            allow_idp_initiated: w.allow_idp_initiated.or(cur.map(|c| c.allow_idp_initiated)).unwrap_or(false),
            description: w.description.or_else(|| cur.and_then(|c| c.description.clone())),
            created_at: cur.map(|c| c.created_at).unwrap_or(now),
            updated_at: now,
        };
        // Index first: an index the record does not confirm is ignored.
        self.put_record(&index_key, &SpIndex { version: RECORD_VERSION, sp: rec.name.clone() }).await?;
        self.put_record(&format!("{SP_PREFIX}{}", rec.name), &rec).await?;
        log::info!(
            target: "idp",
            "idp.saml.sp: {} name={} environment={} idp_initiated={}",
            if cur.is_none() { "create" } else { "update" },
            rec.name,
            rec.environment,
            rec.allow_idp_initiated
        );
        Ok((rec, cur.is_none()))
    }

    pub async fn delete_sp(&self, name: &str) -> Result<Option<ServiceProvider>, RvError> {
        validate_name("service provider", name)?;
        let _lock = self.write_lock().await?;
        let Some(rec) = self.get_sp(name).await? else {
            return Ok(None);
        };
        self.storage.delete(&format!("{SP_PREFIX}{name}")).await?;
        self.storage.delete(&format!("{ENTITY_INDEX}{}", sha256_hex(rec.entity_id.as_bytes()))).await?;
        log::info!(target: "idp", "idp.saml.sp: delete name={name}");
        Ok(Some(rec))
    }

    // ─── Replay cache ───────────────────────────────────────────

    /// Remember that `request_id` from `sp` was answered. `false` if it
    /// already was (a replay). Expired entries are pruned first.
    pub async fn record_request(
        &self,
        sp: &str,
        request_id: &str,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<bool, RvError> {
        if request_id.len() > MAX_URL_LEN {
            return Err(PosixError::Invalid("request ID is too long".into()).into());
        }
        let _lock = self.write_lock().await?;
        for key in self.storage.list(SEEN_PREFIX).await? {
            if key_expiry(&key).is_none_or(|e| e <= now.timestamp()) {
                self.storage.delete(&format!("{SEEN_PREFIX}{key}")).await?;
            }
        }
        let digest = sha256_hex(format!("{sp}\n{request_id}").as_bytes());
        let key = format!("{SEEN_PREFIX}{:0>12}-{digest}", expires_at.timestamp());
        if self.storage.get(&key).await?.is_some() {
            return Ok(false);
        }
        self.put_record(&key, &SeenRequest { version: RECORD_VERSION, sp: sp.to_string(), expires_at }).await?;
        Ok(true)
    }
}
