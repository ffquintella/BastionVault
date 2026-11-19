//! `idp/oidc/` on the root system view: the OP configuration, registered
//! clients (each bound for life to one environment, its secret stored only
//! as a SHA-256), single-use authorization codes, single-use launch
//! sessions (the browser's OP login, T545) and the signing key ring.
//! Records are JSON `version: 1`, unknown versions and fields refused.

use std::{any::Any, fmt, sync::Arc};

use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    entitlement::{
        model::{validate_description, EnvironmentState},
        store::EntitlementStore,
    },
    errors::RvError,
    posix::model::{decode_versioned, validate_entity_id, PosixError, RECORD_VERSION},
    provider::{
        federation::{
            keys::KeyRingStore, random_b64url, sha256_hex, validate_https_url, validate_url_list, MAX_URL_LEN,
        },
        radius::store::validate_name,
    },
    storage::{Storage, StorageEntry},
};

pub const STORAGE_LOCK_NAME: &str = "bv-idp/oidc";
const KEYS_LOCK_NAME: &str = "bv-idp/oidc-keys";
const CONFIG_KEY: &str = "config";
const KEYS_KEY: &str = "keys";
pub const CLIENT_PREFIX: &str = "clients/";
pub const CODE_PREFIX: &str = "codes/";
pub const LAUNCH_SESSION_PREFIX: &str = "launch-sessions/";
const KEY_COMMON_NAME: &str = "BastionVault OpenID Provider signing key";

pub const DEFAULT_ID_TOKEN_TTL_SECS: u64 = 300;
pub const MIN_ID_TOKEN_TTL_SECS: u64 = 60;
pub const MAX_ID_TOKEN_TTL_SECS: u64 = 3600;
pub const DEFAULT_CODE_TTL_SECS: u64 = 60;
pub const MIN_CODE_TTL_SECS: u64 = 10;
pub const MAX_CODE_TTL_SECS: u64 = 600;
pub const MAX_REDIRECT_URIS: usize = 16;
/// 256 random bits for client secrets and authorization codes.
pub const SECRET_BYTES: usize = 32;

static LOCAL_WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct WriteLock {
    _cluster: Box<dyn Any + Send>,
    _local: tokio::sync::MutexGuard<'static, ()>,
}

// ─── Configuration ──────────────────────────────────────────────────

/// `idp/oidc/config`. Absent or disabled: no code or token is issued and
/// discovery and the JWKS are not served.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    pub version: u32,
    pub enabled: bool,
    /// The `iss` of every token; discovery is served at
    /// `<issuer>/.well-known/openid-configuration`.
    pub issuer: String,
    /// The browser-facing authorization endpoint discovery publishes.
    /// `None`: `<issuer>/authorize`, which with the documented issuer is the
    /// vault's own `GET /v2/idp/oidc/authorize` (launch-session cookie).
    pub authorization_endpoint: Option<String>,
    pub id_token_ttl_secs: u64,
    pub code_ttl_secs: u64,
    pub updated_at: DateTime<Utc>,
}

impl OidcConfig {
    pub fn authorization_endpoint(&self) -> String {
        self.authorization_endpoint.clone().unwrap_or_else(|| format!("{}/authorize", self.issuer))
    }

    pub fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("enabled".into(), self.enabled.into());
        m.insert("issuer".into(), self.issuer.clone().into());
        m.insert("authorization_endpoint".into(), self.authorization_endpoint().into());
        m.insert("id_token_ttl".into(), self.id_token_ttl_secs.into());
        m.insert("code_ttl".into(), self.code_ttl_secs.into());
        m.insert("updated_at".into(), self.updated_at.to_rfc3339().into());
        m
    }

    fn validate(&self) -> Result<(), PosixError> {
        validate_https_url("issuer", &self.issuer)?;
        let url = url::Url::parse(&self.issuer).map_err(|_| PosixError::Invalid("issuer is not a URL".into()))?;
        if url.query().is_some() || self.issuer.ends_with('/') {
            return Err(PosixError::Invalid("issuer must have no query and no trailing slash".into()));
        }
        if let Some(a) = &self.authorization_endpoint {
            validate_https_url("authorization_endpoint", a)?;
        }
        if !(MIN_ID_TOKEN_TTL_SECS..=MAX_ID_TOKEN_TTL_SECS).contains(&self.id_token_ttl_secs) {
            return Err(PosixError::Invalid(format!(
                "id_token_ttl must lie within [{MIN_ID_TOKEN_TTL_SECS}, {MAX_ID_TOKEN_TTL_SECS}] seconds"
            )));
        }
        if !(MIN_CODE_TTL_SECS..=MAX_CODE_TTL_SECS).contains(&self.code_ttl_secs) {
            return Err(PosixError::Invalid(format!(
                "code_ttl must lie within [{MIN_CODE_TTL_SECS}, {MAX_CODE_TTL_SECS}] seconds"
            )));
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct OidcConfigUpdate {
    pub enabled: Option<bool>,
    pub issuer: Option<String>,
    /// `Some("")` clears it.
    pub authorization_endpoint: Option<String>,
    pub id_token_ttl_secs: Option<u64>,
    pub code_ttl_secs: Option<u64>,
}

// ─── Clients ────────────────────────────────────────────────────────

/// `idp/oidc/clients/<client_id>`: one relying party, bound for life to one
/// environment. `Debug` never prints the secret digest.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcClient {
    pub version: u32,
    pub client_id: String,
    pub environment: String,
    /// Matched byte for byte against a request's `redirect_uri`.
    pub redirect_uris: Vec<String>,
    /// SHA-256 (hex) of the client secret; the secret itself is not kept.
    pub secret_sha256: String,
    /// OIDC Third-Party Initiated Login entry point of the RP, if any.
    pub initiate_login_uri: Option<String>,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for OidcClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcClient")
            .field("client_id", &self.client_id)
            .field("environment", &self.environment)
            .field("redirect_uris", &self.redirect_uris)
            .finish_non_exhaustive()
    }
}

impl OidcClient {
    pub fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("client_id".into(), self.client_id.clone().into());
        m.insert("environment".into(), self.environment.clone().into());
        m.insert("redirect_uris".into(), Value::from(self.redirect_uris.clone()));
        m.insert("initiate_login_uri".into(), self.initiate_login_uri.clone().into());
        m.insert("description".into(), self.description.clone().into());
        m.insert("created_at".into(), self.created_at.to_rfc3339().into());
        m.insert("updated_at".into(), self.updated_at.to_rfc3339().into());
        m
    }
}

#[derive(Default)]
pub struct ClientWrite {
    pub client_id: String,
    /// Required to create; fixed afterwards (an update may restate it).
    pub environment: Option<String>,
    /// Replaces the whole list; required to create.
    pub redirect_uris: Option<Vec<String>>,
    /// `Some("")` clears it.
    pub initiate_login_uri: Option<String>,
    pub description: Option<String>,
    /// Mint a new secret (the old one stops working at once).
    pub rotate_secret: bool,
}

// ─── Authorization codes ────────────────────────────────────────────

/// `idp/oidc/codes/<expiry>-<sha256(code)>`. The code itself is not
/// stored. The expiry in the key lets expired codes be pruned by listing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthCode {
    pub version: u32,
    pub client_id: String,
    pub entity_id: String,
    pub environment: String,
    /// The roles the gate granted at authorization; the token step asks
    /// for exactly these again.
    pub roles: Vec<String>,
    pub redirect_uri: String,
    /// PKCE S256 challenge (base64url of SHA-256 of the verifier).
    pub code_challenge: String,
    pub nonce: Option<String>,
    pub scope: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

// ─── Launch sessions ────────────────────────────────────────────────

/// `idp/oidc/launch-sessions/<expiry>-<sha256(secret)>`: a single-use OP
/// login for one browser, minted by `v2/idp/oidc/launch-session` with the
/// caller's vault token and consumed by the browser-facing authorization
/// endpoint. The secret itself is not stored, nor is the caller's launch
/// id (only its SHA-256, the digest the launch's own audit lines carry).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchSession {
    pub version: u32,
    /// Random, non-secret identifier the mint, consume and refusal audit
    /// events carry, so they can be tied together without the secret.
    pub session_id: String,
    pub client_id: String,
    pub entity_id: String,
    pub environment: String,
    /// The roles the gate granted at mint; the authorization step asks for
    /// exactly these again.
    pub roles: Vec<String>,
    /// SHA-256 (hex) of the launch id the session is bound to.
    pub launch_id_sha256: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Codes and launch-session secrets are `<expiry unix seconds>.<43
/// base64url characters>`; the key is the expiry (for pruning by listing)
/// and the secret's SHA-256.
fn secret_key(prefix: &str, secret: &str) -> Option<String> {
    let (expiry, random) = secret.split_once('.')?;
    let ok = !expiry.is_empty()
        && expiry.len() <= 12
        && expiry.bytes().all(|b| b.is_ascii_digit())
        && random.len() == 43
        && random.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    ok.then(|| format!("{prefix}{expiry:0>12}-{}", sha256_hex(secret.as_bytes())))
}

fn code_key(code: &str) -> Option<String> {
    secret_key(CODE_PREFIX, code)
}

fn key_expiry(key: &str) -> Option<i64> {
    key.split_once('-').and_then(|(e, _)| e.parse::<i64>().ok())
}

// ─── Store ──────────────────────────────────────────────────────────

pub struct OidcStore {
    storage: Arc<dyn Storage>,
    pub keys: KeyRingStore,
}

#[maybe_async::maybe_async]
impl OidcStore {
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
        let mut entry = StorageEntry::new(key, value)?;
        let result = self.storage.put(&entry).await;
        entry.value.zeroize();
        result
    }

    // ─── Configuration ──────────────────────────────────────────

    pub async fn config(&self) -> Result<Option<OidcConfig>, RvError> {
        self.get_record("oidc config", CONFIG_KEY).await
    }

    pub async fn put_config(&self, update: OidcConfigUpdate, now: DateTime<Utc>) -> Result<OidcConfig, RvError> {
        let _lock = self.write_lock().await?;
        let current = self.config().await?;
        let cur = current.as_ref();
        let issuer = update
            .issuer
            .or_else(|| cur.map(|c| c.issuer.clone()))
            .ok_or_else(|| PosixError::Invalid("issuer is required".into()))?;
        let authorization_endpoint = match update.authorization_endpoint {
            Some(s) if s.is_empty() => None,
            Some(s) => Some(s),
            None => cur.and_then(|c| c.authorization_endpoint.clone()),
        };
        let cfg = OidcConfig {
            version: RECORD_VERSION,
            enabled: update.enabled.or(cur.map(|c| c.enabled)).unwrap_or(false),
            issuer,
            authorization_endpoint,
            id_token_ttl_secs: update
                .id_token_ttl_secs
                .or(cur.map(|c| c.id_token_ttl_secs))
                .unwrap_or(DEFAULT_ID_TOKEN_TTL_SECS),
            code_ttl_secs: update.code_ttl_secs.or(cur.map(|c| c.code_ttl_secs)).unwrap_or(DEFAULT_CODE_TTL_SECS),
            updated_at: now,
        };
        cfg.validate()?;
        self.put_record(CONFIG_KEY, &cfg).await?;
        log::info!(target: "idp", "idp.oidc.config: enabled={} issuer={}", cfg.enabled, cfg.issuer);
        Ok(cfg)
    }

    // ─── Clients ────────────────────────────────────────────────

    pub async fn get_client(&self, client_id: &str) -> Result<Option<OidcClient>, RvError> {
        validate_name("client", client_id)?;
        let rec: Option<OidcClient> = self.get_record("oidc client", &format!("{CLIENT_PREFIX}{client_id}")).await?;
        if rec.as_ref().is_some_and(|r| r.client_id != client_id) {
            return Err(PosixError::Corrupt(format!("oidc client record `{client_id}` names another client")).into());
        }
        Ok(rec)
    }

    pub async fn list_clients(&self) -> Result<Vec<OidcClient>, RvError> {
        let mut out = Vec::new();
        for entry in self.storage.scan(CLIENT_PREFIX, None).await? {
            out.push(decode_versioned::<OidcClient>("oidc client", &entry.value)?);
        }
        out.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        Ok(out)
    }

    /// Create or update a client. A new client, or `rotate_secret`, mints a
    /// secret that is returned once and stored only as its SHA-256.
    pub async fn put_client(
        &self,
        authz: &EntitlementStore,
        w: ClientWrite,
        now: DateTime<Utc>,
    ) -> Result<(OidcClient, bool, Option<Zeroizing<String>>), RvError> {
        validate_name("client", &w.client_id)?;
        if let Some(d) = &w.description {
            validate_description(d)?;
        }
        let _lock = self.write_lock().await?;
        let current = self.get_client(&w.client_id).await?;
        let cur = current.as_ref();
        let environment = match (w.environment, cur) {
            (Some(e), Some(c)) if e != c.environment => {
                return Err(PosixError::Invalid("a client's environment is fixed at creation".into()).into())
            }
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
        let redirect_uris = match (w.redirect_uris, cur) {
            (Some(r), _) => r,
            (None, Some(c)) => c.redirect_uris.clone(),
            (None, None) => {
                return Err(PosixError::Invalid("redirect_uris are required to create a client".into()).into())
            }
        };
        validate_url_list("redirect_uris", &redirect_uris, MAX_REDIRECT_URIS)?;
        let initiate_login_uri = match w.initiate_login_uri {
            Some(s) if s.is_empty() => None,
            Some(s) => {
                validate_https_url("initiate_login_uri", &s)?;
                Some(s)
            }
            None => cur.and_then(|c| c.initiate_login_uri.clone()),
        };
        let fresh = (cur.is_none() || w.rotate_secret).then(|| random_b64url(SECRET_BYTES));
        let secret_sha256 = match (&fresh, cur) {
            (Some(s), _) => sha256_hex(s.as_bytes()),
            (None, Some(c)) => c.secret_sha256.clone(),
            (None, None) => return Err(PosixError::Corrupt("a new client has no secret".into()).into()),
        };
        let rec = OidcClient {
            version: RECORD_VERSION,
            client_id: w.client_id.clone(),
            environment,
            redirect_uris,
            secret_sha256,
            initiate_login_uri,
            description: w.description.or_else(|| cur.and_then(|c| c.description.clone())),
            created_at: cur.map(|c| c.created_at).unwrap_or(now),
            updated_at: now,
        };
        self.put_record(&format!("{CLIENT_PREFIX}{}", rec.client_id), &rec).await?;
        log::info!(
            target: "idp",
            "idp.oidc.client: {} client_id={} environment={} secret_rotated={}",
            if cur.is_none() { "create" } else { "update" },
            rec.client_id,
            rec.environment,
            fresh.is_some()
        );
        Ok((rec, cur.is_none(), fresh))
    }

    pub async fn delete_client(&self, client_id: &str) -> Result<Option<OidcClient>, RvError> {
        validate_name("client", client_id)?;
        let _lock = self.write_lock().await?;
        let Some(rec) = self.get_client(client_id).await? else {
            return Ok(None);
        };
        self.storage.delete(&format!("{CLIENT_PREFIX}{client_id}")).await?;
        log::info!(target: "idp", "idp.oidc.client: delete client_id={client_id}");
        Ok(Some(rec))
    }

    // ─── Codes ──────────────────────────────────────────────────

    /// Store a code for `rec` (the gate has already allowed it) and return
    /// the code, once. Expired codes are pruned first.
    pub async fn mint_code(&self, rec: &AuthCode, now: DateTime<Utc>) -> Result<Zeroizing<String>, RvError> {
        validate_entity_id(&rec.entity_id)?;
        if rec.redirect_uri.len() > MAX_URL_LEN {
            return Err(PosixError::Invalid("redirect_uri is too long".into()).into());
        }
        self.mint_secret(CODE_PREFIX, rec, rec.expires_at, now).await
    }

    /// Store `rec` under a fresh `<expiry>.<random>` secret below `prefix`
    /// and return the secret, once. Expired entries under `prefix` are
    /// pruned first.
    async fn mint_secret<T: Serialize + Sync>(
        &self,
        prefix: &str,
        rec: &T,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<Zeroizing<String>, RvError> {
        let _lock = self.write_lock().await?;
        for key in self.storage.list(prefix).await? {
            if key_expiry(&key).is_none_or(|e| e <= now.timestamp()) {
                self.storage.delete(&format!("{prefix}{key}")).await?;
            }
        }
        let random = random_b64url(SECRET_BYTES);
        let secret = Zeroizing::new(format!("{}.{}", expires_at.timestamp(), random.as_str()));
        let key =
            secret_key(prefix, &secret).ok_or_else(|| PosixError::Corrupt("minted secret is malformed".into()))?;
        self.put_record(&key, rec).await?;
        Ok(secret)
    }

    /// Take a code: whatever happens next, it is gone (single use). `None`
    /// if there is no such code (never minted, already used, or pruned).
    pub async fn take_code(&self, code: &str) -> Result<Option<AuthCode>, RvError> {
        let Some(key) = code_key(code) else {
            return Ok(None);
        };
        let _lock = self.write_lock().await?;
        let rec = self.get_record::<AuthCode>("oidc authorization code", &key).await?;
        if rec.is_some() {
            self.storage.delete(&key).await?;
        }
        Ok(rec)
    }

    // ─── Launch sessions ────────────────────────────────────────

    /// Store a launch session for `rec` (the gate has already allowed it)
    /// and return its secret, once. Expired sessions are pruned first.
    pub async fn mint_launch_session(
        &self,
        rec: &LaunchSession,
        now: DateTime<Utc>,
    ) -> Result<Zeroizing<String>, RvError> {
        validate_entity_id(&rec.entity_id)?;
        self.mint_secret(LAUNCH_SESSION_PREFIX, rec, rec.expires_at, now).await
    }

    /// Take a launch session: whatever happens next, it is gone (single
    /// use). `None` if there is no such session (malformed, never minted,
    /// already used, or pruned).
    pub async fn take_launch_session(&self, secret: &str) -> Result<Option<LaunchSession>, RvError> {
        let Some(key) = secret_key(LAUNCH_SESSION_PREFIX, secret) else {
            return Ok(None);
        };
        // The browser endpoint is unauthenticated: a miss is answered
        // without the cluster-wide write lock, so guessing cannot contend
        // it. A hit is read again under the lock before it is deleted, so
        // two concurrent uses cannot both get it.
        if self.storage.get(&key).await?.is_none() {
            return Ok(None);
        }
        let _lock = self.write_lock().await?;
        let rec = self.get_record::<LaunchSession>("oidc launch session", &key).await?;
        if rec.is_some() {
            self.storage.delete(&key).await?;
        }
        Ok(rec)
    }
}
