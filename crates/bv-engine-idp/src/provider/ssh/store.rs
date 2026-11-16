//! `idp/ssh/` on the root system view: the SSH provider's configuration and
//! a registry of every certificate it issued, which the KRL is built from.
//! Writes run under a process-local mutex plus the storage lock, as the
//! POSIX and entitlement stores do.

use std::{any::Any, sync::Arc};

use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    errors::RvError,
    posix::model::{decode_versioned, validate_entity_id, validate_reason, PosixError, RECORD_VERSION},
    storage::{Storage, StorageEntry},
};

pub const STORAGE_LOCK_NAME: &str = "bv-idp/ssh";
const CONFIG_KEY: &str = "config";
pub const CERT_PREFIX: &str = "certs/";

/// Hard ceiling on any certificate lifetime, whatever the configuration.
pub const TTL_CEILING_SECS: u64 = 8 * 3600;
pub const MIN_TTL_SECS: u64 = 60;
pub const DEFAULT_TTL_SECS: u64 = 30 * 60;
pub const DEFAULT_MAX_TTL_SECS: u64 = 3600;
pub const DEFAULT_MOUNT: &str = "ssh";
pub const DEFAULT_ROLE: &str = "idp";
/// An expired certificate's record is pruned this long after it expired,
/// the next time the same identity is issued a certificate.
pub const EXPIRED_RETENTION_SECS: u64 = 24 * 3600;
const MAX_MOUNT_LEN: usize = 128;
const MAX_ROLE_LEN: usize = 64;

static LOCAL_WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Both halves of the write lock; field order is drop order.
struct WriteLock {
    _cluster: Box<dyn Any + Send>,
    _local: tokio::sync::MutexGuard<'static, ()>,
}

/// `idp/ssh/config`. Absent means the SSH provider is off: nothing is signed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshProviderConfig {
    pub version: u32,
    /// SSH engine mount path, resolved inside each environment's namespace.
    pub mount: String,
    /// CA-mode role on that mount.
    pub role: String,
    pub default_ttl_secs: u64,
    pub max_ttl_secs: u64,
    pub updated_at: DateTime<Utc>,
}

impl SshProviderConfig {
    pub fn to_map(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut m = serde_json::Map::new();
        m.insert("enabled".into(), true.into());
        m.insert("mount".into(), self.mount.clone().into());
        m.insert("role".into(), self.role.clone().into());
        m.insert("default_ttl".into(), self.default_ttl_secs.into());
        m.insert("max_ttl".into(), self.max_ttl_secs.into());
        m.insert("ttl_ceiling".into(), TTL_CEILING_SECS.into());
        m.insert("updated_at".into(), self.updated_at.to_rfc3339().into());
        m
    }
}

/// A partial update; the first write fills the rest with the defaults.
#[derive(Debug, Clone, Default)]
pub struct SshConfigUpdate {
    pub mount: Option<String>,
    pub role: Option<String>,
    pub default_ttl_secs: Option<u64>,
    pub max_ttl_secs: Option<u64>,
}

/// `idp/ssh/certs/<entity_id>/<serial>`: one issued certificate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertRecord {
    pub version: u32,
    /// 16 lower-case hex digits, as the SSH engine reports it.
    pub serial: String,
    pub entity_id: String,
    pub login: String,
    pub uid: u32,
    pub environment: String,
    pub namespace: String,
    pub key_id: String,
    /// The CA that signed it, as an OpenSSH public-key line.
    pub ca_public_key: String,
    pub valid_after: u64,
    pub valid_before: u64,
    pub issued_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoke_reason: Option<String>,
}

impl CertRecord {
    pub fn serial_u64(&self) -> Result<u64, PosixError> {
        parse_serial(&self.serial)
    }
}

pub fn format_serial(serial: u64) -> String {
    format!("{serial:016x}")
}

/// Exactly 16 lower-case hex digits.
pub fn parse_serial(s: &str) -> Result<u64, PosixError> {
    let ok = s.len() == 16 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !ok {
        return Err(PosixError::Invalid(format!("serial `{s}` is not 16 lower-case hex digits")));
    }
    u64::from_str_radix(s, 16).map_err(|_| PosixError::Invalid(format!("serial `{s}` is not a 64-bit number")))
}

/// A mount path: `/`-separated segments of `[A-Za-z0-9_-]`.
pub fn validate_mount(mount: &str) -> Result<(), PosixError> {
    let ok = !mount.is_empty()
        && mount.len() <= MAX_MOUNT_LEN
        && mount
            .split('/')
            .all(|seg| !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'));
    if ok {
        Ok(())
    } else {
        Err(PosixError::Invalid(format!(
            "mount must be at most {MAX_MOUNT_LEN} characters of `/`-separated [A-Za-z0-9_-] segments"
        )))
    }
}

/// The SSH engine's role-name pattern `\w[\w-]*\w`.
pub fn validate_role(role: &str) -> Result<(), PosixError> {
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let bytes = role.as_bytes();
    let ok = bytes.len() >= 2
        && bytes.len() <= MAX_ROLE_LEN
        && word(bytes[0])
        && word(bytes[bytes.len() - 1])
        && bytes.iter().all(|b| word(*b) || *b == b'-');
    if ok {
        Ok(())
    } else {
        Err(PosixError::Invalid(format!("role must match \\w[\\w-]*\\w and be at most {MAX_ROLE_LEN} characters")))
    }
}

fn validate_ttls(default_ttl: u64, max_ttl: u64) -> Result<(), PosixError> {
    if !(MIN_TTL_SECS..=TTL_CEILING_SECS).contains(&max_ttl) {
        return Err(PosixError::Invalid(format!(
            "max_ttl must lie within [{MIN_TTL_SECS}, {TTL_CEILING_SECS}] seconds"
        )));
    }
    if default_ttl < MIN_TTL_SECS || default_ttl > max_ttl {
        return Err(PosixError::Invalid(format!("default_ttl must lie within [{MIN_TTL_SECS}, max_ttl] seconds")));
    }
    Ok(())
}

fn cert_dir(entity_id: &str) -> String {
    format!("{CERT_PREFIX}{entity_id}/")
}

pub struct SshStore {
    storage: Arc<dyn Storage>,
}

#[maybe_async::maybe_async]
impl SshStore {
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
            Some(entry) => Ok(Some(decode_versioned(what, &entry.value)?)),
        }
    }

    async fn put_record<T: Serialize + Sync>(&self, key: &str, value: &T) -> Result<(), RvError> {
        self.storage.put(&StorageEntry::new(key, value)?).await
    }

    pub async fn config(&self) -> Result<Option<SshProviderConfig>, RvError> {
        self.get_record("ssh provider config", CONFIG_KEY).await
    }

    pub async fn put_config(&self, update: SshConfigUpdate, now: DateTime<Utc>) -> Result<SshProviderConfig, RvError> {
        let _lock = self.write_lock().await?;
        let current = self.config().await?;
        let mount = update
            .mount
            .map(|m| m.trim().trim_matches('/').to_string())
            .or_else(|| current.as_ref().map(|c| c.mount.clone()))
            .unwrap_or_else(|| DEFAULT_MOUNT.to_string());
        let role = update.role.or_else(|| current.as_ref().map(|c| c.role.clone())).unwrap_or(DEFAULT_ROLE.into());
        let max_ttl_secs =
            update.max_ttl_secs.or_else(|| current.as_ref().map(|c| c.max_ttl_secs)).unwrap_or(DEFAULT_MAX_TTL_SECS);
        let default_ttl_secs = update
            .default_ttl_secs
            .or_else(|| current.as_ref().map(|c| c.default_ttl_secs))
            .unwrap_or(DEFAULT_TTL_SECS.min(max_ttl_secs));
        validate_mount(&mount)?;
        validate_role(&role)?;
        validate_ttls(default_ttl_secs, max_ttl_secs)?;
        let cfg =
            SshProviderConfig { version: RECORD_VERSION, mount, role, default_ttl_secs, max_ttl_secs, updated_at: now };
        self.put_record(CONFIG_KEY, &cfg).await?;
        log::info!(
            target: "idp",
            "idp.ssh.config: mount={} role={} default_ttl={} max_ttl={}",
            cfg.mount,
            cfg.role,
            cfg.default_ttl_secs,
            cfg.max_ttl_secs
        );
        Ok(cfg)
    }

    /// Record a certificate before it is handed out. A serial already
    /// recorded for the identity is refused (the certificate is not issued).
    /// Records expired for longer than [`EXPIRED_RETENTION_SECS`] are pruned.
    pub async fn record_issued(&self, rec: &CertRecord, now_secs: u64) -> Result<(), RvError> {
        validate_entity_id(&rec.entity_id)?;
        parse_serial(&rec.serial)?;
        let _lock = self.write_lock().await?;
        let dir = cert_dir(&rec.entity_id);
        let key = format!("{dir}{}", rec.serial);
        if self.storage.get(&key).await?.is_some() {
            return Err(PosixError::Conflict(format!("certificate serial {} is already recorded", rec.serial)).into());
        }
        for existing in self.certs_of_locked(&rec.entity_id).await? {
            if existing.valid_before.saturating_add(EXPIRED_RETENTION_SECS) < now_secs {
                self.storage.delete(&format!("{dir}{}", existing.serial)).await?;
            }
        }
        self.put_record(&key, rec).await
    }

    async fn certs_of_locked(&self, entity_id: &str) -> Result<Vec<CertRecord>, RvError> {
        let mut out = Vec::new();
        for entry in self.storage.scan(&cert_dir(entity_id), None).await? {
            out.push(decode_versioned::<CertRecord>("certificate", &entry.value)?);
        }
        Ok(out)
    }

    pub async fn certs_of(&self, entity_id: &str) -> Result<Vec<CertRecord>, RvError> {
        validate_entity_id(entity_id)?;
        let mut out = self.certs_of_locked(entity_id).await?;
        out.sort_by(|a, b| a.serial.cmp(&b.serial));
        Ok(out)
    }

    /// Mark every unexpired, unrevoked certificate of the identity revoked.
    /// Idempotent; returns how many were newly marked.
    pub async fn revoke_entity(&self, entity_id: &str, reason: &str, now: DateTime<Utc>) -> Result<usize, RvError> {
        validate_entity_id(entity_id)?;
        validate_reason(reason)?;
        let now_secs = u64::try_from(now.timestamp()).unwrap_or(0);
        let _lock = self.write_lock().await?;
        let dir = cert_dir(entity_id);
        let mut marked = 0;
        for mut rec in self.certs_of_locked(entity_id).await? {
            if rec.revoked_at.is_some() || rec.valid_before <= now_secs {
                continue;
            }
            rec.revoked_at = Some(now);
            rec.revoke_reason = Some(reason.to_string());
            self.put_record(&format!("{dir}{}", rec.serial), &rec).await?;
            marked += 1;
        }
        if marked > 0 {
            log::info!(target: "idp", "idp.ssh.revoke: entity_id={entity_id} certificates={marked} reason={reason}");
        }
        Ok(marked)
    }

    /// Every recorded certificate. A record that does not decode is an error,
    /// never skipped: the KRL is built from this list.
    pub async fn list_certs(&self) -> Result<Vec<CertRecord>, RvError> {
        let mut out = Vec::new();
        for entry in self.storage.scan(CERT_PREFIX, None).await? {
            let rec: CertRecord = decode_versioned("certificate", &entry.value)?;
            if entry.key != format!("{}{}", cert_dir(&rec.entity_id), rec.serial) {
                return Err(PosixError::Corrupt(format!(
                    "certificate record `{}` is filed under another key",
                    entry.key
                ))
                .into());
            }
            out.push(rec);
        }
        out.sort_by(|a, b| (&a.entity_id, &a.serial).cmp(&(&b.entity_id, &b.serial)));
        Ok(out)
    }
}
