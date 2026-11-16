//! `idp/revoke/` on the root system view: the deny feed's version state and
//! its signing key. The key sits behind the storage barrier like every other
//! key the vault holds; it is created on first use and never logged.

use std::{any::Any, sync::Arc};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::feed::{FeedSigner, FEED_ALGORITHM};
use crate::{
    errors::RvError,
    posix::model::{decode_versioned, PosixError, RECORD_VERSION},
    storage::{Storage, StorageEntry},
};

pub const STORAGE_LOCK_NAME: &str = "bv-idp/revoke";
const STATE_KEY: &str = "feed/state";
const KEY_KEY: &str = "feed/key";

static LOCAL_WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Held while a feed version is decided. Field order is drop order.
pub struct FeedLock {
    _cluster: Box<dyn Any + Send>,
    _local: tokio::sync::MutexGuard<'static, ()>,
}

/// `idp/revoke/feed/state`: the current version and the content it names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedState {
    pub version: u32,
    pub feed_version: u64,
    pub content_sha256: String,
    pub updated_at: DateTime<Utc>,
}

/// `idp/revoke/feed/key`. The seeds are wiped when the record drops.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FeedKeyRecord {
    version: u32,
    algorithm: String,
    ed25519_seed: String,
    mldsa65_seed: String,
    created_at: DateTime<Utc>,
}

impl Drop for FeedKeyRecord {
    fn drop(&mut self) {
        self.ed25519_seed.zeroize();
        self.mldsa65_seed.zeroize();
    }
}

fn decode_seed<const N: usize>(what: &'static str, b64: &str) -> Result<Zeroizing<[u8; N]>, RvError> {
    let bytes = Zeroizing::new(
        B64.decode(b64).map_err(|_| PosixError::Corrupt(format!("deny-feed key: {what} is not base64")))?,
    );
    let mut out = Zeroizing::new([0u8; N]);
    if bytes.len() != N {
        return Err(PosixError::Corrupt(format!("deny-feed key: {what} has the wrong length")).into());
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub struct FeedStore {
    storage: Arc<dyn Storage>,
}

#[maybe_async::maybe_async]
impl FeedStore {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }

    pub async fn lock(&self) -> Result<FeedLock, RvError> {
        let local = LOCAL_WRITE_LOCK.lock().await;
        let cluster = self.storage.lock(STORAGE_LOCK_NAME).await?;
        Ok(FeedLock { _cluster: cluster, _local: local })
    }

    pub async fn state(&self) -> Result<Option<FeedState>, RvError> {
        match self.storage.get(STATE_KEY).await? {
            None => Ok(None),
            Some(entry) => Ok(Some(decode_versioned("deny-feed state", &entry.value)?)),
        }
    }

    /// The version for `digest`: unchanged when the content is, otherwise
    /// one above the stored version. Never moves down; never wraps. Takes
    /// the lock by `&mut` because the guard is `Send` but not `Sync`.
    pub async fn advance_locked(&self, _lock: &mut FeedLock, digest: &str, now: DateTime<Utc>) -> Result<u64, RvError> {
        let current = self.state().await?;
        if let Some(state) = &current {
            if state.content_sha256 == digest {
                return Ok(state.feed_version);
            }
        }
        let previous = current.as_ref().map(|s| s.feed_version).unwrap_or(0);
        let next =
            previous.checked_add(1).ok_or_else(|| PosixError::Corrupt("deny-feed version is exhausted".into()))?;
        let state = FeedState {
            version: RECORD_VERSION,
            feed_version: next,
            content_sha256: digest.to_string(),
            updated_at: now,
        };
        self.storage.put(&StorageEntry::new(STATE_KEY, &state)?).await?;
        log::info!(target: "idp", "idp.deny-feed.version: {previous} -> {next}");
        Ok(next)
    }

    /// The signing key, created on first use under the lock.
    pub async fn signer(&self, now: DateTime<Utc>) -> Result<FeedSigner, RvError> {
        if let Some(signer) = self.load_signer().await? {
            return Ok(signer);
        }
        let _lock = self.lock().await?;
        if let Some(signer) = self.load_signer().await? {
            return Ok(signer);
        }
        let signer = FeedSigner::generate()?;
        let (ed, ml) = signer.seeds();
        let record = FeedKeyRecord {
            version: RECORD_VERSION,
            algorithm: FEED_ALGORITHM.to_string(),
            ed25519_seed: B64.encode(ed.as_ref()),
            mldsa65_seed: B64.encode(ml.as_ref()),
            created_at: now,
        };
        let mut entry = StorageEntry { key: KEY_KEY.to_string(), value: serde_json::to_vec(&record)? };
        let stored = self.storage.put(&entry).await;
        entry.value.zeroize();
        stored?;
        log::info!(target: "idp", "idp.deny-feed.key-create: key_id={}", signer.public_key().key_id());
        Ok(signer)
    }

    async fn load_signer(&self) -> Result<Option<FeedSigner>, RvError> {
        let Some(mut entry) = self.storage.get(KEY_KEY).await? else {
            return Ok(None);
        };
        let decoded = decode_versioned::<FeedKeyRecord>("deny-feed key", &entry.value);
        entry.value.zeroize();
        let record = decoded?;
        if record.algorithm != FEED_ALGORITHM {
            return Err(PosixError::Corrupt(format!("deny-feed key has algorithm `{}`", record.algorithm)).into());
        }
        let ed = decode_seed::<32>("ed25519 seed", &record.ed25519_seed)?;
        let ml = decode_seed::<{ bv_crypto::ML_DSA_65_SEED_LEN }>("ml-dsa-65 seed", &record.mldsa65_seed)?;
        Ok(Some(FeedSigner::from_seeds(&ed, &ml)))
    }
}
