//! The credential cache behind `creds/` (`bv_dynamic::cache`): entries per
//! node, validity cluster-wide. Opt-in per role (`cache_ttl_secs`), keyed by
//! (mount, role, caller entity). A hit hands back an earlier credential and
//! names its lease; it mints nothing. Every hit re-reads two records in the
//! mount's replicated storage (the mount epoch and the credential's marker),
//! so a renew, revoke, role or config write or rotate-root on any node refuses it.
//! Unreadable storage is a miss, never a stale hit.

use std::{
    any::Any,
    sync::{Arc, OnceLock, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bv_dynamic::cache::{
    effective_ttl, marker_key, CacheKey, CredentialCache, EpochRecord, MarkerRecord, Read, Validity,
    DEFAULT_MAX_ENTRIES, EPOCH_KEY,
};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::{
    errors::RvError,
    storage::{Storage, StorageEntry},
};

/// The `RwLock<Option<String>>` the kernel writes the miss's lease id into
/// (`expiration::HOST_MANAGED_LEASE_SLOT`) once it registered that lease.
pub type LeaseSlot = Arc<RwLock<dyn Any + Send + Sync>>;

pub fn new_slot() -> LeaseSlot {
    Arc::new(RwLock::new(None::<String>))
}

/// One cached credential. No `Debug`: `data` holds the password; it is
/// serialised once, shared by every hit and wiped when the last copy drops.
#[derive(Clone)]
pub struct CachedCredential {
    data: Arc<Zeroizing<Vec<u8>>>,
    lease: LeaseSlot,
    lease_expires_at: Instant,
    validity: Validity,
    pub renewable: bool,
    pub plugin: String,
    /// `name@version#sha256` of the build that issued it.
    pub plugin_build: String,
    pub role: String,
    pub connection: String,
    pub username: String,
}

/// What [`NodeCache::remember`] needs about the credential it caches.
pub struct Issued<'a> {
    pub data: &'a Map<String, Value>,
    pub lease_ttl: Duration,
    pub renewable: bool,
    pub plugin: &'a str,
    pub plugin_build: &'a str,
    pub role: &'a str,
    pub connection: &'a str,
    pub username: &'a str,
}

impl CachedCredential {
    /// The lease the kernel registered for it; `None` until then, and for
    /// good when registration failed.
    pub fn lease_id(&self) -> Option<String> {
        self.lease.read().ok()?.downcast_ref::<Option<String>>()?.clone()
    }

    pub fn data(&self) -> Option<Map<String, Value>> {
        serde_json::from_slice(&self.data).ok()
    }

    pub fn lease_remaining(&self, now: Instant) -> Duration {
        self.lease_expires_at.saturating_duration_since(now)
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The mount's cache epoch, as storage holds it now.
pub async fn read_epoch(storage: &dyn Storage) -> Read<EpochRecord> {
    match storage.get(EPOCH_KEY).await {
        Ok(None) => Read::Absent,
        Ok(Some(e)) => EpochRecord::decode(&e.value).map_or(Read::Failed, Read::Found),
        Err(e) => {
            log::warn!("credential cache epoch unreadable ({e}); serving no cached credential");
            Read::Failed
        }
    }
}

async fn read_marker(storage: &dyn Storage, username: &str) -> Read<MarkerRecord> {
    let Ok(key) = marker_key(username) else { return Read::Failed };
    match storage.get(&key).await {
        Ok(None) => Read::Absent,
        Ok(Some(e)) => MarkerRecord::decode(&e.value).map_or(Read::Failed, Read::Found),
        Err(e) => {
            log::warn!("credential cache marker unreadable ({e}); serving no cached credential");
            Read::Failed
        }
    }
}

/// One node's entries.
pub struct NodeCache {
    entries: CredentialCache<CachedCredential>,
}

impl NodeCache {
    pub fn new(max_entries: usize) -> Self {
        Self { entries: CredentialCache::new(max_entries) }
    }

    /// Cache `issued` under `key` for the role's window, clamped well inside
    /// the lease, after writing its marker. `epoch` is what [`read_epoch`]
    /// returned *before* the role was read. Returns the slot to hand the
    /// kernel, or `None` when nothing was cached (the window clamps to zero,
    /// or the epoch or marker could not be read or written: fail closed).
    pub async fn remember(
        &self,
        storage: &dyn Storage,
        key: CacheKey,
        issued: Issued<'_>,
        cache_ttl: Duration,
        epoch: &Read<EpochRecord>,
    ) -> Option<LeaseSlot> {
        let ttl = effective_ttl(cache_ttl, issued.lease_ttl);
        let epoch = match epoch {
            _ if ttl.is_zero() => return None,
            Read::Absent => None,
            Read::Found(rec) => Some(rec.nonce.clone()),
            Read::Failed => return None,
        };
        let marker = MarkerRecord::fresh(unix_now() + ttl.as_secs() + 1).ok()?;
        let entry = StorageEntry { key: marker_key(issued.username).ok()?, value: serde_json::to_vec(&marker).ok()? };
        if let Err(e) = storage.put(&entry).await {
            log::warn!("credential cache marker could not be written ({e}); credential not cached");
            return None;
        }
        let data = Zeroizing::new(serde_json::to_vec(issued.data).ok()?);
        let now = Instant::now();
        let slot = new_slot();
        let cached = CachedCredential {
            data: Arc::new(data),
            lease: slot.clone(),
            lease_expires_at: now + issued.lease_ttl,
            validity: Validity { epoch, marker: marker.nonce },
            renewable: issued.renewable,
            plugin: issued.plugin.to_string(),
            plugin_build: issued.plugin_build.to_string(),
            role: issued.role.to_string(),
            connection: issued.connection.to_string(),
            username: issued.username.to_string(),
        };
        self.entries.insert(key, issued.username, cached, ttl, now).then_some(slot)
    }

    /// The entry for `key` and its lease id, if the cluster still vouches for
    /// it: its lease is registered, the issuing build is still `plugin_build`,
    /// and the mount epoch and its marker are as they were. Anything else
    /// drops the entry here.
    pub async fn lookup(
        &self,
        storage: &dyn Storage,
        key: &CacheKey,
        plugin_build: &str,
    ) -> Option<(CachedCredential, String)> {
        let entry = self.entries.get(key, Instant::now())?;
        let lease_id = entry.lease_id().filter(|_| entry.plugin_build == plugin_build);
        let Some(lease_id) = lease_id else {
            self.entries.remove(key);
            return None;
        };
        let epoch = read_epoch(storage).await;
        let marker = read_marker(storage, &entry.username).await;
        if !entry.validity.holds(&epoch, &marker, unix_now()) {
            self.entries.remove(key);
            return None;
        }
        Some((entry, lease_id))
    }

    /// The lease of the credential `username` was revoked or renewed here.
    pub fn invalidate_credential(&self, username: &str) -> usize {
        self.entries.evict_credential(username)
    }

    pub fn invalidate_mount(&self, mount_id: &str) -> usize {
        self.entries.evict_matching(|k, _| k.mount == mount_id)
    }

    pub fn invalidate_role(&self, mount_id: &str, role: &str) -> usize {
        self.entries.evict_matching(|k, _| k.mount == mount_id && k.role == role)
    }

    pub fn invalidate_plugin(&self, plugin: &str) -> usize {
        self.entries.evict_matching(|_, v| v.plugin == plugin)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// This node's cache.
pub fn node() -> &'static NodeCache {
    static CACHE: OnceLock<NodeCache> = OnceLock::new();
    CACHE.get_or_init(|| NodeCache::new(DEFAULT_MAX_ENTRIES))
}

/// The lease of `username` is being renewed or revoked (by this node): drop
/// it here and remove its marker, so no node serves it again. A marker that
/// cannot be removed is an error for the caller to fail on.
pub async fn forget_credential(storage: &dyn Storage, username: &str) -> Result<(), RvError> {
    node().invalidate_credential(username);
    let key = marker_key(username)?;
    storage.delete(&key).await
}

/// Every cached credential of the mount is stale (a role or connection was
/// written or deleted, the root credential rotated): drop them here and start
/// a new epoch, which refuses them on every other node.
pub async fn bump_epoch(storage: &dyn Storage, mount_id: &str) -> Result<(), RvError> {
    node().invalidate_mount(mount_id);
    let record = EpochRecord::fresh()?;
    storage.put(&StorageEntry { key: EPOCH_KEY.to_string(), value: serde_json::to_vec(&record)? }).await
}

/// Local-only: the lease of `username` was revoked or renewed, and the
/// caller has no storage (its marker is then dropped on that lease's retry).
pub fn invalidate_credential(username: &str) -> usize {
    node().invalidate_credential(username)
}

/// Every entry of `role` on `mount_id` on this node (before a role write;
/// the epoch is bumped after it).
pub fn invalidate_role(mount_id: &str, role: &str) -> usize {
    node().invalidate_role(mount_id, role)
}

/// Every entry a plugin issued on this node (it was unloaded, replaced or
/// quarantined). Other nodes refuse those entries on their own: a
/// quarantined or deleted plugin's mount is refused before the cache, and a
/// replaced build no longer matches the entry's `plugin_build`.
pub fn invalidate_plugin(plugin: &str) -> usize {
    node().invalidate_plugin(plugin)
}
