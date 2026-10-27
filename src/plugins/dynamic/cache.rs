//! The credential cache behind `creds/` (`bv_dynamic::cache`), one per node.
//!
//! Opt-in per role (`cache_ttl_secs`), keyed by (mount, role, caller entity).
//! A hit hands back the credential of an earlier request and names its lease;
//! it mints nothing and registers no lease. Entries are dropped on any revoke
//! or renew of their lease, on rotate-root, on plugin unload and on expiry.

use std::{
    any::Any,
    sync::{Arc, OnceLock, RwLock},
    time::{Duration, Instant},
};

use bv_dynamic::cache::{effective_ttl, CacheKey, CredentialCache, DEFAULT_MAX_ENTRIES};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

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
    pub renewable: bool,
    pub plugin: String,
    pub role: String,
    pub connection: String,
    pub username: String,
}

/// What [`remember`] needs about the credential it caches.
pub struct Issued<'a> {
    pub data: &'a Map<String, Value>,
    pub lease_ttl: Duration,
    pub renewable: bool,
    pub plugin: &'a str,
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

fn cache() -> &'static CredentialCache<CachedCredential> {
    static CACHE: OnceLock<CredentialCache<CachedCredential>> = OnceLock::new();
    CACHE.get_or_init(|| CredentialCache::new(DEFAULT_MAX_ENTRIES))
}

/// Cache `issued` under `key` for the role's window, clamped well inside the
/// lease. Returns the slot to hand the kernel, or `None` when the window
/// clamps to nothing (the credential is then not cached).
pub fn remember(key: CacheKey, issued: Issued<'_>, cache_ttl: Duration) -> Option<LeaseSlot> {
    let ttl = effective_ttl(cache_ttl, issued.lease_ttl);
    if ttl.is_zero() {
        return None;
    }
    let data = Zeroizing::new(serde_json::to_vec(issued.data).ok()?);
    let now = Instant::now();
    let slot = new_slot();
    let entry = CachedCredential {
        data: Arc::new(data),
        lease: slot.clone(),
        lease_expires_at: now + issued.lease_ttl,
        renewable: issued.renewable,
        plugin: issued.plugin.to_string(),
        role: issued.role.to_string(),
        connection: issued.connection.to_string(),
        username: issued.username.to_string(),
    };
    cache().insert(key, issued.username, entry, ttl, now).then_some(slot)
}

/// The live entry for `key` and its lease id. An entry whose lease was never
/// registered is dropped rather than served.
pub fn lookup(key: &CacheKey) -> Option<(CachedCredential, String)> {
    let entry = cache().get(key, Instant::now())?;
    match entry.lease_id() {
        Some(lease_id) => Some((entry, lease_id)),
        None => {
            cache().remove(key);
            None
        }
    }
}

/// The lease of the credential `username` was revoked or renewed.
pub fn invalidate_credential(username: &str) -> usize {
    cache().evict_credential(username)
}

/// Every entry of the mount `mount_id` (its root credential rotated).
pub fn invalidate_mount(mount_id: &str) -> usize {
    cache().evict_matching(|k, _| k.mount == mount_id)
}

/// Every entry of `role` on `mount_id` (the role was rewritten or deleted).
pub fn invalidate_role(mount_id: &str, role: &str) -> usize {
    cache().evict_matching(|k, _| k.mount == mount_id && k.role == role)
}

/// Every entry a plugin issued (it was unloaded, replaced or quarantined).
pub fn invalidate_plugin(plugin: &str) -> usize {
    cache().evict_matching(|_, v| v.plugin == plugin)
}
