//! Opt-in per-(mount, role, identity) credential cache.
//!
//! A role with `cache_ttl > 0` may hand the same credential to one identity
//! that asks again within a short window. The key always carries the caller's
//! entity, so two identities never share a credential, and a caller without an
//! entity is never cached. Entries expire well before the credential does.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Hard ceiling on a cache entry's life, whatever the role asks for.
pub const MAX_CACHE_TTL: Duration = Duration::from_secs(300);
/// Least lease time a credential must have left to be served from the cache.
pub const MIN_LEASE_HEADROOM: Duration = Duration::from_secs(60);
/// Default bound on live entries per cache.
pub const DEFAULT_MAX_ENTRIES: usize = 4096;

/// Who a cached credential belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CacheKey {
    pub mount: String,
    pub role: String,
    pub entity_id: String,
}

impl CacheKey {
    /// `None` when the caller has no identity entity: such callers are never
    /// served from the cache.
    pub fn new(mount: &str, role: &str, entity_id: &str) -> Option<Self> {
        if entity_id.trim().is_empty() || mount.is_empty() || role.is_empty() {
            return None;
        }
        Some(Self { mount: mount.to_string(), role: role.to_string(), entity_id: entity_id.to_string() })
    }
}

/// How long a credential whose lease has `lease_ttl` left may be served from
/// the cache: the role's `cache_ttl` (at most [`MAX_CACHE_TTL`]), ending while
/// the lease still has `max(2 x that window, MIN_LEASE_HEADROOM)` to run.
/// Zero means "do not cache".
pub fn effective_ttl(cache_ttl: Duration, lease_ttl: Duration) -> Duration {
    let window = cache_ttl.min(MAX_CACHE_TTL);
    if window.is_zero() {
        return Duration::ZERO;
    }
    let headroom = window.saturating_mul(2).max(MIN_LEASE_HEADROOM);
    window.min(lease_ttl.saturating_sub(headroom))
}

struct Entry<V> {
    value: V,
    /// The credential behind the entry (the host uses the target identity).
    credential: String,
    inserted_at: Instant,
    expires_at: Instant,
}

/// The cache. `V` is whatever the host hands back on a hit (it should wipe
/// itself on drop); the clock is passed in so expiry is testable.
pub struct CredentialCache<V> {
    entries: Mutex<HashMap<CacheKey, Entry<V>>>,
    max_entries: usize,
}

impl<V: Clone> CredentialCache<V> {
    pub fn new(max_entries: usize) -> Self {
        Self { entries: Mutex::new(HashMap::new()), max_entries: max_entries.max(1) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<CacheKey, Entry<V>>> {
        // A poisoned cache is only a cache: start over rather than fail.
        self.entries.lock().unwrap_or_else(|poisoned| {
            let mut guard = poisoned.into_inner();
            guard.clear();
            guard
        })
    }

    /// The live entry for `key`. An expired one is dropped.
    pub fn get(&self, key: &CacheKey, now: Instant) -> Option<V> {
        let mut map = self.lock();
        match map.get(key) {
            Some(e) if e.expires_at > now => Some(e.value.clone()),
            Some(_) => {
                map.remove(key);
                None
            }
            None => None,
        }
    }

    /// Cache `value` for `ttl` (already passed through [`effective_ttl`]).
    /// Returns whether it was stored: a zero TTL is not, and when full the
    /// expired entries go first, then the oldest one.
    pub fn insert(&self, key: CacheKey, credential: &str, value: V, ttl: Duration, now: Instant) -> bool {
        if ttl.is_zero() {
            return false;
        }
        let mut map = self.lock();
        if map.len() >= self.max_entries && !map.contains_key(&key) {
            map.retain(|_, e| e.expires_at > now);
            if map.len() >= self.max_entries {
                if let Some(victim) = map.iter().min_by_key(|(_, e)| e.inserted_at).map(|(k, _)| k.clone()) {
                    map.remove(&victim);
                }
            }
        }
        let entry = Entry { value, credential: credential.to_string(), inserted_at: now, expires_at: now + ttl };
        map.insert(key, entry);
        true
    }

    /// Forget the entry for `key`, if any.
    pub fn remove(&self, key: &CacheKey) -> bool {
        self.lock().remove(key).is_some()
    }

    /// Forget every entry backed by `credential` (its lease was revoked or
    /// renewed). Returns how many went.
    pub fn evict_credential(&self, credential: &str) -> usize {
        self.evict_where(|_, _| false, Some(credential))
    }

    /// Forget every entry `pred` selects (a mount's, a plugin's). Returns how
    /// many went.
    pub fn evict_matching(&self, pred: impl Fn(&CacheKey, &V) -> bool) -> usize {
        self.evict_where(pred, None)
    }

    fn evict_where(&self, pred: impl Fn(&CacheKey, &V) -> bool, credential: Option<&str>) -> usize {
        let mut map = self.lock();
        let before = map.len();
        map.retain(|k, e| !(pred(k, &e.value) || credential.is_some_and(|c| e.credential == c)));
        before - map.len()
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(entity: &str) -> CacheKey {
        CacheKey::new("database/", "readonly", entity).unwrap()
    }

    #[test]
    fn miss_then_hit() {
        let cache = CredentialCache::new(8);
        let now = Instant::now();
        assert!(cache.get(&key("e1"), now).is_none());
        assert!(cache.insert(key("e1"), "user-1", "cred-1".to_string(), Duration::from_secs(30), now));
        assert_eq!(cache.get(&key("e1"), now + Duration::from_secs(29)), Some("cred-1".to_string()));
    }

    #[test]
    fn entries_expire() {
        let cache = CredentialCache::new(8);
        let now = Instant::now();
        cache.insert(key("e1"), "user-1", 1u32, Duration::from_secs(30), now);
        assert!(cache.get(&key("e1"), now + Duration::from_secs(30)).is_none());
        assert!(cache.is_empty(), "an expired entry is dropped on read");
    }

    #[test]
    fn identities_and_roles_and_mounts_are_isolated() {
        let cache = CredentialCache::new(8);
        let now = Instant::now();
        cache.insert(key("alice"), "user-a", "alice-cred", Duration::from_secs(30), now);
        assert!(cache.get(&key("bob"), now).is_none(), "another identity never gets alice's credential");
        let other_role = CacheKey::new("database/", "admin", "alice").unwrap();
        assert!(cache.get(&other_role, now).is_none());
        let other_mount = CacheKey::new("database-2/", "readonly", "alice").unwrap();
        assert!(cache.get(&other_mount, now).is_none());
        assert_eq!(cache.get(&key("alice"), now).unwrap(), "alice-cred");
    }

    #[test]
    fn callers_without_an_entity_are_never_cached() {
        assert!(CacheKey::new("database/", "readonly", "").is_none());
        assert!(CacheKey::new("database/", "readonly", "   ").is_none());
        assert!(CacheKey::new("", "readonly", "e").is_none());
    }

    #[test]
    fn ttl_stays_well_inside_the_lease() {
        let s = Duration::from_secs;
        assert_eq!(effective_ttl(s(60), s(3600)), s(60));
        assert_eq!(effective_ttl(s(60), s(150)), s(30), "60 s window: served while > 120 s of lease remain");
        assert_eq!(effective_ttl(s(10), s(65)), s(5), "never with less than 60 s of lease left");
        assert_eq!(effective_ttl(s(600), s(60)), Duration::ZERO, "a short lease is not cached at all");
        assert_eq!(effective_ttl(s(3600), s(86_400)), MAX_CACHE_TTL);
        assert_eq!(effective_ttl(Duration::ZERO, s(86_400)), Duration::ZERO, "off by default");
        assert!(!CredentialCache::new(1).insert(key("e"), "u", 0u8, Duration::ZERO, Instant::now()));
    }

    #[test]
    fn revoked_credentials_and_selected_entries_are_evicted() {
        let cache = CredentialCache::new(8);
        let now = Instant::now();
        cache.insert(key("e1"), "user-1", 1u8, Duration::from_secs(30), now);
        cache.insert(key("e2"), "user-2", 2u8, Duration::from_secs(30), now);
        assert_eq!(cache.evict_credential("user-1"), 1);
        assert!(cache.get(&key("e1"), now).is_none());
        assert!(cache.get(&key("e2"), now).is_some());
        let other_mount = CacheKey::new("database-2/", "readonly", "e1").unwrap();
        cache.insert(other_mount.clone(), "user-3", 3u8, Duration::from_secs(30), now);
        assert_eq!(cache.evict_matching(|k, _| k.mount == "database/"), 1);
        assert!(cache.get(&other_mount, now).is_some(), "another mount's entry stays");
        assert!(cache.remove(&other_mount));
        assert!(cache.is_empty());
    }

    #[test]
    fn a_full_cache_drops_expired_entries_then_the_oldest() {
        let cache = CredentialCache::new(2);
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        cache.insert(key("e1"), "u1", 1u8, Duration::from_secs(50), now);
        cache.insert(key("e2"), "u2", 2u8, Duration::from_secs(10), later);
        cache.insert(key("e3"), "u3", 3u8, Duration::from_secs(50), later);
        assert_eq!(cache.len(), 2, "bounded");
        assert!(cache.get(&key("e1"), later).is_none(), "the oldest went");
        assert!(cache.get(&key("e2"), later).is_some() && cache.get(&key("e3"), later).is_some());

        let much_later = later + Duration::from_secs(20);
        cache.insert(key("e4"), "u4", 4u8, Duration::from_secs(50), much_later);
        assert!(cache.get(&key("e3"), much_later).is_some(), "the expired e2 went first, not the older e3");
        assert!(cache.get(&key("e4"), much_later).is_some());
    }
}
