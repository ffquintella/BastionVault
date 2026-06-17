//! Per-namespace quota enforcement (Phase 4).
//!
//! Quotas are configured on each namespace ([`super::store::NamespaceQuotas`])
//! and enforced at request-admit time. A value of `0` means "unlimited".
//!
//! This module enforces the quotas that can be checked cheaply and exactly from
//! in-memory or already-loaded state:
//!
//! - **`max_child_namespaces`** — checked in [`super::store::NamespaceStore::create`]
//!   against the parent's live child count.
//! - **`max_mounts`** — checked before a namespace mount is created, against the
//!   per-namespace router's live mount count.
//! - **`request_rate`** — a per-namespace token bucket enforced at the top of
//!   `Core::handle_request` (returns `429` when exhausted).
//!
//! The **accounting** quotas — `max_storage_bytes`, `max_leases`, and
//! `max_entities` — are enforced from live usage counted at admit time:
//!
//! - **`max_entities`** — checked before a *new* entity is provisioned in a
//!   namespace (login that would create an identity); existing entities still
//!   authenticate.
//! - **`max_storage_bytes`** — checked before a logical write, comparing the
//!   namespace's current barrier-byte total (summed under its logical prefix)
//!   plus the incoming value against the cap. Computed on demand and only when a
//!   cap is set, so there is zero cost unless an operator opts in.
//! - **`max_leases`** — checked when a secret lease is registered, against the
//!   namespace's live lease count.
//!
//! All accounting quotas apply to *non-root* namespaces only: the root
//! namespace is the deployment owner and is never self-limited.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::Instant,
};

use crate::{
    bv_error_response_status,
    errors::RvError,
    logical::Operation,
    storage::Storage,
};

use super::router::namespace_logical_prefix;

/// Error returned when a capacity quota (mounts, children) is exceeded.
pub fn capacity_exceeded(what: &str, limit: u64) -> RvError {
    // 507 Insufficient Storage mirrors the spec's capacity-quota status.
    bv_error_response_status!(
        507,
        &format!("namespace quota exceeded: {what} limit of {limit} reached")
    )
}

/// Check an additive capacity quota: refuse when `current >= limit` (and the
/// limit is set). `0` means unlimited.
pub fn check_capacity(what: &str, current: usize, limit: u64) -> Result<(), RvError> {
    if limit != 0 && current as u64 >= limit {
        return Err(capacity_exceeded(what, limit));
    }
    Ok(())
}

/// A simple per-key token bucket. Capacity equals the configured rate (one
/// second of burst); it refills continuously at `rate` tokens/second.
struct Bucket {
    tokens: f64,
    rate: f64,
    last: Instant,
}

impl Bucket {
    fn new(rate: f64, now: Instant) -> Self {
        Self { tokens: rate, rate, last: now }
    }

    /// Try to consume one token, refilling for elapsed time first.
    fn try_take(&mut self, now: Instant) -> bool {
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.rate);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Per-namespace request-rate limiter. Keyed by namespace path; buckets are
/// created lazily on first request and reset if the configured rate changes.
#[derive(Default)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self { buckets: Mutex::new(HashMap::new()) }
    }

    /// Admit one request for `ns_path` under `rate` requests/second. `rate == 0`
    /// is unlimited. Returns `Err(429)` when the bucket is empty.
    pub fn admit(&self, ns_path: &str, rate: u64) -> Result<(), RvError> {
        if rate == 0 {
            return Ok(());
        }
        let now = Instant::now();
        let mut g = self.buckets.lock().unwrap();
        let bucket = g.entry(ns_path.to_string()).or_insert_with(|| Bucket::new(rate as f64, now));
        // Re-arm the bucket if the operator changed the configured rate.
        if (bucket.rate - rate as f64).abs() > f64::EPSILON {
            *bucket = Bucket::new(rate as f64, now);
        }
        if bucket.try_take(now) {
            Ok(())
        } else {
            Err(bv_error_response_status!(
                429,
                &format!("namespace request-rate quota exceeded: {rate} req/s for {ns_path:?}")
            ))
        }
    }
}

/// Enforce the per-namespace request-rate quota for a routed request. Resolves
/// the target namespace from the (already namespace-normalised) request path and
/// admits it against that namespace's `request_rate`. A no-op for root/unlimited
/// namespaces and when the namespace module is unavailable.
#[maybe_async::maybe_async]
pub async fn enforce_request_rate(
    core: &crate::core::Core,
    req: &crate::logical::Request,
) -> Result<(), RvError> {
    use super::{NamespaceModule, NAMESPACE_MODULE_NAME};

    // sys/auth/identity are header-scoped, not path-rewritten; rate-limit them
    // under the root bucket along with every other root request.
    let Some(module) = core.module_manager.get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
    else {
        return Ok(());
    };
    let Some(store) = module.store() else {
        return Ok(());
    };

    let resolved = store.resolve_request(None, &req.path).await?;
    let rate = resolved.namespace.quotas.request_rate;
    if rate == 0 {
        return Ok(());
    }
    module.rate_limiter.admit(&resolved.namespace.path, rate)
}

/// Error returned when an accounting capacity quota (storage, leases,
/// entities) is exceeded. Mirrors the spec's `507 Insufficient Storage`.
fn accounting_exceeded(what: &str, current: u64, limit: u64) -> RvError {
    bv_error_response_status!(
        507,
        &format!("namespace quota exceeded: {what} {current}/{limit}")
    )
}

/// Sum the barrier-encrypted value bytes stored under a namespace's logical
/// prefix (`namespaces/<uuid>/logical/`). Walks the prefix and reads each
/// value's length. O(n) in the namespace's key count — only invoked when a
/// storage cap is set on the namespace.
#[maybe_async::maybe_async]
async fn namespace_storage_bytes(
    barrier: &dyn Storage,
    ns_uuid: &str,
) -> Result<u64, RvError> {
    let prefix = namespace_logical_prefix(ns_uuid);
    let mut pending = vec![prefix];
    let mut total: u64 = 0;
    while let Some(curr) = pending.pop() {
        for child in barrier.list(&curr).await? {
            let full = format!("{curr}{child}");
            if child.ends_with('/') {
                pending.push(full);
            } else if let Some(entry) = barrier.get(&full).await? {
                total += entry.value.len() as u64;
            }
        }
    }
    Ok(total)
}

/// Enforce a namespace's `max_entities` cap before a *new* entity is created.
/// A no-op when the entity already exists (existing principals keep logging in),
/// when the namespace is root, or when the cap is unset.
#[maybe_async::maybe_async]
pub async fn check_entity_create(
    core: &crate::core::Core,
    mount: &str,
    name: &str,
    ns_path: &str,
) -> Result<(), RvError> {
    use super::{NamespaceModule, NAMESPACE_MODULE_NAME};
    if ns_path.is_empty() {
        return Ok(());
    }
    let Some(ns_module) = core.module_manager.get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
    else {
        return Ok(());
    };
    let Some(store) = ns_module.store() else {
        return Ok(());
    };
    let Some(ns) = store.get_by_path(ns_path).await? else {
        return Ok(());
    };
    let limit = ns.quotas.max_entities;
    if limit == 0 {
        return Ok(());
    }
    let Some(id_module) =
        core.module_manager.get_module::<crate::modules::identity::IdentityModule>("identity")
    else {
        return Ok(());
    };
    let Some(entity_store) = id_module.entity_store() else {
        return Ok(());
    };
    // Existing principal → not a new entity → never blocked.
    if entity_store.get_by_alias_ns(mount, name, ns_path).await?.is_some() {
        return Ok(());
    }
    let current = entity_store.list_entities_ns(ns_path).await?.len() as u64;
    if current >= limit {
        return Err(accounting_exceeded("entities", current, limit));
    }
    Ok(())
}

/// Enforce a namespace's `max_storage_bytes` cap before a logical write. The
/// incoming value size is added to the namespace's current total so the write
/// that would cross the threshold is the one refused. A no-op for non-writes,
/// the root namespace, or an unset cap.
#[maybe_async::maybe_async]
pub async fn enforce_write_storage_quota(
    core: &crate::core::Core,
    req: &crate::logical::Request,
) -> Result<(), RvError> {
    use super::{NamespaceModule, NAMESPACE_MODULE_NAME};
    if req.operation != Operation::Write {
        return Ok(());
    }
    let Some(ns_module) = core.module_manager.get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
    else {
        return Ok(());
    };
    let Some(store) = ns_module.store() else {
        return Ok(());
    };
    let resolved = store.resolve_request(None, &req.path).await?;
    if resolved.namespace.is_root() {
        return Ok(());
    }
    let limit = resolved.namespace.quotas.max_storage_bytes;
    if limit == 0 {
        return Ok(());
    }
    let incoming = req
        .body
        .as_ref()
        .and_then(|b| serde_json::to_vec(b).ok())
        .map(|v| v.len() as u64)
        .unwrap_or(0);
    let current = namespace_storage_bytes(core.barrier.as_storage(), &resolved.namespace.uuid).await?;
    if current.saturating_add(incoming) > limit {
        return Err(accounting_exceeded("storage bytes", current, limit));
    }
    Ok(())
}

/// Enforce a namespace's `max_leases` cap given the namespace's current live
/// lease count. Pure helper so the expiration manager can call it without a
/// dependency on the namespace store. A no-op for the root namespace or an
/// unset cap.
pub fn check_lease_quota(ns_path: &str, current_leases: u64, limit: u64) -> Result<(), RvError> {
    if ns_path.is_empty() || limit == 0 {
        return Ok(());
    }
    if current_leases >= limit {
        return Err(accounting_exceeded("leases", current_leases, limit));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_capacity() {
        assert!(check_capacity("mounts", 0, 0).is_ok()); // unlimited
        assert!(check_capacity("mounts", 999, 0).is_ok());
        assert!(check_capacity("mounts", 0, 1).is_ok());
        assert!(check_capacity("mounts", 1, 1).is_err()); // at limit
        assert!(check_capacity("mounts", 2, 1).is_err());
    }

    #[test]
    fn test_rate_limiter_token_bucket() {
        let rl = RateLimiter::new();
        // rate = 3 → a burst of 3 admits, the 4th is refused (negligible refill
        // over the microseconds these calls take).
        assert!(rl.admit("tenant-a", 3).is_ok());
        assert!(rl.admit("tenant-a", 3).is_ok());
        assert!(rl.admit("tenant-a", 3).is_ok());
        assert!(rl.admit("tenant-a", 3).is_err());
        // A different namespace has its own independent bucket.
        assert!(rl.admit("tenant-b", 3).is_ok());
        // rate = 0 is unlimited.
        for _ in 0..100 {
            assert!(rl.admit("tenant-c", 0).is_ok());
        }
    }
}
