# Feature: Caching

## Summary

Extend BastionVault's caching layer beyond the current policy-only scope to include token lookups, secret reads, and mount table resolution, reducing storage backend round-trips and improving request latency.

## Motivation

Every BastionVault request currently hits the storage backend multiple times:

1. Token lookup (authentication).
2. Policy resolution (authorization) -- **cached today via stretto**.
3. Mount table lookup (routing).
4. Secret read/write (the actual operation).

For a single `GET /v1/secret/data/myapp`, the vault performs token validation, policy evaluation, and a storage read. Only policy evaluation benefits from caching today. Token lookups and secret reads always go to disk/database/raft, adding latency that scales with backend round-trip time.

With hiqlite as the default backend, local leader reads are fast, but follower nodes forward to the leader for consistent reads (`query_consistent_map`). Caching on the follower avoids this network hop for frequently accessed data.

## Current State

### What Exists

**Policy cache** (`src/modules/policy/policy_store.rs`):
- Uses `stretto` crate (concurrent, cost-based cache).
- Two LRU caches: `token_policies_lru` (ACL policies) and `egp_lru` (endpoint-governing policies).
- Cache size: `POLICY_CACHE_SIZE = 1024` entries.
- Cache hit path: `get_policy()` checks cache before storage, populates on miss.
- Cache invalidation: explicit `remove_token_policy_cache()` / `remove_egp_cache()` on policy write/delete.

**stretto dependency** (`Cargo.toml`):
- `stretto = "0.8"` is already a non-optional dependency.

### What Is Missing

- **Token cache**: every request re-reads the token entry from storage for validation.
- **Secret read cache**: frequently read secrets are fetched from storage on every request.
- **Mount table cache**: mount table is loaded from storage on startup but changes are detected by a polling monitor (`mounts_monitor_interval` config, default 5s).
- **Cache statistics**: no metrics for hit/miss rates.
- **Cache configuration**: no operator-facing config for cache sizes or TTLs.
- **Cache invalidation on write**: no mechanism to invalidate cached secrets when they're updated.

## Design

### Cache Layers

Three new cache layers, each with different invalidation semantics:

| Layer | Key | Value | TTL | Invalidation |
|---|---|---|---|---|
| Token cache | accessor hash | TokenEntry | Short (30s) | On token revoke/renew |
| Secret read cache | mount_uuid + path | StorageEntry (encrypted) | Configurable (default 0 = disabled) | On write/delete to same path |
| Lease cache | lease_id | LeaseEntry | Lease TTL | On revoke/renew/expire |

### Token Cache

**Purpose**: avoid re-reading the token entry from storage on every request.

**Implementation**:
- Add a stretto `Cache<String, TokenEntry>` to `TokenStore`.
- Key: HMAC of the token accessor (not the raw token, to avoid cache key leakage).
- On token creation/renewal: insert into cache.
- On token revocation: remove from cache.
- TTL: 30 seconds (short, since tokens can be revoked at any time and staleness must be bounded).

**Consistency**: a revoked token may be accepted for up to 30 seconds if it's cached. This is acceptable for most deployments. Operators who need immediate revocation can set `token_cache_ttl = 0` to disable.

### Secret Read Cache

**Purpose**: avoid re-reading frequently accessed secrets from storage.

**Implementation**:
- Add a stretto `Cache<String, Option<StorageEntry>>` to `BarrierView`.
- Key: full storage path (already prefixed by mount UUID).
- Populated on `get()` cache miss.
- Invalidated on `put()` or `delete()` to the same path.
- Default TTL: 0 (disabled). Must be explicitly enabled via config because caching secrets introduces a staleness window.

**Write-through invalidation**: when `put()` or `delete()` is called on a `BarrierView`, the corresponding cache entry is removed immediately. This ensures the local node always sees its own writes.

**Multi-node staleness**: in a multi-node hiqlite cluster, a write on node A does not invalidate the cache on node B. Node B will serve stale data until the cache TTL expires. This is documented and acceptable when `secret_cache_ttl > 0`.

### Cache Configuration

Add to the server config:

```hcl
cache {
  token_cache_size     = 4096
  token_cache_ttl      = "30s"
  secret_cache_size    = 8192
  secret_cache_ttl     = "0s"
  policy_cache_size    = 1024
}
```

| Key | Default | Description |
|---|---|---|
| `token_cache_size` | 4096 | Maximum token entries in cache. |
| `token_cache_ttl` | `"30s"` | TTL for cached token lookups. `"0s"` disables. |
| `secret_cache_size` | 8192 | Maximum secret entries in cache. |
| `secret_cache_ttl` | `"0s"` | TTL for cached secret reads. `"0s"` disables (default). |
| `policy_cache_size` | 1024 | Maximum policy entries in cache (existing, now configurable). |

### Cache Metrics

Expose cache statistics through the existing Prometheus metrics endpoint:

| Metric | Type | Description |
|---|---|---|
| `bvault_cache_hits_total{layer}` | Counter | Total cache hits per layer (token, secret, policy). |
| `bvault_cache_misses_total{layer}` | Counter | Total cache misses per layer. |
| `bvault_cache_evictions_total{layer}` | Counter | Total evictions per layer. |
| `bvault_cache_size{layer}` | Gauge | Current number of entries per layer. |

### Cache Warming

No proactive cache warming is implemented. Caches are populated lazily on first access (cache-aside pattern). This avoids loading the entire secret tree into memory on startup.

## Implementation Scope

### New Files

| File | Purpose |
|---|---|
| `src/cache/mod.rs` | Cache configuration, shared types |
| `src/cache/token_cache.rs` | Token lookup cache wrapping stretto |
| `src/cache/secret_cache.rs` | Secret read cache wrapping stretto |

### Modified Files

| File | Change |
|---|---|
| `src/cli/config.rs` | Parse `cache { ... }` config block |
| `src/modules/auth/token_store.rs` | Integrate token cache on lookup, create, revoke |
| `src/modules/policy/policy_store.rs` | Make policy cache size configurable |
| `src/storage/barrier_view.rs` | Integrate secret read cache on get/put/delete |
| `src/core.rs` | Pass cache config to token store and barrier views |
| `src/metrics/mod.rs` | Add cache hit/miss/eviction counters |

### Not In Scope

- Write-behind caching (buffering writes before flushing to storage). Too risky for a secrets manager.
- Distributed cache invalidation across cluster nodes. Hiqlite's Raft handles write consistency; cache staleness is bounded by TTL.
- Negative caching (caching "not found" results). Could cause confusion if a secret is created shortly after a miss.

## Testing Requirements

### Unit Tests
- Token cache: insert, hit, miss, evict, revoke-invalidates.
- Secret cache: insert on read, invalidate on write, invalidate on delete, TTL expiry.
- Policy cache: configurable size applied.
- Cache disabled when TTL = 0.

### Integration Tests
- Read a secret twice: first is a cache miss (storage hit), second is a cache hit (no storage call).
- Write a secret then read: cache is invalidated, read goes to storage.
- Revoke a token: subsequent requests with that token fail even if it was cached.
- Metrics endpoint reports cache hit/miss counters.

### Cucumber BDD Scenarios
- Read a secret repeatedly and verify cache metrics show hits.
- Update a secret and verify the next read returns the new value.
- Disable secret caching and verify every read hits storage.

## Security Considerations

- **Cached secrets are in memory**: the cache holds `StorageEntry` values that are encrypted by the barrier. Raw plaintext secrets are never in the cache -- only encrypted blobs. Decryption happens after cache retrieval, same as with a direct storage read.
- **Token cache staleness**: a revoked token can be accepted for up to `token_cache_ttl` seconds. This is a deliberate trade-off. For environments requiring instant revocation, disable the token cache.
- **Secret cache staleness**: disabled by default (`secret_cache_ttl = "0s"`). Operators who enable it accept that secrets may be stale for up to the TTL after an update on another node.
- **Cache size limits memory usage**: stretto enforces cost-based eviction. The configured sizes are entry counts, not bytes. Large secrets consume more memory but count as one entry.
- **Cache is not persisted**: cache contents exist only in memory and are lost on seal/restart. No sensitive data persists beyond the process lifetime through the cache.
