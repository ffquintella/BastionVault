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

**Done.** All four slices landed:

- **Slice 1** — `CacheConfig` scaffold parsed from `cache { ... }` in server config, threaded through `Core`. Policy cache size now operator-configurable (previously a compile-time constant).
- **Slice 2a** — `src/cache/token_cache.rs`: `TokenCache` keyed by the existing `salt_id` (SHA1(salt || token), never the raw bearer token). Cached payload is `Zeroizing<Vec<u8>>` in a non-`Clone` / non-`Serialize` / redacted-`Debug` `CachedToken` wrapper. Wired into `TokenStore::{lookup_salted, create, use_token, revoke_salted}` with invalidate-before-and-after on revoke to close the racing-lookup window. TTL-gated (`token_cache_ttl_secs = 0` disables).
- **Slice 2b** — `src/metrics/cache_metrics.rs`: process-wide `CacheMetrics` singleton exporting `bvault_cache_{hits,misses,evictions}_total{layer}` + a reserved `bvault_cache_size{layer}` gauge. Registered by `MetricsManager::new`. Token and policy caches record hits/misses/evictions (stretto-internal TTL/cost evictions are invisible — only explicit invalidations feed the counter).
- **Slice 3** — `src/cache/secret_cache.rs`: `CachingBackend` decorator implementing the `Backend` trait (below the barrier, by construction). Stores `Zeroizing<Vec<u8>>` ciphertext bit-for-bit; no negative caching (absent-key lookups always reach the inner backend); write-through invalidation on `put`/`delete` with the delete path invalidating both before and after. `storage::wrap_with_cache` is a no-op when `secret_cache_ttl_secs = 0`, so existing deployments pay zero overhead.
- **Slice 4** — `src/cache/guardrails.rs`: `mlockall(MCL_CURRENT|MCL_FUTURE)` on Unix when `cache.memlock = true` (startup aborts if the syscall fails rather than silently running unprotected); `prctl(PR_SET_DUMPABLE, 0)` on Linux when caches are enabled and `allow_core_dumps = false` (default); `memlock = true` on Windows aborts startup with an explicit error. `Core::flush_caches` zeroizes all three layers and is invoked by `pre_seal` (so cached material cannot survive a seal) and by the new `POST /sys/cache/flush` admin endpoint, which is sudo-gated via the system backend's `root_paths`.

### Test coverage (54 cache-specific tests in `cargo test --lib`)

- Cache-config: defaults, missing block, partial block, `deny_unknown_fields`, merge.
- Token cache: TTL-zero disables, roundtrip, invalidate, clear, redacted `Debug`, serialized-payload shape, `Zeroize` wipe, end-to-end cache-enabled-by-default, revoke-invalidates.
- Secret cache: populate-then-hit, put invalidates, delete invalidates, negative result not cached, `ttl == 0` rejected, `Debug` redacted, not-`Clone`, `clear()` flushes, bit-for-bit byte-pattern preservation.
- Cache metrics: independent hit/miss recording per layer, absolute-size gauge, singleton identity, text-encoding scrape.
- Guardrails: defaults apply cleanly, status struct reflects config.
- `Core::flush_caches` empties the token cache (direct test + integration through pre_seal).
- `/sys/cache/flush` HTTP endpoint succeeds as root (sudo-gated).

### Deliberate non-goals / known limitations

- **No eviction callback on stretto 0.8.** The `bvault_cache_evictions_total` counter reflects *explicit* invalidations only; cost-overflow and TTL drops are invisible. `bvault_cache_size` is reserved but unpopulated.
- **No negative caching.** Path existence can be sensitive metadata.
- **No plaintext ever cached.** Enforced structurally by the trait layering (secret cache on `Backend`, not `Storage`) and by per-layer `Zeroize` wrappers.
- **Mount table caching is out of scope.** Covered by the existing `mounts_monitor` poller, not this feature.
- **Windows `memlock` unimplemented.** Explicit startup error rather than silent partial support.

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

**What the cache holds**: `TokenEntry` is auth metadata (policies attached, creation/expiry timestamps, accessor, bound CIDRs). It is the **deserialized** form of what `TokenStore` already reads on every request; caching it is equivalent to caching the storage lookup, not the token secret. Specifically:

- The **raw token string** (the bearer credential the client presents) is **never** cached. The cache is keyed by HMAC of the accessor, not by the token. A memory dump of the cache cannot be replayed against the vault because the token value is not there to replay.
- The accessor HMAC used as the cache key must be derived with the barrier-held HMAC key (the same one used for audit redaction), so even the key side of each cache entry is opaque outside the running process.
- `TokenEntry` must not be extended to carry any field that would be dangerous to hold plaintext in memory. Any future such field requires either a separate non-cached lookup or explicit re-encryption before insertion. This is enforced by a review note on `TokenEntry` and an `assert`-style test that rejects new fields without an explicit attribute.

**Consistency**: a revoked token may be accepted for up to 30 seconds if it's cached. This is acceptable for most deployments. Operators who need immediate revocation can set `token_cache_ttl = 0` to disable.

### Secret Read Cache

**Purpose**: avoid re-reading frequently accessed secrets from storage.

> **Hard invariant: the secret cache MUST hold ciphertext only. Caching decrypted `StorageEntry` values is forbidden.**
>
> An earlier draft of this spec proposed caching `Option<StorageEntry>` inside `BarrierView`. That is **incorrect** and must not be implemented: `BarrierView` sits above the barrier in the call chain (`BarrierView::get` → `SecurityBarrier::get` → AEAD decrypt → plaintext `StorageEntry`), so anything it caches would be plaintext secret material held in process memory for the entire TTL. Review rejected this design.

**Correct placement**: the cache lives at the **physical `Backend`** layer, below the barrier. The type is `Cache<String, Option<BackendEntry>>` and `BackendEntry::value` is the raw AEAD-encrypted blob exactly as written to disk. Decryption always happens on the barrier's hot path, on every request, whether the value came from disk or from the cache. The cache saves the storage round-trip; it does **not** save the AEAD open — that cost is tolerated so plaintext never persists past a single request frame.

**Implementation**:
- Wrap the configured physical `Backend` (file, MySQL, Hiqlite, …) in a `CachingBackend` decorator that implements the `Backend` trait.
- Key: the physical-layer key (already includes the barrier prefix), so a single cache covers all mounts without cross-mount confusion.
- Populated on `Backend::get()` cache miss with the ciphertext returned by the inner backend.
- Invalidated on `Backend::put()` or `Backend::delete()` to the same key, same request, before the call returns.
- Default TTL: 0 (disabled). Must be explicitly enabled via config because it introduces a staleness window against other cluster nodes.

**Zeroization**: every cache layer (policy, token, secret) zeroizes entry buffers on eviction, TTL expiry, explicit invalidation, and seal. See the dedicated *Zeroization and Memory-Only Guarantees* section below for the full contract.

**Write-through invalidation**: when `put()` or `delete()` is called on the `CachingBackend`, the corresponding cache entry is removed before the method returns. This ensures the local node always sees its own writes.

**Multi-node staleness**: in a multi-node hiqlite cluster, a write on node A does not invalidate the cache on node B. Node B will serve stale ciphertext (still authentic — the AEAD tag is verified on every decrypt) until the cache TTL expires. This is documented and acceptable when `secret_cache_ttl > 0`.

### Zeroization and Memory-Only Guarantees

Two invariants that together mean no cache layer ever leaks its contents past the moment they're no longer needed.

#### Invariant 1: every cache layer zeroizes on every release path

Applies to all three caches (policy, token, secret). Every path that removes a value from a cache must zeroize the bytes it used to hold. "Release path" covers:

| Path | Trigger |
|---|---|
| Eviction | stretto cost-based eviction or LRU pressure |
| TTL expiry | background tick fires or next access finds the entry expired |
| Explicit invalidation | `put` / `delete` on same key, token revoke, policy write/delete |
| Seal | `Core::seal` must drop and zeroize all cache layers before releasing the unseal key |
| Process shutdown | drop order guaranteed by storing caches in fields owned by `Core`; `Drop` impl zeroizes |

**Implementation**:

- Every cache value type wraps its sensitive bytes in `zeroize::Zeroizing<Vec<u8>>` (or `zeroize::Zeroizing<Box<[u8]>>`). `zeroize` is already a workspace dependency via `bv_crypto`.
- `BackendEntry::value` in cached form is `Zeroizing<Vec<u8>>`. The secret cache never holds a `Vec<u8>` that isn't inside a `Zeroizing` wrapper.
- `TokenEntry` fields that are arrays of bytes (accessor-hmac, bound-cidrs serialized form) are `Zeroizing`. The struct gains `#[derive(ZeroizeOnDrop)]`.
- `Policy` is left as-is (not secret), but the `Arc<Policy>` drop releases the underlying allocation which is then zeroized by the global allocator-integration path *only if* the `secure_zero_on_free` feature is compiled in. For the policy cache we do **not** require zeroization — adding a line of code is explicit.
- stretto does not natively call a user callback on eviction in all paths. To cover that, the cache value type's `Drop` impl does the zeroization. Because stretto releases the `Arc`/`Box` it holds on eviction, `Drop` runs, and the bytes are wiped. A unit test `stretto_eviction_runs_drop` proves this for the version pinned in `Cargo.toml` — if a future stretto update breaks this, CI catches it.
- Explicit `flush_all()` / `clear()` methods iterate entries, replace each value with a zeroized sentinel before removal from the map, and finally call `stretto::Cache::clear`. Used by seal and by a new `sys/cache/flush` admin endpoint (gated behind a `sudo` capability).

**Test**: `cache_zeroized_on_flush` — insert a ciphertext blob whose bytes contain a unique marker; call `flush_all()`; retain a raw pointer to the backing allocation via a test-only hook; assert the marker bytes are now `0x00`. Symmetric test for token cache with a token-accessor marker.

#### Invariant 2: caches live in memory only — never on disk

No cache layer may spill to disk, be serialized to disk, or be paged to swap. Enforcement:

1. **No disk-backed cache variant is supported.** Cache configuration does not expose a `backend = "disk"` option; there is only one implementation, and it is `stretto::Cache` (in-process, heap-allocated). Anyone adding a disk-backed variant in the future must amend this spec first.
2. **No serialization path out of the cache.** Cache value types do **not** implement `Serialize`. Attempting to serialize the cache is a compile error. This prevents accidental inclusion in debug dumps, config exports, or audit JSON.
3. **Audit / debug / error paths are forbidden from logging cache values.** Cache value types implement `Debug` as a fixed redacted string (`"<cached:redacted>"`). Key types (for the secret cache) also redact: keys include mount paths that can themselves be sensitive, so `Debug` prints `<cached-key:len=N>`.
4. **Memory locking (optional, platform-gated).** A new config flag `cache.memlock = true` calls `mlock(2)` (Unix) / `VirtualLock` (Windows) on the backing allocations to prevent swap-out. Default is `false` because `mlock` requires privilege on many systems and can fail in containers; when the flag is on but the syscall fails, startup aborts rather than silently running without the protection. This flag also applies to the policy cache (historically unprotected).
5. **Core dumps.** The process sets `prctl(PR_SET_DUMPABLE, 0)` on Linux when any cache layer is enabled with a non-zero TTL, so a crash does not write cache contents into a core file. This is opt-out via `cache.allow_core_dumps = true` for debugging builds. Windows equivalent: `SetErrorMode(SEM_NOGPFAULTERRORBOX)` plus `WerAddExcludedApplication` guidance in docs.
6. **No `tmpfs` / mmap misuse.** The cache must not be backed by an `mmap`ed file or a `tmpfs`-derived allocation. Asserted at construction by checking the allocator is the global heap.

**Test**: `cache_is_memory_only` — attempt to `serde_json::to_string` a cache value type; this must be a compilation failure (verified via `trybuild`). `Debug` print of a populated cache entry must not contain the value's bytes. `mlock` round-trip test on Linux CI.

**Residual risk called out explicitly**: an attacker with `ptrace` / `/proc/<pid>/mem` / kernel access can still read in-process memory. These invariants do not defend against a root-on-host adversary; they defend against swap leaks, core-dump leaks, accidental serialization, and post-eviction-memory-reuse leaks. For a root-on-host threat model, operators must seal the vault.

### Cache Configuration

Add to the server config:

```hcl
cache {
  token_cache_size     = 4096
  token_cache_ttl      = "30s"
  secret_cache_size    = 8192
  secret_cache_ttl     = "0s"
  policy_cache_size    = 1024
  memlock              = false
  allow_core_dumps     = false
}
```

| Key | Default | Description |
|---|---|---|
| `token_cache_size` | 4096 | Maximum token entries in cache. |
| `token_cache_ttl` | `"30s"` | TTL for cached token lookups. `"0s"` disables. |
| `secret_cache_size` | 8192 | Maximum secret entries in cache. |
| `secret_cache_ttl` | `"0s"` | TTL for cached secret reads. `"0s"` disables (default). |
| `policy_cache_size` | 1024 | Maximum policy entries in cache (existing, now configurable). |
| `memlock` | `false` | `mlock(2)` / `VirtualLock` all cache allocations to prevent swap. Startup aborts if the syscall fails. Requires privilege on most systems. |
| `allow_core_dumps` | `false` | Leave `PR_SET_DUMPABLE = 1` when caches are enabled. Debug-only; production leaves this `false`. |

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
| `src/cache/mod.rs` | Cache configuration, shared types, startup logging |
| `src/cache/token_cache.rs` | Token lookup cache wrapping stretto (TokenEntry metadata, keyed by HMAC(accessor)) |
| `src/cache/secret_cache.rs` | `CachingBackend` decorator implementing `Backend` — ciphertext-only |

### Modified Files

| File | Change |
|---|---|
| `src/cli/config.rs` | Parse `cache { ... }` config block |
| `src/modules/auth/token_store.rs` | Integrate token cache on lookup, create, revoke |
| `src/modules/policy/policy_store.rs` | Make policy cache size configurable |
| `src/storage/mod.rs` (`new_backend`) | Wrap configured backend in `CachingBackend` when `secret_cache_ttl > 0`. **Note**: the cache lives at the `Backend` layer, *below* the barrier, so it only ever sees ciphertext. `BarrierView` is deliberately **not** modified. |
| `src/core.rs` | Pass cache config to token store and `new_backend`. Seal path must drop all caches. |
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
- **`cache_never_holds_plaintext`** (security regression): write a secret whose plaintext contains a unique marker string, enable the secret cache, read twice, scan the cache's backing storage bytes via a test-only introspection hook, assert the marker does **not** appear. Symmetric test for `TokenEntry` caches scans for the raw token string and asserts absence.
- **`cache_zeroized_on_flush`**: insert a value with a unique byte pattern; call `flush_all()`; via a test-only raw-pointer hook, assert the previous backing allocation contains `0x00`, not the pattern. Covers seal, eviction, TTL expiry, and explicit `sys/cache/flush`.
- **`stretto_eviction_runs_drop`**: force eviction via cost overflow; assert the `Drop` impl of the wrapped value ran (counter hook). Pins the behavior of the current stretto version so a future upgrade that breaks it fails CI.
- **`cache_is_memory_only`**: a `trybuild` test asserts that `serde_json::to_string` on cache value types is a compile error. `Debug` print of a populated cache contains no raw value bytes. Linux CI additionally runs an `mlock` round-trip test verifying allocations are pinned.
- **Seal drops all caches**: unseal → read secrets (populate cache) → seal → assert all cache layers report zero entries and previously-held bytes are zeroized.

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

### Global invariant: no cache holds plaintext secret payloads

This is the single most important rule for the caching subsystem, and the only one that, if violated, would make the feature a net negative for security:

> **No cache introduced by this feature — secret, token, policy, or any future layer — may store decrypted secret material, raw bearer tokens, private keys, or any other value whose confidentiality depends on the barrier. Caches below the barrier hold ciphertext only; caches above the barrier hold non-secret metadata only.**

How each layer satisfies this:

| Layer | Sits… | Stores | Why it's safe |
|---|---|---|---|
| Policy cache (existing) | Above the barrier | `Arc<Policy>` — authorization rules, path globs, capabilities | Policies are not secret material. They are effectively public inside a running vault and are already returned in plaintext over the HTTP API to authorized callers. |
| Token cache (new) | Above the barrier | `TokenEntry` — policies, TTLs, accessor, bound CIDRs | Does **not** hold the raw token value. Key is an HMAC over the accessor. Losing the cache contents to a memory dump does not yield a replayable credential — same threat profile as the existing storage lookup that the cache replaces. |
| Secret read cache (new) | **Below** the barrier | `BackendEntry` — raw AEAD ciphertext + nonce + tag | Cache entries are bit-identical to what the physical backend returns. A memory dump of the cache is no more useful than a dump of the storage backend. Decryption happens on the barrier hot path on every request, cache hit or miss. |

### Enforcement

- The `CachingBackend` decorator is implemented against the `Backend` trait, not `Storage`. The Rust type system therefore makes it impossible to hand a decrypted `StorageEntry` to the secret cache — the trait won't fit.
- A unit test (`cache_never_holds_plaintext`) writes a known plaintext through the barrier, dumps the cache's raw bytes via a test-only introspection hook, and asserts the plaintext pattern does not appear. Runs on every CI build.
- The `TokenEntry` struct gains a `#[deny_on_clone_if_secret]`-style review marker (comment + compile-time check via a sealed trait bound) so future additions of secret-bearing fields force a review of whether caching is still safe.
- The feature flag that enables the secret cache emits a loud startup log line listing the backend, TTL, and the ciphertext-only invariant, so operators can see from logs that they are running with caching on.

### Other considerations

- **Token cache staleness**: a revoked token can be accepted for up to `token_cache_ttl` seconds. Deliberate trade-off. For environments requiring instant revocation, disable the token cache (`token_cache_ttl = 0`).
- **Secret cache staleness**: disabled by default (`secret_cache_ttl = "0s"`). Enabling it accepts up to TTL-bounded staleness across cluster nodes. The local node always sees its own writes via write-through invalidation.
- **Integrity preserved under staleness**: because the cache holds ciphertext, every cache hit is re-authenticated by the AEAD tag on decrypt. A corrupted cache entry fails open-verification and returns an error rather than silently yielding wrong data.
- **Cache size limits memory usage**: stretto enforces cost-based eviction. Configured sizes are entry counts, not bytes.
- **Cache is not persisted**: cache contents exist only in memory and are lost on seal/restart. Seal must drop all caches — this is part of the seal hot path and must be tested.
- **No negative caching of sensitive existence**: caching "not found" for a path is explicitly out of scope, both for the previously-stated correctness reason and because the presence or absence of a path can itself be sensitive metadata.
