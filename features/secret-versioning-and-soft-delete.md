# Feature: Secret Versioning & Soft-Delete

## Summary

Add a KV v2 secret engine that stores multiple versions of each secret, supports soft-delete with recovery, and provides separate metadata and data access paths. This aligns BastionVault with HashiCorp Vault's KV v2 API for compatibility.

## Motivation

The current KV engine (v1) stores a single value per key. Writes overwrite the previous value with no history. Deletes are permanent and unrecoverable. This is inadequate for production use cases where:

- Operators need to roll back a secret after a bad rotation.
- Compliance requires an audit trail of secret changes.
- Accidental deletion must be recoverable without a full restore from backup.
- CI/CD pipelines use check-and-set (CAS) to avoid clobbering concurrent writes.

## Current State

- The KV v1 module lives in `src/modules/kv/mod.rs`.
- It registers a single path pattern (`.*`) with Read, Write, Delete, List handlers.
- Storage is a flat key-value map: one `StorageEntry` per secret path.
- Deletions call `storage_delete()` directly -- the data is gone.
- No metadata, no version tracking, no soft-delete.
- The CLI already has a `kv_preflight_version_request()` helper in `src/cli/kv_util.rs` that checks mount version, indicating v2 was anticipated.

## Design

### Storage Layout

Each secret managed by the KV v2 engine uses two storage prefixes under its mount:

```
metadata/<secret_name>   -> SecretMetadata JSON
versions/<secret_name>/<version_number>  -> VersionData JSON
```

**SecretMetadata** (stored at `metadata/<name>`):

```json
{
  "current_version": 3,
  "oldest_version": 1,
  "max_versions": 10,
  "cas_required": false,
  "delete_version_after": "0s",
  "created_time": "2026-04-14T12:00:00Z",
  "updated_time": "2026-04-14T15:30:00Z",
  "versions": {
    "1": { "created_time": "...", "deletion_time": "", "destroyed": false },
    "2": { "created_time": "...", "deletion_time": "...", "destroyed": false },
    "3": { "created_time": "...", "deletion_time": "", "destroyed": false }
  }
}
```

**VersionData** (stored at `versions/<name>/<version>`):

```json
{
  "data": { "username": "admin", "password": "secret" },
  "version": 3,
  "created_time": "2026-04-14T15:30:00Z",
  "deletion_time": "",
  "destroyed": false
}
```

### API Paths

The KV v2 engine registers five path groups under its mount point. All paths are relative to the mount (e.g., if mounted at `secret/`, the full API path is `/v1/secret/data/myapp`).

| Path Pattern | Operations | Description |
|---|---|---|
| `config` | Read, Write | Engine-level configuration (max_versions, cas_required, delete_version_after) |
| `data/<name>` | Read, Write, Delete | Read/write versioned secret data. Delete soft-deletes the latest version. |
| `metadata/<name>` | Read, Delete, List | Read version metadata. Delete permanently removes all versions and metadata. |
| `destroy/<name>` | Write | Permanently destroy specific versions (irreversible). |
| `undelete/<name>` | Write | Recover soft-deleted versions. |

### Operations Detail

#### Write Secret (`POST/PUT data/<name>`)

Request body:

```json
{
  "data": { "key": "value" },
  "options": {
    "cas": 2
  }
}
```

Behavior:
1. Read current metadata (or create new if first write).
2. If `cas` is provided, verify `cas == current_version`. Reject with 400 if mismatch.
3. If `cas_required` is set on metadata or engine config, reject writes without `cas`.
4. Increment `current_version`.
5. Store new `VersionData` at `versions/<name>/<new_version>`.
6. Update metadata with new version entry and `updated_time`.
7. If version count exceeds `max_versions`, permanently delete the oldest version data and remove its metadata entry.

Response:

```json
{
  "data": {
    "version": 3,
    "created_time": "2026-04-14T15:30:00Z",
    "deletion_time": "",
    "destroyed": false
  }
}
```

#### Read Secret (`GET data/<name>`)

Query parameter: `?version=N` (optional, defaults to latest non-deleted version).

Behavior:
1. Read metadata to find the requested version.
2. If version is soft-deleted (`deletion_time` is set, `destroyed` is false), return 404 with a warning.
3. If version is destroyed, return 404 with error.
4. Read version data from `versions/<name>/<version>`.
5. Return data with version metadata.

Response:

```json
{
  "data": {
    "data": { "key": "value" },
    "metadata": {
      "version": 3,
      "created_time": "2026-04-14T15:30:00Z",
      "deletion_time": "",
      "destroyed": false
    }
  }
}
```

#### Soft-Delete (`DELETE data/<name>`)

Request body (optional):

```json
{
  "versions": [2, 3]
}
```

Behavior:
1. If `versions` is provided, soft-delete those specific versions.
2. If no body, soft-delete the latest version only.
3. Set `deletion_time` on the targeted version entries in metadata.
4. Do **not** remove the version data from storage.
5. Subsequent reads of soft-deleted versions return 404 with a warning indicating the version was deleted.

#### Undelete (`POST undelete/<name>`)

Request body:

```json
{
  "versions": [2, 3]
}
```

Behavior:
1. For each specified version, clear `deletion_time` in metadata.
2. Only works on soft-deleted versions (non-empty `deletion_time`, `destroyed == false`).
3. Destroyed versions cannot be undeleted.

#### Destroy (`POST destroy/<name>`)

Request body:

```json
{
  "versions": [1, 2]
}
```

Behavior:
1. For each specified version:
   - Delete the version data from storage (`versions/<name>/<version>`).
   - Set `destroyed = true` in metadata.
2. This is irreversible. The secret data is permanently gone.

#### Read Metadata (`GET metadata/<name>`)

Returns the full metadata object without any secret data.

#### Delete All (`DELETE metadata/<name>`)

Permanently removes:
- All version data entries from storage.
- The metadata entry from storage.
- This is a hard delete of the entire secret and all its history.

#### List (`LIST metadata/`)

Lists all secret names that have metadata. Returns keys, not values.

#### Engine Config (`GET/POST config`)

```json
{
  "max_versions": 10,
  "cas_required": false,
  "delete_version_after": "0s"
}
```

- `max_versions`: Default maximum versions per secret (0 = unlimited). Individual secrets can override via metadata write.
- `cas_required`: If true, all writes must include a `cas` parameter.
- `delete_version_after`: Duration after which versions are automatically soft-deleted. `0s` disables.

### Module Registration

The KV v2 engine registers as a new logical backend type `"kv-v2"`. The existing KV v1 (`"kv"`) remains unchanged.

- Operators choose the version at mount time: `bvault secrets enable -version=2 kv`
- The default `secret/` mount should remain KV v1 for backwards compatibility.
- A future phase can make v2 the default for new mounts.

### Mount Options

When mounting, the `options` map on the `MountEntry` carries engine-level defaults:

```json
{
  "version": "2",
  "max_versions": "10",
  "cas_required": "false",
  "delete_version_after": "0s"
}
```

### Concurrency

- Writes must be serialized per secret name to prevent version number conflicts. Use the storage `lock()` method with the secret path as the lock name.
- CAS provides application-level optimistic concurrency. The lock ensures version number atomicity.

### Version Cleanup

When `max_versions` is exceeded after a write:
1. Identify versions to prune (oldest first, by version number).
2. Delete their `versions/<name>/<version>` storage entries.
3. Remove their entries from the `versions` map in metadata.
4. Update `oldest_version`.

When `delete_version_after` is set:
- On each read or write, check if any non-destroyed versions have `created_time` older than the threshold.
- Soft-delete expired versions (set `deletion_time`, do not destroy).
- A background cleanup is not required for correctness but may be added later for efficiency.

## Implementation Scope

### New Files

| File | Purpose |
|---|---|
| `src/modules/kv_v2/mod.rs` | KV v2 module and backend implementation |
| `src/modules/kv_v2/metadata.rs` | SecretMetadata and VersionMetadata types, serialization |
| `src/modules/kv_v2/version.rs` | VersionData type, serialization |
| `tests/features/kv_v2.feature` | Cucumber BDD scenarios |
| `tests/cucumber_kv_v2.rs` | Cucumber step definitions |

### Modified Files

| File | Change |
|---|---|
| `src/modules/mod.rs` | Add `pub mod kv_v2` |
| `src/module_manager.rs` | Register KvV2Module in default modules |
| `src/core.rs` | Register `"kv-v2"` logical backend |
| `src/cli/command/secrets.rs` | Support `-version=2` flag for mount |
| `tests/test_default_logical.rs` | Add KV v2 integration tests |

### Not In Scope

- Automatic background version expiry (lazy expiry on access is sufficient for Phase 1).
- Event-driven notifications on secret changes.
- Cross-datacenter replication semantics (handled by the storage backend, not the KV engine).
- Migration tool from KV v1 to KV v2 (can be added later).

## Compatibility

This feature targets API compatibility with HashiCorp Vault's KV v2 secret engine:
- Same path structure (`data/`, `metadata/`, `destroy/`, `undelete/`, `config`).
- Same request/response JSON shapes.
- Same CAS semantics.
- Same soft-delete/destroy distinction.

Clients using the Vault KV v2 API (e.g., `hvac` Python library, `vault` CLI) should work against BastionVault with minimal or no changes.

## Testing Requirements

### Unit Tests

- Metadata serialization round-trip.
- Version number increment logic.
- CAS validation (match, mismatch, required but missing).
- Max version pruning.
- Soft-delete and undelete state transitions.
- Destroy permanence (undelete after destroy fails).

### Integration Tests

- Full lifecycle: write v1, write v2, read latest, read v1, soft-delete v1, undelete v1, destroy v1.
- CAS conflict detection.
- Max version eviction.
- List metadata after various operations.
- Delete all via metadata endpoint.
- Engine config persistence and effect on new writes.

### Cucumber BDD Scenarios

- Store and retrieve a versioned secret.
- Read a specific version by number.
- Soft-delete and recover a version.
- Destroy a version permanently.
- CAS prevents concurrent write conflicts.
- Max versions evicts oldest automatically.
- Delete metadata removes all versions.

## Security Considerations

- Soft-deleted data remains encrypted in storage until destroyed. This is intentional for recoverability but means sensitive data persists after soft-delete.
- Destroy operations must permanently remove data from the storage backend. Verify that the physical backend does not retain deleted entries (e.g., in WAL or journal files).
- CAS values are not secret but should not be predictable by unauthorized parties. Since they are sequential integers, they reveal write frequency. This is acceptable and matches Vault behavior.
- Version metadata (timestamps, deletion status) is stored encrypted through the barrier like all other data.
