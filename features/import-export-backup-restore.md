# Feature: Import/Export & Backup/Restore

## Summary

Add the ability to create point-in-time backups of all vault data (encrypted), restore from those backups, and import/export individual secrets or subtrees for migration between vault instances.

## Motivation

BastionVault has no way to recover from data loss, storage corruption, or operator error beyond what the underlying storage backend provides. Operators need:

- **Disaster recovery**: restore a vault after storage failure or corruption.
- **Migration**: move data between vault instances (e.g., dev to staging, or switching storage backends).
- **Testing**: clone production vault data into a test environment with different encryption keys.
- **Compliance**: retain periodic snapshots for regulatory requirements.

Without this feature, the only recovery path is to rely on the storage backend's own backup mechanism (filesystem snapshots, MySQL dumps, hiqlite Raft snapshots), which is backend-specific and does not provide a portable format.

## Current State

- The `Backend` trait exposes only `list()`, `get()`, `put()`, `delete()`. No dump, snapshot, or bulk-read operations.
- No CLI commands for backup or restore.
- No HTTP API endpoints for snapshots.
- Hiqlite has built-in backup capabilities (`client.backup()`, `client.backup_file_local()`) that are not exposed through BastionVault.
- The file backend stores data as individual files, so a filesystem copy is a de-facto backup -- but not portable across backends.
- Key material import exists only for narrow cases: `import_pem()` and `import_pq_seed()` in `src/utils/key.rs` for cryptographic keys.

## Design

### Backup/Restore (Full Vault)

A backup captures all data stored through the barrier (encrypted secrets, mount configuration, auth state, policies) as a single portable archive.

#### Backup Format

A backup is a file containing:

```
[8-byte magic: "BVBK\x00\x01\x00\x00"]
[4-byte header length (LE)]
[header JSON]
[sequence of entry frames]
[32-byte HMAC-SHA256 over entire file content preceding the HMAC]
```

**Header:**
```json
{
  "version": 1,
  "created_at": "2026-04-14T16:00:00Z",
  "barrier_type": "chacha20-poly1305",
  "entry_count": 4523,
  "compressed": true
}
```

**Entry frame:**
```
[4-byte key length (LE)]
[key bytes (UTF-8 path)]
[4-byte value length (LE)]
[value bytes (encrypted, as stored in the barrier)]
```

Data is stored **as-is from the barrier** -- still encrypted with the data encryption key. This means:
- A backup file is useless without the corresponding unseal keys.
- No secret material is exposed in the backup.
- Restoring requires the same barrier key (or a re-encryption step).

**Compression**: entry frames are optionally compressed with zstd before writing. Indicated by `compressed: true` in the header.

**Integrity**: the trailing HMAC-SHA256 (keyed with the barrier's HMAC key) covers all preceding bytes. On restore, the HMAC is verified before any data is written.

#### Backup Operation

1. Acquire a read lock (prevent writes during backup for consistency).
2. Iterate all keys in the storage backend via `list("")` recursively.
3. For each key, `get()` the raw encrypted entry.
4. Write the entry frame to the backup file.
5. Compute and append the HMAC.
6. Release the lock.

For hiqlite specifically, prefer `client.backup_file_local()` for an atomic SQLite snapshot, then wrap it in the BastionVault backup format for portability.

#### Restore Operation

1. Verify the backup file magic and version.
2. Verify the HMAC (requires the vault to be unsealed).
3. Optionally wipe the current storage (operator must confirm).
4. Iterate entry frames and `put()` each entry into the storage backend.
5. Reload mount tables, policies, and auth state from the restored data.

#### API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/v1/sys/backup` | POST | Create a backup. Returns the backup file as a binary download. |
| `/v1/sys/restore` | POST | Restore from a backup file (multipart upload). Requires root token. |

#### CLI Commands

| Command | Description |
|---|---|
| `bvault operator backup -output=/path/to/backup.bvbk` | Create a backup to a local file. |
| `bvault operator restore -input=/path/to/backup.bvbk` | Restore from a backup file. |
| `bvault operator backup -output=- \| gzip > backup.bvbk.gz` | Stream backup to stdout for piping. |

### Import/Export (Subtree)

Import/export operates on a subtree of the secret namespace and transfers **decrypted** secret data. This enables migration between vault instances with different encryption keys.

#### Export

Export reads secrets through the barrier (decrypting them) and writes them to a JSON file.

```json
{
  "version": 1,
  "created_at": "2026-04-14T16:00:00Z",
  "mount": "secret/",
  "prefix": "myapp/",
  "entries": [
    {
      "key": "myapp/db",
      "value": { "username": "admin", "password": "s3cret" }
    },
    {
      "key": "myapp/api-key",
      "value": { "key": "abc123" }
    }
  ]
}
```

The export file contains **plaintext secrets**. It must be treated as highly sensitive, encrypted at rest by the operator, and deleted after import.

#### Import

Import reads the JSON export file and writes each entry through the barrier (encrypting them with the target vault's key).

- Entries are written to the same relative paths under the target mount.
- Existing entries at the same path can be overwritten or skipped (operator choice via `--force` flag).

#### API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/v1/sys/export/{mount}/{prefix}` | GET | Export decrypted secrets under prefix. Requires root token. |
| `/v1/sys/import/{mount}` | POST | Import secrets from JSON body. Requires root token. |

#### CLI Commands

| Command | Description |
|---|---|
| `bvault operator export -mount=secret/ -prefix=myapp/ -output=export.json` | Export a subtree. |
| `bvault operator import -mount=secret/ -input=export.json` | Import from a file. |
| `bvault operator import -mount=secret/ -input=export.json --force` | Import, overwriting existing keys. |

### Cross-Backend Migration

Combining export from one backend and import to another enables storage backend migration:

```bash
# On old vault (file backend)
bvault operator export -mount=secret/ -output=all-secrets.json

# On new vault (hiqlite backend)
bvault operator import -mount=secret/ -input=all-secrets.json
```

For full vault migration (including mounts, policies, auth), use backup/restore if both vaults share the same unseal keys, or use export/import per mount if they don't.

## Implementation Scope

### New Files

| File | Purpose |
|---|---|
| `src/backup/mod.rs` | Backup format, writer, reader, HMAC verification |
| `src/backup/format.rs` | Magic bytes, header serialization, entry frame codec |
| `src/backup/export.rs` | Subtree export (decrypted JSON) |
| `src/backup/import.rs` | Subtree import |
| `src/cli/command/operator_backup.rs` | Backup CLI command |
| `src/cli/command/operator_restore.rs` | Restore CLI command |
| `src/cli/command/operator_export.rs` | Export CLI command |
| `src/cli/command/operator_import.rs` | Import CLI command |

### Modified Files

| File | Change |
|---|---|
| `src/lib.rs` | Add `pub mod backup` |
| `src/modules/system/mod.rs` | Add backup/restore/export/import API endpoints |
| `src/cli/mod.rs` | Register new CLI commands |
| `Cargo.toml` | Add `zstd` dependency for compression |

## Testing Requirements

### Unit Tests
- Backup format write/read round-trip.
- HMAC verification: valid file passes, tampered file fails.
- Entry frame codec: handles empty values, large values, special characters in keys.
- Export JSON serialization round-trip.

### Integration Tests
- Full backup and restore cycle: write secrets, backup, wipe, restore, verify secrets.
- Export subtree, import to different mount, verify data matches.
- Import with `--force` overwrites, without skips.
- Backup during concurrent writes (lock behavior).
- Cross-backend: backup from file backend, restore to hiqlite.

### Cucumber BDD Scenarios
- Create a backup and restore it to a clean vault.
- Export secrets and import them into a different vault instance.
- Verify backup HMAC rejects a tampered file.
- Verify export contains only the requested prefix.

## Security Considerations

- **Backup files contain encrypted data** -- safe to store on untrusted media as long as unseal keys are not colocated. Losing the unseal keys makes the backup unrecoverable.
- **Export files contain plaintext secrets** -- must be encrypted by the operator (e.g., GPG, age) before storage or transfer. The CLI should print a warning when creating an export.
- **Restore is a destructive operation** -- it overwrites current vault state. Require root token and explicit confirmation.
- **Import with `--force`** overwrites existing secrets silently. Without `--force`, conflicts are reported and skipped.
- **Backup during active writes** may produce a slightly inconsistent snapshot if the storage backend doesn't support atomic snapshots. For hiqlite, use the native SQLite backup API for atomicity. For file/MySQL backends, the read lock provides consistency.
- **HMAC key for backup integrity** is derived from the barrier. A backup can only be verified by an unsealed vault with the same key. This is intentional -- it prevents offline tampering verification by unauthorized parties.
