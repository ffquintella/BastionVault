# Feature: Hiqlite High-Availability Storage

## Summary

Make an embedded Raft-based SQLite engine (hiqlite) the default storage backend for BastionVault, so that high availability, automatic replication, leader-aware writes, distributed locking, and self-healing are built into the vault process itself with no external database dependencies.

## Motivation

BastionVault's previous storage model offered:

- `file` -- single-node, no replication, no failover.
- `mysql` -- requires an external database, operator-managed HA, and network-accessible credentials.
- `sqlx` -- same as mysql but with Postgres/SQLite support (now removed due to dependency conflict).

None of these provide built-in high availability. Operators who want a resilient vault must provision and manage a separate database cluster, configure replication, handle failover, and monitor quorum -- all outside BastionVault's control.

With hiqlite, a BastionVault cluster **is** the Raft cluster. Each vault node embeds a SQLite database replicated via Raft consensus. Writes are automatically routed to the leader. Reads are locally consistent. Failover happens automatically when a leader node goes down. No external database infrastructure is required.

## Current State (Phase 1 Complete)

### What Is Implemented

**Backend** (`src/storage/hiqlite/mod.rs`):
- `HiqliteBackend` struct implementing the `Backend` trait.
- CRUD operations via hiqlite's SQL interface:
  - `list()` -- `SELECT ... WHERE vault_key LIKE ?` with prefix truncation logic.
  - `get()` -- `SELECT ... WHERE vault_key = ?` via `query_consistent_map()` (strong consistency).
  - `put()` -- `INSERT OR REPLACE` via `client.execute()` (Raft-replicated write).
  - `delete()` -- `DELETE ... WHERE vault_key = ?` via `client.execute()`.
- Distributed locking via `client.lock()` using hiqlite's `dlock` feature.
- Automatic table creation on startup (`CREATE TABLE IF NOT EXISTS`).
- Graceful shutdown on drop.

**Configuration** (`src/cli/config.rs`):
- `"hiqlite"` recognized in `STORAGE_TYPE_KEYWORDS`.
- Config keys: `data_dir`, `node_id`, `secret_raft`, `secret_api`, `table`, `listen_addr_api`, `listen_addr_raft`, `nodes`.
- Supports both single-node (default) and multi-node cluster configurations.

**Build integration**:
- `storage_hiqlite` feature flag, enabled by default in `Cargo.toml`.
- `hiqlite = { version = "0.13", optional = true, features = ["sqlite", "dlock"] }`.
- `sqlx` removed from the project (libsqlite3-sys link conflict).

**Tests**:
- Unit tests using existing `test_backend_curd` and `test_backend_list_prefix` generic test functions.
- Cucumber BDD scenarios in `tests/features/hiqlite_storage.feature` (8 scenarios).
- Config parsing test `test_load_config_hiqlite`.
- CI jobs for Linux, macOS, and Windows.

### What Is Not Yet Implemented

- Raft error mapping to BastionVault error types (Phase 2).
- Health/status endpoints exposing cluster state (Phase 2).
- Multi-node integration tests (Phase 2).
- Documentation and config examples treating hiqlite as the default (Phase 3).
- Startup validation warning about non-HA configs (Phase 4).
- Cluster management CLI commands (Phase 4A).
- Migration tooling from file/mysql to hiqlite (Phase 5).
- HA fault-injection validation (Phase 6).

## Design

### Architecture

```
┌────────────────────────────────────────────────┐
│           BastionVault Node 1 (Leader)         │
│                                                │
│  HTTP API ─→ Core ─→ Barrier ─→ HiqliteBackend│
│                                     │          │
│                               ┌─────┴─────┐   │
│                               │  hiqlite   │   │
│                               │  (SQLite   │   │
│                               │  + Raft)   │   │
│                               └─────┬─────┘   │
└─────────────────────────────────────┼──────────┘
                                      │ Raft
                    ┌─────────────────┼─────────────────┐
                    │                 │                  │
┌───────────────────┴──┐   ┌─────────┴────────┐  ┌─────┴──────────────┐
│  BastionVault Node 2 │   │ BastionVault     │  │ BastionVault       │
│  (Follower)          │   │ Node 3 (Follower)│  │ Node N (Follower)  │
│                      │   │                  │  │                    │
│  HiqliteBackend      │   │ HiqliteBackend   │  │ HiqliteBackend     │
│  (local SQLite       │   │ (local SQLite    │  │ (local SQLite      │
│   replica)           │   │  replica)        │  │  replica)          │
└──────────────────────┘   └──────────────────┘  └────────────────────┘
```

Each node runs:
- A full BastionVault HTTP API server.
- An embedded hiqlite instance with its own SQLite database.
- A Raft participant (voter or non-voter).

Writes on any node are forwarded to the Raft leader. Reads on the leader are local. Reads on followers use `query_consistent_map()` which forwards to the leader for strong consistency.

### Data Model

Single SQLite table per vault:

```sql
CREATE TABLE IF NOT EXISTS vault (
    vault_key   TEXT NOT NULL PRIMARY KEY,
    vault_value BLOB NOT NULL
);
```

- `vault_key`: hierarchical path (e.g., `logical/<mount_uuid>/secret/myapp/db`).
- `vault_value`: encrypted bytes from the barrier layer.

All data is encrypted by the barrier before reaching hiqlite. Hiqlite stores only opaque encrypted blobs.

### Consistency Model

| Operation | Consistency | Mechanism |
|---|---|---|
| `put()` | Linearizable | `client.execute()` -- Raft-replicated write through leader |
| `delete()` | Linearizable | `client.execute()` -- Raft-replicated write through leader |
| `get()` | Strong | `client.query_consistent_map()` -- forwarded to leader |
| `list()` | Strong | `client.query_consistent_map()` -- forwarded to leader |
| `lock()` | Linearizable | `client.lock()` -- Raft-replicated distributed lock |

Strong consistency is the default for all operations. This is appropriate for a secrets manager where stale reads could cause authentication failures or expose revoked credentials.

### Distributed Locking

The `lock()` method uses hiqlite's `dlock` feature, which provides Raft-replicated distributed locks. This replaces:
- File backend: `lockfile` crate (process-local file locks).
- MySQL backend: `GET_LOCK()` / `RELEASE_LOCK()` (database-level advisory locks).

Hiqlite locks are cluster-wide and survive leader failover. A lock acquired on node A is visible and respected on all nodes.

### Node Configuration

**Single-node** (development):
```hcl
storage "hiqlite" {
  data_dir    = "/var/lib/bvault/data"
  node_id     = 1
  secret_raft = "your_raft_secret_16ch"
  secret_api  = "your_api_secret_16chr"
}
```

When `nodes` is omitted, the backend creates a single-node cluster using `listen_addr_raft` and `listen_addr_api` as its own address.

**Multi-node** (production):
```hcl
storage "hiqlite" {
  data_dir         = "/var/lib/bvault/data"
  node_id          = 1
  secret_raft      = "shared_raft_secret_1"
  secret_api       = "shared_api_secret_12"
  listen_addr_api  = "0.0.0.0:8100"
  listen_addr_raft = "0.0.0.0:8200"
  nodes            = [
    "1:10.0.0.11:8200:10.0.0.11:8100",
    "2:10.0.0.12:8200:10.0.0.12:8100",
    "3:10.0.0.13:8200:10.0.0.13:8100",
  ]
}
```

Each node entry follows the format `"id:raft_host:raft_port:api_host:api_port"`.

**Config keys:**

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `data_dir` | Yes | -- | Directory for Raft logs, SQLite DB, and snapshots |
| `node_id` | Yes | -- | Unique node ID in the cluster (u64) |
| `secret_raft` | Yes | -- | Shared secret for Raft inter-node messages (>=16 chars) |
| `secret_api` | Yes | -- | Shared secret for hiqlite API communication (>=16 chars) |
| `table` | No | `"vault"` | SQLite table name |
| `listen_addr_api` | No | `"0.0.0.0:8100"` | Hiqlite API listen address |
| `listen_addr_raft` | No | `"0.0.0.0:8200"` | Raft consensus listen address |
| `nodes` | No | single-node self | Cluster member list |

### Replication Error Handling (Phase 2)

Hiqlite errors must be mapped to BastionVault errors that operators can act on:

| Hiqlite Condition | BastionVault Error | Operator Action |
|---|---|---|
| No leader elected | `ErrClusterNoLeader` | Wait for election, check quorum |
| Leader changed mid-request | Automatic retry by hiqlite | Transparent to caller |
| Quorum lost | `ErrClusterQuorumLost` | Restore failed nodes |
| Node not part of cluster | `ErrClusterNodeUnknown` | Check node config and rejoin |
| Raft log replication timeout | `ErrClusterReplicationTimeout` | Check network between nodes |

### Health Endpoints (Phase 2)

Expose cluster state through the existing `/v1/sys/health` and new `/v1/sys/cluster` endpoints:

**`GET /v1/sys/health`** (extended):
```json
{
  "initialized": true,
  "sealed": false,
  "cluster_name": "bvault-prod",
  "cluster_id": "uuid-here",
  "is_leader": true,
  "is_healthy_db": true,
  "raft_leader_id": 1
}
```

**`GET /v1/sys/cluster/status`** (new):
```json
{
  "leader_id": 1,
  "node_id": 1,
  "is_leader": true,
  "voters": [
    { "id": 1, "addr_raft": "10.0.0.11:8200", "addr_api": "10.0.0.11:8100" },
    { "id": 2, "addr_raft": "10.0.0.12:8200", "addr_api": "10.0.0.12:8100" },
    { "id": 3, "addr_raft": "10.0.0.13:8200", "addr_api": "10.0.0.13:8100" }
  ],
  "healthy": true
}
```

### Cluster Management CLI (Phase 4A)

| Command | Description | Hiqlite API |
|---|---|---|
| `bvault cluster status` | Show cluster health and leader | `client.metrics_db()`, `client.is_healthy_db()` |
| `bvault cluster leader` | Show current leader node | `client.is_leader_db()` |
| `bvault cluster members` | List all cluster members | `NodeConfig.nodes` + `client.metrics_db()` |
| `bvault cluster init` | Bootstrap a new cluster | First node startup with `nodes` config |
| `bvault cluster join` | Join an existing cluster | Add node to `nodes` config and restart |
| `bvault cluster leave` | Gracefully remove this node | `client.shutdown()` + config update |
| `bvault cluster remove-node <id>` | Remove a failed node | Raft membership change via openraft |
| `bvault cluster failover` | Trigger leader step-down | Raft leadership transfer |
| `bvault cluster recover` | Recover from quorum loss | Force new cluster from surviving nodes |

### Migration from Existing Backends (Phase 5)

Offline migration path:

```bash
# 1. Seal the old vault
bvault operator seal

# 2. Export all data (requires unseal keys)
bvault operator backup -output=vault-backup.bvbk

# 3. Configure new vault with hiqlite storage
# 4. Initialize new vault (new encryption keys)
bvault operator init

# 5. Import data (requires old unseal keys for reading backup)
bvault operator restore -input=vault-backup.bvbk
```

For same-key migration (keeping unseal keys), the backup format stores encrypted data as-is, so it can be restored directly into a hiqlite backend.

### Deployment Tiers

| Tier | Storage | Nodes | Use Case |
|---|---|---|---|
| Development | `file` or `hiqlite` (single-node) | 1 | Local development, testing |
| Standard | `hiqlite` | 3 | Default production deployment |
| Large | `hiqlite` | 5 | High-throughput or geo-distributed |
| Legacy | `mysql` | 1+ (external DB) | Existing deployments not yet migrated |

## Implementation Scope

### Phase 1 (Complete)

| File | Status |
|---|---|
| `src/storage/hiqlite/mod.rs` | Done |
| `src/storage/mod.rs` (module + factory) | Done |
| `src/cli/config.rs` (keyword + test) | Done |
| `Cargo.toml` (dependency + feature + default) | Done |
| `tests/features/hiqlite_storage.feature` | Done |
| `tests/cucumber_hiqlite.rs` | Done |
| `.github/workflows/rust.yml` (CI jobs) | Done |

### Phase 2: Replication Semantics

| File | Purpose |
|---|---|
| `src/storage/hiqlite/mod.rs` | Map hiqlite errors to RvError variants |
| `src/errors.rs` | Add cluster-specific error variants |
| `src/modules/system/mod.rs` | Implement cluster health/status endpoints |
| `src/http/sys.rs` | Register `/sys/cluster/status` route |
| `tests/` | Multi-node integration tests |

### Phase 3: Default Server Recommendation

| File | Purpose |
|---|---|
| Config examples and docs | Update to show hiqlite as default |
| `src/cli/command/server.rs` | Warn if using file backend in non-dev mode |

### Phase 4 + 4A: Cluster Management

| File | Purpose |
|---|---|
| `src/cli/command/cluster.rs` | Cluster CLI command group |
| `src/cli/mod.rs` | Register cluster commands |
| `src/http/sys.rs` | Cluster management API endpoints |

### Phase 5: Migration

Depends on the Import/Export & Backup/Restore feature (`features/import-export-backup-restore.md`).

### Phase 6: HA Validation

Test-only. No production code changes expected. Fault injection test suite covering the test matrix in the roadmap.

## Testing Requirements

### Unit Tests (Phase 1 -- Done)
- Backend CRUD via `test_backend_curd()`.
- Prefix listing via `test_backend_list_prefix()`.
- Config parsing via `test_load_config_hiqlite`.

### Cucumber BDD Scenarios (Phase 1 -- Done)
- Store and retrieve an entry.
- Get returns empty for missing key.
- Delete an entry.
- Delete a nonexistent key succeeds.
- List entries at root.
- List entries with prefix.
- List returns empty for unmatched prefix.
- Overwrite an existing entry.

### Integration Tests (Phase 2)
- Three-node cluster formation.
- Write on leader, read on follower.
- Leader failure and automatic failover.
- Write during leader election (expect transient error then success).
- Quorum loss behavior (2 of 3 nodes down).

### HA Validation (Phase 6)
- Single leader steady-state throughput.
- Follower restart without data loss.
- Leader restart with automatic re-election.
- Leader failover under write load.
- Quorum loss and recovery.
- Network partition simulation.
- Slow follower catching up.
- Auto-heal after ungraceful shutdown.
- Cluster management CLI end-to-end workflows.

## Security Considerations

- **Raft secrets**: `secret_raft` and `secret_api` protect inter-node communication. They must be at least 16 characters and shared identically across all cluster nodes. Compromising these secrets allows a rogue node to join the cluster.
- **Data at rest**: hiqlite stores data in a SQLite file on disk. The data is encrypted by the barrier layer before reaching hiqlite, so the SQLite file contains only encrypted blobs. However, Raft logs may contain plaintext SQL statements with encrypted parameter values -- verify that parameter binding does not leak key paths in Raft logs.
- **Data in transit**: inter-node Raft communication is authenticated via the shared secrets. TLS for inter-node traffic is supported via hiqlite's `tls_raft` and `tls_api` config options (not yet exposed through BastionVault config -- future work).
- **Split-brain**: Raft consensus prevents split-brain by requiring a majority quorum for writes. In a 3-node cluster, at most one partition can have quorum. The minority partition becomes read-only (and eventually times out).
- **`libsqlite3-sys` conflict**: hiqlite's dependency on `rusqlite` 0.39 conflicts with sqlx's dependency on `libsqlite3-sys` 0.28. Both claim the native `sqlite3` link. This forced removal of the sqlx backend. Projects needing both would require sqlx to upgrade its sqlite dependency, or use a separate process for one backend.
- **Dependency surface**: hiqlite pulls in openraft, rusqlite, axum, reqwest, and their transitive dependencies. This is a significant increase in the trusted dependency set. The trade-off is accepted because hiqlite replaces an entire external database tier.
