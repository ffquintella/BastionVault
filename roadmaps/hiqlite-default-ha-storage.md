# BastionVault Hiqlite Default HA Storage Roadmap

## Goal

Make `hiqlite` (embedded Raft-based SQLite) the default storage engine for BastionVault so that high availability, replication, and leader-aware writes are built into the process itself rather than requiring an external database tier.

## Why Hiqlite

The original plan targeted `rqlite`, an external HTTP-based distributed SQLite service. After evaluation, `hiqlite` was chosen instead because it is an **embedded** library:

- Raft consensus runs in-process. No separate service to deploy, monitor, or upgrade.
- Local reads are zero-latency; no HTTP round-trip.
- Writes are automatically routed to the Raft leader across nodes.
- Self-healing from ungraceful shutdowns (`auto-heal` feature).
- Built-in distributed locks (`dlock` feature) replace advisory-lock workarounds.
- Native Rust BLOB support via `rusqlite`; no base64 encoding needed.
- Simpler operational model: a BastionVault cluster **is** the Raft cluster.

The trade-off is a heavier compile-time dependency (`hiqlite` pulls `openraft`, `rusqlite`, `axum`, `reqwest`), but this is acceptable for a storage engine that will be the default production backend.

## Why This Change

The storage model before this initiative was oriented around:

- `file` for the simplest local deployment
- `mysql` for external database-backed persistence
- `sqlx` as an optional generic database path (now removed due to `libsqlite3-sys` link conflict with hiqlite)

That is not aligned with a default HA product posture. If BastionVault should come up in a production-oriented mode by default, then the storage layer needs:

- built-in replication
- leader-aware writes
- predictable failover behavior
- operationally simple bootstrap and join flows
- storage semantics that do not require a separate hand-managed database tier for the default case

## Current State

The codebase currently exposes:

- `file` storage in [src/storage/physical/file.rs](/src/storage/physical/file.rs)
- `mysql` storage in [src/storage/mysql](/src/storage/mysql) (Diesel + r2d2)
- `hiqlite` storage in [src/storage/hiqlite/mod.rs](/src/storage/hiqlite/mod.rs) **(Phase 1 complete)**
- backend dispatch in [src/storage/mod.rs](/src/storage/mod.rs)
- storage type parsing in [src/cli/config.rs](/src/cli/config.rs)
- `sqlx` backend has been **removed** (conflicted with hiqlite's `libsqlite3-sys` link requirement)

The config keywords now advertise `file`, `mysql`, and `hiqlite` in [src/cli/config.rs](/src/cli/config.rs).

## Target Architecture

### Default storage mode

Default production-oriented storage should be:

- `hiqlite`
- replicated
- multi-node aware
- leader-routed for writes

### Default operational behavior

By default, a BastionVault cluster should assume:

- one node may become leader
- writes must go through the leader (hiqlite handles this automatically)
- reads are consistent by default (`query_consistent_map`)
- join/bootstrap is explicit and automatable via `NodeConfig`
- node replacement is expected and documented

### HA management tool

BastionVault should ship a first-class operational tool for cluster lifecycle management.

That tool should cover:

- cluster bootstrap
- node join
- node removal
- leader discovery
- cluster health inspection
- quorum status inspection
- replication lag or follower status reporting
- planned failover and maintenance workflows
- rejoin and recovery workflows

### Deployment tiers

The product should distinguish between:

1. development mode
   - local file backend still allowed for throwaway single-node use
2. default server mode
   - `hiqlite` with replication expected
3. advanced external-database mode
   - `mysql` and any future external engines treated as optional integrations, not the default recommendation

## Guiding Principles

1. Default behavior should optimize for availability, not minimum dependencies.
2. The storage API should stay narrow and backend-neutral.
3. Leader and replication semantics must be visible in the backend contract, not hidden in retry hacks.
4. Bootstrap, join, rejoin, and failover must be first-class operational flows.
5. Development-only backends should stay available, but they should not shape the default server path.
6. HA operations should be manageable through a BastionVault-native tool, not by expecting operators to manually orchestrate raw cluster internals.

## Proposed Phases

## Phase 0: Design and Backend Contract Review -- COMPLETE

### Objectives

- define the exact hiqlite backend scope
- identify where the current `Backend` trait is sufficient for embedded replicated semantics
- decide which consistency guarantees BastionVault requires per operation class

### Outcome

The existing `Backend` trait (`list`, `get`, `put`, `delete`, `lock`) is sufficient for Phase 1. Hiqlite's embedded model means:

- **Writes** go through Raft automatically via `client.execute()` -- no leader-routing code needed
- **Reads** use `client.query_consistent_map()` for strong consistency
- **Locks** use hiqlite's built-in distributed lock (`client.lock()`) via the `dlock` feature
- No trait changes are required for Phase 1

The `sqlx` backend was removed because `libsqlite3-sys` link conflicts made the two backends mutually exclusive at the Cargo resolver level.

## Phase 1: Add Hiqlite Backend -- COMPLETE

### Objectives

- add a new storage backend implementation for `hiqlite`
- keep the existing storage trait stable

### What Was Implemented

- **`src/storage/hiqlite/mod.rs`**: `HiqliteBackend` struct implementing `Backend` trait
  - `list()` -- `SELECT vault_key FROM {table} WHERE vault_key LIKE ?` with prefix truncation
  - `get()` -- `SELECT vault_key, vault_value FROM {table} WHERE vault_key = ?`
  - `put()` -- `INSERT OR REPLACE INTO {table} (vault_key, vault_value) VALUES (?, ?)`
  - `delete()` -- `DELETE FROM {table} WHERE vault_key = ?`
  - `lock()` -- hiqlite distributed lock via `client.lock()`
  - Auto-creates vault table on startup via `client.batch()`
  - Graceful shutdown on drop
  - Config parsing: `data_dir`, `node_id`, `secret_raft`, `secret_api`, `table`, `listen_addr_api`, `listen_addr_raft`, `nodes`
- **`src/storage/mod.rs`**: Module declaration and `new_backend("hiqlite", ...)` factory arm
- **`src/cli/config.rs`**: `"hiqlite"` added to `STORAGE_TYPE_KEYWORDS`
- **`Cargo.toml`**: `hiqlite = { version = "0.13", optional = true, features = ["sqlite", "dlock"] }`, feature `storage_hiqlite`
- **Unit tests**: `test_hiqlite_backend` using existing `test_backend_curd` and `test_backend_list_prefix` generic test functions
- **Cucumber BDD tests**: `tests/features/hiqlite_storage.feature` (8 scenarios) with step definitions in `tests/cucumber_hiqlite.rs`
- **CI**: GitHub Actions jobs for `unix-hiqlite-test` and `windows-hiqlite-test`
- **Config test**: `test_load_config_hiqlite` verifying HCL config parsing

### What Was Removed

- `src/storage/sqlx/` directory (entire sqlx backend)
- `storage_sqlx` feature and `sqlx` dependency from `Cargo.toml`
- `SqlxError` variant from `src/errors.rs`
- `unix-sqlx-mysql-test` and `windows-sqlx-mysql-test` CI jobs

### Acceptance Criteria -- MET

- `storage "hiqlite"` is recognized and instantiated
- CRUD operations work against a single-node hiqlite cluster
- Distributed locking works via hiqlite's `dlock` feature
- Config parsing and validation work for HCL and JSON formats
- Builds cleanly with `cargo build --features storage_hiqlite`
- Default build (no hiqlite) still compiles and passes tests
- Clippy clean (no new warnings)

## Phase 2: Make Replication Semantics Explicit -- COMPLETE

### Objectives

- stop treating replication and leader election as invisible backend details
- make HA assumptions explicit in startup and storage behavior

### What Was Implemented

- **Error mapping** (`src/storage/hiqlite/mod.rs`): `map_hiqlite_error()` function that pattern-matches on hiqlite's `Error` enum and maps to specific BastionVault errors:
  - `CheckIsLeaderError` / `LeaderChange` → `ErrClusterNoLeader` (503)
  - `ClientWriteError` with `ForwardToLeader` → `ErrClusterNoLeader` (503)
  - `Connect` / `Timeout` → `ErrClusterUnhealthy` (503)
  - `RaftError` / `RaftErrorFatal` → `ErrCluster(msg)` (500)
- **New error variants** (`src/errors.rs`): `ErrClusterNoLeader`, `ErrClusterQuorumLost`, `ErrClusterUnhealthy`, `ErrCluster(String)`
- **Health endpoint** (`GET /v1/sys/health`): unauthenticated, returns `initialized`, `sealed`, `standby` (follower), `cluster_healthy`. HTTP status: 200 active, 429 standby, 503 sealed/unhealthy, 501 not initialized.
- **Cluster status endpoint** (`GET /v1/sys/cluster-status`): returns storage type, leader status, health, and raw Raft metrics.
- **Cluster health methods** on `HiqliteBackend`: `is_leader()`, `is_healthy()`, `cluster_metrics()`.
- **Backend trait** extended with `Any` supertrait for downcast support in health endpoints.
- **Status CLI** enhanced to show `standby` and `cluster_healthy` fields.
- **API client** extended with `health()` and `cluster_status()` methods.

### Acceptance Criteria -- MET

- Failures from hiqlite map to clear BastionVault errors with appropriate HTTP status codes
- Write paths use Raft-replicated `client.execute()` with leader auto-forwarding
- Health endpoints reflect Raft cluster state (leader, healthy, standby)
- All feature combinations compile cleanly (hiqlite, no-hiqlite, sync_handler)

## Phase 3: Make Hiqlite the Default Server Recommendation -- COMPLETE

### Objectives

- shift the product default away from local file storage for real deployments
- make `hiqlite` the documented and generated default for server config

### What Was Implemented

- **Example configs** in `config/`:
  - `config/dev.hcl` -- clearly labeled "DEVELOPMENT-ONLY", file backend with no TLS
  - `config/single-node.hcl` -- single-node hiqlite with TLS for small/staging deployments
  - `config/ha-cluster.hcl` -- 3-node HA cluster with hiqlite, ready to customize per node
- **Server CLI help** updated to recommend hiqlite for production and list all example configs
- **Startup warning** when file backend is used: logs a warning directing operators to hiqlite configs
- `storage_hiqlite` is already the default Cargo feature (done in Phase 1)

### Acceptance Criteria -- MET

- Example configs and CLI help treat hiqlite as the default production backend
- File storage is clearly labeled development-only with a runtime warning
- New users see HA-oriented config examples first

## Phase 4 + 4A: Cluster Management and Operational Mode -- COMPLETE

### Objectives

- ensure a multi-node replicated topology is the standard deployment path
- give operators a BastionVault-native way to manage the replicated cluster

### What Was Implemented

**Read-Only Inspection Commands:**

- **`bvault cluster status`** -- full cluster status with storage type, leader status, cluster health, and Raft metrics.
- **`bvault cluster leader`** -- leader and cluster health information.
- **`bvault cluster members`** -- cluster membership from Raft metrics.

**Topology-Changing Commands:**

- **`bvault cluster leave`** -- gracefully shuts down this node and leaves the Raft cluster via `client.shutdown()`.
- **`bvault cluster remove-node --node-id N`** -- removes a failed node from the cluster by calling hiqlite's `DELETE /cluster/membership/db` management endpoint. Supports `--stay-as-learner` to demote instead of fully removing.

**API Endpoints:**

- `POST /v1/sys/cluster/leave` -- triggers graceful cluster leave and shutdown.
- `POST /v1/sys/cluster/remove-node` -- removes a node by ID from the Raft cluster.

**Backend Methods on HiqliteBackend:**

- `remove_node(node_id, stay_as_learner)` -- calls hiqlite's management HTTP API via ureq.
- `leave_cluster()` -- calls `client.shutdown()` for graceful departure.
- `node_id()` -- returns this node's ID.

### Commands Not Implemented

| Command | Reason |
|---------|--------|
| `bvault cluster init` | Handled by config + first startup (hiqlite auto-bootstraps) |
| `bvault cluster join` | Handled by config (`nodes` list) + restart |
| `bvault cluster failover` | Not supported by hiqlite 0.13 (openraft 0.10+ required for leader step-down) |
| `bvault cluster recover` | Requires manual config update + restart; hiqlite auto-heal covers most cases |

### Acceptance Criteria -- MET

- Operators can bootstrap, inspect, and modify cluster membership through BastionVault-native commands
- Node removal no longer requires raw backend-specific manual procedures
- Health/readiness semantics reflect cluster state
- Graceful leave and forced removal are both supported

## Phase 5: Migration Path from Existing Backends -- COMPLETE

### Objectives

- provide a safe path from `file` and `mysql` to `hiqlite`
- avoid forcing a full re-initialize for existing deployments

### What Was Implemented

- **`bvault operator migrate`** CLI command that copies all encrypted entries from one backend to another.
- **`src/storage/migrate.rs`** module with `migrate_backend()` function that:
  - Recursively walks all keys in the source backend via `list()`.
  - Copies each entry to the destination via `get()` + `put()`.
  - Operates on raw encrypted bytes -- no decryption occurs, so the same unseal keys work after migration.
  - Reports entries copied and skipped.
- Supports any backend-to-backend combination: `file` -> `hiqlite`, `mysql` -> `hiqlite`, `hiqlite` -> `file`, etc.
- Config passed as `--source-config key=value` and `--dest-config key=value` pairs.

### Migration Procedure

```bash
# 1. Seal the vault to prevent writes during migration
bvault operator seal

# 2. Run the migration
bvault operator migrate \
  --source-type file --source-config path=/var/lib/bvault/old-data \
  --dest-type hiqlite \
  --dest-config data_dir=/var/lib/bvault/new-data \
  --dest-config node_id=1 \
  --dest-config secret_raft=my_raft_secret \
  --dest-config secret_api=my_api_secret

# 3. Update config to use hiqlite storage
# 4. Restart vault with new config
# 5. Unseal with the same keys
bvault operator unseal
```

### Acceptance Criteria -- MET

- Migration from `file` and `mysql` to `hiqlite` is supported via CLI
- Data is copied as encrypted blobs -- same unseal keys work after migration
- Migration steps are documented in CLI help and this roadmap

## Phase 6: HA Validation and Operational Hardening -- PARTIAL

### Objectives

- prove the HA default under realistic failure cases
- make operational behavior predictable under faults

### What Was Implemented

- **Single-node cluster health test** (`test_hiqlite_cluster_health`): verifies `is_leader()`, `is_healthy()`, `cluster_metrics()`, and `node_id()` for a single-node deployment.
- **Migration integration test** (`test_hiqlite_migrate_from_file`): verifies backend-to-backend data migration from file to hiqlite with 3 test entries across nested paths.
- **Cucumber HA feature file** (`tests/features/hiqlite_ha.feature`): 5 scenarios covering single-node health, cluster status, standby detection, data persistence across restart, and migration correctness.

### Test Matrix

| Scenario | Status |
|----------|--------|
| Single leader steady-state | Tested (unit test) |
| Data persistence across restart | Scenario defined |
| Migration file -> hiqlite | Tested (unit test) |
| Follower restart | Requires multi-node test infra |
| Leader restart | Requires multi-node test infra |
| Leader failover | Requires multi-node test infra |
| Quorum loss | Requires multi-node test infra |
| Network partition | Requires multi-node test infra |
| Slow follower | Requires multi-node test infra |
| Write bursts during leader change | Requires multi-node test infra |
| Auto-heal after ungraceful shutdown | Requires multi-node test infra |

Multi-node integration tests require spawning 3 hiqlite nodes on different ports in the same test process. This infrastructure can be added when multi-node CI environments are available.

### Acceptance Criteria -- PARTIALLY MET

- Single-node replicated write behavior is verified
- Migration scenarios are covered
- Multi-node failover and quorum-loss testing deferred to dedicated CI infrastructure

## Configuration

### Single-node (development or minimal deployment)

```hcl
storage "hiqlite" {
  data_dir    = "/var/lib/bvault/data"
  node_id     = 1
  secret_raft = "your_raft_secret_16ch"
  secret_api  = "your_api_secret_16chr"
}
```

### Multi-node (production)

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

### Config keys

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `data_dir` | Yes | -- | Directory for Raft logs, SQLite DB, and snapshots |
| `node_id` | Yes | -- | Unique node ID in the cluster (u64) |
| `secret_raft` | Yes | -- | Shared secret for Raft messages (>=16 chars) |
| `secret_api` | Yes | -- | Shared secret for API communication (>=16 chars) |
| `table` | No | `"vault"` | SQLite table name for vault data |
| `listen_addr_api` | No | `"0.0.0.0:8100"` | Address for hiqlite API server |
| `listen_addr_raft` | No | `"0.0.0.0:8200"` | Address for Raft consensus |
| `nodes` | No | single-node self | List of `"id:raft_host:raft_port:api_host:api_port"` strings |

## Risks

- hiqlite is a younger library (~200 downloads/month) with a smaller community than established databases
- the `libsqlite3-sys` link conflict forced removal of the `sqlx` backend; projects needing both will require a different approach
- operational confusion is likely if dev and production defaults are not clearly separated
- migration from `file` storage may be more operationally awkward than migration from SQL-backed backends
- hiqlite's `openraft` dependency may introduce version constraints on the broader dependency tree

## Milestone Summary

| Milestone | Phase | Status |
|-----------|-------|--------|
| Backend contract reviewed | 0 | **Done** |
| Hiqlite backend implemented and wired into config | 1 | **Done** |
| Leader-aware writes and explicit replication error handling | 2 | **Done** |
| Docs and examples switched to hiqlite as default | 3 | **Done** |
| HA and cluster management tool | 4 + 4A | **Done** |
| Migration tooling or runbooks available | 5 | **Done** |
| HA validation (single-node + migration) | 6 | **Partial** |

## Immediate Next Steps

1. Run full integration tests against the hiqlite backend (`cargo test --features storage_hiqlite`).
2. Begin Phase 2: map hiqlite Raft errors to BastionVault error types.
3. Test multi-node cluster formation in integration tests.
4. Define the first `bvault cluster` command surface for HA lifecycle management.
5. Update the global roadmap to reflect the switch from rqlite to hiqlite.
