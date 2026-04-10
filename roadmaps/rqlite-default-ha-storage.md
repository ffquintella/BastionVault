# BastionVault Rqlite Default HA Storage Roadmap

## Goal

Make `rqlite` the default storage engine for BastionVault and make replication the default operating mode, so high availability is part of the default deployment model rather than an optional add-on.

## Why This Change

The current storage model is still oriented around:

- `file` for the simplest local deployment
- `mysql` for external database-backed persistence
- `sqlx` as an optional generic database path

That is not aligned with a default HA product posture. If BastionVault should come up in a production-oriented mode by default, then the storage layer needs:

- built-in replication
- leader-aware writes
- predictable failover behavior
- operationally simple bootstrap and join flows
- storage semantics that do not require a separate hand-managed database tier for the default case

`rqlite` is a strong fit for that direction because it gives BastionVault:

- SQLite semantics
- Raft-backed replication
- a small operational footprint
- a clear leader/follower model

This initiative also requires a dedicated HA and cluster management tool so operators can bootstrap, inspect, repair, and manage the replicated deployment model without dropping down into ad hoc raw backend commands.

## Current State

The codebase currently exposes:

- `file` storage in [src/storage/file.rs](/Users/felipe/Dev/BastionVault/src/storage/file.rs)
- `mysql` storage in [src/storage/mysql](/Users/felipe/Dev/BastionVault/src/storage/mysql)
- optional `sqlx` storage in [src/storage/sqlx/mod.rs](/Users/felipe/Dev/BastionVault/src/storage/sqlx/mod.rs)
- backend dispatch in [src/storage/mod.rs](/Users/felipe/Dev/BastionVault/src/storage/mod.rs)
- storage type parsing in [src/cli/config.rs](/Users/felipe/Dev/BastionVault/src/cli/config.rs)

The current config keywords still only advertise `file` and `mysql` in [src/cli/config.rs](/Users/felipe/Dev/BastionVault/src/cli/config.rs).

## Target Architecture

### Default storage mode

Default production-oriented storage should be:

- `rqlite`
- replicated
- multi-node aware
- leader-routed for writes

### Default operational behavior

By default, a BastionVault cluster should assume:

- one node may become leader
- writes must go through the leader
- reads may be configurable as leader-only or stale-tolerant depending on endpoint class
- join/bootstrap is explicit and automatable
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
   - `rqlite` with replication expected
3. advanced external-database mode
   - `mysql` and any future external engines treated as optional integrations, not the default recommendation

## Guiding Principles

1. Default behavior should optimize for availability, not minimum dependencies.
2. The storage API should stay narrow and backend-neutral.
3. Leader and replication semantics must be visible in the backend contract, not hidden in retry hacks.
4. Bootstrap, join, rejoin, and failover must be first-class operational flows.
5. Development-only backends should stay available, but they should not shape the default server path.
6. HA operations should be manageable through a BastionVault-native tool, not by expecting operators to manually orchestrate raw `rqlite` internals.

## Proposed Phases

## Phase 0: Design and Backend Contract Review

### Objectives

- define the exact `rqlite` backend scope
- identify where the current `Backend` trait is too weak for replicated semantics
- decide which consistency guarantees BastionVault requires per operation class

### Work Items

- review [src/storage/mod.rs](/Users/felipe/Dev/BastionVault/src/storage/mod.rs)
- define backend expectations for:
  - leader writes
  - read consistency
  - lock behavior
  - transient leader changes
  - retry boundaries
- define the config schema for `rqlite`

### Acceptance Criteria

- a written backend contract exists for replicated storage
- the required `rqlite` config surface is agreed
- stale-read and leader-write policy is documented

## Phase 1: Add an Rqlite Backend

### Objectives

- add a new storage backend implementation for `rqlite`
- keep the existing storage trait stable where possible

### Work Items

- add `src/storage/rqlite/mod.rs`
- implement `Backend` for `RqliteBackend`
- add backend creation in [src/storage/mod.rs](/Users/felipe/Dev/BastionVault/src/storage/mod.rs)
- add config keyword support in [src/cli/config.rs](/Users/felipe/Dev/BastionVault/src/cli/config.rs)
- define config keys such as:
  - `address`
  - `bootstrap_expect`
  - `join`
  - `api_key` or auth material if needed
  - `timeout`
  - `read_consistency`

### Acceptance Criteria

- `storage "rqlite"` is recognized and instantiated
- CRUD operations work against a live `rqlite` cluster
- leader redirects or leader discovery are handled correctly

## Phase 2: Make Replication Semantics Explicit

### Objectives

- stop treating replication and leader election as invisible backend details
- make HA assumptions explicit in startup and storage behavior

### Work Items

- define how BastionVault reacts when:
  - there is no leader
  - the leader changes mid-request
  - quorum is lost
  - a follower receives a write
- add backend-level error mapping for:
  - not leader
  - read-only follower
  - unavailable quorum
  - cluster join failure

### Acceptance Criteria

- failures from `rqlite` map to clear BastionVault errors
- write paths behave correctly during leader changes
- expected degraded modes are documented

## Phase 3: Make Rqlite the Default Server Recommendation

### Objectives

- shift the product default away from local file storage for real deployments
- make `rqlite` the documented and generated default for server config

### Work Items

- update config examples and docs
- change generated example configs to prefer `storage "rqlite"`
- keep `file` for dev-only quickstart flows
- update CLI help and install docs to describe HA-first deployment

### Acceptance Criteria

- docs and examples treat `rqlite` as the default production backend
- local file storage is clearly labeled development-only
- new users land on an HA-oriented deployment path by default

## Phase 4: Make Replication the Default Operational Mode

### Objectives

- ensure a multi-node replicated topology is the standard deployment path
- reduce the amount of manual cluster bootstrap work

### Work Items

- add startup validation that warns or fails on obviously non-HA production configs
- add join/bootstrap workflow documentation
- add a cluster formation path for:
  - first node bootstrap
  - follower join
  - node replacement
  - restart and recovery
- decide whether BastionVault should expose cluster health based on `rqlite` leader/quorum state
- define the minimum HA management UX that BastionVault itself must provide

### Acceptance Criteria

- a three-node replicated deployment is documented as the baseline production topology
- bootstrap and join are repeatable
- health/readiness semantics reflect cluster state

## Phase 4A: Add an HA and Cluster Management Tool

### Objectives

- give operators a BastionVault-native way to manage the replicated cluster
- avoid making HA depend on manual `rqlite` API usage

### Scope

The tool may start as a CLI command group and later grow into API endpoints or an operator subsystem, but it should begin with a concrete operational surface in BastionVault itself.

### Suggested command areas

- `rvault cluster init`
- `rvault cluster join`
- `rvault cluster leave`
- `rvault cluster remove-node`
- `rvault cluster status`
- `rvault cluster leader`
- `rvault cluster members`
- `rvault cluster failover`
- `rvault cluster recover`

### Work Items

- define the BastionVault cluster-management abstraction over `rqlite`
- decide which operations are:
  - read-only inspection
  - topology-changing admin actions
  - disaster-recovery actions
- add operator-safe output for:
  - leader
  - voters
  - non-voters
  - quorum health
  - node reachability
  - replication state
- add clear failure messages for:
  - no quorum
  - split-brain suspicion
  - join target mismatch
  - node identity conflicts

### Acceptance Criteria

- operators can bootstrap and inspect a cluster through BastionVault-native commands
- node lifecycle operations no longer require raw backend-specific manual procedures
- the default HA deployment path is operationally manageable

## Phase 5: Migration Path from Existing Backends

### Objectives

- provide a safe path from `file` and `mysql` to `rqlite`
- avoid forcing a full re-initialize for existing deployments

### Work Items

- define export/import or copy-based migration for:
  - `file` -> `rqlite`
  - `mysql` -> `rqlite`
  - optional `sqlx` -> `rqlite`
- define offline and online migration guidance
- add data verification steps

### Acceptance Criteria

- migration steps are documented and testable
- operators can validate storage parity before cutover

## Phase 6: HA Validation and Operational Hardening

### Objectives

- prove the HA default under realistic failure cases
- make operational behavior predictable under faults

### Test Matrix

- single leader steady-state
- follower restart
- leader restart
- leader failover
- quorum loss
- network partition
- slow follower
- repeated write bursts during leader change
- operator workflows through the HA management tool

### Acceptance Criteria

- replicated write behavior is verified
- restart and failover scenarios are covered
- BastionVault behavior under quorum loss is documented and tested

## Configuration Direction

Illustrative target config shape:

```hcl
storage "rqlite" {
  address          = "http://127.0.0.1:4001"
  bootstrap_expect = 3
  join             = [
    "http://10.0.0.11:4001",
    "http://10.0.0.12:4001",
    "http://10.0.0.13:4001",
  ]
  read_consistency = "strong"
  timeout          = "5s"
}
```

This roadmap does not lock the final schema. It shows the level of explicitness the config should have.

## Risks

- `rqlite` leader semantics may require backend trait changes rather than a drop-in implementation
- lock behavior may need redesign if current storage locking assumes single-node locality
- operational confusion is likely if dev and production defaults are not clearly separated
- migration from `file` storage may be more operationally awkward than migration from SQL-backed backends

## Recommended Milestone Sequence

### Milestone 1

Backend contract updated for replicated storage.

### Milestone 2

`rqlite` backend implemented and wired into config parsing.

### Milestone 3

Leader-aware writes and explicit replication error handling landed.

### Milestone 4

Docs and generated examples switched to `rqlite` as the default production backend.

### Milestone 5

HA and cluster management tool available for bootstrap, inspection, and node lifecycle operations.

### Milestone 6

Migration tooling or documented migration runbooks available.

### Milestone 7

HA validation complete for failover, restart, and quorum-loss scenarios.

## Immediate Next Steps

1. Add a progress tracker once implementation starts.
2. Create `src/storage/rqlite/` with a minimal backend skeleton and config parser.
3. Update [src/cli/config.rs](/Users/felipe/Dev/BastionVault/src/cli/config.rs) to recognize `rqlite`.
4. Decide whether `rqlite` access will use raw HTTP requests or a dedicated client crate.
5. Define the first `rvault cluster` command surface for HA lifecycle management.
