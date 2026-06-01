# Feature: Vault Cluster — Client Discovery & Health-Aware Connection

## Summary

Add client-side cluster awareness so a BastionVault client (GUI, CLI, or bv-client consumer) given a single cluster name can locate the cluster's nodes via DNS SRV records, probe each node's health, pick the best one to connect to, and stay on that node for the lifetime of the session — failing over only when the host goes down or the user opens a fresh connection.

Server-side clustering already exists (Hiqlite HA, `/sys/cluster-status`, `/sys/health`). The missing piece is the client never having to know which physical node it talks to.

## Status

**Done.** All 8 roadmap phases shipped: bv-client discovery + health modules; `RemoteBackendBuilder::build_with_discovery`; `ClientError::{NodeUnavailable, NoHealthyNode}` + sticky failure mapping; Tauri `connect_remote` runs discovery and exposes the picked node via `get_selected_node` + `cluster_discover` commands; GUI ConnectPage gains a cluster-discovery toggle, Layout shows the connected node in the vault-chip tooltip, Settings has a Re-probe diagnostics modal; `bvault` CLI auto-discovers on bare DNS names with `--no-cluster-discovery` opt-out and a new `bvault cluster discover` subcommand; 7 e2e integration tests use in-process fake HTTP nodes to cover leader-over-follower, SRV priority floor (both ways), cluster_id minority rejection, RTT tiebreak, all-unreachable rejection, and post-failure reconnect; operator runbook at `docs/docs/cluster-client-discovery.md`. 26 new tests in total (19 unit + 7 e2e).

## Motivation

Today operators connecting a client to an HA cluster have to:

1. Pick one node's address by hand and put it in `RemoteProfile.address`.
2. Hope that node is the live leader (or accept follower-forwarding overhead).
3. Manually rotate to a different address when the chosen node is sealed, partitioned, or being upgraded.

That's a per-node concern leaking into every client config. The desired posture is: the operator types `vault.corp.example`, the client resolves `_bvault._tcp.vault.corp.example`, scores the answers, connects to the best one, and the user never sees a hostname rotation unless their host actually fails.

It also unblocks zero-downtime rolling upgrades for end users — drain a node, the next fresh client connection skips it, existing sessions get a clean reconnect.

## Design

### Discovery — DNS SRV

Cluster address is a bare DNS name (e.g. `vault.corp.example`). The client queries:

```
_bvault._tcp.<cluster-name>     SRV
```

A standard SRV record set, e.g.:

```
_bvault._tcp.vault.corp.example. 60 IN SRV 10 50 8200 bv-1.corp.example.
_bvault._tcp.vault.corp.example. 60 IN SRV 10 50 8200 bv-2.corp.example.
_bvault._tcp.vault.corp.example. 60 IN SRV 20 50 8200 bv-3.corp.example.
```

Semantics:

- **Priority** is honored as a hard preference — lower wins. Higher-priority nodes are tried first; the client only considers a lower-priority node if every higher-priority node fails the health screen.
- **Weight** is used as a tiebreaker among healthy same-priority candidates (RFC 2782 weighted random pick).
- **Port** from the SRV record overrides any default.
- **Target hostname** is what the TLS connection uses for SNI and certificate verification — so SAN coverage stays predictable.

Fallback: if SRV lookup returns NXDOMAIN or empty, the client treats the input as a literal `scheme://host[:port]` and behaves exactly like today's `RemoteProfile.address` — no regressions for non-clustered deployments.

Resolution is async via `hickory-resolver` (already pulled in transitively via `reqwest` rustls features; if not, add as a thin direct dep). System resolver config is honored.

A scheme hint can be carried in the cluster name (`https://vault.corp.example`) when operators want to force the wire protocol; otherwise default to HTTPS.

### Health screen

For each candidate node, the client issues a single unauthenticated `GET /v1/sys/health` with a short connect+read timeout (default 1.5 s). The response shape (Vault-compatible) carries:

- `initialized: bool`
- `sealed: bool`
- `standby: bool`
- `performance_standby: bool`
- `replication_perf_mode` / `replication_dr_mode`
- `version: string`
- `cluster_id`, `cluster_name`
- `server_time_utc`

Classification:

| State | Health code | Action |
|---|---|---|
| `initialized=true, sealed=false, standby=false` | active leader | preferred |
| `initialized=true, sealed=false, standby=true` | follower / performance standby | accepted |
| `initialized=true, sealed=true` | sealed | rejected |
| not initialized | uninitialized | rejected |
| network error / timeout / TLS failure | unreachable | rejected |

Scoring (lower is better):

1. SRV priority bucket (hard floor).
2. State: leader = 0, follower = 1, anything else = ∞.
3. RTT of the health probe in ms (tiebreaker among same-bucket nodes).
4. SRV weight (RFC 2782 weighted random across the remaining ties).

The cluster_id field is also captured and used as a sanity check: every node in a single SRV answer is expected to advertise the same cluster_id; mismatches are logged and the minority cluster_id is rejected so a stale DNS entry pointing at a decomissioned node can't poison the selection.

### Sticky session with failover-on-next-open

Once a node is chosen, the client pins it for the entire session:

- All subsequent HTTP requests go to the same target host:port.
- We do NOT re-probe in the background, do NOT re-resolve SRV per request, do NOT silently move requests to another node.
- If the pinned node fails (connection refused, TLS handshake fails, 5xx with `sealed` body, or a configurable number of consecutive request errors), the current request returns an error and the session ends. The GUI surfaces "the BastionVault node you were connected to became unavailable — reconnect to retry on another node."
- The next `connect_remote` call (a fresh user action, app restart, new CLI invocation) re-runs discovery + health screen from scratch and picks again, naturally skipping the dead node.

Rationale: re-pointing an in-flight session at a new node mid-stream interacts badly with anything that has node-local state (Resource Connect SSH/RDP transports, long-poll watchers, ongoing FIDO2 ceremonies, plugin surface caches). Sticky-with-explicit-reconnect makes that boundary unambiguous and gives the operator a clean retry without surprise behaviour.

### Caching

- Discovery result cached for the lifetime of the session keyed on cluster name.
- Health-probe RTT is NOT remembered across sessions — every fresh open re-probes.
- DNS TTL is respected when the underlying resolver does its own caching; we don't second-guess it.

### Configuration surface

`RemoteProfile` gains:

- `cluster_discovery: bool` (default `true`) — when `false`, force literal-address mode for the existing single-node behavior.
- `discovery_srv_service: String` (default `"_bvault._tcp"`) — escape hatch for operators using a non-standard SRV label.
- `health_probe_timeout_ms: u32` (default `1500`).
- `health_probe_parallelism: u8` (default `4`) — concurrent probes; with a small cluster this just runs them all in parallel.

Existing `address` field is reinterpreted as the cluster name when `cluster_discovery=true`; otherwise it's a literal scheme://host[:port] as today.

### CLI

`bvault --address vault.corp.example` automatically does discovery + health. A new `--no-cluster-discovery` flag forces literal mode for diagnostics.

### Observability

- Each connection records a single structured log line: cluster name, candidate count, chosen target, RTT, leader vs follower.
- Prometheus counters on the server side already cover health endpoint hits; no new server metrics needed.
- The GUI shows the connected node in the status bar (small text under "Connected to <cluster name>") so operators can sanity-check which node they landed on.

### Out of scope

- Per-request load balancing across nodes (deliberate — see sticky session above).
- Mid-session transparent failover (deliberate — see sticky session above).
- Active-active multi-datacenter routing / geo-based selection.
- Latency-aware re-pinning after the initial choice.
- Discovery via mechanisms other than SRV (mDNS, Consul, k8s headless services).

These can be follow-up sub-initiatives once SRV-based discovery proves operationally useful.

## Acceptance Criteria

- Operator can put a single DNS name in the GUI's connection profile and connect successfully against a 3-node Hiqlite cluster, with the GUI status bar showing which node was chosen.
- Sealing the chosen node forces an explicit reconnect (not a silent retry), and the next reconnect picks a different healthy node.
- A profile pointing at a literal `https://host:8200` still works without any DNS query attempts.
- The CLI `bvault` with a cluster name in `--address` exhibits the same behavior.
- Unit tests cover: SRV parsing, priority ordering, weighted-random tiebreak, health classification table, cluster_id mismatch rejection, fallback to literal address on NXDOMAIN.
- Integration test against the existing HA fault-injection harness: bring up 3 nodes, point client at the cluster, kill the chosen node, confirm next `connect_remote` picks a survivor.

## Implementation Notes

- The probing happens inside `crates/bv-client` so both CLI and GUI inherit it; the GUI's `connect_remote` Tauri command just calls into the same path.
- SRV resolution belongs in a new `crates/bv-client/src/discovery.rs`.
- Health classification + scoring belongs in `crates/bv-client/src/health.rs` to keep `remote.rs` free of selection logic.
- The chosen target is materialized into the existing `Client`/`RemoteBackend` types — no trait surface changes downstream.

See [roadmaps/vault-cluster-client-discovery.md](../roadmaps/vault-cluster-client-discovery.md) for the phased plan.

## Current State

Phases 1–4 shipped in `crates/bv-client`:

- `discovery.rs` — `SrvCandidate`, `DiscoveryConfig`, `SrvLookup` trait, `SystemResolver` (hickory-resolver backed), `resolve()` entry point. Parses literal URLs (with scheme prefix, explicit port, IP literal, or IPv6 brackets) into single-candidate `ResolvedAddress::Literal`; bare DNS names go through `_bvault._tcp.<name>` SRV lookup with NXDOMAIN/error fallback to literal-hostname resolution. Inputs that already start with `_` (e.g. `_cofre-html._tcp.esi.fgv.br`) are recognised as SRV-shaped FQDNs and queried verbatim instead of being prefixed — with no A/AAAA fallback on empty answers, since underscore labels can't resolve as hostnames.
- `health.rs` — `NodeState` enum, `HealthResponse` (subset of `/sys/health`), pure `classify()` function, `ProbeResult`, `Selected`, `HealthConfig`, `probe_all` (parallel `ureq` probes via `tokio::spawn`), and pure `pick()` selector applying SRV-priority hard floor → leader-over-follower → RTT → weight tiebreak with cluster_id minority rejection.
- `error.rs` — `ClientError::NodeUnavailable { host, reason }` and `ClientError::NoHealthyNode { cluster, reason }`. `classify_node_failure()` helper folds transport errors (ureq/io) and sealed-shaped 5xx responses into `NodeUnavailable`; 4xx and unrelated 5xx pass through untouched.
- `remote.rs` — `RemoteBackendBuilder::with_cluster_discovery`, `with_discovery_config`, `with_health_config`, and `build_with_discovery` (+ `build_with_discovery_using` for test injection). The chosen node is frozen into `RemoteInner` and exposed via `RemoteBackend::selected()` and `input_label()`. `handle()` runs every response through `classify_node_failure` so a downed node yields `NodeUnavailable` for the GUI/CLI to recognise.

Server `/sys/health` and `/sys/cluster-status` already exist and require no changes.

**Cluster-wide operator seal/unseal:** because seal state is per-node (each node holds its own in-memory barrier and accumulates unseal-key shares independently), `bvault operator seal` and `bvault operator unseal` now fan out over *every* node returned by SRV discovery rather than the single `pick()`ed node. `HttpOptions::cluster_clients(local)` (`src/cli/command/mod.rs`) returns one `(url, Client)` per discovered candidate (reusing `probe_cluster` + `client_at`), or a single entry for `--local` / literal `http(s)://` addresses / `--no-cluster-discovery`. Unseal broadcasts each share to all nodes so they cross the threshold in lockstep; both commands report per-node results and continue past per-node failures.

**Not yet wired into the GUI's `connect_remote` Tauri command or the CLI's `--address` flag** — phases 5 and 6 of the roadmap. Today every caller still uses `RemoteBackendBuilder::build` (literal path), so the new behaviour is dormant until a caller switches to `build_with_discovery`.
