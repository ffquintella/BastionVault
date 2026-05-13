# Roadmap: Vault Cluster — Client Discovery & Health-Aware Connection

Companion to [features/vault-cluster-client-discovery.md](../features/vault-cluster-client-discovery.md). Server-side clustering (Hiqlite HA) already ships; this roadmap covers the client side.

## Goal

Given a single DNS name as a "cluster address", the client locates BastionVault nodes via `_bvault._tcp` SRV records, probes each one's `/sys/health`, scores them, picks the best, and pins the session to that node — failing over only when the user opens a new connection.

## Status

**All 8 phases done.** Full feature shipped end-to-end: bv-client discovery + health + sticky failure contract; GUI wired into `connect_remote` with cluster-discovery toggle, status-bar tooltip, and a Re-probe diagnostics modal in Settings; `bvault` CLI auto-discovers on bare hostnames and exposes `bvault cluster discover` + `--no-cluster-discovery`; 7 e2e tests against in-process fake HTTP nodes covering leader/follower preference, SRV priority floor, cluster_id minority rejection, RTT tiebreak, and post-failure reconnect; operator docs at `docs/docs/cluster-client-discovery.md`.

## Phase 1 — SRV discovery primitive ✅ Done

Pure resolver work. No transport changes yet.

- Add `crates/bv-client/src/discovery.rs` with a single async fn that, given a cluster name, returns `Vec<SrvCandidate { target, port, priority, weight }>`.
- Use `hickory-resolver` (lightweight, already in the dep tree via reqwest's rustls features in most builds; promote to a direct dep if not).
- Honor system resolver config (`/etc/resolv.conf` on Linux, system APIs on macOS/Windows).
- Fallback: parse the input as a literal `scheme://host[:port]` URL when SRV lookup returns NXDOMAIN, empty, or any resolver error short of timeout.
- Unit tests with a mock resolver: NXDOMAIN fallback, mixed-priority sort, weighted-random tiebreak.

Acceptance: `discovery::resolve("vault.corp.example").await` returns the candidate list; `discovery::resolve("https://localhost:8200").await` returns a single literal candidate.

## Phase 2 — Health screen + scoring ✅ Done

Pure HTTP work over the candidate list from Phase 1.

- Add `crates/bv-client/src/health.rs` with the health classifier and scoring function (table from the feature spec).
- Async parallel probes (default 4-wide) with per-probe timeout 1.5 s, configurable.
- Reject sealed / uninitialized / unreachable.
- Tiebreak: SRV priority → state (leader best) → RTT → SRV weight (RFC 2782).
- Capture each node's `cluster_id`; reject the minority side of a mismatch so stale DNS pointing at a decomissioned node can't win.
- Return `Selected { target_host, target_port, scheme, observed_state }`.
- Unit tests for every row of the classification table, the cluster_id mismatch path, and the scoring tiebreaks.

Acceptance: feeding a fake candidate list at a local mock HTTP server returns the expected pick; sealed/standby/active states all classified correctly.

## Phase 3 — Wire discovery + health into `Client` / `RemoteBackend` ✅ Done

Plumbing only. No external API change yet.

- `RemoteProfile` gets the new fields: `cluster_discovery`, `discovery_srv_service`, `health_probe_timeout_ms`, `health_probe_parallelism` (with the defaults in the feature spec).
- `RemoteBackend::connect` (or the equivalent constructor) first runs `discovery::resolve` then `health::pick` and uses the chosen target as the request base URL. Old literal-address path still works when `cluster_discovery=false` or the input is clearly a URL.
- Once chosen, the target is frozen for the lifetime of the `RemoteBackend` instance. No background re-probing.
- Add a `Selected` accessor so the GUI status bar can read back which node it landed on.

Acceptance: existing `RemoteBackend` integration tests still pass; a new test using a 3-node mock cluster proves the right node is picked.

## Phase 4 — Sticky-with-explicit-reconnect failure handling ✅ Done

Define and enforce the "session ends on node failure" contract.

- A request error that indicates node-level failure (connection refused, TLS handshake fail, repeated 5xx with a sealed body) causes the in-flight request to return a typed error variant `Error::NodeUnavailable { host, reason }`.
- No automatic retry against a different node. No silent re-resolution.
- Document the error contract so upstream callers (GUI, CLI) can surface a single clear "node went away, reconnect to retry" message.
- The GUI's existing `connect_remote` is the recovery path: calling it again re-runs Phases 1 + 2 from scratch and naturally skips the dead node.

Acceptance: integration test kills the chosen node mid-session, observes `NodeUnavailable`, then calls `connect_remote` again and observes the next call succeeds against a survivor.

## Phase 5 — GUI surfacing ✅ Done

Operator UX.

- `RemoteProfile` form picks up the new fields with sensible defaults; advanced fields hidden behind a disclosure (operators just type a hostname for the common case).
- Status-bar element shows `Connected to <cluster name>` with a tooltip carrying the actual node target + leader/follower state.
- On `NodeUnavailable`, the GUI surfaces a clear toast + a one-click "Reconnect" action that triggers `connect_remote` again.
- Settings page gains a read-only "Cluster discovery" diagnostics panel that re-runs discovery and shows the full candidate table with scores — useful for operators debugging "why did it pick that node."

Acceptance: walkthrough with a 3-node Hiqlite test cluster: connect by cluster name, see chosen node, kill it, get the toast, click Reconnect, land on a survivor.

## Phase 6 — CLI surfacing ✅ Done

- `bvault --address <cluster-name>` automatically does discovery + health.
- `bvault --no-cluster-discovery` forces literal mode for diagnostics.
- New `bvault cluster discover <name>` subcommand prints the scored candidate table without actually connecting — the CLI analogue of Phase 5's diagnostics panel.

Acceptance: against the integration cluster, `bvault cluster discover vault.test.local` prints the three nodes ranked correctly.

## Phase 7 — Hiqlite HA fault-injection coverage ✅ Done

- Extend the existing `tests/hiqlite_ha_fault_injection.rs` harness to spin up a real cluster and exercise the client side.
- Scenarios: cold start with all 3 nodes up; cold start with leader killed; mid-session leader kill (expects `NodeUnavailable` + clean reconnect to a survivor); rolling restart of all three.
- Gate behind `CARGO_TEST_HIQLITE=1` like the existing HA tests.

Acceptance: HA fault-injection suite green on CI for all four scenarios.

## Phase 8 — Documentation + operator runbook ✅ Done

- Add a `docs/cluster-client-discovery.md` (or expand the existing HA doc) covering: SRV record shape, port/scheme conventions, TLS SAN coverage requirements, troubleshooting (`bvault cluster discover`), known caveats (no mid-session failover by design).
- Update CHANGELOG, roadmap.md, and the feature file's "Current State".

Acceptance: a new operator can configure a clustered deployment from the docs without reading the source.

## Out of scope (recorded for later)

- Per-request load-balancing — deferred indefinitely.
- Mid-session transparent failover — would require redesigning the Resource Connect transport layer, ongoing FIDO2 ceremony state, and plugin surface cache invalidation. Sticky-with-reconnect is the deliberate boundary.
- Non-SRV discovery (mDNS, Consul, k8s headless services).
- Geo / latency-aware re-pinning.

## Dependencies

- `hickory-resolver` — direct dep if not already present.
- No new server-side work — `/sys/health` and `/sys/cluster-status` already provide everything the client needs.
