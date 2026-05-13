---
sidebar_label: Cluster Client Discovery
sidebar_position: 16
---

# Cluster Client Discovery & Health-Aware Connection

BastionVault clients (the GUI, the `bvault` CLI, anything built on the
`bv-client` crate) can locate the nodes of an HA cluster from a single
DNS name, probe each node's health, pick the best one, and pin the
session to it for the lifetime of the connection.

Server-side clustering (Hiqlite HA) is unchanged — this page is purely
about the client side.

## When to use it

Configure cluster discovery instead of a literal node URL whenever you
have:

- More than one BastionVault node in HA (Hiqlite cluster).
- Operators connecting from laptops or CI runners who shouldn't have to
  pick a node by hand.
- A rolling-upgrade story where draining one node shouldn't break
  every operator's bookmark.

A single-node deployment can keep using a literal URL — the client
detects the URL shape and skips DNS entirely.

## How it works

1. **Input** — the operator types a cluster address. Two shapes are
   recognised:
   - **Cluster name** (`vault.corp.example`): runs discovery.
   - **Literal URL** (`https://host:port`, `http://10.0.0.5`): bypasses
     discovery entirely.
2. **SRV lookup** — for cluster names, the client queries
   `_bvault._tcp.<cluster-name>` and collects the records.
3. **Health probe** — every candidate's `/v1/sys/health` endpoint is
   queried in parallel with a short timeout (default 1500 ms). The
   response classifies each node as one of: `ActiveLeader`,
   `Follower`, `Sealed`, `Uninitialized`, or `Unreachable`.
4. **Pick** — the highest-ranked healthy node wins:
   1. SRV priority is a hard floor.
   2. Within the same priority, leader beats follower.
   3. Within the same (priority, state), lower RTT wins.
   4. Final tiebreak: higher SRV weight wins.
   The minority side of a `cluster_id` disagreement is dropped before
   the rank so a stale SRV pointing at a decommissioned node can't win.
5. **Pin** — the chosen node is frozen for the lifetime of the session.
   All subsequent requests go to the same host. There is no mid-session
   transparent failover by design — see [Sticky session](#sticky-session)
   below.

## DNS configuration

The minimum SRV record set for a 3-node cluster:

```dns
_bvault._tcp.vault.corp.example. 60 IN SRV 10 50 8200 bv-1.corp.example.
_bvault._tcp.vault.corp.example. 60 IN SRV 10 50 8200 bv-2.corp.example.
_bvault._tcp.vault.corp.example. 60 IN SRV 10 50 8200 bv-3.corp.example.
```

Fields:

- **Priority** — equal priority means equal preference; a higher number
  means "only use this when nothing lower is healthy" (e.g. a DR site).
- **Weight** — only used as a final tiebreaker when priority, state,
  and RTT are all equal. Setting weight to 0 disables it for that
  record.
- **Port** — overrides any scheme default. SRV is authoritative.
- **Target** — the hostname the TLS connection uses for SNI + cert
  verification. Make sure SANs cover every target hostname.

### TLS SAN coverage

Because the target hostname is what the client puts into the SNI
extension, each node's certificate needs a SAN matching its own target
name in the SRV set. The cluster name (`vault.corp.example`) is NOT
required in the SANs unless you also want literal-URL connects to work.

A common shortcut is to issue every node a cert with all three SANs
plus the cluster name; that way you don't need to re-issue certs when
SRV records change.

### Scheme hint

The default scheme is HTTPS. To force HTTP, prefix the cluster name
with `http://` (e.g. `http://vault.corp.example`). The scheme prefix
is preserved through discovery; SRV-derived ports + targets are
combined with that scheme.

## Sticky session

Once the client picks a node, it pins it. If that node goes down
mid-session, the next request returns a `NodeUnavailable` error
instead of silently retrying against a different node.

This is a deliberate boundary. A few features carry node-local state
that doesn't transparently survive a re-pin:

- Resource Connect SSH / RDP transports.
- Long-poll watchers on the plugin surface.
- In-flight FIDO2 ceremonies.
- The on-disk plugin surface cache.

Recovery is explicit: the operator calls `connect_remote` (GUI) or
re-runs the CLI command. Discovery + health re-run from scratch, the
dead node fails its probe, and the next pick lands on a survivor.

The GUI surfaces `NodeUnavailable` with a "Reconnect" toast.

## CLI usage

The `bvault` CLI auto-discovers whenever `--address` is a bare DNS
name:

```bash
# Cluster discovery (bare hostname) — picks a node automatically
bvault read --address vault.corp.example secret/data/db

# Literal URL — connects directly to that node, no DNS lookup
bvault read --address https://bv-1.corp.example:8200 secret/data/db

# Force literal mode against a bare hostname (no SRV, no health)
bvault read --address vault.corp.example --no-cluster-discovery
```

Environment-variable equivalent: `VAULT_NO_CLUSTER_DISCOVERY=1`.

### `bvault cluster discover`

Diagnostics-only — prints the ranked candidate table without actually
connecting to anything. Useful for "why did the client pick that node"
investigations:

```bash
$ bvault cluster discover --address vault.corp.example

Cluster: vault.corp.example

Target                                    Pri   Wt State           RTT(ms)  Cluster ID
--------------------------------------------------------------------------------
https://bv-1.corp.example:8200             10   50 leader               12  c1
https://bv-2.corp.example:8200             10   50 follower             14  c1
https://bv-3.corp.example:8200             10   50 follower             18  c1

Picked: https://bv-1.corp.example:8200 (ActiveLeader, 12 ms)
```

Same TLS flags as the other subcommands (`--ca-cert`, `--tls-skip-verify`,
etc.).

## GUI usage

In the connection profile form (Settings → Connect):

- Type the cluster name as the **Server Address**.
- Leave **Cluster discovery** ticked (the default).
- If the cluster uses non-default TLS material, fill in the CA cert as
  usual — the probes use the same trust material as the eventual
  request.

After connecting, hover the vault chip in the bottom-left of the
sidebar to see which node was chosen and what its RTT was.

The Settings → General page has a **Cluster Discovery** row with a
"Re-probe" button that re-runs discovery against the current profile
and shows the full candidate table. This does NOT change the live
connection — it's diagnostics only.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| "no healthy node found" on connect | All nodes sealed / uninitialized / unreachable | Check `bvault cluster discover` table; unseal the candidates. |
| Picks the wrong node consistently | SRV priorities not set | Lower the priority on the preferred node. |
| Each connect picks a different node | All nodes equal across (priority, state, RTT) | Set SRV weights deterministically (e.g. 100 / 50 / 50). |
| "node is unavailable" mid-session | Pinned node went away | The session is over by design — call connect again. |
| Literal URL still triggers DNS | Bug; the input must contain `://` to bypass discovery | File an issue. |

## Limitations

- **No mid-session transparent failover.** See above for the rationale.
- **No non-SRV discovery** (mDNS, Consul, k8s headless services) —
  SRV-only for v1.
- **Deterministic weight tiebreak**, not RFC 2782 weighted-random. Same
  weights → same pick.
- **No latency-aware re-pinning** after the initial choice. RTT is
  observed once at connect time.

## Implementation pointers

- Discovery: [`crates/bv-client/src/discovery.rs`](https://github.com/ffquintella/BastionVault/blob/main/crates/bv-client/src/discovery.rs)
- Health probes + scoring: [`crates/bv-client/src/health.rs`](https://github.com/ffquintella/BastionVault/blob/main/crates/bv-client/src/health.rs)
- `RemoteBackendBuilder::build_with_discovery`: [`crates/bv-client/src/remote.rs`](https://github.com/ffquintella/BastionVault/blob/main/crates/bv-client/src/remote.rs)
- Tauri wire-up: `gui/src-tauri/src/commands/connection.rs`
- CLI subcommand: `src/cli/command/cluster_discover.rs`
- E2E tests against in-process fake nodes: `crates/bv-client/tests/cluster_discovery_e2e.rs`
- Spec: [`features/vault-cluster-client-discovery.md`](https://github.com/ffquintella/BastionVault/blob/main/features/vault-cluster-client-discovery.md)
- Roadmap: [`roadmaps/vault-cluster-client-discovery.md`](https://github.com/ffquintella/BastionVault/blob/main/roadmaps/vault-cluster-client-discovery.md)
