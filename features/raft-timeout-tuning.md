# Feature: Raft Timeout Tuning — operator-set timeouts for a two-node cluster on a lossy inter-site link

> Status: **complete (T479, S117)**, declared by the operator on 2026-11-10.
> The three timeout keys, their validation and the isolated-leader threshold
> are implemented in `crates/bv-storage/src/hiqlite/raft_timing.rs` and
> unit-tested. Not done and not verified: the effective values in
> `cluster-status`, the Puppet parameters and a staging run with induced loss
> (see [Phases](#phases)). Spec written against
> `4bafa84b`. Extends the hiqlite storage backend and relates to
> [HSM Pool HA](hsm-pool-ha.md) (S114), whose T474 / T475 retries it does not
> replace. Touches liveness behaviour of the storage layer on high-risk ground
> (AGENTS.md §7: storage): `make test-release` before merge. No persisted
> format changes.

## Summary

A production two-node hiqlite cluster, one node per site, loses quorum many
times an hour. The nodes, the clocks and the NIC counters are healthy, and the
round-trip time is about 1 ms. The inter-site path loses a small share of
packets in bursts, and the Raft heartbeat (500 ms) is shorter than what one or
two TCP retransmissions cost. The heartbeat is also the time-to-live of every
`AppendEntries` call (openraft `replication/mod.rs`), which is why the logs say
`timeout after 500ms when AppendEntries`. BastionVault never set it, so
operators could not change it.

This feature makes the Raft timeouts operator-configurable, with unchanged
defaults, and ties the "isolated leader" health threshold to the configured
heartbeat. It is a **mitigation**. It does not fix the network and does not remove
the two-node topology's lack of fault tolerance (see
[Non-goals](#non-goals)).

## What blocks it today (evidence)

Measured on 2026-11-10 on the production cluster described above. The capture
was partial (about 3.5 of 10 planned minutes, roughly 23,800 TCP data
segments), so treat the rates as indicative.

- Both nodes report `Cluster lost quorum` at 7 to 56 times per hour over the
  previous 18 hours. The leader logs 1,193 `timeout while confirming
  leadership for read request … timeout after 500ms when AppendEntries`
  errors over the same period.
- Round-trip time between the nodes is about 1 ms. Ping loss on the inter-site
  path was 2% to 9% in short runs and 0.1% in a longer one: it comes in bursts.
- The local NICs and the bonded interface show no errors and no flapping, and
  the clocks are in sync (offset below 1 ms).
- In a packet capture taken on both nodes at the same time, every one of the 47
  retransmitted TCP segments on the Raft port was retransmitted with no ACK at
  the sender's NIC. In 35 of the 47 cases the original data never reached the
  receiving NIC, and in the others the receiver ACKed within 30 ms and the ACK
  never reached the sender. The loss therefore happens on the path between the
  sites, in both directions. A host-local packet filter on one node was
  suspected and ruled out.
- A TCP retransmission timeout of about 200 ms means two losses in a row cost
  at least 600 ms. That is already past the 500 ms heartbeat, so one short
  burst fails the `AppendEntries` call and, with it, the leadership
  confirmation a linearizable read waits for.
- The retries added by T474 and T475 apply only while `init` and HSM
  auto-unseal run. Normal traffic gets no retry, which is where the production
  errors surface (scheduled exports, the rustion pinger, HSM probes and drain,
  the dashboard stats read).

## Non-goals

- **Fixing the network.** The path between the sites needs its own
  investigation by the network team. This feature only makes the cluster
  tolerate a given amount of loss better.
- **Fault tolerance of a two-node cluster.** With two voters, one unreachable
  node still loses quorum for as long as it is unreachable. A third voter or a
  witness is a separate piece of work and needs its own spec.
- **Changing consistency.** Reads stay linearizable. Raft's safety does not
  depend on timing; only liveness does, so longer timeouts cannot cause a
  split brain or lose an acknowledged write.
- **Retrying writes** or retrying reads outside `init` / HSM unseal. That
  would change error semantics for every caller and is not proposed here.

## Proposal (as built)

### Configuration

Optional keys in the `storage "hiqlite"` block. Absent keys keep hiqlite's
values exactly. hiqlite hands the whole openraft `Config` to the caller, so
no fork patch is needed.

| Key | Default | Meaning |
|---|---|---|
| `raft_heartbeat_interval_ms` | `500` | Leader heartbeat period, and the time-to-live of every `AppendEntries` call |
| `raft_election_timeout_min_ms` | `1500` | Shortest follower election timeout |
| `raft_election_timeout_max_ms` | `3000` | Longest follower election timeout |
| `raft_allow_aggressive_timeouts` | `false` | Opt-in to a heartbeat or election minimum below the defaults |

Rules, all enforced at startup with an error that names the key, and no
clamping (`raft_timing.rs`):

- A present key must be a whole number of milliseconds (a string, a float or a
  negative number is an error); the flag must be a boolean.
- Heartbeat 100 to 60,000 ms; election maximum at most 300,000 ms.
- The election minimum must be at least 3 x the heartbeat, so raising only the
  heartbeat is refused and the message says to raise the election timeouts.
- The election maximum must exceed the minimum.
- A heartbeat or election minimum below the defaults needs
  `raft_allow_aggressive_timeouts = true`.
- When any value differs from the default, one startup line logs the effective
  values and the defaults. Nothing secret is logged. hiqlite's own
  validation still runs afterwards.

### Isolated-leader health threshold

`cluster-status` reports a leader unhealthy when its last quorum
acknowledgement is older than a threshold (previously the fixed 3,000 ms). It
is now `max(3000, 6 x heartbeat)`, so a leader that is only waiting out a
longer heartbeat is not flagged as isolated, and an unconfigured node behaves
exactly as before. A single-node leader still self-acknowledges.

### Status surface (not done)

The effective values should appear in the existing cluster-status output so a
mismatch between nodes is visible. Not implemented yet. Any new field goes
under `v2/` (AGENTS.md §7) and in `docs/api.md`.

### Recommended starting value

For the measured link, a burst of two losses costs at least 600 ms before TCP
retransmits. A heartbeat of **2,000 ms** with election timeouts of 6,000 to
12,000 ms covers that with room for the RTT and a second burst. This is a
proposal to confirm on staging with induced loss, not a measured optimum. The
cost is slower detection of a partitioned leader. With two voters an election
cannot succeed without the other node anyway, so the long election window
costs little there; with three or more nodes it delays failover by up to the
maximum.

## Security and risk

- Liveness only. Timeouts do not affect Raft safety, key custody, the seal or
  the barrier, and cannot cause a split brain or lose an acknowledged write.
  No new secret, network surface or dependency.
- A longer heartbeat means an isolated leader keeps serving reads for longer
  before failing with `Cluster lost quorum`. Callers with their own timeouts
  (HTTP clients, the HSM gateway relay) must be longer than the new value or
  they fail first. Listing each such timeout is still open.
- Compatibility: absent keys behave as today, old configs load unchanged,
  nothing is persisted and nothing needs migrating. Setting the keys on some
  nodes only is allowed by the code but not recommended: use the same values
  on every node.

## Phases

| Phase | Work | Status |
|---|---|---|
| 0 | Find which timeouts hiqlite exposes | done: `NodeConfig::raft_config` is the openraft `Config`; the 500 ms is `heartbeat_interval` |
| 1 | Fork patch | not needed |
| 2 | `bv-storage`: parse, validate, apply, derive the threshold, log | done, unit-tested |
| 3 | `docs/configuration.md`; effective values in cluster-status and `docs/api.md` | docs done; status fields planned |
| 4 | Deployment parameters in the Puppet module | planned |
| 5 | Validation on a staging pair with induced loss, then one production rollout, one node at a time | planned |

## Test plan

- Unit, `cargo nextest run -p bv-storage --lib --features storage_hiqlite raft_timing`
  (11 tests, passing): absent and unrelated keys give the defaults exactly;
  a longer heartbeat with matching election timeouts is accepted; heartbeat
  only is refused with a message naming the fix; election max not above min;
  non-integer and non-numeric values; out-of-range values; election minimum
  below three heartbeats; the aggressive opt-in (and `false`, and a
  non-boolean); the threshold for several heartbeats.
- Staging, manual, never on production: two nodes with `tc netem` loss and
  delay on the inter-node link (for example 1% to 5% loss, 200 ms bursts).
  Compare `Cluster lost quorum` lines per hour with the default and with the
  recommended values. Not run.

## Open questions

1. Which downstream timeouts must be longer than the new heartbeat (HSM
   gateway relay, scheduled exports, rustion pinger, HTTP clients)?
2. Per node or per cluster? Code accepts per node; operators should set the
   same values everywhere, and the status surface should make a mismatch
   visible.

## Tracking text

- `ROADMAP.md`: T479 is `[x]`, declared done by the operator on 2026-11-10
  with the status fields, the Puppet parameters and the staging run still open.
- `CHANGELOG.md`: an entry under `[Unreleased]` / Added, "Storage: Raft timing
  on a lossy link", already lands with this change.
