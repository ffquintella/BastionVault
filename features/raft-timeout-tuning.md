# Feature: Raft Timeout Tuning — operator-set timeouts for a two-node cluster on a lossy inter-site link

> Status: **draft, planned (T479, S117)**. Written 2026-11-10 against
> `4bafa84b`. Nothing is implemented. Extends the hiqlite storage backend
> (`crates/bv-storage/src/hiqlite/`) and relates to
> [HSM Pool HA](hsm-pool-ha.md) (S114), whose T474 / T475 retries it does not
> replace. Touches liveness behaviour of the storage layer on high-risk
> ground (AGENTS.md §7: storage): review this spec before any code, and run
> `make test-release` before merge. No persisted format changes.

## Summary

A production two-node hiqlite cluster, one node per site, loses quorum many
times an hour. The nodes, the clocks and the NIC counters are healthy, and the
round-trip time is about 1 ms. The inter-site path loses a small share of
packets in bursts, and the Raft read-index timeout (500 ms, set inside hiqlite)
is shorter than what one or two TCP retransmissions cost. Operators cannot
change that timeout today.

This feature makes the Raft timeouts operator-configurable, with unchanged
defaults, and ties the "isolated leader" health threshold to the configured
value. It is a **mitigation**. It does not fix the network and does not remove
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
  at least 600 ms. That is already past the 500 ms read-index timeout, so one
  short burst fails a linearizable read.
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

## Proposal

### Configuration

New optional keys in the `storage "hiqlite"` block. **Names are provisional**
and the set depends on what the hiqlite fork can accept (see
[Open questions](#open-questions)). Every key is optional, and an absent key
keeps today's behaviour exactly.

| Key | Default | Meaning |
|---|---|---|
| `raft_read_index_timeout_ms` | `500` | How long a linearizable read waits to confirm leadership with a quorum |
| `raft_heartbeat_interval_ms` | hiqlite default | Leader heartbeat period |
| `raft_election_timeout_min_ms` / `_max_ms` | hiqlite default | Follower election timeout window |

Rules, all enforced at startup with a clear error and no clamping:

- Every value is a positive integer in a bounded range (the bounds are set in
  phase 1, once the fork's limits are known). A value outside the range or of
  the wrong type is an error, not a silent default.
- `election_timeout_min` must exceed `heartbeat_interval` by a fixed factor, so
  an operator cannot configure a cluster that elects a new leader on every
  quiet heartbeat.
- `raft_read_index_timeout_ms` below the default is refused unless an explicit
  `raft_allow_aggressive_timeouts = true` is set. A shorter timeout makes the
  problem in this spec worse, so it must be a deliberate choice.
- When any of these keys is set, the server logs one line at startup with the
  effective values. Nothing secret is logged.

### Isolated-leader health threshold

`QUORUM_ACK_STALE_MS` (3,000 ms, `crates/bv-storage/src/hiqlite/mod.rs:50`) is
documented as "several heartbeat intervals of slack" over the 500 ms read-index
timeout. It must follow the configured value, so a leader waiting longer for
confirmation is not reported unhealthy by `cluster-status` while it is merely
waiting. Proposal: `max(3000, 6 x raft_read_index_timeout_ms)`. A single-node
leader keeps self-acknowledging and stays healthy, as today.

### Status surface

The effective timeout values appear in the existing cluster-status output, so
an operator can see what a running node uses without reading its config file.
No new route. Per AGENTS.md §7 any new API field goes under `v2/`; this adds
fields to a response that already exists there, and `docs/api.md` gets the
update.

### Recommended starting value

For the measured link, one burst of two losses costs at least 600 ms before
TCP retransmits. A read-index timeout of **2,000 ms** covers that with room
for the RTT and for a second burst. This is a proposal to confirm on staging
with induced loss, not a measured optimum. The trade-off is slower detection
of a partitioned leader and slower failover, both bounded by the same values.

## Security and risk

- Liveness only. Timeouts do not affect Raft safety, key custody, the seal, or
  the barrier. No new secret, no new network surface, no new dependency.
- A longer read-index timeout lets an isolated leader serve fewer reads
  quickly during a real partition. Requests wait longer before failing with
  `Cluster lost quorum` instead of failing fast. Callers with their own
  timeouts (HTTP clients, the HSM gateway relay) must be longer than the new
  value, or they fail first. The spec work must list each such timeout.
- The change is in a storage backend and in a fork of a third-party
  dependency, which is the main review cost. Keep the fork patch minimal and
  documented.
- Compatibility: absent keys behave as today. Old configs load unchanged.
  There is no persisted-format change and nothing to migrate.

## Phases

| Phase | Work | Status |
|---|---|---|
| 0 | Read the hiqlite fork (through its own workflow, since `third_party/` is outside the normal tree) and record which timeouts it already exposes and where the 500 ms read-index value is set | planned |
| 1 | Fork patch only if a knob is missing: make the value configurable, default unchanged | planned |
| 2 | `bv-storage`: parse and validate the keys, pass them to the node config, derive the stale-ack threshold, log the effective values | planned |
| 3 | Cluster-status fields, `docs/configuration.md`, `docs/api.md` | planned |
| 4 | Deployment parameters in the Puppet module for the new keys | planned |
| 5 | Validation on a staging pair with induced loss, then one production rollout, one node at a time | planned |

## Test plan

- Unit, in `bv-storage` (`cargo nextest run -p bv-storage --lib`): absent keys
  produce today's node config; each key parses, rejects zero, negative,
  non-integer and out-of-range values, and rejects the heartbeat / election
  inconsistency; the aggressive-timeout guard; the derived stale-ack threshold
  for several inputs, including the default.
- Regression: a config with none of the new keys yields a node config
  identical to the current one, so existing deployments cannot change
  behaviour by upgrading.
- Staging, manual, never on production: two nodes with `tc netem` loss and
  delay on the inter-node link (for example 1% to 5% loss, 200 ms bursts).
  Compare the count of `Cluster lost quorum` lines per hour with the default
  and with the recommended value.

## Open questions

1. Does the hiqlite fork already expose a read-index timeout and the Raft
   timing parameters, or does phase 1 need a patch? The 500 ms value is
   described in this repo's comments but is not set in `bv-storage`.
2. What are the safe bounds for each key, given the fork's own validation?
3. Which downstream timeouts must be longer than the new read-index timeout
   (HSM gateway relay, scheduled exports, rustion pinger, HTTP clients)?
4. Should `raft_read_index_timeout_ms` be per cluster or per node? Nodes with
   different values behave differently during a partition, so the proposal is
   that operators set the same value everywhere and the status output makes a
   mismatch visible.

## Tracking text (to land with the implementation, not before)

- `ROADMAP.md`: T479 moves to `[x]` when phases 0 to 3 are done and checked on
  staging.
- `CHANGELOG.md`: an entry under `[Unreleased]` / Added, grouped under a
  `Storage` sub-heading, ending in `(T479, S117, S114)`.
