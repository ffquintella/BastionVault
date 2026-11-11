# Feature: Raft Connection Pool — reuse the peer stream instead of opening one per linearizable read

> Status: **in the product build since the `Cargo.lock` pin to fork commit `6bcb940`
> (2026-11-11), with an HA test that fails without it; hiqlite's cluster suite passes; not yet
> validated on a staging pair or a real cluster (T480, T481, S118)**. 0.46.0 shipped without it,
> see "What went wrong with 0.46.0". The pool and its unit tests are in
> `third_party/hiqlite/hiqlite/src/network/raft_client.rs`. Extends
> [Raft Timeout Tuning](raft-timeout-tuning.md) (S117), which it completes.
> Touches the Raft replication path (AGENTS.md §7: storage, high risk):
> `make test-release` before a release. No persisted format and no wire
> change: the peer sees the same streams it always did, fewer of them.

## Summary

With the S117 timeouts in place, a two-node cluster on a lossy inter-site link
still logged `Cluster lost quorum` about 50 times an hour. The cause is that
every linearizable read opens a brand-new TCP + TLS + WebSocket connection to
the peer. This feature keeps idle peer streams in a small pool and hands one
out instead.

## What blocks it today (evidence)

Measured on 2026-11-10 on the production pair, after S117 was deployed.

- The leader (node 1) still logged 14 to 28 `timeout while confirming
  leadership for read request … timeout after 2s when AppendEntries` an hour
  (down from about 66 an hour at the 500 ms default).
- A 10 s capture on the follower showed 40 new connections to the Raft port,
  4 a second, each lasting about 11 ms and closed by the leader with a FIN and
  no TLS `close_notify`. The follower logged the same number of
  `peer closed connection without sending TLS close_notify` errors. The
  sockets listed by `ss` never changed, because each one was gone before the
  next sample.
- With `hiqlite=debug` on the leader, the log showed one `Building new Raft DB
  client with target Node 2` and one `Trying to open WebSocket stream` per
  connection (237 in two minutes).
- In openraft 0.9, `raft_core.rs` calls `RaftNetworkFactory::new_client` for
  every linearizable read it confirms, sends one empty `AppendEntries` whose
  timeout is the heartbeat interval, and drops the client. hiqlite's
  `new_client` spawned a `ws_handler` and a WebSocket each time, and its
  `Drop` aborted them, which is the FIN without `close_notify`.
- A new connection has to survive a TCP handshake, a TLS handshake and the
  WebSocket upgrade inside that timeout. One lost SYN costs a 1 s retransmit,
  a second one 3 s in all, which beats the 2 s S117 allows. A stream that is
  already open recovers from a loss in about 200 ms.

## What went wrong with 0.46.0

The pool was in the fork and not in the product. The build resolves `hiqlite` from the fork's
`main-local` branch on GitHub (`[patch.crates-io]` in the root manifest), at the commit
`Cargo.lock` records; the `third_party/hiqlite` submodule is only a working copy. The lock
pinned `ca4cf81e`, which predates the pool, and the commit that moved the submodule pointer did
not touch it, so tags `v0.45.52` and `v0.46.0` contained the pool in the submodule and not in
the binary.

Measured on 2026-11-11 on the production pair, running 0.46.0:

- The `bvault` binary of the image has no `Reusing a pooled Raft stream` string; the same image
  runs on both nodes.
- With `hiqlite::network::raft_client=debug` on the leader, four minutes logged 949
  `Building new Raft DB client` and no `Reusing a pooled Raft stream`: about 500 a minute.
- A two-minute capture of TCP flags on the Raft port showed the leader opening about four
  connections a second and ending each with a FIN and an RST that it sent itself, so neither
  the network nor a middlebox was resetting them.
- The log level comes from `log_level` in the server config and overrides `RUST_LOG`.

Fix: the lock pins `6bcb940` (the pool, plus the one-line fix of the 0.16.0 merge, which did not
compile), and `bv-storage` requires `hiqlite =0.16.0`. Moving to 0.16.0 changes `rustls`,
`aws-lc-sys` and `rusqlite`, so the post-quantum and TLS suites were run on it (ML-KEM, ML-DSA,
composite PKI, SSH, FerroGate, Rustion, mTLS) and `bv-utils` asserts that TLS still offers
`X25519MLKEM768` first. A rolling upgrade of a 0.15.3 pair and 0.16.0 on an existing 0.15.3 data
directory are not exercised yet.

## Non-goals

- Fixing the network, or the two-node cluster's lack of fault tolerance
  (S117's non-goals still hold).
- Multiplexing concurrent requests on one stream. The peer handles the
  requests of a stream in order, so a long `AppendEntries` or snapshot would
  delay a read behind it. A stream is therefore used by one client at a time.
- Changing what a read guarantees. A read still waits for the peer's answer
  to its own `AppendEntries`.

## Design (as built)

`NetworkStreaming` (the openraft network factory) holds a `ConnPool`: idle
`PooledConn`s keyed by peer node id.

- `new_client` takes the most recently used idle connection to the peer, and
  opens a new one only when there is none. A connection in use is never shared.
- When a client is dropped its connection goes back to the pool, unless a
  request on it failed, or a request is still unanswered (openraft drops the
  call when its timeout fires, and the peer would answer a request nobody
  waits for). Those connections are shut down, as before.
- When the peer answers a request with a fatal Raft error (its instance is
  stopped), the stream is not pooled and its task is told to reconnect. A
  stream can outlive the instance it was opened to: the node restarts, a new
  instance listens on the same address, and the old stream keeps answering
  `Stopped` because the server only closes it for a stopped `append_entries`.
  Without this rule hiqlite's cluster suite hung in `test_self_healing` (the
  leader resent a snapshot over such a stream 531 times); it passes with it.
- At most 4 idle connections per peer. One idle for more than 60 s, one whose
  task ended and one to a peer whose address changed are not reused, and are
  shut down when met.
- Replication streams are long-lived and keep their connection until dropped,
  then return it like any other client.
- Dropping a `PooledConn` sends `Shutdown` and aborts its task, so a
  connection that is evicted or never returned cannot leak a socket.

## Security and risk

- No new surface: the same authenticated stream, the same shared secret, the
  same TLS settings. A pooled stream was authenticated when it was opened.
- Liveness behaviour on the replication path. A pooled stream that the network
  silently killed is detected by the owning task on its next use and rebuilt
  by the existing reconnect loop, so one request may fail where a fresh
  connection would have succeeded. That is the failure the pool is meant to make
  rarer, not a new one, but it is not measured yet.
- An idle connection to a down peer keeps its reconnect loop running (the
  existing 250 ms to 3 x heartbeat cadence), for up to 4 connections and 60 s
  after the last use.

## Phases

| Phase | Work | Status |
|---|---|---|
| 0 | Locate who opens the connections | done: openraft `raft_core.rs` `new_client` per read |
| 1 | Pool in the hiqlite fork, with unit tests | done, 13 tests |
| 2 | hiqlite cluster suite with the pool | done: passes (it hung before the fatal-answer rule, see Design) |
| 3 | `bv-storage` consumes the fork; `make test-hiqlite` | done: 9 storage tests and 8 HA fault-injection tests pass |
| 3b | The product build contains the pool | done 2026-11-11: lock pinned to `6bcb940`, `hiqlite =0.16.0`; `test_raft_peer_streams_are_pooled` (T481) passes with the pool and fails with it disabled |
| 4 | Staging pair with induced loss; then production, one node at a time | planned: confirm on the production leader that `Building new Raft DB client` is mostly followed by `Reusing a pooled Raft stream` |

## Test plan

- Unit, in the fork: `cargo test -p hiqlite --lib raft_client`. Empty pool;
  return then reuse; a moved peer, an expired and an ended connection are not
  reused; per-peer isolation; the idle cap; an unanswered or failed client does
  not return its connection and its task is shut down; `checkout` prefers an
  idle connection and never shares one in use.
- hiqlite's own cluster tests (`just test-no-s3` equivalent): run as
  `cargo test --features cache,counters,dlock,listen_notify,macros,toml,external-state-machine --test cluster`
  with `TEST_SKIP_S3_RESTORE=true`. The original fork passes, and so does the
  pool with the fatal-answer rule.
- In this repository: `CARGO_TEST_HIQLITE=1 cargo test --test hiqlite_ha_fault_injection
  test_raft_peer_streams_are_pooled` (also part of `make test-hiqlite`) counts the Raft client's
  `Building new Raft DB client` events (one per client, pooled or not) and its `Reusing a pooled
  Raft stream` events over 100 linearizable reads, and requires a hit rate of at least 80%. It
  scored 200 of 200 with the pool and 0 of 200 with `POOL_MAX_IDLE_PER_PEER = 0`. It matches the
  debug message text, so a hiqlite that renames the messages fails it with a message that says
  so. `cargo nextest run -p bv-utils --lib default_provider_prefers` guards the post-quantum TLS
  group.
- Staging, manual, never on production: two nodes with `tc netem` loss on the
  Raft port. Compare `Cluster lost quorum` and the new-connection rate (`ss`,
  `nstat TcpActiveOpens`) before and after. Not run.

## Open questions

1. Is 4 idle connections and 60 s the right size for the read rate of a busy
   cluster (about 4 reads a second here)?
2. Should an idle pooled connection stop reconnecting by itself while its peer
   is down, instead of waiting for its idle timeout?
