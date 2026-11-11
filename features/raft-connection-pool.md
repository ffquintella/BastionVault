# Feature: Raft Connection Pool — reuse the peer stream instead of opening one per linearizable read

> Status: **implemented in the hiqlite fork; unit tests and hiqlite's cluster suite pass,
> not yet validated on a staging pair or a real cluster (T480, S118)**. The pool and its unit tests are in
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
| 3 | `bv-storage` consumes the fork; `make test-hiqlite` | done: 9 storage tests and 8 HA fault-injection tests pass; the fork change is not committed and the submodule pointer is not moved yet |
| 4 | Staging pair with induced loss; then production, one node at a time | planned |

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
- Staging, manual, never on production: two nodes with `tc netem` loss on the
  Raft port. Compare `Cluster lost quorum` and the new-connection rate (`ss`,
  `nstat TcpActiveOpens`) before and after. Not run.

## Open questions

1. Is 4 idle connections and 60 s the right size for the read rate of a busy
   cluster (about 4 reads a second here)?
2. Should an idle pooled connection stop reconnecting by itself while its peer
   is down, instead of waiting for its idle timeout?
