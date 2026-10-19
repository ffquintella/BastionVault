# Feature: HSM Pool HA — an N-node cluster served by two YubiHSM 2 devices

> Status: **planned** (T454). Spec written 2026-10-19. Extends
> [HSM Support (YubiHSM 2)](hsm-support.md) (S17), whose non-negotiable security
> rules apply here unchanged unless a section below says otherwise and why.

## Summary

Today's HSM design ([hsm-support.md](hsm-support.md)) mandates **one YubiHSM 2 per
cluster node**. Every node wraps its own copy of the barrier KEK under its own
device, and nodes replicate secrets HSM-to-HSM.

This feature adds a second topology, the **HSM pool**:

- A BastionVault cluster of any size N (≥ 1, practically 3–12 nodes) depends on
  exactly **two** YubiHSM 2 devices.
- Any node can unseal and perform HSM-gated operations as long as **at least one**
  of the two devices is reachable.
- Nodes without a local device reach the pool over the network. They go through an
  mTLS **HSM gateway**, and each node keeps its own end-to-end-encrypted,
  device-authenticated session with each HSM.

Key material is kept on both devices by **dual-wrap**:

- Each HSM holds its own non-exportable wrap keys.
- Every protected secret (the barrier KEK and each post-quantum seed) is stored as a
  **blob set** with one copy per HSM.
- If one HSM is down when a secret is created, the secret is stored with one copy,
  flagged *under-replicated*, and repaired automatically when the device returns.
- An optional, init-time-only **recovery copy** is sealed to an ML-KEM-768 recovery
  key whose private half is Shamir-split among operators. The cluster survives
  losing both devices.

The existing per-node topology keeps working unchanged. The two topologies are
mutually exclusive per cluster.

## Decisions

| Decision | Choice | Made by |
|---|---|---|
| Number of devices | Exactly two online devices for any cluster size | User |
| Key sharing between the two devices | **Dual-wrap**: independent non-exportable wrap keys, one blob per device. Cloned wrap key (FW 2.4 RSA-OAEP export) rejected, see [Rejected alternatives](#rejected-alternatives) | User |
| Recovery if both devices are lost | **Shamir ceremony** (existing opt-in `recovery = "shamir-ceremony"`), defined concretely here as an ML-KEM-768 recovery copy | User |
| Key creation with one device down | **Allowed**. One copy, flagged under-replicated, alerted, repaired later (`min_wrap_copies = 1` default; `2` available) | User |
| Network access path | mTLS gateway in front of a localhost-only `yubihsm-connector`; node-side loopback relay | Claude (see [HSM link](#hsm-link-gateway-and-relay)) |
| Node → HSM authentication | Per-node, per-device **random** symmetric auth keys (not password-derived), delivered sealed to a node transport key; asymmetric auth later | Claude |
| Where ceremonies execute | In the leader, with the device admin credential supplied per request and never stored | Claude |
| Device audit log | Drained into the BastionVault audit log by default; *forced audit* opt-in only | Claude |
| Custody storage | Central barrier-protected custody store; engines hold handles, not blobs | Claude |
| Recovery copy construction | Existing `bv_crypto::KemDemEnvelopeV1` with ML-KEM-768 | Claude |
| Bootstrap | `init` takes the admin credentials once, enrolls the init node, and wraps the KEK through that node's sessions | Claude |
| Membership authority | Seal record in storage; config `member` blocks only bootstrap | Claude |
| Set-write atomicity | One `hsm-custody` cluster lock; pool topology requires hiqlite (or single-node file for dev) | Claude |

## Motivation

- **Cost and logistics.** One YubiHSM 2 per node is wasteful once a cluster grows
  past three nodes. Nodes in cloud or VM environments often cannot have a USB
  device attached at all.
- **The per-node model cannot cover HSM-less nodes.** `HsmSealRecord.kek_blobs` is
  keyed by node id, and `recover_kek` refuses any node without its own entry
  (`crates/bv-core/src/seal/hsm.rs`). The blob AAD binds the creating node's id
  (`crates/bv-core/src/hsm/blob.rs`, `BlobAad.node_id`). So a blob made by one
  node cannot be opened by another, even through the same device.
- **The per-node replication handshake was never shipped over the network.** T17's
  remaining work is exactly that HSM-to-HSM channel. In the pool topology every
  node talks to both devices directly, so the channel is unnecessary: replication is
  just "unwrap through A, wrap through B" inside one process.

## Goals

1. Any number of nodes, up to the supported maximum of 12 (see
   [Session budget](#session-and-throughput-budget)), depends on two devices.
2. Losing either device, its host, or its gateway causes **no outage**: every node
   still unseals, reads, writes, and creates keys.
3. Losing both devices keeps already-unsealed nodes serving barrier-protected data
   (fail-closed for new unseals and new HSM-gated operations). With recovery
   configured, the cluster can be rebuilt onto two new devices.
4. No wrap key can be exported from a device in any supported configuration.
5. Every key release stays an HSM-signed, replay-resistant, attributable audit
   event (existing signed unwrap authorization).
6. Replacing a failed device is an operator procedure with no downtime and no
   plaintext key material on disk or on the wire.
7. Per-node revocation is enforced by the devices themselves: deleting a node's
   auth key on both HSMs.

## Non-goals

- Network HSMs other than YubiHSM 2 (PKCS#11 / Luna / CloudHSM). The pool
  abstraction leaves room for them; none is implemented.
- More than two online devices in a pool. The format keys copies by HSM id, so it
  could hold more, but tooling, validation and tests target exactly two.
- Wiring HSM custody into the PKI, transit and SSH engines. No engine uses HSM
  custody today; this spec defines the custody-store API they will call, and
  adoption is separate work.
- Mixed topologies (some nodes per-node, others pool) inside one cluster.
- Load-balancing HSM traffic for throughput beyond two devices.

## Anti-goals (failure even if it works)

- **Any path that lets a wrap key or a stored seed leave a device in plaintext.** That
  includes Yubico's backup ceremony, which holds the wrap key in plaintext on a host.
- **A silent single-copy state.** An under-replicated secret that no metric, status
  field or audit event reports is a defect.
- **A silent downgrade.** A node that cannot reach either device must stay sealed
  and say why. It must never fall back to the recovery key, a cached KEK, or a
  software path.
- **The gateway becoming a trusted component.** It must remain safe for the gateway
  host to be compromised (DoS only, never disclosure).
- **A credential that, once stolen from one node, cannot be revoked** without
  re-keying the whole cluster.

---

## Device facts this design relies on

Verified against Yubico documentation on 2026-10-19; re-check on firmware changes.

| Fact | Consequence here | Source |
|---|---|---|
| 16 concurrent sessions per device; a session expires after 30 s idle; at the limit the device returns `SESSIONS_FULL` (0x05) | Hard cap on nodes per pool; sessions must be closed on shutdown | [Core concepts](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-intro-core-concepts.html) |
| Sessions are SCP03-style: end-to-end encrypted and MAC'd between client and device; Yubico states the connector "is not a trusted component" | The gateway and the network can drop or delay traffic but cannot read or forge commands | [Connector guide](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-tools-connector.html) |
| The device executes one command at a time across all sessions; the connector serializes with a global mutex | Throughput per device is the inverse of the sum of latencies | Core concepts; `yubihsm-connector` `usb_libusb.go` |
| `yubihsm-connector` 3.0.x: HTTP, optional server-side TLS (`--cert/--key`), **no client authentication**, one device per process (`--serial`) | Never expose the connector itself; front it with an mTLS gateway | [yubihsm-connector](https://github.com/Yubico/yubihsm-connector) |
| 256 objects, 126 KB, 16 domains; capabilities are immutable after creation; auth keys carry *delegated capabilities* | Fits ~12 node auth keys plus a dozen service objects comfortably | Core concepts |
| `wrap-data` / `unwrap-data`: AES-CCM, device-generated 13-byte nonce, 16-byte MAC, message buffer 3136 bytes | Seeds (32–64 B) and the KEK fit in one command | [Command reference](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html) |
| Attestation certificates exist only for asymmetric keys generated in-device, and chain to the Yubico attestation intermediate and root; extension `1.3.6.1.4.1.41482.4.2` carries the device serial, `.5` the capabilities | AES wrap keys **cannot** be attested. Their capabilities are checked by an authenticated `get-object-info` in a session bound to an attested key | [YubiHSM OIDs](https://docs.yubico.com/hardware/oid/oid-product-arc.html) |
| Device audit log: 62 entries, circular by default, SHA-256-chained digests; "forced audit" makes loggable commands fail with `LOG_FULL` until acknowledged (`set-log-index`) | Drain continuously; forced audit is an availability risk, so opt-in | Core concepts, Command reference |
| Datasheet latencies on an idle device: ECDSA-P256 ~73 ms, Ed25519 (32 B) ~105 ms, AES-CCM wrap ~10 ms | About 6–8 authorized unwraps per second per device; see budget | [Data sheet](https://docs.yubico.com/hardware/yubihsm-2/datasheet/_static/YubiHSM_2_Technical_Data_Sheet.pdf) |
| Asymmetric (EC P-256) session authentication exists from FW 2.3.1 | A future replacement for symmetric node credentials | Command reference |
| `yubihsm` crate 0.42.1: HTTP (plain TCP, no TLS), USB, MockHsm connectors; the connector trait is `pub(crate)`; no asymmetric session auth; one session per `Client`, re-opened lazily | The node needs a loopback relay to reach an mTLS gateway (see [HSM link](#hsm-link-gateway-and-relay)) | [yubihsm.rs](https://github.com/iqlusioninc/yubihsm.rs) |

---

## Topology

```
                         ┌───────────── BastionVault cluster (Raft / hiqlite) ─────────────┐
                         │  vault-1      vault-2      vault-3      …      vault-N (≤ 12)    │
                         │  relay        relay        relay               relay             │
                         └────┬─┬─────────┬─┬──────────┬─┬───────────────────┬─┬───────────┘
                    mTLS      │ │         │ │          │ │                   │ │
              ┌───────────────┘ └─────────┼─┼──────────┼─┼─────────┐ ...     │ │
              ▼                           ▼ ▼          ▼ ▼         ▼         ▼ ▼
   ┌──────────────────────────┐                     ┌──────────────────────────┐
   │ HSM host A               │                     │ HSM host B               │
   │  bvault hsm-gateway :8250│                     │  bvault hsm-gateway :8250│
   │        │ 127.0.0.1       │                     │        │ 127.0.0.1       │
   │  yubihsm-connector :12345│                     │  yubihsm-connector :12345│
   │        │ USB             │                     │        │ USB             │
   │   [ YubiHSM 2  #A ]      │                     │   [ YubiHSM 2  #B ]      │
   └──────────────────────────┘                     └──────────────────────────┘
          failure domain 1                                failure domain 2
```

- Each node keeps **one session per device**, opened lazily and re-opened on
  expiry, inside a SCP03 channel that runs end to end through relay, gateway and
  connector.
- An HSM host may be a dedicated machine or one of the vault nodes. A vault node
  that hosts a device may skip the gateway and talk to its local connector directly
  (`connector = …` on that member). It still uses the same pool logic and still
  serves the gateway to the other nodes.
- The two devices must sit in different failure domains (host, power, rack, and
  ideally site). The Raft quorum is independent of HSM placement: three Raft
  nodes and two HSM hosts is the minimal production layout.

## HSM object layout (each pool device)

Every object is in domain 1 unless noted. Object ids are defaults and can be
overridden in config.

| Id | Label | Type | Capabilities | Purpose |
|---|---|---|---|---|
| 1 | *(factory default auth key)* | auth | — | **Deleted** by `provision`. A device still holding key 1 is refused. |
| 2 | `bv-admin` | auth key (password-derived), **domains 1 and 2** | `generate-asymmetric-key`, `generate-wrap-key`, `put-authentication-key`, `delete-authentication-key`, `delete-asymmetric-key`, `delete-wrap-key`, `get-object-info`, `sign-attestation-certificate`, `sign-ecdsa`; delegated = exactly the union of the capabilities of the objects in this table (so it can never mint an exportable object) | Ceremonies only. Credential held by operators, never stored by BastionVault. |
| 3 | `bv-wrap-barrier` | AES-256-CCM wrap key | `wrap-data`, `unwrap-data`; **no** `exportable-under-wrap`, no `export-wrapped`; delegated = none | Wraps the barrier KEK. |
| 4 | `bv-wrap-pqc` | AES-256-CCM wrap key | same as above | Wraps PQC seeds (separate from the barrier key, rule 5). |
| 5 | `bv-identity` | EC P-256, **domain 2** | `sign-ecdsa` | Device identity: signs pool-membership and re-wrap transcripts. Attested. Not usable by node keys (domain 2). |
| 6 | `bv-seed-ecdh` | EC P-256 | `derive-ecdh` | Hardware contribution to PQC seed derivation (spec S17 Capability 2, step 3). Attested. |
| 7 | `bv-authz` | Ed25519 | `sign-eddsa` | Signs every unwrap authorization. Attested. |
| 8 | `bv-auditor` | auth key (random) | `get-log-entries`; domain 1 | Device-log drain. |
| 0x100 + n | `bv-node-<node_id>` | auth key (random AES pair) | `wrap-data`, `unwrap-data`, `sign-eddsa`, `derive-ecdh`, `get-pseudo-random`, `get-object-info`; delegated = none; domain 1 only | One per enrolled node. |

Why this layout differs from S17's per-node table:

- **`bv-identity` moves to domain 2.** Capabilities attach to objects, not to
  (auth key, object) pairs: any auth key with `sign-ecdsa` in a shared domain can
  use any ECDSA key in it. In S17 that was harmless (one node per device). Here,
  any of N nodes could forge device-signed transcripts. Splitting the ECDH duty
  into `bv-seed-ecdh` (domain 1) and keeping signing in domain 2 (admin-only)
  restores separation of purpose (rule 5).
- **There is one `bv-authz` per device, not per node.** Per-node signing keys would
  need per-node domains, and there are only 16. Attribution comes from the signed
  `node_id` in the authorization request **and** from the device audit log, which
  records which auth key ran every command.
- **Node keys cannot create, delete or export objects.** A compromised node can
  misuse its own session (see [Security considerations](#security-considerations))
  but cannot mint credentials, extract keys or tamper with the layout.

## HSM link: gateway and relay

### Gateway (`bvault hsm-gateway`)

A small standalone process on each HSM host. It runs from the `bvault` binary but
is not a vault: it has no storage and no tokens.

- It listens with **mTLS** (rustls, already in the tree). The client certificate
  must chain to `client_ca_file`, and its SAN must match `allowed_clients`
  (node ids).
- It forwards `POST /connector/api` and `GET /connector/status` bodies **verbatim**
  to the localhost connector. It does not parse commands; the protocol is
  end-to-end encrypted anyway.
- Limits:
  - Request body 3–3139 bytes (the connector's own bound).
  - One in-flight request per client certificate.
  - A per-client request rate limit.
  - A 5 s upstream timeout.
- Logs: connection open and close, client identity, request count and errors.
  Never payloads.
- The connector stays bound to `127.0.0.1` and is never exposed.

### Relay (in the vault node)

`yubihsm` 0.42 only speaks plain HTTP over TCP and has no pluggable transport.
Each node therefore runs, per pool member, an **in-process loopback relay**:

- It binds `127.0.0.1:<ephemeral>` and accepts only connections from the same
  process, which is the `yubihsm::Client` it created.
- It forwards each request over a pooled mTLS connection to the member's gateway.

This needs no fork of the crate. An upstream patch to `yubihsm.rs` adding HTTPS or a
public connector trait removes the loopback hop without any change visible outside
the link crate; it is tracked as a follow-up.

The relay accepts one client connection at a time. Other local processes can at
most consume that member's session slot until idle expiry, which is DoS and never
disclosure: they would still need the node's HSM credential.

Both halves live in a new Tier 0 crate, **`bv-hsm-link`**. It depends on
`bv-errors`, `rustls` and `tokio`, and on nothing else in the workspace.
`bv-core` uses the relay; `bvault-cli` uses the gateway.

## Session and throughput budget

| Consumer | Sessions per device |
|---|---|
| Each vault node | 1 (the `yubihsm::Client` serializes; no pooling inside a node) |
| Device-log drain (leader) | 1 (`bv-auditor`) |
| Ceremonies (`bv-admin`) | 1, transient |
| Headroom for sessions orphaned by crashed nodes (30 s expiry) | 2 |
| **Maximum vault nodes per pool** | **12** |

- Enrollment refuses node 13 with an explicit error.
- On graceful shutdown or seal, nodes send `CloseSession`.
- On `SESSIONS_FULL`, a node backs off with jitter (100 ms → 5 s), tries the other
  member, and reports the condition in metrics.

Throughput, from datasheet latencies:

- One authorized unwrap (Ed25519 authz signature plus AES-CCM unwrap plus two round
  trips) costs about 120–160 ms of device time, so roughly 6–8 per second per
  device, or 12–16 per second for the pool.
- Creating a key costs one random, one ECDH and two wraps, about 50–100 ms per
  device.
- A full cold start of 12 nodes needs 12 unwraps, about 2 s.
- PQC private-key operations on hot paths depend on the existing bounded session
  cache (`pqc_key_cache_ttl`, default 60 s). The capacity limit is documented in
  `docs/hsm.md`, and the metric `bv_hsm_command_duration_seconds` makes saturation
  visible.

The builder should measure the authz signature over the real request size on
hardware. If it dominates, signing a SHA-256 digest of the request instead is an
allowed authz **v2** change: a new context string, and v1 is still verified for
old audit records.

---

## Key custody: dual-wrap

### Blob format v2 (`BvHsmBlob`)

v1's AAD binds `node_id`. v2 replaces it with **`hsm_id`** (`yubihsm2:<serial>` or
`mock:<id>`), so any node can open a copy made by any other node through the same
device:

```
BlobAad v2 = context ‖ purpose ‖ epoch ‖ hsm_id ‖ authz_alg ‖ authz_fingerprint(of that device)
```

`authz_alg` ∈ {`ed25519`, `ecdsa-p256`} is chosen per member at `provision` and
recorded in the member entry. Ed25519 is the default. Carrying the algorithm in v2
means the FIPS question in [Security considerations](#security-considerations) can be
answered in Phase 7 without another format change.

- v1 blobs remain readable (per-node topology, and seal records not yet migrated).
- New blobs are always v2.
- `open_blob` rejects a v2 blob whose `hsm_id` is not the device being asked to
  open it, before calling the device.

### Blob set (`BvHsmBlobSet v1`)

```rust
struct BvHsmBlobSet {
    version: u8,                                   // 1
    purpose: Purpose,                              // BarrierKek | PqcSeed{alg}
    epoch: u64,
    copies: BTreeMap<HsmId, BvHsmBlob>,            // one per pool member that holds it
    recovery: Option<KemDemEnvelopeV1>,            // present iff recovery = shamir-ceremony
    created_at: u64,
    created_by: NodeId,
}
```

A set is **fully replicated** when it holds a copy for every *active* pool member,
and **under-replicated** otherwise. The recovery copy does not count towards
replication.

### Barrier KEK

The seal record (format v2 below) holds `kek: BvHsmBlobSet`.

**Bootstrap at `init`.** Init is the one ceremony that runs before any node holds a
credential, so in pool mode it takes the admin credential for both members (TTY or
`env:`, same rules as other ceremonies). The init node must already have written its
pending transport key (see [Node enrollment](#node-enrollment-and-revocation)).

1. Verify both attestation bundles and both device layouts.
2. Enroll **the init node itself**. Create `bv-node-<init node>` on each member with
   the admin session, and hand the credential to the local process directly. It never
   touches storage.
3. Close the admin sessions and zeroize the admin credentials.
4. Generate the KEK (unchanged).
5. Wrap it under `bv-wrap-barrier` on **each** member, through the init node's own
   `bv-node` sessions. `bv-admin` never gets `wrap-data`.
6. Add the recovery copy if configured, and zeroize the KEK.
7. Write the seal record and the init node's enrollment record.

All other nodes enroll afterwards through `node add`, which needs an unsealed cluster
and a sudo token.

`init` in pool mode requires **both** members to be reachable. Starting a cluster with
one copy is refused, and the error names the unreachable member. It also requires an
explicit `recovery` value (`none` or `shamir-ceremony`) in the config. Pool init never
falls back to a default recovery posture.

### PQC seeds and the custody store

Seeds are created exactly as in S17 Capability 2. The only differences are which
device contributes and where the result is stored:

1. `e_host = OsRng(64)`.
2. `e_hsm = get_random(32)` from the node's preferred reachable member.
3. `s_ecdh = derive_ecdh(bv-seed-ecdh, cluster_binding_pub)` on that same member.
4. `seed = HKDF-SHA-512(…)`, with unchanged context strings.
5. Derive the keypair and publish the public key.
6. Wrap the seed under `bv-wrap-pqc` on **every** reachable member, add the
   recovery copy, and zeroize every intermediate.

The device's ECDH contribution is consumed once, at derivation. Later use never
needs that particular device, because the stored object is the seed itself.

Blob sets for seeds live in a **central, barrier-protected custody store**, at
`core/hsm/custody/<key_id>` in the barrier view. Engines receive an opaque
**handle** (`BvHsmHandle { version: 1, key_id }`) as the "secret key" at the
provider boundary, never a blob. Centralizing is what lets the repair job, device
replacement and recovery find every protected secret without knowing each engine's
storage layout. No engine stores HSM blobs today, so no engine data migrates.

Custody API in `crates/bv-core/src/hsm/custody_store.rs`:

```rust
async fn create(&self, purpose: Purpose, alg: PqcAlg) -> Result<(BvHsmHandle, PublicKey), RvError>;
async fn with_private<R>(&self, h: &BvHsmHandle, f: impl FnOnce(&PqcKeypair) -> R) -> Result<R, RvError>;
async fn delete(&self, h: &BvHsmHandle) -> Result<(), RvError>;
async fn replication_report(&self) -> Result<ReplicationReport, RvError>;
```

`with_private` goes through the existing session cache: unwrap, then use, then
zeroize.

**Write atomicity.** `bv-storage` has no compare-and-swap; it has
`list`/`get`/`put`/`delete`/`lock`. So **every** writer of a blob set or of the seal
record's membership takes one cluster lock, `hsm-custody`, for the read-modify-write.
That covers custody create and delete, repair, member add and retire, revoke, epoch
rotation and recovery. Writes are rare (key creation, repair at ≤ `repair_rate`), so
one lock costs nothing measurable.

Because the default `Storage::lock()` is a no-op, pool topology is accepted only on a
storage backend with a real cluster lock: hiqlite. It is also accepted on a
single-node `file` backend, for dev and homolog only. Any other combination is a
startup error naming the backend.

### Member selection and failover

- **Preference.** Each node orders the active members by
  `SHA-256(node_id ‖ hsm_id)`, so roughly half the nodes prefer A and half prefer
  B. `prefer = true` on a member overrides the order.
- **Reads (unwrap).** Try the preferred member that holds a copy; on a transport,
  session or device error, try the next one. A *cryptographic* failure is never
  retried on another member as if it were an outage: AAD mismatch, authz
  verification failure, or unwrap MAC failure. It is raised as a security event,
  because it means tampering or misrouting, not unavailability.
- **Writes (wrap).** Wrap on every active member, in parallel. The write succeeds
  if at least `min_wrap_copies` copies were produced; otherwise it fails with
  `ErrHsmInsufficientCopies { have, need, unreachable }`. A set stored with fewer
  copies than active members is under-replicated.
- **Health.** Each member is probed every 10 s with the unauthenticated
  `device-info` command through the link. This checks the serial and holds no
  session slot.
- **Circuit breaker.** A member is marked `down` after 3 consecutive transport or
  session failures. It is retried with exponential backoff (1 s → 60 s), and while
  it is down, operations do not wait for it.

### Unseal flow (pool topology)

1. Read the seal record v2 from physical storage. This needs the Raft quorum,
   unchanged.
2. Order the members by preference and skip any that are `down`.
3. For the first member that holds a KEK copy:
   1. Open a session with this node's credential for that member.
   2. Verify the device serial against the record.
   3. Obtain a signed unwrap authorization: `bv-authz` on that device, using the
      per-node counter described below.
   4. `unwrap_data`.
   5. Verify the authorization against the fingerprint in the blob.
4. `barrier.unseal(kek)`, then zeroize the KEK.
5. If every member fails, stay sealed, return `ErrHsmUnavailable` listing each
   member and its error, and log at `error`. Never consult the recovery copy here.

**Per-node authz counters.** The single `core/hsm-authz-counter` key is replaced by
`core/hsm-authz-counter/<node_id>`, so concurrent unseals on many nodes cannot race
on one read-increment-write. On first use, a node's counter starts above the value
of the legacy global key.

## Degraded operation and repair

| State | Unseal | Key use | Key creation | Signal |
|---|---|---|---|---|
| Both members up | ✓ | ✓ | ✓, 2 copies | — |
| One member down | ✓ via the other | ✓ via the other | ✓, 1 copy, set under-replicated (`min_wrap_copies = 1`) or refused (`= 2`) | `bv_hsm_member_up{member}=0`, `bv_hsm_under_replicated_sets`, audit `hsm.member_down` |
| Both members down | ✗ new unseals | already-unsealed nodes: barrier data ✓; PQC private ops only from cache until TTL, then `ErrHsmUnavailable` | ✗ | as above, plus `error` log on every refused operation |

**Repair job.** It runs on the Raft leader only, guarded by the existing hiqlite
cluster lock (`hsm-repair`).

- **Triggers:** a member transitions to `up`, a new member is added, every 5 minutes,
  and on demand (`POST v2/sys/hsm/repair`).
- **Work:** scan the KEK set and `core/hsm/custody/`. For each set missing a copy for
  an active member:
  1. Unwrap through a member that has a copy, with authz purpose `Rewrap`, audited.
  2. Wrap under the missing member.
  3. Write the set back under the `hsm-custody` lock (below).
  4. Zeroize.
- **Rate limit:** at most 2 sets per second by default (`repair_rate`), so repair
  never starves live traffic on the surviving device.
- **Progress:** visible in `v2/sys/hsm/status`.

The risk the user accepted with `min_wrap_copies = 1` is the window between
creating a key and repairing it. Losing the surviving device inside that window
loses those keys, unless the recovery copy exists. Docs, `operator hsm status` and
the GUI show the under-replicated count prominently.

## Node enrollment and revocation

Each node needs its own credential on **each** device. Credentials are random
256-bit AES key pairs (encryption plus MAC), which avoids PBKDF2 over a password.
They are never typed by an operator and never stored in the vault's storage in
clear.

**Node transport key.** On first start in pool mode, a node generates an ML-KEM-768
keypair:

- The private key goes to `credential_dir`, mode 0600.
- The public key goes to `core/hsm/node-pending/<node_id>` in physical storage. A
  sealed node can write there through Raft.
- The node logs the public-key fingerprint.

**Enroll** (`bvault operator hsm node add <node_id>`, sudo):

1. The operator confirms the fingerprint against the node's log out of band.
2. The CLI sends the admin credential for each member, once per request, over the
   API's TLS. The leader holds it in a `Zeroizing` buffer for that request only.
3. For each member, the leader opens a `bv-admin` session, generates fresh random
   credential material, and creates `bv-node-<node_id>` (`put-authentication-key`,
   node capability set, domain 1).
4. The leader seals each credential to the node's transport key
   (`KemDemEnvelopeV1`, AAD = node id ‖ hsm id) and writes the envelopes to
   `core/hsm/node-credentials/<node_id>`.
5. The leader writes an enrollment record
   `{node_id, per-member auth key id, transport key fingerprint, enrolled_at, enrolled_by}`,
   signed by each member's `bv-identity` (domain-2 admin session).
6. The node picks the envelopes up, decrypts them, stores the credentials in
   `credential_dir`, deletes the storage entry, and unseals.

Credentials at rest on the node have the same exposure class as today's `env:`
password. TPM sealing of `credential_dir` is a later hardening step, not in scope.

**Revoke** (`bvault operator hsm node revoke <node_id>`, sudo, admin credentials):

1. Delete `bv-node-<node_id>` on each member.
2. Remove the node from both gateways' `allowed_clients`. This is an operator step,
   and the command prints it.
3. Mark the enrollment record revoked.

If a member is down, its deletion is recorded as `revocation_pending` and shown in
status. The device itself keeps accepting the revoked key until the deletion runs, so
three controls cover that window:

1. **Gateway first.** The gateway reloads `allowed_clients` on `SIGHUP`, and also
   honors an optional `crl_file` for link certificates. The revoke command prints the
   exact allowlist edit. The operator procedure is to update the down host's gateway
   config *before* the host or its gateway comes back.
2. **Leader applies the revocation on return.** When the health probe sees a member
   with pending revocations come back, the leader applies them before doing anything
   else on that member. It does not wait for the 5-minute repair tick. Until every
   pending revocation is applied, the cluster's own nodes treat that member as
   `down`.
3. **The residual risk is stated.** A revoked node that reaches a returning device
   before the leader does, through a gateway that was not updated, can still use it.
   Docs and the revoke command's output say so. Only device-side deletion closes it.

The cap of 12 nodes is enforced here.

## Pool membership: provision, add, replace, retire

**Provision a device** (`bvault operator hsm provision --connector http://127.0.0.1:12345`,
run on the HSM host):

1. Log in with factory key 1, after checking that the device is in factory state.
2. Create `bv-admin` with an operator-chosen password.
3. Generate objects 3–8 with the exact capability masks above.
4. Produce the **attestation bundle**: device serial, firmware version, and
   attestation certificates for `bv-identity`, `bv-seed-ecdh` and `bv-authz`.
5. Delete key 1.

The command refuses a device that is not in factory state, unless `--adopt` is
given and the layout verifies exactly.

**Bootstrap a pool** (`operator init` in pool mode). Both devices must be
provisioned. Init:

1. Verifies both attestation bundles (below).
2. Creates the seal record v2 with both members `active` and the dual-wrapped KEK.
3. Has both `bv-identity` keys sign the membership.

**Attestation verification**, which closes the S17 gap "Yubico root-CA pinning not
yet enforced":

1. Pin the Yubico attestation root and intermediate certificates. They ship in the
   binary, with SHA-256 fingerprints in the source.
2. Walk the chain: leaf → device attestation certificate → intermediate → root.
3. Require the serial extension (`41482.4.2`) to equal the device serial reported
   by `device-info`.
4. Require the capability extension (`.5`) to equal the expected mask, and the
   origin (`.3`) to be "generated".
5. Because AES wrap keys cannot be attested, in the **same authenticated session**:
   1. Have `bv-identity` sign a fresh 32-byte challenge, proving the session reaches
      the attested device.
   2. Then `get-object-info` the wrap keys and require their capabilities and
      delegated capabilities to match the table, with no export bits.

**Replace a failed device:**

1. `provision` the new device B′.
2. `bvault operator hsm member add hsm-b2 --bundle b2.json`, with admin
   credentials. B′ is attested, then added as `joining`.
3. `node add` re-runs automatically for every enrolled node on B′: new credentials
   sealed to each node's transport key.
4. The repair job fills B′ copies for every set.
5. When the last set is fully replicated, B′ becomes `active`, and a transcript
   signed by A's and B′'s `bv-identity` is stored and audited.
6. `bvault operator hsm member retire hsm-b` marks B `retired`. Its copies are
   removed from every set by the repair job.

The failed physical device should be reset or destroyed. Its blobs are useless
without it, and retiring removes them anyway.

**Retire a healthy device.** Only step 6. Retiring is refused if it would leave no
active member, or fewer active members than `min_wrap_copies`.

**HSM key epoch rotation** (`operator hsm rotate-epoch`) reuses the repair machinery:
new wrap keys are generated on every member, every set is re-wrapped to epoch + 1,
and the old wrap keys are deleted once no set references them.

## Recovery: Shamir ceremony

With `recovery = "shamir-ceremony"`, which is honored at `init` only, as in S17:

1. At init, generate a fresh ML-KEM-768 **recovery keypair** from `OsRng`.
2. Shamir-split the 64-byte keypair seed M-of-N with `bv-shamir`. Init takes
   `-recovery-shares` and `-recovery-threshold`, default 5 / 3.
3. Return the shares once, exactly like Shamir unseal keys, and zeroize the seed.
4. Store only the recovery **public** key and its fingerprint in the seal record.
5. Every blob set, both the KEK and every seed, gets a `recovery` copy:
   `KemDemEnvelopeV1::seal(ml_kem_768, recovery_pub, aad, secret)`, with
   `aad = context ‖ purpose ‖ epoch ‖ "recovery"`. Adding a recovery copy needs
   only the public key, so no recovery secret is ever online. The repair job also
   adds missing recovery copies.

**Recovering after losing both devices:**

1. Provision two new devices.
2. Run `operator hsm recover --member hsm-a2=… --member hsm-b2=…`. Holders submit M
   shares to `v2/sys/hsm/recover` (unauthenticated, like `sys/unseal`, but only
   accepted while the node is sealed *and* every member in the record is
   unreachable or retired).
3. The node reconstructs the recovery private key in a `Zeroizing` buffer. It
   opens the KEK and every custody set's recovery copy, wraps each one under the
   new members, writes the new sets and membership, bumps the epoch, and zeroizes.
4. A `hsm.recovery_ceremony` audit event records which share indexes were used.

**Per-node topology and today's silent no-op.** In the current code
`recovery = "shamir-ceremony"` only logs a warning: no recovery key is generated and
init returns no shares (`crates/bv-core/src/seal/hsm.rs`). That is a silent failure.
Phase 1 fixes it as follows:

- **At init**, per-node + `shamir-ceremony` is refused with an explicit error that
  names this spec, until per-node recovery exists. Pool + `shamir-ceremony` works as
  described above.
- **An already-initialized per-node cluster** whose config says `shamir-ceremony`
  keeps starting, so an upgrade does not break a running node. It logs at `error` on
  every start, and status reports `recovery_requested: "shamir-ceremony"`,
  `recovery_configured: false`. A recovery that never existed is never reported as
  present.

This is the explicit software break-glass path that rule 6 allows. A quorum of share
holders together with a copy of storage can decrypt everything. That is the
trade-off the operator opts into, and init prints it. Rotating recovery shares is
not in scope.

## Audit

- **BastionVault audit.** Unchanged events for every authorized unwrap, now carrying
  `hsm_id`. New events:
  - `hsm.member_up`, `hsm.member_down`
  - `hsm.set_under_replicated`, `hsm.set_repaired`
  - `hsm.node_enrolled`, `hsm.node_revoked`
  - `hsm.member_added`, `hsm.member_retired`
  - `hsm.recovery_ceremony`
  - `hsm.crypto_failure` (AAD or authz mismatch)
- **Device log drain** (`device_audit = "drain"`, the default). Every 5 s the leader
  reads each member's log with `bv-auditor`. For each entry it:
  1. Verifies the digest chain from the cursor stored at `core/hsm/audit-cursor/<hsm_id>`.
  2. Emits `hsm.device_log` with the command, the auth key id mapped to a node id,
     the result, and the systick.
  3. Acknowledges with `set-log-index`.

  An index jump or a chain break emits `hsm.device_log_gap`, raises a metric, and is
  never silent. The 62-entry circular buffer can overflow under load when the drain
  lags; the gap event makes that visible.
- **`device_audit = "forced"`** enables the device's forced-audit option. Commands
  then fail with `LOG_FULL` when the drain falls behind. That guarantees no unlogged
  command, at the price that a stalled drain blocks the whole pool. It is opt-in for
  that reason.
- **`device_audit = "off"`** skips the drain. It is allowed only outside production.

---

## Persisted formats and migration

All of these are versioned, read-old/write-new.

| Record | Old | New | Migration |
|---|---|---|---|
| Seal record `core/hsm-seal` | v1: `kek_blobs: node_id → blob v1` | v2: `topology`, `members: hsm_id → {name, gateway, serial, identity_pub, seed_ecdh_pub, authz_pub, authz_alg, attestation_fps, state, pending_revocations}`, `kek: BvHsmBlobSet`, `recovery_pub`, `legacy_node_blobs: node_id → blob v1` | v2 reader accepts v1, loading it as `topology = per-node` with `legacy_node_blobs`. The first write converts the record. Per-node clusters keep unsealing from `legacy_node_blobs`. |
| `BvHsmBlob` | v1 AAD binds `node_id` | v2 AAD binds `hsm_id` | v1 still opens. All new blobs are v2. |
| Authz counter | `core/hsm-authz-counter` | `core/hsm-authz-counter/<node_id>` | A node's first counter is greater than the legacy value. The legacy key is left in place, read-only. |
| Custody store | — (no engine uses custody) | `core/hsm/custody/<key_id>` (barrier) | None needed. |
| Pending, credentials, enrollment, audit cursor | — | new keys under `core/hsm/` | None needed. |

**Per-node → pool** (`bvault operator hsm migrate-to-pool`, sudo, admin credentials
for both new members):

1. Provision and attest the two pool members.
2. Unwrap the KEK through the local per-node device.
3. Dual-wrap it onto the pool and write the seal record with `topology = pool`.
4. Remove `legacy_node_blobs`, and enroll each node.

Every per-node cluster today is effectively single-node, because the networked
enrollment handshake (T17) never shipped. That makes this a one-node operation in
practice. Migration tests must use a v1 seal record captured from the current code.

Downgrade is not supported once the record is v2 with `topology = pool`. The release
notes must state this.

## Configuration

Vault node, pool topology:

```hcl
hsm "yubihsm2" {
  topology          = "pool"                       # "per-node" (default, S17) | "pool"
  node_id           = "vault-3"
  credential_dir    = "/var/lib/bastionvault/hsm"  # transport key + per-member credentials, 0600
  pqc_key_cache_ttl = "60s"
  recovery          = "shamir-ceremony"            # init-time only
  min_wrap_copies   = 1                            # 1 (default) | 2
  device_audit      = "drain"                      # "drain" | "forced" | "off" (non-production only)
  repair_rate       = 2                            # sets per second

  link {
    ca_file   = "/etc/bastionvault/hsm-link/ca.pem"
    cert_file = "/etc/bastionvault/hsm-link/vault-3.pem"   # SAN = node_id
    key_file  = "/etc/bastionvault/hsm-link/vault-3.key"
  }

  member "hsm-a" {
    gateway = "https://hsm-a.internal:8250"
    serial  = "0012345678"
  }
  member "hsm-b" {
    gateway = "https://hsm-b.internal:8250"
    serial  = "0087654321"
    # connector = "http://127.0.0.1:12345"   # instead of gateway, on the node hosting this device
    # prefer    = true
  }
}
```

Validation rules:

- `topology = "pool"` requires exactly two `member` blocks, each with exactly one of
  `gateway` / `connector`, and a `serial`.
- `link` is required when any member uses `gateway`.
- `password` / `auth_key_id` are rejected in pool mode, because credentials come
  from `credential_dir`.
- **Membership lives in storage, not in config.** The `member` blocks are a
  *bootstrap* list, used only by `init` and by a node whose seal record is not yet
  readable. After init, the seal record's member entries are authoritative,
  including `gateway` URL, serial, state and `authz_alg`. `member add` supplies the
  URL of a new member.
- Nodes re-read the membership whenever the record changes, and at least every 30 s.
  A replacement device therefore reaches every running node without a restart or a
  config edit, as Goal 6 requires.
- A `member` block that disagrees with the record is ignored, with a `warn` naming
  the field. The record wins. The only per-node setting that overrides the record is
  `connector = …`, which marks the device as local to this node.
- The mock backend accepts the same shape (`hsm "mock" { topology = "pool" … }`),
  with `member` blocks naming `state_path`s. It keeps the production-refusal guard.

Gateway (`bvault hsm-gateway -config gateway.hcl`):

```hcl
hsm_gateway {
  listen           = "0.0.0.0:8250"
  connector        = "http://127.0.0.1:12345"
  tls_cert_file    = "/etc/bastionvault/hsm-link/hsm-a.pem"
  tls_key_file     = "/etc/bastionvault/hsm-link/hsm-a.key"
  client_ca_file   = "/etc/bastionvault/hsm-link/ca.pem"
  allowed_clients  = ["vault-1", "vault-2", "vault-3"]   # SAN match, exact
  max_rps_per_client = 50
}
```

## API, CLI and GUI

All routes go under `v2/`, per AGENTS.md §7, and all are sudo-gated except
`recover`, which is gated by state as described above.

| Route | Method | Purpose |
|---|---|---|
| `v2/sys/hsm/status` | GET | Extended: `topology`, per-member `{state, up, serial, last_error, latency}`, `under_replicated_sets`, `pending_revocations`, repair progress, `recovery_configured`. Never returns secrets. |
| `v2/sys/hsm/members` | GET | List the members. |
| `v2/sys/hsm/members/:name` | POST | Add a member (attestation bundle, admin credential). |
| `v2/sys/hsm/members/:name/retire` | POST | Retire a member. |
| `v2/sys/hsm/nodes` | GET | Enrolled and pending nodes. |
| `v2/sys/hsm/nodes/:node_id` | POST / DELETE | Enroll / revoke (admin credentials). |
| `v2/sys/hsm/repair` | GET / POST | Repair status / trigger. |
| `v2/sys/hsm/rotate-epoch` | POST | Epoch rotation. |
| `v2/sys/hsm/migrate-to-pool` | POST | Per-node → pool migration. |
| `v2/sys/hsm/recover` | POST | Submit a recovery share. |

CLI: `bvault operator hsm {status, provision, members, member add|retire, node add|revoke|list, repair, rotate-epoch, migrate-to-pool, recover}` and `bvault hsm-gateway`.

The CLI reads admin credentials from a TTY prompt or `env:`, never from an argument.

GUI: extend the read-only **HSM / Seal** page (`gui/src/routes/HsmStatusPage.tsx`)
with a members table, the under-replicated count (warning style when > 0), pending
revocations and repair progress. Ceremonies stay CLI-only.

Metrics:

- `bv_hsm_member_up{member}`
- `bv_hsm_command_duration_seconds{member,op}`
- `bv_hsm_session_errors_total{member,kind}`, where `kind` includes `sessions_full`
- `bv_hsm_under_replicated_sets`
- `bv_hsm_repair_total{result}`
- `bv_hsm_device_log_gap_total{member}`
- `bv_hsm_link_requests_total{member,code}`

## Failure modes

| Failure | Behaviour |
|---|---|
| One device, its host, gateway or link is down | Its circuit breaker opens. Traffic uses the other member. Creation produces under-replicated sets (or is refused with `min_wrap_copies = 2`). Alerting through metrics and audit. |
| Both down | Already-unsealed nodes keep serving barrier data. HSM-gated operations fail with `ErrHsmUnavailable` once the cache expires. Restarted nodes stay sealed. No fallback. |
| `SESSIONS_FULL` | Back off with jitter, try the other member, count in metrics. Persistent saturation suggests too many nodes or orphaned sessions. |
| Device was reset or tampered with (objects missing, factory key present) | Member marked `faulted` (stays down until an operator acts), `error` log and audit, never auto-recovered. Handle with the replacement flow. |
| Cryptographic mismatch on unwrap (AAD, authz, MAC) | `hsm.crypto_failure` audit event and the operation fails. It does **not** fail over as if it were an outage. |
| Device-log chain break or overflow | `hsm.device_log_gap` and metric. Operations continue unless `device_audit = "forced"`. |
| Raft quorum lost | No node can read the seal record, so nothing unseals. Unchanged from today. |
| Node compromised | Revoke its auth keys on both devices and its link certificate. Rotate the barrier key and the HSM epoch if it was unsealed. |

## Security considerations

- **What a node credential grants.** It can unwrap the KEK and every seed, the same
  power an unsealed node already has over the DEK. It cannot export keys or create
  credentials, and it is revocable per node at the device.
- **A gateway or network compromise** gives DoS only. SCP03 is end to end, and the
  admin credential crosses the network only inside the vault API's TLS to the leader
  and then inside SCP03.
- **Admin credential exposure.** It sits in leader memory for the length of one
  ceremony request, zeroized afterwards, and is never logged or stored. Operators
  should keep it offline. Holding it on a YubiKey through the YubiHSM Auth applet
  is a desirable follow-up, but needs client support that the `yubihsm` crate lacks.
- **Replication plaintext.** Re-wrap during repair, replacement and recovery
  materializes one secret at a time in a `Zeroizing` buffer on the leader. That is
  the same runtime exposure S17 already accepts for use.
- **No exportable wrap key exists in any flow.** Provisioning sets the masks, and
  attestation plus `get-object-info` verifies them before a device becomes a
  member.
- **What the signed unwrap authorization does and does not defend.** A node
  credential holds `sign-eddsa` on `bv-authz`, so a compromised node can mint valid
  authorizations for itself. Authz is therefore **not** a control against a
  compromised node; revocation and the device log are.

  What authz does provide:
  - A device-signed, context-bound record of every release.
  - Detection of a blob being presented under the wrong context, purpose, epoch or
    device.
  - Replay resistance against *storage-level* tampering by anyone who is not an
    enrolled node.

  Because a legitimate node never produces a bad authorization, every authz
  verification failure is a **security event** (`hsm.crypto_failure`), not just an
  audit line. Storage rollback of the per-node counter is detected by the node, which
  also keeps its high-water mark in `credential_dir`. A counter in storage below the
  local mark raises the same event.
- **FIPS-mode devices.** Whether Ed25519 (`bv-authz`) is an approved algorithm under
  YubiHSM 2 FIPS 140-3 certificate #5302 is unconfirmed. If it is not, provision FIPS
  devices with `authz_alg = ecdsa-p256`. The v2 AAD already carries the algorithm, so
  that needs no format change. Confirm against the Security Policy in Phase 7, and
  also confirm on hardware that Ed25519 keys are attestable.

## Rejected alternatives

- **Cloned wrap key via FW 2.4 RSA-OAEP export/import.** It stores one blob per
  secret and avoids both the under-replicated window and the replacement sweep. It
  was rejected because the wrap key would have to carry `exportable-under-wrap`,
  which breaks S17's rule, and because it needs FW 2.4 everywhere plus new commands
  in the `yubihsm` crate.
- **Yubico backup ceremony** (wrap key generated on a host, split, `put-wrap-key`
  into both devices). The wrap key exists in plaintext on the ceremony host, which
  is an anti-goal.
- **Exposing `yubihsm-connector` directly**, even with its TLS. It has no client
  authentication, so any network peer can exhaust sessions or brute-force
  password-derived credentials.
- **A custodian node that unwraps for the others.** It makes a software process the
  release gate instead of the device, and loses per-node, device-enforced
  revocation.

---

## Implementation phases

| Phase | Scope | Main files |
|---|---|---|
| 1. Formats and custody core | `BvHsmBlob` v2, `BvHsmBlobSet`, seal record v2 + v1 reader, per-node authz counters, custody store and handles. Mock only. | `crates/bv-core/src/hsm/{blob,blobset,custody_store}.rs`, `crates/bv-core/src/seal/hsm.rs` |
| 2. Pool backend | `HsmPool`: members, preference, failover, health probe, circuit breaker, parallel wrap, `min_wrap_copies`. Mock enforces the 16-session limit and `SESSIONS_FULL`. | `crates/bv-core/src/hsm/{pool,mock,yubihsm2,mod}.rs` |
| 3. HSM link | `bv-hsm-link` crate (gateway + relay), `bvault hsm-gateway` | `crates/bv-hsm-link/`, `crates/bvault-cli` |
| 4. Ceremonies and repair | `provision`, attestation chain pinning, node enroll/revoke with credential delivery, member add/retire, repair job, epoch rotation, `migrate-to-pool`, v2 routes, CLI | `crates/bv-core/src/hsm/{enroll,ceremony,repair,attest}.rs`, `crates/bv-kernel/src/modules/system/`, `crates/bvault-cli` |
| 5. Recovery | Recovery keypair, Shamir split, recovery copies, `recover` route | `crates/bv-core/src/hsm/recovery.rs` |
| 6. Audit and observability | Device-log drain, events, metrics, status, GUI page, `docs/hsm.md`, `docs/api.md` | `crates/bv-core/src/hsm/device_audit.rs`, `gui/src/routes/HsmStatusPage.tsx` |
| 7. Hardware validation | Two physical devices plus three nodes; measure latencies; confirm the FIPS Ed25519 question | `tests/` behind `BVAULT_TEST_YUBIHSM_POOL=1` |

**What happens to the existing modules:**

- **`enroll.rs` and `replicate.rs`** (HSM-to-HSM channel, migration transcript) stay,
  unchanged, for the per-node topology. Pool mode does not call them: every node
  reaches both devices, so it needs no channel.
- **`custody.rs`** providers move from a wrapped-blob boundary to the handle-based
  custody store in both topologies. No engine or persisted record uses the blob
  boundary today, so this is an API change and not a format migration. Its tests move
  with it.
- **`derive.rs`** takes the ECDH key id as a parameter: `bv-identity` in per-node
  mode (unchanged), `bv-seed-ecdh` in pool mode. The ECDH result is only an entropy
  input to a seed that is then stored wrapped, and the context strings do not change,
  so this is not a format change.

Phases 1–2 change persisted formats and the seal path. Per AGENTS.md they need
`make test-release` before merging, and `make check-hsm` after every change under
`crates/bv-core/src/hsm/`.

## Testing requirements

**Unit tests (mock):**

- v2 blob opens only on its own `hsm_id`; v1 still opens.
- A blob set with one copy is reported under-replicated.
- `min_wrap_copies = 2` refuses creation with one member down.
- Failover on a transport error.
- **No** failover on an AAD, authz or MAC mismatch, and an audit event is emitted.
- Preference ordering is deterministic and spreads nodes.
- Per-node counters do not race under concurrent unseals.
- Recovery envelope round-trip.
- Recovery refused while any member is reachable.
- Revocation with one member down leaves `revocation_pending` and blocks
  re-activation.

**Format and migration:**

- A v1 seal record captured from the current code loads and unseals under the new
  code, and the first write produces v2.
- `migrate-to-pool` from a v1 single-node record.
- Malformed v2 records and blob sets are rejected: unknown version, empty `copies`,
  duplicate `hsm_id`, truncated envelope.

**Integration (mock, in-process, 3 nodes and 2 mock devices):**

- Init, then each node unseals.
- With A down, every node still unseals and creates keys (under-replicated); bring A
  back and repair converges.
- With both down, sealed nodes stay sealed and unsealed nodes still serve KV.
- Device replacement end to end.
- Node revoke: the revoked node can no longer unseal.
- 13th node enrollment refused.
- Session exhaustion leads to backoff and failover.

**Link tests:**

- The gateway rejects a missing or wrong-CA certificate, a SAN not on the allowlist,
  oversize bodies, and concurrent requests from one client.
- The relay forwards a real `yubihsm` MockHsm exchange over mTLS.

**Audit:** the drain verifies the chain, and a simulated gap emits
`hsm.device_log_gap`.

**Hardware suite** (`BVAULT_TEST_YUBIHSM_POOL=1`, two devices):

- `provision`; attestation against the pinned Yubico root; capability verification
  of the wrap keys.
- Dual-wrap round-trip; unplug one device mid-run.
- Latency measurements recorded in `docs/hsm.md`.

**Cucumber:** initialize a 3-node pool, stop one HSM gateway, restart every node,
and all of them unseal.

## Left to the builder

- Exact backoff, probe and repair intervals, within the bounds above.
- The gateway port (8250 is a suggestion) and the rate-limit defaults.
- Whether to prehash the authz request (authz v2), decided by hardware measurement.
- Whether `device-info` probes travel over the same pooled mTLS connection or a
  separate one.
- The upstream `yubihsm.rs` patch (HTTPS / public connector trait, asymmetric
  session auth). Asymmetric auth would let `node add` install only public keys and
  remove credential delivery entirely. Worth a follow-up task once it is upstream.
