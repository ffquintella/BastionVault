# Feature: HSM Pool HA — an N-node cluster served by two YubiHSM 2 devices

> Status: **in progress** (T454) — phases 1–2 of 7 (formats and custody core;
> pool backend) done 2026-10-19, phase 3 (HSM link) done 2026-10-27, phase 4
> (ceremonies, repair, bootstrap, provisioning, YubiHSM 2 wiring, rotation,
> migration) done 2026-10-27 on the mock, phase 5 (recovery) done 2026-10-27
> on the mock, phase 6 (audit and observability) done 2026-10-27 on the mock,
> phase 7 (hardware validation) prepared 2026-10-27 and awaiting the hardware
> run; the [pool of one](#pool-of-one-a-single-member-pool) (operator decision
> 2026-10-27) done on the mock the same day; see [Current state](#current-state). Spec
> written 2026-10-19. Extends
> [HSM Support (YubiHSM 2)](hsm-support.md) (S17), whose non-negotiable security
> rules apply here unchanged unless a section below says otherwise and why.

## Summary

Today's HSM design ([hsm-support.md](hsm-support.md)) mandates **one YubiHSM 2 per
cluster node**. Every node wraps its own copy of the barrier KEK under its own
device, and nodes replicate secrets HSM-to-HSM.

This feature adds a second topology, the **HSM pool**:

- A BastionVault cluster of any size N (≥ 1, practically 3–12 nodes) depends on
  at most **two** YubiHSM 2 devices. It can start with **one** (a *pool of
  one*, explicitly reported as having no redundancy) and gain the second later,
  see [Pool of one](#pool-of-one-a-single-member-pool).
- Any node can unseal and perform HSM-gated operations as long as **at least one**
  of the pool's devices is reachable.
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
| Number of devices | Exactly two online devices for any cluster size. **Amended 2026-10-27:** one or two; a cluster starts with one and adds the second as redundancy, and never holds more than two (see [Pool of one](#pool-of-one-a-single-member-pool)) | User |
| Pool of one without a recovery key | Refused unless the node's `hsm` block sets `acknowledge_single_member_without_recovery = true` (init, `migrate-to-pool`, and a retire that leaves one member) | User (requirement), Claude (mechanism) |
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

`init` in pool mode requires **every configured** member to be reachable. With two
configured, starting with one copy is refused, and the error names the unreachable
member. (A pool configured with one member starts with one copy by design; see
[Pool of one](#pool-of-one-a-single-member-pool).) It also requires an
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

## Pool of one: a single-member pool

**Operator decision, 2026-10-27.** T454 and the mTLS gateway link stay. The pool
environment must be able to come up with **one** HSM; the second device is
redundancy added later. Requirements as the operator stated them:

- **R1.** A vault can be initialized, started and unsealed with only one HSM
  present, and, once two are enrolled, unsealed with either one of them present.
- **R2.** Nodes without a local HSM never need one of their own: they use a member
  through the mTLS gateway and relay (`bv-hsm-link`). A node with a local device
  uses `connector = "http://127.0.0.1:<port>"` and needs no mTLS.
- **R3.** The cluster as a whole has at most two HSMs.

> **Risk, stated loudly.** A pool of one is a single point of failure. Losing
> that device (hardware failure, a factory reset, loss or theft) loses every
> HSM-protected secret, the barrier KEK included, and therefore the vault,
> **unless a recovery copy exists** (`recovery = "shamir-ceremony"`, chosen at
> init). A pool of one with `recovery = "none"` is accepted only with an explicit
> acknowledgement, and is reported as non-redundant for as long as it lasts.

What a pool of one is, precisely:

| Aspect | Rule |
|---|---|
| Config | `topology = "pool"` takes **one or two** `member` blocks. Zero or three are refused. The blocks stay a bootstrap list; after init the seal record decides. |
| Members in the record | At most **two** members that are not `retired`. `member add` refuses a third (R3). |
| Init / bootstrap | `operator hsm bootstrap` attests the members the config lists; init needs **every configured member** reachable and writes a seal record with exactly those members `active`. One block: a one-member record and a one-copy KEK set. Two blocks and one device unreachable: init is **refused**, naming the device; it never becomes a pool of one by itself. To start with one device, list only that one. |
| `min_wrap_copies` | Copies a new set needs, each on a distinct active member. A pool of one can hold only one, so `min_wrap_copies = 2` with one `member` block is a config error. A node whose `min_wrap_copies` is larger than the record's active members cannot build its pool and stays sealed with an error naming both numbers (never a lower value picked for it). |
| Sets | Single-copy. A set is fully replicated when it holds a copy for every **active** member, so in a pool of one a one-copy set is *not* under-replicated: no `hsm.set_under_replicated`, no `bv_hsm_under_replicated_sets`, nothing for repair to do. The missing redundancy is reported once, at pool level (next row), not as per-set repair noise. |
| Signals | `v2/sys/hsm/status`: `redundancy` (`"none"` or `"full"`), `members_active`, `members_expected` (2), and `redundancy_warning` (text, only when `none`). Event `hsm.pool_not_redundant` and a `warn` in the `security` log at every start (provider open) and every unseal of a pool of one, and at the init that creates one. Metric `bv_hsm_pool_redundancy{level="none"|"full"}` (the current level is 1, the other 0). |
| `recovery = "none"` | Init of a pool of one is refused unless the node's `hsm` block sets `acknowledge_single_member_without_recovery = true`. The same applies to `migrate-to-pool` onto one member and to a `member retire` that leaves one active member in a record without a recovery key. The flag is refused with `recovery = "shamir-ceremony"` and in the per-node topology. |
| Adding the second device | The existing `member add` ceremony: attest, enroll every enrolled node on it, write it `joining`. Repair then wraps the second copy of the KEK and of every custody set; during that window the sets are counted under-replicated against the joining member (real, pending work). An admin-credentialed repair promotes it to `active`, and status reports `redundancy: "full"`. The recovery copy, if any, is unchanged: it does not depend on members. |
| Retire | Refused for the **last** active member, whatever `min_wrap_copies` says; below `min_wrap_copies` active members; when a set would keep no copy on another active member; and (see above) into a pool of one without a recovery key unless acknowledged. |
| Replacing a failed device | Retire first, then add (R3): retire the failed member (the survivor must hold every set), run as a pool of one, `member add` the replacement, repair, promote. With `min_wrap_copies = 2`, set it to 1 on the nodes first (a failed member already refuses key creation at 2). |
| mTLS | Only for a node that reaches a member over the network: that member's block has `gateway = "https://…"` and the node has a `link` block. A node on the HSM host uses `connector = "http://127.0.0.1:<port>"` and needs no `link`. A record written by a node that reached the device through its local connector names no gateway for it; other nodes then use the `gateway` in their own `member` block. |
| Persisted formats | None change. Seal record v2 already holds one or more members; redundancy is derived from member states, never stored; the acknowledgement is config, read at the moment of the transition. Two-member records written before this change load and encode byte for byte (fixture `crates/bv-core/src/seal/testdata/hsm-seal-pool-v2/`, captured from commit 7e0a8c45). |

Rejected alternatives:

- **Init falling back to the reachable member** when two are configured. That is
  the silent downgrade the anti-goals forbid; a pool of one must be asked for.
- **The acknowledgement as a `v2/sys/init` request field.** The frozen `v1/sys/init`
  cannot carry it, so a v1 client could never init a pool of one; the config sits
  next to `recovery`, which is init-time too; and one setting also covers
  `migrate-to-pool` and retire, which have no init request.
- **Keeping a transient third member** (the replacement joining while the failed
  device is still a member). R3 rules it out, and the pool of one it is replaced
  by is now a reported, first-class state. Records written before this change
  that already hold a third, joining member still load, repair and promote; only
  new additions are refused.
- **Reporting single-copy sets in a pool of one as under-replicated.** It would
  page operators for "repair needed" when there is nothing to repair, and bury the
  real signal, which is the pool's missing redundancy.
- **A redundancy field in the seal record.** It would be a second source of truth
  for what the member states already say.

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

1. Pin the Yubico attestation root and intermediate certificates. *(Changed in
   phase 7: they do not ship in the binary. The operator supplies them in a
   PEM trust file, `attestation_roots_file`, after checking their fingerprints
   against Yubico's; without it every YubiHSM 2 attestation is refused. See
   [Current state](#current-state).)*
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

*Amended 2026-10-27 (R3, at most two devices):* step 6 now comes first. Retire
the failed B, which leaves a [pool of one](#pool-of-one-a-single-member-pool),
then run steps 1–5; `member add` refuses B′ while A and B are both still
members. The steps below are kept as written for records that already hold a
joining third member.

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
active member, or fewer active members than `min_wrap_copies`, or (amended
2026-10-27) a pool of one without a recovery key and without
`acknowledge_single_member_without_recovery = true`.

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
| Wrap keys per epoch (seal record v2) | — (the config's ids) | optional `wrap_keys: epoch → {barrier, pqc}` and `rotating_to` | Absent means the config's ids at every epoch; init, migration and rotation write them. No version bump: an earlier build ignores the fields, which is harmless until the first rotation and fatal for unseal after it (it would use the config's ids), so do not roll back past this build once an epoch has rotated. |
| Recovery key (seal record v2, phase 5) | `recovery_pub: {public_key, fingerprint}` defined, never written | adds required `threshold`, `shares`; pool records only | None needed: no record ever held one. A record without `recovery_pub` encodes byte for byte as before. An earlier build reads a record with one (it ignores the split), but cannot run the ceremony. |
| Recovery copy (`BvHsmBlobSet.recovery`) | defined, never written | `KemDemEnvelopeV1` (ML-KEM-768 + ChaCha20-Poly1305) under AAD `"bastionvault/hsm/recovery-copy/v1" ‖ context ‖ purpose ‖ epoch ‖ subject ‖ "recovery"`, each field length-prefixed; subject = `barrier-kek` or the custody key id | None needed. A KEK recovery copy without a record recovery key is refused. |

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

- `topology = "pool"` requires one or two `member` blocks (amended 2026-10-27; it
  was exactly two), each with exactly one of `gateway` / `connector`, and a
  `serial`. `min_wrap_copies = 2` needs two. `acknowledge_single_member_without_recovery`
  (bool, default false) is accepted only with `recovery = "none"`; see
  [Pool of one](#pool-of-one-a-single-member-pool).
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

## Current state

Phases 1 (formats and custody core) and 2 (pool backend) are implemented in
`bv-core` and tested with the mock backend. A cluster can run `topology = "pool"`
on two **mock** devices: init dual-wraps the KEK, every node unseals through the
preferred reachable member, and custody keys are created and used through the
pool. Phase 3 adds the network link as a standalone crate, `bv-hsm-link`, and the
`bvault hsm-gateway` command; `bv-core` does not use the relay yet. Phase 4
part 1 adds the ceremonies (node enroll and revoke, member add, retire and
promotion), credential delivery and the repair job, all on the **mock**; a
`yubihsm2` pool is still validated but refused at startup until part 2 wires
the relay and the device's admin commands in. Phase 5 adds the recovery key,
recovery copies and the recovery ceremony, also on the mock. Phase 6 adds the
device-log drain, the remaining metrics, the extended status and the GUI pool
sections; the drain runs on the mock and is refused on a YubiHSM 2 until
phase 7. Phase 7 is **prepared, awaiting the hardware run**: the Yubico
attestation chain is verified against an operator-supplied trust file, and a
hardware suite that only an operator runs is in place; nothing has been run
on a device yet. The **pool of one** (operator decision 2026-10-27) is
implemented on the mock: a cluster starts with one device and adds the second
later.

Pool of one (mock; the YubiHSM 2 path compiles, unverified on hardware like
the rest of phase 7). Supersedes the "exactly two `member` blocks" rule of
phase 2 and the "at most three members not retired" decision of phase 4 part 1:

- **Config** (`hsm/mod.rs`). One or two `member` blocks (`MAX_POOL_MEMBERS =
  2`; zero and three refused); `min_wrap_copies = 2` with one block refused;
  `acknowledge_single_member_without_recovery` (pool only, refused with
  `shamir-ceremony`, false by default).
- **Init and bootstrap** (`seal/hsm.rs`, `seal/hsm/pool_admin.rs`). Unchanged
  machinery over one member: bootstrap attests and enrolls on the one
  configured member, init writes a one-member record and a one-copy KEK set.
  With `recovery = "none"` and one member, bootstrap, init and
  `migrate-to-pool` are refused (`ErrHsmConfigInvalid`, naming the setting and
  the risk) unless acknowledged, before any device or record changes. A
  two-member config with one device down still refuses init, now with a hint
  to list only the present device.
- **Signals.** Status `redundancy`, `members_active`, `members_expected`,
  `redundancy_warning` (also before init, from the config); `GET
  v2/sys/hsm/members` adds the first three and reports `max_live_members: 2`.
  Event `hsm.pool_not_redundant` (`warn`) at start (`HsmSealProvider::open`),
  at every unseal, at init / migration, after a retire into one member and on
  promotion while still one; the startup line says `redundancy none|full`.
  Metric `bv_hsm_pool_redundancy{level}` in `bv-metrics` (no series until a
  pool reports). Single-copy sets of a pool of one are fully replicated: no
  `hsm.set_under_replicated`, no under-replicated count, nothing to repair.
- **Membership.** `member add` refuses a third member that is not retired
  (`HsmPool` still accepts three, so a record that already holds a joining
  replacement repairs and promotes). `member retire` refuses the last active
  member explicitly, and a retire into a pool of one without a recovery key
  unless acknowledged. Replacing a failed device is now retire, then add.
- **No format change.** Redundancy is derived from member states. Fixture
  `seal/testdata/hsm-seal-pool-v2/` (a two-member record and its two mock
  device states, captured from commit 7e0a8c45) loads, re-encodes byte for
  byte, reports `redundancy: "full"` and unseals through either member alone.
- **Tests** (mock): init and unseal of a pool of one, with and without the
  acknowledgement and with a recovery key; a second node without a device
  unseals through it; the second device added, repaired and promoted, then A
  down → B unseals and B down → A unseals (and a custody key opens through B);
  a third device refused; last-member and unacknowledged retires refused;
  status, events and the metric; config rules (one or two members, `link` only
  for a gateway member, the flag); the old two-member fixture; the
  replacement test rewritten as retire-then-add.

Decisions made where the operator's brief left room:

- The acknowledgement is a config setting, not a `v2/sys/init` field
  (rejected: the frozen `v1/sys/init` cannot carry it, and it must also cover
  `migrate-to-pool` and retire, which have no init request). It applies to
  every transition into a pool of one without a recovery key, not to init
  only, so a retire cannot drop to one device silently.
- R3 is enforced as "at most two members not retired" on writes. Rejected:
  keeping the three-member replacement window (R3), and refusing to read
  records that already hold three (read-old).
- `min_wrap_copies` is never lowered for the operator: two with one member is
  a config error, and a node whose value exceeds the record's active members
  stays sealed with an error naming both.
- The redundancy metric is a labelled gauge, so a vault without a pool never
  exports a `none` that would page someone.

Still open: the GUI's HSM / Seal page does not show `redundancy` yet (the
fields are in the status it reads); the YubiHSM 2 pool of one is verified on
hardware only with the rest of phase 7.

Phase 7 (hardware validation, prepared; compiled and tested against the
mock and generated certificates only):

- **Attestation chain** (`hsm/attestation.rs`, `x509-parser` with its `ring`
  verifier). A YubiHSM 2 attestation is now `key certificate ‖ device
  attestation certificate` (opaque object 0), DER. `verify_chain` checks:
  exactly those two certificates (intermediates come from the trust file);
  every link's signature, validity now, X.509 v3, an accepted algorithm (SHA-2
  RSA PKCS#1, ECDSA SHA-256/384, Ed25519) matching the TBS one, and no unknown
  critical extension; the key certificate is signed by the device certificate
  and is not a CA; the device certificate is issued by a trust-file
  certificate, every trust-file certificate on the path is a CA with
  `keyCertSign`, and the path ends at a self-signed root in the file within
  four links; the YubiHSM extensions `41482.4.{2,3,4,5,6,9}` are present and
  well formed; origin is "generated on the device". A BIT STRING field is read
  in full or DER-minimal (trailing zero bits dropped), the same bits either
  way; the firmware field is reported, never decided on.
- **Pinned to the device** (`yubihsm2.rs`). The admin session's
  `verify_attestation` additionally requires the attested serial to be the
  `device-info` serial of the device reached, and object id, label, domains,
  capabilities and algorithm to equal what `provision` creates for that
  object (`attested_layout`, the table `provision` itself generates from), with
  no export bit; `verify_member` then compares the key with the device's own
  public key and runs the `bv-identity` challenge and the layout check, as on
  the mock. The per-node backend's `verify_attestation` (S17 enrollment) is
  pinned to the same trust file and requires origin "generated"; it used to
  accept an unpinned leaf with a warning.
- **Trust file** (`attestation_roots_file`, yubihsm2 only, refused on the
  mock). PEM certificates only (a key or other block is refused), at most
  1 MiB, at least one self-signed root; a missing or unreadable file is an
  error naming it. Unset: every YubiHSM 2 attestation is refused, with the
  message naming the setting and where Yubico publishes the certificates.
- **`provision`** reads the device attestation certificate with the factory
  key before any write (only the factory key holds `get-opaque` in this
  layout) and appends it to each attestation in the bundle. `--adopt` on a
  pool device cannot read it (`bv-admin` lacks `get-opaque`) and is refused,
  rather than emitting a bundle that could never be attested. A bundle from an
  earlier build holds only the key certificate and is refused as truncated.
- **Hardware suite** (feature `hsm_hardware_tests`, which no crate above
  `bv-core` forwards; `tests/hsm_pool_hardware.rs` with `required-features`;
  logic in `hsm/hw_validation/mod.rs`, device half in
  `hsm/hw_validation/device.rs`). Skipped unless `BVAULT_TEST_YUBIHSM_POOL=1`.
  Three invocations, ordered least to most destructive: `snapshot`
  (read-only: serial, firmware, algorithms, storage, force-audit and
  command-audit options, every object's metadata, the device certificate's
  summary, the device log and whether its digest chain verifies; then the
  factory-state preflight; saved once as `snapshot-before.json`, never
  overwritten), `validate` (re-snapshot and match, preflight, trust file, then
  behind `BVAULT_TEST_YUBIHSM_ALLOW_WRITES=1`: provision, attest, test node
  key, dual-wrap, relay through a real gateway, latency, revoke, and the
  reset instructions), and `compare` after the operator's physical reset
  (read-only: snapshot, save, preflight, diff with "none" expected; log
  counters, the device log and the connector version are ignored, an
  unreadable value is reported as unverified, never as equal). Serial
  allow-list of exactly two (`BVAULT_TEST_YUBIHSM_SERIALS`), checked at the
  connector status and again at `device-info`; one `yubihsm-connector` per
  device on its own loopback port with `--serial`, killed on exit; passwords
  only from the environment, zeroized, never printed. The harness refuses by
  name, with the reason, any request to reset, update firmware, enable FIPS
  mode, set command or forced audit, or run the production provision.
  Runbook: `docs/hsm.md` § Phase 7 hardware validation.

Decisions made in phase 7 where this spec left room:

- The Yubico root and intermediate are operator-supplied, not shipped.
  Rejected: embedding them (the spec's first plan), because this build has no
  copy whose provenance can be checked offline, and a wrong embedded root
  would be trusted silently; a trust file the operator verified against
  Yubico's published fingerprints keeps that check with the operator, and its
  absence refuses rather than trusts.
- The bundle carries the device certificate next to each key certificate
  instead of `verify_member` reading object 0 through the admin session:
  `bv-admin`'s capabilities stay as the layout table says (no `get-opaque`).
- The hardware suite is a feature-gated test binary, not `#[ignore]` tests:
  `--ignored` would run it from any default build, and a default build should
  not even compile the device half.
- The suite stops before the production `provision` and never runs
  `bootstrap` / `init` against the devices; its write set is the test
  `provision` and one node key.

Still owed by the hardware run (not done, not claimed): attestation against
the real Yubico chain (the extension encodings are Yubico's documented ones,
unconfirmed on a device; any mismatch refuses), `provision` and `--adopt` on
hardware, the unwrap MAC-failure code, the relay's latencies, the device-log
layout (captured read-only by the snapshot; the YubiHSM 2 drain, `bv-auditor`
and forced audit stay refused until it is reviewed), unplugging a device
mid-run, a three-node `bootstrap` / `init`, the reset-then-`faulted` check,
and the FIPS Ed25519 question (these devices are not FIPS models).

Phase 6 (audit and observability, mock):

- **Device log** (`hsm/device_audit.rs`). `DeviceLogEntry` is the device's
  16 data bytes plus `SHA-256(data ‖ previous digest)[..16]`. `verify_log`
  checks a `get-log-entries` answer against the member's cursor
  (`core/hsm/audit-cursor/<hsm_id>`, physical, no secret: last index and
  digest, unlogged-event counters, `drained_at`, `drained_by`): the cursor's
  entry still present resumes after it; an entry missing from a buffer whose
  entries are all later is overflow (an index jump unless the oldest chains
  from the cursor); anything else is a reset or rewrite and every entry is
  treated as new. Each jump, chain break, reset and unlogged-event change is a
  gap; the chain re-anchors and later entries are still drained.
- **Mock device log** (`hsm/mock.rs`). 62 entries in memory per device object
  (per process, like the session table), every node, admin and failed command
  logged under the auth key that ran it; `forced_audit` persisted in the state
  file (absent = off, written only when on, so earlier files read unchanged)
  makes a loggable command fail with `LOG_FULL` while 62 entries are
  unacknowledged. `bv-auditor` (auth key 8) authenticates on every command and
  may only `get-log-entries` / `set-log-index`; the mock does not log those two.
- **Drain** (`seal/hsm/device_drain.rs`, tick in `hooks.rs`). Every 5 s while
  unsealed, on every node, under `hsm-device-audit`: for each member that is
  not retired, read its `bv-auditor` credential from the barrier
  (`core/hsm/auditor/<hsm_id>`), skip it when another node's cursor is younger
  than 5 s, read the log (`bv_hsm_command_duration_seconds{op="get_log_entries"}`),
  verify, raise `hsm.device_log` per entry (command, auth key, the node the
  enrollment maps it to, target, result, systick; the drain's own reads are not
  raised) and `hsm.device_log_gap` per gap (`bv_hsm_device_log_gap_total`),
  store the cursor, then `set-log-index`. A failure between the two re-reads
  entries (duplicates, never a loss). A member with no credential or a failure
  is logged once when it appears, and reported in status.
- **`bv-auditor` install.** A repair run with admin credentials and the barrier
  (`bvault operator hsm repair --run --admin …`) gives each live member it has
  a credential for a random 32-byte `bv-auditor` when the stored one is missing
  or no longer authenticates: replace key 8 on the device first, store second.
  It then sets the forced-audit option to `device_audit = "forced"`.
  `auditors_installed` is in the report. `device_audit = "off"` installs and
  drains nothing.
- **Metrics** (`bv-metrics`). `bv_hsm_command_duration_seconds{member,op}`
  (`wrap`, `read`, `probe`, `get_log_entries`; 5 ms to ~10 s buckets),
  `bv_hsm_repair_total{result}` (`added`, `removed`, `recovery_added`,
  `failed`), `bv_hsm_device_log_gap_total{member}` and
  `bv_hsm_link_requests_total{member,code}` (`ok`, `failed`), fed from each
  member client's relay totals by the 10 s probe (a reopened relay counts from
  zero again, never negative).
- **Status.** Per member `latency_ms` (last successful command from this node)
  and `pending_revocations`; the pool's `pending_revocations`
  (`[{member, node}]`), `repair` (as `GET v2/sys/hsm/repair`) and
  `device_audit` (`mode`, `interval_secs`, and per member `enrolled`,
  `last_index`, `last_drain_at`, `drained_by`, `entries_drained`, `gaps`,
  `last_error`, from this node's drains). Never a credential.
- **GUI** (`gui/src/routes/HsmStatusPage.tsx`). For `topology = "pool"`: the
  under-replicated warning, a members table (state, link, latency, serial, KEK
  copy, pending revocations, last error), pending revocations with the repair
  command, the repair card and the device-audit card (a missing auditor key
  names the repair command). Read-only.
- **`v1/sys/init`** (correction owed from phase 5). `/init` is registered per
  version. `v1` is exactly what it was before phase 5: the recovery fields are
  not part of its request and are ignored, and an init that would return
  recovery shares (a pool with `shamir-ceremony`, which could not be
  initialized before phase 5) is refused; `v2` takes the fields. Regression
  tests: `bv-server` `sys_init_version_tests`.

Decisions made in phase 6 where this spec left room:

- `v1/sys/init` ignores the recovery fields rather than refusing them: that
  is its behaviour before phase 5 and what a Vault client that always sends
  them expects; the only case where ignoring would lose something (a
  shamir-ceremony pool) is refused. Rejected: a `400` on `v1` (changes a frozen
  route for old clients).
- The drain runs on every node like the repair tick (no leadership signal);
  the lock and the cursor's `drained_by` / `drained_at` keep it to about one
  drain per member per interval. The cursor gains `drained_by` (new record,
  `serde(default)`).
- The `bv-auditor` credential is created by BastionVault (an admin repair), not
  by `provision`: it has to live behind the barrier, which does not exist when
  a device is provisioned. Rejected: a dedicated `device-audit` route and
  command (one more admin surface for what repair already reaches).
- `hsm.device_log` goes to the `security` log at `debug` only; the audit
  device is its record. Gaps are `error`.
- `bv-admin`'s capability list is unchanged: the `set-option` and
  `put-authentication-key` delegation the device needs for forced audit and
  `bv-auditor` are confirmed with the log layout in phase 7.

Not done in phase 6, deliberately (phase 7, hardware):

- The YubiHSM 2 side: `put_auditor_auth_key`, `set_forced_audit` and
  `open_auditor` refuse on a YubiHSM 2, naming phase 7, until the entry layout,
  the digest chain, whether the device logs `get-log-entries` /
  `set-log-index`, and `LOG_FULL` behaviour are confirmed on a device.
- Gateway-side counters (`GatewayStats`) stay in the gateway's log; the metric
  is the node's relay view.
- The mock's log is per process: a mock pool whose nodes run in separate
  processes sees a different log per process and reports restarts; run such a
  dev cluster with `device_audit = "off"` (allowed outside production).

Phase 5 (recovery, mock):

- **Recovery key** (`hsm/recovery.rs`). Pool init with `recovery =
  "shamir-ceremony"` generates a 64-byte seed from the host CSPRNG, derives the
  ML-KEM-768 keypair, Shamir-splits the seed with `bv-shamir` (`RecoverySplit`,
  default 5 / 3, `2 <= threshold <= shares <= 254`) and returns the shares
  once; the seal record keeps the public key, its fingerprint and the split.
  `v2/sys/init` (only; `v1` is frozen) takes `recovery_shares` / `recovery_threshold` (both or
  neither) and returns `recovery_keys` apart from `keys`; `bvault operator
  init --recovery-shares --recovery-threshold`. Per-node, a pool with
  `recovery = "none"` and every non-HSM seal refuse the fields
  (`SealProvider::check_init_recovery`, before anything is written).
- **Recovery copies.** The KEK and every custody set carry a
  `KemDemEnvelopeV1` sealed to the recovery public key, AAD-bound to the set's
  context, purpose, epoch and subject (custody key id). Written by init,
  custody `create`, `repair` (adds a missing one, `recovery_copies_added`) and
  `rotate-epoch` (re-sealed at the new epoch; the phase 4 refusal is gone).
  Unseal never reads one.
- **Ceremony** (`seal/hsm/recovery_ceremony.rs`, `POST v2/sys/hsm/recover`,
  `bvault operator hsm recover`). Route class `public-probe` (the shares are
  the credential, as for `sys/unseal`); the handler and the provider both
  require a sealed node, and the provider requires a pool record with a
  recovery key and every non-retired member unreachable from this node (only
  `ErrHsmTransport` counts; any other answer refuses). Shares accumulate in
  memory (zeroized; malformed, duplicate or surplus ones refused, never
  echoed); the final request names 1–2 new members (at least
  `min_wrap_copies`) with bundles and admin credentials. Under `hsm-repair`:
  recombine (accepted only on the recorded fingerprint; every attempt consumes
  the shares), open the KEK's recovery copy, attest the new devices and give
  them the epoch's wrap keys, enroll every enrolled node (this node's
  credentials installed directly, the others sealed for delivery), wrap the
  KEK on each and prove each copy with an authorized `rewrap` unwrap, unseal
  the node's own barrier object with the recovered KEK to add each custody
  set's copies (seed checked against its public key), commit the record (old
  members `retired`, pending revocations on them dropped with a warning)
  against the exact bytes read at the start, bump the epoch with the rotation
  ceremony, reseal the barrier; the route then auto-unseals through the new
  members. Before the commit a failure deletes every node key it created.
  Event `hsm.recovery_ceremony` (share indexes, members, custody counts).
- **Status:** `recovery_fingerprint`, `recovery_threshold`, `recovery_shares`,
  `kek_recovery_copy`, `recovery_progress` (a count, never a share).
- **Migration** refuses `recovery = "shamir-ceremony"`: the key is made at init
  only, so a migrated pool has none.

Decisions made in phase 5 where this spec left room:

- The recovery-share fields and `recovery_keys` exist on `v2/sys/init` only
  (AGENTS.md §7: `v1` is frozen, no new operations; corrected in phase 6).
  `/init` is registered per version (`V1_INIT`, `V2_INIT`); `v1` ignores the
  fields as it did before phase 5, refuses an init that would return recovery
  shares (a pool with `shamir-ceremony`), because its response cannot carry
  them, and otherwise runs the same logic. `bvault operator init` always calls
  `v2`. Rejected: accepting the fields on the shared handler (the first phase
  5 commit), and split parameters in the HSM config.
- The ceremony adds copies at each set's own epoch, commits, and then bumps
  the epoch through `rotate-epoch` (which drops the retired copies and
  re-seals the recovery copies). A failed bump leaves a complete recovery at
  the old epoch, finished by a later `rotate-epoch`; rejected: re-wrapping
  straight to epoch + 1 before the commit, which leaves custody sets unusable
  if the ceremony is abandoned and the old devices come back.
- Custody sets live behind the barrier, so the ceremony unseals the node's own
  barrier object with the recovered KEK for the custody step only (the node's
  state stays sealed, no request is served) and seals it again on every path.
  Rejected: unsealing the node first through the new members and recovering
  custody afterwards, which strands every custody set if that step fails,
  because the gate is closed once the new members answer.
- The recovery copy's AAD also binds a subject (the custody key id), stricter
  than the spec's `context ‖ purpose ‖ epoch ‖ "recovery"`: custody contexts
  do not name the key, so two keys of one kind and epoch would otherwise share
  an AAD.
- A custody set that cannot be recovered (no copy, a copy that does not open,
  a seed that does not derive its public key) is reported and raised, not
  fatal: failing the ceremony for one tampered copy would turn tampering into
  a denial of recovery for everything else.
- Recovery onto one new device is allowed when `min_wrap_copies = 1`; `member
  add` brings the second.

Not done in phase 5, deliberately:

- `bv-shamir` does not zeroize its internal copies of the shares and
  coefficients (pre-existing, shared with the unseal path); fixing it touches
  a Tier 0 crate and every dependent, so it is a follow-up.
- Rotating the recovery shares (re-split without a ceremony) stays out of
  scope, as the spec says.
- The ceremony on a YubiHSM 2 pool stops at member attestation like `member
  add` (phase 7: Yubico chain pinning); nothing in it needs hardware beyond
  that.

Phase 4, part 1:

- **Device administration** (`hsm/admin.rs`). `HsmAdminSession` is a `bv-admin`
  session: object info, auth-key list, `put` / `delete` of **node** keys only
  (`0x100 + slot`, slots 0–11; the factory key and `bv-admin` are out of reach),
  `bv-identity` signing and attestation verification. `verify_layout` refuses a
  device with the factory key, without `bv-admin`, with a wrap key whose
  capabilities are not exactly `wrap-data` / `unwrap-data` or that delegates
  anything, or with an export bit on an attested key. `AdminCredentials` hold
  per-member passwords in `Zeroizing` buffers and never print them.
- **Mock auth model** (`hsm/mock.rs`). Auth keys are their own id namespace, as
  on the device. `open_factory` gives a device holding only factory key 1;
  `provision` (factory password, admin password) creates `bv-admin` and the
  objects, deletes key 1 and returns the attestation bundle, and refuses any
  other state unless `adopt` and the layout verifies. A device with auth keys
  refuses an unauthenticated session; `connect_with_credential` authenticates
  **on every command**, so deleting a node's key cuts it off at once, and a
  failed authentication takes no session slot. Pre-phase-4 state files (no auth
  keys) keep working unchanged.
- **Credential delivery** (`hsm/node_creds.rs`). A pool node with
  `credential_dir` creates a 64-byte ML-KEM-768 seed (`transport.seed`, 0600, in
  a 0700 directory), logs the fingerprint and publishes
  `core/hsm/node-pending/<node>` while it holds no credential. Enrollment seals
  each credential with `KemDemEnvelopeV1`, AAD = context ‖ node ‖ hsm_id ‖
  transport fingerprint ‖ auth key id, at `core/hsm/node-credentials/<node>`.
  The node installs them (`credentials.json`, written 0600 through a rename)
  under `hsm-custody` and deletes the entry; nothing is written unless every
  envelope opens. Files group- or world-readable are refused.
- **Ceremonies** (`seal/hsm/pool_admin.rs`, records in `hsm/ceremony.rs`).
  Every ceremony holds `hsm-custody` for its whole read-modify-write, opens all
  its admin sessions before changing anything, closes them on every path, and
  rolls back keys it created if a later step fails.
  - `bootstrap_enroll` (init, step 2): before any seal record, the init node's
    key on every configured member, credentials stored locally only, the
    enrollment record written; init then wraps through those sessions.
  - `enroll_node`: the confirmed fingerprint must match the pending record; at
    most 12 non-revoked nodes; every live (active or joining) member needs its
    admin credential; lowest free slot not held by a record or present on a
    device. Writes the delivery, the enrollment record
    (`core/hsm/nodes/<node>`, one `bv-identity` signature per member over that
    member's entry) and removes the pending record.
  - `revoke_node`: discards undelivered credentials first, deletes the key on
    every member it can reach with an admin credential, records a pending
    revocation on the others, marks the record revoked, and returns the gateway
    allow-list step and the residual risk.
  - `add_member`: name and device unique, at most three members not retired;
    `verify_member` (bundle names this device, both attested keys are the
    device's own, a fresh challenge signed by `bv-identity` in this session,
    `verify_layout`); every enrolled node gets a key and a delivery on the new
    member; the member is written `joining`.
  - `retire_member`: refused below `min_wrap_copies` (at least one) active
    members, or when the KEK or any custody set has no copy on another active
    member (needs the unsealed barrier).
  - Promotion: a repair run with admin credentials for the joining member and an
    active one moves a joining member that holds every set to `active`, with a
    transcript both identities sign at `core/hsm/promotions/`.
- **Repair** (`hsm/repair.rs`, `HsmSealProvider::repair`). Under `hsm-repair`:
  picks up the leader's own new credentials, applies pending revocations when
  admin credentials are given, then plans each set (the KEK, every custody set)
  against active ∪ joining, unwraps once through a member holding a copy with a
  `rewrap` authorization checked against the pinned key, wraps on each missing
  member, drops retired copies only when another copy exists, and writes back
  under `hsm-custody` only if the set did not change meanwhile. Writes are
  spaced `1 / repair_rate` s apart. The report (scanned, added, removed,
  failures, still under-replicated, ready to promote, promoted, revocations)
  is kept for `GET v2/sys/hsm/repair` and feeds `bv_hsm_under_replicated_sets`.
- **Authorization `rewrap`** (`hsm/authz.rs`). `UnwrapRequest.operation`
  (`use` | `rewrap`, absent = `use`, so old requests read and serialize byte for
  byte) selects both the signed tag and the `bv-authz` context.
- **Membership.** Clients are opened through a `MemberOpener` with this node's
  credential for the device, cached, and reopened when a credential arrives. A
  member with a pending revocation is unusable for every node. Membership is
  re-read from the record on unseal, on status and every 30 s
  (`MEMBERSHIP_REFRESH_INTERVAL`), which also picks up deliveries.
- **Routes and CLI.** `GET v2/sys/hsm/members`, `POST v2/sys/hsm/members/:name`,
  `POST …/:name/retire`, `GET v2/sys/hsm/nodes`, `POST` / `DELETE
  v2/sys/hsm/nodes/:node_id`, `GET` / `POST v2/sys/hsm/repair`, all sudo
  (`root_paths`), v2 only; `bvault operator hsm members | member add|retire |
  node add|revoke|list | repair [--run]`, with `--admin <member>` (TTY prompt)
  or `--admin <member>=env:VAR` and a literal value refused.
- **Config.** `repair_rate` (1–100, default 2) is accepted in pool mode.

Decisions made in phase 4 part 1 where this spec left room:

- Pending revocations are applied by the next ceremony that carries that
  member's admin credential (`node revoke` again, or `repair --run --admin`),
  not automatically on the member's return: deleting a key needs `bv-admin`,
  whose credential the leader never stores. Until then the member is down for
  every node, which is stricter than the spec's automatic step 2.
- Promotion needs an admin-credentialed repair run for the same reason (the
  transcript is signed by `bv-identity`, an admin-domain key); an automatic run
  reports `ready_to_promote` instead.
- Enrollment needs every live member reachable with its admin credential, so a
  node is never enrolled on one device only. Rejected: a pending enrollment.
- A pool holds at most three members that are not retired (two plus a
  replacement while it joins); the config still takes exactly two.
  *Superseded 2026-10-27 by the [pool of one](#pool-of-one-a-single-member-pool):
  at most two, and the config takes one or two.*
- Device object ids stay the configured `HsmObjectIds` (the released defaults),
  because auth keys are a separate id namespace: `bv-admin` is auth key 2 and
  node keys are `0x100 + slot` without colliding with wrap key 2.
- Enrollment and promotion records, deliveries and pending records live in
  physical storage (a sealed node reads them); they hold no secret in clear.
- Custody sets are repaired in the seal record's cluster scope
  (`record.cluster_uuid`).

Phase 4, part 2:

- **Bootstrap and attested init.** `bootstrap_enroll(admin, bundles)` runs
  `verify_member` on both configured members before anything changes, enrolls
  the node, and writes `core/hsm/bootstrap` (each member's identity, authz and
  seed-ECDH keys and attestation fingerprints). Pool init by a node that holds
  node credentials needs that record for every member, refuses one whose device
  reports other keys, pins the keys and fingerprints in the member entries, and
  deletes the record. `POST /v2/sys/hsm/bootstrap` (route class
  `cluster-local`, but the handler accepts **only a loopback peer**, and only
  while uninitialized) and `bvault operator hsm bootstrap --bundle
  NAME=FILE --admin …` expose it.
- **Provisioning.** `bvault operator hsm provision --mock-state-path P --serial
  S` (builds with `hsm_mock`) or `--connector URL` (YubiHSM 2, local to the HSM
  host), `--adopt`, `--admin-password env:VAR` or a TTY prompt,
  `--factory-password env:VAR` (default: the published one), `--out
  bundle.json`. Runs against the device; the vault is not involved.
- **Layout.** `HsmObjectIds.seed_ecdh` (default 6, `seed_ecdh_key_id`).
  Provisioning creates `bv-seed-ecdh` (domain 1, `derive-ecdh`) and puts
  `bv-identity` in domain 2 (`sign-ecdsa`, admin only); the bundle carries a
  third attestation and `verify_layout` checks it. On a provisioned mock a node
  session can neither sign nor run ECDH with `bv-identity`; pool custody scopes
  use `seed_ecdh`. Pre-phase-4 mock state files keep the old four objects.
- **Events and the repair tick** (`seal/hsm/hooks.rs`). `ProviderHooks` is the
  pool's event sink: the `security` log always, and after
  `HsmSealProvider::attach(core)` (called by `bvault server`) an audit entry at
  `sys/hsm/events/<event>/<member>` (details HMAC-redacted like any body). New
  events: `hsm.set_repaired`, `hsm.node_enrolled`, `hsm.node_revoked`,
  `hsm.revocation_pending`, `hsm.member_added`, `hsm.member_retired`,
  `hsm.member_promoted`. The tick runs repair every 5 minutes, or within 10 s
  of `hsm.member_up`, while unsealed.
- **YubiHSM 2 wiring** (`hsm/yubihsm2.rs`, compiled by `make check-hsm`,
  unverified on hardware). A pool member client opens with the node's
  credential through its local `connector`, or through a `bv-hsm-link` relay
  started for that client to the record's gateway (the `link` block's
  certificates). `YubiHsm2AdminSession` implements the ceremonies with
  `bv-admin`; `provision` creates the layout from factory state with the
  capability masks of § HSM object layout and deletes key 1. The startup gate
  is lifted. `verify_attestation` on the admin session **refuses**, because no
  Yubico root or intermediate is pinned, so bootstrap and `member add` on a
  YubiHSM 2 stop there with an error naming phase 7.

Decisions made in phase 4 part 2:

- The repair tick runs on every node, serialized by `hsm-repair`, not on the
  Raft leader only: `Core` exposes no leadership signal. Each write still
  re-checks its set, so concurrent runs cannot clobber each other.
- Bootstrap is loopback-only rather than any cluster node: before init it is a
  `bv-admin` password oracle for whoever can reach it.
- `bv-auditor` is left to phase 6 with the drain: its credential has nowhere to
  go until the drain exists.
- YubiHSM 2 calls stay synchronous on the calling task (as per node); the relay
  runs on its own thread, so this cannot deadlock. `spawn_blocking` waits for
  phase 7 latency measurements.

Phase 4, part 3:

- **Seal record: wrap keys per epoch** (`record.rs`, read-old/write-new).
  `wrap_keys: epoch → {barrier, pqc}` and `rotating_to` are new optional
  fields. A record without them (every record before this part) uses the
  config's ids at any epoch and still encodes byte for byte without them; a
  recorded map must hold the current epoch and never answers for an
  unrecorded one; `rotating_to` must name recorded keys. New pool records
  (init, migration) always carry the map. Unseal, repair and custody resolve
  the key for the set's own epoch; `CustodyScope.pqc_wrap_keys` carries the
  record's map to the custody store.
- **`rotate-epoch`** (`POST v2/sys/hsm/rotate-epoch`, sudo, admin credentials
  for every active member; `bvault operator hsm rotate-epoch --admin …`).
  Under `hsm-repair`, refused with a joining member, a pending revocation or a
  member it cannot reach (phase 5 lifted the refusal of recovery copies: they
  are re-sealed at the new epoch). It allocates two free
  wrap-key ids (from 0x20, checked on every device), generates them through
  the admin sessions (`generate_wrap_key`, capabilities verified), records them
  with `rotating_to` **before** touching any set, re-wraps each custody set
  and then the KEK to epoch + 1 on every member (a `rewrap` authorization, a
  full set or nothing), clears `rotating_to`, deletes the old keys and forgets
  their epoch. An interrupted run resumes with the recorded keys and skips sets
  already moved; nodes keep unsealing at the old epoch until the KEK moves.
  `member add` gives a replacement the current (and target) epoch's keys.
- **`migrate-to-pool`** (`POST v2/sys/hsm/migrate-to-pool`, loopback only,
  the node being sealed; `bvault operator hsm migrate-to-pool`). The node runs
  the pool config with a `migrate_from` block (mock: `state_path`; yubihsm2:
  `connector` and `password = "env:VAR"`, a literal refused) naming its old
  per-node device. `operator hsm bootstrap` is allowed over a per-node record
  only then. Migration unwraps the KEK through the per-node device (signed,
  per-node counter), dual-wraps it on the attested members, and replaces the
  exact per-node record bytes it read with a pool record that keeps
  `cluster_uuid` and `epoch` and drops the legacy blobs; the route then tries
  to auto-unseal. One-way. Tested from the captured v1 fixture.
- Event `hsm.epoch_rotated`.

Decisions made in phase 4 part 3:

- Wrap-key ids are one pair per epoch for the whole pool, not per member: a
  ceremony that adds keys makes them the same on every member.
- Per-node custody sets are not migrated: no engine creates custody keys, and
  the barrier is sealed while a node migrates.
- Per-node rotation stays out (T456); `rotate-epoch` is a pool ceremony.

Phase 7 (needs hardware): pin the Yubico attestation root and intermediate
and walk the chain (serial, capability and origin extensions); run
`provision`, bootstrap, enrollment and the relay against two devices.
Prepared, see the phase 7 entry at the top of this section.

Phase 3:

- **`bv-hsm-link`** (`crates/bv-hsm-link`, Tier 0: `bv-errors` only). Both
  halves frame HTTP/1.1 strictly (`src/http.rs`, httparse for tokenizing):
  exactly one `Content-Length`, `Transfer-Encoding` refused (501), `Expect`
  refused (417), exactly one `Host`, no bare CR or LF, an 8 KiB head and 32
  headers at most, HTTP/1.1 only, and no pipelining (bytes after a body are a
  400, before anything is forwarded). The API body is 3–3139 bytes (400 / 413);
  the status request takes no body. Every refusal closes the connection.
- **Gateway** (`src/gateway.rs`). TLS 1.3 only, aws-lc-rs, client certificate
  mandatory and verified against `client_ca_file`. The client identity is the one
  DNS SAN that equals an `allowed_clients` entry byte for byte; none or two
  different ones refuse the connection. Per client: one request in flight across
  all its connections (a second gets 429, not a queue) and a token bucket of
  `max_rps_per_client` (default 50, burst one second). Each request opens a fresh
  loopback connection to the connector, carries only `Host` and framing, and has
  5 s end to end (504; other upstream failures are 502). Logs: connection open
  and close with peer, client, request and error counts, and rejections with
  their reason; bodies never (a test captures every log record and asserts it).
- **Relay** (`src/relay.rs`). `Relay::start(RelayConfig)` returns once
  `127.0.0.1:<ephemeral>` is bound; `local_addr()` is what the `yubihsm` HTTP
  connector points at, `stats()` feeds future metrics, and `shutdown()` / drop
  stop it. It runs on its own thread and current-thread runtime, so blocking
  and async callers use it the same way. It forwards over one pooled mTLS
  connection, verified against the link CA and the gateway URL's host.
- **`bvault hsm-gateway --config gateway.hcl`** (`crates/bvault-cli`). Parses the
  [Gateway](#configuration) block with unknown fields refused, validates it
  before anything listens (exit code `Config` on failure) and stops on Ctrl-C or
  SIGTERM.

Decisions made in phase 3 where this spec left room:

- The gateway writes to the connector as **HTTP/1.0**, so Go's `net/http` frames
  the reply by `Content-Length` or by closing, never chunked; the gateway accepts
  those two and refuses chunked (502). Rejected: a chunked decoder.
- "One in flight per client certificate" is enforced per client **identity**:
  two certificates for the same node id share the slot. Stricter, and a relay
  never sends two at once.
- The relay serves one local connection at a time and has no idle timeout on
  it. A new local connection replaces an idle one at once, and waits for the
  answer if a request is in progress (at most the 10 s request timeout). A
  local process can therefore make the node's requests fail, which is the DoS
  the spec accepts, but cannot park an idle connection and block the node's
  client forever. Rejected: an idle timeout, which would also fail the node's
  first command after every quiet period. Use one relay per `yubihsm::Client`.
- The relay never retries a failed exchange: a command the device may have run
  must not be replayed. It replaces a pooled connection the gateway has closed
  (checked without blocking before each send) or one idle for 30 s, below the
  gateway's 60 s idle timeout.
- The relay answers the local client with the whole response in one write and
  the exact `HTTP/1.1 200 OK` / `Content-Length: ` lines: `yubihsm` 0.42's reader
  assumes one read and matches those strings literally.
- The connector URL must be `http://` on a loopback **IP literal**;
  `localhost` and names are refused, since DNS could repoint them.
- No CRL: a node's link certificate is revoked by removing it from
  `allowed_clients` (with its device auth keys, phase 4).
- The flag is `--config`, as for `bvault server`; clap has no single-dash long
  options.

Not done in phase 3, deliberately:

- `bv-core` does not start relays, so a `yubihsm2` pool is still refused. Phase 4
  wires one relay per member client and adds `spawn_blocking` around the
  blocking `yubihsm` client.
- The "real `yubihsm` MockHsm exchange over mTLS" link test needs a
  `yubihsm::Client` and belongs with that wiring; the crate's tests drive the
  gateway and relay with a fake connector and the exact client wire format.
  The connector's real reply framing is confirmed on hardware in phase 7.
- `bv_hsm_link_requests_total{member,code}` was not exported in phase 3 (phase 6 exports it from the relay totals); `GatewayStats`
  and `RelayStats` hold the counters (phase 6).

Phase 2:

- **`HsmPool`** (`crates/bv-core/src/hsm/pool.rs`). Members are ordered per node
  by `SHA-256(node_id ‖ hsm_id)`, or `prefer = true`. Reads go through a
  `ReadAttempt` the caller drives, so the per-member steps (counter,
  authorization, unwrap) stay at the call site. One function, `classify`,
  decides failover: AAD, authorization and MAC failures (`ErrHsmContextMismatch`,
  `ErrHsmAuthzInvalid`, `ErrHsmBlobInvalid`) stop the read and raise
  `hsm.crypto_failure`; transport (`ErrHsmTransport`), `SESSIONS_FULL` and other
  device errors fail over. Writes wrap on every usable member concurrently and
  need `min_wrap_copies` copies, else `ErrHsmInsufficientCopies { have, need,
  unreachable }`. A device that is not the member it is opened as is `faulted`.
- **Health.** Breaker: down after 3 consecutive transport failures, retried
  after 1 s doubling to 60 s; `probe_all` (`device-info`, no session) every
  10 s from a background task, honouring the backoff. `SESSIONS_FULL`: that
  member is skipped for 100 ms → 5 s with jitter, the other one is tried, and it
  does not open the breaker. Time is an injected `Clock` (`hsm/clock.rs`), so
  the tests use a manual clock and never sleep.
- **Mock** (`hsm/mock.rs`). Split into `MockHsmDevice` (object store, session
  table, link state) and `MockHsmBackend` (one client, one session owner). The
  device holds 16 sessions, expires one after 30 s idle, answers
  `SESSIONS_FULL`, and can be set offline. A new device takes the configured
  serial; an existing one keeps its own.
- **Config** (`hsm/mod.rs`, `config.rs`). `topology = "pool"` with exactly two
  `member` blocks, the rules in [Configuration](#configuration), and the storage
  gate (hiqlite, or a single-node local `file` backend), checked both at config
  resolution and on the physical backend the provider is given.
- **Seal path** (`seal/hsm.rs`). Pool init requires both members reachable and an
  explicit `recovery`; `shamir-ceremony` is refused as phase 5. It writes a v2
  record with `topology = pool` under the `hsm-custody` lock and refuses to
  overwrite an existing record. Pool unseal is the [Unseal flow](#unseal-flow-pool-topology),
  with the authorization checked against the `bv-authz` key the record pins for
  the member. A per-node node refuses a pool record and a pool node refuses a
  per-node record, each with an explicit error.
- **Custody store** runs over an `HsmPool`: a one-member pool for a per-node
  device, the two-member pool otherwise. Seed inputs come from the preferred
  reachable member; the seed is wrapped on every member.
- **`Storage::lock` / `Backend::lock` return a `Send` guard**, so custody
  `create` / `delete` futures are `Send` (a compile-time test asserts it).
- **Status and metrics.** `v2/sys/hsm/status` reports `topology`, per-member
  `{state, up, faulted, serial, last_error, holds_kek_copy}`,
  `under_replicated_sets` (the KEK set) and `min_wrap_copies`.
  `bv_hsm_member_up{member}`, `bv_hsm_session_errors_total{member,kind}` and
  `bv_hsm_under_replicated_sets` are in `bv-metrics`.

Phase 1:

- **Blob v2** (`crates/bv-core/src/hsm/blob.rs`). The AAD binds `hsm_id` and
  `authz_alg`; `HsmBackend::hsm_id()` / `device_binding()` supply them from the
  device. Every new wrap is v2; v1 still opens. A v2 blob for another `hsm_id` is
  refused before the device is called. The YubiHSM 2 backend now fails to open if
  it cannot read the device serial, because the serial is part of `hsm_id`.
- **Blob set v1** (`hsm/blobset.rs`). Copies are keyed by `hsm_id` and must be v2,
  bound to their key, with the set's purpose and epoch. Duplicate map keys are
  rejected, not shadowed. The `recovery` envelope is structurally validated and
  never written yet.
- **Seal record v2** (`crates/bv-core/src/seal/hsm/record.rs`). v1 loads as
  `per-node` with `legacy_node_blobs` (byte-for-byte), and the first write produces
  v2. Unsealing does not write. A fresh per-node init stores the KEK as a one-copy
  v2 set. Fixture: `crates/bv-core/src/seal/testdata/hsm-seal-v1/`, captured from
  the pre-T454 code.
- **Per-node authz counters** at `core/hsm-authz-counter/<node_id>`, seeded above
  the legacy global key, which is left in place. A non-decimal counter is an error
  (the old code silently reset it to 0). `node_id` must be 1–128 characters of
  `[A-Za-z0-9._-]`, because it names this key.
- **Recovery.** Per-node + `recovery = "shamir-ceremony"` is refused at init, through
  a new `SealProvider::check_init` that `Core::init` calls before anything is
  written. An already-initialized cluster with that config keeps starting, logs at
  `error` on every unseal, and status reports `recovery_requested` /
  `recovery_configured: false`.
- **Custody store** (`hsm/custody_store.rs`). `BvHsmHandle { version: 1, key_id }`;
  `create`, `with_private`, `delete` and `replication_report` over
  `core/hsm/custody/<key_id>` in the barrier. Writes take the `hsm-custody` lock;
  use goes through the session cache that `custody.rs` used to own. The
  `custody.rs` providers take handles, and `derive.rs` takes the ECDH key id.

Decisions made in phase 1 where this spec left room:

- `kek` is optional in the v2 record: a record converted from v1 has no v2 copy,
  only `legacy_node_blobs`, and a set with no copies is invalid.
- The custody API is `create(kind: PqcKeyKind)`, not `create(purpose, alg)`: the
  pair admits invalid combinations such as `BarrierKek` + ML-KEM-768.
- A custody record also stores its `key_id` (a record copied to another key is
  refused) and the public key (every use checks that the unwrapped seed derives it).
- Per-node unseal picks exactly one copy: the v2 copy for this device, else this
  node's legacy v1 blob. A failure on that copy is not retried on the other.
- PQC custody unwraps keep the process-local authorization counter they had
  before; only the barrier unwrap uses the persisted per-node counter.

Phase 1 left three items to phase 2, all now closed: the storage gate, the `Send`
lock guard, and `hsm-custody` around the seal-record write (pool init takes it).

Decisions made in phase 2 where this spec left room:

- `SESSIONS_FULL` never sleeps on the request path: the member gets a jittered
  "not before" window and the other member is tried at once. If both are
  unusable the operation fails, naming each member. Rejected: sleeping and
  retrying inside unseal, which hides saturation and stalls the caller.
- Only `ErrHsmTransport` counts towards the breaker. Other device errors fail
  over but do not open it, and `SESSIONS_FULL` has its own backoff.
- Unseal takes a fresh per-node counter for each member it tries, so every
  authorization is distinct. A counter storage failure is returned as is, not
  booked against a member.
- The authorization is checked against the `bv-authz` key the seal record pins
  for the member, before the unwrap rather than after (stricter than step 3.5).
- Unavailability is a new `ErrHsmPoolUnavailable(String)` naming each member,
  not a payload on `ErrHsmUnavailable`, which mock and per-node code use as a
  unit variant. New `ErrHsmTransport` and `ErrHsmSessionsFull` let backends say
  what failed; the YubiHSM 2 backend maps connector and session errors, device
  `SESSIONS_FULL`, and an `unwrap-data` `INVALID_DATA` (a CCM tag failure; to be
  confirmed on hardware in phase 7) to them.
- Mock members are reached by `state_path` and take no `gateway` / `connector`;
  `serial` is required for both backends because it forms the member's `hsm_id`
  even while the device is unreachable.
- `device_audit` and `repair_rate` were refused, not ignored, until phases 6 and 4
  (both are accepted now).
- The record's `seed_ecdh_pub` holds the member's `bv-identity` key, which is what
  the mock and today's layout use for the seed ECDH; `bv-seed-ecdh` is phase 4.
- Pool init uses the session the node's member client already has; per-node
  credential delivery is phase 4. Event delivery is the `security` log through a
  `PoolEventSink`; an audit-broker sink is phase 6.

Not done in phase 2, deliberately:

- Custody sets are not counted in `v2/sys/hsm/status` (the provider has no
  barrier); `CustodyStore::replication_report` counts them and feeds the metric.
  No engine uses the custody store yet, so the only live set is the KEK.
- Membership is re-read from the record on every unseal and status call, not on
  a 30 s timer: nothing writes membership until phase 4.
- `close_sessions` exists but is not yet called on seal or shutdown.
- "Parallel" wrap runs the member futures concurrently on one task. The
  YubiHSM 2 client is blocking, so its pool wraps will need `spawn_blocking`
  when the link lands (phase 3).

## Implementation phases

| Phase | Scope | Main files | Status |
|---|---|---|---|
| 1. Formats and custody core | `BvHsmBlob` v2, `BvHsmBlobSet`, seal record v2 + v1 reader, per-node authz counters, custody store and handles. Mock only. | `crates/bv-core/src/hsm/{blob,blobset,custody_store}.rs`, `crates/bv-core/src/seal/hsm.rs`, `crates/bv-core/src/seal/hsm/record.rs` | Done |
| 2. Pool backend | `HsmPool`: members, preference, failover, health probe, circuit breaker, parallel wrap, `min_wrap_copies`. Mock enforces the 16-session limit and `SESSIONS_FULL`. Pool init and unseal, storage gate, status, metrics. | `crates/bv-core/src/hsm/{pool,clock,mock,yubihsm2,mod}.rs`, `crates/bv-core/src/seal/hsm.rs`, `crates/bv-metrics/src/hsm_metrics.rs` | Done |
| 3. HSM link | `bv-hsm-link` crate (gateway + relay), `bvault hsm-gateway` | `crates/bv-hsm-link/`, `crates/bvault-cli` | Done |
| 4. Ceremonies and repair | `provision`, attestation chain pinning, node enroll/revoke with credential delivery, member add/retire, repair job, epoch rotation, `migrate-to-pool`, v2 routes, CLI | `crates/bv-core/src/hsm/{admin,ceremony,node_creds,repair}.rs`, `crates/bv-core/src/seal/hsm/pool_admin.rs`, `crates/bv-kernel/src/modules/system/`, `crates/bvault-cli` | Done (mock; Yubico attestation pinning and device validation moved to phase 7) |
| 5. Recovery | Recovery keypair, Shamir split, recovery copies, `recover` route | `crates/bv-core/src/hsm/recovery.rs`, `crates/bv-core/src/seal/hsm/recovery_ceremony.rs`, `crates/bv-server/src/sys.rs`, `crates/bvault-cli` | Done (mock; the YubiHSM 2 ceremony waits on phase 7 attestation) |
| 6. Audit and observability | Device-log drain, events, metrics, status, GUI page, `docs/hsm.md`, `docs/api.md` | `crates/bv-core/src/hsm/device_audit.rs`, `crates/bv-core/src/seal/hsm/device_drain.rs`, `gui/src/routes/HsmStatusPage.tsx` | Done (mock; the YubiHSM 2 drain waits on phase 7) |
| Amendment: pool of one (2026-10-27) | One or two members; init, bootstrap and unseal with one; `acknowledge_single_member_without_recovery`; at most two members not retired; redundancy status, event and metric | `crates/bv-core/src/hsm/{mod,pool}.rs`, `crates/bv-core/src/seal/hsm.rs`, `crates/bv-core/src/seal/hsm/pool_admin.rs`, `crates/bv-metrics/src/hsm_metrics.rs` | Done (mock; YubiHSM 2 with phase 7) |
| 7. Hardware validation | Two physical devices plus three nodes; pin the Yubico attestation chain and lift the YubiHSM 2 attestation refusal; validate `provision`, bootstrap, enrollment and the relay; confirm the device log layout, digest chain and forced audit, and lift the YubiHSM 2 drain refusal; measure latencies; confirm the FIPS Ed25519 question; **end every run by factory-resetting both devices and checking they provision again** (see [Resetting the test devices](#resetting-the-test-devices)) | `crates/bv-core/src/hsm/{attestation,yubihsm2}.rs`, `crates/bv-core/src/hsm/hw_validation/`, `crates/bv-core/tests/hsm_pool_hardware.rs` (feature `hsm_hardware_tests`, behind `BVAULT_TEST_YUBIHSM_POOL=1`), `docs/hsm.md` | Prepared, awaiting hardware run (attestation pinning and the suite done on the mock; no device run yet) |

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
- Pool of one: init and unseal with one member; a node without a device
  unseals through it; `recovery = "none"` without the acknowledgement refused;
  the second member added later and repaired, then either device alone
  unseals; a third member refused; the last member never retires; status,
  events and metric report `redundancy: "none"`; an old two-member record
  loads unchanged.

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

### Resetting the test devices

Phase 7 runs on two physical devices that must return to a known state
afterwards. Checked against Yubico's
[reset guide](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-reset-to-factory.html)
(not yet exercised on a device):

- **Physical reset always works.** Press the metal rim while inserting the
  device and keep pressing for at least 10 seconds. It needs no credential,
  so it is the recovery path whatever state `provision` left the device in.
- **Software reset does not work after `provision`.** The `RESET DEVICE`
  command (`yubihsm-shell` `reset`, or `yubihsm-manager reset`) needs an
  authentication key with the `reset-device` capability. No key in the layout
  above carries it (`bv-admin` is limited to the capabilities of the objects
  it manages) and `provision` deletes the factory key, so the software route
  is unavailable on a provisioned device. This is deliberate: a leaked
  `bv-admin` credential must not be able to wipe the pool. Do not add the
  capability for test convenience.
- A reset destroys every object that is not factory-installed, restores the
  default authentication key and options, and so makes the device accepted by
  `provision` again.

Phase 7 acceptance: after the run, both devices are reset by the physical
method, `provision` succeeds on each from scratch, and a device that is only
reset (not re-provisioned) is reported `faulted` by a running node, as the
failure-mode table requires. The operator must be at the machine for the
10-second press; the run cannot do it unattended.

### Phase 7 must leave the devices in factory state

The two devices are reused for the production cluster, whose `provision`
ceremony refuses any device that is not in factory state. Phase 7 therefore
passes only when the final check below succeeds; a green functional run on a
device that fails it is a failed phase.

- **Reversible operations only.** The run must not update firmware, must not
  turn on FIPS mode (Yubico documents it as available right after a reset and
  leavable by a reset, but the model and its behaviour are confirmed first),
  and must not set command audit to an enforced value (a
  [third-party note](https://gist.github.com/karalabe/fb7ac43f3899f511b5547279c036bf4e)
  says only a reset clears it; confirm against Yubico's own page before any
  forced-audit test). Each of these is a separate, explicitly approved step.
- **Before/after snapshot.** Record serial, firmware version, options and the
  object list on each device before the first write, and diff against the
  same read after the reset. The expected difference is none.
- **Final check, read-only.** After the physical reset, authenticate with the
  factory key and confirm: only the factory-installed objects exist, options
  are the defaults, and the BastionVault `provision` preflight accepts the
  device (the factory key 1 present, no other objects). The check never
  writes, so it cannot spoil the state it verifies.
- **Same ceremony as production.** The production cluster starts with
  `provision`, `bootstrap` and `init`; the run ends exactly one step before
  that, so no test identity, member entry or node credential survives on a
  device or in a seal record.
- A reset device is open to the public factory password until `provision`
  runs. Keep the devices off any shared host between the reset and the
  production `provision`.

### Phase 7 test devices: "before" snapshot

Read on 2026-10-27 through a local `yubihsm-connector`, authenticating with
the factory key only. Part number 78CLUFX5000P, firmware 2.4.1 on both.

| | 36470559 | 36470560 |
|---|---|---|
| Objects | `0x0001` factory key only (read) | `0x0001` factory key only (read) |
| `force-audit` | `00` (assumed) | `00` (read) |
| `command-audit` | all 65 commands `00` (assumed) | all 65 commands `00` (read) |
| `algorithm-toggle` | all 55 algorithms enabled (assumed) | all 55 algorithms enabled (read) |
| `fips-mode` | assumed absent | rejected as malformed: not a FIPS model |
| Storage | assumed 255/256 records, 1023/1024 pages | 255/256 records, 1023/1024 pages (read) |
| Log used | 7/62 | 9/62 |

"Assumed" means the operator declared device 36470559 identical to 36470560
and its options were not read. The post-reset comparison for that device
uses the values above as expectations; a mismatch there cannot tell a device
that was changed by the run from one that was already different, so read its
options and storage before the first write if that distinction matters.
After the reset, both devices must read as the table says (log counters
aside).
