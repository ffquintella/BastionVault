# HSM Support (YubiHSM 2)

BastionVault can anchor its master key, post-quantum key custody, and every
key-release decision in a hardware security module. The mandated device is the
**YubiHSM 2** (one per cluster node). A software **mock** backend implements the
same interface for development and homologation, where no hardware is available.

With an HSM seal configured, BastionVault **auto-unseals** at startup — no
operator share entry — and no persisted key material is decryptable without the
key inside an enrolled device.

> Security posture at a glance
>
> - The KEK and all PQC seeds are wrapped by the HSM; nothing on disk decrypts
>   without the device.
> - Every unwrap is gated by an HSM-signed, replay-resistant, audited
>   authorization.
> - **No software recovery path by default.** Losing every cluster HSM loses the
>   vault — this is the intended guarantee. Opt into an escrow ceremony at init
>   only if you accept the trade-off.
> - The mock backend provides **zero** hardware protection and refuses to start
>   in production.

---

## Quick start (development, mock backend)

The mock backend is intended for dev/CI/homolog only and needs a writable state
file. The **official container image already bundles both HSM backends**
(`hsm_mock` + `hsm_yubihsm2`), so no special build is required there — the mock
still refuses to start when the environment is production. For a local
`cargo`/CLI build (which ships neither backend by default) enable the feature
explicitly:

```bash
cargo build -p bvault-cli --features hsm_mock --bin bvault
```

Add an `hsm "mock"` block to your config (e.g. `config/dev.hcl`):

```hcl
storage "file" {
  path = "/var/lib/bastionvault/data"
}

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = "true"
}

# Dev / homolog ONLY. Bundled in the official image (and in any build with the
# `hsm_mock` feature); refuses to start when the environment is production.
hsm "mock" {
  state_path = "/var/lib/bastionvault/mock-hsm.json"
  node_id    = "dev-node-1"
}
```

Then:

```bash
# 1. Start the server — it detects the hsm block and opens the mock device.
bvault server --config=config/dev.hcl

# 2. Initialize once. With an HSM seal the KEK is wrapped under the device and
#    NO unseal shares are returned (auto-unseal takes over on every restart).
bvault operator init

# 3. Restart the server — it auto-unseals with no operator input.
#    Confirm the seal posture:
bvault operator hsm status
```

`operator init` prints a warning making the recovery posture explicit, and the
server logs `HSM auto-unseal succeeded` on subsequent starts.

---

## Production (YubiHSM 2)

Build with the hardware backend feature:

```bash
cargo build -p bvault-cli --features hsm_yubihsm2 --release --bin bvault
```

This pulls the pure-Rust `yubihsm` crate and its USB (libusb) dependency. Each
node needs its own YubiHSM 2, reachable either over the
[`yubihsm-connector`](https://developers.yubico.com/yubihsm-connector/) or via
direct USB.

Provide the auth-key password out-of-band via an environment variable — never
in the config file:

```bash
export BVAULT_HSM_PASSWORD='...'          # read via env: reference below
export BVAULT_ENV=production               # blocks the mock backend
```

Config:

```hcl
hsm "yubihsm2" {
  connector          = "http://127.0.0.1:12345"   # yubihsm-connector, or "usb"
  auth_key_id        = 3
  password           = "env:BVAULT_HSM_PASSWORD"   # plaintext is rejected
  domains            = [1]
  pqc_key_cache_ttl  = "60s"                        # "0" = strict per-op unwrap
  recovery           = "none"                       # or "shamir-ceremony"
  node_id            = "node-a"

  # Optional: override the per-node object ids (defaults shown).
  # wrap_barrier_key_id = 2
  # wrap_pqc_key_id     = 3
  # identity_key_id     = 4
  # authz_key_id        = 5
}
```

Start the server; it opens the device, installs the auto-unseal provider, and
(after `operator init`) unseals automatically on every boot.

---

## Configuration reference

The seal is configured with a single `hsm "<backend>" { … }` block. `<backend>`
is either `yubihsm2` or `mock`. At most one block may be present; more than one
is a startup error. With no block, BastionVault uses the classic Shamir
operator-unseal.

| Key | Backend | Required | Default | Description |
|---|---|---|---|---|
| `connector` | yubihsm2 | Yes | — | `yubihsm-connector` URL (`http://host:port`) or `usb`. |
| `auth_key_id` | yubihsm2 | Yes | `1` | HSM authentication-key object id. |
| `password` | yubihsm2 | Yes | — | Auth credential. Supports `env:VAR`; plaintext is rejected. |
| `domains` | yubihsm2 | No | `[1]` | YubiHSM domains for BastionVault objects. |
| `state_path` | mock | No | *(ephemeral)* | File backing the mock object store. Empty ⇒ in-memory only. |
| `node_id` | both | No | `$HOSTNAME` | Stable node identity used in context strings and per-node key routing. Set explicitly in clusters. 1–128 characters of `[A-Za-z0-9._-]` (it names the node's unwrap-counter key). |
| `pqc_key_cache_ttl` | both | No | `60s` | TTL for the unwrapped-seed session cache. `0` disables caching (strict per-operation unwrap). |
| `recovery` | both | No | `none` | `none` or `shamir-ceremony`. **Honored only at `init`; cannot be enabled later.** `shamir-ceremony` is refused at `init` in the per-node topology (see below). |
| `topology` | both | No | `per-node` | `per-node` or `pool`. The pool keys (`member`, `min_wrap_copies`, `link`, `credential_dir`) are in [configuration.md](configuration.md#hsm-pool-topology-topology--pool); see [Pool topology](#pool-topology-two-devices-for-the-cluster). |

### Recovery modes

- `recovery = "none"` (default) — no software escrow. If every cluster HSM is
  lost, the vault is unrecoverable. This is the documented, intended guarantee.
- `recovery = "shamir-ceremony"` — **not available in the per-node topology.**
  Earlier builds accepted it, logged a warning, and generated no recovery key
  and no shares. `operator init` now refuses it with an error naming
  [HSM pool HA](../features/hsm-pool-ha.md#recovery-shamir-ceremony), where the
  recovery copy is defined (T454). A per-node cluster that was initialized
  with it keeps starting, logs an `error` on every start, and reports
  `recovery_requested: "shamir-ceremony"`, `recovery_configured: false` in
  `v2/sys/hsm/status`. No recovery exists for it; treat it as `none`.

### Per-node HSM objects

Each device is provisioned with five minimal-capability objects:

| Label | Type | Capabilities | Purpose |
|---|---|---|---|
| `bv-auth-<node>` | Auth key | session auth | Application login to the device. |
| `bv-wrap-barrier-<node>` | AES-256 wrap | wrap/unwrap (no export) | Wraps the barrier KEK (auto-unseal). |
| `bv-wrap-pqc-<node>` | AES-256 wrap | wrap/unwrap (no export) | Wraps PQC seeds (separate from the barrier key). |
| `bv-identity-<node>` | ECC P-256 | sign-ecdsa, derive-ecdh, attest | Node identity, replication ECDH, attestation. |
| `bv-authz-<node>` | Ed25519 | sign-eddsa | Signs every unwrap authorization. |

Wrap keys never carry `exportable-under-wrap`; identity keys cannot unwrap;
authz keys can only sign.

---

## Operations

### Check seal status

```bash
bvault operator hsm status
```

or over HTTP:

```
GET /v2/sys/hsm/status
```

Returns the active seal type and, for an HSM seal, the backend, device serial
and `hsm_id`, cluster epoch, topology, enrolled-node count, the recovery mode
requested in config and whether a recovery key actually exists, the stored
seal-record version, and the cache TTL. In the pool topology it lists each
member (`state`, `up`, `serial`, `last_error`) with `min_wrap_copies` and
`under_replicated_sets` instead of one device. Read-only; never returns secret
material. See the [API reference](api.md#hsm-seal-status).

### Upgrading to the T454 formats

- **Seal record.** A record written before T454 (`seal_record_version: 1`)
  keeps unsealing; it is read as `topology = per-node` and converted to v2 by
  the first write. Unsealing does not write it. A vault initialized by this
  build has a v2 record, and an older build cannot unseal it.
- **Blobs.** New blobs bind the device (`hsm_id`) instead of the node, so any
  node can open a copy through the same device. Old node-bound blobs still open.
- **Unwrap counters.** Each node now keeps its own counter at
  `core/hsm-authz-counter/<node_id>`, started above the old cluster-wide
  `core/hsm-authz-counter`, which is left in place and no longer written. A
  counter that is not a decimal integer is an error, not a reset to 0.

### Clustering

Every node has its own physical device, so shared key material (the KEK, PQC
seeds) is stored **once per node**, each copy wrapped by that node's own HSM.

- **Bootstrap** — the first node creates a signed *custody root* record: the
  trust anchor all later enrollments chain to.
- **Enrollment** — a joining node presents a YubiHSM 2 **attestation** bundle
  for its identity and authz keys, proving in-device generation and
  non-exportability. The sponsor verifies the attestation and pins the new
  node's keys.
- **Key transfer** — the sponsor and joiner establish an ECDH-derived,
  transcript-bound encrypted channel; the sponsor sends each secret, the joiner
  immediately re-wraps it under its own device and zeroizes the plaintext. Both
  HSMs sign the migration transcript. Plaintext never touches the wire or
  storage.
- **HSM loss** — a node that loses its device re-enrolls as a fresh joiner;
  nothing on its disk was decryptable without the old device. Recovery comes
  from its peers, not from any software escrow.

### Pool topology (two devices for the cluster)

`topology = "pool"` lets every node use the same two devices
([HSM pool HA](../features/hsm-pool-ha.md), T454). This build implements the
pool itself on the **mock** backend (phase 2 of 7); the network link to remote
devices, node enrollment, repair and recovery come in later phases.

- **Init** needs both members reachable and an explicit `recovery`. The KEK is
  wrapped on each member at once and stored as a two-copy set in a v2 seal
  record with `topology = pool` and both members `active`. `recovery =
  "shamir-ceremony"` is refused until the recovery copy exists (phase 5).
- **Unseal** tries the members in this node's preference order
  (`SHA-256(node_id ‖ hsm_id)`, or `prefer = true`). On a member it takes a
  fresh per-node counter, gets a signed unwrap authorization, checks it was
  made by the `bv-authz` key the seal record pins for that member, and
  unwraps. A transport, session or device failure moves on to the other
  member. If no member answers, the node stays sealed with an error naming
  each member; it never uses a recovery copy, a cache or a software path.
- **Tampering is not an outage.** An AAD, authorization or MAC mismatch stops
  the operation on that member and is **not** retried on the other one. It
  raises `hsm.crypto_failure` on the `security` log target (the audit broker
  is not up before unseal; audit delivery is phase 6) and counts in
  `bv_hsm_session_errors_total{kind="crypto"}`.
- **Circuit breaker.** Three consecutive transport failures mark a member down
  (`hsm.member_down`, `bv_hsm_member_up{member}=0`). Operations skip it; it is
  retried after 1 s, then 2, 4, … up to 60 s. A health probe (`device-info`)
  runs every 10 s and brings it back (`hsm.member_up`). A member whose device
  reports another serial than the record is `faulted` and stays down.
- **`SESSIONS_FULL`.** A device holds 16 sessions. When it is full the node
  backs off from that member for 100 ms → 5 s, with jitter, and uses the other
  one. It is counted as `kind="sessions_full"`; it does not open the breaker.
- **Key creation with one member down** stores one copy and reports the set
  as under-replicated (`hsm.set_under_replicated`,
  `bv_hsm_under_replicated_sets`), unless `min_wrap_copies = 2`, which refuses
  it. `repair` fills those sets (below).
- **Storage.** Every blob-set and membership write takes the `hsm-custody`
  lock, so the pool is accepted only on hiqlite or a single-node local `file`
  backend.

The mock pool is for dev and homolog. Its session limit is per process: two
processes that open the same `state_path` are two devices as far as sessions go.

#### Ceremonies (phase 4 part 1, mock)

A provisioned device (factory key deleted, `bv-admin` created) takes only
authenticated sessions: each node has its own random credential per device,
and revoking a node deletes it on the device. Ceremonies need a sudo token and
the `bv-admin` credential of each member they touch, given per request with
`--admin <member>` (prompted on the TTY) or `--admin <member>=env:VAR`; a
literal value is refused, and nothing stores, logs or returns it.

~~~bash
# On each HSM host (mock: a state file), from factory state:
bvault operator hsm provision --mock-state-path /var/lib/bv/hsm-a.json --serial MOCK-A --out a.json
# On the init node, before `operator init`: attest both devices, enroll this node.
bvault operator hsm bootstrap --bundle hsm-a=a.json --bundle hsm-b=b.json --admin hsm-a --admin hsm-b
bvault operator init

# A node with `credential_dir` logs its transport key fingerprint at startup.
# Confirm it out of band, then enroll it on every member:
bvault operator hsm node add vault-2 --fingerprint <fp> --admin hsm-a --admin hsm-b
bvault operator hsm node list
bvault operator hsm node revoke vault-2 --admin hsm-a --admin hsm-b

# Replace a failed device: attest and add it, repair, promote, retire the old one.
bvault operator hsm member add hsm-b2 --bundle b2.json --admin hsm-b2
bvault operator hsm repair --run
bvault operator hsm repair --run --admin hsm-a --admin hsm-b2   # promotes hsm-b2
bvault operator hsm member retire hsm-b
bvault operator hsm repair --run                                # drops hsm-b's copies
~~~

- **At most 12 nodes** are enrolled at once (the device session budget); the
  13th is refused until one is revoked.
- **Revoking with a member down** records a *pending revocation* on it. Every
  node then treats that member as down, even after it returns, until a
  ceremony with its admin credential (`node revoke` again or `repair --run
  --admin`) deletes the key. Update the down host's gateway `allowed_clients`
  before it comes back: a revoked node that reaches it first through a gateway
  that still allows it can use it until the key is deleted.
- **Repair** re-wraps at most `repair_rate` sets per second (default 2) and
  never drops the last copy of a set. It runs every 5 minutes, within 10 s of
  a member coming back, and on demand.
- **Bootstrap** answers only a loopback peer and only before init; init then
  refuses a member that was not attested or whose keys changed.
- **Layout:** `bv-identity` is admin-only (domain 2); nodes derive seeds with
  `bv-seed-ecdh` (object 6 by default, `seed_ecdh_key_id`).
- **Audit:** pool events reach the audit log at
  `sys/hsm/events/<event>/<member>` once it is up, and the `security` log always.
- **YubiHSM 2 pools** start and reach members through the link, but attesting a
  YubiHSM 2 is refused until the Yubico attestation chain is pinned, so
  bootstrap and `member add` stop there; nothing on the device path is
  verified on hardware yet (phase 7).
- **Not yet:** epoch rotation and `migrate-to-pool`.

### Failure behavior (fail-closed)

An unreachable or unenrolled HSM keeps the node **sealed** — it never opens the
vault on a degraded device. Cluster HA covers single-node HSM failures; monitor
HSM session errors so you can react before quorum is threatened. In the pool
topology, one member down is not an outage; both down keeps restarted nodes
sealed while already-unsealed nodes keep serving barrier data.

---

## Security notes

- **Runtime PQC exposure.** The YubiHSM 2 cannot execute ML-KEM / ML-DSA, so PQC
  private keys exist transiently in host memory during use and enrollment.
  Mitigations: `Zeroizing` buffers, a bounded (or disabled) session cache, and
  no `Clone`/`Debug` on key types. The at-rest and custody guarantees are
  absolute (HSM-gated); the runtime guarantee is best-effort. Set
  `pqc_key_cache_ttl = "0"` for strict per-operation unwrap.
- **Attestation is the enrollment trust root.** Enrollment verifies the device
  attestation before any key material moves. On real hardware, pin the Yubico
  attestation root CA before production enrollment.
- **Credentials.** The auth-key password is read via `env:` (or the OS keychain
  in GUI/embedded mode); plaintext credentials in config are rejected outside
  dev builds.
- **Mock ≠ security.** The mock backend is compile-time gated (`hsm_mock`),
  provides no hardware protection, and refuses to start in production. Release
  artifacts must not enable it.

See [`features/hsm-support.md`](https://github.com/ffquintella/BastionVault/blob/main/features/hsm-support.md)
for the full design and the non-negotiable security rules.
