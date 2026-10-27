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
| `recovery` | both | No | `none` | `none` or `shamir-ceremony`. **Honored only at `init`; cannot be enabled later.** `shamir-ceremony` is refused at `init` in the per-node topology and by `migrate-to-pool` (see below). |
| `topology` | both | No | `per-node` | `per-node` or `pool`. The pool keys (`member`, `min_wrap_copies`, `link`, `credential_dir`) are in [configuration.md](configuration.md#hsm-pool-topology-topology--pool); see [Pool topology](#pool-topology-two-devices-for-the-cluster). |
| `attestation_roots_file` | yubihsm2 | For attestation | — | PEM file of the Yubico attestation root and intermediates. Unset ⇒ every YubiHSM 2 attestation is refused. See [Yubico attestation trust file](#yubico-attestation-trust-file). |

### Yubico attestation trust file

A YubiHSM 2 attests a key by signing a certificate for it with the device's
attestation key, whose own certificate (opaque object 0, read by `provision`)
Yubico signs through an intermediate under its root. BastionVault verifies
that chain against a trust file **you supply**: it does not ship the Yubico
certificates and never downloads them.

1. Download the YubiHSM attestation root and intermediate certificates from
   Yubico (<https://developers.yubico.com/YubiHSM2/Concepts/Attestation.html>)
   on a trusted machine, and check their SHA-256 fingerprints against the
   values Yubico publishes.
2. Concatenate them into one PEM file (certificates only; any other block,
   such as a key, is refused) and point `attestation_roots_file` at it on
   every node that runs `bootstrap`, `member add` or `recover`.
3. The file needs no secrecy, only integrity: make it root-owned and
   read-only.

What is checked, for each attested key (`bv-identity`, `bv-seed-ecdh`,
`bv-authz`): the bundle holds exactly the key certificate and the device
certificate (intermediates come from the trust file, never from the device);
each link's signature, validity at the current time, X.509 v3 and an accepted
algorithm (SHA-2 RSA PKCS#1, ECDSA P-256/P-384, Ed25519; SHA-1 and RSA-PSS are
refused); every trust-file certificate on the path is a CA allowed to sign
certificates; the path ends at a self-signed root in the file; the key was
generated on the device (origin); and its serial, object id, label, domains,
capabilities and algorithm are exactly what `provision` created on the device
reached. The `security` log names the root fingerprint each attestation
reached. A missing, unreadable or rootless trust file is an error naming the
file, never an empty trust set.

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
- `recovery = "shamir-ceremony"` in the **pool** topology (T454 phase 5) — see
  [Recovery](#recovery-pool-topology-shamir-ceremony) below. This is the one
  explicit software break-glass path: a quorum of share holders together
  with a copy of storage can decrypt everything.

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
member (`state`, `up`, `serial`, `last_error`) with `min_wrap_copies`,
`under_replicated_sets` and the pool's `redundancy` (`full`, or `none` for a
pool of one, with a `redundancy_warning`) instead of one device. Read-only; never returns secret
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

`topology = "pool"` lets every node use the same devices, at most two
([HSM pool HA](../features/hsm-pool-ha.md), T454). A cluster can start with one
and add the second later ([Starting with one HSM](#starting-with-one-hsm-a-pool-of-one)).
This build implements the pool on the **mock** backend; the YubiHSM 2 path
compiles and waits for the [phase 7 run](#phase-7-hardware-validation-t454).

- **Init** needs every configured member reachable and an explicit `recovery`.
  The KEK is wrapped on each member at once and stored as a set with one copy
  per member in a v2 seal record with `topology = pool` and the members
  `active`. With two members configured and one unreachable, init is refused:
  it never becomes a pool of one on its own. With `recovery =
  "shamir-ceremony"` it also creates the recovery key and returns its shares
  (see [Recovery](#recovery-pool-topology-shamir-ceremony)).
- **Unseal** tries the members in this node's preference order
  (`SHA-256(node_id ‖ hsm_id)`, or `prefer = true`). On a member it takes a
  fresh per-node counter, gets a signed unwrap authorization, checks it was
  made by the `bv-authz` key the seal record pins for that member, and
  unwraps. A transport, session or device failure moves on to the other
  member. If no member answers, the node stays sealed with an error naming
  each member; it never uses a recovery copy, a cache or a software path.
- **Tampering is not an outage.** An AAD, authorization or MAC mismatch stops
  the operation on that member and is **not** retried on the other one. It
  raises `hsm.crypto_failure` on the `security` log target (and in the audit
  log once the audit broker is up, which it is not before unseal) and counts
  in `bv_hsm_session_errors_total{kind="crypto"}`.
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

#### Starting with one HSM (a pool of one)

A pool can come up with **one** device and get the second one later as
redundancy. The cluster never holds more than two.

> **A pool of one is a single point of failure.** Losing that device (failure,
> a factory reset, loss) loses every HSM-protected secret and so the vault,
> unless a recovery copy exists (`recovery = "shamir-ceremony"`, chosen at
> init). Add the second device as soon as you can.

1. **Config: list only the device you have.** One `member` block,
   `min_wrap_copies = 1` (the default; `2` is refused with one member), and an
   explicit `recovery`. With `recovery = "none"`, also set
   `acknowledge_single_member_without_recovery = true`, which states that
   you accept losing the vault with that device; without it bootstrap and init
   are refused.

   ~~~hcl
   # On the HSM host: the device is local, so no mTLS.
   hsm "yubihsm2" {
     topology       = "pool"
     node_id        = "vault-1"
     credential_dir = "/var/lib/bastionvault/hsm"
     attestation_roots_file = "/etc/bastionvault/yubico-attestation.pem"
     recovery       = "shamir-ceremony"     # or "none" plus the acknowledgement
     member "hsm-a" {
       connector = "http://127.0.0.1:12345"
       serial    = "0012345678"
     }
   }

   # On every node without a local device: through the gateway, with mTLS.
   hsm "yubihsm2" {
     topology       = "pool"
     node_id        = "vault-2"
     credential_dir = "/var/lib/bastionvault/hsm"
     attestation_roots_file = "/etc/bastionvault/yubico-attestation.pem"
     recovery       = "shamir-ceremony"
     link {
       ca_file   = "/etc/bastionvault/hsm-link/ca.pem"
       cert_file = "/etc/bastionvault/hsm-link/vault-2.pem"   # SAN = node_id
       key_file  = "/etc/bastionvault/hsm-link/vault-2.key"
     }
     member "hsm-a" {
       gateway = "https://hsm-a.internal:8250"
       serial  = "0012345678"
     }
   }
   ~~~

2. **Provision, bootstrap and init** as for two devices, with one bundle:
   `operator hsm provision` on the HSM host, `operator hsm bootstrap --bundle
   hsm-a=a.json --admin hsm-a` and `operator init` on the init node. Run
   `bvault hsm-gateway` on the HSM host for the nodes without a device, and
   enroll them with `operator hsm node add`.
3. **What you see.** `v2/sys/hsm/status` reports `redundancy: "none"`,
   `members_active: 1`, `members_expected: 2` and a `redundancy_warning`;
   every start and every unseal raises `hsm.pool_not_redundant` (a `warn` on
   the `security` log, an audit entry once the audit device is up); the
   metric is `bv_hsm_pool_redundancy{level="none"} 1`. Alert on that. Each
   secret has one copy, which is complete for a pool of one: nothing is
   reported as under-replicated and repair has nothing to do.
4. **Add the second device** when it arrives: provision it on its host, then

   ~~~bash
   bvault operator hsm member add hsm-b --bundle b.json --gateway https://hsm-b.internal:8250 --admin hsm-b
   bvault operator hsm repair --run                                # second copy of the KEK and every key
   bvault operator hsm repair --run --admin hsm-a --admin hsm-b    # promotes hsm-b to active
   ~~~

   `member add` enrolls every enrolled node on the new device. Until the
   promotion the new member is `joining` and the sets count as
   under-replicated against it (real work for repair). After it, status
   reports `redundancy: "full"` and either device alone unseals every node.
   The recovery copy, if any, is unchanged. Every node that reaches the new
   device through its gateway needs a `link` block, including the first HSM
   host if it had none.
5. **A third device is refused.** To replace a failed one, retire it first
   (`operator hsm member retire hsm-b`; the survivor must hold every set), run
   as a pool of one, then add the replacement as in step 4. With
   `min_wrap_copies = 2`, set it to 1 on the nodes before retiring. Retiring
   the last active member is always refused, and retiring down to one member
   without a recovery key needs the acknowledgement above.

**mTLS, in short.** A node that reaches a device on its own host uses
`connector = "http://127.0.0.1:<port>"` and needs no `link` and no gateway.
A node without a device of its own never needs one: it uses the member's
`gateway` (`bvault hsm-gateway` on the HSM host) with its `link` certificate.
The connector itself is never exposed beyond loopback.

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

# Replace a failed device: retire it (a pool of one meanwhile), then attest
# and add the replacement, repair, promote. A third member is refused.
bvault operator hsm member retire hsm-b
bvault operator hsm repair --run                                # drops hsm-b's copies
bvault operator hsm member add hsm-b2 --bundle b2.json --admin hsm-b2
bvault operator hsm repair --run
bvault operator hsm repair --run --admin hsm-a --admin hsm-b2   # promotes hsm-b2
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
- **YubiHSM 2 pools** start and reach members through the link. Attestation is
  verified against the [Yubico trust file](#yubico-attestation-trust-file)
  (`attestation_roots_file`) and refused without it. Nothing on the device
  path is verified on hardware until the
  [phase 7 run](#phase-7-hardware-validation-t454); `provision` now also
  reads the device attestation certificate, so a bundle made by an earlier
  build (key certificate only) is refused as truncated: provision again.
- **Epoch rotation:** `bvault operator hsm rotate-epoch --admin hsm-a --admin hsm-b`
  generates new wrap keys on every active member, re-wraps the KEK and every
  custody set to the next epoch and deletes the old keys; an interrupted run
  resumes. Do not roll back past this build after a rotation.
- **Per-node to pool:** run the node with the pool config plus
  `migrate_from { state_path = "…" }` (mock) or
  `migrate_from { connector = "…", password = "env:VAR" }`, then
  `operator hsm bootstrap …` and `bvault operator hsm migrate-to-pool` on that
  node (loopback). The cluster keeps its id and epoch; the change is one-way.
  A migrated pool has no recovery key (it is made at init only), so the node
  must run `recovery = "none"` for the migration.

#### Device audit log and observability (phase 6, mock)

Each pool device keeps its own audit log: the last 62 commands, each with the
auth key that ran it and a digest chained from the entry before. BastionVault
drains it so the record of what every node did on the device ends up in the
audit log, and a gap in it is never silent.

~~~bash
# Once, after init (and after a member is added or replaced): give each member
# the `bv-auditor` key the drain reads the log with. Also sets the device's
# forced-audit option to match `device_audit`.
bvault operator hsm repair --run --admin hsm-a --admin hsm-b
bvault operator hsm status        # device_audit.members[].enrolled = true
~~~

- **Drain.** Every 5 s while unsealed, each member's log is read with
  `bv-auditor` (auth key 8: `get-log-entries` and `set-log-index` only), the
  chain is verified from the member's cursor (`core/hsm/audit-cursor/<hsm_id>`),
  every new command becomes an `hsm.device_log` audit event (command, auth key,
  the node the key belongs to, target object, result), and the log is
  acknowledged once the cursor is stored. Every node runs the drain; a member
  another node drained less than 5 s ago is skipped.
- **Gaps.** An index jump (the drain lagged and the 62-entry buffer wrapped), a
  chain break (an entry changed), a log that restarted or was rewritten, and
  unlogged events the device reports each raise `hsm.device_log_gap` and
  `bv_hsm_device_log_gap_total{member}`. The entries after a gap are still
  verified and drained.
- **`device_audit`.** `drain` (default) as above. `forced` also turns on the
  device's forced-audit option: a member then refuses commands with `LOG_FULL`
  while its log is full, so no command ever runs unlogged, at the price that a
  stalled drain stops that member (the pool fails over to the other one, then
  stops). `off` drains nothing and is refused when `BVAULT_ENV=production`; use
  it for a mock pool whose nodes run in separate processes (the mock keeps one
  log per process and would report restarts).
- **The credential** is random, made by BastionVault during an admin repair,
  stored behind the barrier at `core/hsm/auditor/<hsm_id>` and never shown. A
  repair replaces it when it no longer authenticates (device reset).
- **YubiHSM 2:** installing `bv-auditor`, the forced-audit option and the drain
  are refused, naming phase 7, until the log layout is confirmed on a device.
  `v2/sys/hsm/status` then shows each member with `enrolled: false`.

Metrics (`/metrics`):

| Metric | Labels | Meaning |
|---|---|---|
| `bv_hsm_member_up` | `member` | 1 while the member answers from this node |
| `bv_hsm_command_duration_seconds` | `member`, `op` (`wrap`, `read`, `probe`, `get_log_entries`) | Wall time of a member operation; a high tail means device or link saturation |
| `bv_hsm_session_errors_total` | `member`, `kind` (`transport`, `sessions_full`, `device`, `crypto`) | Failed member operations |
| `bv_hsm_under_replicated_sets` | — | Sets missing a copy on an active or joining member (never the single copy of a pool of one) |
| `bv_hsm_pool_redundancy` | `level` (`full`, `none`) | The current level is 1, the other 0: `none` is a pool of one. No series before a pool reports. Alert on `bv_hsm_pool_redundancy{level="none"} == 1` |
| `bv_hsm_repair_total` | `result` (`added`, `removed`, `recovery_added`, `failed`) | Repair outcomes |
| `bv_hsm_device_log_gap_total` | `member` | Device-log gaps found by the drain |
| `bv_hsm_link_requests_total` | `member`, `code` (`ok`, `failed`) | Requests this node's HSM link relay sent to the member's gateway (YubiHSM 2 through a gateway only) |

`v2/sys/hsm/status` (and the GUI's **HSM / Seal** page) adds, for a pool, each
member's `latency_ms` and pending revocations, the last repair run and each
member's drain (see `docs/api.md`).

#### Recovery (pool topology, `shamir-ceremony`)

Init with `recovery = "shamir-ceremony"` generates an ML-KEM-768 recovery
keypair from a fresh 64-byte seed, splits the seed M-of-N with Shamir
(`bvault operator init --recovery-shares 5 --recovery-threshold 3`, the
default), prints the shares **once** as `recovery_keys` and keeps only the
public key, its fingerprint and the split in the seal record. The seed is
zeroized before init returns. Every blob set (the KEK and each custody key)
then carries a recovery copy sealed to the public key, so adding one needs no
secret: custody `create`, `repair` (which also adds a missing one, counted as
`recovery_copies_added`) and `rotate-epoch` (which re-seals it at the new
epoch) all do. The copy's AAD binds the set's context, purpose, epoch and key
id, so a copy moved to another set does not open.

Unseal **never** uses a recovery copy. When both devices are lost:

~~~bash
# 1. Provision two new devices (bundles c.json, d.json), point this node's
#    `member` blocks at them, restart it: it stays sealed.
# 2. Holders submit shares (one hidden prompt each, or --share env:VAR),
#    then the new devices go in with their admin credentials:
bvault operator hsm recover --member hsm-a2=c.json --member hsm-b2=d.json --admin hsm-a2 --admin hsm-b2
~~~

`POST /v2/sys/hsm/recover` takes no token (the shares are the credential, as
for `sys/unseal`) and is accepted only on a **sealed** node while every member
that is not retired is unreachable (a transport failure; any device that
answers refuses the ceremony: repair or `member add` instead). Shares stay in
that node's memory until the ceremony runs or `--reset`. The ceremony accepts
the recombined key only if it has the recorded fingerprint (wrong, tampered or
too few shares are refused, and every attempt consumes the shares); opens the
KEK's recovery copy; attests the new devices and gives them the epoch's wrap
keys; enrolls every enrolled node on them; wraps the KEK on each and proves
each copy by an authorized unwrap; opens the barrier with the recovered KEK
only to wrap each custody set's seed (checked against its public key) on the
new devices; commits the record (old members `retired`, their pending
revocations dropped) against the exact bytes it started from; bumps the epoch
with `rotate-epoch`; seals the barrier again; and then auto-unseals through the
new devices. A failure before the commit deletes the node keys it created. It
raises `hsm.recovery_ceremony` with the share indexes used; a custody set that
cannot be recovered is listed in `custody_unrecovered` and raised as
`hsm.crypto_failure`. Other enrolled nodes pick up their new credentials on
their next refresh. Reset or destroy the lost devices if they reappear.

### Phase 7 hardware validation (T454)

The pool's YubiHSM 2 path is validated on two real devices, or on one as a
[pool of one](#starting-with-one-hsm-a-pool-of-one) (see
[With one device](#with-one-device-a-pool-of-one)), by a test suite that only
an operator at the machine runs. It is compiled only with the
`hsm_hardware_tests` feature (no product build, `make test` or
`make test-changed` compiles it) and does nothing unless
`BVAULT_TEST_YUBIHSM_POOL=1`. Design and acceptance:
[HSM pool HA § Phase 7](../features/hsm-pool-ha.md#resetting-the-test-devices).

**What it never does:** reset a device, update firmware, enable FIPS mode, set
any audit option (forced or command audit), run the production `provision`,
or touch a device whose serial is not in `BVAULT_TEST_YUBIHSM_SERIALS`. Its
only writes are the test `provision` (behind `BVAULT_TEST_YUBIHSM_ALLOW_WRITES=1`)
and one test node key, which it deletes again. Passwords come only from the
environment and are never printed or written.

Prerequisites: the devices named in `BVAULT_TEST_YUBIHSM_SERIALS` in factory
state on this host, which is not shared; `yubihsm-connector` 3.0.x (no
connector already running on port 12345, nor on 12346 with two devices); the
[Yubico trust file](#yubico-attestation-trust-file); a new, empty output
directory per campaign.

| Variable | Required | Meaning |
|---|---|---|
| `BVAULT_TEST_YUBIHSM_POOL` | yes | `1` runs the suite; anything else skips it |
| `BVAULT_TEST_YUBIHSM_SERIALS` | yes | One serial (a pool-of-one run) or two (a two-member run), comma-separated. Zero, three or more, a duplicate or a zero serial are refused; any device not listed is refused |
| `BVAULT_TEST_YUBIHSM_OUT` | yes | Output directory (snapshots, bundles, reports) |
| `BVAULT_TEST_YUBIHSM_STEP` | no | `snapshot` (default), `validate` or `compare` |
| `BVAULT_TEST_YUBIHSM_UNTIL` | no | Stop after this step, e.g. `anchors` (before the first write) |
| `BVAULT_TEST_YUBIHSM_ALLOW_WRITES` | for `provision` | `1` opens the write gate; without it a plan that writes is refused whole |
| `BVAULT_TEST_YUBIHSM_ADMIN_PASSWORD` | for writes | The **test** `bv-admin` password; must differ from the factory one |
| `BVAULT_TEST_YUBIHSM_FACTORY_PASSWORD` | no | Factory key password; default the published one |
| `BVAULT_TEST_YUBICO_ATTESTATION_ROOTS` | for `validate` | The Yubico trust file |
| `BVAULT_TEST_YUBIHSM_CONNECTOR` | no | Connector binary; default `yubihsm-connector` on `PATH` |
| `BVAULT_TEST_YUBIHSM_PORT_BASE` | no | First connector port, default `12345` (a second device gets the next) |
| `BVAULT_TEST_YUBIHSM_LATENCY_ITERATIONS` | no | Rounds per timed operation, 1–1000, default 20 |

Each invocation starts one connector per device on `127.0.0.1` with
`--serial`, checks the connector's status and then the authenticated
`device-info` serial against the list, and kills the connectors when it
exits.

~~~bash
# 0. Build it (no device is touched).
cargo test -p bv-core --features hsm_hardware_tests --test hsm_pool_hardware --no-run

export BVAULT_TEST_YUBIHSM_POOL=1
export BVAULT_TEST_YUBIHSM_SERIALS=36470559,36470560
export BVAULT_TEST_YUBIHSM_OUT="$HOME/bv-phase7-$(date +%Y%m%d)"
export BVAULT_TEST_YUBIHSM_CONNECTOR=/usr/local/bin/yubihsm-connector
export BVAULT_TEST_YUBICO_ATTESTATION_ROOTS=/path/to/yubico-attestation.pem
mkdir "$BVAULT_TEST_YUBIHSM_OUT"

# 1. Read-only: snapshot both devices with the factory key, preflight them
#    (factory key 0x0001 and nothing else) and save snapshot-before.json.
BVAULT_TEST_YUBIHSM_STEP=snapshot \
  cargo test -p bv-core --features hsm_hardware_tests --test hsm_pool_hardware -- --nocapture

# 2a. Still read-only: re-snapshot, match the saved one, preflight, load the
#     trust file. Stops before the first write.
BVAULT_TEST_YUBIHSM_STEP=validate BVAULT_TEST_YUBIHSM_UNTIL=anchors \
  cargo test -p bv-core --features hsm_hardware_tests --test hsm_pool_hardware -- --nocapture

# 2b. The run. Writes begin here; from now on the devices need a physical reset.
read -rs BVAULT_TEST_YUBIHSM_ADMIN_PASSWORD && export BVAULT_TEST_YUBIHSM_ADMIN_PASSWORD
BVAULT_TEST_YUBIHSM_STEP=validate BVAULT_TEST_YUBIHSM_ALLOW_WRITES=1 \
  cargo test -p bv-core --features hsm_hardware_tests --test hsm_pool_hardware -- --nocapture
unset BVAULT_TEST_YUBIHSM_ADMIN_PASSWORD

# 3. Physical reset, each device in turn: unplug it, press and hold the metal
#    rim while inserting it, keep pressing for at least 10 seconds, release.

# 4. Read-only: snapshot again, save snapshot-after-<time>.json, preflight,
#    and diff against snapshot-before.json. The expected difference is none.
BVAULT_TEST_YUBIHSM_STEP=compare \
  cargo test -p bv-core --features hsm_hardware_tests --test hsm_pool_hardware -- --nocapture
~~~

The two-member `validate` run (one device: see
[below](#with-one-device-a-pool-of-one)), in order: connectors, snapshot, match-before, preflight,
anchors (all read-only); **provision** both devices from factory state with
the test password (it reads each device's attestation certificate first);
attest each with `verify_member` (pinned chain, `bv-identity` challenge,
layout check) and present each device's bundle to the other (must be
refused); enroll a test node key on both; dual-wrap and unwrap on each, a
copy for one device refused by the other, a tampered copy reported as a
crypto failure, `bv-identity` refused to the node key (domain 2); the
latency rounds (wrap, signed unwrap authorization, unwrap, custody key
creation) on each device through a real gateway and relay (throwaway mTLS CA,
nothing written to disk) and directly through its connector; delete
the test node key and confirm the device refuses it; print the reset
instructions (also in `RESET-REQUIRED.txt`). A failed check is recorded and
the run goes on, because each run costs a reset; the test fails at the end
if any check failed. A step that errors after the first write still prints
the reset instructions.

Output, in `BVAULT_TEST_YUBIHSM_OUT` (no secrets; bundles and certificates
are public): `snapshot-before.json` (never overwritten), `snapshot-after-*.json`,
`comparison-*.json`, `bundle-<serial>.json`, `attestations.json` (each
attested key's serial, origin, domains, capabilities, firmware, device
certificate and Yubico root fingerprints), `checks-*.json`, `latency.md` /
`latency.json`, `RESET-REQUIRED.txt` and `connector-<serial>.log`. Each
snapshot also records the device log read with the factory key and whether
its digest chain verified as the drain expects; that is the evidence the
YubiHSM 2 drain refusal is lifted on.

Every output names its run mode. The JSON files carry `"mode"`
(`"pool-of-one"` or `"two-member"`) and the `serials`; `latency.md`,
`RESET-REQUIRED.txt` and each `connector-<serial>.log` start with a
`phase 7 mode …` line. `bundle-<serial>.json` stays a bare attestation bundle,
because that format refuses unknown fields; `attestations.json` names it under
`bundle_files`. `checks-*.json` holds `mode`, `serials`, `verdict`, the
`passed` / `failed` / `not_exercised` counts and each check's `outcome`:
`passed`, `failed` or `not exercised (pool of one)`. A snapshot saved before
the label existed still loads, and is compared device by device. A run in one
mode does not match a "before" snapshot taken in the other: the comparison
reports the mode as a difference.

Read by hand, with the factory key, after the reset (the suite cannot):
`algorithm-toggle`, with `yubihsm-shell`'s `get-option`, the way the
"before" table in the spec was read. Then the production `provision`, which
this suite never runs.

Not covered by the suite (manual or later): unplugging a device mid-run,
a full three-node `bootstrap` / `init` on the devices, the forced-audit
option and the YubiHSM 2 drain, and the FIPS Ed25519 question (these two
devices are not FIPS models).

**Measured latencies:** not measured yet; paste the run's `latency.md` here.

#### With one device (a pool of one)

With one serial in `BVAULT_TEST_YUBIHSM_SERIALS` the suite validates a
[pool of one](#starting-with-one-hsm-a-pool-of-one) on that device. The steps,
the factory-state preflight (factory key `0x0001` and nothing else), the
allow-list and the write gate are the same as with two. Only that device's
connector is started, and a second device that is plugged in is never
touched. Use a new output directory: a "before" snapshot of one mode does not
match a run in the other.

On the one device it checks: connector and `device-info` serial, snapshot,
preflight, trust file, the test `provision`, attestation through the pinned
Yubico chain (`verify_member`: `bv-identity` challenge, layout check), the
test node key, a wrap and unwrap round trip, a tampered copy reported as a
crypto failure, `bv-identity` refused to the node key (domain 2), the latency
rounds directly and through a real gateway and relay (mTLS), the deletion of
the test node key, the reset instructions and, after the reset, the
comparison.

These need a second device and are recorded as `not exercised (pool of one)`
in `checks-*.json` and the console summary, never as passed and never left
out:

| Check | Recorded at step | Two-member run |
|---|---|---|
| One device's attestation bundle is refused by the other device | `attest` | checked |
| `member add` of the second device, then repair to two copies | `enroll-test-node` | not in this suite (mock tests only) |
| Dual-wrap: one copy on each of two members | `dual-wrap` | checked |
| A copy wrapped for one device is refused by the other | `dual-wrap` | checked |
| Failover between the two members | `dual-wrap` | not in this suite (mock tests only) |
| Either device alone unseals once both are enrolled | `dual-wrap` | not in this suite (mock tests only) |

The run passes when no check failed. Its last line, also `verdict` in
`checks-*.json`, names the pool-of-one run and its device and says that it
does not validate two-device behaviour, whatever passed. The suite never runs
`bootstrap` or `init`, so `acknowledge_single_member_without_recovery` (which
gates those) plays no part: the one-device `provision` is the same device
ceremony as with two.

~~~bash
# 0. Build it (no device is touched).
cargo test -p bv-core --features hsm_hardware_tests --test hsm_pool_hardware --no-run

export BVAULT_TEST_YUBIHSM_POOL=1
export BVAULT_TEST_YUBIHSM_SERIALS=36470559          # one serial: a pool-of-one run
export BVAULT_TEST_YUBIHSM_OUT="$HOME/bv-phase7-pool-of-one-$(date +%Y%m%d)"
export BVAULT_TEST_YUBIHSM_CONNECTOR=/usr/local/bin/yubihsm-connector
export BVAULT_TEST_YUBICO_ATTESTATION_ROOTS=/path/to/yubico-attestation.pem
mkdir "$BVAULT_TEST_YUBIHSM_OUT"

# 1. Read-only: snapshot and preflight 36470559, save snapshot-before.json.
BVAULT_TEST_YUBIHSM_STEP=snapshot \
  cargo test -p bv-core --features hsm_hardware_tests --test hsm_pool_hardware -- --nocapture

# 2a. Still read-only: re-snapshot, match, preflight, load the trust file.
BVAULT_TEST_YUBIHSM_STEP=validate BVAULT_TEST_YUBIHSM_UNTIL=anchors \
  cargo test -p bv-core --features hsm_hardware_tests --test hsm_pool_hardware -- --nocapture

# 2b. The run. Writes begin here; from now on 36470559 needs a physical reset.
read -rs BVAULT_TEST_YUBIHSM_ADMIN_PASSWORD && export BVAULT_TEST_YUBIHSM_ADMIN_PASSWORD
BVAULT_TEST_YUBIHSM_STEP=validate BVAULT_TEST_YUBIHSM_ALLOW_WRITES=1 \
  cargo test -p bv-core --features hsm_hardware_tests --test hsm_pool_hardware -- --nocapture
unset BVAULT_TEST_YUBIHSM_ADMIN_PASSWORD

# 3. Physical reset of 36470559: unplug it, press and hold the metal rim while
#    inserting it, keep pressing for at least 10 seconds, release.

# 4. Read-only: snapshot again and diff against snapshot-before.json (expected: none).
BVAULT_TEST_YUBIHSM_STEP=compare \
  cargo test -p bv-core --features hsm_hardware_tests --test hsm_pool_hardware -- --nocapture
~~~

A later two-member run (both serials, its own output directory) covers the
rows marked "checked" above; the others stay with the mock tests.

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
  attestation before any key material moves. On a YubiHSM 2 it is verified
  against the operator's [Yubico trust file](#yubico-attestation-trust-file);
  without one it is refused, never accepted unverified.
- **Credentials.** The auth-key password is read via `env:` (or the OS keychain
  in GUI/embedded mode); plaintext credentials in config are rejected outside
  dev builds.
- **Mock ≠ security.** The mock backend is compile-time gated (`hsm_mock`),
  provides no hardware protection, and refuses to start in production. Release
  artifacts must not enable it.

See [`features/hsm-support.md`](https://github.com/ffquintella/BastionVault/blob/main/features/hsm-support.md)
for the full design and the non-negotiable security rules.
