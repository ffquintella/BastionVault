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

The mock backend needs a build with the `hsm_mock` feature and a writable state
file. It is intended for dev/CI/homolog only.

```bash
cargo build --features hsm_mock --bin bvault
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

# Dev / homolog ONLY. Requires the `hsm_mock` build feature and refuses to
# start when the environment is production.
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
cargo build --features hsm_yubihsm2 --release --bin bvault
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
| `node_id` | both | No | `$HOSTNAME` | Stable node identity used in context strings and per-node key routing. Set explicitly in clusters. |
| `pqc_key_cache_ttl` | both | No | `60s` | TTL for the unwrapped-seed session cache. `0` disables caching (strict per-operation unwrap). |
| `recovery` | both | No | `none` | `none` or `shamir-ceremony`. **Honored only at `init`; cannot be enabled later.** |

### Recovery modes

- `recovery = "none"` (default) — no software escrow. If every cluster HSM is
  lost, the vault is unrecoverable. This is the documented, intended guarantee.
- `recovery = "shamir-ceremony"` — at `init` only, a recovery wrapping key is
  generated and Shamir-split; store the shares offline. Opt in only if you
  accept a software recovery path.

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

Returns the active seal type and, for an HSM seal, the backend, device serial,
cluster epoch, enrolled-node count, recovery posture, and cache TTL. Read-only;
never returns secret material. See the [API reference](api.md#hsm-seal-status).

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

### Failure behavior (fail-closed)

An unreachable or unenrolled HSM keeps the node **sealed** — it never opens the
vault on a degraded device. Cluster HA covers single-node HSM failures; monitor
HSM session errors so you can react before quorum is threatened.

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
