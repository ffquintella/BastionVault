# Feature: HSM Support (YubiHSM 2)

## Summary

Add hardware security module (HSM) integration so that BastionVault's master key, key custody, and critical cryptographic operations are anchored in tamper-resistant hardware. The **mandated device is the YubiHSM 2** (one physical device per cluster node). Development and homologation environments use a **feature-gated mock backend** that implements the same interface with no hardware.

Because the YubiHSM 2 has no native ML-KEM / ML-DSA support, post-quantum keys use a **hybrid custody model**: the HSM acts as the custody, policy, wrapping, and attestation anchor, while ML-KEM-768 / ML-DSA-65 operations are performed in software on transiently-unwrapped key material that is zeroized immediately after use. **No persisted key material is decryptable without the key inside an enrolled YubiHSM 2.**

## Implementation Status

- **Phase 1 — HSM abstraction + YubiHSM 2 + mock + auto-unseal: Done.** `HsmBackend` trait,
  `BvHsmBlob` envelope, context strings, signed unwrap authorization, `MockHsmBackend`
  (feature `hsm_mock`, production-refusal guard), `YubiHsm2Backend` (feature `hsm_yubihsm2`,
  compiles against the real `yubihsm` 0.42 crate), `SealProvider` trait + `ShamirSealProvider`
  + `HsmSealProvider`, `Core` seal-provider dispatch + `Core::auto_unseal`, and HCL `hsm "…"`
  config parsing. Files: `src/hsm/{mod,blob,context,authz,mock,yubihsm2}.rs`,
  `src/seal/{mod,hsm}.rs`, `src/core.rs`, `src/cli/config.rs`.
- **Phase 2 — Hybrid PQC key custody: Done.** HKDF-SHA-512 seed derivation (host entropy + HSM
  randomness + in-HSM ECDH) and `HsmCustodyKemProvider` / `HsmCustodySigProvider` with the
  unwrap-use-zeroize lifecycle and a bounded zeroizing session cache. Files:
  `src/hsm/derive.rs`, `src/hsm/custody.rs`. *Layering note:* the custody providers live in the
  host `hsm` module (not `crates/bv_crypto/`, as the spec sketched) because the unwrap lifecycle
  needs the host `HsmBackend`; `bv_crypto` stays a pure, host-free crypto crate and supplies the
  raw ML-KEM / ML-DSA math.
- **Phase 3 — Cluster bootstrap, enrollment, replication: Library-complete + status surface.**
  Custody-root record, attestation-verified enrollment, ECDH replication channel, and dual-signed
  migration transcripts are implemented and tested with two mock devices in-process
  (`src/hsm/enroll.rs`, `src/hsm/replicate.rs`). `GET v2/sys/hsm/status` +
  `bvault operator hsm status` + a read-only **HSM / Seal** page in the desktop GUI
  (`gui/src/routes/HsmStatusPage.tsx`, backed by the `hsm_status` Tauri command) are wired.
  **Remaining:** the *networked* enroll / rotate-epoch
  HTTP handshake endpoints (a live multi-node exchange) — deferred until they can be validated
  against real hardware or a running cluster rather than shipped as untested stubs.

All behavior is covered by unit/integration tests using the mock backend (30+ tests across the
`hsm` and `seal` modules). The `hsm_yubihsm2` backend compiles against the real crate but requires
a device (`BVAULT_TEST_YUBIHSM=1`) to exercise; its attestation chain still needs Yubico root-CA
pinning before production use (flagged in `src/hsm/yubihsm2.rs`).

## Motivation

BastionVault's master key (the key encryption key, or KEK) is currently generated, split, and reconstructed entirely in software. During unseal, the reconstructed KEK exists in process memory. This creates several risks:

- **Memory exposure**: a memory dump, core dump, or cold-boot attack can extract the KEK.
- **Operational burden**: operators must manually provide unseal shares after every restart.
- **No hardware root of trust**: the entire key hierarchy is rooted in software entropy and software storage.
- **Compliance gaps**: PCI-DSS, FIPS 140-2/3, and FedRAMP require or strongly recommend hardware-backed key protection for secrets management systems.
- **No hardware anchor for the PQC hierarchy**: ML-KEM-768 / ML-DSA-65 private keys live entirely in software; nothing binds them to a physical device or to an auditable custody chain.

HSM integration addresses all of these by delegating custody, wrapping, and attestation to hardware that never exports its private key material.

## Non-Negotiable Security Rules

These rules constrain every design decision below and MUST be enforced in code review and tests:

1. **Never derive PQC keys only from RSA/ECC HSM keys.** Classical HSM secrets are one input among several; a quantum-capable adversary who breaks the classical key must not be able to reconstruct the PQC keys.
2. **The YubiHSM 2 is the custody / policy / wrapping / attestation anchor** — not the PQC computation engine. All persisted PQC key material is HSM-wrapped; all key-release decisions are gated and attested by the HSM.
3. **Generate fresh PQC entropy.** Every PQC seed includes fresh CSPRNG output from the host (`OsRng`) mixed at derivation time; HSM-sourced randomness augments, never replaces, it.
4. **Use explicit context strings** in every KDF invocation, signature, and wrap operation. No key is ever derived or used without a domain-separating context (see [Context Strings](#context-strings)).
5. **Use separate keys for KEM, signatures, wrapping, and application encryption.** One HSM object and one derived key per purpose; no key is reused across domains.
6. **It must NOT be possible to decrypt persisted key material without the key inside the HSM.** All wrap keys are created with export capabilities disabled. There is no software-only recovery path unless the operator explicitly opts into a break-glass ceremony at init time (disabled by default).
7. **Use-then-zeroize.** Unwrapped private key material lives in `Zeroizing` buffers, is used for the immediate operation (or a short bounded-TTL session), and is zeroized. No long-lived plaintext PQC private keys in process memory.

## Current State

### Crypto Provider Layer (`crates/bv_crypto/`)

The project uses trait-based abstractions for cryptographic operations:

- **`KemProvider`** trait: `generate_keypair()`, `encapsulate()`, `decapsulate()`, `keypair_from_seed()`. Currently implemented by `MlKem768Provider` (software-only ML-KEM-768).
- **`MlDsa65Provider`**: signature operations (`sign()`, `verify()`). Software-only.
- **`AeadCipher`** trait: `encrypt()`, `decrypt()`. Currently `Chacha20Poly1305Cipher`.

These traits are designed for multiple implementations but only have software backends today.

### Barrier Key Lifecycle

**Initialization** (`Core::init()`):
1. `barrier.generate_key()` produces a random KEK (64 bytes for ChaCha20 barrier).
2. `barrier.init(kek)` generates a random data encryption key, wraps it with the KEK, stores the wrapped key at `barrier/init`.
3. KEK is split via Shamir's Secret Sharing into N shares with threshold T.
4. Shares are returned to the operator. The KEK is zeroized from memory.

**Unseal** (`Core::do_unseal()`):
1. Operator provides T shares.
2. Shares are combined to reconstruct the KEK.
3. `barrier.unseal(kek)` loads the wrapped key from `barrier/init`, unwraps it with the KEK, and holds the data encryption key in memory.
4. All subsequent storage operations use the data encryption key.

**Seal** (`Core::seal()`):
1. Data encryption key is zeroized from memory.
2. Barrier enters sealed state. All operations fail until unsealed again.

### Cluster Topology

BastionVault runs as a Hiqlite (Raft) cluster. Each node is a separate host. **Each host has its own YubiHSM 2** attached (USB or via `yubihsm-connector`). There is no shared network HSM; the design must replicate wrapped key material so every node can operate with only its local device.

## Device and Backend Selection

### YubiHSM 2 (production)

- Access via the `yubihsm` Rust crate (yubihsm.rs), using the HTTP connector (`yubihsm-connector`) or direct USB.
- Relevant device capabilities used: object generation (AES, ECC P-256, Ed25519), `wrap-data` / `unwrap-data` (AES-CCM wrap keys), `sign-ecdsa` / `sign-eddsa`, `derive-ecdh`, `get-pseudo-random`, `sign-attestation-certificate`, domains and capability masks for policy enforcement.
- Feature flag: `hsm_yubihsm2`.

### Mock backend (dev / homolog)

- Feature flag: `hsm_mock`. Implements the same `HsmBackend` trait in software (backed by the yubihsm.rs `MockHsm` where possible, plus a file-persisted object store so dev clusters survive restarts).
- Deterministic and network-free: usable in CI, unit tests, and the homologation cluster (HML containers have no USB passthrough).
- **Guardrails**: the mock is compiled only under `hsm_mock`. The stock `cargo build`, the CLI packages, and the GUI leave it off; the **official container image bundles it** (alongside `hsm_yubihsm2`) so one image serves prod + homolog. The runtime guard is what makes bundling safe: if the seal config declares `backend = "mock"` the server logs a prominent warning and **refuses to start** when `BVAULT_ENV=production` (or the config sets `environment = "production"`), so a production node must use a real HSM (or Shamir).
- The mock honors the same object model, capability masks, context strings, and wire formats, so dev/homolog exercise the identical code path minus the hardware.

### Backend abstraction

```rust
/// Narrow abstraction over the operations BastionVault needs from the HSM.
/// Implemented by `YubiHsm2Backend` (feature `hsm_yubihsm2`) and
/// `MockHsmBackend` (feature `hsm_mock`).
#[maybe_async::maybe_async]
pub trait HsmBackend: Send + Sync {
    fn backend_type(&self) -> &str; // "yubihsm2" | "mock"

    /// AES-CCM wrap/unwrap of opaque data with an HSM-resident wrap key.
    async fn wrap_data(&self, key: HsmObjectId, ctx: &Context, plaintext: &[u8]) -> Result<Vec<u8>, RvError>;
    async fn unwrap_data(&self, key: HsmObjectId, ctx: &Context, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, RvError>;

    /// Signature with an HSM-resident classical key (ECDSA P-256 or Ed25519).
    async fn sign(&self, key: HsmObjectId, ctx: &Context, msg: &[u8]) -> Result<Vec<u8>, RvError>;
    async fn verify_attestation(&self, cert_chain: &[u8]) -> Result<AttestedKey, RvError>;

    /// ECDH between an HSM-resident private key and a peer public key.
    async fn derive_ecdh(&self, key: HsmObjectId, peer_pub: &[u8]) -> Result<Zeroizing<Vec<u8>>, RvError>;

    /// Hardware randomness (augments, never replaces, host CSPRNG).
    async fn get_random(&self, len: usize) -> Result<Zeroizing<Vec<u8>>, RvError>;
}
```

## HSM Object Layout (per node)

Each node's YubiHSM 2 is provisioned at enrollment with the following objects, each with the minimal capability mask and a dedicated domain:

| Label | Type | Capabilities | Purpose |
|---|---|---|---|
| `bv-auth-<node>` | Authentication key | session auth only | Application login to the device. PIN/password via `env:` reference, never plaintext in config. |
| `bv-wrap-barrier-<node>` | AES-256 wrap key | `wrap-data`, `unwrap-data` (**no** `exportable-under-wrap`) | Wraps the barrier KEK (auto-unseal). |
| `bv-wrap-pqc-<node>` | AES-256 wrap key | `wrap-data`, `unwrap-data` (**no** export) | Wraps PQC seeds/private keys. Separate from the barrier wrap key (rule 5). |
| `bv-identity-<node>` | ECC P-256 keypair | `sign-ecdsa`, `derive-ecdh`, `sign-attestation-certificate` | Node identity: signs transcripts, ECDH for the replication channel, attestation proves residence in a genuine YubiHSM 2. |
| `bv-authz-<node>` | Ed25519 keypair | `sign-eddsa` | Unwrap-authorization signatures (the "signed part" gating every decrypt — see below). |

Distinct wrap keys per purpose mean a compromise or mis-scoped session for one domain cannot unwrap material from another.

## Design

### Capability 1: HSM Auto-Unseal

The HSM holds `bv-wrap-barrier-<node>`, which protects the KEK at rest. On startup, BastionVault asks the local HSM to unwrap the KEK — no manual share entry.

**Initialization (one-time, on the bootstrap node):**
1. Operator configures the `hsm "yubihsm2"` (or `"mock"`) seal in the config file.
2. `Core::init()` generates the KEK as before.
3. The KEK is wrapped via `wrap_data(bv-wrap-barrier, ctx_barrier, kek)` and the blob stored at `core/seal-config`. The plaintext KEK is zeroized.
4. **No software recovery copy is created by default** (rule 6). If the operator explicitly sets `recovery = "shamir-ceremony"` at init, a recovery wrapping key is generated, Shamir-split M-of-N, and the shares must be stored offline; the spec default is `recovery = "none"`, meaning loss of all cluster HSMs makes the vault unrecoverable — this is the intended guarantee, and init prints an explicit warning either way.

**Auto-unseal (every startup):**
1. Read the wrapped KEK blob for **this node** from storage (each node has its own blob, wrapped by its own HSM — see cluster section).
2. Produce an unwrap authorization (below), then call `unwrap_data`.
3. `barrier.unseal(kek)` proceeds as normal; the KEK is zeroized after the barrier derives what it needs.

### Signed Unwrap Authorization ("the signed part")

Every `unwrap_data` call for KEK or PQC material is gated by a signed authorization, so possession of the wrapped blob plus a storage compromise is never sufficient — the decrypt decision itself is anchored in the HSM:

1. The caller builds an **unwrap request** = `context string ‖ blob digest (SHA-256) ‖ node id ‖ key epoch ‖ monotonic counter ‖ purpose`.
2. The HSM signs it with `bv-authz-<node>` (Ed25519, inside the device).
3. The wrapped blob format (`BvHsmBlob v1`) embeds, as AEAD associated data, the context string, purpose, epoch, and the **verifying key fingerprint** of `bv-authz`. `unwrap_data` binds the same associated data, so a blob cannot be unwrapped under a different context/purpose, and the software layer refuses to use unwrapped material unless the authorization signature verifies against the fingerprint baked into the blob.
4. The signed request is appended to the audit log — every key release is an attributable, HSM-signed audit event.

This makes each decrypt a two-factor operation: the AES-CCM unwrap can only happen inside the HSM, and the release is bound to an HSM-signed, context-explicit, replay-resistant (counter) authorization record.

### Capability 2: Hybrid PQC Key Custody

The YubiHSM 2 cannot run ML-KEM-768 / ML-DSA-65. The custody model is:

```
YubiHSM2 classical key + YubiHSM2 random secret + host PQC KEM
        │
        ├── HSM signs/binds the migration transcript
        ├── HSM wraps the PQC seed/private key as opaque wrapped material
        └── software performs ML-KEM / ML-DSA operations
```

**Generation (per PQC key, per purpose):**

1. **Fresh host entropy**: `e_host = OsRng(64)` (rule 3 — mandatory, never optional).
2. **HSM random secret**: `e_hsm = get_random(32)` from the local YubiHSM 2.
3. **Classical HSM contribution**: `s_ecdh = derive_ecdh(bv-identity, cluster_binding_pub)` — an ECDH secret computable only inside an enrolled HSM, binding the seed to hardware custody. It is an *additional* input, never the sole one (rule 1).
4. **Seed derivation**: `seed = HKDF-SHA-512(ikm = e_host ‖ e_hsm ‖ s_ecdh, salt = cluster_uuid, info = context string)`. Separate invocations with separate context strings for the KEM seed and the signature seed (rules 4, 5).
5. Software expands the seed into the ML-KEM-768 / ML-DSA-65 keypair (`keypair_from_seed`), publishes the public key, then immediately wraps the seed with `wrap_data(bv-wrap-pqc, ctx, seed)` and zeroizes `seed`, `e_host`, `e_hsm`, `s_ecdh` (all `Zeroizing`).
6. Only the `BvHsmBlob` (wrapped seed) and the public key are persisted. The plaintext seed never touches storage and never persists in memory.

**Use (encapsulate/decapsulate/sign):**

1. Public-key operations (encapsulate, verify) need no HSM round-trip.
2. Private-key operations obtain a signed unwrap authorization, call `unwrap_data`, re-derive the keypair from the seed into a `Zeroizing` buffer, perform the ML-KEM decapsulation / ML-DSA signature in software, and zeroize.
3. **Bounded session cache** (performance): to avoid an HSM round-trip per operation on hot paths, an unwrapped key may be retained in a `Zeroizing` in-memory slot for a configurable TTL (`pqc_key_cache_ttl`, default 60 s, `0` = strict per-operation unwrap) and is zeroized on expiry, on `seal()`, and on process signals. The cache never spills, is excluded from core dumps where the platform allows (`madvise(MADV_DONTDUMP)` / `mlock`), and key types implement neither `Clone` nor `Debug`.

**Provider integration:** a new `HsmCustodyKemProvider` / `HsmCustodySigProvider` wrap the existing software `MlKem768Provider` / `MlDsa65Provider`, adding the unwrap-use-zeroize lifecycle. The `secret_key` parameter at the trait boundary carries a `BvHsmBlob` reference, not raw key material.

### Capability 3: Cluster Bootstrap, Enrollment, and Key Replication

Each node has a different physical YubiHSM 2, so cluster-shared key material (barrier KEK, PQC seeds) must be made available to every node **without ever being persisted or transmitted in a form decryptable outside an enrolled HSM**. Storage holds one wrapped copy *per node*, each wrapped by that node's own HSM.

**Bootstrap (first node):**
1. Provision the local HSM objects (table above); record the device serial and attestation certificates.
2. `Core::init()` generates the KEK and PQC seeds as in Capabilities 1–2, wrapped under the local HSM.
3. Create the **cluster custody root record**: cluster UUID, bootstrap node ID, HSM serial, object IDs, public keys, key epoch 0 — signed by `bv-identity-<node>` and stored in the replicated storage. This is the trust anchor all later enrollments chain to.

**Node enrollment (join):**
1. The joining node provisions its local HSM and produces an **attestation bundle**: the YubiHSM 2 attestation certificate chain for `bv-identity-<new>` and `bv-authz-<new>` (chaining to the Yubico attestation root CA), proving the keys were generated inside a genuine YubiHSM 2 and are non-exportable.
2. An operator (or an existing admin token, per policy) approves the enrollment; the sponsoring node verifies the attestation chain and pins the new node's public keys.
3. **Secure key transfer** — an HSM-to-HSM authenticated channel:
   - Sponsor and joiner perform ECDH between their `bv-identity` keys (each side's `derive_ecdh` runs inside its own HSM).
   - Channel key = `HKDF-SHA-512(s_ecdh, salt = cluster_uuid, info = ctx_replication ‖ transcript_hash)`; payload encrypted with ChaCha20-Poly1305.
   - The sponsor unwraps each cluster secret (signed unwrap authorization, audited), sends it over the channel; the joiner **immediately re-wraps it under its own `bv-wrap-*` keys and zeroizes the plaintext**. Plaintext exists only transiently in the two processes' zeroizing buffers, never on the wire (which carries only channel-encrypted data) and never in storage.
4. **Migration transcript**: the entire exchange is bound to a transcript — `cluster UUID ‖ epoch ‖ sponsor node/HSM serial ‖ joiner node/HSM serial ‖ object IDs ‖ SHA-256 of every wrapped blob produced ‖ attestation fingerprints ‖ logical timestamp`. **Both HSMs sign the transcript** (`sign-ecdsa` on `bv-identity`); the doubly-signed transcript is stored in replicated storage and in the audit log. A node whose wrapped blobs don't match a valid transcript refuses to unseal.

**Steady-state sync and rotation:**
- New PQC keys or epoch rotations are generated on the current leader and fanned out to every enrolled node via the same transcript-bound channel; each node ends up with its own HSM-wrapped copy at the new epoch.
- Rotation (`bvault operator rotate-hsm-epoch`) bumps the epoch, re-derives/re-wraps, and marks old-epoch blobs for lazy re-wrap; old epochs are retired once all nodes confirm (Raft-replicated confirmation records).
- A node that loses its HSM (device failure/replacement) re-enrolls as a new joiner: nothing on its disk is decryptable without the old device, which is exactly the guarantee — recovery comes from its peers, not from any software escrow.
- Losing **all** HSMs simultaneously loses the cluster (unless the opt-in Shamir ceremony was configured at init). Documentation must state this loudly.

### Configuration

```hcl
hsm "yubihsm2" {
  connector        = "http://127.0.0.1:12345"   # yubihsm-connector; or "usb"
  auth_key_id      = 3
  password         = "env:BVAULT_HSM_PASSWORD"
  domains          = [1]
  pqc_key_cache_ttl = "60s"                     # 0 = strict per-operation unwrap
  recovery         = "none"                     # or "shamir-ceremony" (opt-in at init only)
}

# Dev / homolog only — requires the `hsm_mock` build feature; refuses to start
# in production environments.
hsm "mock" {
  state_path = "/var/lib/bastionvault/mock-hsm.json"
}
```

| Key | Required | Description |
|---|---|---|
| `connector` | Yes | `yubihsm-connector` URL or `usb` for direct USB access. |
| `auth_key_id` | Yes | HSM authentication key object ID. |
| `password` | Yes | Auth key credential. Supports `env:VAR_NAME`; plaintext in config is rejected outside dev. |
| `domains` | No | YubiHSM domains for BastionVault objects (default `[1]`). |
| `pqc_key_cache_ttl` | No | Bounded TTL for unwrapped-key session cache (default `60s`, `0` disables caching). |
| `recovery` | No | `none` (default) or `shamir-ceremony`. Only honored at `init`; cannot be enabled later. |

### Context Strings

All KDF/info, signature, and AEAD associated-data contexts are explicit versioned constants (rule 4), e.g.:

```
bastionvault/hsm/v1/barrier-kek/<cluster-uuid>
bastionvault/hsm/v1/pqc-seed/ml-kem-768/<cluster-uuid>/<key-epoch>
bastionvault/hsm/v1/pqc-seed/ml-dsa-65/<cluster-uuid>/<key-epoch>
bastionvault/hsm/v1/unwrap-authz/<node-id>/<purpose>
bastionvault/hsm/v1/replication-channel/<cluster-uuid>/<epoch>
bastionvault/hsm/v1/migration-transcript/<cluster-uuid>/<epoch>
```

A blob wrapped under one context can never be unwrapped or accepted under another; version bumps (`v1` → `v2`) are treated as new contexts.

## Implementation Scope

### Phase 1: HSM Abstraction + YubiHSM 2 + Mock + Auto-Unseal

| File | Purpose |
|---|---|
| `src/hsm/mod.rs` | `HsmBackend` trait, `BvHsmBlob` format, context-string constants, config parsing |
| `src/hsm/yubihsm2.rs` | `YubiHsm2Backend` via the `yubihsm` crate (feature `hsm_yubihsm2`) |
| `src/hsm/mock.rs` | `MockHsmBackend` (feature `hsm_mock`), file-persisted, production-refusal guard |
| `src/hsm/authz.rs` | Signed unwrap-authorization construction/verification + audit emission |
| `src/seal/mod.rs` | `SealProvider` trait; `ShamirSealProvider` (refactor of current behavior) |
| `src/seal/hsm.rs` | `HsmSealProvider` (auto-unseal) over `HsmBackend` |
| `src/core.rs` | Replace hardcoded Shamir logic with `SealProvider` dispatch |
| `src/cli/config.rs` | Parse `hsm "yubihsm2" { ... }` / `hsm "mock" { ... }` blocks |

Dependencies: `yubihsm` crate (with `mockhsm` for the mock feature), behind `hsm_yubihsm2` / `hsm_mock` feature flags; `zeroize` (already in tree).

### Phase 2: Hybrid PQC Key Custody

| File | Purpose |
|---|---|
| `crates/bv_crypto/src/kem/hsm_custody.rs` | `HsmCustodyKemProvider`: seed derivation, wrap/unwrap lifecycle, session cache |
| `crates/bv_crypto/src/signature/hsm_custody.rs` | `HsmCustodySigProvider` for ML-DSA-65 |
| `src/hsm/derive.rs` | HKDF seed derivation (host entropy + HSM random + ECDH input) with context strings |

### Phase 3: Cluster Bootstrap, Enrollment, Replication

| File | Purpose |
|---|---|
| `src/hsm/enroll.rs` | Attestation verification, enrollment approval flow, per-node object provisioning |
| `src/hsm/replicate.rs` | HSM-to-HSM channel, transcript construction/dual-signing/verification, re-wrap on receipt |
| `src/modules/system/` | `v2/sys/hsm/enroll`, `v2/sys/hsm/status`, `v2/sys/hsm/rotate-epoch` endpoints (+ actix shim for the logical routes) |
| CLI | `bvault operator hsm enroll|status|rotate-epoch` |
| `gui/src/routes/HsmStatusPage.tsx` | Read-only GUI **HSM / Seal** page (seal posture, HSM device, cluster key custody); backed by the `hsm_status` Tauri command |

### Not In Scope

- Generic PKCS#11 backend (Thales Luna, Utimaco, SoftHSM2, AWS CloudHSM) — the `HsmBackend` trait leaves room for it, but only YubiHSM 2 and the mock are targeted now.
- Cloud KMS providers (AWS KMS, Azure Key Vault, GCP KMS) — separate feature, HTTP APIs.
- FIPS 140-2/3 certification process — requires vendor engagement, not just code changes.
- Native HSM PQC operations — revisit when Yubico ships ML-KEM/ML-DSA support; the custody model is designed so seeds can later be migrated into hardware via a signed migration transcript.

## Testing Requirements

### Unit Tests (mock backend, no hardware)
- Wrap/unwrap round-trip; unwrap fails under a different context string, purpose, or epoch.
- Signed unwrap authorization: missing/invalid/replayed (stale counter) authorizations are rejected.
- Seed derivation: output changes when any of the three entropy inputs changes; identical inputs + context are deterministic; different context strings yield unrelated seeds.
- Zeroize discipline: key buffers are `Zeroizing`, cache TTL expiry clears slots, `seal()` clears the cache.
- Config parsing for `hsm "yubihsm2"` and `hsm "mock"` blocks; mock refuses `environment = "production"`.
- Key-separation: attempting to unwrap a PQC blob with the barrier wrap key (and vice versa) fails.

### Integration Tests (mock backend; real-device suite behind `BVAULT_TEST_YUBIHSM=1`)
- Full init + auto-unseal cycle; seal + auto-unseal after restart.
- Two-node enrollment: attestation verification, transcript dual-signing, joiner re-wraps and can unseal with only its own (mock) HSM.
- Tampered transcript or blob digest mismatch → joiner refuses to unseal.
- Epoch rotation: all nodes converge on the new epoch; old blobs retired.
- HSM unavailable at startup → clear error, vault stays sealed; with `recovery = "shamir-ceremony"` configured at init, ceremony unseal works.

### Cucumber BDD Scenarios
- Initialize vault with the mock HSM seal and verify auto-unseal without operator input.
- Enroll a second node and verify it serves reads/writes after a restart using only its own HSM.
- Verify persisted blobs are opaque (not raw keys) and undecryptable after simulated HSM loss.
- Verify every unwrap emits an HSM-signed audit event.

## Security Considerations

- **Residual software exposure**: because the YubiHSM 2 cannot execute ML-KEM/ML-DSA, PQC private keys exist transiently in host memory during use and during enrollment transfer. Mitigations: `Zeroizing` buffers, bounded TTL cache (or strict per-op mode), `mlock`/`MADV_DONTDUMP`, no `Clone`/`Debug` on key types. This is an accepted, documented trade-off until hardware PQC support exists; the *at-rest* and *custody* guarantees are absolute (HSM-gated), the *runtime* guarantee is best-effort.
- **Attestation is the enrollment trust root**: enrollment MUST verify the Yubico attestation chain before any key material moves; the mock backend simulates attestation with a test CA so dev exercises the same code path.
- **HSM credentials**: the auth-key password is read via `env:` (or the OS keychain in GUI/embedded mode); plaintext credentials in config files are rejected outside dev builds.
- **Capability minimization**: wrap keys carry only `wrap-data`/`unwrap-data`; identity keys cannot unwrap; authz keys can only sign. Provisioning code sets capability masks explicitly and enrollment verification checks them.
- **No silent escrow**: `recovery = "none"` is the default and the documented posture — losing every cluster HSM loses the data. `shamir-ceremony` is an explicit, init-time-only, audited opt-in.
- **Mock ≠ security**: the mock backend provides zero hardware protection. The CLI/GUI release artifacts are built without `hsm_mock`; the container image bundles it but the runtime production-refusal guard prevents it from ever backing a production seal. Defense-in-depth rests on that guard, not on the feature being absent from the image.
- **Denial of service vs. fail-closed**: an unreachable HSM keeps the node sealed (fail-closed). Cluster HA covers single-node HSM failures; monitoring should alert on HSM session errors before quorum is threatened.
