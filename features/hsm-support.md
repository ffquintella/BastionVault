# Feature: HSM Support

## Summary

Add hardware security module (HSM) integration so that BastionVault's master key and critical cryptographic operations can be protected by tamper-resistant hardware. This covers three capabilities: HSM-backed auto-unseal, HSM-backed key wrapping for the barrier, and HSM-backed cryptographic provider for KEM/signature operations.

## Motivation

BastionVault's master key (the key encryption key, or KEK) is currently generated, split, and reconstructed entirely in software. During unseal, the reconstructed KEK exists in process memory. This creates several risks:

- **Memory exposure**: a memory dump, core dump, or cold-boot attack can extract the KEK.
- **Operational burden**: operators must manually provide unseal shares after every restart.
- **No hardware root of trust**: the entire key hierarchy is rooted in software entropy and software storage.
- **Compliance gaps**: PCI-DSS, FIPS 140-2/3, and FedRAMP require or strongly recommend hardware-backed key protection for secrets management systems.

HSM integration addresses all of these by delegating sensitive key operations to hardware that never exports the private key material.

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

### Where HSM Plugs In

The existing trait abstractions provide clean integration points:

- **KemProvider**: an HSM implementation generates and stores the KEM keypair in hardware; `decapsulate()` happens inside the HSM.
- **SecurityBarrier**: the barrier trait is backend-agnostic; an HSM-backed barrier delegates key wrapping to hardware.
- **Auto-unseal**: a new abstraction that retrieves or unwraps the KEK using an HSM-resident key, eliminating manual share entry.

## Design

### Capability 1: HSM Auto-Unseal

The highest-value, lowest-complexity integration. The HSM holds a wrapping key that protects the KEK at rest. On startup, BastionVault asks the HSM to unwrap the KEK, eliminating manual unseal.

#### How It Works

**Initialization (one-time):**
1. Operator configures an HSM seal in the config file.
2. `Core::init()` generates the KEK as before.
3. Instead of Shamir splitting, the KEK is wrapped by the HSM's wrapping key.
4. The wrapped KEK blob is stored at `core/seal-config` in the storage backend.
5. A recovery key (Shamir-split) is still generated for disaster recovery if the HSM is unavailable.

**Auto-unseal (every startup):**
1. BastionVault reads the wrapped KEK blob from `core/seal-config`.
2. BastionVault sends the blob to the HSM for unwrapping.
3. The HSM returns the plaintext KEK (it never leaves the HSM in persistent form).
4. `barrier.unseal(kek)` proceeds as normal.
5. No human operator intervention required.

**Recovery (HSM unavailable):**
1. Operator provides recovery key shares (generated during init).
2. Recovery key decrypts a backup copy of the KEK stored alongside the HSM-wrapped blob.
3. Unseal proceeds manually.

#### Seal Abstraction

```rust
/// A seal provider wraps and unwraps the barrier's key encryption key.
#[maybe_async::maybe_async]
pub trait SealProvider: Send + Sync {
    /// Seal type identifier (e.g., "shamir", "pkcs11", "awskms").
    fn seal_type(&self) -> &str;

    /// Wrap a key encryption key for storage.
    async fn wrap_kek(&self, kek: &[u8]) -> Result<Vec<u8>, RvError>;

    /// Unwrap a previously wrapped key encryption key.
    async fn unwrap_kek(&self, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, RvError>;

    /// Whether this provider supports automatic unsealing.
    fn is_auto_unseal(&self) -> bool;
}
```

Implementations:
- `ShamirSealProvider` -- current behavior (manual shares). `is_auto_unseal()` returns false.
- `Pkcs11SealProvider` -- PKCS#11 HSM wrapping key. `is_auto_unseal()` returns true.
- Future: `AwsKmsSealProvider`, `AzureKeyVaultSealProvider`, `GcpKmsSealProvider`.

#### Configuration

```hcl
seal "pkcs11" {
  lib_path       = "/usr/lib/softhsm/libsofthsm2.so"
  slot           = 0
  pin            = "env:BVAULT_HSM_PIN"
  key_label      = "bvault-auto-unseal"
  mechanism      = "CKM_AES_KEY_WRAP_KWP"
  generate_key   = true
}
```

| Key | Required | Description |
|---|---|---|
| `lib_path` | Yes | Path to the PKCS#11 shared library. |
| `slot` | No | HSM slot number (default: 0). |
| `pin` | Yes | HSM PIN. Supports `env:VAR_NAME` to read from environment. |
| `key_label` | Yes | Label of the wrapping key in the HSM. |
| `mechanism` | No | PKCS#11 wrapping mechanism (default: `CKM_AES_KEY_WRAP_KWP`). |
| `generate_key` | No | If true and key_label doesn't exist, generate the wrapping key (default: false). |

### Capability 2: HSM-Backed Key Wrapping for Barrier

Instead of software AES-GCM or ChaCha20 wrapping the data encryption key, the HSM performs the wrap/unwrap. The data encryption key never exists in plaintext outside the HSM during the wrapping operation.

This extends Capability 1 by also protecting the **data encryption key wrapping** step, not just the KEK storage.

#### How It Differs from Auto-Unseal

- Auto-unseal: HSM protects the KEK → KEK unwraps the data encryption key in software.
- HSM barrier wrapping: HSM directly wraps/unwraps the data encryption key. The KEK concept is replaced by an HSM-resident key.

#### Implementation

A new barrier variant `HsmBarrier` implements `SecurityBarrier`:
- `init()`: generates a data encryption key inside the HSM, stores an HSM key ID at `barrier/init`.
- `unseal()`: retrieves the key from the HSM by ID. The key stays in HSM memory; barrier operations call out to the HSM for each encrypt/decrypt.
- Performance consideration: per-operation HSM calls add latency. A hybrid approach can cache the data encryption key in memory after HSM retrieval (same as current barriers do), using the HSM only for the initial unwrap.

### Capability 3: HSM-Backed Crypto Provider

Replace the software KEM, signature, and AEAD providers with HSM-backed implementations.

#### KEM Provider

```rust
pub struct HsmMlKem768Provider {
    session: Pkcs11Session,
    key_id: ObjectHandle,
}

impl KemProvider for HsmMlKem768Provider {
    fn generate_keypair(&self) -> Result<KemKeypair, CryptoError> {
        // HSM generates and stores the keypair
        // Returns public key; private key stays in HSM
    }

    fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<SharedSecret, CryptoError> {
        // HSM performs decapsulation using stored private key
        // `secret_key` parameter is an HSM key handle, not raw key material
    }
}
```

#### Signature Provider

Similar pattern: `sign()` uses an HSM-resident signing key. The signing key never leaves hardware.

#### Scope Note

Capability 3 is the most complex and HSM-dependent. Not all HSMs support ML-KEM-768 or ML-DSA-65 (post-quantum algorithms). Phase 1 should focus on Capabilities 1 and 2 using standard PKCS#11 mechanisms (AES key wrap, RSA OAEP). Post-quantum HSM support depends on HSM vendor adoption of NIST PQC standards.

## Implementation Scope

### Phase 1: Auto-Unseal via PKCS#11

| File | Purpose |
|---|---|
| `src/seal/mod.rs` | `SealProvider` trait, `SealConfig` parsing |
| `src/seal/shamir.rs` | `ShamirSealProvider` (refactor current behavior) |
| `src/seal/pkcs11.rs` | `Pkcs11SealProvider` using PKCS#11 HSM |
| `src/core.rs` | Replace hardcoded Shamir logic with `SealProvider` dispatch |
| `src/cli/config.rs` | Parse `seal "pkcs11" { ... }` config blocks |

Dependencies:
- `cryptoki` crate (Rust PKCS#11 bindings) -- optional, behind `hsm_pkcs11` feature flag.

### Phase 2: HSM-Backed Barrier

| File | Purpose |
|---|---|
| `src/storage/barrier_hsm.rs` | `HsmBarrier` implementing `SecurityBarrier` |
| `src/storage/mod.rs` | Add `BarrierType::Hsm` variant |

### Phase 3: HSM Crypto Providers

| File | Purpose |
|---|---|
| `crates/bv_crypto/src/kem/hsm.rs` | `HsmKemProvider` implementing `KemProvider` |
| `crates/bv_crypto/src/sig/hsm.rs` | HSM signature provider |

### Not In Scope

- Cloud KMS providers (AWS KMS, Azure Key Vault, GCP KMS) -- separate feature, uses HTTP APIs not PKCS#11.
- FIPS 140-2/3 certification process -- requires vendor engagement, not just code changes.
- HSM cluster/HA management -- assumed to be handled by the HSM infrastructure itself.

## Testing Requirements

### Unit Tests
- `SealProvider` trait with a mock HSM (in-memory key store).
- Wrap/unwrap round-trip via mock PKCS#11.
- Recovery key generation and manual unseal fallback.
- Config parsing for `seal "pkcs11"` blocks.

### Integration Tests (require SoftHSM2)
- Full init + auto-unseal cycle with SoftHSM2.
- Seal + auto-unseal after restart.
- Recovery unseal when HSM is unavailable (remove SoftHSM library).
- Key rotation: generate new wrapping key, re-wrap KEK.

### Cucumber BDD Scenarios
- Initialize vault with PKCS#11 seal and verify auto-unseal works.
- Seal the vault and verify it auto-unseals without operator input.
- Simulate HSM failure and verify recovery key unseal works.
- Verify wrapped KEK blob is opaque (not the raw KEK).

## Security Considerations

- The HSM PIN must not be stored in the config file in plaintext for production. The `env:VAR_NAME` syntax reads from environment variables. A future enhancement can support file-based or stdin-based PIN entry.
- The data encryption key still exists in process memory during normal operation (same as current behavior). HSM integration protects the **key at rest** and **key wrapping**, not the runtime key in memory. For full runtime protection, Capability 2 with per-operation HSM calls is needed, at significant performance cost.
- SoftHSM2 is acceptable for development and testing but provides no hardware protection. Production deployments must use a real HSM (e.g., Thales Luna, Utimaco, YubiHSM 2, AWS CloudHSM).
- PKCS#11 library loading (`lib_path`) executes native code. The library path must be validated and restricted to trusted locations.
- Recovery keys are the fallback if the HSM is permanently lost. They must be stored securely (e.g., in a physical safe, separate from the HSM). Without recovery keys and without the HSM, the vault data is unrecoverable.
