# BastionVault Post-Quantum Crypto Migration Roadmap

## Goal

Remove the dependency on the Tongsuo library and migrate BastionVault toward a post-quantum-ready cryptography stack with:

- `ChaCha20-Poly1305` for payload encryption
- `ML-KEM-768` for key establishment and key wrapping
- a modular provider model that no longer assumes OpenSSL/Tongsuo APIs

## Important Scope Clarification

`ML-KEM-768` does not replace bulk encryption.

It is a key encapsulation mechanism, not a data cipher. The correct architecture is:

1. generate a random data encryption key (DEK)
2. encrypt payloads with `ChaCha20-Poly1305`
3. protect the DEK with `ML-KEM-768` or a hybrid KEM
4. store both the encrypted payload and the KEM output in a versioned envelope

This roadmap therefore separates:

- removing `Tongsuo`
- reducing `OpenSSL` coupling
- introducing `ChaCha20-Poly1305`
- introducing `ML-KEM-768`
- migrating TLS and PKI later, as separate tracks

## Current State

The current codebase is not only Tongsuo-dependent. It is structurally OpenSSL-centric, with Tongsuo exposed as a compatible variant through the Rust `openssl` API.

Key locations:

- [Cargo.toml](/Users/felipe/Dev/BastionVault/Cargo.toml)
- [src/modules/crypto/mod.rs](/Users/felipe/Dev/BastionVault/src/modules/crypto/mod.rs)
- [src/modules/crypto/crypto_adaptors/mod.rs](/Users/felipe/Dev/BastionVault/src/modules/crypto/crypto_adaptors/mod.rs)
- [src/modules/crypto/crypto_adaptors/openssl_adaptor.rs](/Users/felipe/Dev/BastionVault/src/modules/crypto/crypto_adaptors/openssl_adaptor.rs)
- [src/modules/crypto/crypto_adaptors/tongsuo_adaptor.rs](/Users/felipe/Dev/BastionVault/src/modules/crypto/crypto_adaptors/tongsuo_adaptor.rs)
- [src/storage/barrier_aes_gcm.rs](/Users/felipe/Dev/BastionVault/src/storage/barrier_aes_gcm.rs)
- [src/cli/command/server.rs](/Users/felipe/Dev/BastionVault/src/cli/command/server.rs)
- [src/http/mod.rs](/Users/felipe/Dev/BastionVault/src/http/mod.rs)
- [src/utils/cert.rs](/Users/felipe/Dev/BastionVault/src/utils/cert.rs)
- [src/modules/pki](/Users/felipe/Dev/BastionVault/src/modules/pki)

## Target Architecture

### Crypto responsibilities

Split the crypto layer into explicit capability groups:

- random generation
- AEAD encryption
- hashing and HMAC
- KDF and key derivation
- signatures
- KEM and key agreement
- X.509 and certificate operations
- TLS server integration

### Desired cryptographic defaults

- Payload encryption: `ChaCha20-Poly1305`
- Key wrapping / key establishment: `ML-KEM-768`
- Transitional key establishment mode: `hybrid (X25519 + ML-KEM-768)`
- TLS stack: `rustls`

### Recommended migration principle

Use hybrid mode before PQ-only mode.

That keeps the system operationally safer while PQ support matures and while clients, peers, and operational tooling catch up.

## Guiding Principles

1. Remove Tongsuo first, then remove OpenSSL-shaped assumptions.
2. Migrate storage and envelope encryption before attempting PQ PKI.
3. For the new `chacha20-poly1305` path, prioritize the PQ target state over backward compatibility.
4. Introduce new formats with explicit versioning.
5. Do not break operational unseal or rekey paths during rollout.
6. Prefer pure Rust or Rust-first libraries where feasible.

## Implementation Status

The roadmap is no longer only a design document. The migration is already underway in small slices.

For the execution tracker and latest completion status, see [post-quantum-crypto-progress.md](/Users/felipe/Dev/BastionVault/roadmaps/post-quantum-crypto-progress.md).

### Completed or in progress

- `crates/bv_crypto` now exists and contains the new AEAD, KEM, and KEM+DEM envelope building blocks.
- `ChaCha20-Poly1305` is implemented in the new crate behind a small provider-neutral interface.
- `ML-KEM-768` is implemented in the new crate, including deterministic seed-based keypair derivation for stable unseal and sealing flows.
- a versioned `KemDemEnvelopeV1` exists and is used as the shared post-quantum envelope primitive.
- the storage layer now includes:
  - [src/storage/barrier_chacha20_poly1305.rs](/Users/felipe/Dev/BastionVault/src/storage/barrier_chacha20_poly1305.rs)
  - [src/storage/barrier_chacha20_poly1305_init.rs](/Users/felipe/Dev/BastionVault/src/storage/barrier_chacha20_poly1305_init.rs)
  - [src/storage/pq_key_envelope.rs](/Users/felipe/Dev/BastionVault/src/storage/pq_key_envelope.rs)
- `barrier_type = chacha20-poly1305` is live and the ChaCha barrier now uses PQ bootstrap by default.
- [src/utils/seal.rs](/Users/felipe/Dev/BastionVault/src/utils/seal.rs) now seals with `ML-KEM-768 + ChaCha20-Poly1305` and Shamir-splits the ML-KEM seed rather than a symmetric AES key.
- [src/utils/crypto.rs](/Users/felipe/Dev/BastionVault/src/utils/crypto.rs) now uses the same PQ envelope model.
- [src/utils/key.rs](/Users/felipe/Dev/BastionVault/src/utils/key.rs) has started the same migration for symmetric key encryption while keeping the current `KeyBundle` API stable.
- the PKI key-management endpoints now validate and test symmetric import/export material as PQ seed input instead of legacy AES-sized raw keys.
- certificate-role validation for RSA and EC issuance is now centralized instead of duplicated across multiple PKI entry points.
- the Tongsuo Cargo patch, CI job, and adaptor export have been removed, and Tongsuo is no longer a supported build target.
- the runtime TLS stack has been migrated to `rustls`, and transport-layer certificate data now moves as DER rather than OpenSSL `X509` objects.
- several PKI boundary paths now delegate OpenSSL-heavy parsing and conversion work into shared helpers in [src/utils/cert.rs](/Users/felipe/Dev/BastionVault/src/utils/cert.rs) instead of duplicating it in path handlers.
- generic hashing and HMAC code paths used by mounts, AppRole validation, and salt handling no longer depend on OpenSSL.
- the shared test temp-directory race was fixed in [src/test_utils.rs](/Users/felipe/Dev/BastionVault/src/test_utils.rs), which unblocked parallel test execution for the affected lib tests.

### Still pending

- removal of remaining OpenSSL-centric helper paths
- PKI redesign away from OpenSSL/Tongsuo assumptions

## Proposed Phases

## Phase 0: Design and Inventory

### Objectives

- identify every Tongsuo-specific feature, test, and doc path
- identify every direct `openssl` coupling that blocks a clean provider model
- define new internal crypto capability traits

### Deliverables

- internal RFC for the new crypto provider interfaces
- dependency inventory for Tongsuo/OpenSSL usage
- migration decision document for crate selection

### Acceptance Criteria

- a written interface design exists for AEAD, KEM, RNG, hash, KDF, signature, TLS, and X.509
- all current Tongsuo-specific code paths are enumerated

## Phase 1: Remove Tongsuo as a Supported Backend

Status: in progress

### Objectives

- remove Tongsuo as a build feature
- keep the system functioning while still temporarily using OpenSSL where necessary

### Work Items

- remove `crypto_adaptor_tongsuo` from [Cargo.toml](/Users/felipe/Dev/BastionVault/Cargo.toml)
- remove the Cargo patch to `rust-tongsuo`
- delete [src/modules/crypto/crypto_adaptors/tongsuo_adaptor.rs](/Users/felipe/Dev/BastionVault/src/modules/crypto/crypto_adaptors/tongsuo_adaptor.rs)
- remove Tongsuo-specific CI from [.github/workflows/rust.yml](/Users/felipe/Dev/BastionVault/.github/workflows/rust.yml)
- remove Tongsuo-specific documentation from:
  - [docs/docs/crypto.md](/Users/felipe/Dev/BastionVault/docs/docs/crypto.md)
  - [docs/docs/design.md](/Users/felipe/Dev/BastionVault/docs/docs/design.md)

### Current State

- complete:
  - Cargo patch removal
  - feature removal from [Cargo.toml](/Users/felipe/Dev/BastionVault/Cargo.toml)
  - adaptor export removal
  - adaptor file deletion
  - CI job removal
  - main crypto adaptor docs cleanup
- remaining:
  - remove any residual Tongsuo-era design/docs references that still survive outside the main cleaned paths

### Risks

- some current code paths appear to use Tongsuo-only algorithms such as SM4 and SM2
- removing the feature may expose hidden assumptions in tests and docs

### Acceptance Criteria

- the repo builds and tests without Tongsuo
- there is no Tongsuo feature flag, dependency patch, or CI job left

## Phase 2: Introduce a Provider-Neutral AEAD Interface

Status: substantially complete in the new `crates/bv_crypto` crate, but not yet the only crypto surface in the repository.

### Objectives

- stop treating the crypto layer as an OpenSSL wrapper
- define an AEAD abstraction with a `ChaCha20-Poly1305` implementation

### Work Items

- keep expanding `crates/bv_crypto` as the narrow PQ-first crypto surface
- redesign [src/modules/crypto/mod.rs](/Users/felipe/Dev/BastionVault/src/modules/crypto/mod.rs) to expose provider-neutral traits
- replace the current adaptor layout in [src/modules/crypto/crypto_adaptors](/Users/felipe/Dev/BastionVault/src/modules/crypto/crypto_adaptors)
- retain explicit format versioning where legacy formats still exist

### Suggested API shape

- `encrypt(key, nonce, aad, plaintext) -> ciphertext`
- `decrypt(key, nonce, aad, ciphertext) -> plaintext`
- `generate_key()`
- `generate_nonce()`

### Acceptance Criteria

- an internal AEAD trait exists
- `ChaCha20-Poly1305` is implemented behind it
- new PQ-first code paths no longer require OpenSSL for payload encryption

## Phase 3: Migrate Barrier Encryption to ChaCha20-Poly1305

Status: in progress, with the new ChaCha barrier live and PQ-backed.

### Objectives

- replace direct OpenSSL use in storage barrier encryption
- make the `chacha20-poly1305` barrier path the canonical PQ storage path

### Work Items

- continue reducing the old AES barrier's importance in favor of:
  - [src/storage/barrier_chacha20_poly1305.rs](/Users/felipe/Dev/BastionVault/src/storage/barrier_chacha20_poly1305.rs)
  - [src/storage/barrier_chacha20_poly1305_init.rs](/Users/felipe/Dev/BastionVault/src/storage/barrier_chacha20_poly1305_init.rs)
- keep the barrier type selection explicit in config while the PQ rollout is still being staged
- document the new unseal behavior for the PQ barrier bootstrap

### Migration Strategy

- keep the AES barrier path available temporarily
- keep moving new work onto the ChaCha/PQ path
- add rewrite or promotion tooling later if full cutover automation is needed

### Risks

- barrier format changes are operationally sensitive
- unseal and rekey flows must remain stable

### Acceptance Criteria

- the `chacha20-poly1305` barrier path is stable
- new writes on that path use the new `ChaCha20-Poly1305` barrier format
- barrier bootstrap uses PQ wrapping rather than direct symmetric wrapping

## Phase 4: Introduce a KEM Abstraction

Status: substantially complete in `crates/bv_crypto`.

### Objectives

- add first-class support for KEM-based key protection
- make `ML-KEM-768` a pluggable mechanism rather than a one-off feature

### Work Items

- add a KEM trait in the crypto module
- implement an `ML-KEM-768` provider
- define serialized envelope structures for KEM outputs

### Suggested API shape

- `keygen() -> (public_key, secret_key)`
- `encapsulate(public_key) -> (ciphertext, shared_secret)`
- `decapsulate(secret_key, ciphertext) -> shared_secret`

### Acceptance Criteria

- KEM operations are available through a provider-neutral interface
- `ML-KEM-768` works through deterministic tests and seeded derivation paths needed by BastionVault runtime flows

## Phase 5: Move Envelope Encryption to Hybrid PQ Mode

Status: partially complete, but currently using `ML-KEM-768` directly rather than a hybrid mode.

### Objectives

- adopt `ChaCha20-Poly1305 + ML-KEM-768` for key protection across the remaining helper surfaces
- optionally add hybrid mode later if operational requirements justify it

### Recommended Envelope Structure

- `version`
- `aead_algorithm`
- `nonce`
- `ciphertext`
- `aad`
- `kem_algorithm`
- `kem_ciphertext`
- optional `hybrid_metadata`

### Current Mode

Current implementation work is using:

- `ML-KEM-768` for key establishment and wrapping
- `ChaCha20-Poly1305` for payload encryption

Hybrid mode remains a possible later step rather than a current blocker.

### Work Items

- finish moving remaining helper paths to the new envelope format
- migrate remaining higher-level key handling away from direct AES/OpenSSL wrapping
- decide whether any runtime flows actually need hybrid mode before adding more complexity

### Acceptance Criteria

- all new envelope encryption uses `ChaCha20-Poly1305`
- the main storage and helper surfaces use `ML-KEM-768` wrapping
- any remaining direct symmetric wrapping paths are removed or explicitly deprecated

## Phase 6: Remove OpenSSL from TLS and Runtime Server Paths

Status: substantially complete

### Objectives

- move the HTTP/TLS server stack off OpenSSL
- reduce the remaining runtime dependency on OpenSSL

### Work Items

- replace OpenSSL server binding in [src/cli/command/server.rs](/Users/felipe/Dev/BastionVault/src/cli/command/server.rs)
- replace TLS peer certificate handling in [src/http/mod.rs](/Users/felipe/Dev/BastionVault/src/http/mod.rs)
- migrate to `rustls`
- verify mutual TLS parity

### Current State

- server TLS now binds through `rustls`
- transport-layer client certificate data is carried as DER and converted only at the cert-auth boundary
- the remaining work is no longer the TLS runtime migration itself; it is the residual OpenSSL usage inside PKI validation and certificate-construction helpers

### Risks

- certificate handling APIs differ materially
- mTLS and certificate inspection paths may require redesign

### Acceptance Criteria

- server TLS no longer depends on OpenSSL
- all existing TLS configuration and mTLS behavior has parity or documented differences

## Phase 7: PKI and Certificate Track

Status: in progress

### Objectives

- decouple PKI from OpenSSL internals
- postpone PQ PKI until the storage, KEM, and TLS migrations are stable

### Work Items

- inventory direct PKI OpenSSL usage in:
  - [src/modules/pki](/Users/felipe/Dev/BastionVault/src/modules/pki)
  - [src/utils/cert.rs](/Users/felipe/Dev/BastionVault/src/utils/cert.rs)
  - [src/modules/credential/cert](/Users/felipe/Dev/BastionVault/src/modules/credential/cert)
- preserve RSA/ECDSA support first under the new architecture
- evaluate later support for PQ signatures separately

### Recommendation

Do not block Tongsuo removal on PQ certificate issuance.

Treat PQ PKI as a later, optional track.

### Acceptance Criteria

- classical PKI still works without Tongsuo
- PQ PKI remains a separate milestone, not a prerequisite for core migration

## Phase 8: Cleanup and OpenSSL Exit

Status: in progress

### Objectives

- remove OpenSSL from remaining non-PKI paths
- shrink the trusted cryptographic surface area

### Work Items

- remove OpenSSL usage from helper utilities where feasible
- replace OpenSSL-based hashing, random, and key helpers with Rust-native implementations
- review remaining OpenSSL-only test helpers

### Current focus

- continue shrinking helper-level OpenSSL usage in:
  - [src/utils/key.rs](/Users/felipe/Dev/BastionVault/src/utils/key.rs)
  - [src/utils/crypto.rs](/Users/felipe/Dev/BastionVault/src/utils/crypto.rs)
  - [src/utils/seal.rs](/Users/felipe/Dev/BastionVault/src/utils/seal.rs)
- keep tightening the PKI management surfaces so their key import/export semantics match the PQ-backed symmetric implementation
- remove the Tongsuo feature and its Cargo/CI/doc wiring
- isolate the still-OpenSSL-dependent PKI and TLS code so the remaining exit work is explicit

### Acceptance Criteria

- OpenSSL is no longer required for storage, envelope encryption, or TLS
- any remaining OpenSSL usage is limited, explicit, and justified

## Recommended Milestone Sequence

### Milestone 1

Tongsuo removed from build, docs, and CI.

### Milestone 2

Provider-neutral AEAD introduced and `ChaCha20-Poly1305` implemented.

### Milestone 3

Barrier encryption migrated to the new versioned `ChaCha20-Poly1305` format.

### Milestone 4

KEM trait introduced and `ML-KEM-768` implemented.

### Milestone 5

Envelope encryption migrated to hybrid PQ mode.

### Milestone 6

TLS migrated from OpenSSL to `rustls`.

### Milestone 7

PKI refactor completed, with PQ PKI evaluated separately.

## Testing Strategy

### Required test categories

- known-answer tests for AEAD and KEM
- backward compatibility tests for old barrier and envelope formats
- migration tests for read-old / write-new behavior
- operational tests for init, unseal, rekey, rotate, and restart
- negative tests for malformed ciphertexts, invalid tags, and invalid KEM payloads

### Specific requirements

- golden vectors for every ciphertext format version
- explicit tests for nonce handling and AAD validation
- compatibility tests proving that old storage can still be read after upgrade

## Risks and Constraints

### Technical risks

- the current abstraction layer is too close to OpenSSL and will need redesign
- PKI and X.509 are much harder to migrate than storage AEAD
- PQ TLS and PQ PKI have less mature interoperability than classical stacks

### Product risks

- incompatible ciphertext format changes can break unseal or recovery if not versioned correctly
- an overly aggressive PQ-only rollout could reduce operational compatibility

### Mitigations

- use hybrid mode first
- preserve read compatibility during migration
- version all serialized cryptographic formats
- migrate storage and envelope encryption before PKI

## Suggested Decision Record

The project should explicitly adopt the following technical position:

- `ChaCha20-Poly1305` is the default payload encryption mechanism
- `ML-KEM-768` is the default PQ KEM for key protection
- hybrid key establishment is the default transition mode
- Tongsuo support will be removed before full OpenSSL removal

## Immediate Next Steps

1. remove the Tongsuo feature, Cargo patch, docs, and CI job
2. define provider-neutral AEAD and KEM traits
3. prototype a new versioned barrier format based on `ChaCha20-Poly1305`
4. select the `ML-KEM-768` crate and write conformance tests before integrating it into higher-level flows
