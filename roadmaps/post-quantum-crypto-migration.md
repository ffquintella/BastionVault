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
3. Keep old ciphertexts readable during the migration.
4. Introduce new formats with explicit versioning.
5. Do not break operational unseal or rekey paths during rollout.
6. Prefer pure Rust or Rust-first libraries where feasible.

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

### Risks

- some current code paths appear to use Tongsuo-only algorithms such as SM4 and SM2
- removing the feature may expose hidden assumptions in tests and docs

### Acceptance Criteria

- the repo builds and tests without Tongsuo
- there is no Tongsuo feature flag, dependency patch, or CI job left

## Phase 2: Introduce a Provider-Neutral AEAD Interface

### Objectives

- stop treating the crypto layer as an OpenSSL wrapper
- define an AEAD abstraction with a `ChaCha20-Poly1305` implementation

### Work Items

- redesign [src/modules/crypto/mod.rs](/Users/felipe/Dev/BastionVault/src/modules/crypto/mod.rs) to expose provider-neutral traits
- replace the current adaptor layout in [src/modules/crypto/crypto_adaptors](/Users/felipe/Dev/BastionVault/src/modules/crypto/crypto_adaptors)
- add a `ChaCha20-Poly1305` provider
- retain explicit format versioning for compatibility

### Suggested API shape

- `encrypt(key, nonce, aad, plaintext) -> ciphertext`
- `decrypt(key, nonce, aad, ciphertext) -> plaintext`
- `generate_key()`
- `generate_nonce()`

### Acceptance Criteria

- an internal AEAD trait exists
- `ChaCha20-Poly1305` is implemented behind it
- new code paths no longer require OpenSSL for payload encryption

## Phase 3: Migrate Barrier Encryption to ChaCha20-Poly1305

### Objectives

- replace direct OpenSSL use in storage barrier encryption
- keep existing stored barrier data readable

### Work Items

- refactor [src/storage/barrier_aes_gcm.rs](/Users/felipe/Dev/BastionVault/src/storage/barrier_aes_gcm.rs)
- introduce a new barrier format version using `ChaCha20-Poly1305`
- preserve support for decrypting previous barrier versions
- document any changes in barrier metadata and unseal behavior

### Migration Strategy

- read old barrier versions
- write new barrier versions
- provide rekey / rewrite tooling if needed for storage migration

### Risks

- barrier format changes are operationally sensitive
- unseal and rekey flows must remain stable

### Acceptance Criteria

- existing repositories can still unseal
- new writes use the new `ChaCha20-Poly1305` barrier version
- compatibility tests cover old and new formats

## Phase 4: Introduce a KEM Abstraction

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
- `ML-KEM-768` works through deterministic tests and known-answer vectors

## Phase 5: Move Envelope Encryption to Hybrid PQ Mode

### Objectives

- adopt `ChaCha20-Poly1305 + ML-KEM-768` for key protection
- avoid a PQ-only cutover as the first deployment mode

### Recommended Envelope Structure

- `version`
- `aead_algorithm`
- `nonce`
- `ciphertext`
- `aad`
- `kem_algorithm`
- `kem_ciphertext`
- optional `hybrid_metadata`

### Recommended Mode

Start with:

- `X25519 + ML-KEM-768` hybrid key establishment

Later, if required:

- `ML-KEM-768` only

### Work Items

- identify all key wrapping or envelope encryption flows
- migrate those flows to the new envelope format
- maintain read compatibility for old envelope formats

### Acceptance Criteria

- all new envelope encryption uses `ChaCha20-Poly1305`
- key wrapping supports hybrid PQ mode
- old envelopes remain readable until an explicit removal window

## Phase 6: Remove OpenSSL from TLS and Runtime Server Paths

### Objectives

- move the HTTP/TLS server stack off OpenSSL
- reduce the remaining runtime dependency on OpenSSL

### Work Items

- replace OpenSSL server binding in [src/cli/command/server.rs](/Users/felipe/Dev/BastionVault/src/cli/command/server.rs)
- replace TLS peer certificate handling in [src/http/mod.rs](/Users/felipe/Dev/BastionVault/src/http/mod.rs)
- migrate to `rustls`
- verify mutual TLS parity

### Risks

- certificate handling APIs differ materially
- mTLS and certificate inspection paths may require redesign

### Acceptance Criteria

- server TLS no longer depends on OpenSSL
- all existing TLS configuration and mTLS behavior has parity or documented differences

## Phase 7: PKI and Certificate Track

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

### Objectives

- remove OpenSSL from remaining non-PKI paths
- shrink the trusted cryptographic surface area

### Work Items

- remove OpenSSL usage from helper utilities where feasible
- replace OpenSSL-based hashing, random, and key helpers with Rust-native implementations
- review remaining OpenSSL-only test helpers

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

