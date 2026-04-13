# BastionVault Post-Quantum Crypto Migration Roadmap

## Goal

Remove the dependency on the Tongsuo library and migrate BastionVault toward a post-quantum-ready cryptography stack with:

- `ChaCha20-Poly1305` for payload encryption
- `ML-KEM-768` for key establishment and key wrapping
- `ML-DSA-65` for post-quantum signatures
- a modular provider model that no longer assumes OpenSSL/Tongsuo APIs

## Status: Complete

All phases of the post-quantum crypto migration have been completed. The default build is fully PQ-backed with no OpenSSL or Tongsuo dependencies.

## Important Scope Clarification

`ML-KEM-768` does not replace bulk encryption.

It is a key encapsulation mechanism, not a data cipher. The correct architecture is:

1. generate a random data encryption key (DEK)
2. encrypt payloads with `ChaCha20-Poly1305`
3. protect the DEK with `ML-KEM-768` or a hybrid KEM
4. store both the encrypted payload and the KEM output in a versioned envelope

## Current Cryptographic Stack

| Purpose | Algorithm | Implementation |
|---------|-----------|----------------|
| Payload encryption | `ChaCha20-Poly1305` | `crates/bv_crypto` |
| Key establishment | `ML-KEM-768` | `crates/bv_crypto` |
| Post-quantum signatures | `ML-DSA-65` | `crates/bv_crypto` |
| Storage barrier | `ChaCha20-Poly1305` + `ML-KEM-768` envelope | `src/storage/barrier_chacha20_poly1305.rs` |
| TLS | TLS 1.2/1.3 | `rustls` |
| Hashing / HMAC | BLAKE2b, SHA-256 | `blake2`, `sha2` |

## Phase Completion Summary

### Phase 0: Design and Inventory — Done

- Dependency inventory completed
- Interface design for AEAD, KEM, signature, and envelope primitives completed
- All Tongsuo-specific code paths were enumerated and removed

### Phase 1: Remove Tongsuo as a Supported Backend — Done

- Removed `crypto_adaptor_tongsuo` feature from Cargo.toml
- Removed the Cargo patch to `rust-tongsuo`
- Deleted `tongsuo_adaptor.rs`
- Removed Tongsuo CI job
- Cleaned all Tongsuo documentation references

### Phase 2: Introduce a Provider-Neutral AEAD Interface — Done

- `crates/bv_crypto` provides the provider-neutral AEAD surface
- `ChaCha20-Poly1305` is the sole AEAD implementation
- Legacy adaptor layer fully retired (stubs, traits, and directory removed)

### Phase 3: Migrate Barrier Encryption to ChaCha20-Poly1305 — Done

- `barrier_chacha20_poly1305.rs` is live and PQ-backed
- `chacha20-poly1305` is the default barrier type
- Bootstrap and unseal use ML-KEM-768 envelope wrapping

### Phase 4: Introduce a KEM Abstraction — Done

- `ML-KEM-768` implemented in `crates/bv_crypto` with provider-neutral interface
- Deterministic seed-based keypair derivation supported
- Versioned `KemDemEnvelopeV1` envelope primitive in use

### Phase 5: Move Envelope Encryption to PQ Mode — Done

- All envelope encryption uses `ChaCha20-Poly1305` + `ML-KEM-768`
- `seal.rs`, `crypto.rs`, and `key.rs` all migrated to PQ envelope model
- No remaining direct AES/OpenSSL wrapping paths

### Phase 5A: Introduce PQ Signatures for Key Management — Done

- `ML-DSA-65` implemented in `crates/bv_crypto`
- `KeyBundle` supports `ml-dsa-65` sign and verify
- PKI key-management endpoints support PQ signature generation, import, sign, and verify

### Phase 6: Remove OpenSSL from TLS and Runtime Server Paths — Done

- Server TLS binds through `rustls` only
- Transport-layer certificate data carried as DER
- No OpenSSL types in the transport or routing layer

### Phase 7: PKI and Certificate Track — Done

- Legacy PKI certificate issuance and cert-auth modules disabled in default build
- PQ key-management endpoints remain active
- Future PQ certificate or trust-distribution work is a separate initiative

### Phase 8: Cleanup and OpenSSL Exit — Done

- OpenSSL fully removed from the default build graph
- Legacy crypto adaptor layer removed (stubs, traits, directory)
- Dead Tongsuo cfg gate removed from `build.rs`
- All documentation updated to reflect PQ-first stack
- No `openssl` crate in Cargo.toml dependencies

## Testing Strategy

### Required test categories

- known-answer tests for AEAD, KEM, and PQ signature flows
- backward compatibility tests for old barrier and envelope formats
- migration tests for read-old / write-new behavior
- operational tests for init, unseal, rekey, rotate, and restart
- negative tests for malformed ciphertexts, invalid tags, and invalid KEM payloads

### Specific requirements

- golden vectors for every ciphertext format version
- explicit tests for nonce handling and AAD validation
- compatibility tests proving that old storage can still be read after upgrade

## Future Work

The following items are explicitly out of scope for this migration and would be separate initiatives:

- PQ certificate issuance (PQ X.509 or alternative trust-distribution model)
- Hybrid mode (`X25519 + ML-KEM-768`) if operational requirements justify it
- Full removal of the legacy AES-GCM barrier (kept for read compatibility)
