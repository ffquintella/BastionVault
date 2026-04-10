# BastionVault Post-Quantum Crypto Migration Progress

## Purpose

This file tracks implementation progress for the post-quantum migration.

Use it as the execution log for what is already done, what is in flight, and what should be tackled next.
The strategy, target architecture, and phase definitions remain in [post-quantum-crypto-migration.md](/Users/felipe/Dev/BastionVault/roadmaps/post-quantum-crypto-migration.md).

## Current Status

Overall state: active, partially implemented

Current focus:
- finish the remaining PKI and certificate cleanup
- migrate TLS and runtime server paths away from OpenSSL
- keep new crypto work isolated in smaller modules and crates

## Checklist

### Completed

- [x] Create `crates/bv_crypto`
- [x] Add provider-neutral AEAD primitives
- [x] Implement `ChaCha20-Poly1305`
- [x] Implement `ML-KEM-768`
- [x] Add deterministic ML-KEM seed-derived keypair support
- [x] Add shared versioned KEM+DEM envelope support
- [x] Add `chacha20-poly1305` barrier implementation
- [x] Add PQ-backed barrier bootstrap and unseal flow
- [x] Expose config-selectable ChaCha barrier path
- [x] Migrate `seal.rs` to the PQ envelope model
- [x] Migrate `crypto.rs` to the PQ envelope model
- [x] Migrate the symmetric path in `key.rs` to the PQ envelope model
- [x] Remove the Tongsuo Cargo patch
- [x] Remove the Tongsuo Cargo feature
- [x] Remove the Tongsuo CI job
- [x] Delete the Tongsuo adaptor source file
- [x] Remove dead Tongsuo cfg branches from active code paths
- [x] Align PKI symmetric key import/export with PQ seed semantics
- [x] Update PKI symmetric test fixtures to PQ seed material
- [x] Centralize RSA/EC certificate role validation
- [x] Fix the shared test temp-directory race
- [x] Replace `openssl::ssl::SslVersion` in `config.rs` and `server.rs` with a local `TlsVersion` enum
- [x] Remove the dead OpenSSL `TlsStream` handler branch from `src/http/mod.rs`
- [x] Remove the `client_verify_result: X509VerifyResult` field (was only populated by the removed OpenSSL path)
- [x] Drop the `"openssl"` feature from `actix-web` in `Cargo.toml`
- [x] Fix stale `HandshakeSignatureValid` import path in `src/utils/rustls.rs`
- [x] Audit PKI CA import and certificate response paths — no stale SM2/SM4 algorithm claims found in active code
- [x] Update `docs/docs/req.md` to reflect current algorithm support (remove SM2/SM4, add PQ targets)
- [x] Update zh-CN `design.md` to remove Tongsuo/rust-tongsuo description from Crypto Manager
- [x] Switch `peer_tls_cert` in `src/logical/connection.rs` from `Vec<X509>` to `Vec<CertificateDer<'static>>`
- [x] Switch `TlsClientInfo.client_cert_chain` in `src/http/mod.rs` to `Vec<CertificateDer<'static>>` and store DER directly from rustls with no conversion
- [x] Add `der_chain_to_x509` conversion helper in `src/modules/credential/cert/path_login.rs` and convert at the cert-auth module boundary
- [x] Add `build_x509_subject_name()` helper to `src/utils/cert.rs` as the single point where `X509NameBuilder` is used for PKI subject construction
- [x] Remove `openssl::x509::X509NameBuilder` import from `src/modules/pki/util.rs`; call `build_x509_subject_name()` from `cert.rs` instead
- [x] Refactor `path_issue.rs::issue_cert()` to delegate to `util::generate_certificate()` — removed 80 lines of duplicated name-building and SAN parsing; only the CA-TTL comparison (`Asn1Time`) remains unique to `issue_cert`
- [x] Replace `CertBundle.private_key: PKey<Private>` with `Vec<u8>` (PKCS8 PEM bytes) — `CertBundle` no longer holds an OpenSSL type as a stored field; add `private_key_as_pkey()` helper for on-demand conversion; update all callers (`path_config_ca.rs`, `path_issue.rs`, `path_root.rs`)

### In Progress

- [ ] Continue reducing OpenSSL surface in `src/utils/cert.rs` and PKI modules

### Next

- [ ] Run a broader repository validation pass after PKI type migration lands
- [ ] Identify remaining `openssl` types in PKI structs and function signatures

## Completed

### Workspace and crypto foundation

- created [crates/bv_crypto](/Users/felipe/Dev/BastionVault/crates/bv_crypto)
- added a provider-neutral AEAD surface
- implemented `ChaCha20-Poly1305`
- implemented `ML-KEM-768`
- added deterministic ML-KEM seed-based keypair derivation
- added a shared versioned `KemDemEnvelopeV1`

### Storage and barrier path

- added [barrier_chacha20_poly1305.rs](/Users/felipe/Dev/BastionVault/src/storage/barrier_chacha20_poly1305.rs)
- added [barrier_chacha20_poly1305_init.rs](/Users/felipe/Dev/BastionVault/src/storage/barrier_chacha20_poly1305_init.rs)
- added [pq_key_envelope.rs](/Users/felipe/Dev/BastionVault/src/storage/pq_key_envelope.rs)
- added config-selectable `barrier_type = chacha20-poly1305`
- made the ChaCha barrier PQ-backed by default for bootstrap/unseal

### Helper and sealing paths

- migrated [seal.rs](/Users/felipe/Dev/BastionVault/src/utils/seal.rs) to `ML-KEM-768 + ChaCha20-Poly1305`
- migrated [crypto.rs](/Users/felipe/Dev/BastionVault/src/utils/crypto.rs) to the PQ envelope model
- migrated the symmetric path in [key.rs](/Users/felipe/Dev/BastionVault/src/utils/key.rs) to PQ-backed envelope encryption while keeping the external `KeyBundle` API stable

### Tongsuo removal

- removed the Cargo patch to `rust-tongsuo`
- removed the `crypto_adaptor_tongsuo` feature from [Cargo.toml](/Users/felipe/Dev/BastionVault/Cargo.toml)
- removed the Tongsuo CI job from [rust.yml](/Users/felipe/Dev/BastionVault/.github/workflows/rust.yml)
- deleted [tongsuo_adaptor.rs](/Users/felipe/Dev/BastionVault/src/modules/crypto/crypto_adaptors/tongsuo_adaptor.rs)
- removed the remaining `crypto_adaptor_tongsuo` cfg branches from build and legacy runtime code
- cleaned the main crypto adaptor docs

### PKI progress

- removed SM2-specific build branches from the active PKI code paths
- aligned PKI symmetric key import/export with PQ seed semantics
- updated PKI symmetric test fixtures to use valid ML-KEM seed material
- centralized certificate role validation for RSA and EC issuance
- corrected stale PKI field/help text that no longer matched the current implementation

### Test and maintenance work

- fixed the shared temp-directory race in [src/test_utils.rs](src/test_utils.rs)
- kept targeted storage, helper, and PKI tests green through each migration slice

### Runtime networking — OpenSSL fully removed from the TLS stack

- removed dead OpenSSL `TlsStream` handler from [src/http/mod.rs](src/http/mod.rs); server was already on `bind_rustls_0_23`
- removed `client_verify_result: X509VerifyResult` from `TlsClientInfo` (was only set by the removed OpenSSL path)
- dropped the `"openssl"` feature from `actix-web` in [Cargo.toml](Cargo.toml)
- replaced `openssl::ssl::SslVersion` in [src/cli/config.rs](src/cli/config.rs) with a local `TlsVersion` enum
- removed the last `SslVersion` import from [src/cli/command/server.rs](src/cli/command/server.rs)
- fixed stale `HandshakeSignatureValid` import path in [src/utils/rustls.rs](src/utils/rustls.rs)
- switched `peer_tls_cert` in [src/logical/connection.rs](src/logical/connection.rs) from `Vec<X509>` to `Vec<CertificateDer<'static>>`
- switched `TlsClientInfo.client_cert_chain` in [src/http/mod.rs](src/http/mod.rs) to `Vec<CertificateDer<'static>>` — rustls DER bytes now stored directly with no OpenSSL conversion
- added `der_chain_to_x509` in [src/modules/credential/cert/path_login.rs](src/modules/credential/cert/path_login.rs) to convert `CertificateDer` → `X509` at the cert-auth module boundary only

### Documentation cleanup

- audited PKI CA import and certificate response paths — no stale SM2/SM4 algorithm claims found in active code
- updated [docs/docs/req.md](docs/docs/req.md) to remove SM2/SM4 from active requirements; added PQ targets
- updated zh-CN [design.md](docs/i18n/zh-CN/docusaurus-plugin-content-docs/current/design.md) to remove the Tongsuo/rust-tongsuo binding reference from the Crypto Manager description

## In Progress

### PKI and certificate cleanup

State: ongoing

What landed:
- added `build_x509_subject_name()` to [src/utils/cert.rs](src/utils/cert.rs) as the single place where `X509NameBuilder` is called
- removed `X509NameBuilder` import from [src/modules/pki/util.rs](src/modules/pki/util.rs); now calls `build_x509_subject_name()` from `cert.rs`
- refactored [src/modules/pki/path_issue.rs](src/modules/pki/path_issue.rs) `issue_cert()` to delegate to `util::generate_certificate()` — eliminated 80 lines of duplicated name-building and SAN parsing; CA-TTL comparison (`Asn1Time`) is the only OpenSSL-specific logic remaining in that function

Remaining work:
- shrink remaining OpenSSL type surface in the PKI module function signatures and helper types

### OpenSSL exit for runtime networking

State: substantially complete

What landed:
- server never starts an OpenSSL TLS acceptor — `bind_rustls_0_23` is the only TLS path
- `TlsClientInfo.client_cert_chain` and `Connection.peer_tls_cert` now travel as `Vec<CertificateDer<'static>>`; no OpenSSL type touches the transport or routing layer
- the DER→X509 conversion is isolated to the cert-auth credential module (`path_login.rs`) where OpenSSL validation logic lives

Remaining work:
- shrink [src/utils/cert.rs](src/utils/cert.rs): `CertBundle.private_key: PKey<Private>` still forces an OpenSSL key type as the main key container in the PKI code
## Next

1. Run a broader repository validation pass across PKI, credential, and helper modules.
2. Identify and reduce remaining `openssl` types in PKI function signatures and intermediate data structures.

## Verification Snapshot

Recently revalidated during the current migration track:

- `cargo test -q key_operation --lib`
- `cargo test -q crypto_key --lib`
- `cargo test -q pki_generate_root --lib -- --test-threads=1`
- `cargo test -q pki_generate_key --lib -- --test-threads=1`
- `cargo test -q pki_import_key --lib -- --test-threads=1`
- `cargo test -q pki_config_role --lib -- --test-threads=1`
- `cargo test -q pki_issue_cert --lib -- --test-threads=1`
- `cargo test -q test_barrier_chacha20poly1305 --lib -- --test-threads=1`

This is not a full repository validation pass.
