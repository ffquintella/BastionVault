# BastionVault Post-Quantum Crypto Migration Progress

## Purpose

This file tracks implementation progress for the post-quantum migration.

Use it as the execution log for what is already done, what is in flight, and what should be tackled next.
The strategy, target architecture, and phase definitions remain in [post-quantum-crypto-migration.md](/Users/felipe/Dev/BastionVault/roadmaps/post-quantum-crypto-migration.md).

## Current Status

Overall state: complete for the active default build scope

Current focus:
- maintain the PQ-first default build
- keep new crypto work isolated in smaller modules and crates
- treat any future certificate or trust-distribution redesign as a separate roadmap

## Checklist

### Completed

- [x] Create `crates/bv_crypto`
- [x] Add provider-neutral AEAD primitives
- [x] Implement `ChaCha20-Poly1305`
- [x] Implement `ML-KEM-768`
- [x] Implement `ML-DSA-65`
- [x] Add deterministic ML-KEM seed-derived keypair support
- [x] Add deterministic ML-DSA seed-derived keypair support
- [x] Add shared versioned KEM+DEM envelope support
- [x] Add `chacha20-poly1305` barrier implementation
- [x] Add PQ-backed barrier bootstrap and unseal flow
- [x] Expose config-selectable ChaCha barrier path
- [x] Migrate `seal.rs` to the PQ envelope model
- [x] Migrate `crypto.rs` to the PQ envelope model
- [x] Migrate the `ml-kem-768` path in `key.rs` to the PQ envelope model
- [x] Add `ml-dsa-65` sign/verify support in `key.rs`
- [x] Expose `ml-kem-768` and `ml-dsa-65` through PKI key generate/import/sign/verify paths
- [x] Remove legacy symmetric alias handling from active PQ key-management code
- [x] Make `chacha20-poly1305` the default barrier type
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
- [x] Change `Certificate::to_cert_bundle()` to accept CA key PEM bytes (`Option<&[u8]>`) instead of `Option<&PKey<Private>>`; `path_issue.rs` now passes bytes directly with no OpenSSL key conversion in the caller
- [x] Change `Certificate::to_x509()` to accept PEM bytes (`ca_key_pem`, `private_key_pem`) instead of `PKey` references in its public signature
- [x] Move PEM bundle parsing and private-key-type detection out of `path_config_ca.rs` into `utils/cert.rs`
- [x] Move CA not-after validation out of `path_issue.rs` into `utils/cert.rs`
- [x] Change PKI cert fetch/store helpers in `path_fetch.rs` to use raw DER bytes at the storage boundary instead of `X509`
- [x] Run a broad repository lib validation pass (`cargo test -q --lib`)
- [x] Remove OpenSSL from generic HMAC/hash helpers in `mount.rs`, AppRole validation, `utils/mod.rs`, and `utils/salt.rs`
- [x] Remove OpenSSL from the active default build graph
- [x] Retire legacy X.509 PKI and cert-auth modules from the default build
- [x] Remove OpenSSL-based test helper implementations from `src/test_utils.rs`

### In Progress

- [ ] None for the active PQ migration scope

### Next

- [ ] Create a separate roadmap if BastionVault later needs a new PQ trust-distribution or certificate model

## Completed

### Workspace and crypto foundation

- created [crates/bv_crypto](/Users/felipe/Dev/BastionVault/crates/bv_crypto)
- added a provider-neutral AEAD surface
- implemented `ChaCha20-Poly1305`
- implemented `ML-KEM-768`
- implemented `ML-DSA-65`
- added deterministic ML-KEM seed-based keypair derivation
- added deterministic ML-DSA seed-based keypair derivation
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
- migrated the `ml-kem-768` path in [key.rs](/Users/felipe/Dev/BastionVault/src/utils/key.rs) to PQ-backed envelope encryption while keeping the external `KeyBundle` API stable
- added `ml-dsa-65` signing and verification to [key.rs](/Users/felipe/Dev/BastionVault/src/utils/key.rs)
- retired PEM-based PKI key import for active key-management paths in favor of PQ seed import
- removed legacy `aes-*` key-management aliases from the active reusable key layer

### Tongsuo removal

- removed the Cargo patch to `rust-tongsuo`
- removed the `crypto_adaptor_tongsuo` feature from [Cargo.toml](/Users/felipe/Dev/BastionVault/Cargo.toml)
- removed the Tongsuo CI job from [rust.yml](/Users/felipe/Dev/BastionVault/.github/workflows/rust.yml)
- deleted [tongsuo_adaptor.rs](/Users/felipe/Dev/BastionVault/src/modules/crypto/crypto_adaptors/tongsuo_adaptor.rs)
- removed the remaining `crypto_adaptor_tongsuo` cfg branches from build and legacy runtime code
- cleaned the main crypto adaptor docs

### PKI progress

- removed SM2-specific build branches from the active PKI code paths
- aligned PKI key import/export with PQ seed semantics
- updated PKI key test fixtures to use valid ML-KEM and ML-DSA seed material
- updated [path_keys.rs](/Users/felipe/Dev/BastionVault/src/modules/pki/path_keys.rs) defaults and field descriptions around `ml-kem-768` and `ml-dsa-65`
- centralized certificate role validation for RSA and EC issuance
- corrected stale PKI field/help text that no longer matched the current implementation
- retired the legacy certificate-centric PKI module from the default build
- retired the legacy cert-auth module from the default build

### Test and maintenance work

- fixed the shared temp-directory race in [src/test_utils.rs](src/test_utils.rs)
- kept targeted storage, helper, and PKI tests green through each migration slice
- removed OpenSSL from generic hashing/HMAC code paths used by mount HMACs, AppRole secret-id HMACs, and salt hashing

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

State: closed for the active migration scope

What landed:
- the default build no longer ships the legacy certificate-centric PKI or cert-auth modules
- [src/utils/cert.rs](/Users/felipe/Dev/BastionVault/src/utils/cert.rs) is now an OpenSSL-free minimal helper surface for the remaining client-side rustls integration points
- any future certificate or trust-distribution redesign is explicitly treated as a separate initiative rather than a blocker for PQ storage and key-management migration

Remaining work:
- none in the active PQ migration scope

### OpenSSL exit for runtime networking

State: substantially complete

What landed:
- server never starts an OpenSSL TLS acceptor — `bind_rustls_0_23` is the only TLS path
- `TlsClientInfo.client_cert_chain` and `Connection.peer_tls_cert` now travel as `Vec<CertificateDer<'static>>`; no OpenSSL type touches the transport or routing layer
- the DER→X509 conversion is isolated to the cert-auth credential module (`path_login.rs`) where OpenSSL validation logic lives

Remaining work:
- none in the active default build

### PQ key-management surface

State: active and usable

What landed:
- `crates/bv_crypto` now exposes both `ML-KEM-768` and `ML-DSA-65`
- [src/utils/key.rs](/Users/felipe/Dev/BastionVault/src/utils/key.rs) now distinguishes PQ KEM and PQ signature key types explicitly
- [src/modules/pki/path_keys.rs](/Users/felipe/Dev/BastionVault/src/modules/pki/path_keys.rs) now defaults new key-management operations to `ml-kem-768`
- PKI key generate/import/sign/verify tests now cover both `ml-kem-768` and `ml-dsa-65`

Remaining work:
- none in the active default build
## Next

1. Treat future PQ certificate or trust-distribution work as a separate roadmap.
2. Keep validating the existing PQ-first default build as other major features land.

## Verification Snapshot

Recently revalidated during the current migration track:

- `cargo check -q`
- `cargo test -q -p bv_crypto`
- `cargo test -q key_operation --lib`
- `cargo test -q test_load_config --lib`

The default build now targets the PQ-first, OpenSSL-free runtime scope. Any future certificate redesign belongs in a separate initiative.
