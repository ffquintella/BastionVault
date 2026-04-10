# BastionVault Post-Quantum Crypto Migration Progress

## Purpose

This file tracks implementation progress for the post-quantum migration.

Use it as the execution log for what is already done, what is in flight, and what should be tackled next.
The strategy, target architecture, and phase definitions remain in [post-quantum-crypto-migration.md](/Users/felipe/Dev/BastionVault/roadmaps/post-quantum-crypto-migration.md).

## Current Status

Overall state: active, partially implemented

Current focus:
- keep PQ key-management centered on `ML-KEM-768` for encapsulation and `ML-DSA-65` for signatures
- continue reducing the remaining OpenSSL-heavy certificate and cert-auth core in `src/utils/cert.rs`
- keep new crypto work isolated in smaller modules and crates
- maintain broad validation coverage as the migration advances

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

### In Progress

- [ ] Continue reducing OpenSSL surface in `src/utils/cert.rs` and remaining PKI helper internals

### Next

- [ ] Identify the next `CertBundle` / `Certificate` fields that can stop storing OpenSSL types directly
- [ ] Reduce OpenSSL usage in PKI test fixtures where it no longer reflects runtime behavior

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

State: ongoing

What landed:
- added `build_x509_subject_name()` to [src/utils/cert.rs](src/utils/cert.rs) as the single place where `X509NameBuilder` is called
- removed `X509NameBuilder` import from [src/modules/pki/util.rs](src/modules/pki/util.rs); now calls `build_x509_subject_name()` from `cert.rs`
- refactored [src/modules/pki/path_issue.rs](src/modules/pki/path_issue.rs) `issue_cert()` to delegate to `util::generate_certificate()` — eliminated 80 lines of duplicated name-building and SAN parsing; CA-TTL comparison (`Asn1Time`) is the only OpenSSL-specific logic remaining in that function
- changed [src/utils/cert.rs](src/utils/cert.rs) `Certificate::to_cert_bundle()` to accept CA key PEM bytes (`Option<&[u8]>`) and parse internally; this removed OpenSSL `PKey` handling from the [src/modules/pki/path_issue.rs](src/modules/pki/path_issue.rs) call site
- changed [src/utils/cert.rs](src/utils/cert.rs) `Certificate::to_x509()` public signature to accept PEM bytes (`ca_key_pem`, `private_key_pem`) and perform on-demand parsing internally
- moved PEM bundle parsing and private-key-type detection out of [src/modules/pki/path_config_ca.rs](src/modules/pki/path_config_ca.rs) into shared helpers in [src/utils/cert.rs](src/utils/cert.rs)
- moved CA expiry validation out of [src/modules/pki/path_issue.rs](src/modules/pki/path_issue.rs) into [src/utils/cert.rs](src/utils/cert.rs)
- changed [src/modules/pki/path_fetch.rs](src/modules/pki/path_fetch.rs) to store and fetch certificate DER bytes directly instead of exposing `X509` in its storage-facing API

Remaining work:
- shrink the remaining OpenSSL type surface in [src/utils/cert.rs](src/utils/cert.rs) data structures and helper internals
- decide how far certificate issuance and cert-auth should move away from classical X.509 before a broader PKI redesign

### OpenSSL exit for runtime networking

State: substantially complete

What landed:
- server never starts an OpenSSL TLS acceptor — `bind_rustls_0_23` is the only TLS path
- `TlsClientInfo.client_cert_chain` and `Connection.peer_tls_cert` now travel as `Vec<CertificateDer<'static>>`; no OpenSSL type touches the transport or routing layer
- the DER→X509 conversion is isolated to the cert-auth credential module (`path_login.rs`) where OpenSSL validation logic lives

Remaining work:
- shrink remaining OpenSSL-heavy type usage in PKI helper signatures and intermediate objects

### PQ key-management surface

State: active and usable

What landed:
- `crates/bv_crypto` now exposes both `ML-KEM-768` and `ML-DSA-65`
- [src/utils/key.rs](/Users/felipe/Dev/BastionVault/src/utils/key.rs) now distinguishes PQ KEM and PQ signature key types explicitly
- [src/modules/pki/path_keys.rs](/Users/felipe/Dev/BastionVault/src/modules/pki/path_keys.rs) now defaults new key-management operations to `ml-kem-768`
- PKI key generate/import/sign/verify tests now cover both `ml-kem-768` and `ml-dsa-65`

Remaining work:
- remove or demote remaining legacy symmetric alias handling from PKI key-management APIs once callers are migrated
- decide whether `ml-dsa-65` should become the default sign/verify key type in higher-level workflows that still assume classical key names
## Next

1. Identify the next `Certificate` and `CertBundle` fields that can stop storing OpenSSL types directly.
2. Continue narrowing OpenSSL-heavy helper internals in [src/utils/cert.rs](src/utils/cert.rs) without destabilizing issuance and validation paths.

## Verification Snapshot

Recently revalidated during the current migration track:

- `cargo test -q -p bv_crypto`
- `cargo test -q pki --lib -- --test-threads=1`
- `cargo test -q key_operation --lib`
- `cargo test -q crypto_key --lib`
- `cargo test -q pki_generate_root --lib -- --test-threads=1`
- `cargo test -q pki_generate_key --lib -- --test-threads=1`
- `cargo test -q test_pki_import_pq_keys --lib -- --test-threads=1`
- `cargo test -q pki_config_role --lib -- --test-threads=1`
- `cargo test -q pki_issue_cert --lib -- --test-threads=1`
- `cargo test -q test_barrier_chacha20poly1305 --lib -- --test-threads=1`
- `cargo test -q mount --lib`
- `cargo test -q approle --lib`
- `cargo test -q salt --lib`
- `cargo test -q --lib`

This includes a broad lib validation pass, but not an exhaustive workspace or integration-only sweep.
