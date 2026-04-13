---
sidebar_position: 3
title: Cryptography
---
# BastionVault Cryptography

BastionVault uses a post-quantum-ready cryptographic stack built on pure Rust libraries. The legacy OpenSSL-based adaptor layer has been fully retired.

## Current Cryptographic Stack

| Purpose | Algorithm | Library |
|---------|-----------|---------|
| Payload encryption | `ChaCha20-Poly1305` | `chacha20poly1305` crate via `bv_crypto` |
| Key establishment | `ML-KEM-768` | `ml-kem` crate via `bv_crypto` |
| Post-quantum signatures | `ML-DSA-65` | `fips204` crate via `bv_crypto` |
| TLS | TLS 1.2/1.3 | `rustls` |
| Hashing / HMAC | BLAKE2b, SHA-256 | `blake2`, `sha2` |

## Architecture

All new cryptographic work lives in `crates/bv_crypto`, which provides a provider-neutral interface for:

- **AEAD encryption** (`ChaCha20-Poly1305`)
- **KEM key encapsulation** (`ML-KEM-768`)
- **Digital signatures** (`ML-DSA-65`)
- **KEM+DEM envelope encryption** (`KemDemEnvelopeV1`)

The storage barrier uses `ChaCha20-Poly1305` by default, with keys wrapped via `ML-KEM-768` post-quantum envelopes.

## Migration History

BastionVault previously supported OpenSSL and Tongsuo as cryptographic backends through an adaptor mechanism. Both have been removed:

- **Tongsuo**: fully removed (Cargo feature, CI job, adaptor source, and documentation)
- **OpenSSL**: fully removed from the default build (runtime TLS, hashing, HMAC, storage encryption)

The legacy PKI certificate issuance and cert-auth modules are disabled in the current build. PQ key-management endpoints (generate, import, sign, verify) for `ml-kem-768` and `ml-dsa-65` remain active.
