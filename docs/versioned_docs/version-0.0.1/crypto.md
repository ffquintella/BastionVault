---
sidebar_position: 3
title: Cryptography
---
# BastionVault Cryptography

BastionVault uses a post-quantum-ready cryptographic stack built on pure Rust libraries.

## Current Cryptographic Stack

| Purpose | Algorithm | Library |
|---------|-----------|---------|
| Payload encryption | `ChaCha20-Poly1305` | `chacha20poly1305` crate via `bv_crypto` |
| Key establishment | `ML-KEM-768` | `ml-kem` crate via `bv_crypto` |
| Post-quantum signatures | `ML-DSA-65` | `fips204` crate via `bv_crypto` |
| TLS | TLS 1.2/1.3 | `rustls` |
| Hashing / HMAC | BLAKE2b, SHA-256 | `blake2`, `sha2` |

All cryptographic work lives in `crates/bv_crypto`, which provides a provider-neutral interface for AEAD encryption, KEM key encapsulation, digital signatures, and envelope encryption.
