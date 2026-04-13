---
sidebar_position: 4
title: Motivation
---
# Motivation

HashiCorp Vault is the most widely used secret management product in the cloud native space. But in practice, it has some disadvantages:

1. Open-source license is no longer OSI-approved;
2. Many useful features are not open-sourced;
3. Limited post-quantum cryptography support;
4. Inadequate cryptography performance in critical scenarios;

Compared to HashiCorp Vault, there are few open-source key/secret management projects available. BastionVault was started to address these issues.

The project needs to fulfill most features a traditional KMS has, while also serving as a replacement for HashiCorp Vault with features not included in its open-source versions. As such, BastionVault should be:

1. Written in Rust for memory safety
2. Fully compatible with HashiCorp Vault on APIs and data format
3. Post-quantum-ready cryptographic stack
4. High performance on cryptographic operations
5. High availability
6. OSI-approved open-source license

# Requirements List

Language: Rust

Project Name: BastionVault

Features:

* API
  * RESTful
     * Compatible with HashiCorp Vault
* Authentication
  * Token-based authentication
  * AppRole authentication
  * Username/password authentication
  * Certificate authentication
  * Path-based ACL policies
* Configuration
  * HCL configuration files
  * JSON configuration files
* Key Management
  * Post-quantum key wrapping: ML-KEM-768
  * Post-quantum signatures: ML-DSA-65
  * Symmetric key: generation/storage/rotation
* Cryptography
  * Payload encryption: ChaCha20-Poly1305
  * Key encapsulation: ML-KEM-768
  * Digital signatures: ML-DSA-65
  * TLS: rustls (TLS 1.2/1.3)
  * Hashing: BLAKE2b, SHA-256
* Storage
  * Encrypted file backend
  * MySQL backend
  * SQLx backend (PostgreSQL, SQLite)
  * Rqlite backend (planned, for HA)
* Monitoring
  * Prometheus metrics
* Logging and Audit
  * Log to file
* Cluster and HA
  * Rqlite-backed replication (planned)
