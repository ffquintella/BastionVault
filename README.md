# BastionVault

![BastionVault logo](docs/static/img/bastionvault-logo.svg)

[![Crates.io Version](https://img.shields.io/crates/v/bastion_vault)](https://crates.io/crates/bastion_vault)

## Overview

BastionVault is a modern secret management system, written in Rust. BastionVault provides various features which support many scenarios including secure storage, cloud identity management, secret management, Kubernetes integration, PKI infrastructure, cryptographic computing, traditional key management, etc.

BastionVault can be deployed in either cloud or physical environments. Depending on different requirements, BastionVault may run as standalone application with a set of RESTful APIs provided, and it can also be used as a crate thus you can easily integrate it into your own Rust application.

BastionVault is a fork of RustyVault. We decided to rebrand because this fork is taking a different direction in the library design and API surface, while keeping the same general problem space around secret management and Vault-compatible workflows.

The cryptographic core uses a post-quantum-ready stack built on pure Rust libraries, with `ChaCha20-Poly1305` for payload encryption, `ML-KEM-768` for key establishment, and `ML-DSA-65` for post-quantum signatures.

One of the goals of BastionVault is to replace Hashicorp Vault seamlessly if you are seeking for an OSI-approved open-source license and enterprise level features.

## Feature

Part of the features provided by BastionVault are as follows:

* Working Mode
  * standalone process w/HTTP APIs
  * Rust crate that can be easily integrated with other applications
* Cryptography
  * payload encryption: `ChaCha20-Poly1305`
  * key establishment: `ML-KEM-768` (post-quantum KEM)
  * signatures: `ML-DSA-65` (post-quantum signatures)
  * TLS: `rustls` (pure Rust TLS stack)
* API
  * RESTful API, compatible with Hashicorp Vault
* Authentication & Authorization
  * token-based authentication
  * AppRole authentication
  * username/password authentication
  * certificate authentication
  * path-based ACL policies
* Secure Storage
  * encrypted file backend
  * MySQL backend
  * SQLx backend (Postgres/SQLite)
* Configuration
  * HCL compatible
* Key Management
  * post-quantum key wrapping with ML-KEM-768
  * ML-DSA-65 signing and verification
  * key rotation and re-encryption
* Monitoring
  * Prometheus metrics
* Logging & Audit
  * log to file

## Design

Read the [design](./docs/docs/design.md) document.
