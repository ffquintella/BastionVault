---
sidebar_position: 5
title: Design
---
# BastionVault Design

As per: [BastionVault Requirements Document](./req.md). In this document we describe the architecture of BastionVault.

# Architecture Diagram

![BastionVault Architecture](../static/img/BastionVault-arch.svg)

Detailed description:

1. BastionVault contains three main components: BastionVault Core, BastionVault Modules and BastionVault Interface.
  * BastionVault Core, the core component of BastionVault, contains several managers. Each manager is in charge of a specific mechanism or layer. For instance, the Module Manager handles all module management in BastionVault, providing mechanisms such as module loading and unloading. The Crypto Manager provides an abstract layer for cryptographic operations using the post-quantum `bv_crypto` crate.
  * BastionVault Modules, which consists of several modules, is where the real features of BastionVault take place. Most functionality code sits in BastionVault Modules. For instance, the KV Module provides secure key-value secret storage; the PKI Module provides post-quantum key management endpoints for ML-KEM-768 and ML-DSA-65 operations.
  * BastionVault Interface is the part that interacts with end users. The BastionVault Interface provides a set of RESTful APIs via an HTTP/HTTPS server (using `rustls` for TLS). After the server receives the API requests, it routes them to the corresponding BastionVault Module. That module then processes the request and responds to the caller.

2. BastionVault uses a post-quantum-ready cryptographic stack built on pure Rust libraries. The `bv_crypto` crate provides `ChaCha20-Poly1305` for payload encryption, `ML-KEM-768` for key establishment, and `ML-DSA-65` for post-quantum signatures. TLS is handled by `rustls`.

3. BastionVault is designed to support cryptographic hardware such as HSMs or cryptography cards in the future. The modular crypto layer makes it possible to integrate hardware-backed key operations.

4. The sensitive data in BastionVault (secrets, credentials, passwords, keys) can be stored in local encrypted file storage or external database storage such as MySQL or PostgreSQL. The Storage Manager in BastionVault Core abstracts over different storage backends, so other modules do not need to deal with storage differences directly.

## Desktop GUI key management

The Tauri desktop app — which can host multiple saved vaults (Local / Remote / Cloud) side-by-side — uses a two-layer keystore on top of the OS keychain rather than storing per-vault unseal keys directly:

1. **Local key** — a single 32-byte symmetric key per installation, held in the OS keychain under service `bastion-vault-gui` / entry `local-master-key`. Generated on first launch if absent. This is the ONLY credential the keychain holds for BastionVault.

2. **Encrypted vault-keys file** at `<data_local>/.bastion_vault_gui/vault-keys.enc`. A `ChaCha20-Poly1305` AEAD envelope over a JSON map `{ vault_id → { unseal_key_hex, root_token, created_at } }`. The nonce is 12 random bytes prepended to the ciphertext; a 4-byte magic header (`BVK\x01`) versions the format. Atomic write via tmp-then-rename survives crashes mid-write.

The earlier single-slot design stored only the most recently initialised vault's key under a fixed `unseal-key` keychain entry, which meant initialising or opening a second vault silently overwrote the first one's key and turned subsequent switches back into "unseal failed" errors. The two-layer model indexes every per-vault record by vault id inside the encrypted file, so adding a second vault never touches the first one's entry. See [Security Structure](./security-structure.md) for the full threat model and the planned YubiKey + ML-KEM follow-on phases.

The legacy `unseal-key` / `root-token` keychain slots are still read on first launch after upgrade; values are migrated into the new file under the `last_used_id` profile and the legacy slots are wiped. Migration is idempotent and runs from every `get_*` call so out-of-order upgrades converge.
