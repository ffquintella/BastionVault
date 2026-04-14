# BastionVault Roadmap

This document is the global entrypoint for roadmap and long-term planning documents in this repository.

The post-quantum crypto migration is complete. The default build uses a PQ-first, OpenSSL-free cryptographic stack.

## Feature Status

| Feature | Status |
|---------|--------|
| **Core** | |
| Core Vault Operations (init, seal, unseal, status) | Done |
| Secret Management (KV CRUD) | Done |
| Secret Versioning & Soft-Delete | Todo |
| Access Control (RBAC, path-based ACL policies) | Done |
| Audit Logging (tamper-evident, HMAC chain) | Partial |
| Metrics (Prometheus) | Done |
| **Cryptography** | |
| Post-Quantum Crypto Migration | Done |
| Key Management (ML-KEM-768, ML-DSA-65, ChaCha20-Poly1305) | Done |
| Key Rotation & Re-encryption | Done |
| HSM Support | Todo |
| **Storage** | |
| Storage Backend: Encrypted File | Done |
| Storage Backend: MySQL | Done |
| Storage Backend: SQLx (removed, libsqlite3-sys conflict) | Removed |
| Storage Backend: Hiqlite (embedded Raft SQLite, HA) | Done (Phase 1) |
| Import/Export & Backup/Restore | Todo |
| Caching | Partial |
| Batch Operations | Todo |
| **Networking & TLS** | |
| TLS & mTLS (Rustls-based) | Done |
| **Authentication** | |
| Auth: Token-based | Done |
| Auth: AppRole | Done |
| Auth: Userpass | Done |
| Auth: Certificate | Done |
| **Secret Engines** | |
| Secret Engine: PKI (legacy, retired from default build) | Partial |
| Secret Engine: Transit | Todo |
| Secret Engine: TOTP | Todo |
| Secret Engine: SSH | Todo |
| Dynamic Secrets | Todo |
| **Infrastructure** | |
| High Availability (Raft consensus via Hiqlite) | Done (multi-node fault tests deferred) |
| Plugin System (dynamic loading) | Todo |
| Namespaces / Multi-tenancy | Partial |
| Kubernetes Integration | Todo |
| Web UI / Desktop GUI (Tauri) | Todo |
| Auth: FIDO2 / WebAuthn / YubiKey | Todo |
| Compliance Reporting | Todo |

## Completed Initiatives

- [Post-Quantum Crypto Migration](roadmaps/post-quantum-crypto-migration.md)
  Completed migration removing Tongsuo and OpenSSL, adopting `ChaCha20-Poly1305` for payload encryption, and `ML-KEM-768` plus `ML-DSA-65` for post-quantum key management.
- [Post-Quantum Crypto Progress](roadmaps/post-quantum-crypto-progress.md)
  Execution tracker with full completion checklist.

## Active Initiatives

- [Hiqlite Default HA Storage](roadmaps/hiqlite-default-ha-storage.md)
  Roadmap for making `hiqlite` (embedded Raft-based SQLite) the default storage engine. Phase 1 (backend implementation) is complete. Phases 2-6 cover replication semantics, cluster management, migration tooling, and HA validation.
- [Tauri GUI with FIDO2/YubiKey Support](roadmaps/tauri-gui-fido2.md)
  Cross-platform desktop GUI (Tauri v2 + React + TypeScript) with embedded and remote vault modes, full vault/user/policy management, FIDO2/WebAuthn/YubiKey authentication backend, and machine auth (AppRole) dashboard.

## Notes

- Put new roadmap documents under [roadmaps](roadmaps/).
- Keep this file updated whenever a roadmap is added, renamed, or removed.
- Prefer one roadmap per major initiative so planning, sequencing, and acceptance criteria stay reviewable.
