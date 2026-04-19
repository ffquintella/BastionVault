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
| Identity Groups (user groups, application groups, group→policy mapping) | Done |
| Per-User Scoping (ownership + policy templating + sharing) | Todo |
| Resource Groups (named collections of resources with reverse index + ACL gate) | Partial |
| Asset Groups (secret + resource collections with group-based ACLs) | Partial (MVP shipped; ownership/sharing/GUI pending) |
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
| Storage Backend: Hiqlite (embedded Raft SQLite, HA) | Done |
| Import/Export & Backup/Restore | Done |
| Resource Management (inventory + grouped secrets) | In Progress |
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
| High Availability (Raft consensus via Hiqlite) | Done |
| Plugin System (dynamic loading) | Todo |
| Namespaces / Multi-tenancy | Partial |
| Kubernetes Integration | Todo |
| Web UI / Desktop GUI (Tauri) | Done (all 9 phases) |
| Auth: OIDC | Todo |
| Auth: SAML 2.0 | Todo |
| Auth: FIDO2 / WebAuthn / YubiKey | Done (server module) |
| Compliance Reporting | Todo |

## Completed Initiatives

- [Post-Quantum Crypto Migration](roadmaps/post-quantum-crypto-migration.md)
  Completed migration removing Tongsuo and OpenSSL, adopting `ChaCha20-Poly1305` for payload encryption, and `ML-KEM-768` plus `ML-DSA-65` for post-quantum key management.
- [Post-Quantum Crypto Progress](roadmaps/post-quantum-crypto-progress.md)
  Execution tracker with full completion checklist.
- [Hiqlite Default HA Storage](roadmaps/hiqlite-default-ha-storage.md)
  All 6 phases complete: backend implementation, Raft error mapping, cluster health/status endpoints, cluster CLI commands (including failover), post-quantum TLS (X25519MLKEM768), backup/restore/export/import tooling, and HA fault-injection validation (8 multi-node test scenarios).
- [Tauri GUI with FIDO2/YubiKey Support](roadmaps/tauri-gui-fido2.md)
  All 9 phases complete: project scaffold, embedded vault mode (auto-init/unseal via OS keychain), core screens (connect, init, login, dashboard), secrets management (KV browser, users, policies, mounts), AppRole dashboard, FIDO2 server module + GUI, remote mode (connection profiles, TLS config, HTTP API client), and polish (error boundary, settings page, packaging). 55 Tauri commands, 49 frontend tests, 79 React modules, 10 pages.

## Active Initiatives

- [OIDC Authentication](features/oidc-auth.md)
  OpenID Connect auth backend with Authorization Code Flow + PKCE and claim-to-policy role mappings.
- [SAML 2.0 Authentication](features/saml-auth.md)
  SAML 2.0 auth backend with SP-initiated SSO and attribute-to-policy role mappings.
- [Resource Management](features/resources.md)
  Higher-level inventory abstraction for organizing secrets by infrastructure entity (servers, network devices, websites, databases, applications, custom types). Stored in the KV engine with metadata (hostname, IP, OS, location, owner, tags).
- [Identity Groups](features/identity-groups.md)
  User groups and application groups with group-to-policy mapping. Policies attached to a group are unioned with the caller's direct policies at login time. Backend, HTTP API, GUI, and FIDO2 login union all shipped. Extension to Certificate / OIDC / SAML auth backends is deferred until those backends themselves are implemented (Cert is currently disabled in the OpenSSL-free build; OIDC/SAML are design-only).
- [Per-User Scoping (Ownership & Sharing)](features/per-user-scoping.md)
  Ownership-aware ACLs: entity IDs provisioned on first login, policy templating (`{{username}}`, `{{entity.id}}`), a new `scopes = ["owner" | "shared"]` qualifier on policy paths, and owner metadata on KV secrets and resources. Enables seeded `standard-user-readonly` and `secret-author` roles, with an explicit secret-sharing layer as a later phase. Design only; not yet implemented.
- [Resource Groups](features/resource-groups.md)
  Named collections of resources **and KV secrets**, with two parallel reverse indexes for cheap "which groups is this object in?" lookups. Shipped: `ResourceGroupStore` with both halves, HTTP API (`resource-group/groups/*`, `by-resource/*`, `by-secret/*`, `reindex`, history), default mount, 7 integration tests, resource-delete lifecycle prune, KV path canonicalization (v1 / v2 `data/` / v2 `metadata/` all collapse to one entry), and the ACL `groups = [...]` qualifier with evaluator integration for both target kinds — a policy may now gate capabilities on either resource-group or KV-secret membership. Remaining: GUI, KV-delete lifecycle prune (needs a router-level touch point), ownership / sharing (all depend on per-user-scoping).
- [Asset Groups](features/asset-groups.md)
  Named collections of KV secrets and resources used to organize objects and to grant access by membership. Policies reference an asset group via the `groups = [...]` qualifier (additive with the per-user-scoping `scopes`); reverse indexes make authorization checks and list-filtering cheap. Integrates with identity groups (compose the "this team gets this bundle" story) and with the future sharing model. The **minimum viable feature is shipped** as [Resource Groups](features/resource-groups.md) — both resource and KV-secret halves, including the ACL grammar extension for each. Ownership / admin transfer, sharing integration (blocked on per-user-scoping), the KV-delete lifecycle prune, and the unified GUI remain pending.

## Notes

- Put new roadmap documents under [roadmaps](roadmaps/).
- Keep this file updated whenever a roadmap is added, renamed, or removed.
- Prefer one roadmap per major initiative so planning, sequencing, and acceptance criteria stay reviewable.
