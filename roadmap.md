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
| Per-User Scoping (ownership + policy templating + sharing) | Partial (ownership + `scopes` qualifier + seeded baseline roles shipped; templating / sharing / GUI pending) |
| Resource Groups (named collections of resources + KV with reverse index, ACL gate, list-filter, lifecycle prune) | Done (non-ownership model) |
| Asset Groups (secret + resource collections with group-based ACLs) | Done (non-ownership model); ownership / admin transfer / sharing blocked on per-user-scoping |
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
  Ownership-aware ACLs: entity IDs provisioned on first login, a `scopes = ["owner" | "shared"]` qualifier on policy paths, and a unified `OwnerStore` that tracks KV-secret and resource owners behind the vault barrier. Shipped: `EntityStore` auto-provisioning, `scopes` qualifier + evaluator integration, owner-record bookkeeping in `PolicyStore::post_route` (write records, delete forgets), list-filter that narrows LIST response keys to caller-owned entries, and seeded `standard-user-readonly` + `secret-author` baseline policies. Pending: policy templating (`{{username}}` et al.), explicit sharing (`SecretShare`), admin ownership transfer, and the GUI affordances (owner column, "only show mine" toggle).
- [Resource Groups](features/resource-groups.md) / [Asset Groups](features/asset-groups.md)
  Named collections of resources **and** KV-secret paths. Feature-complete for the single-tenant, non-ownership model: two parallel reverse indexes, HTTP CRUD + `by-resource` / `by-secret` / `reindex` / history, KV-path canonicalization across v1 and v2 forms, lifecycle prunes on both resource-delete (in the resource module) and KV-delete (via `PolicyStore::post_route`), the ACL `groups = [...]` qualifier with evaluator integration for both target kinds, list-filter that narrows LIST response keys to group members when the list was authorized only via a gated rule, policy-compile warnings for unknown group references, and the GUI (Asset Groups page, Termius-style group cards on Resources and Secrets pages with click-to-filter + breadcrumb, chips on each object, collapsible admin menu). Mount path stays `resource-group/` for backward compatibility with the initial resource-only ship; the operator-facing label is "Asset Group". Remaining: ownership / admin transfer / sharing, all blocked on per-user-scoping's entity-ID and `SecretShare` plumbing.

## Notes

- Put new roadmap documents under [roadmaps](roadmaps/).
- Keep this file updated whenever a roadmap is added, renamed, or removed.
- Prefer one roadmap per major initiative so planning, sequencing, and acceptance criteria stay reviewable.
