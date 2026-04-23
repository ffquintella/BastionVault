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
| Per-User Scoping (ownership + policy templating + sharing) | Done (all 10 phases + migration story: ownership, `scopes`, seeded baselines, policy templating with fail-closed substitution + unit-tested wrapper, `ShareStore`, v2 sharing API, `shared` scope, share-cascade, admin transfer, the GUI — `/sharing` page plus per-resource Sharing tab — and the `POST /v2/sys/owner/backfill` admin migration endpoint for deployments upgrading from pre-ownership versions) |
| Resource Groups (named collections of resources + KV with reverse index, ACL gate, list-filter, lifecycle prune) | Done (full model with ownership + sharing; see Asset Groups row) |
| Asset Groups (secret + resource collections with group-based ACLs) | Done (full model: ownership, admin transfer, sharing via ShareTargetKind::AssetGroup, and member-redaction on read all shipped) |
| Audit Logging (tamper-evident, HMAC chain) | Done (Phase 1: file device, hash chain, sys/audit API, pipeline hook, config persistence; syslog/HTTP devices deferred) |
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
| Storage Backend: Cloud targets for `Encrypted File` (S3 / OneDrive / Google Drive / Dropbox) | Done (all 8 phases shipped; `FileTarget` trait + four provider backends behind `cloud_*` feature flags + OAuth/PKCE infra + CLI + GUI + OS keychain + key-obfuscation decorator; see Completed Initiatives) |
| Import/Export & Backup/Restore | Done |
| Resource Management (inventory + grouped secrets) | Done |
| File Resources (binary blobs + SMB/SCP/SFTP sync) | In Progress (Phases 1–4 + 8 shipped: engine + CRUD + history + 32 MiB cap + SHA-256 integrity + ownership / sharing / admin transfer / backfill + asset-group membership + local-FS sync target + minimum-viable GUI + content versioning with snapshot-on-write / retention / restore; Phases 5–7 — SMB / SFTP / SCP sync + periodic re-sync — still Todo) |
| Caching | Done |
| Batch Operations | Done (Phase 1: HTTP endpoint; CLI + client SDK deferred) |
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
- [Caching](features/caching.md)
  Four-slice feature: cache-config scaffold; token lookup cache (keyed by salted hash, zeroized on release, never caches raw tokens); Prometheus metrics (`bvault_cache_{hits,misses,evictions}_total{layer}`); ciphertext-only secret read cache below the barrier (`CachingBackend` decorator, zeroized on release, no negative caching); memory-protection guardrails (`mlockall` on Unix, `PR_SET_DUMPABLE=0` on Linux); `POST /sys/cache/flush` admin endpoint (sudo-gated); automatic flush on seal. No cache at any layer holds plaintext secret material or raw bearer tokens — enforced structurally (secret cache implements `Backend` not `Storage`) and by per-layer zeroize-on-drop wrappers.
- [Resource Management](features/resources.md)
  Dedicated resource storage engine (`src/modules/resource/`) with per-resource metadata + secret grouping, per-field change history, per-secret version snapshots, configurable resource types, ownership + sharing + asset-group integration, 14 Tauri commands, and the full Resources GUI page. Goes beyond the original spec (which described a KV-prefix convention) — resources now live in a dedicated barrier-encrypted engine independent of KV.
- [Per-User Scoping (Ownership & Sharing)](features/per-user-scoping.md)
  All ten phases + the migration story shipped. `EntityStore` auto-provisioning, `scopes = ["owner" | "shared"]` qualifier with evaluator integration, unified `OwnerStore` with write-records / delete-forgets bookkeeping, LIST-filter that narrows response keys to caller-owned or caller-shared entries, seeded `standard-user-readonly` + `secret-author` baselines, policy templating (`{{username}}`, `{{entity.id}}`, `{{auth.mount}}`) with fail-closed unresolved-placeholder semantics and full unit-test coverage of the `apply_templates` wrapper, the `/v2/identity/sharing/…` CRUD API, `/v2/identity/entity/self` + `/v2/identity/owner/{kv,resource}/…` introspection routes, share-cascade on KV / resource delete, `POST /v2/sys/{kv,resource}-owner/transfer` admin endpoints, the new `POST /v2/sys/owner/backfill` admin migration endpoint (sudo-gated) for upgrading deployments with unowned pre-existing objects, root-token writes now stamping `root` as owner so the Owner card in the GUI is populated for admin-created objects, and the GUI — top-level `/sharing` page plus per-resource Sharing tab with Grant / Revoke / admin-only Transfer. Re-sharing by sharees is intentionally unsupported.
- [Identity Groups](features/identity-groups.md)
  User groups and application groups with group-to-policy mapping. Phases 1–7 all shipped: `GroupStore`, `v2/identity/…` HTTP + Tauri surface, default mount, UserPass + AppRole login policy union, integration tests (CRUD, namespace isolation, end-to-end login), the Groups GUI page, and the FIDO2 login policy union. Phase 8 (extension to Certificate / OIDC / SAML) is deliberately deferred on those backends landing — Certificate is currently disabled in the OpenSSL-free build and OIDC / SAML are design-only. The union pattern ships: when the Certificate / OIDC / SAML login handlers arrive they plug into the same `GroupStore::load_group_policies` path that UserPass / AppRole / FIDO2 already use.
- [Resource Groups / Asset Groups](features/resource-groups.md)
  All thirteen phases shipped. Named collections of resources **and** KV-secret paths, with two parallel reverse indexes, HTTP + Tauri CRUD + `by-resource` / `by-secret` / `reindex` / history, KV-path canonicalization across v1 and v2 forms, lifecycle prunes on both resource-delete (resource module) and KV-delete (`PolicyStore::post_route`), the ACL `groups = [...]` qualifier with evaluator integration for both target kinds, list-filter that narrows LIST response keys to group members when the list was authorized only via a gated rule, policy-compile warnings for unknown group references, the GUI (Asset Groups page, Termius-style group cards on Resources and Secrets pages with click-to-filter + breadcrumb, chips on each object, collapsible admin menu), **ownership** with first-write capture, admin transfer via `POST /v2/sys/asset-group-owner/transfer`, **sharing** via `ShareTargetKind::AssetGroup` with indirect member-expansion at authorize time, and **member redaction** for non-owner / non-admin readers (cardinality stays truthful, paths are hidden). Mount path stays `resource-group/` for backward compatibility with the initial resource-only ship; the operator-facing label is "Group".
- [Cloud Storage Targets for the Encrypted File backend](features/cloud-storage-backend.md)
  All 8 phases shipped. The Encrypted File backend (`src/storage/physical/file/`) now sits on a pluggable `FileTarget` trait with four provider implementations — **AWS S3** via `rusty-s3` + `ureq` (MinIO-compatible), **Microsoft OneDrive** via Graph API (App-folder scoped), **Google Drive** via Drive v3 (app-data scoped, ID-based chain walking + folder-id cache), **Dropbox** via v2 API (dual-host content/api endpoints, supports both OAuth refresh tokens and long-lived access tokens wrapped in a `{"access_token":"..."}` JSON envelope). Each provider is feature-gated (`cloud_s3` / `cloud_onedrive` / `cloud_gdrive` / `cloud_dropbox`) so default builds carry zero cloud code. Shared infrastructure: `credentials_ref` URI grammar (`env:` / `file:` / `inline:` / `keychain:`) with `Secret`-newtype zero-on-drop; OAuth + PKCE + loopback-redirect consent flow (fixed port 8472 so the redirect URI is stable across runs); `bvault operator cloud-target connect` CLI; **Settings → Cloud Storage Targets GUI card** with inline provider consent flow, dev-console help links, "paste existing token" shortcut (uses Dropbox's Generated-access-token), S3 inline credentials, and stable-redirect-URI display with Copy button; OS keychain writer via the `keyring` crate behind `cloud_keychain`; **`ObfuscatingTarget` decorator** (Phase 8) that HMAC-SHA256s every object key with an auto-bootstrapped per-target salt. **Get Started integration**: new "Cloud Vault" option on the chooser backed by the multi-vault saved-profiles model (`VaultProfile` + `last_used_id`, hand-editable JSON preferences, full CRUD + legacy-shape migration). InitPage branches its copy on the active profile's kind and carries ⇄/⚙/🗑 controls (switch, inline credential re-paste, forget) so an init failure is recoverable without leaving the page. Deferred sub-slices (not blocking): rekey-CLI for the obfuscation salt (library pieces present; orchestrator not shipped), and sync-path bootstrap of obfuscation for server-mode boots that go through `storage::new_backend` (desktop uses `FileBackend::new_maybe_obfuscated` directly via `embedded::build_backend`).

## Active Initiatives

- [OIDC Authentication](features/oidc-auth.md)
  OpenID Connect auth backend with Authorization Code Flow + PKCE and claim-to-policy role mappings.
- [SAML 2.0 Authentication](features/saml-auth.md)
  SAML 2.0 auth backend with SP-initiated SSO and attribute-to-policy role mappings.
- [File Resources](features/file-resources.md)
  New resource kind that stores binary files (SSH keys, cert bundles, keytabs, config files) under the barrier alongside secrets. **Phases 1–4 + 8 shipped**: dedicated `files/` mount with meta + blob + history + sync-target + version storage, v2 CRUD, 32 MiB hard cap, SHA-256 integrity re-verified on every read (including historical versions); ownership / sharing / admin transfer / backfill wired through `OwnerStore` + `ShareStore`; **asset-group membership** for files via a third reverse index in `ResourceGroupStore`; **local-FS sync target** with atomic tmp-then-rename write + optional Unix mode, per-target sync-state, on-demand `push` endpoint; **content versioning** with snapshot-on-write, `DEFAULT_VERSION_RETENTION = 5` prune policy, `GET files/{id}/versions[/…]` list / read / content / restore (displaced content is itself snapshotted, so restore is reversible); **minimum-viable GUI** with a top-level Files page and a per-file detail modal (Info + Sync + Versions tabs). 22 file-module tests passing; full Rust suite 393/393; TS type-check clean; 66/66 GUI unit tests pass. Remaining: SMB (Phase 5), SFTP / SCP (Phase 6), periodic re-sync (Phase 7).

## Notes

- Put new roadmap documents under [roadmaps](roadmaps/).
- Keep this file updated whenever a roadmap is added, renamed, or removed.
- Prefer one roadmap per major initiative so planning, sequencing, and acceptance criteria stay reviewable.
