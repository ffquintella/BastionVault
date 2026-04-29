# BastionVault Roadmap

Global entrypoint for roadmap and long-term planning in this repository.

The post-quantum crypto migration is complete. The default build uses a PQ-first, OpenSSL-free cryptographic stack.

## How to read this

- **Status** is one of `Done`, `Todo`, `Partial`, `Removed` — followed by a one-line summary.
- Detailed phase notes live in each feature's spec under [`features/`](features/).
- Multi-phase initiatives that have closed out are summarised under **Completed Initiatives**.
- Currently open follow-ups that aren't a top-line feature live under **Deferred sub-initiatives**.

## Feature Status

### Core

| Feature | Status |
|---|---|
| Core Vault Operations (init / seal / unseal / status) | Done |
| Secret Management (KV CRUD) | Done |
| Secret Versioning & Soft-Delete | Todo |
| Access Control (RBAC + path-based ACL) | Done |
| Identity Groups (user / app groups → policy mapping) | Done |
| Per-User Scoping (ownership + policy templating + sharing) | Done — all 10 phases + the migration backfill endpoint |
| Asset Groups (collections of resources + KV paths with group-based ACLs) | Done — all 13 phases incl. ownership, sharing, member redaction |
| Audit Logging (tamper-evident, HMAC chain) | Done — Phase 1 (file device); syslog/HTTP devices deferred |
| Metrics (Prometheus) | Done |

### Cryptography

| Feature | Status |
|---|---|
| Post-Quantum Crypto Migration | Done |
| Key Management (ML-KEM-768, ML-DSA-65, ChaCha20-Poly1305) | Done |
| Key Rotation & Re-encryption | Done |
| HSM Support | Todo |

### Storage

| Feature | Status |
|---|---|
| Storage Backend: Encrypted File | Done |
| Storage Backend: MySQL | Done |
| Storage Backend: SQLx | Removed (libsqlite3-sys conflict) |
| Storage Backend: Hiqlite (embedded Raft SQLite, HA) | Done |
| Cloud targets for Encrypted File (S3 / OneDrive / Google Drive / Dropbox) | Done — all 8 phases incl. cache decorator + key-obfuscation |
| Import / Export & Backup / Restore | Done |
| Import / Export Module (`.bvx`) ([spec](features/import-export-module.md)) | Todo |
| Scheduled Exports ([spec](features/scheduled-exports.md)) | Todo |
| Caching | Done — token + ciphertext-only secret cache + memory hardening |
| Batch Operations | Done — Phase 1 (HTTP); CLI + SDK deferred |

### Resources

| Feature | Status |
|---|---|
| Resource Management (inventory + grouped secrets) | Done |
| File Resources (binary blobs + local-FS sync) | Done — all 8 phases (local-FS, SMB, SFTP, SCP, periodic re-sync, sync-on-write) |
| Resource Connect — in-app SSH / RDP for server resources ([spec](features/resource-connect.md)) | Done — Phases 1–7 shipped. Launch matrix: SSH × {Secret, LDAP, PKI} ✅, RDP × {Secret, LDAP, PKI (CredSSP smartcard via sspi-rs's PIV emulator)} ✅. Phase 7 polish landed: per-resource-type Connect policy on `ResourceTypeDef`, recently-connected list (last 10) on every resource, ⌘K global Connect palette with fuzzy resource × profile picker. Only the `ssh-engine` credential source remains as a deferred follow-up. |

### Networking & TLS

| Feature | Status |
|---|---|
| TLS & mTLS (Rustls-based) | Done |

### Authentication

| Feature | Status |
|---|---|
| Auth: Token | Done |
| Auth: AppRole | Done |
| Auth: Userpass | Done |
| Auth: Certificate | Done |
| Auth: OIDC | Done — server module + login + provider admin lifecycle |
| Auth: SAML 2.0 | Done — pure-Rust SP-initiated SSO, no libxml2 / xmlsec |
| Auth: FIDO2 / WebAuthn / YubiKey | Done |

### Secret Engines

| Feature | Status |
|---|---|
| PKI ([spec](features/pki-secret-engine.md)) | Done — Phases 1–5.2; classical + ML-DSA PQC + composite, multi-issuer, on-demand + auto tidy |
| PKI: ACME server endpoints ([spec](features/pki-acme.md)) | Done — Phases 6.1 + 6.1.5 + 6.2 + 6.3, feature-complete on RFC 8555 (HTTP-01 + DNS-01, EAB, key-change, revoke, rate limit, expiry sweep) |
| Transit ([spec](features/transit-secret-engine.md)) | Done — Phases 1–4: AEAD + HMAC + sign/verify + ML-KEM datakey + ML-DSA + derived/convergent + BYOK + hybrid composite |
| TOTP ([spec](features/totp-secret-engine.md)) | Done — Phases 1–4: HOTP/TOTP + GUI |
| SSH ([spec](features/ssh-secret-engine.md)) | Done — Phases 1–4: CA Ed25519 + OTP + ML-DSA-65 PQC + GUI |
| OpenLDAP / AD password-rotation ([spec](features/ldap-secret-engine.md)) | Done — all 5 phases incl. identity-aware check-out affinity |
| Dynamic Secrets framework ([spec](features/dynamic-secrets.md)) | Todo — host ships only the framework; concrete engines (Postgres, MySQL, AWS, …) ship as plugins under [`dynamic-engine-plugins/`](dynamic-engine-plugins/), loaded on demand |

### Infrastructure

| Feature | Status |
|---|---|
| High Availability (Raft via Hiqlite) | Done |
| Plugin System ([spec](features/plugin-system.md)) | Done — WASM + supervised long-lived process runtime, signed manifests, per-plugin metrics, GUI |
| Namespaces / Multi-tenancy ([spec](features/namespaces-multitenancy.md)) | Partial |
| Kubernetes Integration ([spec](features/kubernetes-integration.md)) | Todo |
| Rustion Bastion Integration ([spec](features/rustion-integration.md)) | Todo — spec drafted; mediates Resource Connect through a PQC bastion with master-cert trust anchor, signed/encrypted session-grant envelopes, TTL+renewal, recording delegated to Rustion |
| Web UI / Desktop GUI (Tauri) | Done — all 9 phases |
| Compliance Reporting ([spec](features/compliance-reporting.md)) | Todo |

## Active Initiatives

None — all previously-active items have closed out. Next up are the `Todo` rows above, primarily:

- Secret Versioning & Soft-Delete
- Resource Connect (Phase 1 unblocks Phases 2–7)
- Dynamic Secrets framework + first engine plugins
- HSM Support
- Kubernetes Integration
- Compliance Reporting
- Rustion Bastion Integration (delegated PAM transport + recording)

## Completed Initiatives

Each entry below has a dedicated spec / roadmap document with full phase notes.

- [Post-Quantum Crypto Migration](roadmaps/post-quantum-crypto-migration.md) — removed Tongsuo / OpenSSL, adopted ChaCha20-Poly1305 + ML-KEM-768 + ML-DSA-65.
- [Hiqlite Default HA Storage](roadmaps/hiqlite-default-ha-storage.md) — 6 phases incl. cluster CLI, PQ TLS (X25519MLKEM768), HA fault-injection.
- [Tauri GUI with FIDO2 / YubiKey Support](roadmaps/tauri-gui-fido2.md) — 9 phases, 55 Tauri commands, 49 frontend tests, 79 React modules, 10 pages.
- [Caching](features/caching.md) — token cache + ciphertext-only secret cache + Prometheus metrics + `mlockall` / no-core-dump + sealed-flush + admin flush endpoint.
- [Resource Management](features/resources.md) — dedicated `resource/` engine, per-resource metadata + secret grouping, history, version snapshots, configurable types, ownership / sharing / asset-group integration, 14 Tauri commands, full GUI.
- [Per-User Scoping (Ownership & Sharing)](features/per-user-scoping.md) — 10 phases + migration backfill, `OwnerStore` + `ShareStore`, `scopes = ["owner", "shared"]`, policy templating, `/sharing` GUI page + per-resource Sharing tab.
- [Identity Groups](features/identity-groups.md) — user + app groups, policy union for UserPass / AppRole / FIDO2 logins, integration tests, GUI.
- [Resource / Asset Groups](features/resource-groups.md) — 13 phases; collections of resources + KV paths, two reverse indexes, ACL `groups = [...]` qualifier, ownership + sharing + member redaction, GUI.
- [File Resources](features/file-resources.md) — `files/` mount, 32 MiB cap + SHA-256 integrity, ownership / sharing / asset-group membership, local-FS sync target, content versioning, GUI. Phases 5–7 (SMB / SFTP / SCP / periodic re-sync) deferred (see below).
- [Cloud Storage Targets for Encrypted File](features/cloud-storage-backend.md) — 8 phases; pluggable `FileTarget` trait + S3 / OneDrive / Google Drive / Dropbox providers, OAuth/PKCE infra, OS keychain, key-obfuscation decorator, multi-vault saved profiles.
- [Cloud FileTarget Memory Cache](features/cloud-storage-backend.md) — bounded TTL cache (30 s read / 10 s list / 65k entries / 500 MiB), singleflight coalescing, stale-while-revalidate, opt-in prefetch, Prometheus metrics. Default-on for cloud providers.
- [PKI Secret Engine](features/pki-secret-engine.md) — Phases 1–5.2; classical + PQC + composite, multi-issuer with per-usage gates, full Vault-shape route surface, on-demand + auto tidy.
- [OIDC Authentication](features/oidc-auth.md) — server module + GUI admin lifecycle. PKCE + CSRF + nonce, JWKS verification, claim-to-policy mapping, mode-aware redirect-URI hints (server-stable vs. RFC 8252 loopback).
- [SAML 2.0 Authentication](features/saml-auth.md) — pure-Rust SP-initiated SSO; AuthnRequest, streaming `quick-xml` parsing, RSA-SHA256/SHA1 verify, hand-rolled Exclusive C14N. Zero libxml2 / xmlsec / OpenSSL footprint. 46 tests.

## Deferred sub-initiatives

Self-contained follow-ups with no current blocker on the parent feature. Each can graduate to Active when operator demand + a specific implementation choice are confirmed.

**PKI**
- `--allow-mixed-chain` opt-in — guard is fail-closed today; trivial to add as a flag for migration windows.
- AIA / CRL Distribution Points / Name Constraints extensions in issued certs — `pki/config/urls` round-trips the URLs; cert builders don't emit the extensions yet.
- Composite IETF-draft tracking — Phase 3 pins a BastionVault-internal prehash domain; swap point is `composite::bv_prehash` once `draft-ietf-lamps-pq-composite-sigs` locks.
- Additional composite variants — Phase 3 ships `id-MLDSA65-ECDSA-P256-SHA512`; other pairings (44+P-256, 87+P-384, RSA-PSS) follow the same structure.

## Notes

- Put new roadmap documents under [`roadmaps/`](roadmaps/).
- Keep this file updated whenever a roadmap is added, renamed, or removed.
- Prefer one roadmap per major initiative so planning, sequencing, and acceptance criteria stay reviewable.
