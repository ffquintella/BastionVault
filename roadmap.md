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
| Import / Export Module (user-facing JSON + password-encrypted `.bvx`) ([spec](features/import-export-module.md)) | Todo |
| Scheduled Exports (cron-driven `.bvx` / BVBK with retention + verification) ([spec](features/scheduled-exports.md)) | Todo |
| Resource Management (inventory + grouped secrets) | Done |
| File Resources (binary blobs + local-FS sync) | Done (Phases 1–4 + 8 shipped — engine + CRUD + history + 32 MiB cap + SHA-256 integrity + ownership / sharing / admin transfer / backfill + asset-group membership + local-FS sync target + GUI + content versioning. Phases 5–7 — SMB / SFTP / SCP transports + periodic re-sync — deferred as separate follow-up initiatives; see feature file) |
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
| Secret Engine: PKI (pure-Rust, PQC-capable -- [spec](features/pki-secret-engine.md)) | In Progress (Phases 1 + 2 + 3 + 4 + 4.1 done) |
| Secret Engine: Transit ([spec](features/transit-secret-engine.md)) | Todo |
| Secret Engine: TOTP ([spec](features/totp-secret-engine.md)) | Todo |
| Secret Engine: SSH ([spec](features/ssh-secret-engine.md)) | Todo |
| Dynamic Secrets ([spec](features/dynamic-secrets.md)) | Todo |
| **Infrastructure** | |
| High Availability (Raft consensus via Hiqlite) | Done |
| Plugin System (dynamic loading) ([spec](features/plugin-system.md)) | Todo |
| Namespaces / Multi-tenancy ([spec](features/namespaces-multitenancy.md)) | Partial |
| Kubernetes Integration ([spec](features/kubernetes-integration.md)) | Todo |
| Web UI / Desktop GUI (Tauri) | Done (all 9 phases) |
| Auth: OIDC | Done (server module + GUI login + full provider admin lifecycle — `src/modules/credential/oidc/` ships Authorization-Code-Flow-with-PKCE, provider config + role CRUD, `auth_url` + `callback`, ID-token verification, claim-to-policy mapping, token renewal. Login page SSO tab shows one clickable button per configured provider — no mount/role typing; Settings page "Single Sign-On (SSO)" card drives the full mount + config + role admin from the root token, with mode-aware redirect-URI hints (stable server URL for remote, RFC 8252 loopback for desktop). Global enable/disable toggle persisted at `core/sso/settings`. Unauth `sys/sso/providers` discovery endpoint drives the login tab visibility.) |
| Auth: SAML 2.0 | Done (server module — pure-Rust SP-initiated SSO in `src/modules/credential/saml/`: AuthnRequest + HTTP-Redirect encoding, Response parsing via `quick-xml`, structural validation, RSA-SHA256/SHA1 signature verification via `rsa 0.9` + `x509-parser` with a hand-rolled Exclusive C14N that handles every major IdP's output format. Zero libxml2/libxmlsec1/OpenSSL footprint. 46 unit + integration tests, including an end-to-end sign-and-verify roundtrip.) |
| Auth: FIDO2 / WebAuthn / YubiKey | Done (server module) |
| Compliance Reporting ([spec](features/compliance-reporting.md)) | Todo |

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
- [File Resources](features/file-resources.md)
  Core feature shipped: dedicated `files/` mount with `src/modules/files/mod.rs` — barrier-encrypted metadata + blob storage, per-file history log, 32 MiB hard cap with SHA-256 integrity re-verified on every read (including historical versions). Ownership / sharing / admin transfer / backfill wired through the shared `OwnerStore` + `ShareStore` (new `ShareTargetKind::File` variant); asset-group membership via a third reverse index in `ResourceGroupStore`. Local-filesystem sync target with atomic tmp-then-rename write, optional Unix mode, per-target sync-state, on-demand `POST files/{id}/sync/{name}/push` endpoint. Content versioning with snapshot-on-write + `DEFAULT_VERSION_RETENTION = 5` prune policy + restore (restore is reversible because the displaced content is itself snapshotted). Full Admin → Audit integration emitting `create` / `update` / `delete` / `restore` events with actor entity ids through the shared `FileAuditStore`. GUI: top-level Files page (drag-and-drop upload with Windows WebView2 drop-handler fix, edit metadata modal, sync-targets management, versions tab), per-resource-detail Files tab listing files associated with each resource, `TargetPicker` typeahead for resource association. 22 module tests + integration tests against the full Rust suite. **Phases 5–7 (SMB / SFTP / SCP transports + periodic re-sync) are deferred** as separate follow-up initiatives — each needs its own crate decision (SMB: `pavao` vs. `smb3`; SSH: `russh` vs. `libssh2-sys`) and container-based integration-test infrastructure, and they're additive sync *transports* rather than gaps in the core file-resource model. The local-FS target covers common deployment patterns today (operators often front it with `rclone` / `rsync` / `syncthing` managed out-of-band).
- [Cloud Storage Targets for the Encrypted File backend](features/cloud-storage-backend.md)
  All 8 phases shipped. The Encrypted File backend (`src/storage/physical/file/`) now sits on a pluggable `FileTarget` trait with four provider implementations — **AWS S3** via `rusty-s3` + `ureq` (MinIO-compatible), **Microsoft OneDrive** via Graph API (App-folder scoped), **Google Drive** via Drive v3 (app-data scoped, ID-based chain walking + folder-id cache), **Dropbox** via v2 API (dual-host content/api endpoints, supports both OAuth refresh tokens and long-lived access tokens wrapped in a `{"access_token":"..."}` JSON envelope). Each provider is feature-gated (`cloud_s3` / `cloud_onedrive` / `cloud_gdrive` / `cloud_dropbox`) so default builds carry zero cloud code. Shared infrastructure: `credentials_ref` URI grammar (`env:` / `file:` / `inline:` / `keychain:`) with `Secret`-newtype zero-on-drop; OAuth + PKCE + loopback-redirect consent flow (fixed port 8472 so the redirect URI is stable across runs); `bvault operator cloud-target connect` CLI; **Settings → Cloud Storage Targets GUI card** with inline provider consent flow, dev-console help links, "paste existing token" shortcut (uses Dropbox's Generated-access-token), S3 inline credentials, and stable-redirect-URI display with Copy button; OS keychain writer via the `keyring` crate behind `cloud_keychain`; **`ObfuscatingTarget` decorator** (Phase 8) that HMAC-SHA256s every object key with an auto-bootstrapped per-target salt. **Get Started integration**: new "Cloud Vault" option on the chooser backed by the multi-vault saved-profiles model (`VaultProfile` + `last_used_id`, hand-editable JSON preferences, full CRUD + legacy-shape migration). InitPage branches its copy on the active profile's kind and carries ⇄/⚙/🗑 controls (switch, inline credential re-paste, forget) so an init failure is recoverable without leaving the page. Deferred sub-slices (not blocking): rekey-CLI for the obfuscation salt (library pieces present; orchestrator not shipped), and sync-path bootstrap of obfuscation for server-mode boots that go through `storage::new_backend` (desktop uses `FileBackend::new_maybe_obfuscated` directly via `embedded::build_backend`).

- [OIDC Authentication](features/oidc-auth.md)
  Server module + full GUI admin lifecycle shipped. `src/modules/credential/oidc/` registers the `oidc` auth kind via `OidcModule` + `OidcBackend`. Provider config (discovery URL, client id/secret, allowed redirect URIs, default scopes) and role config (bound audiences, bound claims, claim-to-metadata mappings, user/groups claims, per-role redirect whitelist, policies, token TTLs) CRUD under `auth/<mount>/config` and `auth/<mount>/role/<name>`. Unauth-paths `auth/<mount>/auth_url` (PKCE + CSRF state + nonce, state persisted for 5 minutes at `state/<csrf>`) and `auth/<mount>/callback` (code exchange + ID-token verification via the `openidconnect` crate's JWKS path + bound-claim validation + metadata projection). Token renewal re-loads the role and rejects if policies drifted. Client secrets are redacted on read. **GUI login**: three Tauri commands (`oidc_login_start` / `complete` / `cancel`) bridge a loopback listener to the backend; login page SSO tab shows one clickable button per configured provider — no mount/role typing. **GUI admin**: Settings → Single Sign-On card drives the full mount + config + default-role admin from the root token, with validation, secret-preservation on edit, and mode-aware callback-URI hints (stable server URL for remote; RFC 8252 loopback pattern for desktop with IdP-specific labels — Azure AD's "Mobile and desktop applications", Okta's "Native app", Google's "Desktop app"). Unauth `sys/sso/providers` discovery + root-gated `sys/sso/settings` global toggle (stored at barrier key `core/sso/settings`) drive the login-tab visibility. 17 unit tests + 1 CRUD integration test + 1 `#[ignore]`d live-IdP test.

- [Cloud FileTarget Memory Cache](features/cloud-storage-backend.md)
  Feature-complete bounded TTL-based `CachingTarget` decorator (`src/storage/physical/file/cache.rs`) with 30s read TTL / 10s list TTL / 65,536-entry / **500 MiB** soft caps, write-and-delete invalidation (including prefix-affected list entries), negative-result caching, FIFO eviction, **per-key singleflight coalescing** (8 concurrent misses → 1 provider call via `tokio::sync::Mutex`), **stale-while-revalidate** (default `stale_ratio = 0.5` — entries past the halfway point serve cached value + spawn background refresh via `tokio::spawn` so hot keys stay hot under steady traffic), **opt-in bounded-concurrency background prefetch** (non-empty `prefetch_keys` triggers a warmup task on construction), and `bvault_cache_*{layer="cloud_target"}` Prometheus metrics. Default-on for `s3`/`onedrive`/`gdrive`/`dropbox`, default-off for `local`. All async features `#[cfg(not(feature = "sync_handler"))]`-gated — sync builds fall back to v1 pure-TTL behavior. Config keys: `cache_{read_ttl_secs,list_ttl_secs,max_entries,max_bytes,stale_ratio,prefetch_keys,prefetch_concurrency}`. Zero new deps. 13 unit tests green.

- [SAML 2.0 Authentication](features/saml-auth.md)
  Server module shipped end-to-end. `src/modules/credential/saml/` implements SP-initiated SSO with a fully pure-Rust stack — no `samael` / `libxml2` / `libxmlsec1` / OpenSSL dependency. AuthnRequest generation + HTTP-Redirect encoding, streaming `quick-xml` Response parsing, structural validation (status + Destination + InResponseTo + Issuer + Audience + timestamp with 60 s clock-skew grace), RSA-SHA256 / RSA-SHA1 signature verification via `rsa 0.9` + `x509-parser`, and a hand-rolled Exclusive XML Canonicalization that handles the output format every major IdP (Azure AD, Okta, Keycloak, Shibboleth, ADFS) emits. Attribute-to-policy role mappings with per-role `bound_attributes` / `bound_subjects` enforcement at callback time. Login + callback paths `auth/<mount>/login` + `auth/<mount>/callback` (both unauth), state persisted at `state/<relay_state>` with 5-minute TTL and single-use load-and-delete. 46 unit + integration tests, including an end-to-end sign-and-verify roundtrip against a freshly-generated RSA keypair.

## Active Initiatives

No active initiatives — all previously-active items have closed out.
Next up are the items tracked under `Todo` in the Feature Status
table (Secret Versioning & Soft-Delete, Transit / TOTP / SSH secret
engines, Dynamic Secrets, HSM Support, Kubernetes Integration,
Compliance Reporting, Plugin System).

## Deferred sub-initiatives

Tracked separately from Active Initiatives because each is self-contained, needs its own crate decision + container-based integration-test infrastructure, and has no current blocker on the core features that incubated it. Each can graduate to Active when operator demand + a specific crate candidate are confirmed.

- **File Resources — SMB sync transport** — `FileSyncTarget { kind = "smb" }` with NTLMv2 + optional Kerberos auth. Crate candidates: `pavao` / `smb3` (alpha); Windows-native via `windows-rs` as an alternative. Samba container in CI for tests. See `features/file-resources.md` § "Deferred sub-initiatives".
- **File Resources — SFTP + SCP sync transports** — two transports sharing an SSH session; `russh` + `russh-sftp` vs. `libssh2-sys`. Key-stored-in-vault bootstrap ordering needs design. OpenSSH container in CI. See `features/file-resources.md` § "Deferred sub-initiatives".
- **File Resources — periodic re-sync** — internal-scheduler vs. external-tick-endpoint design question; cluster coordination via `hiqlite::dlock`. Blocked on at least one non-local sync transport landing first (nothing to re-sync with only local-FS). See `features/file-resources.md` § "Deferred sub-initiatives".
- **Cloud Storage Targets — rekey CLI** — library pieces present (`ObfuscatingTarget::with_salt`, `list("")` enumeration); end-to-end CLI that walks old-salt → new-salt is not shipped. Production rekey today via `operator migrate` through a non-obfuscated intermediate.
- **Cloud Storage Targets — server-mode obfuscation bootstrap** — desktop mode honors `obfuscate_keys` via `FileBackend::new_maybe_obfuscated`; server mode's sync `storage::new_backend` logs a warning when the flag is set. Requires propagating the async bootstrap through the broader storage chain.

## Notes

- Put new roadmap documents under [roadmaps](roadmaps/).
- Keep this file updated whenever a roadmap is added, renamed, or removed.
- Prefer one roadmap per major initiative so planning, sequencing, and acceptance criteria stay reviewable.
