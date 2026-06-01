# BastionVault Roadmap

Global entrypoint for roadmap and long-term planning in this repository.

The post-quantum crypto migration is complete. The default build uses a PQ-first, OpenSSL-free cryptographic stack.

## At a glance

| State | Count |
|---|---|
| Done | 46 |
| Partial | 2 |
| Todo | 7 |
| Removed | 1 |
| **Total tracked features** | **56** |

Active initiative: **Packaging & Distribution** ([roadmap](roadmaps/packaging-and-distribution.md)) — sequenced into four release waves; Waves 1 + 2 shipped (with Linux GUI bundler caveat), Wave 3 next.

## How to read this

- Tables below carry one row per tracked feature. **Status** is one of `Done`, `Todo`, `Partial`, `Removed`. **Notes** is a one-line summary with a spec link.
- Detailed phase notes for each feature live in the linked spec under [`features/`](features/) — the table is deliberately terse.
- Multi-phase initiatives that have closed out are summarised under [Completed Initiatives](#completed-initiatives) with full phase notes and outcomes.
- Open follow-ups that are not a top-line feature live under [Deferred sub-initiatives](#deferred-sub-initiatives).

## Feature Status

### Core

| Feature | Status | Notes |
|---|---|---|
| Core Vault Operations (init / seal / unseal / status) | Done | Vault-API-compatible. |
| Secret Management (KV CRUD) | Done | KV v1 + KV v2 incl. nested-folder LIST. |
| Secret Versioning & Soft-Delete | Done | KV v2 backend, CLI auto-detect, full GUI (history panel + per-version actions + CAS + engine config). [spec](features/secret-versioning-and-soft-delete.md) |
| Access Control (RBAC + path-based ACL) | Done | Path-based policy engine with allow / deny / capabilities. |
| Identity Groups (user / app groups → policy mapping) | Done | [spec](features/identity-groups.md) — policy union for UserPass / AppRole / FIDO2, plus Phase 7 group-shared resources via `metadata { group_shared_resources = "true" }`. |
| Per-User Scoping (ownership + policy templating + sharing) | Done | [spec](features/per-user-scoping.md) — 11 phases + migration backfill (Phase 11: self-service claim + list badge). |
| Asset Groups (collections of resources + KV paths) | Done | [spec](features/resource-groups.md) — 13 phases incl. ownership, sharing, member redaction. |
| Audit Logging (tamper-evident, HMAC chain) | Done | Phase 1 file device shipped; syslog / HTTP devices [deferred](#deferred-sub-initiatives). |
| Metrics (Prometheus) | Done | Standard `/metrics` endpoint. |

### Cryptography

| Feature | Status | Notes |
|---|---|---|
| Post-Quantum Crypto Migration | Done | [roadmap](roadmaps/post-quantum-crypto-migration.md) — host stack OpenSSL-free, including FIDO2 (now using an in-tree pure-Rust WebAuthn RP at `src/modules/credential/fido2/rp/`). |
| Key Management (ML-KEM-768, ML-DSA-65, ChaCha20-Poly1305) | Done | PQ-first stack. |
| Key Rotation & Re-encryption | Done | Re-encrypt with new barrier key on rotate. |
| HSM Support | Todo | [spec](features/hsm-support.md) |

### Storage

| Feature | Status | Notes |
|---|---|---|
| Storage Backend: Encrypted File | Done | Local file storage with barrier encryption. |
| Storage Backend: MySQL | Done | Diesel + r2d2 pool. |
| Storage Backend: SQLx | Removed | libsqlite3-sys conflict. |
| Storage Backend: Hiqlite (embedded Raft SQLite, HA) | Done | [roadmap](roadmaps/hiqlite-default-ha-storage.md) — default backend, 6 phases. |
| Cloud targets for Encrypted File (S3 / OneDrive / Google Drive / Dropbox) | Done | [spec](features/cloud-storage-backend.md) — 8 phases incl. cache decorator + key obfuscation. |
| Operator Backup / Restore (BVBK) | Done | [spec](features/import-export-backup-restore.md) — full-vault binary archive, HMAC-SHA256, for disaster recovery. |
| User-facing Exchange Module (`.bvx`) | Done | [spec](features/import-export-module.md) — password-encrypted JSON for "Alice shares N secrets with Bob"; built on top of BVBK but a different threat model. Argon2id + XChaCha20-Poly1305, two-step preview-then-apply import with `skip` / `overwrite` / `rename` conflict policies, full GUI with scope picker + entropy meter. |
| Scheduled Exports | Done | [spec](features/scheduled-exports.md) — `src/scheduled_exports/` (runner + schedule + store), `POST/GET/PUT/DELETE /v1/sys/scheduled-exports/*`, Tauri commands + GUI tab under `/exchange` (Scheduled backups). Built on top of the `.bvx` Exchange machinery. |
| Caching | Done | [spec](features/caching.md) — token cache + ciphertext-only secret cache + memory hardening. |
| Batch Operations | Done | [spec](features/batch-operations.md) — Phase 1 HTTP shipped; CLI + SDK [deferred](#deferred-sub-initiatives). |

### Resources

| Feature | Status | Notes |
|---|---|---|
| Resource Management (inventory + grouped secrets) | Done | [spec](features/resources.md) — 14 Tauri commands, full GUI. |
| File Resources (binary blobs + sync targets) | Done | [spec](features/file-resources.md) — local-FS + SMB + SFTP + SCP + periodic re-sync + sync-on-write. |
| First-class `firewall` / `switch` types + refined `database` | Done | [spec](features/resource-types-firewall-switch-db.md) — three phases shipped; closed-enum DB engines, vendor / HA-role / layer / firmware fields. |
| Resource Connect — in-app SSH / RDP for server resources | Done | [spec](features/resource-connect.md) — Phases 1–7 incl. ⌘K palette, recently-connected list, Connect-policy on `ResourceTypeDef`. SSH × {Secret, LDAP, PKI, **SSH engine (CA + OTP)**}, RDP × {Secret, LDAP, PKI}. |

### Networking & TLS

| Feature | Status | Notes |
|---|---|---|
| TLS & mTLS (Rustls-based) | Done | PQ-friendly hybrid suites (X25519MLKEM768) supported. |

### Authentication

| Feature | Status | Notes |
|---|---|---|
| Auth: Token | Done | Vault-shape token store. |
| Auth: AppRole | Done | RoleID + SecretID. |
| Auth: Userpass | Done | Argon2 password hashing. |
| Auth: Certificate | Done | mTLS client-cert auth. |
| Auth: OIDC | Done | [spec](features/oidc-auth.md) — server module + GUI lifecycle, PKCE / nonce / JWKS. |
| Auth: SAML 2.0 | Done | [spec](features/saml-auth.md) — pure-Rust SP-initiated SSO, no libxml2 / xmlsec. |
| Auth: FIDO2 / WebAuthn / YubiKey | Done | [roadmap](roadmaps/tauri-gui-fido2.md) — server uses an in-tree pure-Rust RP (`fido2/rp/`); no `openssl` in the server crate. ES256 + Ed25519, attestation `none` only. |
| Packaging — server container image | In progress | [roadmap](roadmaps/packaging-and-distribution.md) — Wave 1 + Wave 2 (cluster compose, multi-arch, Cosign keyless, CycloneDX SBOM, `:debug` variant) shipped. Helm chart + Phase 1.5 trusted-proxy still open. |
| Packaging — Linux CLI installers | Done (amd64) | cargo-deb + cargo-generate-rpm metadata in `Cargo.toml`; `make linux-cli-packages`. GPG signing + arm64 cross-builds deferred to later waves. |
| Packaging — Linux GUI installers | Skeleton | Postinst/prerm scripts staged; `tauri.conf.json` wiring + first `tauri build` pass on a Linux host pending. |
| Packaging — macOS / Windows installers | Todo | Wave 3 — pending macOS / Windows build runners + signing identities (notary, EV Authenticode). |
| Packaging — client distribution website | Todo | Wave 3/4 — depends on signed client artefacts. |
| Auth: Machine Authentication | Todo | [spec](features/machine-authentication.md) — composite-key (random + host-hardware fingerprint), admin-approval gated. |

### Secret Engines

| Feature | Status | Notes |
|---|---|---|
| PKI | Done | [spec](features/pki-secret-engine.md) — Phases 1–5.2; classical + ML-DSA + composite, multi-issuer, on-demand + auto tidy. |
| PKI: ACME server endpoints | Done | [spec](features/pki-acme.md) — RFC-8555 feature-complete, HTTP-01 + DNS-01 + EAB. |
| PKI: Key Management + Cert Lifecycle | Done | [spec](features/pki-key-management-and-lifecycle.md) — 7 phases incl. `CertDeliveryPlugin` trait. |
| Transit | Done | [spec](features/transit-secret-engine.md) — Phases 1–4: AEAD + HMAC + sign/verify + ML-KEM + ML-DSA + BYOK + hybrid. |
| TOTP | Done | [spec](features/totp-secret-engine.md) — Phases 1–4: HOTP / TOTP + GUI. |
| SSH | Done | [spec](features/ssh-secret-engine.md) — Phases 1–4: CA Ed25519 + OTP + ML-DSA-65. |
| OpenLDAP / AD password-rotation | Done | [spec](features/ldap-secret-engine.md) — 5 phases incl. identity-aware check-out affinity. |
| Dynamic Secrets framework | Todo | [spec](features/dynamic-secrets.md) — host ships only the framework; engines under [`dynamic-engine-plugins/`](dynamic-engine-plugins/). |
| XCA database import | Done | [spec](features/xca-import.md) — external plugin `bastion-plugin-xca` shipped; reads `.xdb` SQLite, decrypts both XCA envelope formats, imports into the PKI engine via the operator-driven GUI wizard. |
| Password Manager Pro resource import | Done | [spec](features/pmp-import.md) — `bastion-plugin-pmp` external plugin + GUI wizard. |

### Infrastructure

| Feature | Status | Notes |
|---|---|---|
| High Availability (Raft via Hiqlite) | Done | [roadmap](roadmaps/hiqlite-default-ha-storage.md) — cluster CLI, PQ TLS, HA fault-injection. |
| Vault Cluster — Client Discovery & Health-Aware Connection | Done | [spec](features/vault-cluster-client-discovery.md), [roadmap](roadmaps/vault-cluster-client-discovery.md) — All 8 phases shipped. `bv-client` discovery + health, `build_with_discovery` builder, sticky failure contract, Tauri `connect_remote` wiring + Settings diagnostics modal, `bvault cluster discover` CLI subcommand + `--no-cluster-discovery` flag, 26 new tests (19 unit + 7 e2e), operator runbook in docs. `operator seal` / `operator unseal` fan out cluster-wide via SRV discovery (per-node seal state), with `--local` to scope to one node. |
| Plugin System | Done | [spec](features/plugin-system.md) — WASM + supervised process runtime, signed manifests, per-plugin metrics, GUI. |
| Plugin Extensibility (surface manifest, dynamic GUI menus/forms, client cache, auto-update) | Done | [spec](features/plugin-extensibility.md), [roadmap](roadmaps/plugin-extensibility-redesign.md) — 8 phases shipped end-to-end (server surface storage + 3 HTTP routes, bv-client cache, GUI dynamic render, form-hook WASM sandbox, long-poll watcher, operator UX, reference TOTP example + SDK helpers). |
| Namespaces / Multi-tenancy | Partial | [spec](features/namespaces-multitenancy.md) |
| Kubernetes Integration | Todo | [spec](features/kubernetes-integration.md) — `kubernetes` auth backend + CSI driver + agent injector. |
| Rustion Bastion Integration | In progress | [spec](features/rustion-integration.md) — mediates Resource Connect through a PQC bastion; recording delegated to Rustion. **Phases 1–9 done, Phase 4.2-full done, Phase 7.4 done** (BV 0.7.14 → 0.8.23, Rustion 0.7.11 → 0.8.0): full session/recording pipeline + four-tier policy + telemetry pull + audit-witness replication + rate-limited telemetry + recording.replayed audit + fleet analytics + stable deployment_id + Rustion authorities-pending holding pen + disk-backed `authorities-pending/` + `tombstoned/` YAML with `rustion authority {list-pending, approve, reject, deenrol, untombstone, list, list-tombstones}` operator CLI + BV weekly re-attestation timer + `rustion_authority_attest` + `rustion_target_deenrol` Tauri commands + deployment_id binding (403 attestation_mismatch) + separate SessionReplayWindow Tauri WebviewWindow + WASM bitmap-update decoder at `gui/wasm/rdp-replay/` with matching TS port + RdpReplayCanvas live playback (uncompressed 16/24/32 bpp + RLE16/RLE24) + signed-URL replay path (`POST /v1/recordings/<rid>/replay` + HMAC-bound `GET /v1/recordings/<rid>`) + bastion-driven CredSSP injection driver (NTLMv2 sealing + RC4 keystream + pubKeyAuth +1 contract + sealed TSCredentials, simulated-Windows e2e tested) + operator deployment guide at [`features/rustion-authority-lifecycle.md`](features/rustion-authority-lifecycle.md) + **master authority lifecycle Phase 2** (`rustion master issue` / `rotate` CLI + HTTP, hybrid Ed25519 + ML-DSA-65 keypair lifecycle with rotate-grace window, real pubkey export, previous-key acceptance during grace via `verify_with_grace`). Phase 7.4 wires the in-app Connect button to the policy resolver: SSH-password sessions (BV 0.8.21) and RDP-password sessions (BV 0.8.22) route through the bastion when transport is `rustion-required` / `rustion-preferred`; non-password SSH and smart-card (rdp-cert) RDP under `rustion-required` fail closed pending the bastion's PKINIT path. BV 0.8.23 wires the spawned SSH/RDP session window into `useRustionSessionLifecycle` via a new `session_rustion_info` Tauri command + shared `RustionSessionChip` (auto-renew + manual Renew/Terminate + live TTL). Remaining: bastion host-key / TLS pinning in the GUI dialler (cross-repo with Rustion), rdp-cert via PKINIT/SPNEGO, live-Windows-VM transport hookup, `attestation_renew_at` enforcement at envelope-verify, Rustion admin web UI, BV-side GUI buttons for the new Tauri commands, cluster-replicated master + true PKI-engine cert emission (Phase 9 of authority lifecycle). NSCodec / RemoteFX / 8 bpp RLE / bitmap-cache references and `rdp-cert` smart-card PKINIT documented as separate tracks. |
| Web UI / Desktop GUI (Tauri) | Done | [roadmap](roadmaps/tauri-gui-fido2.md) — 9 phases, 55 Tauri commands, 79 React modules, 10 pages. |
| Compliance Reporting | Todo | [spec](features/compliance-reporting.md) |

### Packaging & Distribution

Sequenced together under [`roadmaps/packaging-and-distribution.md`](roadmaps/packaging-and-distribution.md). Specs drafted; no code yet.

| Feature | Status | Notes |
|---|---|---|
| Server Container Image (Podman / OCI, standalone + cluster) | Partial | [spec](features/packaging-podman-server.md) — **Phase 1 shipped**: standalone, `linux/amd64`, distroless `cc-debian12:nonroot`, GHCR push on `v*.*.*` tags, unsigned. Phases 1.5 (client-IP propagation), 2 (cluster), 3 (multi-arch + Cosign + SBOM + `:debug`), 4 (Helm chart) pending. |
| Native Client Installers (deb / rpm / pkg / msi for GUI + CLI) | Todo | [spec](features/packaging-client-binaries.md) — Tauri bundler for GUI, parallel CLI track via `cargo-deb` / `cargo-generate-rpm` / `pkgbuild` / WiX 3.x. Double-signed (platform-native + Cosign). Phase 5 publishes apt + dnf repos. |
| Client Distribution Website (OCI image) | Todo | [spec](features/packaging-distribution-website.md) — small `axum` + `askama` static-site server, signed `manifest.json` consumed by both the landing page and the GUI's "update available" banner (link-out only, no auto-update). |

## Active Initiatives

- **Packaging & Distribution** ([roadmap](roadmaps/packaging-and-distribution.md)) — server container image + native client installers + client-binary distribution website. Sequenced into four release waves. **Wave 1 shipped** (standalone server container image, distroless, GHCR push on `v*.*.*` tags). Wave 2 largely shipped (cluster compose, multi-arch, Cosign keyless, SBOM, Linux CLI installers); GUI Linux bundler + Phase 1.5 trusted-proxy still open. Wave 3 (macOS/Windows installers + downloads website) next.

Next-up `Todo` rows once Packaging & Distribution lands:

- Dynamic Secrets framework + first engine plugins
- HSM Support
- Kubernetes Integration
- Compliance Reporting
- Rustion Bastion Integration (delegated PAM transport + recording)
- Machine Authentication (composite-key auth for headless clients, admin-approval gated)

## Completed Initiatives

Each entry below has a dedicated spec / roadmap document with full phase notes.

- [Vault Cluster — Client Discovery & Health-Aware Connection](roadmaps/vault-cluster-client-discovery.md) — 8 phases shipped: SRV-based node discovery, `/sys/health` scoring with leader-over-follower + RTT + cluster_id minority rejection, sticky session with explicit-reconnect on `NodeUnavailable`, GUI + CLI surfacing, `bvault cluster discover` diagnostics subcommand, 7 in-process e2e tests + 19 unit tests, operator runbook.
- [Post-Quantum Crypto Migration](roadmaps/post-quantum-crypto-migration.md) — removed Tongsuo / OpenSSL, adopted ChaCha20-Poly1305 + ML-KEM-768 + ML-DSA-65.
- [Hiqlite Default HA Storage](roadmaps/hiqlite-default-ha-storage.md) — 6 phases incl. cluster CLI, PQ TLS (X25519MLKEM768), HA fault-injection.
- [Tauri GUI with FIDO2 / YubiKey Support](roadmaps/tauri-gui-fido2.md) — 9 phases, 55 Tauri commands, 49 frontend tests, 79 React modules, 10 pages.
- [Caching](features/caching.md) — token cache + ciphertext-only secret cache + Prometheus metrics + `mlockall` / no-core-dump + sealed-flush + admin flush endpoint.
- [Resource Management](features/resources.md) — dedicated `resource/` engine, per-resource metadata + secret grouping, history, version snapshots, configurable types, ownership / sharing / asset-group integration, 14 Tauri commands, full GUI.
- [Per-User Scoping (Ownership & Sharing)](features/per-user-scoping.md) — 10 phases + migration backfill, `OwnerStore` + `ShareStore`, `scopes = ["owner", "shared"]`, policy templating, `/sharing` GUI page + per-resource Sharing tab.
- [Identity Groups](features/identity-groups.md) — user + app groups, policy union for UserPass / AppRole / FIDO2 logins, integration tests, GUI.
- [Resource / Asset Groups](features/resource-groups.md) — 13 phases; collections of resources + KV paths, two reverse indexes, ACL `groups = [...]` qualifier, ownership + sharing + member redaction, GUI.
- [File Resources](features/file-resources.md) — `files/` mount, 32 MiB cap + SHA-256 integrity, ownership / sharing / asset-group membership, local-FS / SMB / SFTP / SCP sync, content versioning, GUI.
- [Cloud Storage Targets for Encrypted File](features/cloud-storage-backend.md) — 8 phases; pluggable `FileTarget` trait + S3 / OneDrive / Google Drive / Dropbox providers, OAuth/PKCE infra, OS keychain, key-obfuscation decorator, multi-vault saved profiles.
- [Cloud FileTarget Memory Cache](features/cloud-storage-backend.md) — bounded TTL cache (30 s read / 10 s list / 65k entries / 500 MiB), singleflight coalescing, stale-while-revalidate, opt-in prefetch, Prometheus metrics. Default-on for cloud providers.
- [PKI Secret Engine](features/pki-secret-engine.md) — Phases 1–5.2; classical + PQC + composite, multi-issuer with per-usage gates, full Vault-shape route surface, on-demand + auto tidy.
- [PKI Key Management + Cert Lifecycle](features/pki-key-management-and-lifecycle.md) — all seven phases (L1–L7): managed key store, key reuse on issue/sign, issuer-bound keys, chain endpoint + `ca_chain` on responses, emission controls (domain matrix + ACME kill-switch + TTL/pathLen clamps), cert-lifecycle module with manual renew, periodic scheduler with backoff, and `CertDeliveryPlugin` trait with built-in `file` + `http-push` deliverers. The `plugin-ext` bridge for third-party deliverers is a deferred follow-up.
- [PKI ACME Server](features/pki-acme.md) — Phases 6.1 + 6.1.5 + 6.2 + 6.3, feature-complete on RFC 8555 (HTTP-01 + DNS-01, EAB, key-change, revoke, rate limit, expiry sweep).
- [Transit Secret Engine](features/transit-secret-engine.md) — Phases 1–4: AEAD + HMAC + sign/verify + ML-KEM datakey + ML-DSA + derived/convergent + BYOK + hybrid composite.
- [TOTP Secret Engine](features/totp-secret-engine.md) — Phases 1–4: HOTP / TOTP + GUI.
- [SSH Secret Engine](features/ssh-secret-engine.md) — Phases 1–4: CA Ed25519 + OTP + ML-DSA-65 PQC + GUI.
- [OpenLDAP / AD password-rotation](features/ldap-secret-engine.md) — 5 phases incl. identity-aware check-out affinity.
- [OIDC Authentication](features/oidc-auth.md) — server module + GUI admin lifecycle. PKCE + CSRF + nonce, JWKS verification, claim-to-policy mapping, mode-aware redirect-URI hints (server-stable vs. RFC 8252 loopback).
- [SAML 2.0 Authentication](features/saml-auth.md) — pure-Rust SP-initiated SSO; AuthnRequest, streaming `quick-xml` parsing, RSA-SHA256/SHA1 verify, hand-rolled Exclusive C14N. Zero libxml2 / xmlsec / OpenSSL footprint. 46 tests.
- [First-class `firewall` / `switch` types + refined `database`](features/resource-types-firewall-switch-db.md) — three phases shipped: `firewall` + `switch` builtins (vendor enums, HA role, layer, firmware, model; SSH-22 connect defaults), `database.engine` closed enum (PostgreSQL / MySQL / MariaDB / MSSQL / Oracle / MongoDB / Redis / Elasticsearch / SQLite / Other) + `engine_version` + `tls_required`. PMP importer's `Fortimanager` → firewall and `Cisco IOS` → switch mappings verified end-to-end.
- [Resource Connect](features/resource-connect.md) — Phases 1–7. Launch matrix: SSH × {Secret, LDAP, PKI} ✅, RDP × {Secret, LDAP, PKI (CredSSP smartcard via sspi-rs's PIV emulator)} ✅. Per-resource-type Connect policy on `ResourceTypeDef`, recently-connected list (last 10), ⌘K global Connect palette with fuzzy resource × profile picker.
- [XCA database import](features/xca-import.md) — external plugin `bastion-plugin-xca` (process runtime) reads XCA `.xdb` SQLite databases, decrypts both envelope formats (EVP_BytesToKey for XCA ≤ 2.0, PBKDF2-HMAC-SHA512 for XCA ≥ 2.4) plus per-key `ownPass`, and imports certificates / private keys / CRLs into the PKI engine via the `Settings → PKI → Import XCA` GUI wizard. Standalone keys / CSRs / templates land as KV blobs under `secret/xca-import/<batch-id>/...`. Zero host-crate code; rides on the plugin substrate alongside `bastion-plugin-pmp`.
- [Password Manager Pro resource import](features/pmp-import.md) — all phases shipped: `validate` + `preview` + `import` ops over `.xls` / `.xlsx`, fixed `OS Type` → BV type/os_type table with per-call overrides, multi-account collapse, KV routing for `Generic Keys` / `Application Passwords` / `License Store`, Department → asset-group derivation, custom-column preservation. External plugin under `plugins-ext/bastion-plugin-pmp` (process runtime); GUI wizard at `gui/src/routes/PmpImportPage.tsx`. Encrypted-export rejection at validate time, synthetic version-matrix tests covering PMP 11 / 12 / 13 layouts, operator migration guide bundled with the plugin.

## Deferred sub-initiatives

Self-contained follow-ups with no current blocker on the parent feature. Each can graduate to Active when operator demand + a specific implementation choice are confirmed.

**Audit Logging**
- Syslog and HTTP audit devices — Phase 1 file device shipped; the trait + dispatcher accept additional devices; only the syslog / HTTP implementations are missing.

**Batch Operations**
- CLI + SDK clients — Phase 1 HTTP surface shipped; the CLI and SDK wrappers are deferred until at least one engine asks for them.

**PKI**
- `--allow-mixed-chain` opt-in — guard is fail-closed today; trivial to add as a flag for migration windows.
- AIA / CRL Distribution Points / Name Constraints extensions in issued certs — `pki/config/urls` round-trips the URLs; cert builders don't emit the extensions yet.
- Composite IETF-draft tracking — Phase 3 pins a BastionVault-internal prehash domain; swap point is `composite::bv_prehash` once `draft-ietf-lamps-pq-composite-sigs` locks.
- Additional composite variants — Phase 3 ships `id-MLDSA65-ECDSA-P256-SHA512`; other pairings (44+P-256, 87+P-384, RSA-PSS) follow the same structure.
- `plugin-ext` bridge for third-party `CertDeliveryPlugin` deliverers — trait + `DelivererRegistry::register` plug point are stable; runtime bridge is the remaining work.

**FIDO2 / WebAuthn**
- ~~Replace the `openssl-sys` link in `webauthn-rs` 0.5~~ — done. The server now uses an in-tree pure-Rust Relying Party at [`src/modules/credential/fido2/rp/`](src/modules/credential/fido2/rp/); `cargo tree -p bastion_vault -i openssl` is empty. See [tauri-gui-fido2.md](roadmaps/tauri-gui-fido2.md) for the new module layout. Storage compat note: existing FIDO2 enrollments require re-enrollment after the upgrade.
- Remove GUI-side OpenSSL — the `authenticator` crate's `crypto_openssl` feature plus a single PKCS#12 import in `gui/src-tauri/src/commands/pki.rs`. Candidates: `ctap-hid-fido2` (USB-only) or `authenticator` with `crypto_nss`; `p12-keystore` for the PKCS#12 import.

## Notes

- Put new roadmap documents under [`roadmaps/`](roadmaps/).
- Keep this file updated whenever a feature status changes (Todo → In Progress → Done) or a new roadmap is added.
- The status table is the single source of truth for project progress. The `Notes` column is intentionally short — phase-by-phase detail belongs in the linked spec, not in this table.
- Prefer one roadmap per major initiative so planning, sequencing, and acceptance criteria stay reviewable.
