# BastionVault Roadmap

Global entrypoint for roadmap and long-term planning in this repository.

The post-quantum crypto migration is complete. The default build uses a PQ-first, OpenSSL-free cryptographic stack.

## At a glance

| State | Count |
|---|---|
| Done | 48 |
| Partial | 1 |
| Todo | 7 |
| Removed | 1 |
| **Total tracked features** | **57** |

Active initiative: **Packaging & Distribution** ([roadmap](roadmaps/packaging-and-distribution.md)) — sequenced into four release waves; Waves 1 + 2 shipped (with Linux GUI bundler caveat), Wave 3 next.

## How to read this

- Tables below carry one row per tracked feature. **Status** leads with a progress checkbox followed by one of `Done`, `Todo`, `Partial`, `Removed`. **Notes** is a one-line summary with a spec link.
- **Checkbox legend:**
  - `[x]` — Done / shipped
  - `[/]` — In progress (includes `Partial` and `Skeleton`)
  - `[ ]` — Todo / not started
  - `[~]` — Removed / dropped
- A feature counts as Done (`[x]`) only when every phase in its linked spec is complete. Mixed-phase features stay `[/]`.
- Detailed phase notes for each feature live in the linked spec under [`features/`](features/) — the table is deliberately terse.
- Multi-phase initiatives that have closed out are summarised under [Completed Initiatives](#completed-initiatives) with full phase notes and outcomes.
- Open follow-ups that are not a top-line feature live under [Deferred sub-initiatives](#deferred-sub-initiatives).

## Feature Status

### Core

| Status | Feature | Notes |
|---|---|---|
| `[x]` Done | Core Vault Operations (init / seal / unseal / status) | Vault-API-compatible. |
| `[x]` Done | Secret Management (KV CRUD) | KV v1 + KV v2 incl. nested-folder LIST. |
| `[x]` Done | Secret Versioning & Soft-Delete | KV v2 backend, CLI auto-detect, full GUI (history panel + per-version actions + CAS + engine config). [spec](features/secret-versioning-and-soft-delete.md) |
| `[x]` Done | Access Control (RBAC + path-based ACL) | Path-based policy engine with allow / deny / capabilities (incl. `connect`). |
| `[/]` In progress | Connect-Only Access | [spec](features/connect-only-access.md) — `connect` capability + `rustion/v2/session/open` server-side credential resolution + `v2/sys/capabilities-self` + GUI credential hiding. Phase 1 + GUI filtering + GUI Rustion connect-path rewiring (Phase 2b) done. **e2e-validated live** via the revived `tests/e2e/rustion-ssh/` harness: a connect-only token is denied a direct secret read (403) yet proxies a real SSH shell to the target through the bastion. Remaining: RDP connect path + non-secret credential kinds. |
| `[x]` Done | Identity Groups (user / app groups → policy mapping) | [spec](features/identity-groups.md) — policy union for UserPass / AppRole / FIDO2, plus Phase 7 group-shared resources via `metadata { group_shared_resources = "true" }`. |
| `[x]` Done | Per-User Scoping (ownership + policy templating + sharing) | [spec](features/per-user-scoping.md) — 11 phases + migration backfill (Phase 11: self-service claim + list badge). |
| `[x]` Done | Asset Groups (collections of resources + KV paths) | [spec](features/resource-groups.md) — 13 phases incl. ownership, sharing, member redaction. |
| `[x]` Done | Audit Logging (tamper-evident, HMAC chain) | Phase 1 file device shipped; syslog / HTTP devices [deferred](#deferred-sub-initiatives). |
| `[x]` Done | Metrics (Prometheus) | Standard `/metrics` endpoint. |

### Cryptography

| Status | Feature | Notes |
|---|---|---|
| `[x]` Done | Post-Quantum Crypto Migration | [roadmap](roadmaps/post-quantum-crypto-migration.md) — host stack OpenSSL-free, including FIDO2 (now using an in-tree pure-Rust WebAuthn RP at `src/modules/credential/fido2/rp/`). |
| `[x]` Done | Key Management (ML-KEM-768, ML-DSA-65, ChaCha20-Poly1305) | PQ-first stack. |
| `[x]` Done | Key Rotation & Re-encryption | Re-encrypt with new barrier key on rotate. |
| `[ ]` Todo | HSM Support | [spec](features/hsm-support.md) |

### Storage

| Status | Feature | Notes |
|---|---|---|
| `[x]` Done | Storage Backend: Encrypted File | Local file storage with barrier encryption. |
| `[x]` Done | Storage Backend: MySQL | Diesel + r2d2 pool. |
| `[~]` Removed | Storage Backend: SQLx | libsqlite3-sys conflict. |
| `[x]` Done | Storage Backend: Hiqlite (embedded Raft SQLite, HA) | [roadmap](roadmaps/hiqlite-default-ha-storage.md) — default backend, 6 phases. |
| `[x]` Done | Cloud targets for Encrypted File (S3 / OneDrive / Google Drive / Dropbox) | [spec](features/cloud-storage-backend.md) — 8 phases incl. cache decorator + key obfuscation. |
| `[x]` Done | Operator Backup / Restore (BVBK) | [spec](features/import-export-backup-restore.md) — full-vault binary archive, HMAC-SHA256, for disaster recovery. |
| `[x]` Done | User-facing Exchange Module (`.bvx`) | [spec](features/import-export-module.md) — password-encrypted JSON for "Alice shares N secrets with Bob"; built on top of BVBK but a different threat model. Argon2id + XChaCha20-Poly1305, two-step preview-then-apply import with `skip` / `overwrite` / `rename` conflict policies, full GUI with scope picker + entropy meter. |
| `[x]` Done | Scheduled Exports | [spec](features/scheduled-exports.md) — `src/scheduled_exports/` (runner + schedule + store), `POST/GET/PUT/DELETE /v1/sys/scheduled-exports/*`, Tauri commands + GUI tab under `/exchange` (Scheduled backups). Built on top of the `.bvx` Exchange machinery. |
| `[x]` Done | Caching | [spec](features/caching.md) — token cache + ciphertext-only secret cache + memory hardening. |
| `[x]` Done | Batch Operations | [spec](features/batch-operations.md) — Phase 1 HTTP shipped; CLI + SDK [deferred](#deferred-sub-initiatives). |

### Resources

| Status | Feature | Notes |
|---|---|---|
| `[x]` Done | Resource Management (inventory + grouped secrets) | [spec](features/resources.md) — 14 Tauri commands, full GUI. |
| `[x]` Done | File Resources (binary blobs + sync targets) | [spec](features/file-resources.md) — local-FS + SMB + SFTP + SCP + periodic re-sync + sync-on-write. |
| `[x]` Done | First-class `firewall` / `switch` types + refined `database` | [spec](features/resource-types-firewall-switch-db.md) — three phases shipped; closed-enum DB engines, vendor / HA-role / layer / firmware fields. |
| `[x]` Done | Resource Connect — in-app SSH / RDP for server resources | [spec](features/resource-connect.md) — Phases 1–7 incl. ⌘K palette, recently-connected list, Connect-policy on `ResourceTypeDef`. SSH × {Secret, LDAP, PKI, **SSH engine (CA + OTP)**}, RDP × {Secret, LDAP, PKI}. |

### Networking & TLS

| Status | Feature | Notes |
|---|---|---|
| `[x]` Done | TLS & mTLS (Rustls-based) | PQ-friendly hybrid suites (X25519MLKEM768) supported. |

### Authentication

| Status | Feature | Notes |
|---|---|---|
| `[x]` Done | Auth: Token | Vault-shape token store. |
| `[x]` Done | Auth: AppRole | RoleID + SecretID. |
| `[x]` Done | Auth: Userpass | Argon2 password hashing. |
| `[x]` Done | Auth: Certificate | mTLS client-cert auth. |
| `[x]` Done | Auth: OIDC | [spec](features/oidc-auth.md) — server module + GUI lifecycle, PKCE / nonce / JWKS. |
| `[x]` Done | Auth: SAML 2.0 | [spec](features/saml-auth.md) — pure-Rust SP-initiated SSO, no libxml2 / xmlsec. |
| `[x]` Done | Auth: FIDO2 / WebAuthn / YubiKey | [roadmap](roadmaps/tauri-gui-fido2.md) — server uses an in-tree pure-Rust RP (`fido2/rp/`); no `openssl` in the server crate. ES256 + Ed25519, attestation `none` only. |
| `[x]` Done | Auth: Machine Authentication (FerroGate) | [spec](features/machine-authentication.md) — admit only FerroGate-attested machines (TPM-rooted SVID / DPoP child token), admin-approval gated, first-machine root bootstrap. **All 7 phases done**: `auth/ferrogate/` mount + config + admin lifecycle; DPoP-bound child-token verify + token mint; first-machine root bootstrap + self-poll; `cmis_grpc` JWKS source (cache + plaintext/PQ-TLS, validated live against the dev CMIS); `bvault ferrogate` client CLI; admin GUI page + a **Machine Login** tab that lets the GUI self-bootstrap as a MIA client (reusing the CLI MIA module); direct-SVID mode + CRL enforcement + rate limits + metrics + [docs](docs/ferrogate-machine-auth.md). Verifier vendored from FerroGate SDK v0.15.0. Shipped in **v0.12.0** (GUI MIA-client tab added post-`0.12.0`; in **v0.12.6** the MIA helper socket is discovered from the installed MIA's own config — `FERROGATE_HELPER_SOCKET` → `mia.toml` `[helper].socket` → per-OS wizard default — instead of a hard-coded path; **v0.12.7** adds `bvault ferrogate autoconfig` + a GUI "Autofill from local MIA" button that derives the whole mount config from the host's MIA — CMIS endpoint/pin from `mia.toml`, trust domain from the signed allowlist, live JWKS from CMIS); **v0.12.8** adds a `cmis_same_host` config flag (tries `host.containers.internal`/loopback before the configured endpoint, for a server co-located with CMIS — e.g. in a rootless-podman container) and unwraps tonic's `source()` chain so CMIS connect errors name the real cause. **Phase 8 (Unreleased)** adds combined machine+user auth — `login` binds an optional `user_token` and mints a token with the **intersection** of machine and user policies (user's `entity_id`, machine's `spiffe_id`; intermediate user token revoked), a `require_user_token` flag to enforce it server-side, an operator CLI `bvault operator ferrogate {list,approve,reject,revoke}` that authorizes machines from the server without needing an approved machine (bootstrap escape hatch), and a per-connection GUI "Require machine identity" gate (approved → bind into a combined session; pending → enrolment dialog; rejected/revoked → hard denial). **Phase 8.1 (v0.13.2)** makes the requirement **server-enforced**: a `require_machine_identity` config flag (mirrored to a `Core` atomic at unseal) gates every authenticated request at the token layer (machine-bound `spiffe_id` required; root exempt), an unauthenticated `auth/ferrogate/requirement` endpoint advertises it, and the GUI connect flow runs the gate from the server's answer (the client-side toggle is removed). Supersedes the earlier host-fingerprint design. **v0.13.5** replaces the approve-modal free-text policies field with a multi-select over existing ACL policies; **v0.14.0** extends that to the Config tab's **bootstrap policies** (validated autocomplete via a reusable `PolicySelect`, blocks unknown names) and adds an **MIA environment selector** to the Config + Machine Login tabs and `bvault ferrogate … --environment <env>` (reads `mia-<env>.toml` for side-by-side deployments; environments discovered from the config dirs). **Unreleased** gives the mount the MIA's own CMIS HA failover: a `cmis_srv` config field (DNS SRV owner name) the CMIS client resolves on each fetch and then dials every advertised node for, in RFC 2782 order, until one connects *and* verifies its SPKI pin — so a node whose cert has diverged from the shared cluster pin is skipped instead of failing the fetch; *Autofill from local MIA* now stores the SRV name rather than a single resolved node; and the **MIA environment** is now persisted in the mount config (`mia_environment`, validated, advertised via the `requirement` endpoint) so the GUI's connect-time machine gate, combined login, and Machine Login tab dial the right `mia-<env>.toml` automatically instead of always defaulting to `mia.toml`. **v0.14.6** adds a per-server **MIA environment** combobox to the GUI's Server add/edit form (Get Started screen): the choice persists on the profile (`RemoteProfile.mia_environment`) and is seeded into the shared env store before the `requirement` fetch on connect, so it takes precedence over the server-advertised environment — the operator can now override which `mia-<env>.toml` the machine gate dials and fix "not on the MIA's local allowlist" from setup. |
| `[/]` In progress | Packaging — server container image | [roadmap](roadmaps/packaging-and-distribution.md) — Wave 1 + Wave 2 (cluster compose, multi-arch, Cosign keyless, CycloneDX SBOM, `:debug` variant) shipped. Helm chart + Phase 1.5 trusted-proxy still open. |
| `[/]` Done (amd64) | Packaging — Linux CLI installers | cargo-deb + cargo-generate-rpm metadata in `Cargo.toml`; `make linux-cli-packages`. GPG signing + arm64 cross-builds deferred to later waves. |
| `[/]` Skeleton | Packaging — Linux GUI installers | Postinst/prerm scripts staged; `tauri.conf.json` wiring + first `tauri build` pass on a Linux host pending. |
| `[ ]` Todo | Packaging — macOS / Windows installers | Wave 3 — pending macOS / Windows build runners + signing identities (notary, EV Authenticode). |
| `[ ]` Todo | Packaging — client distribution website | Wave 3/4 — depends on signed client artefacts. |

### Secret Engines

| Status | Feature | Notes |
|---|---|---|
| `[x]` Done | PKI | [spec](features/pki-secret-engine.md) — Phases 1–5.2; classical + ML-DSA + composite, multi-issuer, on-demand + auto tidy. |
| `[x]` Done | PKI: ACME server endpoints | [spec](features/pki-acme.md) — RFC-8555 feature-complete, HTTP-01 + DNS-01 + EAB. |
| `[x]` Done | PKI: Key Management + Cert Lifecycle | [spec](features/pki-key-management-and-lifecycle.md) — 7 phases incl. `CertDeliveryPlugin` trait. |
| `[x]` Done | Transit | [spec](features/transit-secret-engine.md) — Phases 1–4: AEAD + HMAC + sign/verify + ML-KEM + ML-DSA + BYOK + hybrid. |
| `[x]` Done | TOTP | [spec](features/totp-secret-engine.md) — Phases 1–4: HOTP / TOTP + GUI. |
| `[x]` Done | SSH | [spec](features/ssh-secret-engine.md) — Phases 1–4: CA Ed25519 + OTP + ML-DSA-65. |
| `[x]` Done | OpenLDAP / AD password-rotation | [spec](features/ldap-secret-engine.md) — 5 phases incl. identity-aware check-out affinity. |
| `[ ]` Todo | Dynamic Secrets framework | [spec](features/dynamic-secrets.md) — host ships only the framework; engines under [`dynamic-engine-plugins/`](dynamic-engine-plugins/). |
| `[x]` Done | XCA database import | [spec](features/xca-import.md) — external plugin `bastion-plugin-xca` shipped; reads `.xdb` SQLite, decrypts both XCA envelope formats, imports into the PKI engine via the operator-driven GUI wizard. |
| `[x]` Done | Password Manager Pro resource import | [spec](features/pmp-import.md) — `bastion-plugin-pmp` external plugin + GUI wizard. |

### Infrastructure

| Status | Feature | Notes |
|---|---|---|
| `[x]` Done | High Availability (Raft via Hiqlite) | [roadmap](roadmaps/hiqlite-default-ha-storage.md) — cluster CLI, PQ TLS, HA fault-injection. |
| `[x]` Done | Vault Cluster — Client Discovery & Health-Aware Connection | [spec](features/vault-cluster-client-discovery.md), [roadmap](roadmaps/vault-cluster-client-discovery.md) — All 8 phases shipped. `bv-client` discovery + health, `build_with_discovery` builder, sticky failure contract, Tauri `connect_remote` wiring + Settings diagnostics modal, `bvault cluster discover` CLI subcommand + `--no-cluster-discovery` flag, 26 new tests (19 unit + 7 e2e), operator runbook in docs. `operator seal` / `operator unseal` fan out cluster-wide via SRV discovery (per-node seal state), with `--local` to scope to one node. |
| `[x]` Done | Plugin System | [spec](features/plugin-system.md) — WASM + supervised process runtime, signed manifests, per-plugin metrics, GUI. |
| `[x]` Done | Plugin Extensibility (surface manifest, dynamic GUI menus/forms, client cache, auto-update) | [spec](features/plugin-extensibility.md), [roadmap](roadmaps/plugin-extensibility-redesign.md) — 8 phases shipped end-to-end (server surface storage + 3 HTTP routes, bv-client cache, GUI dynamic render, form-hook WASM sandbox, long-poll watcher, operator UX, reference TOTP example + SDK helpers). |
| `[x]` Done | Namespaces / Multi-tenancy | [spec](features/namespaces-multitenancy.md) — **Phases 1–4 complete + re-root activation the unconditional default for all installs.** Hierarchical namespace registry + resolver (header + path-prefix), per-namespace mount routing + dispatch (storage-isolated, cross-tenant isolation proven by test), `v2/sys/namespaces` CRUD, non-destructive barrier re-root copy (activation gated behind `BASTION_NAMESPACE_REROOT`). Namespace-bound tokens + immutable `child_visible` enforced before dispatch; per-login namespace binding (userpass/approle). **Per-namespace policy storage** (tenant ACL keyspaces + namespace-aware ACL compilation on the auth hot path) + cross-namespace path refusal + `{{namespace.*}}` templates. **Per-namespace audit broadcasters** with per-namespace hash chains + a root superuser mirror; `namespace` audit attribution. **Per-namespace identity** (entities/aliases/groups, distinct per tenant) + the parent-visible cross-tenant **identity-link** primitive (`v2/sys/namespace-links`). **All six quotas enforced** (`max_mounts`/`max_child_namespaces`/`request_rate` 429; accounting `max_entities`/`max_storage_bytes` 507/`max_leases`); a **Namespaces management GUI** + a **namespace switcher** (header threaded via `bv_client::Backend::handle_with_namespace` on embedded + remote). **Re-root activation is the unconditional default for every install** (no opt-in): `namespaces/<root_uuid>/…` authoritative from first unseal via a swappable root `mounts_router` + repointed `system_view`/`root_storage_prefix`; existing installs migrate automatically on next unseal (eager non-destructive copy + verify, flip only if verified — fail-safe, retries next boot). Full 836-test lib suite + GUI (tsc/build/120 vitest) green under activation. Minor follow-ups: `cert`-login binding, tenant self-service of `sys/*`, recursive GUI tree + rename. |
| `[ ]` Todo | Kubernetes Integration | [spec](features/kubernetes-integration.md) — `kubernetes` auth backend + CSI driver + agent injector. |
| `[/]` In progress | Rustion Bastion Integration | [spec](features/rustion-integration.md) — mediates Resource Connect through a PQC bastion; recording delegated to Rustion. **Phases 1–9 done, Phase 4.2-full done, Phase 7.4 done** (BV 0.7.14 → 0.8.23, Rustion 0.7.11 → 0.8.0): full session/recording pipeline + four-tier policy + telemetry pull + audit-witness replication + rate-limited telemetry + recording.replayed audit + fleet analytics + stable deployment_id + Rustion authorities-pending holding pen + disk-backed `authorities-pending/` + `tombstoned/` YAML with `rustion authority {list-pending, approve, reject, deenrol, untombstone, list, list-tombstones}` operator CLI + BV weekly re-attestation timer + `rustion_authority_attest` + `rustion_target_deenrol` Tauri commands + deployment_id binding (403 attestation_mismatch) + separate SessionReplayWindow Tauri WebviewWindow + WASM bitmap-update decoder at `gui/wasm/rdp-replay/` with matching TS port + RdpReplayCanvas live playback (uncompressed 16/24/32 bpp + RLE16/RLE24) + signed-URL replay path (`POST /v1/recordings/<rid>/replay` + HMAC-bound `GET /v1/recordings/<rid>`) + bastion-driven CredSSP injection driver (NTLMv2 sealing + RC4 keystream + pubKeyAuth +1 contract + sealed TSCredentials, simulated-Windows e2e tested) + operator deployment guide at [`features/rustion-authority-lifecycle.md`](features/rustion-authority-lifecycle.md) + **master authority lifecycle Phase 2** (`rustion master issue` / `rotate` CLI + HTTP, hybrid Ed25519 + ML-DSA-65 keypair lifecycle with rotate-grace window, real pubkey export, previous-key acceptance during grace via `verify_with_grace`). Phase 7.4 wires the in-app Connect button to the policy resolver: SSH-password sessions (BV 0.8.21) and RDP-password sessions (BV 0.8.22) route through the bastion when transport is `rustion-required` / `rustion`; non-password SSH and smart-card (rdp-cert) RDP under `rustion-required` fail closed pending the bastion's PKINIT path. BV 0.8.23 wires the spawned SSH/RDP session window into `useRustionSessionLifecycle` via a new `session_rustion_info` Tauri command + shared `RustionSessionChip` (auto-renew + manual Renew/Terminate + live TTL). Remaining: bastion host-key / TLS pinning in the GUI dialler (cross-repo with Rustion), rdp-cert via PKINIT/SPNEGO, live-Windows-VM transport hookup, `attestation_renew_at` enforcement at envelope-verify, Rustion admin web UI, BV-side GUI buttons for the new Tauri commands, cluster-replicated master + true PKI-engine cert emission (Phase 9 of authority lifecycle), two-way mTLS on the control plane (today auth rests entirely on the envelope signature; TLS is confidentiality-only), functional `input-redacted` recording mode (plumbed through the envelope + all four policy tiers but a no-op in Rustion's recorder today), and Rustion HA (active/passive) as a prerequisite for `rustion-required` in regulated deployments (the bastion is currently a single point of failure on that path). NSCodec / RemoteFX / 8 bpp RLE / bitmap-cache references, `rdp-cert` smart-card PKINIT, and SMB-through-Rustion documented as separate tracks. |
| `[x]` Done | Web UI / Desktop GUI (Tauri) | [roadmap](roadmaps/tauri-gui-fido2.md) — 9 phases, 55 Tauri commands, 79 React modules, 10 pages. |
| `[ ]` Todo | Graphical Policy Builder & Validator | [spec](features/policy-builder-validator.md), [roadmap](roadmaps/policy-builder-validator.md) — visual block editor + effectivity validator beside the textual HCL editor; hybrid engine (instant client lint + authoritative stateless backend dry-run `POST /v1/sys/policies/acl/test`), savable test cases gating save. 5 phases, spec drafted, no code yet. |
| `[ ]` Todo | Compliance Reporting | [spec](features/compliance-reporting.md) |

### Packaging & Distribution

Sequenced together under [`roadmaps/packaging-and-distribution.md`](roadmaps/packaging-and-distribution.md). Specs drafted; no code yet.

| Status | Feature | Notes |
|---|---|---|
| `[/]` Partial | Server Container Image (Podman / OCI, standalone + cluster) | [spec](features/packaging-podman-server.md) — **Phase 1 shipped**: standalone, `linux/amd64`, distroless `cc-debian12:nonroot`, GHCR push on `v*.*.*` tags, unsigned. Phases 1.5 (client-IP propagation), 2 (cluster), 3 (multi-arch + Cosign + SBOM + `:debug`), 4 (Helm chart) pending. |
| `[ ]` Todo | Native Client Installers (deb / rpm / pkg / msi for GUI + CLI) | [spec](features/packaging-client-binaries.md) — Tauri bundler for GUI, parallel CLI track via `cargo-deb` / `cargo-generate-rpm` / `pkgbuild` / WiX 3.x. Double-signed (platform-native + Cosign). Phase 5 publishes apt + dnf repos. |
| `[ ]` Todo | Client Distribution Website (OCI image) | [spec](features/packaging-distribution-website.md) — small `axum` + `askama` static-site server, signed `manifest.json` consumed by both the landing page and the GUI's "update available" banner (link-out only, no auto-update). |

## Active Initiatives

- **Packaging & Distribution** ([roadmap](roadmaps/packaging-and-distribution.md)) — server container image + native client installers + client-binary distribution website. Sequenced into four release waves. **Wave 1 shipped** (standalone server container image, distroless, GHCR push on `v*.*.*` tags). Wave 2 largely shipped (cluster compose, multi-arch, Cosign keyless, SBOM, Linux CLI installers); GUI Linux bundler + Phase 1.5 trusted-proxy still open. Wave 3 (macOS/Windows installers + downloads website) next.

Next-up `Todo` rows once Packaging & Distribution lands:

- Dynamic Secrets framework + first engine plugins
- HSM Support
- Kubernetes Integration
- Compliance Reporting
- Rustion Bastion Integration (delegated PAM transport + recording)
- Machine Authentication (FerroGate-attested machine identity, admin-approval gated, first-machine root bootstrap)
- Graphical Policy Builder & Validator (visual block editor + effectivity validator on the Policies page)

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
