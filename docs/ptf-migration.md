# PTF v1 migration — map and judgement calls

Record of the 2026-09-28 migration of `roadmap.md` / `CHANGELOG.md` to PTF v1 (`docs/tracking-format.md`).

Generated from `roadmap.md` (240 lines, 79 tracked features) and `CHANGELOG.md` (13,017 lines, 306 release sections, 2,193 entries) on 2026-09-28. Nothing in the old files was deleted or changed.

## Migration map — roadmap items

| Old item | New ID | New state | New location |
|---|---|---|---|
| roadmap.md:94 — TLS & mTLS (Rustls-based) (`[x]` Done) | T1 | `[x]` done | ROADMAP.md M1; first changelog ref: 0.3.1 |
| roadmap.md:95 — IP-based DoS / request-abuse protection (`[x]` Done) | T2 | `[x]` done | ROADMAP.md M1; first changelog ref: 0.41.25 |
| roadmap.md:66 — Storage Backend: Encrypted File (`[x]` Done) | T3 | `[x]` done | ROADMAP.md M2; first changelog ref: 0.3.1 |
| roadmap.md:67 — Storage Backend: MySQL (`[x]` Done) | T4 | `[x]` done | ROADMAP.md M2; first changelog ref: 0.3.1 |
| roadmap.md:68 — Storage Backend: SQLx (`[~]` Removed) | T5 | `[-]` abandoned | ROADMAP.md M2; first changelog ref: 0.3.1 |
| roadmap.md:69 — Storage Backend: Hiqlite (embedded Raft SQLite, HA) (`[x]` Done) | T6 | `[x]` done | ROADMAP.md M2; first changelog ref: 0.25.1 |
| roadmap.md:70 — Cloud targets for Encrypted File (S3 / OneDrive / Google Drive / Dropbox) (`[x]` Done) | T7 | `[x]` done | ROADMAP.md M2; first changelog ref: 0.5.0 |
| roadmap.md completed list: Cloud FileTarget Memory Cache | T8 | `[x]` done | ROADMAP.md M2; first changelog ref: 0.5.0 |
| roadmap.md:71 — Operator Backup / Restore (BVBK) (`[x]` Done) | T9 | `[x]` done | ROADMAP.md M2; first changelog ref: 0.5.0 |
| roadmap.md:72 — User-facing Exchange Module (`.bvx`) (`[x]` Done) | T10 | `[x]` done | ROADMAP.md M2; first changelog ref: 0.37.9 |
| roadmap.md:73 — Scheduled Exports (`[x]` Done) | T11 | `[x]` done | ROADMAP.md M2; first changelog ref: 0.37.3 |
| roadmap.md:74 — Caching (`[x]` Done) | T12 | `[x]` done | ROADMAP.md M2; first changelog ref: 0.44.0 |
| roadmap.md:75 — Batch Operations (`[x]` Done) | T13 | `[x]` done | ROADMAP.md M2; first changelog ref: 0.5.0 |
| roadmap.md:57 — Post-Quantum Crypto Migration (`[x]` Done) | T14 | `[x]` done | ROADMAP.md M3; first changelog ref: 0.5.0 |
| roadmap.md:58 — Key Management (ML-KEM-768, ML-DSA-65, ChaCha20-Poly1305) (`[x]` Done) | T15 | `[x]` done | ROADMAP.md M3; first changelog ref: 0.3.1 |
| roadmap.md:59 — Key Rotation & Re-encryption (`[x]` Done) | T16 | `[x]` done | ROADMAP.md M3; first changelog ref: 0.3.1 |
| roadmap.md:60 — HSM Support (`[/]` In progress) | T17 | `[/]` in progress | ROADMAP.md M3; first changelog ref: 0.25.1 |
| roadmap.md:38 — Core Vault Operations (init / seal / unseal / status) (`[x]` Done) | T18 | `[x]` done | ROADMAP.md M4; first changelog ref: 0.37.6 |
| roadmap.md:39 — `/v1/sys` authorization chokepoint (`[x]` Done) | T19 | `[x]` done | ROADMAP.md M4; first changelog ref: 0.37.6 |
| roadmap.md:40 — Cluster status disclosure gate (`[x]` Done) | T20 | `[x]` done | ROADMAP.md M4; first changelog ref: 0.37.6 |
| roadmap.md:41 — Secret Management (KV CRUD) (`[x]` Done) | T21 | `[x]` done | ROADMAP.md M4; first changelog ref: 0.22.0 |
| roadmap.md:42 — Secret Versioning & Soft-Delete (`[x]` Done) | T22 | `[x]` done | ROADMAP.md M4; first changelog ref: 0.5.22 |
| roadmap.md:43 — Per-Environment Secret Values (`[x]` Done) | T23 | `[x]` done | ROADMAP.md M4; first changelog ref: 0.22.1 |
| roadmap.md:44 — Access Control (RBAC + path-based ACL) (`[x]` Done) | T24 | `[x]` done | ROADMAP.md M4; first changelog ref: 0.28.0 |
| roadmap.md:45 — Connect-Only Access (`[/]` In progress) | T25 | `[/]` in progress | ROADMAP.md M4; first changelog ref: 0.44.5 |
| roadmap.md:46 — Identity Groups (user / app groups → policy mapping) (`[x]` Done) | T26 | `[x]` done | ROADMAP.md M4; first changelog ref: 0.5.21 |
| roadmap.md:47 — Per-User Scoping (ownership + policy templating + sharing) (`[x]` Done) | T27 | `[x]` done | ROADMAP.md M4; first changelog ref: 0.44.9 |
| roadmap.md:48 — Asset Groups (collections of resources + KV paths) (`[x]` Done) | T28 | `[x]` done | ROADMAP.md M4; first changelog ref: 0.5.0 |
| roadmap.md:49 — Audit Logging (tamper-evident, HMAC chain) (`[x]` Done) | T29 | `[x]` done | ROADMAP.md M4; first changelog ref: 0.42.0 |
| roadmap.md:50 — Metrics (Prometheus) (`[x]` Done) | T30 | `[x]` done | ROADMAP.md M4; first changelog ref: 0.5.0 |
| roadmap.md:51 — Formal Verification & Type-Driven Security (`[ ]` Todo) | T31 | `[/]` in progress | ROADMAP.md M4; first changelog ref: — |
| roadmap.md:81 — Resource Management (inventory + grouped secrets) (`[x]` Done) | T32 | `[x]` done | ROADMAP.md M5; first changelog ref: 0.36.0 |
| roadmap.md:82 — File Resources (binary blobs + sync targets) (`[x]` Done) | T33 | `[x]` done | ROADMAP.md M5; first changelog ref: 0.36.0 |
| roadmap.md:83 — First-class `firewall` / `switch` types + refined `database` (`[x]` Done) | T34 | `[x]` done | ROADMAP.md M5; first changelog ref: 0.5.0 |
| roadmap.md:84 — RDP clipboard redirection (host ⇄ session) (`[/]` In progress) | T35 | `[/]` in progress | ROADMAP.md M5; first changelog ref: 0.43.3 |
| roadmap.md:85 — Resource Connect — in-app SSH / RDP for server resources (`[x]` Done) | T36 | `[x]` done | ROADMAP.md M5; first changelog ref: 0.44.1 |
| roadmap.md:86 — Default Resource Account — per-user, per-OS login name as a credential source (`[x]` Done) | T37 | `[x]` done | ROADMAP.md M5; first changelog ref: 0.43.0 |
| roadmap.md:87 — Session Workspace — tabbed + split session layout (`[ ]` Todo) | T38 | `[ ]` planned | ROADMAP.md M5; first changelog ref: 0.41.9 |
| roadmap.md:88 — SSH Login Brokering for Resources (cert-signing / OTP, no shared credential) (`[/]` In progress) | T39 | `[/]` in progress | ROADMAP.md M5; first changelog ref: 0.44.2 |
| roadmap.md:101 — Auth: Token (`[x]` Done) | T40 | `[x]` done | ROADMAP.md M6; first changelog ref: 0.42.2 |
| roadmap.md:102 — Auth: AppID (Vault AppRole-compatible, API type `approle`) (`[x]` Done) | T41 | `[x]` done | ROADMAP.md M6; first changelog ref: 0.42.2 |
| roadmap.md:103 — Auth: Userpass (`[x]` Done) | T42 | `[x]` done | ROADMAP.md M6; first changelog ref: 0.44.8 |
| roadmap.md:104 — Auth: UserPass Account Security (`[x]` Done) | T43 | `[x]` done | ROADMAP.md M6; first changelog ref: 0.31.0 |
| roadmap.md:105 — Auth: Certificate (`[x]` Done) | T44 | `[x]` done | ROADMAP.md M6; first changelog ref: 0.3.1 |
| roadmap.md:106 — Self-Service Profile (own password / contact / default accounts) (`[x]` Done) | T45 | `[x]` done | ROADMAP.md M6; first changelog ref: 0.38.0 |
| roadmap.md:107 — Auth: OIDC (`[x]` Done) | T46 | `[x]` done | ROADMAP.md M6; first changelog ref: 0.5.0 |
| roadmap.md:108 — Auth: SAML 2.0 (`[x]` Done) | T47 | `[x]` done | ROADMAP.md M6; first changelog ref: 0.5.0 |
| roadmap.md:109 — Auth: FIDO2 / WebAuthn / YubiKey (`[x]` Done) | T48 | `[x]` done | ROADMAP.md M6; first changelog ref: 0.43.6 |
| roadmap.md deferred list: FIDO2 openssl-sys — “~~Replace the `openssl-sys` link in `webauthn-rs` 0.5~~ — done. The se…” | T49 | `[x]` done | ROADMAP.md M6; first changelog ref: 0.5.0 |
| roadmap.md deferred list: GUI-side OpenSSL — “Remove GUI-side OpenSSL — the `authenticator` crate's `crypto_openssl`…” | T50 | `[x]` done | ROADMAP.md M6; first changelog ref: 0.5.0 |
| roadmap.md:110 — Auth: Machine Authentication (FerroGate) (`[x]` Done) | T51 | `[x]` done | ROADMAP.md M6; first changelog ref: 0.41.0 |
| roadmap.md:111 — Identity Provider (workforce identity brokering to downstream systems) (`[ ]` Todo) | T52 | `[ ]` planned | ROADMAP.md M6; first changelog ref: 0.18.2 |
| roadmap.md:117 — PKI (`[x]` Done) | T53 | `[x]` done | ROADMAP.md M7; first changelog ref: 0.43.9 |
| roadmap.md:118 — PKI: ACME server endpoints (`[x]` Done) | T54 | `[x]` done | ROADMAP.md M7; first changelog ref: 0.5.0 |
| roadmap.md:119 — PKI: Inbound sign requests (`[x]` Done) | T55 | `[x]` done | ROADMAP.md M7; first changelog ref: 0.41.18 |
| roadmap.md:120 — PKI: Key Management + Cert Lifecycle (`[x]` Done) | T56 | `[x]` done | ROADMAP.md M7; first changelog ref: 0.5.0 |
| roadmap.md:121 — PKI: `rfc822Name` email SANs (S/MIME person certs) (`[x]` Done) | T57 | `[x]` done | ROADMAP.md M7; first changelog ref: 0.41.20 |
| roadmap.md:122 — Transit (`[x]` Done) | T58 | `[x]` done | ROADMAP.md M7; first changelog ref: 0.5.0 |
| roadmap.md:123 — TOTP (`[x]` Done) | T59 | `[x]` done | ROADMAP.md M7; first changelog ref: 0.30.0 |
| roadmap.md:124 — SSH (`[x]` Done) | T60 | `[x]` done | ROADMAP.md M7; first changelog ref: 0.5.0 |
| roadmap.md:125 — OpenLDAP / AD password-rotation (`[x]` Done) | T61 | `[x]` done | ROADMAP.md M7; first changelog ref: 0.5.0 |
| roadmap.md:126 — Dynamic Secrets framework (`[ ]` Todo) | T62 | `[ ]` planned | ROADMAP.md M7; first changelog ref: 0.5.0 |
| roadmap.md:127 — XCA database import (`[x]` Done) | T63 | `[x]` done | ROADMAP.md M7; first changelog ref: 0.43.12 |
| roadmap.md:128 — Password Manager Pro resource import (`[x]` Done) | T64 | `[x]` done | ROADMAP.md M7; first changelog ref: 0.5.0 |
| roadmap.md:134 — High Availability (Raft via Hiqlite) (`[x]` Done) | T65 | `[x]` done | ROADMAP.md M8; first changelog ref: 0.41.19 |
| roadmap.md:135 — Vault Cluster — Client Discovery & Health-Aware Connection (`[x]` Done) | T66 | `[x]` done | ROADMAP.md M8; first changelog ref: 0.21.5 |
| roadmap.md:136 — Plugin System (`[x]` Done) | T67 | `[x]` done | ROADMAP.md M8; first changelog ref: 0.36.4 |
| roadmap.md:137 — Plugin Extensibility (surface manifest, dynamic GUI menus/forms, client cache, auto-update) (`[x]` Done) | T68 | `[x]` done | ROADMAP.md M8; first changelog ref: 0.5.0 |
| roadmap.md:138 — Plugin Unit-Test Infrastructure (`[/]` Partial) | T69 | `[/]` in progress | ROADMAP.md M8; first changelog ref: 0.26.0 |
| roadmap.md:139 — Notifications (in-app notification system + plugin send/channels + email plugin) (`[x]` Done) | T70 | `[x]` done | ROADMAP.md M8; first changelog ref: 0.36.4 |
| roadmap.md:140 — Plugin App Extensions (Extensibility v2: dynamic menus, plugin windows, vault-API + admin-granted network from sandboxed app modules) (`[x]` Done) | T71 | `[x]` done | ROADMAP.md M8; first changelog ref: 0.26.0 |
| roadmap.md:141 — Namespaces / Multi-tenancy (`[x]` Done) | T72 | `[x]` done | ROADMAP.md M8; first changelog ref: 0.44.2 |
| roadmap.md active list: Namespaces Phase 5 | T73 | `[/]` in progress | ROADMAP.md M8; first changelog ref: 0.38.2 |
| roadmap.md:142 — Kubernetes Integration (`[ ]` Todo) | T74 | `[ ]` planned | ROADMAP.md M8; first changelog ref: 0.5.0 |
| roadmap.md:143 — Rustion Bastion Integration (`[/]` In progress) | T75 | `[/]` in progress | ROADMAP.md M8; first changelog ref: 0.43.3 |
| roadmap.md:144 — Web UI / Desktop GUI (Tauri) (`[x]` Done) | T76 | `[x]` done | ROADMAP.md M8; first changelog ref: 0.44.10 |
| roadmap.md:145 — GUI Dashboard Redesign (operational PAM landing view) (`[x]` Done) | T77 | `[x]` done | ROADMAP.md M8; first changelog ref: 0.44.11 |
| roadmap.md:146 — Graphical Policy Builder & Validator (`[x]` Done) | T78 | `[x]` done | ROADMAP.md M8; first changelog ref: 0.41.12 |
| roadmap.md:147 — Compliance Reporting (`[ ]` Todo) | T79 | `[ ]` planned | ROADMAP.md M8; first changelog ref: 0.5.0 |
| roadmap.md:148 — MCP Access (authenticated, permission-scoped Model Context Protocol server — local + network) (`[/]` In progress) | T80 | `[/]` in progress | ROADMAP.md M8; first changelog ref: 0.44.12 |
| roadmap.md active list: Client request efficiency | T81 | `[x]` done | ROADMAP.md M8; first changelog ref: 0.44.0 |
| roadmap.md completed list: Workspace Decomposition | T82 | `[x]` done | ROADMAP.md M8; first changelog ref: 0.41.0 |
| roadmap.md:156 — Server Container Image (Podman / OCI, standalone + cluster) (`[/]` Partial) | T83 | `[/]` in progress | ROADMAP.md M9; first changelog ref: 0.41.13 |
| roadmap.md:157 — Native Client Installers (deb / rpm / pkg / msi / nupkg for GUI + CLI) (`[/]` Partial) | T84 | `[/]` in progress | ROADMAP.md M9; first changelog ref: 0.41.23 |
| roadmap.md:158 — Client Distribution Website (OCI image) (`[/]` Partial) | T85 | `[/]` in progress | ROADMAP.md M9; first changelog ref: 0.41.15 |
| roadmap.md Deferred sub-initiatives — “Syslog and HTTP audit devices — Phase 1 file device shipped; the trait…” | T86 | `[>]` postponed | ROADMAP.md Backlog; first changelog ref: Unreleased |
| roadmap.md Deferred sub-initiatives — “CLI + SDK clients — Phase 1 HTTP surface shipped; the CLI and SDK wrap…” | T87 | `[>]` postponed | ROADMAP.md Backlog; first changelog ref: Unreleased |
| roadmap.md Deferred sub-initiatives — “`--allow-mixed-chain` opt-in — guard is fail-closed today; trivial to …” | T88 | `[>]` postponed | ROADMAP.md Backlog; first changelog ref: Unreleased |
| roadmap.md Deferred sub-initiatives — “AIA / CRL Distribution Points / Name Constraints extensions in issued …” | T89 | `[>]` postponed | ROADMAP.md Backlog; first changelog ref: Unreleased |
| roadmap.md Deferred sub-initiatives — “Composite IETF-draft tracking — Phase 3 pins a BastionVault-internal p…” | T90 | `[>]` postponed | ROADMAP.md Backlog; first changelog ref: Unreleased |
| roadmap.md Deferred sub-initiatives — “Additional composite variants — Phase 3 ships `id-MLDSA65-ECDSA-P256-S…” | T91 | `[>]` postponed | ROADMAP.md Backlog; first changelog ref: Unreleased |
| roadmap.md Deferred sub-initiatives — “`plugin-ext` bridge for third-party `CertDeliveryPlugin` deliverers — …” | T92 | `[>]` postponed | ROADMAP.md Backlog; first changelog ref: Unreleased |

## Migration map — other roadmap content

| Old item | New location |
|---|---|
| Title, intro, "At a glance" count table | ROADMAP.md intro (counts dropped: they are derived now, and were stale — 62/10/6/1 vs. 67/12/5/1 plus 7 backlog after the migration) |
| "How to read this" legend, `[~]` Removed state | replaced by the PTF state legend; `[~]` → `[-]` |
| Feature Status category headings (Core, Cryptography, Storage, Resources, Networking & TLS, Authentication, Secret Engines, Infrastructure, Packaging & Distribution) | milestones M4, M3, M2, M5, M1, M6, M7, M8, M9 (done milestones first) |
| Each row's Notes column | the task's `old-notes:` line, verbatim |
| Active Initiatives bullets | `initiative:` line on T83, T73 (namespaces Phase 5), T81 (client request efficiency) |
| "Next-up" list | ROADMAP.md intro, verbatim |
| Completed Initiatives bullets | `initiative:` line on the matching task (by spec path) |
| Deferred sub-initiatives | Backlog T86–T92 (`[>]`) plus T49, T50 (`[x]`, already done) |
| Notes section | ROADMAP.md intro (paraphrased guidance) |
| `features/*.md`, `roadmaps/*.md`, `docs/*.md` (102 files) | `## Specs` S1–S102 |

## Migration map — changelog

| Old structure | New structure |
|---|---|
| Header + maintenance HTML comment | kept verbatim, with PTF front matter, a KaC/SemVer/PTF intro paragraph and a PTF note comment |
| `## [x.y.z] - date` sections (305) | kept, dates already ISO 8601; bottom-of-file compare links added for every version with a `v<x>` or `releases/<x>` tag |
| `## [Previous entries below …]` + `## Hiqlite Phase 1–6` + `## Test Fixes` | one `## [0.3.1] - 2026-04-14` release; each old section title becomes a `####` sub-heading |
| `### Known gaps`, `### Known limitations`, `### Documentation` | `### Changed` with a `#### Known gaps` / `#### Known limitations` / `#### Documentation` sub-heading |
| `### Plugins (out-of-tree)` | `### Added` + `#### Plugins (out-of-tree)` |
| Repeated category headings inside one release | merged, in canonical order, original order within each |
| Soft-wrapped entry continuation lines | joined onto the entry's first line (renders identically; needed so the trailing reference group sits on the parsed line) |
| `---` release separators | dropped |

## Judgement calls to review

1. **Milestones are feature areas, not delivery stages.** The old roadmap had no dated milestones; M1–M9 are its category tables. Outcomes are invented "done when" statements. No `target:`/`version:` lines — no category maps to one release. No `## Phases` (they would be artificial).
2. **Status corrections against the tree:** T31 Formal verification Todo → `[/]` (Phase 0 fixes shipped, 2.1 part-done, per the old note itself); T81 Client request efficiency Active (Phases 1–2) → `[x]` (its feature file says all five phases complete); T50 GUI-side OpenSSL removal Deferred → `[x]` (`gui/src-tauri/Cargo.toml` uses `authenticator` `crypto_rust` + `p12-keystore`, and 0.5.0 already recorded it).
3. **Partly-stale backlog item:** T89 (AIA / CRL DP / Name Constraints) stays `[>]` but retitled to AIA + Name Constraints — `crates/bv-engine-pki/src/x509.rs` already emits CRL Distribution Points; AIA and Name Constraints are not emitted.
4. **Stale "Next-up" list** still names Machine Authentication, which the table marks Done (T51). Kept verbatim; not acted on.
5. **Invented baseline entries.** T1, T3, T4, T15, T16, T44 are done but have no entry anywhere (they predate the changelog). Each got one entry in 0.3.1 under `#### Recorded during PTF migration`, marked as such. T16 (key rotation) placement in 0.3.1 is the least certain.
6. **Version 0.3.1 for the unversioned pre-history** is `Cargo.toml` at commit 08b5762d (2026-04-14); never tagged. 0.5.0 says it bumped from 0.4.1, so 0.4.x existed untagged with no changelog of its own.
7. **SQLx abandonment** is dated to 0.3.1 (the Removed entry that records it). The Abandoned entry reuses the documented reason.
8. **Postponed entries are under `[Unreleased]`** — the decision dates are not recorded. Reasons come from the old Deferred text.
9. **Entries were not rewritten** into one imperative sentence each. Doing that by hand for 2,193 entries, many of them multi-paragraph, would lose information (goal 2) and could not be reviewed. They keep their bold-lead style; only refs were appended.
10. **References are keyword-derived.** An entry gets a task ID when it links the task's `features/*.md` spec, or when its `####` sub-heading matches the task's keyword. Broad keywords (`GUI`, `PKI`) tag many entries (T76: 159, T53: 218). 871 of 2,207 entries stay untracked (build, CI, deps, refactors), which PTF allows. Six hand-placed refs: T18, T19, T20 (0.37.6), T49, T50 (0.5.0), T81 (0.44.0).
11. **Specs include every `docs/*.md`** (the brief says documents living in `docs/`), minus `_navbar.md`/`_sidebar.md`. `docs/backend/`, `docs/policies/` and `docs/build-timings/` subdirectories are not registered.
12. **Project slug** `bastionvault` (repo name, lowercased).

## Adoption (applied 2026-09-28)

- `roadmap.md` was renamed to `ROADMAP.md` with `git mv` (the volume is case-insensitive) and both files replaced.
- `AGENTS.md` §2 and §8 now describe the PTF rules; the spec is vendored at `docs/tracking-format.md` (S103).
- Links to `../roadmap.md` in `features/*.md` and `roadmaps/*.md` point at `../ROADMAP.md`; stale `roadmap.md:<line>` anchors lost their line numbers. Prose in those files that talks about table "rows" was not rewritten.
- `scripts/test-changed.sh` ignores both `ROADMAP.md` and `roadmap.md`; `.taurignore`'s comment names the new file.
- The generator was a one-off script and is not committed; edit both files by hand from here on.
